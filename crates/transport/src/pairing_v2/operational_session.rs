//! Sealed, verification-only operational-session wire boundary.
//!
//! This module deliberately has no product entry point and no input, clipboard,
//! topology, or runtime-control capability.  It accepts only the frozen V01
//! six-record schedule; transport ownership and durable admission are layered
//! above this exact parser.
use super::{
    Invalid,
    codec::{Value, decode, encode},
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, time::Duration};
use tokio::sync::oneshot;

pub(crate) const ALPN: &[u8] = b"csf12-operational/1";
pub(crate) const APPLICATION_ERROR: u32 = 0x4353_4612;
pub(crate) const RECORD_LIMIT: usize = 4096;
pub(crate) const RECORD_COUNT: u32 = 6;
const MAGIC: &[u8; 8] = b"CSF12S1\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 20;
const SUITE: &str = "x25519-hkdf-sha256-ed25519-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    A,
    B,
}

impl Role {
    pub(crate) fn for_sequence(sequence: u32) -> Result<Self, Invalid> {
        match sequence {
            0 | 2 | 4 => Ok(Self::A),
            1 | 3 | 5 => Ok(Self::B),
            _ => Err(Invalid),
        }
    }

    fn direction(self) -> u8 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordType {
    PreflightOpen,
    PreflightAccept,
    Open,
    Accept,
    Confirm,
}

impl RecordType {
    pub(crate) fn for_sequence(sequence: u32) -> Result<Self, Invalid> {
        match sequence {
            0 => Ok(Self::PreflightOpen),
            1 => Ok(Self::PreflightAccept),
            2 => Ok(Self::Open),
            3 => Ok(Self::Accept),
            4 | 5 => Ok(Self::Confirm),
            _ => Err(Invalid),
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::PreflightOpen => 1,
            Self::PreflightAccept => 2,
            Self::Open => 3,
            Self::Accept => 4,
            Self::Confirm => 5,
        }
    }

    fn from_code(code: u8) -> Result<Self, Invalid> {
        match code {
            1 => Ok(Self::PreflightOpen),
            2 => Ok(Self::PreflightAccept),
            3 => Ok(Self::Open),
            4 => Ok(Self::Accept),
            5 => Ok(Self::Confirm),
            _ => Err(Invalid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationalRecord {
    kind: RecordType,
    sender: Role,
    sequence: u32,
    payload: Vec<u8>,
}

/// Canonical, bounded projection of the local durable admission state.
/// It intentionally contains no device, network, UI, display, or raw admission
/// material.  It is parsed independently from the enclosing V01 record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityView {
    self_fingerprint: [u8; 32],
    peer_fingerprint: [u8; 32],
    suite: String,
    protocol_version: u64,
    policy_revision: u64,
    identity_generation: u64,
    revocation_generation: u64,
    receipt_revision: u64,
    admission_attempt: [u8; 32],
}

impl AuthorityView {
    pub(crate) fn from_snapshot(
        local_leaf: [u8; 32],
        snapshot: &crate::pairing_pending::OperationalAdmissionSnapshot,
    ) -> Result<Self, Invalid> {
        let receipt = &snapshot.receipt;
        let view = Self {
            self_fingerprint: local_leaf,
            peer_fingerprint: receipt.peer_pin,
            suite: receipt.suite.clone(),
            protocol_version: u64::from(receipt.protocol_version),
            policy_revision: receipt.policy_revision,
            identity_generation: receipt.identity_generation,
            revocation_generation: receipt.revocation_generation,
            receipt_revision: receipt.revision,
            admission_attempt: receipt.attempt,
        };
        (view.is_v01() && view.self_fingerprint != view.peer_fingerprint)
            .then_some(view)
            .ok_or(Invalid)
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Invalid> {
        if raw.is_empty() || raw.len() > 512 {
            return Err(Invalid);
        }
        let fields = decode(
            "operational-authority-view-v1",
            raw,
            &[2, 2, 3, 1, 1, 1, 1, 1, 2],
        )?;
        let bytes32 = |index: usize| match &fields[index] {
            Value::Bytes(value) => value.as_slice().try_into().map_err(|_| Invalid),
            _ => Err(Invalid),
        };
        let number = |index: usize| match fields[index] {
            Value::Number(value) => Ok(value),
            _ => Err(Invalid),
        };
        let suite = match &fields[2] {
            Value::Text(value) if value.is_ascii() && value.len() <= 64 => value.clone(),
            _ => return Err(Invalid),
        };
        let view = Self {
            self_fingerprint: bytes32(0)?,
            peer_fingerprint: bytes32(1)?,
            suite,
            protocol_version: number(3)?,
            policy_revision: number(4)?,
            identity_generation: number(5)?,
            revocation_generation: number(6)?,
            receipt_revision: number(7)?,
            admission_attempt: bytes32(8)?,
        };
        if view.self_fingerprint == [0; 32]
            || view.peer_fingerprint == [0; 32]
            || view.admission_attempt == [0; 32]
            || view.receipt_revision == 0
            || view.encode()? != raw
        {
            return Err(Invalid);
        }
        Ok(view)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, Invalid> {
        // The durable store starts both policy and identity generations at zero.
        // V01 requires equality with the active receipt, not a nonzero counter;
        // receipt revision and the admission attempt remain nonzero capability
        // discriminators.
        if self.self_fingerprint == [0; 32]
            || self.peer_fingerprint == [0; 32]
            || self.admission_attempt == [0; 32]
            || self.receipt_revision == 0
            || !self.suite.is_ascii()
            || self.suite.len() > 64
        {
            return Err(Invalid);
        }
        let raw = encode(
            "operational-authority-view-v1",
            &[
                Value::Bytes(self.self_fingerprint.to_vec()),
                Value::Bytes(self.peer_fingerprint.to_vec()),
                Value::Text(self.suite.clone()),
                Value::Number(self.protocol_version),
                Value::Number(self.policy_revision),
                Value::Number(self.identity_generation),
                Value::Number(self.revocation_generation),
                Value::Number(self.receipt_revision),
                Value::Bytes(self.admission_attempt.to_vec()),
            ],
        )?;
        (raw.len() <= 512).then_some(raw).ok_or(Invalid)
    }

    pub(crate) fn is_v01(&self) -> bool {
        // V01 has two independent version domains: the operational framing is
        // VERSION=1 above, while this copied durable pairing receipt field is
        // exact protocol version 2.  They must never be used as a fallback for
        // one another.
        self.suite == SUITE && self.protocol_version == 2
    }

    fn inverse_of(&self, other: &Self) -> bool {
        self.self_fingerprint == other.peer_fingerprint
            && self.peer_fingerprint == other.self_fingerprint
            && self.is_v01()
            && other.is_v01()
    }
}

impl OperationalRecord {
    fn new(sequence: u32, payload: Vec<u8>) -> Result<Self, Invalid> {
        Ok(Self {
            kind: RecordType::for_sequence(sequence)?,
            sender: Role::for_sequence(sequence)?,
            sequence,
            payload,
        })
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Invalid> {
        if raw.len() < HEADER_LEN || raw[..8] != *MAGIC || raw[8..10] != VERSION.to_be_bytes() {
            return Err(Invalid);
        }
        let kind = RecordType::from_code(raw[10])?;
        let sender = match raw[11] {
            1 => Role::A,
            2 => Role::B,
            _ => return Err(Invalid),
        };
        let sequence = u32::from_be_bytes(raw[12..16].try_into().map_err(|_| Invalid)?);
        let length = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| Invalid)?) as usize;
        if length == 0
            || length > RECORD_LIMIT
            || raw.len() != HEADER_LEN.checked_add(length).ok_or(Invalid)?
            || kind != RecordType::for_sequence(sequence)?
            || sender != Role::for_sequence(sequence)?
        {
            return Err(Invalid);
        }
        Ok(Self {
            kind,
            sender,
            sequence,
            payload: raw[HEADER_LEN..].to_vec(),
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, Invalid> {
        if self.payload.is_empty()
            || self.payload.len() > RECORD_LIMIT
            || self.kind != RecordType::for_sequence(self.sequence)?
            || self.sender != Role::for_sequence(self.sequence)?
        {
            return Err(Invalid);
        }
        let mut raw = Vec::with_capacity(HEADER_LEN + self.payload.len());
        raw.extend(MAGIC);
        raw.extend(VERSION.to_be_bytes());
        raw.push(self.kind.code());
        raw.push(self.sender.direction());
        raw.extend(self.sequence.to_be_bytes());
        raw.extend((self.payload.len() as u32).to_be_bytes());
        raw.extend(&self.payload);
        Ok(raw)
    }

    pub(crate) fn sequence(&self) -> u32 {
        self.sequence
    }

    pub(crate) fn expected_type(&self) -> RecordType {
        self.kind
    }

    pub(crate) fn expected_sender(&self) -> Role {
        self.sender
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Validates the immutable portions of the V01 schedule before a transport
/// session derives exporter-bound confirmation keys.  This function has no
/// network side effects and intentionally cannot create runtime authority.
pub(crate) fn validate_v01_schedule(records: &[OperationalRecord]) -> Result<(), Invalid> {
    if records.len() != RECORD_COUNT as usize {
        return Err(Invalid);
    }
    for (index, record) in records.iter().enumerate() {
        if record.sequence != index as u32
            || record.kind != RecordType::for_sequence(index as u32)?
            || record.sender != Role::for_sequence(index as u32)?
        {
            return Err(Invalid);
        }
    }

    let open = preflight_open(&records[0])?;
    let accept = preflight_accept(&records[1])?;
    if open.attempt != accept.attempt
        || open.session_id != accept.session_id
        || open.nonce_a != accept.nonce_a
        || open.a_leaf != accept.a_leaf
        || open.b_leaf != accept.b_leaf
        || !open.a_view.inverse_of(&accept.b_view)
    {
        return Err(Invalid);
    }
    let commitment = authority_commitment(&open.a_view, &accept.b_view)?;
    let commitment_hash: [u8; 32] = Sha256::digest(&commitment).into();
    let a_open = open_record(&records[2])?;
    if a_open.attempt != open.attempt
        || a_open.session_id != open.session_id
        || a_open.commitment_hash != commitment_hash
        || a_open.context_hash == [0; 32]
    {
        return Err(Invalid);
    }
    let b_accept = accept_record(&records[3])?;
    if b_accept.attempt != open.attempt
        || b_accept.session_id != open.session_id
        || b_accept.open_hash != hash(&records[2].payload)
        || b_accept.commitment_hash != commitment_hash
        || b_accept.context_hash != a_open.context_hash
    {
        return Err(Invalid);
    }
    let a_confirm = confirm_record(&records[4], Role::A)?;
    let b_confirm = confirm_record(&records[5], Role::B)?;
    if a_confirm.attempt != open.attempt
        || b_confirm.attempt != open.attempt
        || a_confirm.session_id != open.session_id
        || b_confirm.session_id != open.session_id
        || a_confirm.prior_hash != hash(&records[3].payload)
        || b_confirm.prior_hash != hash(&records[4].payload)
        || a_confirm.confirmation == [0; 32]
        || b_confirm.confirmation == [0; 32]
    {
        return Err(Invalid);
    }
    Ok(())
}

/// Derives the frozen confirmation key from the selected connection's exporter
/// output and verifies both final records.  The exporter is consumed by value
/// and never persisted.  This pure verifier is used before a future session
/// wrapper can expose any completed state.
pub(crate) fn derive_and_verify_confirmation_key(
    records: &[OperationalRecord],
    exporter: [u8; 32],
) -> Result<[u8; 32], Invalid> {
    validate_v01_schedule(records)?;
    let preflight = preflight_open(&records[0])?;
    let accept = preflight_accept(&records[1])?;
    let open = open_record(&records[2])?;
    let response = accept_record(&records[3])?;
    let confirm_a = confirm_record(&records[4], Role::A)?;
    let confirm_b = confirm_record(&records[5], Role::B)?;
    let commitment = authority_commitment(&preflight.a_view, &accept.b_view)?;
    let commitment_hash = hash(&commitment);
    let context = exporter_context(
        preflight.a_leaf,
        preflight.b_leaf,
        commitment_hash,
        preflight.nonce_a,
        accept.nonce_b,
    )?;
    let context_hash = hash(&context);
    if open.context_hash != context_hash
        || response.context_hash != context_hash
        || open.commitment_hash != commitment_hash
        || response.commitment_hash != commitment_hash
    {
        return Err(Invalid);
    }
    let mut extract = Hmac::<Sha256>::new_from_slice(&context_hash).map_err(|_| Invalid)?;
    extract.update(&exporter);
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha256>::new_from_slice(&prk).map_err(|_| Invalid)?;
    expand.update(b"CSF12 operational session confirm key v1\0");
    expand.update(&context_hash);
    expand.update(&[1]);
    let key: [u8; 32] = expand.finalize().into_bytes().into();
    verify_confirmation(
        &key,
        Role::A,
        confirm_a.attempt,
        confirm_a.session_id,
        confirm_a.prior_hash,
        confirm_a.confirmation,
    )?;
    verify_confirmation(
        &key,
        Role::B,
        confirm_b.attempt,
        confirm_b.session_id,
        confirm_b.prior_hash,
        confirm_b.confirmation,
    )?;
    Ok(key)
}

fn exporter_context(
    a_leaf: [u8; 32],
    b_leaf: [u8; 32],
    commitment_hash: [u8; 32],
    nonce_a: [u8; 32],
    nonce_b: [u8; 32],
) -> Result<Vec<u8>, Invalid> {
    encode(
        "operational-session-exporter-context-v1",
        &[
            Value::Text("csf12-operational/1".to_owned()),
            Value::Bytes(a_leaf.to_vec()),
            Value::Bytes(b_leaf.to_vec()),
            Value::Bytes(commitment_hash.to_vec()),
            Value::Bytes(nonce_a.to_vec()),
            Value::Bytes(nonce_b.to_vec()),
            Value::Bytes(b"CSF12S1\0".to_vec()),
            Value::Number(1),
        ],
    )
}

fn verify_confirmation(
    key: &[u8; 32],
    role: Role,
    attempt: [u8; 32],
    session_id: [u8; 16],
    prior_hash: [u8; 32],
    confirmation: [u8; 32],
) -> Result<(), Invalid> {
    let role = match role {
        Role::A => b"A".as_slice(),
        Role::B => b"B".as_slice(),
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Invalid)?;
    mac.update(b"CSF12 operational session confirm v1\0");
    mac.update(role);
    mac.update(&attempt);
    mac.update(&session_id);
    mac.update(&prior_hash);
    mac.verify_slice(&confirmation).map_err(|_| Invalid)
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn authority_commitment(a: &AuthorityView, b: &AuthorityView) -> Result<Vec<u8>, Invalid> {
    if !a.inverse_of(b) {
        return Err(Invalid);
    }
    encode(
        "operational-admission-commitment-v1",
        &[
            Value::Bytes(a.self_fingerprint.to_vec()),
            Value::Bytes(a.peer_fingerprint.to_vec()),
            Value::Bytes(hash(&a.encode()?).to_vec()),
            Value::Bytes(hash(&b.encode()?).to_vec()),
            Value::Text(SUITE.to_owned()),
            Value::Number(1),
        ],
    )
}

struct PreflightOpen {
    attempt: [u8; 32],
    session_id: [u8; 16],
    nonce_a: [u8; 32],
    a_view: AuthorityView,
    a_leaf: [u8; 32],
    b_leaf: [u8; 32],
}

struct PreflightAccept {
    attempt: [u8; 32],
    session_id: [u8; 16],
    nonce_a: [u8; 32],
    nonce_b: [u8; 32],
    b_view: AuthorityView,
    a_leaf: [u8; 32],
    b_leaf: [u8; 32],
}

struct Open {
    attempt: [u8; 32],
    session_id: [u8; 16],
    commitment_hash: [u8; 32],
    context_hash: [u8; 32],
}

struct Accept {
    attempt: [u8; 32],
    session_id: [u8; 16],
    open_hash: [u8; 32],
    commitment_hash: [u8; 32],
    context_hash: [u8; 32],
}

struct Confirm {
    attempt: [u8; 32],
    session_id: [u8; 16],
    prior_hash: [u8; 32],
    confirmation: [u8; 32],
}

fn bytes<const N: usize>(value: &Value) -> Result<[u8; N], Invalid> {
    match value {
        Value::Bytes(bytes) => bytes.as_slice().try_into().map_err(|_| Invalid),
        _ => Err(Invalid),
    }
}

fn role(value: &Value, expected: Role) -> Result<(), Invalid> {
    let expected = match expected {
        Role::A => "A",
        Role::B => "B",
    };
    matches!(value, Value::Text(actual) if actual == expected)
        .then_some(())
        .ok_or(Invalid)
}

fn preflight_open(record: &OperationalRecord) -> Result<PreflightOpen, Invalid> {
    let fields = decode(
        "operational-session-preflight-open-v1",
        record.payload(),
        &[2, 3, 2, 2, 2, 2, 2],
    )?;
    role(&fields[1], Role::A)?;
    let view_raw = bounded_bytes(&fields[4], 512)?;
    let value = PreflightOpen {
        attempt: bytes(&fields[0])?,
        session_id: bytes(&fields[2])?,
        nonce_a: bytes(&fields[3])?,
        a_view: AuthorityView::decode(&view_raw)?,
        a_leaf: bytes(&fields[5])?,
        b_leaf: bytes(&fields[6])?,
    };
    nonzero(&value.attempt)?;
    nonzero(&value.session_id)?;
    nonzero(&value.nonce_a)?;
    if value.a_view.self_fingerprint != value.a_leaf
        || value.a_view.peer_fingerprint != value.b_leaf
    {
        return Err(Invalid);
    }
    Ok(value)
}

fn preflight_accept(record: &OperationalRecord) -> Result<PreflightAccept, Invalid> {
    let fields = decode(
        "operational-session-preflight-accept-v1",
        record.payload(),
        &[2, 3, 2, 2, 2, 2, 2, 2],
    )?;
    role(&fields[1], Role::B)?;
    let view_raw = bounded_bytes(&fields[5], 512)?;
    let value = PreflightAccept {
        attempt: bytes(&fields[0])?,
        session_id: bytes(&fields[2])?,
        nonce_a: bytes(&fields[3])?,
        nonce_b: bytes(&fields[4])?,
        b_view: AuthorityView::decode(&view_raw)?,
        a_leaf: bytes(&fields[6])?,
        b_leaf: bytes(&fields[7])?,
    };
    nonzero(&value.attempt)?;
    nonzero(&value.session_id)?;
    nonzero(&value.nonce_a)?;
    if value.b_view.self_fingerprint != value.b_leaf
        || value.b_view.peer_fingerprint != value.a_leaf
    {
        return Err(Invalid);
    }
    Ok(value)
}

fn open_record(record: &OperationalRecord) -> Result<Open, Invalid> {
    let fields = decode(
        "operational-session-open-v1",
        record.payload(),
        &[2, 3, 2, 2, 2],
    )?;
    role(&fields[1], Role::A)?;
    Ok(Open {
        attempt: bytes(&fields[0])?,
        session_id: bytes(&fields[2])?,
        commitment_hash: bytes(&fields[3])?,
        context_hash: bytes(&fields[4])?,
    })
}

fn accept_record(record: &OperationalRecord) -> Result<Accept, Invalid> {
    let fields = decode(
        "operational-session-accept-v1",
        record.payload(),
        &[2, 3, 2, 2, 2, 2],
    )?;
    role(&fields[1], Role::B)?;
    Ok(Accept {
        attempt: bytes(&fields[0])?,
        session_id: bytes(&fields[2])?,
        open_hash: bytes(&fields[3])?,
        commitment_hash: bytes(&fields[4])?,
        context_hash: bytes(&fields[5])?,
    })
}

fn confirm_record(record: &OperationalRecord, sender: Role) -> Result<Confirm, Invalid> {
    let fields = decode(
        "operational-session-confirm-v1",
        record.payload(),
        &[2, 3, 2, 2, 2],
    )?;
    role(&fields[1], sender)?;
    Ok(Confirm {
        attempt: bytes(&fields[0])?,
        session_id: bytes(&fields[2])?,
        prior_hash: bytes(&fields[3])?,
        confirmation: bytes(&fields[4])?,
    })
}

fn nonzero(bytes: &[u8]) -> Result<(), Invalid> {
    bytes
        .iter()
        .any(|byte| *byte != 0)
        .then_some(())
        .ok_or(Invalid)
}

fn bounded_bytes(value: &Value, limit: usize) -> Result<Vec<u8>, Invalid> {
    match value {
        Value::Bytes(value) if !value.is_empty() && value.len() <= limit => Ok(value.clone()),
        _ => Err(Invalid),
    }
}

/// A sealed endpoint for the distinct V01 operational ALPN.  It is crate-private,
/// owns its strict TLS configuration, and does not expose an arbitrary QUIC
/// connection for adoption or application I/O.
pub(crate) struct OperationalEndpoint {
    endpoint: quinn::Endpoint,
    client: super::provisional_tls::StrictClient,
    local_leaf: [u8; 32],
}

impl OperationalEndpoint {
    pub(crate) fn bind(
        address: SocketAddr,
        certificate: Vec<u8>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Invalid> {
        let local_leaf = hash(&certificate);
        let (server, client) =
            super::provisional_tls::strict_configs(certificate, key, ALPN, 1, 0)?;
        let endpoint = quinn::Endpoint::server(server, address).map_err(|_| Invalid)?;
        Ok(Self {
            endpoint,
            client,
            local_leaf,
        })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, Invalid> {
        self.endpoint.local_addr().map_err(|_| Invalid)
    }

    pub(crate) async fn connect(
        &self,
        peer: SocketAddr,
        expected_peer_pin: [u8; 32],
    ) -> Result<OperationalChannel, Invalid> {
        let (client, auth) = self.client.fresh()?;
        let connecting = self
            .endpoint
            .connect_with(client, peer, "operational.local")
            .map_err(|_| Invalid)?;
        let connection = tokio::time::timeout(Duration::from_secs(30), connecting)
            .await
            .map_err(|_| Invalid)?
            .map_err(|_| Invalid)?;
        if !auth.was_requested() {
            connection.close(APPLICATION_ERROR.into(), b"mutual authentication required");
            return Err(Invalid);
        }
        OperationalChannel::observe(connection, expected_peer_pin)
    }

    pub(crate) async fn accept(
        &self,
        expected_peer_pin: [u8; 32],
    ) -> Result<OperationalChannel, Invalid> {
        let connection = tokio::time::timeout(Duration::from_secs(30), async {
            self.endpoint
                .accept()
                .await
                .ok_or(Invalid)?
                .await
                .map_err(|_| Invalid)
        })
        .await
        .map_err(|_| Invalid)??;
        OperationalChannel::observe(connection, expected_peer_pin)
    }

    pub(crate) async fn connect_admitted(
        &self,
        peer: SocketAddr,
        authority: &super::admission_authority::AdmissionAuthorityStore,
        durable_attempt: [u8; 32],
    ) -> Result<OperationalAttempt, Invalid> {
        let snapshot = authority
            .operational_admission_snapshot(durable_attempt)
            .map_err(|_| Invalid)?;
        let view = AuthorityView::from_snapshot(self.local_leaf, &snapshot)?;
        if view.self_fingerprint >= view.peer_fingerprint {
            return Err(Invalid);
        }
        let channel = self.connect(peer, view.peer_fingerprint).await?;
        OperationalAttempt::new(channel, Role::A, authority, durable_attempt, view).await
    }

    pub(crate) async fn accept_admitted(
        &self,
        authority: &super::admission_authority::AdmissionAuthorityStore,
        durable_attempt: [u8; 32],
    ) -> Result<OperationalAttempt, Invalid> {
        let snapshot = authority
            .operational_admission_snapshot(durable_attempt)
            .map_err(|_| Invalid)?;
        let view = AuthorityView::from_snapshot(self.local_leaf, &snapshot)?;
        if view.self_fingerprint <= view.peer_fingerprint {
            return Err(Invalid);
        }
        let channel = self.accept(view.peer_fingerprint).await?;
        OperationalAttempt::new(channel, Role::B, authority, durable_attempt, view).await
    }
}

impl Drop for OperationalEndpoint {
    fn drop(&mut self) {
        self.endpoint
            .close(APPLICATION_ERROR.into(), b"operational endpoint closed");
    }
}

/// Non-cloneable, non-serializable, selected live TLS connection evidence.
/// No send/receive application-I/O port is exposed by this type.
pub(crate) struct OperationalChannel {
    connection: quinn::Connection,
    observed_peer_fingerprint: [u8; 32],
}

impl OperationalChannel {
    fn observe(
        connection: quinn::Connection,
        expected_peer_pin: [u8; 32],
    ) -> Result<Self, Invalid> {
        let observed = (|| {
            if connection.close_reason().is_some() {
                return Err(Invalid);
            }
            let handshake = connection
                .handshake_data()
                .ok_or(Invalid)?
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .map_err(|_| Invalid)?;
            if handshake.protocol.as_deref() != Some(ALPN) {
                return Err(Invalid);
            }
            let certificates = connection
                .peer_identity()
                .ok_or(Invalid)?
                .downcast::<Vec<CertificateDer<'static>>>()
                .map_err(|_| Invalid)?;
            if certificates.len() != 1 {
                return Err(Invalid);
            }
            let leaf = certificates[0].as_ref();
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Invalid)?
                    .as_secs(),
            )
            .map_err(|_| Invalid)?;
            super::provisional_tls::profile(leaf, now)?;
            let observed: [u8; 32] = Sha256::digest(leaf).into();
            if expected_peer_pin == [0; 32] || observed != expected_peer_pin {
                return Err(Invalid);
            }
            Ok::<_, Invalid>(observed)
        })();
        match observed {
            Ok(observed_peer_fingerprint) => Ok(Self {
                connection,
                observed_peer_fingerprint,
            }),
            Err(error) => {
                connection.close(APPLICATION_ERROR.into(), b"operational TLS rejected");
                Err(error)
            }
        }
    }

    pub(crate) fn observed_peer_fingerprint(&self) -> &[u8; 32] {
        &self.observed_peer_fingerprint
    }

    pub(crate) fn negotiated_alpn(&self) -> &'static [u8] {
        ALPN
    }

    pub(crate) async fn exchange_frozen_schedule(
        &self,
        role: Role,
        records: &[OperationalRecord],
    ) -> Result<(), Invalid> {
        validate_v01_schedule(records)?;
        let connection = self.connection.clone();
        let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(30), async {
            match role {
                Role::A => connection.open_bi().await.map_err(|_| Invalid),
                Role::B => connection.accept_bi().await.map_err(|_| Invalid),
            }
        })
        .await
        .map_err(|_| Invalid)??;
        let expected = records.to_vec();
        let protocol = async {
            for record in &expected {
                if record.sender == role {
                    send.write_all(&record.encode()?)
                        .await
                        .map_err(|_| Invalid)?;
                } else if read_one_record(&mut recv).await? != *record {
                    return Err(Invalid);
                }
            }
            send.finish().map_err(|_| Invalid)?;
            let mut trailing = [0; 1];
            (recv
                .read(&mut trailing)
                .await
                .map_err(|_| Invalid)?
                .is_none())
            .then_some(())
            .ok_or(Invalid)
        };
        tokio::select! {
            result = protocol => result,
            extra = self.connection.accept_bi() => {
                if let Ok((send, recv)) = extra { drop(send); drop(recv); }
                Err(Invalid)
            }
            extra = self.connection.accept_uni() => {
                if let Ok(mut recv) = extra { let _ = recv.stop(APPLICATION_ERROR.into()); }
                Err(Invalid)
            }
        }
    }

    fn exporter(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], Invalid> {
        let mut value = [0; 32];
        self.connection
            .export_keying_material(&mut value, label, context)
            .map_err(|_| Invalid)?;
        Ok(value)
    }
}

/// A sealed, non-cloneable V01 attempt.  Construction is possible only from
/// an atomic durable snapshot and the selected authenticated TLS connection.
pub(crate) struct OperationalAttempt {
    channel: OperationalChannel,
    role: Role,
    view: AuthorityView,
    preflight: crate::pairing_pending::OperationalPreflightLease,
}

/// Watches only for protocol-violating streams after the single V01 stream has
/// been selected.  It never exposes either the connection or a stream handle.
struct ExtraStreamMonitor {
    notified: oneshot::Receiver<()>,
    task: tokio::task::JoinHandle<()>,
}

impl ExtraStreamMonitor {
    fn new(connection: quinn::Connection) -> Self {
        let (send, notified) = oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::select! {
                result = connection.accept_bi() => {
                    if let Ok((send, recv)) = result { drop(send); drop(recv); }
                }
                result = connection.accept_uni() => {
                    if let Ok(mut recv) = result { let _ = recv.stop(APPLICATION_ERROR.into()); }
                }
            }
            let _ = send.send(());
        });
        Self { notified, task }
    }

    fn assert_clear(&mut self) -> Result<(), Invalid> {
        match self.notified.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => Ok(()),
            Ok(()) | Err(oneshot::error::TryRecvError::Closed) => Err(Invalid),
        }
    }
}

impl Drop for ExtraStreamMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl OperationalAttempt {
    async fn new(
        channel: OperationalChannel,
        role: Role,
        authority: &super::admission_authority::AdmissionAuthorityStore,
        durable_attempt: [u8; 32],
        view: AuthorityView,
    ) -> Result<Self, Invalid> {
        let encoded_view = view.encode()?;
        let view_hash = hash(&encoded_view);
        let (a, b) = match role {
            Role::A => (view.self_fingerprint, view.peer_fingerprint),
            Role::B => (view.peer_fingerprint, view.self_fingerprint),
        };
        let context = encode(
            "operational-session-preflight-lease-context-v1",
            &[
                Value::Text("csf12-operational/1".to_owned()),
                Value::Text(
                    match role {
                        Role::A => "A",
                        Role::B => "B",
                    }
                    .to_owned(),
                ),
                Value::Bytes(a.to_vec()),
                Value::Bytes(b.to_vec()),
                Value::Bytes(view_hash.to_vec()),
            ],
        )?;
        let exporter = channel.exporter(
            b"EXPORTER-ControlShiftF12-OperationalPreflightLease-v1",
            &context,
        )?;
        let binding = hash(&encode(
            "operational-session-preflight-lease-binding-v1",
            &[
                Value::Text(
                    match role {
                        Role::A => "A",
                        Role::B => "B",
                    }
                    .to_owned(),
                ),
                Value::Bytes(view_hash.to_vec()),
                Value::Bytes(hash(&context).to_vec()),
                Value::Bytes(hash(&exporter).to_vec()),
            ],
        )?);
        let preflight = authority
            .acquire_operational_preflight_lease(durable_attempt, view_hash, binding)
            .map_err(|_| Invalid)?;
        Ok(Self {
            channel,
            role,
            view,
            preflight,
        })
    }

    /// Runs the dynamic V01 transcript. The only values constructed here are
    /// fresh opaque attempt/session/nonces and the exact durable/TLS bindings.
    pub(crate) async fn complete(self) -> Result<(), Invalid> {
        let mut attempt = [0; 32];
        let mut session = [0; 16];
        let mut nonce_a = [0; 32];
        if self.role == Role::A {
            rand::rngs::OsRng.fill_bytes(&mut attempt);
            rand::rngs::OsRng.fill_bytes(&mut session);
            rand::rngs::OsRng.fill_bytes(&mut nonce_a);
        }
        let (mut send, mut recv) = match self.role {
            Role::A => self
                .channel
                .connection
                .open_bi()
                .await
                .map_err(|_| Invalid)?,
            Role::B => self
                .channel
                .connection
                .accept_bi()
                .await
                .map_err(|_| Invalid)?,
        };
        let mut extra_streams = ExtraStreamMonitor::new(self.channel.connection.clone());
        let first = if self.role == Role::A {
            record(
                0,
                "operational-session-preflight-open-v1",
                &[
                    Value::Bytes(attempt.to_vec()),
                    Value::Text("A".into()),
                    Value::Bytes(session.to_vec()),
                    Value::Bytes(nonce_a.to_vec()),
                    Value::Bytes(self.view.encode()?),
                    Value::Bytes(self.view.self_fingerprint.to_vec()),
                    Value::Bytes(self.view.peer_fingerprint.to_vec()),
                ],
            )?
        } else {
            read_one_record(&mut recv).await?
        };
        if self.role == Role::A {
            send.write_all(&first.encode()?)
                .await
                .map_err(|_| Invalid)?;
        }
        extra_streams.assert_clear()?;
        let a = preflight_open(&first)?;
        if self.role == Role::B {
            attempt = a.attempt;
            session = a.session_id;
            nonce_a = a.nonce_a;
            if !self.view.inverse_of(&a.a_view) {
                return Err(Invalid);
            }
        }
        let mut nonce_b = [0; 32];
        if self.role == Role::B {
            rand::rngs::OsRng.fill_bytes(&mut nonce_b);
        }
        let second = if self.role == Role::B {
            record(
                1,
                "operational-session-preflight-accept-v1",
                &[
                    Value::Bytes(attempt.to_vec()),
                    Value::Text("B".into()),
                    Value::Bytes(session.to_vec()),
                    Value::Bytes(nonce_a.to_vec()),
                    Value::Bytes(nonce_b.to_vec()),
                    Value::Bytes(self.view.encode()?),
                    Value::Bytes(a.a_leaf.to_vec()),
                    Value::Bytes(a.b_leaf.to_vec()),
                ],
            )?
        } else {
            read_one_record(&mut recv).await?
        };
        if self.role == Role::B {
            send.write_all(&second.encode()?)
                .await
                .map_err(|_| Invalid)?;
        }
        extra_streams.assert_clear()?;
        let b = preflight_accept(&second)?;
        if self.role == Role::A {
            nonce_b = b.nonce_b;
            if !self.view.inverse_of(&b.b_view) {
                return Err(Invalid);
            }
        }
        let commitment = authority_commitment(&a.a_view, &b.b_view)?;
        let ch = hash(&commitment);
        let final_lease = self.preflight.promote(ch).map_err(|_| Invalid)?;
        final_lease.assert_current().map_err(|_| Invalid)?;
        let context = exporter_context(a.a_leaf, a.b_leaf, ch, nonce_a, nonce_b)?;
        let cx = hash(&context);
        let exporter = self
            .channel
            .exporter(b"EXPORTER-ControlShiftF12-OperationalSession-v1", &context)?;
        let key = confirm_key(exporter, cx)?;
        let open = if self.role == Role::A {
            record(
                2,
                "operational-session-open-v1",
                &[
                    Value::Bytes(attempt.to_vec()),
                    Value::Text("A".into()),
                    Value::Bytes(session.to_vec()),
                    Value::Bytes(ch.to_vec()),
                    Value::Bytes(cx.to_vec()),
                ],
            )?
        } else {
            read_one_record(&mut recv).await?
        };
        if self.role == Role::A {
            send.write_all(&open.encode()?).await.map_err(|_| Invalid)?;
        }
        extra_streams.assert_clear()?;
        let accept = if self.role == Role::B {
            record(
                3,
                "operational-session-accept-v1",
                &[
                    Value::Bytes(attempt.to_vec()),
                    Value::Text("B".into()),
                    Value::Bytes(session.to_vec()),
                    Value::Bytes(hash(open.payload()).to_vec()),
                    Value::Bytes(ch.to_vec()),
                    Value::Bytes(cx.to_vec()),
                ],
            )?
        } else {
            read_one_record(&mut recv).await?
        };
        if self.role == Role::B {
            send.write_all(&accept.encode()?)
                .await
                .map_err(|_| Invalid)?;
        }
        extra_streams.assert_clear()?;
        let prior = hash(accept.payload());
        let ca = confirmation(&key, Role::A, attempt, session, prior)?;
        let confirm_a = if self.role == Role::A {
            record(
                4,
                "operational-session-confirm-v1",
                &[
                    Value::Bytes(attempt.to_vec()),
                    Value::Text("A".into()),
                    Value::Bytes(session.to_vec()),
                    Value::Bytes(prior.to_vec()),
                    Value::Bytes(ca.to_vec()),
                ],
            )?
        } else {
            read_one_record(&mut recv).await?
        };
        if self.role == Role::A {
            send.write_all(&confirm_a.encode()?)
                .await
                .map_err(|_| Invalid)?;
        }
        extra_streams.assert_clear()?;
        let prior_b = hash(confirm_a.payload());
        let cb = confirmation(&key, Role::B, attempt, session, prior_b)?;
        let confirm_b = if self.role == Role::B {
            record(
                5,
                "operational-session-confirm-v1",
                &[
                    Value::Bytes(attempt.to_vec()),
                    Value::Text("B".into()),
                    Value::Bytes(session.to_vec()),
                    Value::Bytes(prior_b.to_vec()),
                    Value::Bytes(cb.to_vec()),
                ],
            )?
        } else {
            read_one_record(&mut recv).await?
        };
        if self.role == Role::B {
            send.write_all(&confirm_b.encode()?)
                .await
                .map_err(|_| Invalid)?;
        }
        extra_streams.assert_clear()?;
        let records = vec![first, second, open, accept, confirm_a, confirm_b];
        derive_and_verify_confirmation_key(&records, exporter)?;
        final_lease.assert_current().map_err(|_| Invalid)?;
        send.finish().map_err(|_| Invalid)?;
        // A sender must not drop the sealed channel until the peer has also
        // finished its sending half.  Otherwise the final confirmation can be
        // discarded by `OperationalChannel::drop` before the other side reads
        // it.  Any trailing byte is still an immediate protocol violation.
        let mut trailing = [0; 1];
        match recv.read(&mut trailing).await {
            Ok(None) => {}
            // Quinn can surface the peer's final normal application close
            // instead of EOF after it has already consumed both exporter-HMAC
            // confirmations. The transcript check above is therefore the
            // linear evidence that neither confirm was lost; any delivered
            // trailing byte remains a hard failure below.
            Err(quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(_))) => {
            }
            Ok(Some(_)) | Err(_) => return Err(Invalid),
        }
        Ok(())
    }
}

fn record(sequence: u32, kind: &str, fields: &[Value]) -> Result<OperationalRecord, Invalid> {
    OperationalRecord::new(sequence, encode(kind, fields)?)
}
fn confirm_key(exporter: [u8; 32], context: [u8; 32]) -> Result<[u8; 32], Invalid> {
    let mut x = Hmac::<Sha256>::new_from_slice(&context).map_err(|_| Invalid)?;
    x.update(&exporter);
    let p = x.finalize().into_bytes();
    let mut y = Hmac::<Sha256>::new_from_slice(&p).map_err(|_| Invalid)?;
    y.update(b"CSF12 operational session confirm key v1\0");
    y.update(&context);
    y.update(&[1]);
    Ok(y.finalize().into_bytes().into())
}
fn confirmation(
    key: &[u8; 32],
    role: Role,
    attempt: [u8; 32],
    session: [u8; 16],
    prior: [u8; 32],
) -> Result<[u8; 32], Invalid> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Invalid)?;
    m.update(b"CSF12 operational session confirm v1\0");
    m.update(match role {
        Role::A => b"A",
        Role::B => b"B",
    });
    m.update(&attempt);
    m.update(&session);
    m.update(&prior);
    Ok(m.finalize().into_bytes().into())
}

async fn read_one_record(recv: &mut quinn::RecvStream) -> Result<OperationalRecord, Invalid> {
    let mut header = [0; HEADER_LEN];
    recv.read_exact(&mut header).await.map_err(|_| Invalid)?;
    if header[..8] != *MAGIC || header[8..10] != VERSION.to_be_bytes() {
        return Err(Invalid);
    }
    let length = u32::from_be_bytes(header[16..20].try_into().map_err(|_| Invalid)?) as usize;
    if length == 0 || length > RECORD_LIMIT {
        return Err(Invalid);
    }
    let mut raw = header.to_vec();
    let mut payload = vec![0; length];
    recv.read_exact(&mut payload).await.map_err(|_| Invalid)?;
    raw.extend(payload);
    OperationalRecord::decode(&raw)
}

impl Drop for OperationalChannel {
    fn drop(&mut self) {
        // `Connection`'s own last-handle close preserves a peer's already
        // finished final record. Explicit application close here races the
        // reciprocal EOF read that proves both confirmations were consumed.
        // Every fail-closed path still calls `close` explicitly before this
        // wrapper can be returned to the caller.
    }
}
