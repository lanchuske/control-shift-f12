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
use tokio::{sync::oneshot, time::Instant};

pub(crate) const ALPN: &[u8] = b"csf12-operational/1";
pub(crate) const APPLICATION_ERROR: u32 = 0x4353_4612;
pub(crate) const RECORD_LIMIT: usize = 4096;
pub(crate) const RECORD_COUNT: u32 = 6;
const MAGIC: &[u8; 8] = b"CSF12S1\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 20;
const SUITE: &str = "x25519-hkdf-sha256-ed25519-v1";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

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

fn preconfirm_transcript(
    commitment: &[u8],
    records: &[&OperationalRecord],
) -> Result<[u8; 32], Invalid> {
    if records.len() != 4 {
        return Err(Invalid);
    }
    let mut bytes = b"CSF12-operational-session-preconfirm-v1\0".to_vec();
    bytes.extend(
        u16::try_from(ALPN.len())
            .map_err(|_| Invalid)?
            .to_be_bytes(),
    );
    bytes.extend(ALPN);
    bytes.extend(
        u32::try_from(commitment.len())
            .map_err(|_| Invalid)?
            .to_be_bytes(),
    );
    bytes.extend(commitment);
    bytes.extend(4u32.to_be_bytes());
    for record in records {
        let raw = record.encode()?;
        bytes.extend(u32::try_from(raw.len()).map_err(|_| Invalid)?.to_be_bytes());
        bytes.extend(raw);
    }
    Ok(hash(&bytes))
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
/// One absolute, monotonic attempt budget.  It is intentionally created
/// before the durable snapshot and TLS selection, so neither a slow connect
/// nor a slow local-consent callback can extend the V01 30-second window.
pub(crate) struct AttemptGuard {
    deadline: Instant,
    connection: Option<quinn::Connection>,
    // Once a selected V01 stream exists, its abort owns the ordering: emit
    // RESET_STREAM/STOP_SENDING first and only then close the connection.
    // Closing directly here races those control frames and can hide the
    // stream-level failure from the peer.
    stream_selected: bool,
    complete: bool,
}

impl AttemptGuard {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + ATTEMPT_TIMEOUT,
            connection: None,
            stream_selected: false,
            complete: false,
        }
    }

    pub(crate) async fn within<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, Invalid>>,
    ) -> Result<T, Invalid> {
        if Instant::now() >= self.deadline {
            return Err(Invalid);
        }
        tokio::time::timeout_at(self.deadline, operation)
            .await
            .map_err(|_| Invalid)?
    }

    pub(crate) fn remaining_ms(&self) -> u32 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u128::from(u32::MAX)) as u32
    }

    #[cfg(test)]
    pub(crate) fn test_only_expired() -> Self {
        Self {
            deadline: Instant::now() - Duration::from_millis(1),
            connection: None,
            stream_selected: false,
            complete: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_with_timeout(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            connection: None,
            stream_selected: false,
            complete: false,
        }
    }

    fn assert_lease(
        &self,
        lease: Option<&crate::pairing_pending::OperationalFinalLease>,
    ) -> Result<(), Invalid> {
        if Instant::now() >= self.deadline {
            return Err(Invalid);
        }
        if let Some(lease) = lease {
            lease.assert_current().map_err(|_| Invalid)?;
        }
        Ok(())
    }

    fn attach(&mut self, connection: quinn::Connection) {
        self.connection = Some(connection);
    }

    fn mark_stream_selected(&mut self) {
        self.stream_selected = true;
    }

    fn succeed(&mut self) {
        self.complete = true;
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if !self.complete
            && !self.stream_selected
            && let Some(connection) = &self.connection
        {
            connection.close(APPLICATION_ERROR.into(), b"operational session aborted");
        }
    }
}

pub(crate) struct OperationalEndpoint {
    endpoint: quinn::Endpoint,
    client: super::provisional_tls::StrictClient,
    local_leaf: [u8; 32],
}

impl OperationalEndpoint {
    pub(crate) fn local_fingerprint(&self) -> [u8; 32] {
        self.local_leaf
    }

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
        let guard = AttemptGuard::new();
        self.connect_until(peer, expected_peer_pin, &guard).await
    }

    async fn connect_until(
        &self,
        peer: SocketAddr,
        expected_peer_pin: [u8; 32],
        guard: &AttemptGuard,
    ) -> Result<OperationalChannel, Invalid> {
        let (client, auth) = self.client.fresh()?;
        let connecting = self
            .endpoint
            .connect_with(client, peer, "operational.local")
            .map_err(|_| Invalid)?;
        let connection = guard
            .within(async { connecting.await.map_err(|_| Invalid) })
            .await?;
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
        let guard = AttemptGuard::new();
        self.accept_until(expected_peer_pin, &guard).await
    }

    async fn accept_until(
        &self,
        expected_peer_pin: [u8; 32],
        guard: &AttemptGuard,
    ) -> Result<OperationalChannel, Invalid> {
        let connection = guard
            .within(async {
                self.endpoint
                    .accept()
                    .await
                    .ok_or(Invalid)?
                    .await
                    .map_err(|_| Invalid)
            })
            .await?;
        OperationalChannel::observe(connection, expected_peer_pin)
    }

    pub(crate) async fn connect_admitted(
        &self,
        peer: SocketAddr,
        authority: &super::admission_authority::AdmissionAuthorityStore,
        durable_attempt: [u8; 32],
    ) -> Result<OperationalAttempt, Invalid> {
        let guard = AttemptGuard::new();
        guard.assert_lease(None)?;
        let snapshot = authority
            .operational_admission_snapshot(durable_attempt)
            .map_err(|_| Invalid)?;
        guard.assert_lease(None)?;
        let view = AuthorityView::from_snapshot(self.local_leaf, &snapshot)?;
        if view.self_fingerprint >= view.peer_fingerprint {
            return Err(Invalid);
        }
        guard.assert_lease(None)?;
        let channel = self
            .connect_until(peer, view.peer_fingerprint, &guard)
            .await?;
        OperationalAttempt::new(channel, Role::A, authority, durable_attempt, view, guard).await
    }

    pub(crate) async fn accept_admitted(
        &self,
        authority: &super::admission_authority::AdmissionAuthorityStore,
        durable_attempt: [u8; 32],
    ) -> Result<OperationalAttempt, Invalid> {
        let guard = AttemptGuard::new();
        guard.assert_lease(None)?;
        let snapshot = authority
            .operational_admission_snapshot(durable_attempt)
            .map_err(|_| Invalid)?;
        guard.assert_lease(None)?;
        let view = AuthorityView::from_snapshot(self.local_leaf, &snapshot)?;
        if view.self_fingerprint <= view.peer_fingerprint {
            return Err(Invalid);
        }
        guard.assert_lease(None)?;
        let channel = self.accept_until(view.peer_fingerprint, &guard).await?;
        OperationalAttempt::new(channel, Role::B, authority, durable_attempt, view, guard).await
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

/// Test-only raw transcript harness marker. It is deliberately absent from
/// non-test builds and has no constructor or transport authority there.
#[cfg(test)]
pub(crate) struct TestRawPeer {
    channel: OperationalChannel,
    view: AuthorityView,
}

#[cfg(test)]
impl TestRawPeer {
    pub(crate) fn from_admitted_attempt(mut attempt: OperationalAttempt) -> Self {
        // The test peer takes over this already-authenticated connection; do
        // not let the attempt guard abort it during the ownership transfer.
        attempt.guard.succeed();
        Self {
            channel: attempt.channel,
            view: attempt.view,
        }
    }

    pub(crate) fn from_authenticated_channel(channel: &OperationalChannel) -> Self {
        Self {
            channel: OperationalChannel {
                connection: channel.connection.clone(),
                observed_peer_fingerprint: channel.observed_peer_fingerprint,
            },
            // This constructor is used only by the narrow exporter test; a
            // transcript peer must consume an admitted attempt below.
            view: AuthorityView {
                self_fingerprint: [1; 32],
                peer_fingerprint: [2; 32],
                suite: SUITE.to_owned(),
                protocol_version: 2,
                policy_revision: 0,
                identity_generation: 0,
                revocation_generation: 0,
                receipt_revision: 1,
                admission_attempt: [3; 32],
            },
        }
    }

    pub(crate) async fn accept_bi(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), Invalid> {
        self.channel
            .connection
            .accept_bi()
            .await
            .map_err(|_| Invalid)
    }

    pub(crate) fn exporter(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], Invalid> {
        let mut value = [0; 32];
        self.channel
            .connection
            .export_keying_material(&mut value, label, context)
            .map_err(|_| Invalid)?;
        Ok(value)
    }

    /// Drives the A half only far enough to prove the B driver rejects a
    /// syntactically correct but exporter-HMAC-corrupted Confirm A.  This is
    /// deliberately test-only and owns no product authority.
    pub(crate) async fn send_corrupt_confirm_a(self) -> Result<(), Invalid> {
        let (mut send, mut recv) = self
            .channel
            .connection
            .open_bi()
            .await
            .map_err(|_| Invalid)?;
        let attempt = [41; 32];
        let session = [42; 16];
        let nonce_a = [43; 32];
        let first = record(
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
        )?;
        send.write_all(&first.encode()?)
            .await
            .map_err(|_| Invalid)?;
        let second = read_one_record(&mut recv).await?;
        let b = preflight_accept(&second)?;
        if !self.view.inverse_of(&b.b_view)
            || b.attempt != attempt
            || b.session_id != session
            || b.nonce_a != nonce_a
        {
            return Err(Invalid);
        }
        let commitment = authority_commitment(&self.view, &b.b_view)?;
        let ch = hash(&commitment);
        let context = exporter_context(
            self.view.self_fingerprint,
            self.view.peer_fingerprint,
            ch,
            nonce_a,
            b.nonce_b,
        )?;
        let cx = hash(&context);
        let exporter =
            self.exporter(b"EXPORTER-ControlShiftF12-OperationalSession-v1", &context)?;
        let key = confirm_key(exporter, cx)?;
        let open = record(
            2,
            "operational-session-open-v1",
            &[
                Value::Bytes(attempt.to_vec()),
                Value::Text("A".into()),
                Value::Bytes(session.to_vec()),
                Value::Bytes(ch.to_vec()),
                Value::Bytes(cx.to_vec()),
            ],
        )?;
        send.write_all(&open.encode()?).await.map_err(|_| Invalid)?;
        let accept = read_one_record(&mut recv).await?;
        let accepted = accept_record(&accept)?;
        if accepted.attempt != attempt
            || accepted.session_id != session
            || accepted.open_hash != hash(open.payload())
            || accepted.commitment_hash != ch
            || accepted.context_hash != cx
        {
            return Err(Invalid);
        }
        let prior = hash(accept.payload());
        let mut bad = confirmation(&key, Role::A, attempt, session, prior)?;
        bad[0] ^= 1;
        let confirm_a = record(
            4,
            "operational-session-confirm-v1",
            &[
                Value::Bytes(attempt.to_vec()),
                Value::Text("A".into()),
                Value::Bytes(session.to_vec()),
                Value::Bytes(prior.to_vec()),
                Value::Bytes(bad.to_vec()),
            ],
        )?;
        send.write_all(&confirm_a.encode()?)
            .await
            .map_err(|_| Invalid)?;
        send.finish().map_err(|_| Invalid)?;
        let mut byte = [0; 1];
        let terminal = recv.read(&mut byte).await;
        if !matches!(terminal, Err(quinn::ReadError::Reset(code)) if code == APPLICATION_ERROR.into())
        {
            return Err(Invalid);
        }
        // The reset is the first peer-visible consequence. The connection is
        // then closed with the same application code; accepting only the
        // latter would mask a missing RESET_STREAM/STOP_SENDING.
        matches!(
            tokio::time::timeout(Duration::from_secs(1), self.channel.connection.closed()).await,
            Ok(quinn::ConnectionError::ApplicationClosed(close)) if close.error_code == APPLICATION_ERROR.into()
        )
        .then_some(())
        .ok_or(Invalid)
    }

    /// Sends a complete valid A transcript, FINs its selected stream, and
    /// immediately opens one more bidi stream.  The extra stream is therefore
    /// causally after Confirm A and its FIN, rather than a pre-transcript
    /// race.  A correct B must reject it before reporting success.
    pub(crate) async fn send_valid_confirm_a_then_open_late_stream(self) -> Result<(), Invalid> {
        let (mut send, mut recv) = self
            .channel
            .connection
            .open_bi()
            .await
            .map_err(|_| Invalid)?;
        let attempt = [51; 32];
        let session = [52; 16];
        let nonce_a = [53; 32];
        let first = record(
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
        )?;
        send.write_all(&first.encode()?)
            .await
            .map_err(|_| Invalid)?;
        let second = read_one_record(&mut recv).await?;
        let b = preflight_accept(&second)?;
        if !self.view.inverse_of(&b.b_view)
            || b.attempt != attempt
            || b.session_id != session
            || b.nonce_a != nonce_a
        {
            return Err(Invalid);
        }
        let commitment = authority_commitment(&self.view, &b.b_view)?;
        let ch = hash(&commitment);
        let context = exporter_context(
            self.view.self_fingerprint,
            self.view.peer_fingerprint,
            ch,
            nonce_a,
            b.nonce_b,
        )?;
        let cx = hash(&context);
        let exporter =
            self.exporter(b"EXPORTER-ControlShiftF12-OperationalSession-v1", &context)?;
        let key = confirm_key(exporter, cx)?;
        let open = record(
            2,
            "operational-session-open-v1",
            &[
                Value::Bytes(attempt.to_vec()),
                Value::Text("A".into()),
                Value::Bytes(session.to_vec()),
                Value::Bytes(ch.to_vec()),
                Value::Bytes(cx.to_vec()),
            ],
        )?;
        send.write_all(&open.encode()?).await.map_err(|_| Invalid)?;
        let accept = read_one_record(&mut recv).await?;
        let accepted = accept_record(&accept)?;
        if accepted.attempt != attempt
            || accepted.session_id != session
            || accepted.open_hash != hash(open.payload())
            || accepted.commitment_hash != ch
            || accepted.context_hash != cx
        {
            return Err(Invalid);
        }
        let prior = hash(accept.payload());
        let confirm_a = record(
            4,
            "operational-session-confirm-v1",
            &[
                Value::Bytes(attempt.to_vec()),
                Value::Text("A".into()),
                Value::Bytes(session.to_vec()),
                Value::Bytes(prior.to_vec()),
                Value::Bytes(confirmation(&key, Role::A, attempt, session, prior)?.to_vec()),
            ],
        )?;
        send.write_all(&confirm_a.encode()?)
            .await
            .map_err(|_| Invalid)?;
        send.finish().map_err(|_| Invalid)?;

        // This is the linear finalization adversary: it is opened only after
        // the valid selected stream carries Confirm A and FIN.
        let (mut late_send, mut late_recv) = match self.channel.connection.open_bi().await {
            Ok(pair) => pair,
            // The peer can close its V01 acceptance boundary before QUIC
            // admits the late stream. That is the same fail-closed outcome,
            // but still require the explicit application-close evidence.
            Err(_) => return self.expect_any_application_close().await,
        };
        if late_send.write_all(b"late-v01-stream").await.is_err() {
            return self.expect_any_application_close().await;
        }

        // B may have sent Confirm B before it notices the late stream. It is
        // nevertheless forbidden to complete successfully after this point.
        // Observe either selected stream: the peer may abort the selected
        // stream first or the late stream first, but it must surface the
        // application abort rather than let `complete` succeed.
        let mut late_byte = [0; 1];
        let mut selected_byte = [0; 1];
        let terminal = tokio::select! {
            result = late_recv.read(&mut late_byte) => result,
            result = recv.read(&mut selected_byte) => result,
        };
        match terminal {
            Err(quinn::ReadError::Reset(code)) if code == APPLICATION_ERROR.into() => Ok(()),
            Err(quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(
                close,
            ))) if close.error_code == APPLICATION_ERROR.into() => Ok(()),
            _ => Err(Invalid),
        }
    }

    async fn expect_any_application_close(&self) -> Result<(), Invalid> {
        matches!(
            tokio::time::timeout(Duration::from_secs(1), self.channel.connection.closed()).await,
            Ok(quinn::ConnectionError::ApplicationClosed(_))
        )
        .then_some(())
        .ok_or(Invalid)
    }
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

    #[cfg(test)]
    pub(crate) fn test_only_connection(&self) -> quinn::Connection {
        self.connection.clone()
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
    preflight: Option<crate::pairing_pending::OperationalPreflightLease>,
    guard: AttemptGuard,
}

/// A one-use local approval bound to exactly one V01 preconfirm transcript and
/// durable commitment. It is intentionally non-cloneable and has no public
/// constructor: product UI must provide the reviewed local-gesture adapter.
pub(crate) struct LocalOperationalConsent {
    preconfirm: [u8; 32],
    commitment: [u8; 32],
}

impl LocalOperationalConsent {
    pub(super) fn approved(preconfirm: [u8; 32], commitment: [u8; 32]) -> Self {
        Self {
            preconfirm,
            commitment,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_approved(preconfirm: [u8; 32], commitment: [u8; 32]) -> Self {
        Self::approved(preconfirm, commitment)
    }

    pub(crate) fn matches(&self, preconfirm: [u8; 32], commitment: [u8; 32]) -> bool {
        self.preconfirm == preconfirm && self.commitment == commitment
    }
}

/// Watches only for protocol-violating streams after the single V01 stream has
/// been selected.  It never exposes either the connection or a stream handle.
pub(crate) struct ExtraStreamMonitor {
    notified: oneshot::Receiver<()>,
    primary: Option<oneshot::Receiver<(quinn::SendStream, quinn::RecvStream)>>,
    task: tokio::task::JoinHandle<()>,
}

impl ExtraStreamMonitor {
    /// Starts before the selected V01 stream.  B's monitor owns the first
    /// incoming bidi stream and hands it to the driver exactly once; every
    /// later bidi/uni stream is a protocol violation from the outset.
    pub(crate) fn new(connection: quinn::Connection, role: Role) -> Self {
        let (send, notified) = oneshot::channel();
        let (primary_send, primary) = oneshot::channel();
        let task = tokio::spawn(async move {
            if role == Role::B {
                let primary_stream = tokio::select! {
                    result = connection.accept_bi() => result.ok(),
                    result = connection.accept_uni() => {
                        if let Ok(mut recv) = result { let _ = recv.stop(APPLICATION_ERROR.into()); }
                        None
                    }
                };
                let Some(primary_stream) = primary_stream else {
                    let _ = send.send(());
                    return;
                };
                if primary_send.send(primary_stream).is_err() {
                    let _ = send.send(());
                    return;
                }
            }
            tokio::select! {
                result = connection.accept_bi() => {
                    if let Ok((mut stream_send, mut recv)) = result {
                        let _ = stream_send.reset(APPLICATION_ERROR.into());
                        let _ = recv.stop(APPLICATION_ERROR.into());
                        let _ = send.send(());
                    }
                }
                result = connection.accept_uni() => {
                    if let Ok(mut recv) = result {
                        let _ = recv.stop(APPLICATION_ERROR.into());
                        let _ = send.send(());
                    }
                }
            }
        });
        Self {
            notified,
            primary: (role == Role::B).then_some(primary),
            task,
        }
    }

    async fn take_primary(
        &mut self,
        guard: &AttemptGuard,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), Invalid> {
        let primary = self.primary.take().ok_or(Invalid)?;
        guard
            .within(async { primary.await.map_err(|_| Invalid) })
            .await
    }

    pub(crate) fn assert_clear(&mut self) -> Result<(), Invalid> {
        match self.notified.try_recv() {
            Err(oneshot::error::TryRecvError::Empty) => Ok(()),
            Ok(()) => Err(Invalid),
            // A connection that has cleanly reached EOF makes accept_* return
            // and drops the monitor sender. No additional stream was ever
            // observed, so that is not a protocol violation.
            Err(oneshot::error::TryRecvError::Closed) => Ok(()),
        }
    }

    async fn finish_and_assert_clear(&mut self, guard: &AttemptGuard) -> Result<(), Invalid> {
        // Let a concurrently opened late stream become observable before
        // declaring the FIN boundary clean, without extending the absolute
        // attempt deadline.
        guard
            .within(async {
                tokio::task::yield_now().await;
                self.assert_clear()
            })
            .await
    }
}

impl Drop for ExtraStreamMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Owns the selected stream until the complete V01 transcript and reciprocal
/// EOF have succeeded. Any early return resets both directions, including
/// timeout, consent mismatch, lease revocation and parser rejection.
struct AttemptStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    connection: quinn::Connection,
    clean: bool,
}

impl AttemptStream {
    fn new(pair: (quinn::SendStream, quinn::RecvStream), connection: quinn::Connection) -> Self {
        Self {
            send: pair.0,
            recv: pair.1,
            connection,
            clean: false,
        }
    }

    fn succeed(&mut self) {
        self.clean = true;
    }
}

impl Drop for AttemptStream {
    fn drop(&mut self) {
        if !self.clean {
            let _ = self.send.reset(APPLICATION_ERROR.into());
            let _ = self.recv.stop(APPLICATION_ERROR.into());
            // Quinn queues RESET_STREAM/STOP_SENDING synchronously. Yield
            // once before APPLICATION_ERROR so a malicious peer can observe
            // the stream abort rather than only a connection-close race.
            let connection = self.connection.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                connection.close(APPLICATION_ERROR.into(), b"operational session aborted");
            });
        }
    }
}

impl OperationalAttempt {
    fn assert_preflight_current(&self) -> Result<(), Invalid> {
        self.guard.assert_lease(None)?;
        self.preflight
            .as_ref()
            .ok_or(Invalid)?
            .assert_current()
            .map_err(|_| Invalid)
    }

    async fn new(
        channel: OperationalChannel,
        role: Role,
        authority: &super::admission_authority::AdmissionAuthorityStore,
        durable_attempt: [u8; 32],
        view: AuthorityView,
        mut guard: AttemptGuard,
    ) -> Result<Self, Invalid> {
        // From this point every failure has an authenticated connection to
        // close with the operational application error, even a lease-acquire
        // failure before the selected stream exists.
        guard.attach(channel.connection.clone());
        guard.assert_lease(None)?;
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
        guard.assert_lease(None)?;
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
        guard.assert_lease(None)?;
        preflight.assert_current().map_err(|_| Invalid)?;
        Ok(Self {
            channel,
            role,
            view,
            preflight: Some(preflight),
            guard,
        })
    }

    /// Runs the dynamic V01 transcript. The only values constructed here are
    /// fresh opaque attempt/session/nonces and the exact durable/TLS bindings.
    pub(crate) async fn complete_with_local_consent<F, Future>(
        mut self,
        confirm: F,
    ) -> Result<(), Invalid>
    where
        F: FnOnce([u8; 32], [u8; 32], u32) -> Future,
        Future: std::future::Future<Output = Result<LocalOperationalConsent, Invalid>>,
    {
        let result = self.complete_inner(confirm).await;
        if result.is_ok() {
            self.guard.succeed();
        }
        result
    }

    async fn complete_inner<F, Future>(&mut self, confirm: F) -> Result<(), Invalid>
    where
        F: FnOnce([u8; 32], [u8; 32], u32) -> Future,
        Future: std::future::Future<Output = Result<LocalOperationalConsent, Invalid>>,
    {
        let mut attempt = [0; 32];
        let mut session = [0; 16];
        let mut nonce_a = [0; 32];
        if self.role == Role::A {
            rand::rngs::OsRng.fill_bytes(&mut attempt);
            rand::rngs::OsRng.fill_bytes(&mut session);
            rand::rngs::OsRng.fill_bytes(&mut nonce_a);
        }
        // Start stream surveillance before opening/accepting the sole V01
        // stream. For B the monitor transfers exactly the first bidi stream;
        // a second one is already a failure even if it races the first record.
        let mut extra_streams = ExtraStreamMonitor::new(self.channel.connection.clone(), self.role);
        let pair = match self.role {
            Role::A => {
                self.guard
                    .within(async { self.channel.connection.open_bi().await.map_err(|_| Invalid) })
                    .await?
            }
            Role::B => extra_streams.take_primary(&self.guard).await?,
        };
        let mut stream = AttemptStream::new(pair, self.channel.connection.clone());
        self.guard.mark_stream_selected();
        self.assert_preflight_current()?;
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
            receive_validate(&self.guard, None, &mut extra_streams, &mut stream.recv).await?
        };
        if self.role == Role::A {
            send_checked(
                &self.guard,
                None,
                &mut extra_streams,
                &mut stream.send,
                &first,
            )
            .await?;
        }
        self.assert_preflight_current()?;
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
        self.assert_preflight_current()?;
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
            receive_validate(&self.guard, None, &mut extra_streams, &mut stream.recv).await?
        };
        if self.role == Role::B {
            send_checked(
                &self.guard,
                None,
                &mut extra_streams,
                &mut stream.send,
                &second,
            )
            .await?;
        }
        self.assert_preflight_current()?;
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
        let final_lease = self
            .preflight
            .take()
            .ok_or(Invalid)?
            .promote(ch)
            .map_err(|_| Invalid)?;
        self.guard.assert_lease(Some(&final_lease))?;
        let context = exporter_context(a.a_leaf, a.b_leaf, ch, nonce_a, nonce_b)?;
        let cx = hash(&context);
        let exporter = self
            .channel
            .exporter(b"EXPORTER-ControlShiftF12-OperationalSession-v1", &context)?;
        let key = confirm_key(exporter, cx)?;
        self.guard.assert_lease(Some(&final_lease))?;
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
            receive_validate(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.recv,
            )
            .await?
        };
        if self.role == Role::A {
            send_checked(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.send,
                &open,
            )
            .await?;
        }
        extra_streams.assert_clear()?;
        self.guard.assert_lease(Some(&final_lease))?;
        let checked_open = open_record(&open)?;
        if checked_open.attempt != attempt
            || checked_open.session_id != session
            || checked_open.commitment_hash != ch
            || checked_open.context_hash != cx
        {
            return Err(Invalid);
        }
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
            receive_validate(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.recv,
            )
            .await?
        };
        if self.role == Role::B {
            send_checked(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.send,
                &accept,
            )
            .await?;
        }
        extra_streams.assert_clear()?;
        self.guard.assert_lease(Some(&final_lease))?;
        let checked_accept = accept_record(&accept)?;
        if checked_accept.attempt != attempt
            || checked_accept.session_id != session
            || checked_accept.open_hash != hash(open.payload())
            || checked_accept.commitment_hash != ch
            || checked_accept.context_hash != cx
        {
            return Err(Invalid);
        }
        let preconfirm = preconfirm_transcript(&commitment, &[&first, &second, &open, &accept])?;
        let remaining_ms = self.guard.remaining_ms();
        if remaining_ms == 0 {
            return Err(Invalid);
        }
        let consent = self
            .guard
            .within(confirm(preconfirm, ch, remaining_ms))
            .await?;
        if !consent.matches(preconfirm, ch) {
            return Err(Invalid);
        }
        self.guard.assert_lease(Some(&final_lease))?;
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
            receive_validate(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.recv,
            )
            .await?
        };
        if self.role == Role::A {
            send_checked(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.send,
                &confirm_a,
            )
            .await?;
        }
        extra_streams.assert_clear()?;
        self.guard.assert_lease(Some(&final_lease))?;
        let checked_confirm_a = confirm_record(&confirm_a, Role::A)?;
        if checked_confirm_a.attempt != attempt
            || checked_confirm_a.session_id != session
            || checked_confirm_a.prior_hash != hash(accept.payload())
        {
            return Err(Invalid);
        }
        validate_confirmation(
            &key,
            Role::A,
            attempt,
            session,
            checked_confirm_a.prior_hash,
            checked_confirm_a.confirmation,
        )?;
        // Confirm B is not even constructed until the received Confirm A is
        // parse-valid and exporter-HMAC-valid.
        self.guard.assert_lease(Some(&final_lease))?;
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
            receive_validate(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.recv,
            )
            .await?
        };
        if self.role == Role::B {
            send_checked(
                &self.guard,
                Some(&final_lease),
                &mut extra_streams,
                &mut stream.send,
                &confirm_b,
            )
            .await?;
        }
        extra_streams.assert_clear()?;
        self.guard.assert_lease(Some(&final_lease))?;
        let records = vec![first, second, open, accept, confirm_a, confirm_b];
        derive_and_verify_confirmation_key(&records, exporter)?;
        self.guard.assert_lease(Some(&final_lease))?;
        self.guard
            .within(async { stream.send.finish().map_err(|_| Invalid) })
            .await?;
        // A sender must not drop the sealed channel until the peer has also
        // finished its sending half.  Otherwise the final confirmation can be
        // discarded by `OperationalChannel::drop` before the other side reads
        // it.  Any trailing byte is still an immediate protocol violation.
        let mut trailing = [0; 1];
        match self
            .guard
            .within(async {
                match stream.recv.read(&mut trailing).await {
                    Ok(value) => Ok(value),
                    // At this point both exporter-HMAC confirmations have
                    // already been read and verified. Quinn may surface the
                    // peer's normal last-handle close instead of EOF.
                    Err(quinn::ReadError::ConnectionLost(
                        quinn::ConnectionError::ApplicationClosed(_),
                    )) => Ok(None),
                    Err(_) => Err(Invalid),
                }
            })
            .await?
        {
            None => {}
            // Quinn can surface the peer's final normal application close
            // instead of EOF after it has already consumed both exporter-HMAC
            // confirmations. The transcript check above is therefore the
            // linear evidence that neither confirm was lost; any delivered
            // trailing byte remains a hard failure below.
            Some(_) => return Err(Invalid),
        }
        // This is the linear end-of-session boundary. The sealed driver never
        // hands a live QUIC handle to its caller, so once both sides have
        // exchanged Confirm and FIN there is no permitted follow-on stream.
        // Start an explicit application close *before* releasing the monitor:
        // an extra stream that won the race is observed by the monitor and
        // fails this attempt; one that loses cannot be admitted after this
        // boundary and receives the close instead.
        self.channel
            .connection
            .close(0u32.into(), b"operational session finalized");
        extra_streams.finish_and_assert_clear(&self.guard).await?;
        self.guard.assert_lease(Some(&final_lease))?;
        stream.succeed();
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
pub(crate) fn confirmation(
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

/// Verifies a received confirmation before the reciprocal confirmation is even
/// constructed.  Keeping this separate from transcript derivation prevents a
/// peer-controlled Confirm A from becoming input to Confirm B.
pub(crate) fn validate_confirmation(
    key: &[u8; 32],
    sender: Role,
    attempt: [u8; 32],
    session: [u8; 16],
    prior: [u8; 32],
    received: [u8; 32],
) -> Result<(), Invalid> {
    verify_confirmation(key, sender, attempt, session, prior, received)
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

async fn receive_validate(
    guard: &AttemptGuard,
    lease: Option<&crate::pairing_pending::OperationalFinalLease>,
    monitor: &mut ExtraStreamMonitor,
    recv: &mut quinn::RecvStream,
) -> Result<OperationalRecord, Invalid> {
    guard.assert_lease(lease)?;
    monitor.assert_clear()?;
    let record = guard.within(read_one_record(recv)).await?;
    guard.assert_lease(lease)?;
    monitor.assert_clear()?;
    Ok(record)
}

async fn send_checked(
    guard: &AttemptGuard,
    lease: Option<&crate::pairing_pending::OperationalFinalLease>,
    monitor: &mut ExtraStreamMonitor,
    send: &mut quinn::SendStream,
    record: &OperationalRecord,
) -> Result<(), Invalid> {
    // This is deliberately immediately adjacent to write_all: revocation wins
    // before every emitted record, not merely between transcript stages.
    guard.assert_lease(lease)?;
    monitor.assert_clear()?;
    let encoded = record.encode()?;
    guard
        .within(async { send.write_all(&encoded).await.map_err(|_| Invalid) })
        .await?;
    guard.assert_lease(lease)?;
    monitor.assert_clear()
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
