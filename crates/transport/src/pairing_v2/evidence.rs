//! Pure evidence checks only. Verification is NOT durable completion or admission.
use super::{
    Identity, Invalid, WORDLIST_HASH,
    codec::{Value, decode, encode},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
pub const DOMAIN: &str = "control-shift-f12 pairing v2";
pub const SUITE: &str = "x25519-hkdf-sha256-ed25519-v1";
pub const PROTOCOL: &str = "control-shift-f12-pair/2";
pub const ROLE_MAP: &str = "A=lower-fingerprint;B=higher-fingerprint";
pub const SAS_FORMAT: &str = "words4-bip39-en-v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    A,
    B,
}
impl Role {
    pub fn text(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
    pub(super) fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}
#[derive(Clone)]
pub struct SignedEvidence {
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedEvidence {
    pub fn encode(&self) -> Result<Vec<u8>, Invalid> {
        encode("signed", &[b(&self.body), b(&self.signature)])
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Invalid> {
        let values = decode("signed", bytes, &[2, 2])?;
        Ok(Self {
            body: blob(&values[0])?.to_vec(),
            signature: blob(&values[1])?.to_vec(),
        })
    }
}
pub struct EvidenceContext {
    pub(super) identities: [Identity; 2],
    pub(super) attempt: [u8; 32],
    pub(super) transcript: [u8; 32],
}
pub struct FinalizationEvidence {
    hash: [u8; 32],
}
impl FinalizationEvidence {
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}
pub(crate) fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}
pub(crate) fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}
pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn blob(value: &Value) -> Result<&[u8], Invalid> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(Invalid),
    }
}
fn verify_tag(
    kind: &str,
    record: &SignedEvidence,
    live: Option<(&[u8], &[u8])>,
) -> Result<(), Invalid> {
    if let Some((key, tag)) = live {
        if key.len() != 32 {
            return Err(Invalid);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Invalid)?;
        mac.update(&encode(kind, &[b(&record.body), b(&record.signature)])?);
        mac.verify_slice(tag).map_err(|_| Invalid)?;
    }
    Ok(())
}
impl EvidenceContext {
    /// Expected context only; does not assert a CandidateHello was bound.
    pub fn new(
        identities: [Identity; 2],
        attempt: [u8; 32],
        transcript: [u8; 32],
    ) -> Result<Self, Invalid> {
        if identities[0].fingerprint() >= identities[1].fingerprint()
            || attempt == [0; 32]
            || transcript == [0; 32]
        {
            return Err(Invalid);
        }
        Ok(Self {
            identities,
            attempt,
            transcript,
        })
    }
    pub fn verify_approval(
        &self,
        role: Role,
        record: &SignedEvidence,
        live: Option<(&[u8], &[u8])>,
    ) -> Result<(), Invalid> {
        let expected = encode(
            "human-decision",
            &[
                t(DOMAIN),
                b(&self.attempt),
                b(&self.transcript),
                t(role.text()),
                t("match"),
                Value::Number(1),
            ],
        )?;
        if record.body != expected {
            return Err(Invalid);
        }
        self.identities[role.index()].verify(&record.body, &record.signature)?;
        verify_tag("approve-tag", record, live)
    }
    pub fn both_approved(
        &self,
        a: &SignedEvidence,
        b_record: &SignedEvidence,
    ) -> Result<[u8; 32], Invalid> {
        self.verify_approval(Role::A, a, None)?;
        self.verify_approval(Role::B, b_record, None)?;
        Ok(hash(&encode(
            "both-approved",
            &[
                t(DOMAIN),
                b(&self.transcript),
                b(&a.body),
                b(&a.signature),
                b(&b_record.body),
                b(&b_record.signature),
            ],
        )?))
    }
    pub fn verify_finalization(
        &self,
        phase: &str,
        role: Role,
        p: [u8; 32],
        record: &SignedEvidence,
        live: Option<(&[u8], &[u8])>,
    ) -> Result<(), Invalid> {
        if !matches!(
            (phase, role),
            ("ready", _) | ("commit", Role::A) | ("commit_ack", Role::B) | ("complete", Role::A)
        ) {
            return Err(Invalid);
        }
        let expected = encode(
            "finalization-body",
            &[
                t(DOMAIN),
                t(phase),
                b(&self.attempt),
                b(&self.transcript),
                b(&p),
                t(role.text()),
            ],
        )?;
        if record.body != expected {
            return Err(Invalid);
        }
        self.identities[role.index()].verify(&record.body, &record.signature)?;
        verify_tag("finalization-tag", record, live)
    }
    pub fn verify_fc(&self, bytes: &[u8]) -> Result<FinalizationEvidence, Invalid> {
        let fields = decode(
            "finalization-certificate",
            bytes,
            &[3, 3, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2],
        )?;
        let fingerprints = [
            self.identities[0].fingerprint().as_slice(),
            self.identities[1].fingerprint().as_slice(),
        ]
        .concat();
        if fields[..7]
            != [
                t(PROTOCOL),
                t(SUITE),
                b(&WORDLIST_HASH),
                b(&self.attempt),
                b(&self.transcript),
                t(ROLE_MAP),
                b(&fingerprints),
            ]
        {
            return Err(Invalid);
        }
        let a = SignedEvidence::decode(blob(&fields[7])?)?;
        let b_record = SignedEvidence::decode(blob(&fields[8])?)?;
        let p = self.both_approved(&a, &b_record)?;
        for (index, (phase, role)) in [
            ("ready", Role::A),
            ("ready", Role::B),
            ("commit", Role::A),
            ("commit_ack", Role::B),
            ("complete", Role::A),
        ]
        .into_iter()
        .enumerate()
        {
            self.verify_finalization(
                phase,
                role,
                p,
                &SignedEvidence::decode(blob(&fields[index + 9])?)?,
                None,
            )?;
        }
        Ok(FinalizationEvidence { hash: hash(bytes) })
    }
}
/// V11 addendum codec uses raw bytes32 IDs and variable-length nonce/exporter blobs.
/// NOT an operational recovery request or evidence of local durable FC/channel provenance.
#[derive(Clone)]
pub struct RecoveryFields {
    pub attempt_id: [u8; 32],
    pub fc_hash: [u8; 32],
    pub role: Role,
    pub challenger_nonce: Vec<u8>,
    pub responder_nonce: Vec<u8>,
    pub tls_exporter: Vec<u8>,
    pub identity_generation: u64,
    pub revocation_generation: u64,
}
impl RecoveryFields {
    pub fn encode(&self) -> Result<Vec<u8>, Invalid> {
        if [
            self.challenger_nonce.len(),
            self.responder_nonce.len(),
            self.tls_exporter.len(),
        ]
        .iter()
        .any(|n| *n == 0 || *n > 256)
        {
            return Err(Invalid);
        }
        encode(
            "recovery-proof",
            &[
                t(DOMAIN),
                b(&self.attempt_id),
                b(&self.fc_hash),
                t(self.role.text()),
                b(&self.challenger_nonce),
                b(&self.responder_nonce),
                b(&self.tls_exporter),
                Value::Number(self.identity_generation),
                Value::Number(self.revocation_generation),
                t("fc-durably-stored"),
            ],
        )
    }
}
/// One-use signature check, not a restart/promotion capability.
pub struct RecoverySignatureVerifier {
    fields: RecoveryFields,
    deadline: u64,
    consumed: bool,
}
impl RecoverySignatureVerifier {
    pub fn new(fields: RecoveryFields, deadline: u64) -> Self {
        Self {
            fields,
            deadline,
            consumed: false,
        }
    }
    pub fn verify(
        &mut self,
        key: &[u8; 32],
        sig: &[u8],
        now: u64,
        tombstoned: bool,
    ) -> Result<(), Invalid> {
        if self.consumed || now >= self.deadline || tombstoned {
            return Err(Invalid);
        }
        super::identity::verify_ed25519(key, &self.fields.encode()?, sig)?;
        self.consumed = true;
        Ok(())
    }
}
