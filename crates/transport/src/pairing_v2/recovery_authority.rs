//! Recovery verification requires an authoritative persisted context. No source
//! for that context is installed in the application by this experimental slice.
use super::{Invalid, RecoveryFields};
use crate::pairing_pending::{PendingRecord, StoreVersion};

/// Supplied ONLY after validating and durably storing the local role's full FC.
/// Remote generations must come from a previously accepted remote context;
/// they must never be copied/derived from PendingStore's local generations.
#[derive(Clone)]
pub struct RecoveryContext {
    pub challenge_id: [u8; 32],
    pub revision: u64,
    pub local_version: StoreVersion,
    pub pending: PendingRecord,
    pub peer_certificate: Vec<u8>,
    pub peer_node: [u8; 16],
    pub expected: RecoveryFields,
    pub issued_ms: u64,
    pub deadline_ms: u64,
}

/// Must read authoritative durable context and compare revision/context again
/// atomically with consumption. Absence, stale CAS, uncertainty or unsupported
/// persistence MUST return error. No default/in-memory production implementation.
/// The future provider must durably consume the challenge context as well as the
/// exact proof, never reissue a consumed challenge ID, and serialize that action
/// with context replacement/revocation. The test adapter is NOT that provider.
pub trait RecoveryAuthority {
    fn expected(&self, challenge_id: [u8; 32]) -> Result<Option<RecoveryContext>, Invalid>;
    fn consume_if_current(
        &self,
        challenge_id: [u8; 32],
        revision: u64,
        proof: VerifiedRecoveryUse,
    ) -> Result<(), Invalid>;
}

/// Non-forgeable signature-checked consumption request, NOT admission or proof
/// that the authority's expected context has been durably populated correctly.
pub struct VerifiedRecoveryUse {
    pub(crate) fc_hash: [u8; 32],
    pub(crate) peer_role: super::Role,
    pub(crate) local_version: StoreVersion,
    pub(crate) pending: PendingRecord,
    pub(crate) signer: [u8; 32],
    pub(crate) body: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

pub fn verify_authoritative_recovery(
    authority: &impl RecoveryAuthority,
    challenge_id: [u8; 32],
    body: &[u8],
    signature: &[u8],
    monotonic_ms: u64,
    utc_seconds: i64,
) -> Result<(), Invalid> {
    let context = authority.expected(challenge_id)?.ok_or(Invalid)?;
    if context.challenge_id != challenge_id
        || challenge_id == [0; 32]
        || context.pending.attempt_id != context.expected.attempt_id
        || context.expected.fc_hash == [0; 32]
        || monotonic_ms < context.issued_ms
        || monotonic_ms >= context.deadline_ms
        || context
            .deadline_ms
            .checked_sub(context.issued_ms)
            .ok_or(Invalid)?
            > 30_000
        || body.len() > 2048
        || body != context.expected.encode()?
    {
        return Err(Invalid);
    }
    let identity =
        super::validate_identity(&context.peer_certificate, context.peer_node, utc_seconds)?;
    if *identity.fingerprint() != context.pending.peer_fingerprint {
        return Err(Invalid);
    }
    validate_persisted_recovery(body, identity.public_key(), signature)?;
    authority.consume_if_current(
        challenge_id,
        context.revision,
        VerifiedRecoveryUse {
            fc_hash: context.expected.fc_hash,
            peer_role: context.expected.role,
            local_version: context.local_version,
            pending: context.pending,
            signer: *identity.public_key(),
            body: body.to_vec(),
            signature: signature.to_vec(),
        },
    )
}

pub(crate) fn validate_persisted_recovery(
    body: &[u8],
    signer: &[u8; 32],
    signature: &[u8],
) -> Result<[u8; 32], Invalid> {
    use super::{
        DOMAIN,
        codec::{Value, decode},
    };
    if body.len() > 2048 {
        return Err(Invalid);
    }
    let fields = decode("recovery-proof", body, &[3, 2, 2, 3, 2, 2, 2, 1, 1, 3])?;
    if fields[0] != Value::Text(DOMAIN.into())
        || fields[9] != Value::Text("fc-durably-stored".into())
        || !matches!(&fields[3], Value::Text(s) if s == "A" || s == "B")
    {
        return Err(Invalid);
    }
    for index in [1, 2, 4, 5, 6] {
        if !matches!(&fields[index], Value::Bytes(b) if b.len() == 32) {
            return Err(Invalid);
        }
    }
    super::identity::verify_ed25519(signer, body, signature)?;
    let Value::Bytes(attempt) = &fields[1] else {
        return Err(Invalid);
    };
    attempt.as_slice().try_into().map_err(|_| Invalid)
}
