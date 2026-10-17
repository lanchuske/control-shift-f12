//! Quarantined setup metadata. Nothing in this module grants trust or input.
use serde::{Deserialize, Serialize};
#[cfg(feature = "pairing-v2-experimental")]
use sha2::{Digest, Sha256};
use std::path::Path;
#[cfg(feature = "pairing-v2-experimental")]
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("pending storage unavailable")]
    Unavailable,
    #[error("pending storage conflict")]
    Conflict,
    #[error("pairing attempt already consumed")]
    ConsumedAttempt,
    #[error("pairing verification is not implemented in foundations")]
    VerificationUnavailable,
    #[error("invalid pending storage")]
    Invalid,
    #[error("pending storage limit reached")]
    Limit,
    #[error("secure pending storage unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(all(test, feature = "pairing-v2-experimental", any(unix, windows)))]
mod bilateral_admission_state_tests {
    use super::*;

    #[test]
    fn store_owned_awaiting_peer_is_never_operational() {
        let root = tempfile::tempdir().unwrap();
        let store =
            crate::pairing_v2::admission_authority::AdmissionAuthorityStore::open(root.path())
                .unwrap();
        let record = store
            .prepare(store.version().unwrap(), [61; 32], [62; 32])
            .unwrap();
        store
            .commit_operational_test_receipt(&record, [63; 32])
            .unwrap();

        assert_eq!(
            store.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
        let reopened = PendingStore::open(root.path()).unwrap();
        assert_eq!(
            reopened.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn bilateral_transaction_id_changes_when_attempt_or_transcript_changes() {
        let fields = BilateralTransactionFields {
            local_identity: [1; 32],
            peer_identity: [2; 32],
            local_attempt: [3; 32],
            peer_attempt: [4; 32],
            peer_pin: [5; 32],
            transcript: [6; 32],
            suite: crate::pairing_v2::SUITE.to_owned(),
            policy_revision: 0,
        };
        let changed_transcript = BilateralTransactionFields {
            transcript: [7; 32],
            ..fields.clone()
        };
        let changed_attempt = BilateralTransactionFields {
            peer_attempt: [8; 32],
            ..fields.clone()
        };

        assert_ne!(
            derive_bilateral_transaction_id(&fields),
            derive_bilateral_transaction_id(&changed_transcript)
        );
        assert_ne!(
            derive_bilateral_transaction_id(&fields),
            derive_bilateral_transaction_id(&changed_attempt)
        );
    }

    #[test]
    fn inverted_bilateral_perspectives_derive_the_same_transaction_id() {
        let a = BilateralTransactionFields {
            local_identity: [1; 32],
            peer_identity: [2; 32],
            local_attempt: [3; 32],
            peer_attempt: [4; 32],
            peer_pin: [5; 32],
            transcript: [6; 32],
            suite: crate::pairing_v2::SUITE.to_owned(),
            policy_revision: 0,
        };
        let b = BilateralTransactionFields {
            local_identity: a.peer_identity,
            peer_identity: a.local_identity,
            local_attempt: a.peer_attempt,
            peer_attempt: a.local_attempt,
            peer_pin: [7; 32],
            transcript: a.transcript,
            suite: a.suite.clone(),
            policy_revision: a.policy_revision,
        };
        assert_eq!(
            derive_bilateral_transaction_id(&a),
            derive_bilateral_transaction_id(&b)
        );
    }

    fn bilateral_test_receipt() -> AdmissionReceiptRecord {
        let fields = BilateralTransactionFields {
            local_identity: [11; 32],
            peer_identity: [12; 32],
            local_attempt: [13; 32],
            peer_attempt: [14; 32],
            peer_pin: [15; 32],
            transcript: [16; 32],
            suite: crate::pairing_v2::SUITE.to_owned(),
            policy_revision: 0,
        };
        let ownership = AdmissionOwnership::AwaitingHandoff {
            guard_token: [17; 32],
            staged_revision: 1,
        };
        let mut receipt = AdmissionReceiptRecord {
            attempt: fields.local_attempt,
            peer: fields.peer_identity,
            peer_pin: fields.peer_pin,
            durable_fc_hash: [18; 32],
            role: 0,
            suite: fields.suite.clone(),
            protocol_version: 2,
            transcript: fields.transcript,
            binding: [19; 32],
            revision: 1,
            identity_generation: 1,
            revocation_generation: 0,
            policy_revision: fields.policy_revision,
            ownership,
            bilateral: BilateralAdmissionRecord::prepared(&fields, [17; 32], 1, 0, 0),
        };
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        receipt
    }

    #[test]
    fn every_bilateral_descriptor_mutation_or_transaction_id_mutation_is_invalid() {
        let receipt = bilateral_test_receipt();
        assert!(receipt.bilateral.is_well_formed_for(&receipt));

        let mut mutations = vec![];
        let mut local_identity = receipt.clone();
        local_identity.bilateral.fields.local_identity = [21; 32];
        mutations.push(local_identity);
        let mut peer_identity = receipt.clone();
        peer_identity.bilateral.fields.peer_identity = [22; 32];
        mutations.push(peer_identity);
        let mut local_attempt = receipt.clone();
        local_attempt.bilateral.fields.local_attempt = [23; 32];
        mutations.push(local_attempt);
        let mut peer_attempt = receipt.clone();
        peer_attempt.bilateral.fields.peer_attempt = [24; 32];
        mutations.push(peer_attempt);
        let mut peer_pin = receipt.clone();
        peer_pin.bilateral.fields.peer_pin = [25; 32];
        mutations.push(peer_pin);
        let mut transcript = receipt.clone();
        transcript.bilateral.fields.transcript = [26; 32];
        mutations.push(transcript);
        let mut suite = receipt.clone();
        suite.bilateral.fields.suite.push_str("-mutated");
        mutations.push(suite);
        let mut policy = receipt.clone();
        policy.bilateral.fields.policy_revision = 1;
        mutations.push(policy);
        let mut transaction_id = receipt.clone();
        transaction_id.bilateral.transaction_id = BilateralTransactionId([27; 32]);
        mutations.push(transaction_id);

        for mutated in mutations {
            assert!(!mutated.bilateral.is_well_formed_for(&mutated));
        }
    }

    #[test]
    fn receipt_hash_commits_the_transaction_descriptor() {
        let mut receipt = bilateral_test_receipt();
        receipt.bilateral.fields.peer_attempt = [28; 32];
        receipt.bilateral.transaction_id =
            derive_bilateral_transaction_id(&receipt.bilateral.fields);
        assert!(!receipt.bilateral.is_well_formed_for(&receipt));
    }

    #[test]
    fn legacy_receipt_without_bilateral_field_is_rejected() {
        let receipt = bilateral_test_receipt();
        let mut json = serde_json::to_value(receipt).unwrap();
        json.as_object_mut().unwrap().remove("bilateral");
        assert!(serde_json::from_value::<AdmissionReceiptRecord>(json).is_err());
    }

    fn prepared_store_owned_receipt(
        record: &PendingRecord,
        expected: StoreVersion,
    ) -> AdmissionReceiptRecord {
        let revision = expected.revision.checked_add(1).unwrap();
        let ownership = AdmissionOwnership::StoreOwned {
            guard_token: [31; 32],
            staged_revision: expected.revision,
            handoff_revision: revision,
        };
        let fields = BilateralTransactionFields {
            local_identity: [32; 32],
            peer_identity: record.peer_fingerprint,
            local_attempt: record.attempt_id,
            peer_attempt: [33; 32],
            peer_pin: [34; 32],
            transcript: [35; 32],
            suite: crate::pairing_v2::SUITE.to_owned(),
            policy_revision: 0,
        };
        let mut receipt = AdmissionReceiptRecord {
            attempt: record.attempt_id,
            peer: record.peer_fingerprint,
            peer_pin: fields.peer_pin,
            durable_fc_hash: [36; 32],
            role: 0,
            suite: fields.suite.clone(),
            protocol_version: 2,
            transcript: fields.transcript,
            binding: [37; 32],
            revision,
            identity_generation: expected.identity_generation,
            revocation_generation: record.revocation_generation,
            policy_revision: 0,
            ownership,
            bilateral: BilateralAdmissionRecord::prepared(&fields, [31; 32], 0, 0, 0),
        };
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        receipt
    }

    #[test]
    fn local_bilateral_publication_stays_inactive_across_restart() {
        let root = tempfile::tempdir().unwrap();
        let store = PendingStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [41; 32], [42; 32])
            .unwrap();
        let receipt = prepared_store_owned_receipt(&record, store.version().unwrap());
        let published = store
            .publish_local_bilateral_receipt(store.version().unwrap(), &record, receipt)
            .unwrap();
        assert!(matches!(
            published.bilateral.state,
            BilateralAdmissionState::StoreOwnedAwaitingPeer
        ));
        assert_eq!(
            store.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
        let reopened = PendingStore::open(root.path()).unwrap();
        assert_eq!(
            reopened.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn local_bilateral_confirmation_rejects_wrong_transaction_or_receipt_hash() {
        let root = tempfile::tempdir().unwrap();
        let store = PendingStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [43; 32], [44; 32])
            .unwrap();
        let receipt = store
            .publish_local_bilateral_receipt(
                store.version().unwrap(),
                &record,
                prepared_store_owned_receipt(&record, store.version().unwrap()),
            )
            .unwrap();
        assert_eq!(
            store.confirm_bilateral_receipt(
                store.version().unwrap(),
                record.attempt_id,
                BilateralTransactionId([45; 32]),
                receipt.bilateral.local_receipt_hash,
                [46; 32],
            ),
            Err(StoreError::Invalid)
        );
        assert_eq!(
            store.confirm_bilateral_receipt(
                store.version().unwrap(),
                record.attempt_id,
                receipt.bilateral.transaction_id,
                [47; 32],
                [46; 32],
            ),
            Err(StoreError::Invalid)
        );
        let confirmed = store
            .confirm_bilateral_receipt(
                store.version().unwrap(),
                record.attempt_id,
                receipt.bilateral.transaction_id,
                receipt.bilateral.local_receipt_hash,
                [46; 32],
            )
            .unwrap();
        assert!(matches!(
            confirmed.bilateral.state,
            BilateralAdmissionState::BilateralConfirmed
        ));
        assert_eq!(
            store.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
        let reopened = PendingStore::open(root.path()).unwrap();
        assert_eq!(
            reopened.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn delayed_exact_abort_cannot_remove_a_later_same_peer_transaction() {
        let root = tempfile::tempdir().unwrap();
        let store = PendingStore::open(root.path()).unwrap();
        let peer = [49; 32];
        let first = store
            .prepare(store.version().unwrap(), [48; 32], peer)
            .unwrap();
        let first_receipt = store
            .publish_local_bilateral_receipt(
                store.version().unwrap(),
                &first,
                prepared_store_owned_receipt(&first, store.version().unwrap()),
            )
            .unwrap();
        store
            .abort_bilateral_transaction(
                store.version().unwrap(),
                first.attempt_id,
                first_receipt.bilateral.transaction_id,
                first_receipt.bilateral.guard_token,
            )
            .unwrap();

        let second = store
            .prepare(store.version().unwrap(), [50; 32], peer)
            .unwrap();
        let second_receipt = store
            .publish_local_bilateral_receipt(
                store.version().unwrap(),
                &second,
                prepared_store_owned_receipt(&second, store.version().unwrap()),
            )
            .unwrap();
        assert_eq!(
            store.abort_bilateral_transaction(
                store.version().unwrap(),
                first.attempt_id,
                first_receipt.bilateral.transaction_id,
                first_receipt.bilateral.guard_token,
            ),
            Err(StoreError::Invalid)
        );
        let (_, receipt, _) = store.admission_state(second.attempt_id).unwrap();
        assert_eq!(
            receipt.unwrap().bilateral.transaction_id,
            second_receipt.bilateral.transaction_id
        );
        assert_eq!(
            store.operational_admission_snapshot(second.attempt_id),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn timeout_abort_reopens_without_an_operational_admission() {
        let root = tempfile::tempdir().unwrap();
        let store = PendingStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [51; 32], [52; 32])
            .unwrap();
        let receipt = store
            .publish_local_bilateral_receipt(
                store.version().unwrap(),
                &record,
                prepared_store_owned_receipt(&record, store.version().unwrap()),
            )
            .unwrap();
        store
            .abort_bilateral_transaction(
                store.version().unwrap(),
                record.attempt_id,
                receipt.bilateral.transaction_id,
                receipt.bilateral.guard_token,
            )
            .unwrap();

        let reopened = PendingStore::open(root.path()).unwrap();
        assert_eq!(
            reopened.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
        let (pending, receipt, active) = reopened.admission_state(record.attempt_id).unwrap();
        assert!(!pending);
        assert!(receipt.is_none());
        assert!(!active);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreVersion {
    pub revision: u64,
    pub identity_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRecord {
    pub attempt_id: [u8; 32],
    pub peer_fingerprint: [u8; 32],
    pub version: StoreVersion,
    pub revocation_generation: u64,
}

#[cfg(feature = "pairing-v2-experimental")]
const BILATERAL_TRANSACTION_DOMAIN: &[u8] = b"control-shift-f12/admission-v1";

#[cfg(feature = "pairing-v2-experimental")]
const BILATERAL_RECEIPT_DOMAIN: &[u8] = b"control-shift-f12/admission-receipt-v1";

/// Domain-separated identifier for one bilateral admission attempt. It is
/// derived from authenticated handshake data; callers never supply it.
#[cfg(feature = "pairing-v2-experimental")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct BilateralTransactionId([u8; 32]);

#[cfg(feature = "pairing-v2-experimental")]
impl BilateralTransactionId {
    fn is_valid(self) -> bool {
        self.0 != [0; 32]
    }

    pub(crate) fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Result<Self, StoreError> {
        let id = Self(bytes);
        id.is_valid().then_some(id).ok_or(StoreError::Invalid)
    }
}

/// Inputs that determine a bilateral transaction identity and bind the local
/// receipt descriptor. The two identity / attempt pairs are sorted before
/// hashing, so each peer derives the same ID from inverted perspectives.
#[cfg(feature = "pairing-v2-experimental")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BilateralTransactionFields {
    pub(crate) local_identity: [u8; 32],
    pub(crate) peer_identity: [u8; 32],
    pub(crate) local_attempt: [u8; 32],
    pub(crate) peer_attempt: [u8; 32],
    pub(crate) peer_pin: [u8; 32],
    pub(crate) transcript: [u8; 32],
    pub(crate) suite: String,
    pub(crate) policy_revision: u64,
}

#[cfg(feature = "pairing-v2-experimental")]
pub(crate) fn derive_bilateral_transaction_id(
    fields: &BilateralTransactionFields,
) -> BilateralTransactionId {
    let mut sides = [
        (fields.local_identity, fields.local_attempt),
        (fields.peer_identity, fields.peer_attempt),
    ];
    sides.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(BILATERAL_TRANSACTION_DOMAIN);
    for (identity, attempt) in sides {
        digest.update(identity);
        digest.update(attempt);
    }
    digest.update(fields.transcript);
    digest.update((fields.suite.len() as u64).to_be_bytes());
    digest.update(fields.suite.as_bytes());
    digest.update(fields.policy_revision.to_be_bytes());
    BilateralTransactionId(digest.finalize().into())
}

#[cfg(feature = "pairing-v2-experimental")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BilateralAdmissionState {
    Prepared,
    StoreOwnedAwaitingPeer,
    BilateralConfirmed,
    Aborted,
}

/// Durable bilateral status attached to every admission receipt. A local
/// receipt starts prepared, then can become store-owned but remains inactive
/// until a later authenticated peer confirmation changes it to confirmed.
#[cfg(feature = "pairing-v2-experimental")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BilateralAdmissionRecord {
    pub(crate) fields: BilateralTransactionFields,
    pub(crate) transaction_id: BilateralTransactionId,
    pub(crate) state: BilateralAdmissionState,
    pub(crate) local_receipt_hash: [u8; 32],
    pub(crate) peer_receipt_hash: Option<[u8; 32]>,
    pub(crate) guard_token: [u8; 32],
    pub(crate) identity_generation: u64,
    pub(crate) revocation_generation: u64,
    pub(crate) policy_revision: u64,
}

#[cfg(feature = "pairing-v2-experimental")]
impl BilateralAdmissionRecord {
    pub(crate) fn prepared(
        fields: &BilateralTransactionFields,
        guard_token: [u8; 32],
        identity_generation: u64,
        revocation_generation: u64,
        policy_revision: u64,
    ) -> Self {
        Self {
            fields: fields.clone(),
            transaction_id: derive_bilateral_transaction_id(fields),
            state: BilateralAdmissionState::Prepared,
            // Filled from the completed receipt before it reaches the ledger.
            local_receipt_hash: [0; 32],
            peer_receipt_hash: None,
            guard_token,
            identity_generation,
            revocation_generation,
            policy_revision,
        }
    }

    pub(crate) fn bind_local_receipt_hash(&mut self, hash: [u8; 32]) {
        self.local_receipt_hash = hash;
    }

    fn transition_to_store_owned(
        &mut self,
        ownership: &AdmissionOwnership,
    ) -> Result<(), StoreError> {
        if !matches!(self.state, BilateralAdmissionState::Prepared)
            || self.guard_token != ownership.guard_token()
        {
            return Err(StoreError::Invalid);
        }
        self.state = BilateralAdmissionState::StoreOwnedAwaitingPeer;
        Ok(())
    }

    fn is_well_formed_for(&self, receipt: &AdmissionReceiptRecord) -> bool {
        if !self.transaction_id.is_valid()
            || self.transaction_id != derive_bilateral_transaction_id(&self.fields)
            || self.fields.local_identity == [0; 32]
            || self.fields.peer_identity == [0; 32]
            || self.fields.local_attempt == [0; 32]
            || self.fields.peer_attempt == [0; 32]
            || self.fields.peer_pin == [0; 32]
            || self.fields.transcript == [0; 32]
            || self.fields.suite.is_empty()
            || self.fields.policy_revision != self.policy_revision
            || self.fields.local_attempt != receipt.attempt
            || self.fields.peer_identity != receipt.peer
            || self.fields.peer_pin != receipt.peer_pin
            || self.fields.transcript != receipt.transcript
            || self.fields.suite != receipt.suite
            || self.local_receipt_hash == [0; 32]
            || self.guard_token == [0; 32]
            || self.guard_token != receipt.ownership.guard_token()
            || self.identity_generation != receipt.identity_generation
            || self.revocation_generation != receipt.revocation_generation
            || self.policy_revision != receipt.policy_revision
            || self.local_receipt_hash != admission_receipt_hash(receipt)
        {
            return false;
        }
        match self.state {
            BilateralAdmissionState::Prepared => {
                self.peer_receipt_hash.is_none()
                    && matches!(
                        receipt.ownership,
                        AdmissionOwnership::AwaitingHandoff { .. }
                    )
            }
            BilateralAdmissionState::StoreOwnedAwaitingPeer => {
                self.peer_receipt_hash.is_none() && receipt.ownership.is_store_owned()
            }
            BilateralAdmissionState::BilateralConfirmed => {
                self.peer_receipt_hash.is_some_and(|hash| hash != [0; 32])
                    && receipt.ownership.is_store_owned()
            }
            BilateralAdmissionState::Aborted => false,
        }
    }

    fn is_operational_for(&self, _receipt: &AdmissionReceiptRecord) -> bool {
        // `BilateralConfirmed` is durable metadata only until Task 3 supplies
        // an authenticated peer-finalization proof.  A persisted state label
        // and hash are attacker-controlled at rest, so neither may activate
        // an operational snapshot or preflight lease by themselves.
        false
    }
}

#[cfg(feature = "pairing-v2-experimental")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AdmissionOwnership {
    /// The receipt is staged, but its provisional endpoint still owns the
    /// revocation guard. It is never operationally eligible.
    AwaitingHandoff {
        guard_token: [u8; 32],
        staged_revision: u64,
    },
    /// The durable store owns the exact guard after a reviewed handoff.
    StoreOwned {
        guard_token: [u8; 32],
        staged_revision: u64,
        handoff_revision: u64,
    },
}

#[cfg(feature = "pairing-v2-experimental")]
impl AdmissionOwnership {
    pub(crate) fn guard_token(&self) -> [u8; 32] {
        match self {
            Self::AwaitingHandoff { guard_token, .. } | Self::StoreOwned { guard_token, .. } => {
                *guard_token
            }
        }
    }

    fn is_store_owned(&self) -> bool {
        matches!(self, Self::StoreOwned { .. })
    }

    fn is_well_formed_for(&self, receipt_revision: u64) -> bool {
        match self {
            Self::AwaitingHandoff {
                guard_token,
                staged_revision,
            } => *guard_token != [0; 32] && *staged_revision == receipt_revision,
            Self::StoreOwned {
                guard_token,
                staged_revision,
                handoff_revision,
            } => {
                *guard_token != [0; 32]
                    && *staged_revision > 0
                    && *staged_revision < *handoff_revision
                    && *handoff_revision == receipt_revision
            }
        }
    }
}

#[cfg(feature = "pairing-v2-experimental")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionReceiptRecord {
    pub attempt: [u8; 32],
    pub peer: [u8; 32],
    pub peer_pin: [u8; 32],
    pub durable_fc_hash: [u8; 32],
    pub role: u8,
    pub suite: String,
    pub protocol_version: u16,
    pub transcript: [u8; 32],
    pub binding: [u8; 32],
    pub revision: u64,
    pub identity_generation: u64,
    pub revocation_generation: u64,
    pub policy_revision: u64,
    /// No default is intentional: an old receipt can never silently become a
    /// durable admission after this ownership boundary was introduced.
    pub ownership: AdmissionOwnership,
    /// Every receipt belongs to an inactive bilateral transaction until a
    /// later authenticated confirmation explicitly changes its state.
    pub bilateral: BilateralAdmissionRecord,
}

#[cfg(feature = "pairing-v2-experimental")]
fn admission_receipt_hash(receipt: &AdmissionReceiptRecord) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(BILATERAL_RECEIPT_DOMAIN);
    digest.update(receipt.attempt);
    digest.update(receipt.peer);
    digest.update(receipt.peer_pin);
    digest.update(receipt.durable_fc_hash);
    digest.update([receipt.role]);
    digest.update((receipt.suite.len() as u64).to_be_bytes());
    digest.update(receipt.suite.as_bytes());
    digest.update(receipt.protocol_version.to_be_bytes());
    digest.update(receipt.transcript);
    digest.update(receipt.binding);
    digest.update(receipt.identity_generation.to_be_bytes());
    digest.update(receipt.revocation_generation.to_be_bytes());
    digest.update(receipt.policy_revision.to_be_bytes());
    // Revision and ownership are publication-phase metadata. The bilateral
    // proof must remain stable from AwaitingHandoff through StoreOwned, so it
    // commits only the immutable receipt descriptor and bilateral transaction.
    digest.update(receipt.bilateral.transaction_id.0);
    let fields = &receipt.bilateral.fields;
    digest.update(fields.local_identity);
    digest.update(fields.peer_identity);
    digest.update(fields.local_attempt);
    digest.update(fields.peer_attempt);
    digest.update(fields.peer_pin);
    digest.update(fields.transcript);
    digest.update((fields.suite.len() as u64).to_be_bytes());
    digest.update(fields.suite.as_bytes());
    digest.update(fields.policy_revision.to_be_bytes());
    digest.finalize().into()
}

#[cfg(feature = "pairing-v2-experimental")]
pub(crate) fn bind_prepared_bilateral_receipt_hash(receipt: &mut AdmissionReceiptRecord) {
    let hash = admission_receipt_hash(receipt);
    receipt.bilateral.bind_local_receipt_hash(hash);
}

/// Immutable read of a currently active durable admission.  This is a
/// crate-private input to the sealed operational-session boundary, never a
/// runtime-control capability.  In particular, it contains no connection or
/// stream handle and cannot enable input, clipboard, or topology.
#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperationalAdmissionSnapshot {
    pub(crate) receipt: AdmissionReceiptRecord,
    pub(crate) store_revision: u64,
}

/// A local-only preflight lease.  Its token is deliberately process-local and
/// never serialized; dropping it only releases this attempt, never a durable
/// pin or receipt.
#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
pub(crate) struct OperationalPreflightLease {
    store: PendingStore,
    token: [u8; 32],
    snapshot: OperationalAdmissionSnapshot,
    view_hash: [u8; 32],
    connection_binding: [u8; 32],
    live: bool,
}

/// A local-only final lease.  It must be checked before every operational
/// record; a durable revoke/rotation wins by making that check fail closed.
#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
pub(crate) struct OperationalFinalLease {
    store: PendingStore,
    token: [u8; 32],
    snapshot: OperationalAdmissionSnapshot,
    commitment_hash: [u8; 32],
    live: bool,
}

#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationalLeasePhase {
    Preflight {
        view_hash: [u8; 32],
        connection_binding: [u8; 32],
    },
    Final {
        commitment_hash: [u8; 32],
    },
}

#[cfg(feature = "pairing-v2-experimental")]
#[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
#[derive(Clone, Debug)]
struct OperationalLeaseState {
    snapshot: OperationalAdmissionSnapshot,
    phase: OperationalLeasePhase,
}

#[cfg(feature = "pairing-v2-experimental")]
fn operational_leases() -> &'static Mutex<BTreeMap<[u8; 32], OperationalLeaseState>> {
    static LEASES: OnceLock<Mutex<BTreeMap<[u8; 32], OperationalLeaseState>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(feature = "pairing-v2-experimental")]
fn operational_lease_states()
-> std::sync::MutexGuard<'static, BTreeMap<[u8; 32], OperationalLeaseState>> {
    operational_leases()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct PendingStore {
    #[cfg(any(unix, windows))]
    pending_dir: crate::private_fs::PrivateDir,
    #[cfg(any(unix, windows))]
    ledger_dir: crate::private_fs::PrivateDir,
}

#[cfg(feature = "pairing-v2-experimental")]
pub(crate) struct AdmissionRevoker {
    store: PendingStore,
    peer: [u8; 32],
    attempt: [u8; 32],
    token: [u8; 32],
    armed: bool,
    owns_revocation: bool,
}

#[cfg(feature = "pairing-v2-experimental")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionGuardPhase {
    Active,
    RevokingOwned,
    RevokingRetryable,
}

#[cfg(feature = "pairing-v2-experimental")]
pub(crate) struct AdmissionGuardObservation([u8; 32]);

#[cfg(feature = "pairing-v2-experimental")]
impl AdmissionRevoker {
    #[allow(dead_code)] // Consumed by the staged durable handoff in Task 3.
    pub(crate) fn matches_handoff_token(&self, token: [u8; 32]) -> bool {
        self.armed
            && !self.owns_revocation
            && self.token == token
            && token != [0; 32]
            && revocation_guard_phases().get(&token) == Some(&AdmissionGuardPhase::Active)
    }

    pub(crate) fn handoff_token(&self) -> [u8; 32] {
        self.token
    }

    /// The final manifest publication has made this exact guard store-owned.
    /// Disarm before best-effort sidecar cleanup: a cleanup failure must be
    /// reconciled from durable metadata, never turned into a later revocation
    /// by this destructor.
    pub(crate) fn release_to_store(&mut self) -> Result<(), StoreError> {
        if !self.matches_handoff_token(self.token) {
            return Err(StoreError::Invalid);
        }
        self.armed = false;
        self.owns_revocation = false;
        revocation_guard_phases().remove(&self.token);
        self.store
            .clear_admission_guard_exact(self.attempt, self.token)
    }

    pub(crate) fn arm(&mut self) {
        revocation_guard_phases().insert(self.token, AdmissionGuardPhase::Active);
        self.armed = true;
        self.owns_revocation = false;
    }

    pub(crate) fn mark_revoking(&mut self) -> bool {
        if !self.armed {
            return false;
        }
        if self.owns_revocation {
            return true;
        }
        // This registry transition is the revocation linearization point. The
        // mutex is never held across filesystem I/O: it only elects one durable
        // revocation owner, so reconciliation can fail closed without deadlock.
        let mut guards = revocation_guard_phases();
        match guards.get(&self.token) {
            Some(AdmissionGuardPhase::RevokingOwned) => false,
            Some(AdmissionGuardPhase::Active | AdmissionGuardPhase::RevokingRetryable) | None => {
                guards.insert(self.token, AdmissionGuardPhase::RevokingOwned);
                self.owns_revocation = true;
                true
            }
        }
    }

    pub(crate) fn revoke(&mut self) -> Result<(), StoreError> {
        if !self.mark_revoking() {
            return Err(StoreError::Unavailable);
        }
        // Ownership survives after the registry mutex is released. Durable I/O
        // therefore runs lock-free with respect to the in-memory phase machine.
        self.store
            .revoke_current(self.peer, self.attempt, self.token)?;
        self.store
            .clear_admission_guard_exact(self.attempt, self.token)?;
        revocation_guard_phases().remove(&self.token);
        self.armed = false;
        self.owns_revocation = false;
        Ok(())
    }

    /// Cancels only the pending attempt currently owned by this live guard.
    /// This is the pre-staging cleanup path for a prepared bilateral commit;
    /// unlike `revoke`, it never changes peer-scoped revocation state.
    pub(crate) fn cancel_exact(&mut self) -> Result<(), StoreError> {
        if !self.mark_revoking() {
            return Err(StoreError::Unavailable);
        }
        let version = self.store.version()?;
        self.store.cancel(version, self.attempt)?;
        self.store
            .clear_admission_guard_exact(self.attempt, self.token)?;
        revocation_guard_phases().remove(&self.token);
        self.armed = false;
        self.owns_revocation = false;
        Ok(())
    }

    /// Aborts the exact staged bilateral receipt held by this guard.  This is
    /// deliberately narrower than legacy peer-wide revocation so a delayed
    /// endpoint can never damage a newer same-peer admission.
    pub(crate) fn abort_staged_exact(&mut self) -> Result<(), StoreError> {
        if !self.mark_revoking() {
            return Err(StoreError::Unavailable);
        }
        self.store
            .abort_bilateral_guard_exact(self.attempt, self.token)?;
        self.store
            .clear_admission_guard_exact(self.attempt, self.token)?;
        revocation_guard_phases().remove(&self.token);
        self.armed = false;
        self.owns_revocation = false;
        Ok(())
    }

    fn release_for_retry(&mut self) {
        if self.armed && self.owns_revocation {
            revocation_guard_phases().insert(self.token, AdmissionGuardPhase::RevokingRetryable);
            self.owns_revocation = false;
        }
    }
}

#[cfg(feature = "pairing-v2-experimental")]
impl Drop for AdmissionRevoker {
    fn drop(&mut self) {
        if self.armed {
            if !self.owns_revocation {
                let _ = self.mark_revoking();
            }
            self.release_for_retry();
        } else {
            let _ = self
                .store
                .clear_admission_guard_exact(self.attempt, self.token);
        }
    }
}

#[cfg(feature = "pairing-v2-experimental")]
fn revocation_guards() -> &'static Mutex<BTreeMap<[u8; 32], AdmissionGuardPhase>> {
    static GUARDS: OnceLock<Mutex<BTreeMap<[u8; 32], AdmissionGuardPhase>>> = OnceLock::new();
    GUARDS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(feature = "pairing-v2-experimental")]
fn revocation_guard_phases()
-> std::sync::MutexGuard<'static, BTreeMap<[u8; 32], AdmissionGuardPhase>> {
    revocation_guards()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "pairing-v2-experimental")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRevocationGuard {
    attempt: [u8; 32],
    peer: [u8; 32],
    token: [u8; 32],
}

impl PendingStore {
    /// There is intentionally no boolean or caller-supplied "verified" bypass.
    /// A later reviewed protocol must introduce an unforgeable validated-proof type.
    pub fn promote(&self, _attempt: [u8; 32]) -> Result<(), StoreError> {
        Err(StoreError::VerificationUnavailable)
    }
}

#[cfg(any(unix, windows))]
mod unix {
    use super::*;
    use crate::private_fs::PrivateDir;
    #[cfg(feature = "pairing-v2-experimental")]
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    const LEDGER_LIMIT: usize = 512 * 1024;
    const RECORD_LIMIT: usize = 4096;
    const MAX_PENDING: usize = 32;
    const MAX_HISTORY: usize = 1024;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        record: PendingRecord,
        digest: [u8; 32],
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Revocation {
        peer: [u8; 32],
        generation: u64,
    }

    #[cfg(feature = "pairing-v2-experimental")]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ActivePin {
        peer: [u8; 32],
        pin: [u8; 32],
        identity_generation: u64,
        revocation_generation: u64,
    }

    /// One durable reservation per peer while an admission is pending or
    /// awaiting the live-to-store handoff.  StoreOwned admissions use their
    /// active pin as the durable reservation instead.
    #[cfg(feature = "pairing-v2-experimental")]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AdmissionReservation {
        peer: [u8; 32],
        attempt: [u8; 32],
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ledger {
        schema: u32,
        version: StoreVersion,
        pending: Vec<Reference>,
        tombstones: Vec<[u8; 32]>,
        revocations: Vec<Revocation>,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        active_pins: Vec<ActivePin>,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        admission_reservations: Vec<AdmissionReservation>,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        consumed_attempts: Vec<[u8; 32]>,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        admission_receipts: Vec<AdmissionReceiptRecord>,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default)]
        policy_revision: u64,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recoveries: Vec<RecoveryConsumption>,
        #[cfg(feature = "pairing-v2-experimental")]
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        journals: Vec<JournalReference>,
    }

    #[cfg(feature = "pairing-v2-experimental")]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryConsumption {
        signer: [u8; 32],
        body: Vec<u8>,
        signature: Vec<u8>,
    }
    #[cfg(feature = "pairing-v2-experimental")]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JournalReference {
        attempt: [u8; 32],
        revision: u64,
        digest: [u8; 32],
    }
    #[cfg(feature = "pairing-v2-experimental")]
    fn journal_filename(r: &JournalReference) -> String {
        format!("journal-{}-{}", r.revision, filename(r.attempt))
    }

    impl Ledger {
        fn new() -> Self {
            Self {
                schema: 2,
                version: StoreVersion {
                    revision: 0,
                    identity_generation: 0,
                },
                pending: vec![],
                tombstones: vec![],
                revocations: vec![],
                #[cfg(feature = "pairing-v2-experimental")]
                active_pins: vec![],
                #[cfg(feature = "pairing-v2-experimental")]
                admission_reservations: vec![],
                #[cfg(feature = "pairing-v2-experimental")]
                consumed_attempts: vec![],
                #[cfg(feature = "pairing-v2-experimental")]
                admission_receipts: vec![],
                #[cfg(feature = "pairing-v2-experimental")]
                policy_revision: 0,
                #[cfg(feature = "pairing-v2-experimental")]
                recoveries: vec![],
                #[cfg(feature = "pairing-v2-experimental")]
                journals: vec![],
            }
        }
        fn validate(&self) -> Result<(), StoreError> {
            #[cfg(feature = "pairing-v2-experimental")]
            {
                if self.active_pins.len() > MAX_HISTORY
                    || self.admission_reservations.len() > MAX_PENDING
                    || self.consumed_attempts.len() > MAX_HISTORY
                    || self.admission_receipts.len() > MAX_HISTORY
                {
                    return Err(StoreError::Invalid);
                }
                let pins: BTreeSet<_> = self.active_pins.iter().map(|p| p.peer).collect();
                let reserved_peers: BTreeSet<_> = self
                    .admission_reservations
                    .iter()
                    .map(|reservation| reservation.peer)
                    .collect();
                let reserved_attempts: BTreeSet<_> = self
                    .admission_reservations
                    .iter()
                    .map(|reservation| reservation.attempt)
                    .collect();
                if pins.len() != self.active_pins.len()
                    || reserved_peers.len() != self.admission_reservations.len()
                    || reserved_attempts.len() != self.admission_reservations.len()
                    || self.admission_reservations.iter().any(|reservation| {
                        reservation.peer == [0; 32]
                            || reservation.attempt == [0; 32]
                            || !self.pending.iter().any(|pending| {
                                pending.record.attempt_id == reservation.attempt
                                    && pending.record.peer_fingerprint == reservation.peer
                            }) && !self.admission_receipts.iter().any(|receipt| {
                                receipt.attempt == reservation.attempt
                                    && receipt.peer == reservation.peer
                                    && matches!(
                                        receipt.ownership,
                                        AdmissionOwnership::AwaitingHandoff { .. }
                                    )
                                    && receipt.identity_generation
                                        == self.version.identity_generation
                                    && receipt.revocation_generation
                                        == self.revocation(receipt.peer)
                            })
                    })
                    || self.pending.iter().any(|pending| {
                        !self.admission_reservations.iter().any(|reservation| {
                            reservation.attempt == pending.record.attempt_id
                                && reservation.peer == pending.record.peer_fingerprint
                        })
                    })
                    || self.admission_receipts.iter().any(|receipt| {
                        matches!(
                            receipt.ownership,
                            AdmissionOwnership::AwaitingHandoff { .. }
                        ) && receipt.identity_generation == self.version.identity_generation
                            && receipt.revocation_generation == self.revocation(receipt.peer)
                            && !self.admission_reservations.iter().any(|reservation| {
                                reservation.attempt == receipt.attempt
                                    && reservation.peer == receipt.peer
                            })
                    })
                    || self.active_pins.iter().any(|p| {
                        p.peer == [0; 32]
                            || p.pin == [0; 32]
                            || p.identity_generation != self.version.identity_generation
                            || p.revocation_generation != self.revocation(p.peer)
                    })
                {
                    return Err(StoreError::Invalid);
                }
                let consumed: BTreeSet<_> = self.consumed_attempts.iter().copied().collect();
                if consumed.len() != self.consumed_attempts.len()
                    || self.consumed_attempts.contains(&[0; 32])
                {
                    return Err(StoreError::Invalid);
                }
                let receipts: BTreeSet<_> = self
                    .admission_receipts
                    .iter()
                    .map(|receipt| receipt.attempt)
                    .collect();
                let receipt_revisions: BTreeSet<_> = self
                    .admission_receipts
                    .iter()
                    .map(|receipt| receipt.revision)
                    .collect();
                let receipt_guard_tokens: BTreeSet<_> = self
                    .admission_receipts
                    .iter()
                    .map(|receipt| receipt.ownership.guard_token())
                    .collect();
                if receipts.len() != self.admission_receipts.len()
                    || receipt_revisions.len() != self.admission_receipts.len()
                    || receipt_guard_tokens.len() != self.admission_receipts.len()
                    || receipts != consumed
                    || self.admission_receipts.iter().any(|receipt| {
                        receipt.peer == [0; 32]
                            || receipt.peer_pin == [0; 32]
                            || receipt.durable_fc_hash == [0; 32]
                            || receipt.transcript == [0; 32]
                            || receipt.binding == [0; 32]
                            || receipt.role > 1
                            || receipt.suite != crate::pairing_v2::SUITE
                            || receipt.protocol_version
                                != crate::pairing_v2::admission_authority::PROTOCOL_VERSION
                            || receipt.revision == 0
                            || receipt.revision > self.version.revision
                            || !receipt.ownership.is_well_formed_for(receipt.revision)
                            || !receipt.bilateral.is_well_formed_for(receipt)
                            || receipt.identity_generation > self.version.identity_generation
                            || receipt.policy_revision
                                != crate::pairing_v2::admission_authority::POLICY_REVISION
                            || receipt.policy_revision != self.policy_revision
                            || receipt.revocation_generation > self.revocation(receipt.peer)
                    })
                    || self.active_pins.iter().any(|pin| {
                        !self.admission_receipts.iter().any(|receipt| {
                            receipt.peer == pin.peer
                                && receipt.peer_pin == pin.pin
                                && receipt.identity_generation == pin.identity_generation
                                && receipt.revocation_generation == pin.revocation_generation
                                && receipt.ownership.is_store_owned()
                        })
                    })
                    || self
                        .pending
                        .iter()
                        .any(|p| consumed.contains(&p.record.attempt_id))
                    || self
                        .tombstones
                        .iter()
                        .any(|attempt| consumed.contains(attempt))
                {
                    return Err(StoreError::Invalid);
                }
                if self.recoveries.len() > MAX_HISTORY {
                    return Err(StoreError::Invalid);
                }
                let mut unique = BTreeSet::new();
                for proof in &self.recoveries {
                    crate::pairing_v2::validate_persisted_recovery(
                        &proof.body,
                        &proof.signer,
                        &proof.signature,
                    )
                    .map_err(|_| StoreError::Invalid)?;
                    if !unique.insert((proof.signer, &proof.body)) {
                        return Err(StoreError::Invalid);
                    }
                }
                if self.journals.len() > MAX_PENDING {
                    return Err(StoreError::Invalid);
                };
                let mut attempts = BTreeSet::new();
                for reference in &self.journals {
                    if !attempts.insert(reference.attempt)
                        || reference.revision > self.version.revision
                        || !self
                            .pending
                            .iter()
                            .any(|p| p.record.attempt_id == reference.attempt)
                    {
                        return Err(StoreError::Invalid);
                    };
                }
            }
            if self.schema != 2
                || self.pending.len() > MAX_PENDING
                || self.tombstones.len() > MAX_HISTORY
                || self.revocations.len() > MAX_HISTORY
            {
                return Err(StoreError::Invalid);
            }
            let tombstones: BTreeSet<_> = self.tombstones.iter().collect();
            if tombstones.len() != self.tombstones.len() {
                return Err(StoreError::Invalid);
            }
            let mut attempts = BTreeSet::new();
            for entry in &self.pending {
                let record = &entry.record;
                if !attempts.insert(record.attempt_id)
                    || tombstones.contains(&record.attempt_id)
                    || record.attempt_id == [0; 32]
                    || record.peer_fingerprint == [0; 32]
                    || record.version.identity_generation != self.version.identity_generation
                    || record.version.revision > self.version.revision
                    || record.revocation_generation != self.revocation(record.peer_fingerprint)
                {
                    return Err(StoreError::Invalid);
                }
            }
            let mut peers = BTreeSet::new();
            for value in &self.revocations {
                if value.peer == [0; 32] || value.generation == 0 || !peers.insert(value.peer) {
                    return Err(StoreError::Invalid);
                }
            }
            Ok(())
        }
        fn revocation(&self, peer: [u8; 32]) -> u64 {
            self.revocations
                .iter()
                .find(|r| r.peer == peer)
                .map_or(0, |r| r.generation)
        }
        fn advance(&mut self, expected: StoreVersion) -> Result<(), StoreError> {
            if self.version != expected {
                return Err(StoreError::Conflict);
            }
            self.version.revision = self
                .version
                .revision
                .checked_add(1)
                .ok_or(StoreError::Limit)?;
            Ok(())
        }
    }

    fn filename(attempt: [u8; 32]) -> String {
        format!(
            "{}.json",
            attempt
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    #[cfg(feature = "pairing-v2-experimental")]
    fn admission_guard_filename(attempt: [u8; 32]) -> String {
        format!(
            "admission-revocation-{}.json",
            attempt
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    impl PendingStore {
        #[cfg(feature = "pairing-v2-experimental")]
        fn clone_for_operational_lease(&self) -> Result<Self, StoreError> {
            Ok(Self {
                pending_dir: self.pending_dir.try_clone()?,
                ledger_dir: self.ledger_dir.try_clone()?,
            })
        }

        #[cfg(feature = "pairing-v2-experimental")]
        fn current_operational_snapshot(
            &self,
            attempt: [u8; 32],
        ) -> Result<OperationalAdmissionSnapshot, StoreError> {
            if attempt == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let _lock = self.ledger_dir.lock()?;
            let ledger = self.load_validated_manifest()?;
            let receipt = ledger
                .admission_receipts
                .iter()
                .find(|receipt| receipt.attempt == attempt)
                .cloned()
                .ok_or(StoreError::Invalid)?;
            let active = receipt.identity_generation == ledger.version.identity_generation
                && receipt.revocation_generation == ledger.revocation(receipt.peer)
                && receipt.policy_revision == ledger.policy_revision
                && receipt.ownership.is_store_owned()
                && receipt.bilateral.is_operational_for(&receipt)
                && ledger.active_pins.iter().any(|pin| {
                    pin.peer == receipt.peer
                        && pin.pin == receipt.peer_pin
                        && pin.identity_generation == receipt.identity_generation
                        && pin.revocation_generation == receipt.revocation_generation
                });
            active
                .then_some(OperationalAdmissionSnapshot {
                    receipt,
                    store_revision: ledger.version.revision,
                })
                .ok_or(StoreError::Invalid)
        }

        /// Acquires a process-local operational preflight lease only after one
        /// atomic durable snapshot read.  The lease is never serialized and an
        /// ordinary drop merely forgets the local token.
        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn acquire_operational_preflight_lease(
            &self,
            attempt: [u8; 32],
            view_hash: [u8; 32],
            connection_binding: [u8; 32],
        ) -> Result<OperationalPreflightLease, StoreError> {
            if view_hash == [0; 32] || connection_binding == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let snapshot = self.current_operational_snapshot(attempt)?;
            let store = self.clone_for_operational_lease()?;
            let mut token = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut token);
            if token == [0; 32] {
                return Err(StoreError::Unavailable);
            }
            let mut leases = operational_lease_states();
            if leases.contains_key(&token) {
                return Err(StoreError::Unavailable);
            }
            leases.insert(
                token,
                OperationalLeaseState {
                    snapshot: snapshot.clone(),
                    phase: OperationalLeasePhase::Preflight {
                        view_hash,
                        connection_binding,
                    },
                },
            );
            Ok(OperationalPreflightLease {
                store,
                token,
                snapshot,
                view_hash,
                connection_binding,
                live: true,
            })
        }

        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn operational_admission_snapshot(
            &self,
            attempt: [u8; 32],
        ) -> Result<OperationalAdmissionSnapshot, StoreError> {
            self.current_operational_snapshot(attempt)
        }

        #[cfg(feature = "pairing-v2-experimental")]
        #[allow(dead_code)] // Used by the sealed final lease once the V01 driver is wired.
        fn operational_snapshot_still_current(
            &self,
            snapshot: &OperationalAdmissionSnapshot,
        ) -> Result<bool, StoreError> {
            Ok(self.current_operational_snapshot(snapshot.receipt.attempt)? == *snapshot)
        }

        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn admission_revoker(
            &self,
            peer: [u8; 32],
            attempt: [u8; 32],
        ) -> Result<AdmissionRevoker, StoreError> {
            if peer == [0; 32] || attempt == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let mut token = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut token);
            if token == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let guard = AdmissionRevocationGuard {
                attempt,
                peer,
                token,
            };
            let bytes = serde_json::to_vec(&guard).map_err(|_| StoreError::Invalid)?;
            self.ledger_dir
                .replace(&admission_guard_filename(attempt), &bytes)?;
            Ok(AdmissionRevoker {
                store: PendingStore {
                    pending_dir: self.pending_dir.try_clone()?,
                    ledger_dir: self.ledger_dir.try_clone()?,
                },
                peer,
                attempt,
                token,
                armed: false,
                owns_revocation: false,
            })
        }

        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn clear_admission_guard_exact(
            &self,
            attempt: [u8; 32],
            token: [u8; 32],
        ) -> Result<(), StoreError> {
            if token == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let _lock = self.ledger_dir.lock()?;
            let file = admission_guard_filename(attempt);
            let Some(bytes) = self.ledger_dir.read(&file, RECORD_LIMIT)? else {
                return Ok(());
            };
            let guard: AdmissionRevocationGuard =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
            if guard.attempt != attempt || guard.token != token {
                return Err(StoreError::Invalid);
            }
            #[cfg(all(test, feature = "pairing-v2-experimental"))]
            crate::private_fs::faults::point(&file, "before_remove")?;
            self.ledger_dir.remove(&file)?;
            #[cfg(all(test, feature = "pairing-v2-experimental"))]
            crate::private_fs::faults::point(&file, "after_remove")?;
            Ok(())
        }

        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn resolve_admission_guard(
            &self,
            attempt: [u8; 32],
        ) -> Result<Option<AdmissionGuardObservation>, StoreError> {
            let file = admission_guard_filename(attempt);
            let Some(bytes) = self.ledger_dir.read(&file, RECORD_LIMIT)? else {
                return Ok(None);
            };
            let guard: AdmissionRevocationGuard =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
            if guard.attempt != attempt || guard.peer == [0; 32] || guard.token == [0; 32] {
                return Err(StoreError::Invalid);
            }
            match revocation_guard_phases().get(&guard.token).copied() {
                Some(AdmissionGuardPhase::Active) => {
                    return Ok(Some(AdmissionGuardObservation(guard.token)));
                }
                Some(AdmissionGuardPhase::RevokingOwned) => {
                    return Err(StoreError::Unavailable);
                }
                Some(AdmissionGuardPhase::RevokingRetryable) => {}
                None => {
                    // The guard could have been removed after the first read by
                    // a revocation that just completed in this process. Re-read
                    // before treating an unknown token as crash recovery.
                    if self.ledger_dir.read(&file, RECORD_LIMIT)?.is_none() {
                        return Ok(None);
                    }
                }
            }
            // After a process restart there is no in-memory phase entry.  The
            // ledger therefore makes the sole durable ownership decision. An
            // exact AwaitingHandoff receipt is still a live transaction, so
            // it can be aborted by its immutable sidecar token without the
            // legacy peer-wide revocation path. An exact StoreOwned record
            // only needs stale-sidecar cleanup; every ambiguous state remains
            // conservative and is revoked below.
            let (store_owns_guard, staged_owns_guard) = {
                let _lock = self.ledger_dir.lock()?;
                let ledger = self.load_validated_manifest()?;
                let store_owns_guard = ledger.admission_receipts.iter().any(|receipt| {
                    receipt.attempt == guard.attempt
                        && receipt.peer == guard.peer
                        && matches!(
                            receipt.ownership,
                            AdmissionOwnership::StoreOwned { guard_token, .. }
                                if guard_token == guard.token
                        )
                        && receipt.identity_generation == ledger.version.identity_generation
                        && receipt.revocation_generation == ledger.revocation(receipt.peer)
                        && ledger.active_pins.iter().any(|pin| {
                            pin.peer == receipt.peer
                                && pin.pin == receipt.peer_pin
                                && pin.identity_generation == receipt.identity_generation
                                && pin.revocation_generation == receipt.revocation_generation
                        })
                });
                let staged_owns_guard = ledger.admission_receipts.iter().any(|receipt| {
                    receipt.attempt == guard.attempt
                        && receipt.peer == guard.peer
                        && receipt.bilateral.guard_token == guard.token
                        && matches!(
                            receipt.ownership,
                            AdmissionOwnership::AwaitingHandoff { guard_token, .. }
                                if guard_token == guard.token
                        )
                        && receipt.identity_generation == ledger.version.identity_generation
                        && receipt.revocation_generation == ledger.revocation(receipt.peer)
                        && ledger.admission_reservations.iter().any(|reservation| {
                            reservation.attempt == guard.attempt
                                && reservation.peer == guard.peer
                        })
                });
                (store_owns_guard, staged_owns_guard)
            };
            if store_owns_guard {
                self.clear_admission_guard_exact(attempt, guard.token)?;
                revocation_guard_phases().remove(&guard.token);
                return Ok(None);
            }
            if staged_owns_guard {
                self.abort_bilateral_guard_exact(attempt, guard.token)?;
                self.clear_admission_guard_exact(attempt, guard.token)?;
                revocation_guard_phases().remove(&guard.token);
                return Ok(None);
            }
            let mut revoker = AdmissionRevoker {
                store: PendingStore {
                    pending_dir: self.pending_dir.try_clone()?,
                    ledger_dir: self.ledger_dir.try_clone()?,
                },
                peer: guard.peer,
                attempt,
                token: guard.token,
                armed: true,
                owns_revocation: false,
            };
            revoker.revoke()?;
            Ok(None)
        }

        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn admission_guard_still_active(
            &self,
            observation: &AdmissionGuardObservation,
        ) -> bool {
            revocation_guard_phases().get(&observation.0) == Some(&AdmissionGuardPhase::Active)
        }

        #[cfg(feature = "pairing-v2-experimental")]
        pub(super) fn revoke_current(
            &self,
            peer: [u8; 32],
            attempt: [u8; 32],
            token: [u8; 32],
        ) -> Result<(), StoreError> {
            #[cfg(all(test, feature = "pairing-v2-experimental"))]
            crate::private_fs::faults::point("ledger.json", "before_revoke_lock")?;
            let _lock = self.ledger_dir.lock()?;
            #[cfg(all(test, feature = "pairing-v2-experimental"))]
            crate::private_fs::faults::point("ledger.json", "before_revoke_load")?;
            let mut ledger = self.load_validated_manifest()?;
            if peer == [0; 32] || attempt == [0; 32] || token == [0; 32] {
                return Err(StoreError::Invalid);
            }
            // A delayed endpoint may still hold an old guard after its attempt
            // was cancelled and another attempt for this peer completed. Only
            // the exact current reservation (or staged receipt with the same
            // guard token) can revoke peer-scoped metadata. Everything else is
            // stale and is limited to exact sidecar cleanup by the caller.
            let owns_pending = ledger.pending.iter().any(|entry| {
                entry.record.attempt_id == attempt
                    && entry.record.peer_fingerprint == peer
                    && ledger.admission_reservations.iter().any(|reservation| {
                        reservation.attempt == attempt && reservation.peer == peer
                    })
            });
            let owns_staged = ledger.admission_receipts.iter().any(|receipt| {
                receipt.attempt == attempt
                    && receipt.peer == peer
                    && receipt.identity_generation == ledger.version.identity_generation
                    && receipt.revocation_generation == ledger.revocation(peer)
                    && matches!(
                        receipt.ownership,
                        AdmissionOwnership::AwaitingHandoff { guard_token, .. }
                            if guard_token == token
                    )
                    && ledger.admission_reservations.iter().any(|reservation| {
                        reservation.attempt == attempt && reservation.peer == peer
                    })
            });
            if !owns_pending && !owns_staged {
                return Ok(());
            }
            let expected = ledger.version;
            ledger.advance(expected)?;
            if let Some(revocation) = ledger.revocations.iter_mut().find(|r| r.peer == peer) {
                revocation.generation = revocation
                    .generation
                    .checked_add(1)
                    .ok_or(StoreError::Limit)?;
            } else {
                ledger.revocations.push(Revocation {
                    peer,
                    generation: 1,
                });
            }
            ledger.active_pins.retain(|pin| pin.peer != peer);
            ledger
                .admission_reservations
                .retain(|reservation| reservation.peer != peer);
            let removed: Vec<_> = ledger
                .pending
                .iter()
                .filter(|entry| entry.record.peer_fingerprint == peer)
                .map(|entry| entry.record.attempt_id)
                .collect();
            let old_journals: Vec<_> = ledger
                .journals
                .iter()
                .filter(|entry| removed.contains(&entry.attempt))
                .map(journal_filename)
                .collect();
            ledger
                .pending
                .retain(|entry| entry.record.peer_fingerprint != peer);
            ledger
                .journals
                .retain(|entry| !removed.contains(&entry.attempt));
            ledger.tombstones.extend(&removed);
            self.save(&ledger)?;
            for attempt in removed {
                #[cfg(all(test, feature = "pairing-v2-experimental"))]
                crate::private_fs::faults::point("ledger.json", "before_revoke_remove")?;
                self.pending_dir.remove(&filename(attempt))?;
            }
            for file in old_journals {
                #[cfg(all(test, feature = "pairing-v2-experimental"))]
                crate::private_fs::faults::point("ledger.json", "before_revoke_cleanup")?;
                self.pending_dir.remove(&file)?;
            }
            Ok(())
        }
        #[cfg(feature = "pairing-v2-experimental")]
        pub fn reconcile_pairing(
            &self,
            attempt: [u8; 32],
            clock: Option<crate::pairing_v2::JournalClock>,
        ) -> Result<crate::pairing_v2::ReconcileOutcome, StoreError> {
            use crate::pairing_v2::{ReconcileOutcome, RecoveryJournal};
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            if !ledger
                .pending
                .iter()
                .any(|r| r.record.attempt_id == attempt)
            {
                return Err(StoreError::Invalid);
            };
            let reference = ledger.journals.iter().find(|r| r.attempt == attempt);
            let old_file = reference.map(journal_filename);
            if let Some(reference) = reference {
                let journal = self.read_journal(reference)?;
                if let Some(now) = clock
                    && journal.retained(now)
                {
                    return Ok(ReconcileOutcome::RecoveryOnly(Box::new(RecoveryJournal {
                        journal,
                    })));
                }
            }
            let version = ledger.version;
            ledger.advance(version)?;
            ledger.pending.retain(|r| r.record.attempt_id != attempt);
            ledger.journals.retain(|r| r.attempt != attempt);
            ledger.tombstones.push(attempt);
            self.save(&ledger)?;
            self.pending_dir.remove(&filename(attempt))?;
            if let Some(file) = old_file {
                self.pending_dir.remove(&file)?;
            }
            Ok(ReconcileOutcome::Discarded)
        }
        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn persist_pairing_journal(
            &self,
            expected: StoreVersion,
            journal: &crate::pairing_v2::PublicJournal,
        ) -> Result<(), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            ledger.advance(expected)?;
            let record = &ledger
                .pending
                .iter()
                .find(|r| r.record.attempt_id == journal.pending.attempt_id)
                .ok_or(StoreError::Invalid)?
                .record;
            if *record != journal.pending {
                return Err(StoreError::Conflict);
            };
            journal.validate().map_err(|_| StoreError::Invalid)?;
            let previous = ledger
                .journals
                .iter()
                .find(|r| r.attempt == record.attempt_id);
            let old_file = previous.map(journal_filename);
            if let Some(reference) = previous {
                let old = self.read_journal(reference)?;
                if !journal.follows(&old) {
                    return Err(StoreError::Conflict);
                };
            } else if journal.messages.len()
                != if journal.local == crate::pairing_v2::Role::A {
                    3
                } else {
                    4
                }
            {
                return Err(StoreError::Invalid);
            }
            let bytes = serde_json::to_vec(journal).map_err(|_| StoreError::Invalid)?;
            if bytes.len() > 64 * 1024 {
                return Err(StoreError::Limit);
            };
            let reference = JournalReference {
                attempt: record.attempt_id,
                revision: ledger.version.revision,
                digest: Sha256::digest(&bytes).into(),
            };
            self.pending_dir
                .replace(&journal_filename(&reference), &bytes)?;
            ledger.journals.retain(|r| r.attempt != reference.attempt);
            ledger.journals.push(reference);
            self.save(&ledger)?;
            if let Some(file) = old_file {
                self.pending_dir.remove(&file)?;
            }
            Ok(())
        }
        #[cfg(feature = "pairing-v2-experimental")]
        fn read_journal(
            &self,
            reference: &JournalReference,
        ) -> Result<crate::pairing_v2::PublicJournal, StoreError> {
            let bytes = self
                .pending_dir
                .read(&journal_filename(reference), 64 * 1024)?
                .ok_or(StoreError::Invalid)?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            if digest != reference.digest {
                return Err(StoreError::Invalid);
            };
            let journal: crate::pairing_v2::PublicJournal =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
            if journal.pending.attempt_id != reference.attempt {
                return Err(StoreError::Invalid);
            };
            journal.validate().map_err(|_| StoreError::Invalid)?;
            Ok(journal)
        }
        /// Consumes only a signature-checked request from an authoritative context
        /// provider. This does NOT populate that context or authorize admission.
        #[cfg(feature = "pairing-v2-experimental")]
        pub fn consume_verified_recovery(
            &self,
            proof: crate::pairing_v2::VerifiedRecoveryUse,
        ) -> Result<(), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            ledger.advance(proof.local_version)?;
            let reference = ledger
                .pending
                .iter()
                .find(|r| r.record.attempt_id == proof.pending.attempt_id)
                .ok_or(StoreError::Invalid)?;
            if reference.record != proof.pending {
                return Err(StoreError::Conflict);
            }
            let journal_reference = ledger
                .journals
                .iter()
                .find(|r| r.attempt == proof.pending.attempt_id)
                .ok_or(StoreError::Invalid)?;
            let journal = self.read_journal(journal_reference)?;
            if journal.local == proof.peer_role
                || journal.validate().map_err(|_| StoreError::Invalid)? != Some(proof.fc_hash)
            {
                return Err(StoreError::Invalid);
            }
            if ledger
                .recoveries
                .iter()
                .any(|r| r.signer == proof.signer && r.body == proof.body)
            {
                return Err(StoreError::ConsumedAttempt);
            }
            if ledger.recoveries.len() >= MAX_HISTORY {
                return Err(StoreError::Limit);
            }
            ledger.recoveries.push(RecoveryConsumption {
                signer: proof.signer,
                body: proof.body,
                signature: proof.signature,
            });
            self.save(&ledger)
        }

        pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
            let root = PrivateDir::root(root.as_ref())?;
            let pending_dir = root.child("pairing-pending")?;
            let ledger_dir = root.child("pairing-tombstones")?;
            let store = Self {
                pending_dir,
                ledger_dir,
            };
            let _lock = store.ledger_dir.lock()?;
            match store.ledger_dir.read("ledger.json", LEDGER_LIMIT)? {
                Some(_) => {
                    store.load_validated_manifest()?;
                }
                None => {
                    // A missing ledger after initialization is data loss, never a fresh trust epoch.
                    if store.ledger_dir.read("initialized", 16)?.is_some() {
                        return Err(StoreError::Invalid);
                    }
                    store.save(&Ledger::new())?;
                }
            }
            store.ledger_dir.replace("initialized", b"pending-v1")?;
            Ok(store)
        }

        /// Caller holds the ledger lock. Validate the complete referenced state before
        /// returning any observation or allowing a mutation, including unrelated peers.
        fn load_validated_manifest(&self) -> Result<Ledger, StoreError> {
            let bytes = self
                .ledger_dir
                .read("ledger.json", LEDGER_LIMIT)?
                .ok_or(StoreError::Invalid)?;
            let ledger: Ledger = serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
            ledger.validate()?;
            for reference in &ledger.pending {
                let bytes = self
                    .pending_dir
                    .read(&filename(reference.record.attempt_id), RECORD_LIMIT)?
                    .ok_or(StoreError::Invalid)?;
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                let record: PendingRecord =
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
                if digest != reference.digest || record != reference.record {
                    return Err(StoreError::Invalid);
                }
            }
            #[cfg(feature = "pairing-v2-experimental")]
            for reference in &ledger.journals {
                let journal = self.read_journal(reference)?;
                if !ledger.pending.iter().any(|r| r.record == journal.pending) {
                    return Err(StoreError::Invalid);
                };
            }
            Ok(ledger)
        }

        fn save(&self, ledger: &Ledger) -> Result<(), StoreError> {
            ledger.validate()?;
            let bytes = serde_json::to_vec(ledger).map_err(|_| StoreError::Invalid)?;
            if bytes.len() > LEDGER_LIMIT {
                return Err(StoreError::Limit);
            }
            self.ledger_dir.replace("ledger.json", &bytes)
        }

        pub fn version(&self) -> Result<StoreVersion, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            Ok(self.load_validated_manifest()?.version)
        }

        pub fn prepare(
            &self,
            expected: StoreVersion,
            attempt: [u8; 32],
            peer: [u8; 32],
        ) -> Result<PendingRecord, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            ledger.advance(expected)?;
            if attempt == [0; 32] || peer == [0; 32] {
                return Err(StoreError::Invalid);
            }
            if ledger.tombstones.contains(&attempt) {
                return Err(StoreError::ConsumedAttempt);
            }
            #[cfg(feature = "pairing-v2-experimental")]
            if ledger.consumed_attempts.contains(&attempt) {
                return Err(StoreError::ConsumedAttempt);
            }
            // A current StoreOwned pin represents the one admitted durable
            // relationship for this peer.  Reject a retry before it can create
            // pending metadata or a live revocation guard: later cancellation
            // is peer-scoped and must never revoke that existing relationship.
            #[cfg(feature = "pairing-v2-experimental")]
            if ledger.active_pins.iter().any(|pin| pin.peer == peer) {
                return Err(StoreError::Conflict);
            }
            #[cfg(feature = "pairing-v2-experimental")]
            if ledger
                .admission_reservations
                .iter()
                .any(|reservation| reservation.peer == peer)
            {
                return Err(StoreError::Conflict);
            }
            if ledger
                .pending
                .iter()
                .any(|r| r.record.attempt_id == attempt)
            {
                return Err(StoreError::Conflict);
            }
            if ledger.pending.len() >= MAX_PENDING {
                return Err(StoreError::Limit);
            }
            let record = PendingRecord {
                attempt_id: attempt,
                peer_fingerprint: peer,
                version: ledger.version,
                revocation_generation: ledger.revocation(peer),
            };
            let bytes = serde_json::to_vec(&record).map_err(|_| StoreError::Invalid)?;
            let digest = Sha256::digest(&bytes).into();
            // An interrupted prepare may leave an orphan file. Only the locked ledger can reference it.
            self.pending_dir.replace(&filename(attempt), &bytes)?;
            #[cfg(feature = "pairing-v2-experimental")]
            ledger
                .admission_reservations
                .push(AdmissionReservation { peer, attempt });
            ledger.pending.push(Reference {
                record: record.clone(),
                digest,
            });
            self.save(&ledger)?;
            Ok(record)
        }

        pub fn pending(&self, attempt: [u8; 32]) -> Result<Option<PendingRecord>, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let ledger = self.load_validated_manifest()?;
            let Some(reference) = ledger
                .pending
                .iter()
                .find(|r| r.record.attempt_id == attempt)
            else {
                return Ok(None);
            };
            Ok(Some(reference.record.clone()))
        }

        pub fn cancel(&self, expected: StoreVersion, attempt: [u8; 32]) -> Result<(), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            ledger.advance(expected)?;
            if !ledger
                .pending
                .iter()
                .any(|r| r.record.attempt_id == attempt)
            {
                return Err(StoreError::Invalid);
            }
            ledger.pending.retain(|r| r.record.attempt_id != attempt);
            #[cfg(feature = "pairing-v2-experimental")]
            ledger
                .admission_reservations
                .retain(|reservation| reservation.attempt != attempt);
            #[cfg(feature = "pairing-v2-experimental")]
            let old_journals: Vec<_> = ledger
                .journals
                .iter()
                .filter(|r| r.attempt == attempt)
                .map(journal_filename)
                .collect();
            #[cfg(feature = "pairing-v2-experimental")]
            ledger.journals.retain(|r| r.attempt != attempt);
            ledger.tombstones.push(attempt);
            self.save(&ledger)?;
            // Durable tombstone is authoritative even if deletion fails: no resurrection on retry.
            self.pending_dir.remove(&filename(attempt))?;
            #[cfg(feature = "pairing-v2-experimental")]
            for file in old_journals {
                self.pending_dir.remove(&file)?;
            }
            Ok(())
        }

        /// Revokes quarantined setup candidates only. This is NOT legacy IdentityStore::unpair.
        pub fn revoke_candidate(
            &self,
            expected: StoreVersion,
            peer: [u8; 32],
        ) -> Result<(), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            ledger.advance(expected)?;
            if peer == [0; 32] {
                return Err(StoreError::Invalid);
            }
            if let Some(r) = ledger.revocations.iter_mut().find(|r| r.peer == peer) {
                r.generation = r.generation.checked_add(1).ok_or(StoreError::Limit)?;
            } else {
                ledger.revocations.push(Revocation {
                    peer,
                    generation: 1,
                });
            }
            #[cfg(feature = "pairing-v2-experimental")]
            ledger.active_pins.retain(|pin| pin.peer != peer);
            #[cfg(feature = "pairing-v2-experimental")]
            ledger
                .admission_reservations
                .retain(|reservation| reservation.peer != peer);
            let removed: Vec<_> = ledger
                .pending
                .iter()
                .filter(|r| r.record.peer_fingerprint == peer)
                .map(|r| r.record.attempt_id)
                .collect();
            ledger.pending.retain(|r| r.record.peer_fingerprint != peer);
            #[cfg(feature = "pairing-v2-experimental")]
            let old_journals: Vec<_> = ledger
                .journals
                .iter()
                .filter(|r| removed.contains(&r.attempt))
                .map(journal_filename)
                .collect();
            #[cfg(feature = "pairing-v2-experimental")]
            ledger.journals.retain(|r| !removed.contains(&r.attempt));
            ledger.tombstones.extend(&removed);
            self.save(&ledger)?;
            for attempt in removed {
                self.pending_dir.remove(&filename(attempt))?;
            }
            #[cfg(feature = "pairing-v2-experimental")]
            for file in old_journals {
                self.pending_dir.remove(&file)?;
            }
            Ok(())
        }

        pub fn revocation_generation(&self, peer: [u8; 32]) -> Result<u64, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            Ok(self.load_validated_manifest()?.revocation(peer))
        }

        /// Internal foundation for a future reviewed admission authority. This is
        /// deliberately crate-private and returns durable metadata, never a runtime
        /// capability. Pending removal, pin, consumed marker and receipt share the
        /// same manifest publication under the same multiprocess lock.
        #[cfg(feature = "pairing-v2-experimental")]
        #[allow(dead_code)] // Reachable only through the disabled admission foundation.
        pub(crate) fn commit_sealed_admission(
            &self,
            expected: StoreVersion,
            commit: crate::pairing_v2::admission_authority::SealedAdmissionCommit,
        ) -> Result<AdmissionReceiptRecord, StoreError> {
            commit.revalidate()?;
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            commit.revalidate()?;
            let record = commit.record();
            let receipt = commit.receipt();
            let expected_revocation_generation = receipt.revocation_generation;
            let expected_policy_revision = receipt.policy_revision;
            if ledger.version != expected
                || record.version.identity_generation != expected.identity_generation
                || ledger.policy_revision != expected_policy_revision
                || ledger.revocation(record.peer_fingerprint) != expected_revocation_generation
                || record.revocation_generation != expected_revocation_generation
            {
                return Err(StoreError::Conflict);
            }
            let pending = ledger
                .pending
                .iter()
                .find(|entry| entry.record.attempt_id == record.attempt_id)
                .ok_or_else(|| {
                    if ledger.consumed_attempts.contains(&record.attempt_id) {
                        StoreError::ConsumedAttempt
                    } else {
                        StoreError::Invalid
                    }
                })?;
            if pending.record != *record
                || receipt.attempt != record.attempt_id
                || receipt.peer != record.peer_fingerprint
                || receipt.revision != expected.revision.checked_add(1).ok_or(StoreError::Limit)?
                || receipt.identity_generation != expected.identity_generation
                || receipt.revocation_generation != expected_revocation_generation
                || receipt.policy_revision != expected_policy_revision
            {
                return Err(StoreError::Invalid);
            }
            if !ledger.admission_reservations.iter().any(|reservation| {
                reservation.attempt == receipt.attempt && reservation.peer == receipt.peer
            }) {
                return Err(StoreError::Invalid);
            }
            // A pin is bound to exactly one durable admission receipt.  A
            // later attempt for that peer must never inherit the first
            // receipt's pin, even when it presents the same value.
            if ledger
                .active_pins
                .iter()
                .any(|pin| pin.peer == receipt.peer)
            {
                return Err(StoreError::Conflict);
            }
            if ledger.consumed_attempts.contains(&receipt.attempt)
                || ledger
                    .admission_receipts
                    .iter()
                    .any(|stored| stored.attempt == receipt.attempt)
                || ledger.tombstones.contains(&receipt.attempt)
            {
                return Err(StoreError::ConsumedAttempt);
            }
            if ledger.active_pins.len() >= MAX_HISTORY
                || ledger.consumed_attempts.len() >= MAX_HISTORY
                || ledger.admission_receipts.len() >= MAX_HISTORY
            {
                return Err(StoreError::Limit);
            }
            commit.revalidate()?;
            let old_journals: Vec<_> = ledger
                .journals
                .iter()
                .filter(|entry| entry.attempt == receipt.attempt)
                .map(journal_filename)
                .collect();
            ledger.advance(expected)?;
            if !ledger
                .active_pins
                .iter()
                .any(|pin| pin.peer == receipt.peer)
            {
                ledger.active_pins.push(ActivePin {
                    peer: receipt.peer,
                    pin: receipt.peer_pin,
                    identity_generation: receipt.identity_generation,
                    revocation_generation: receipt.revocation_generation,
                });
            }
            ledger
                .pending
                .retain(|entry| entry.record.attempt_id != receipt.attempt);
            ledger
                .journals
                .retain(|entry| entry.attempt != receipt.attempt);
            ledger
                .admission_reservations
                .retain(|reservation| reservation.attempt != receipt.attempt);
            ledger.consumed_attempts.push(receipt.attempt);
            ledger.admission_receipts.push(receipt.clone());
            // Final protocol check immediately precedes the single publication
            // linearization point. No fallible protocol validation follows save.
            commit.revalidate()?;
            self.save(&ledger)?;
            self.pending_dir.remove(&filename(receipt.attempt))?;
            for file in old_journals {
                self.pending_dir.remove(&file)?;
            }
            Ok(receipt.clone())
        }

        /// First publication of a live admission finalization.  A staged
        /// receipt consumes the pending attempt but is explicitly ineligible:
        /// its provisional endpoint still owns the exact revocation guard.
        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn stage_sealed_admission(
            &self,
            expected: StoreVersion,
            record: &PendingRecord,
            receipt: &AdmissionReceiptRecord,
        ) -> Result<AdmissionReceiptRecord, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            let expected_revision = expected.revision.checked_add(1).ok_or(StoreError::Limit)?;
            if ledger.version != expected
                || record.version.identity_generation != expected.identity_generation
                || ledger.policy_revision != receipt.policy_revision
                || ledger.revocation(record.peer_fingerprint) != receipt.revocation_generation
                || record.revocation_generation != receipt.revocation_generation
                || receipt.attempt != record.attempt_id
                || receipt.peer != record.peer_fingerprint
                || receipt.revision != expected_revision
                || receipt.identity_generation != expected.identity_generation
                || !matches!(
                    receipt.ownership,
                    AdmissionOwnership::AwaitingHandoff { .. }
                )
            {
                return Err(StoreError::Conflict);
            }
            let pending = ledger
                .pending
                .iter()
                .find(|entry| entry.record.attempt_id == record.attempt_id)
                .ok_or_else(|| {
                    if ledger.consumed_attempts.contains(&record.attempt_id) {
                        StoreError::ConsumedAttempt
                    } else {
                        StoreError::Invalid
                    }
                })?;
            if pending.record != *record
                || ledger.consumed_attempts.contains(&receipt.attempt)
                || ledger
                    .admission_receipts
                    .iter()
                    .any(|stored| stored.attempt == receipt.attempt)
                || ledger.tombstones.contains(&receipt.attempt)
                || ledger.consumed_attempts.len() >= MAX_HISTORY
                || ledger.admission_receipts.len() >= MAX_HISTORY
            {
                return Err(StoreError::ConsumedAttempt);
            }
            if !ledger.admission_reservations.iter().any(|reservation| {
                reservation.attempt == receipt.attempt && reservation.peer == receipt.peer
            }) {
                return Err(StoreError::Invalid);
            }
            let old_journals: Vec<_> = ledger
                .journals
                .iter()
                .filter(|entry| entry.attempt == receipt.attempt)
                .map(journal_filename)
                .collect();
            ledger.advance(expected)?;
            ledger
                .pending
                .retain(|entry| entry.record.attempt_id != receipt.attempt);
            ledger
                .journals
                .retain(|entry| entry.attempt != receipt.attempt);
            ledger.consumed_attempts.push(receipt.attempt);
            ledger.admission_receipts.push(receipt.clone());
            self.save(&ledger)?;
            self.pending_dir.remove(&filename(receipt.attempt))?;
            for file in old_journals {
                self.pending_dir.remove(&file)?;
            }
            Ok(receipt.clone())
        }

        /// Publishes a local bilateral receipt after the local handoff.  The
        /// active pin is a durable reservation only: Task 1 deliberately
        /// keeps every bilateral state ineligible for an operational
        /// snapshot until a later authenticated peer proof exists.
        #[cfg(feature = "pairing-v2-experimental")]
        #[allow(dead_code)] // Task 2 storage transition; Task 3 wires authenticated proof.
        pub(crate) fn publish_local_bilateral_receipt(
            &self,
            expected: StoreVersion,
            record: &PendingRecord,
            mut receipt: AdmissionReceiptRecord,
        ) -> Result<AdmissionReceiptRecord, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            let published_revision = expected.revision.checked_add(1).ok_or(StoreError::Limit)?;
            if ledger.version != expected
                || record.version.identity_generation != expected.identity_generation
                || ledger.policy_revision != receipt.policy_revision
                || ledger.revocation(record.peer_fingerprint) != receipt.revocation_generation
                || record.revocation_generation != receipt.revocation_generation
                || receipt.attempt != record.attempt_id
                || receipt.peer != record.peer_fingerprint
                || receipt.revision != published_revision
                || receipt.identity_generation != expected.identity_generation
                || !matches!(receipt.ownership, AdmissionOwnership::StoreOwned { .. })
                || !matches!(receipt.bilateral.state, BilateralAdmissionState::Prepared)
                || receipt.bilateral.peer_receipt_hash.is_some()
                || receipt.bilateral.fields.local_attempt != record.attempt_id
                || receipt.bilateral.fields.peer_identity != record.peer_fingerprint
                || receipt.bilateral.fields.peer_pin != receipt.peer_pin
                || receipt.bilateral.fields.transcript != receipt.transcript
                || receipt.bilateral.fields.suite != receipt.suite
                || receipt.bilateral.fields.policy_revision != receipt.policy_revision
                || receipt.bilateral.transaction_id
                    != derive_bilateral_transaction_id(&receipt.bilateral.fields)
                || receipt.bilateral.guard_token != receipt.ownership.guard_token()
                || receipt.bilateral.identity_generation != receipt.identity_generation
                || receipt.bilateral.revocation_generation != receipt.revocation_generation
                || receipt.bilateral.policy_revision != receipt.policy_revision
                || receipt.bilateral.local_receipt_hash != admission_receipt_hash(&receipt)
            {
                return Err(StoreError::Conflict);
            }
            let pending = ledger
                .pending
                .iter()
                .find(|entry| entry.record.attempt_id == record.attempt_id)
                .ok_or_else(|| {
                    if ledger.consumed_attempts.contains(&record.attempt_id) {
                        StoreError::ConsumedAttempt
                    } else {
                        StoreError::Invalid
                    }
                })?;
            if pending.record != *record
                || ledger.consumed_attempts.contains(&receipt.attempt)
                || ledger
                    .admission_receipts
                    .iter()
                    .any(|stored| stored.attempt == receipt.attempt)
                || ledger.tombstones.contains(&receipt.attempt)
            {
                return Err(StoreError::ConsumedAttempt);
            }
            if !ledger.admission_reservations.iter().any(|reservation| {
                reservation.attempt == receipt.attempt && reservation.peer == receipt.peer
            }) {
                return Err(StoreError::Invalid);
            }
            if ledger
                .active_pins
                .iter()
                .any(|pin| pin.peer == receipt.peer)
            {
                return Err(StoreError::Conflict);
            }
            if ledger.active_pins.len() >= MAX_HISTORY
                || ledger.consumed_attempts.len() >= MAX_HISTORY
                || ledger.admission_receipts.len() >= MAX_HISTORY
            {
                return Err(StoreError::Limit);
            }
            let old_journals: Vec<_> = ledger
                .journals
                .iter()
                .filter(|entry| entry.attempt == receipt.attempt)
                .map(journal_filename)
                .collect();
            receipt
                .bilateral
                .transition_to_store_owned(&receipt.ownership)?;
            if !receipt.bilateral.is_well_formed_for(&receipt) {
                return Err(StoreError::Invalid);
            }
            ledger.advance(expected)?;
            ledger
                .pending
                .retain(|entry| entry.record.attempt_id != receipt.attempt);
            ledger
                .journals
                .retain(|entry| entry.attempt != receipt.attempt);
            ledger
                .admission_reservations
                .retain(|reservation| reservation.attempt != receipt.attempt);
            ledger.active_pins.push(ActivePin {
                peer: receipt.peer,
                pin: receipt.peer_pin,
                identity_generation: receipt.identity_generation,
                revocation_generation: receipt.revocation_generation,
            });
            ledger.consumed_attempts.push(receipt.attempt);
            ledger.admission_receipts.push(receipt.clone());
            self.save(&ledger)?;
            self.pending_dir.remove(&filename(receipt.attempt))?;
            for file in old_journals {
                self.pending_dir.remove(&file)?;
            }
            Ok(receipt)
        }

        /// Persists the local observation of an exact peer receipt.  This is
        /// bookkeeping only; without Task 3's authenticated proof it cannot
        /// activate an admission.
        #[cfg(feature = "pairing-v2-experimental")]
        #[allow(dead_code)] // Task 2 storage transition; Task 3 wires authenticated proof.
        pub(crate) fn confirm_bilateral_receipt(
            &self,
            expected: StoreVersion,
            attempt: [u8; 32],
            transaction_id: BilateralTransactionId,
            local_receipt_hash: [u8; 32],
            peer_receipt_hash: [u8; 32],
        ) -> Result<AdmissionReceiptRecord, StoreError> {
            if !transaction_id.is_valid()
                || local_receipt_hash == [0; 32]
                || peer_receipt_hash == [0; 32]
            {
                return Err(StoreError::Invalid);
            }
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            if ledger.version != expected {
                return Err(StoreError::Conflict);
            }
            let index = ledger
                .admission_receipts
                .iter()
                .position(|receipt| receipt.attempt == attempt)
                .ok_or(StoreError::Invalid)?;
            let receipt = &ledger.admission_receipts[index];
            if !matches!(
                receipt.bilateral.state,
                BilateralAdmissionState::StoreOwnedAwaitingPeer
            ) || receipt.bilateral.transaction_id != transaction_id
                || receipt.bilateral.local_receipt_hash != local_receipt_hash
                || receipt.identity_generation != expected.identity_generation
                || receipt.revocation_generation != ledger.revocation(receipt.peer)
                || receipt.policy_revision != ledger.policy_revision
                || !ledger.active_pins.iter().any(|pin| {
                    pin.peer == receipt.peer
                        && pin.pin == receipt.peer_pin
                        && pin.identity_generation == receipt.identity_generation
                        && pin.revocation_generation == receipt.revocation_generation
                })
            {
                return Err(StoreError::Invalid);
            }
            ledger.advance(expected)?;
            let receipt = &mut ledger.admission_receipts[index];
            receipt.bilateral.state = BilateralAdmissionState::BilateralConfirmed;
            receipt.bilateral.peer_receipt_hash = Some(peer_receipt_hash);
            if !receipt.bilateral.is_well_formed_for(receipt) {
                return Err(StoreError::Invalid);
            }
            let confirmed = receipt.clone();
            self.save(&ledger)?;
            Ok(confirmed)
        }

        /// Aborts only the exact durable transaction.  In particular, an old
        /// timeout/drop cannot revoke a later attempt for the same peer.
        #[cfg(feature = "pairing-v2-experimental")]
        #[allow(dead_code)] // Task 2 storage transition; Task 3 wires authenticated proof.
        pub(crate) fn abort_bilateral_transaction(
            &self,
            expected: StoreVersion,
            attempt: [u8; 32],
            transaction_id: BilateralTransactionId,
            guard_token: [u8; 32],
        ) -> Result<(), StoreError> {
            if !transaction_id.is_valid() || guard_token == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            if ledger.version != expected {
                return Err(StoreError::Conflict);
            }
            let index = ledger
                .admission_receipts
                .iter()
                .position(|receipt| receipt.attempt == attempt)
                .ok_or(StoreError::Invalid)?;
            let receipt = &ledger.admission_receipts[index];
            if receipt.bilateral.transaction_id != transaction_id
                || receipt.bilateral.guard_token != guard_token
                || receipt.ownership.guard_token() != guard_token
                || receipt.identity_generation != expected.identity_generation
                || receipt.revocation_generation != ledger.revocation(receipt.peer)
            {
                return Err(StoreError::Invalid);
            }
            let peer = receipt.peer;
            let pin = receipt.peer_pin;
            let identity_generation = receipt.identity_generation;
            let revocation_generation = receipt.revocation_generation;
            ledger.advance(expected)?;
            ledger.admission_receipts.remove(index);
            ledger.consumed_attempts.retain(|stored| *stored != attempt);
            ledger.active_pins.retain(|active| {
                !(active.peer == peer
                    && active.pin == pin
                    && active.identity_generation == identity_generation
                    && active.revocation_generation == revocation_generation)
            });
            ledger
                .admission_reservations
                .retain(|reservation| reservation.attempt != attempt);
            ledger.tombstones.push(attempt);
            self.save(&ledger)
        }

        /// Endpoint-drop recovery for a live staged bilateral transaction.
        /// The opaque sidecar token is the sole authority: no peer lookup or
        /// peer-wide revocation is allowed on this path.
        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn abort_bilateral_guard_exact(
            &self,
            attempt: [u8; 32],
            guard_token: [u8; 32],
        ) -> Result<(), StoreError> {
            if attempt == [0; 32] || guard_token == [0; 32] {
                return Err(StoreError::Invalid);
            }
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            let index = ledger
                .admission_receipts
                .iter()
                .position(|receipt| receipt.attempt == attempt)
                .ok_or(StoreError::Invalid)?;
            let receipt = &ledger.admission_receipts[index];
            if receipt.bilateral.guard_token != guard_token
                || receipt.ownership.guard_token() != guard_token
                || receipt.identity_generation != ledger.version.identity_generation
                || receipt.revocation_generation != ledger.revocation(receipt.peer)
            {
                return Err(StoreError::Invalid);
            }
            let peer = receipt.peer;
            let pin = receipt.peer_pin;
            let identity_generation = receipt.identity_generation;
            let revocation_generation = receipt.revocation_generation;
            let expected = ledger.version;
            ledger.advance(expected)?;
            ledger.admission_receipts.remove(index);
            ledger.consumed_attempts.retain(|stored| *stored != attempt);
            ledger.active_pins.retain(|active| {
                !(active.peer == peer
                    && active.pin == pin
                    && active.identity_generation == identity_generation
                    && active.revocation_generation == revocation_generation)
            });
            ledger
                .admission_reservations
                .retain(|reservation| reservation.attempt != attempt);
            ledger.tombstones.push(attempt);
            self.save(&ledger)
        }

        /// Second publication of live admission finalization.  Only an exact
        /// staged receipt may become `StoreOwned`, and the active pin appears
        /// in the same locked manifest publication as that ownership election.
        #[cfg(feature = "pairing-v2-experimental")]
        pub(crate) fn finalize_staged_admission(
            &self,
            expected: StoreVersion,
            attempt: [u8; 32],
            handoff: crate::pairing_v2::provisional_tls::FrozenAdmissionHandoff,
        ) -> Result<(AdmissionReceiptRecord, AdmissionRevoker), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            let final_revision = expected.revision.checked_add(1).ok_or(StoreError::Limit)?;
            let ownership = handoff.store_owned_ownership(expected.revision, final_revision);
            let receipt_index = ledger
                .admission_receipts
                .iter()
                .position(|stored| stored.attempt == attempt)
                .ok_or(StoreError::Invalid)?;
            let receipt = &ledger.admission_receipts[receipt_index];
            let current_revocation = ledger.revocation(receipt.peer);
            let matches_stage = matches!(
                (&receipt.ownership, &ownership),
                (
                    AdmissionOwnership::AwaitingHandoff {
                        guard_token: staged_token,
                        staged_revision,
                    },
                    AdmissionOwnership::StoreOwned {
                        guard_token: final_token,
                        staged_revision: final_staged_revision,
                        handoff_revision,
                    },
                ) if *staged_token == *final_token
                    && *staged_revision == expected.revision
                    && *final_staged_revision == expected.revision
                    && *handoff_revision == final_revision
            );
            if ledger.version != expected
                || !matches_stage
                || receipt.revision != expected.revision
                || receipt.identity_generation != expected.identity_generation
                || receipt.revocation_generation != current_revocation
                || receipt.policy_revision != ledger.policy_revision
                || ledger
                    .active_pins
                    .iter()
                    .any(|pin| pin.peer == receipt.peer)
            {
                return Err(StoreError::Conflict);
            }
            if ledger.active_pins.len() >= MAX_HISTORY {
                return Err(StoreError::Limit);
            }
            if !ledger.admission_reservations.iter().any(|reservation| {
                reservation.attempt == attempt && reservation.peer == receipt.peer
            }) {
                return Err(StoreError::Invalid);
            }
            // The file lock is held across this short ownership election, but
            // `claim` releases the consent mutex before any filesystem I/O.
            // Thus endpoint drop and final publication have one ordered owner
            // without ever holding a mutex across a save.
            let revoker = handoff.claim().map_err(|_| StoreError::Invalid)?;
            let peer = receipt.peer;
            let peer_pin = receipt.peer_pin;
            let identity_generation = receipt.identity_generation;
            let revocation_generation = receipt.revocation_generation;
            ledger.advance(expected)?;
            let receipt = &mut ledger.admission_receipts[receipt_index];
            receipt.revision = final_revision;
            receipt.ownership = ownership;
            let ownership = receipt.ownership.clone();
            receipt.bilateral.transition_to_store_owned(&ownership)?;
            bind_prepared_bilateral_receipt_hash(receipt);
            ledger
                .admission_reservations
                .retain(|reservation| reservation.attempt != attempt);
            if !ledger.active_pins.iter().any(|pin| pin.peer == peer) {
                ledger.active_pins.push(ActivePin {
                    peer,
                    pin: peer_pin,
                    identity_generation,
                    revocation_generation,
                });
            }
            let finalized = ledger.admission_receipts[receipt_index].clone();
            self.save(&ledger)?;
            Ok((finalized, revoker))
        }

        #[cfg(feature = "pairing-v2-experimental")]
        #[allow(dead_code)] // Used only by the default-off admission foundation.
        pub(crate) fn admission_state(
            &self,
            attempt: [u8; 32],
        ) -> Result<(bool, Option<AdmissionReceiptRecord>, bool), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let ledger = self.load_validated_manifest()?;
            let receipt = ledger
                .admission_receipts
                .iter()
                .find(|receipt| receipt.attempt == attempt)
                .cloned();
            let active = receipt.as_ref().is_some_and(|receipt| {
                receipt.identity_generation == ledger.version.identity_generation
                    && receipt.revocation_generation == ledger.revocation(receipt.peer)
                    && receipt.ownership.is_store_owned()
                    && ledger.active_pins.iter().any(|pin| {
                        pin.peer == receipt.peer
                            && pin.pin == receipt.peer_pin
                            && pin.identity_generation == receipt.identity_generation
                            && pin.revocation_generation == receipt.revocation_generation
                    })
            });
            Ok((
                ledger
                    .pending
                    .iter()
                    .any(|entry| entry.record.attempt_id == attempt),
                receipt,
                active,
            ))
        }

        /// Advances the setup epoch. Does not regenerate, read, or write a device private key.
        pub fn rotate_identity(&self, expected: StoreVersion) -> Result<(), StoreError> {
            let _lock = self.ledger_dir.lock()?;
            let mut ledger = self.load_validated_manifest()?;
            ledger.advance(expected)?;
            ledger.version.identity_generation = ledger
                .version
                .identity_generation
                .checked_add(1)
                .ok_or(StoreError::Limit)?;
            #[cfg(feature = "pairing-v2-experimental")]
            ledger.active_pins.clear();
            #[cfg(feature = "pairing-v2-experimental")]
            ledger.admission_reservations.clear();
            let removed: Vec<_> = ledger.pending.iter().map(|r| r.record.attempt_id).collect();
            ledger.tombstones.extend(&removed);
            ledger.pending.clear();
            #[cfg(feature = "pairing-v2-experimental")]
            let old_journals: Vec<_> = ledger.journals.iter().map(journal_filename).collect();
            #[cfg(feature = "pairing-v2-experimental")]
            ledger.journals.clear();
            self.save(&ledger)?;
            for attempt in removed {
                self.pending_dir.remove(&filename(attempt))?;
            }
            #[cfg(feature = "pairing-v2-experimental")]
            for file in old_journals {
                self.pending_dir.remove(&file)?;
            }
            Ok(())
        }
    }

    #[cfg(feature = "pairing-v2-experimental")]
    #[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
    impl OperationalPreflightLease {
        pub(crate) fn snapshot(&self) -> &OperationalAdmissionSnapshot {
            &self.snapshot
        }

        /// Re-reads the durable receipt/pin tuple while the attempt is still
        /// preflight-only.  Open and Accept are transport-visible records, so
        /// a revoke or rotation must win before either is accepted or emitted.
        pub(crate) fn assert_current(&self) -> Result<(), StoreError> {
            if !self.live
                || !self
                    .store
                    .operational_snapshot_still_current(&self.snapshot)?
            {
                return Err(StoreError::Conflict);
            }
            let leases = operational_lease_states();
            matches!(
                leases.get(&self.token),
                Some(OperationalLeaseState {
                    snapshot,
                    phase: OperationalLeasePhase::Preflight {
                        view_hash,
                        connection_binding,
                    },
                }) if snapshot == &self.snapshot
                    && *view_hash == self.view_hash
                    && *connection_binding == self.connection_binding
            )
            .then_some(())
            .ok_or(StoreError::Conflict)
        }

        /// Final promotion is the local operational linearization point.  It
        /// re-reads the durable state before changing the in-memory token; no
        /// connection, stream, or filesystem I/O occurs while the lease mutex
        /// is held.
        pub(crate) fn promote(
            mut self,
            commitment_hash: [u8; 32],
        ) -> Result<OperationalFinalLease, StoreError> {
            if !self.live || commitment_hash == [0; 32] {
                return Err(StoreError::Invalid);
            }
            if !self
                .store
                .operational_snapshot_still_current(&self.snapshot)?
            {
                return Err(StoreError::Conflict);
            }
            let store = self.store.clone_for_operational_lease()?;
            let mut leases = operational_lease_states();
            let state = leases.get_mut(&self.token).ok_or(StoreError::Invalid)?;
            if state.snapshot != self.snapshot
                || state.phase
                    != (OperationalLeasePhase::Preflight {
                        view_hash: self.view_hash,
                        connection_binding: self.connection_binding,
                    })
            {
                return Err(StoreError::Conflict);
            }
            state.phase = OperationalLeasePhase::Final { commitment_hash };
            self.live = false;
            Ok(OperationalFinalLease {
                store,
                token: self.token,
                snapshot: self.snapshot.clone(),
                commitment_hash,
                live: true,
            })
        }
    }

    #[cfg(feature = "pairing-v2-experimental")]
    impl Drop for OperationalPreflightLease {
        fn drop(&mut self) {
            if self.live {
                operational_lease_states().remove(&self.token);
                self.live = false;
            }
        }
    }

    #[cfg(feature = "pairing-v2-experimental")]
    #[allow(dead_code)] // Sealed default-off operational foundation; no product caller in this phase.
    impl OperationalFinalLease {
        /// This is intentionally a check-only capability: callers receive no
        /// transport, input, or raw TLS handle.  Every record boundary must
        /// call it, so revoke/rotation wins before another record is accepted.
        pub(crate) fn assert_current(&self) -> Result<(), StoreError> {
            if !self.live
                || !self
                    .store
                    .operational_snapshot_still_current(&self.snapshot)?
            {
                return Err(StoreError::Conflict);
            }
            let leases = operational_lease_states();
            matches!(
                leases.get(&self.token),
                Some(OperationalLeaseState {
                    snapshot,
                    phase: OperationalLeasePhase::Final { commitment_hash },
                }) if snapshot == &self.snapshot && *commitment_hash == self.commitment_hash
            )
            .then_some(())
            .ok_or(StoreError::Conflict)
        }
    }

    #[cfg(feature = "pairing-v2-experimental")]
    impl Drop for OperationalFinalLease {
        fn drop(&mut self) {
            if self.live {
                operational_lease_states().remove(&self.token);
                self.live = false;
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl PendingStore {
    #[cfg(feature = "pairing-v2-experimental")]
    pub fn reconcile_pairing(
        &self,
        _attempt: [u8; 32],
        _clock: Option<crate::pairing_v2::JournalClock>,
    ) -> Result<crate::pairing_v2::ReconcileOutcome, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    #[cfg(feature = "pairing-v2-experimental")]
    pub(crate) fn persist_pairing_journal(
        &self,
        _expected: StoreVersion,
        _journal: &crate::pairing_v2::PublicJournal,
    ) -> Result<(), StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    #[cfg(feature = "pairing-v2-experimental")]
    pub fn consume_verified_recovery(
        &self,
        _proof: crate::pairing_v2::VerifiedRecoveryUse,
    ) -> Result<(), StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    /// Windows must acquire tested owner-only ACL/reparse-point storage before writes are enabled.
    pub fn open(_root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
}
