//! Durable admission foundation. This module deliberately emits no runtime
//! authority: product behavior remains fail-closed until a later reviewed phase.
use crate::pairing_pending::{
    AdmissionReceiptRecord, PendingRecord, PendingStore, StoreError, StoreVersion,
};
use std::path::Path;

#[allow(dead_code)]
const PROTOCOL_VERSION: u16 = 2;
#[allow(dead_code)]
const POLICY_REVISION: u64 = 0;

/// Durable metadata only. It is not an input, clipboard, topology or session capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionReceipt {
    attempt: [u8; 32],
    peer: [u8; 32],
    peer_pin: [u8; 32],
    trust_revision: u64,
    identity_generation: u64,
    revocation_generation: u64,
}

impl PromotionReceipt {
    pub fn attempt(&self) -> [u8; 32] {
        self.attempt
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileAdmission {
    Pending,
    Promoted,
    Revoked,
    Absent,
}

/// The only owner of pairing-v2 pending and durable admission metadata.
/// Legacy `IdentityStore` is intentionally not accepted by this API.
pub struct AdmissionAuthorityStore {
    store: PendingStore,
}

impl AdmissionAuthorityStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            store: PendingStore::open(root)?,
        })
    }

    pub fn version(&self) -> Result<StoreVersion, StoreError> {
        self.store.version()
    }

    pub fn prepare(
        &self,
        expected: StoreVersion,
        attempt: [u8; 32],
        peer: [u8; 32],
    ) -> Result<PendingRecord, StoreError> {
        self.store.prepare(expected, attempt, peer)
    }

    pub fn pending(&self, attempt: [u8; 32]) -> Result<Option<PendingRecord>, StoreError> {
        self.store.pending(attempt)
    }

    pub fn revoke_candidate(
        &self,
        expected: StoreVersion,
        peer: [u8; 32],
    ) -> Result<(), StoreError> {
        self.store.revoke_candidate(expected, peer)
    }

    pub fn cancel(&self, expected: StoreVersion, attempt: [u8; 32]) -> Result<(), StoreError> {
        self.store.cancel(expected, attempt)
    }

    pub fn reconcile(&self, attempt: [u8; 32]) -> Result<ReconcileAdmission, StoreError> {
        let (pending, receipt, active) = self.store.admission_state(attempt)?;
        match (pending, receipt, active) {
            (true, None, false) => Ok(ReconcileAdmission::Pending),
            (false, Some(_), true) => Ok(ReconcileAdmission::Promoted),
            (false, Some(_), false) => Ok(ReconcileAdmission::Revoked),
            (false, None, false) => Ok(ReconcileAdmission::Absent),
            _ => Err(StoreError::Invalid),
        }
    }

    #[allow(dead_code)] // No product admission path is wired in this foundation phase.
    fn commit_metadata(
        &self,
        expected: StoreVersion,
        expected_revocation_generation: u64,
        record: &PendingRecord,
        evidence: EvidenceFields,
    ) -> Result<PromotionReceipt, StoreError> {
        if evidence.attempt != record.attempt_id
            || evidence.peer != record.peer_fingerprint
            || evidence.peer_pin == [0; 32]
            || evidence.fc == [0; 32]
            || evidence.transcript == [0; 32]
            || evidence.binding == [0; 32]
            || evidence.role > 1
            || evidence.suite != super::SUITE
        {
            return Err(StoreError::Invalid);
        }
        let durable = AdmissionReceiptRecord {
            attempt: evidence.attempt,
            peer: evidence.peer,
            peer_pin: evidence.peer_pin,
            durable_fc_hash: evidence.fc,
            role: evidence.role,
            suite: evidence.suite.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            transcript: evidence.transcript,
            binding: evidence.binding,
            revision: expected.revision.checked_add(1).ok_or(StoreError::Limit)?,
            identity_generation: expected.identity_generation,
            revocation_generation: expected_revocation_generation,
            policy_revision: POLICY_REVISION,
        };
        let stored = self.store.commit_admission_foundation(
            expected,
            expected_revocation_generation,
            POLICY_REVISION,
            record,
            durable,
            || Ok(()),
        )?;
        Ok(PromotionReceipt {
            attempt: stored.attempt,
            peer: stored.peer,
            peer_pin: stored.peer_pin,
            trust_revision: stored.revision,
            identity_generation: stored.identity_generation,
            revocation_generation: stored.revocation_generation,
        })
    }

    /// Foundation-only commit. It remains crate-private and emits durable metadata,
    /// never an operational/session/input capability.
    #[allow(dead_code)] // Deliberately has no product caller in this phase.
    pub(crate) async fn commit_sealed_foundation(
        &self,
        expected: StoreVersion,
        authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    ) -> Result<PromotionReceipt, StoreError> {
        let evidence = authority
            .seal_for_promotion()
            .await
            .map_err(|_| StoreError::Invalid)?;
        evidence.revalidate().map_err(|_| StoreError::Invalid)?;
        let fields = evidence.fields();
        let durable = AdmissionReceiptRecord {
            attempt: fields.record.attempt_id,
            peer: fields.record.peer_fingerprint,
            peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
            durable_fc_hash: fields.durable_fc_hash,
            role: fields.role.index() as u8,
            suite: super::SUITE.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            transcript: fields.transcript,
            binding: fields.local_binding,
            revision: expected.revision.checked_add(1).ok_or(StoreError::Limit)?,
            identity_generation: expected.identity_generation,
            revocation_generation: fields.record.revocation_generation,
            policy_revision: POLICY_REVISION,
        };
        let stored = self.store.commit_admission_foundation(
            expected,
            fields.record.revocation_generation,
            POLICY_REVISION,
            &fields.record,
            durable,
            || evidence.revalidate().map_err(|_| StoreError::Invalid),
        )?;
        Ok(PromotionReceipt {
            attempt: stored.attempt,
            peer: stored.peer,
            peer_pin: stored.peer_pin,
            trust_revision: stored.revision,
            identity_generation: stored.identity_generation,
            revocation_generation: stored.revocation_generation,
        })
    }
}

#[allow(dead_code)]
struct EvidenceFields {
    attempt: [u8; 32],
    peer: [u8; 32],
    peer_pin: [u8; 32],
    fc: [u8; 32],
    role: u8,
    suite: &'static str,
    transcript: [u8; 32],
    binding: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn evidence(record: &PendingRecord) -> EvidenceFields {
        EvidenceFields {
            attempt: record.attempt_id,
            peer: record.peer_fingerprint,
            peer_pin: [21; 32],
            fc: [22; 32],
            role: 0,
            suite: super::super::SUITE,
            transcript: [23; 32],
            binding: [24; 32],
        }
    }

    #[test]
    fn single_manifest_consumes_pending_and_publishes_pin_receipt_atomically() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let version = store.version().unwrap();
        let record = store.prepare(version, [7; 32], [9; 32]).unwrap();
        let expected = store.version().unwrap();
        let receipt = store
            .commit_metadata(expected, 0, &record, evidence(&record))
            .unwrap();
        assert_eq!(receipt.attempt, record.attempt_id);
        assert!(store.pending(record.attempt_id).unwrap().is_none());
        assert_eq!(
            store.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
        let reopened = AdmissionAuthorityStore::open(root.path()).unwrap();
        assert_eq!(
            reopened.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
    }

    #[test]
    fn consumed_attempt_never_returns_to_pending() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [11; 32], [13; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();
        assert_eq!(
            store.prepare(
                store.version().unwrap(),
                record.attempt_id,
                record.peer_fingerprint
            ),
            Err(StoreError::ConsumedAttempt)
        );
    }

    #[test]
    fn exact_revision_and_revocation_generation_are_required() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let stale = store.version().unwrap();
        let record = store.prepare(stale, [17; 32], [19; 32]).unwrap();
        assert_eq!(
            store.commit_metadata(stale, 0, &record, evidence(&record)),
            Err(StoreError::Conflict)
        );
        let current = store.version().unwrap();
        store
            .revoke_candidate(current, record.peer_fingerprint)
            .unwrap();
        assert_eq!(
            store.commit_metadata(store.version().unwrap(), 0, &record, evidence(&record)),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn incompatible_pin_is_rejected_without_partial_consumption() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [31; 32], [32; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &first, evidence(&first))
            .unwrap();
        let second = store
            .prepare(store.version().unwrap(), [33; 32], first.peer_fingerprint)
            .unwrap();
        let mut conflicting = evidence(&second);
        conflicting.peer_pin = [99; 32];
        assert_eq!(
            store.commit_metadata(store.version().unwrap(), 0, &second, conflicting),
            Err(StoreError::Conflict)
        );
        assert_eq!(
            store.reconcile(second.attempt_id).unwrap(),
            ReconcileAdmission::Pending
        );
    }

    #[test]
    fn revocation_and_identity_rotation_invalidate_active_pin_without_revival() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [35; 32], [36; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();
        store
            .revoke_candidate(store.version().unwrap(), record.peer_fingerprint)
            .unwrap();
        assert_eq!(
            store.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Revoked
        );
        assert_eq!(
            store.prepare(
                store.version().unwrap(),
                record.attempt_id,
                record.peer_fingerprint
            ),
            Err(StoreError::ConsumedAttempt)
        );

        let next = store
            .prepare(store.version().unwrap(), [37; 32], [38; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &next, evidence(&next))
            .unwrap();
        store
            .store
            .rotate_identity(store.version().unwrap())
            .unwrap();
        assert_eq!(
            store.reconcile(next.attempt_id).unwrap(),
            ReconcileAdmission::Revoked
        );
    }

    #[test]
    fn tombstone_and_unrelated_manifest_corruption_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [61; 32], [62; 32])
            .unwrap();
        store
            .cancel(store.version().unwrap(), record.attempt_id)
            .unwrap();
        assert_eq!(
            store.prepare(
                store.version().unwrap(),
                record.attempt_id,
                record.peer_fingerprint
            ),
            Err(StoreError::ConsumedAttempt)
        );

        std::fs::write(
            root.path().join("pairing-tombstones/ledger.json"),
            br#"{"schema":1,"corrupt":true}"#,
        )
        .unwrap();
        assert_eq!(store.version(), Err(StoreError::Invalid));
        assert!(AdmissionAuthorityStore::open(root.path()).is_err());
    }

    #[test]
    fn two_processes_have_exactly_one_admission_winner() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [41; 32], [42; 32])
            .unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for _ in 0..2 {
            children.push(
                Command::new(&exe)
                    .args([
                        "--exact",
                        "pairing_v2::admission_authority::tests::admission_process_worker",
                        "--ignored",
                    ])
                    .env("CSF12_ADMISSION_WORKER_ROOT", root.path())
                    .spawn()
                    .unwrap(),
            );
        }
        let statuses: Vec<_> = children
            .into_iter()
            .map(|mut child| child.wait().unwrap())
            .collect();
        assert_eq!(statuses.iter().filter(|status| status.success()).count(), 1);
        assert_eq!(
            store.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
    }

    #[test]
    #[ignore]
    fn admission_process_worker() {
        let root = std::env::var_os("CSF12_ADMISSION_WORKER_ROOT").unwrap();
        let store = AdmissionAuthorityStore::open(root).unwrap();
        let record = store.pending([41; 32]).unwrap().unwrap();
        let result = store.commit_metadata(store.version().unwrap(), 0, &record, evidence(&record));
        if result.is_err() {
            std::process::exit(17);
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_manifest_durability_boundary_fails_closed_and_reconciles() {
        for (stage, mode) in [
            "before_write",
            "after_write",
            "before_file_sync",
            "after_file_sync",
            "before_rename",
            "after_rename",
            "before_dir_sync",
            "after_dir_sync",
            "before_readback",
            "after_readback",
            "before_cleanup",
            "after_cleanup",
        ]
        .into_iter()
        .flat_map(|stage| [(stage, "error"), (stage, "crash")])
        {
            let root = tempfile::tempdir().unwrap();
            let store = AdmissionAuthorityStore::open(root.path()).unwrap();
            store
                .prepare(store.version().unwrap(), [51; 32], [52; 32])
                .unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pairing_v2::admission_authority::tests::admission_fault_worker",
                    "--ignored",
                ])
                .env("CSF12_ADMISSION_WORKER_ROOT", root.path())
                .env("PAIRING_TEST_FS_FAULT", format!("ledger:{stage}:{mode}"))
                .status()
                .unwrap();
            assert!(
                !status.success(),
                "fault stage {stage}:{mode} did not fail closed"
            );
            let reopened = AdmissionAuthorityStore::open(root.path()).unwrap();
            assert!(matches!(
                reopened.reconcile([51; 32]).unwrap(),
                ReconcileAdmission::Pending | ReconcileAdmission::Promoted
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore]
    fn admission_fault_worker() {
        crate::private_fs::faults::arm();
        let root = std::env::var_os("CSF12_ADMISSION_WORKER_ROOT").unwrap();
        let store = AdmissionAuthorityStore::open(root).unwrap();
        let record = store.pending([51; 32]).unwrap().unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();
    }
}
