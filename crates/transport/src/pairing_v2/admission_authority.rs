//! Durable admission foundation. This module deliberately emits no runtime
//! authority: product behavior remains fail-closed until a later reviewed phase.
#[cfg(test)]
use crate::pairing_pending::AdmissionOwnership;
use crate::pairing_pending::{
    AdmissionReceiptRecord, BilateralAdmissionRecord, BilateralTransactionFields, PendingRecord,
    PendingStore, StoreError, StoreVersion, bind_prepared_bilateral_receipt_hash,
};
#[cfg(test)]
use std::cell::Cell;
use std::path::Path;

#[allow(dead_code)]
pub(crate) const PROTOCOL_VERSION: u16 = 2;
#[allow(dead_code)]
pub(crate) const POLICY_REVISION: u64 = 0;

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum BilateralCommitPhase {
    Prepared,
    Staged,
    ProofVerified,
    Frozen,
    Finalized,
    Confirmed,
    Aborted,
}

/// The one private owner of a live authority and its exact durable reservation.
/// It has no public constructor, no clone/debug/serialization implementation,
/// and each phase transition is deliberately one-shot.
pub(crate) struct PreparedBilateralCommit<'a> {
    store: &'a PendingStore,
    live: Option<super::provisional_tls::PreparedHandshakeAuthority>,
    frozen: Option<super::provisional_tls::FrozenPromotionEvidence>,
    receipt: Option<AdmissionReceiptRecord>,
    proof: Option<super::provisional_tls::PeerFinalizationReceipt>,
    phase: BilateralCommitPhase,
}

impl<'a> PreparedBilateralCommit<'a> {
    pub(crate) async fn prepare(
        owner: &'a AdmissionAuthorityStore,
        authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    ) -> Result<Self, StoreError> {
        let live = authority
            .prepare_bilateral(&owner.store)
            .map_err(|_| StoreError::Invalid)?;
        Ok(Self {
            store: &owner.store,
            live: Some(live),
            frozen: None,
            receipt: None,
            proof: None,
            phase: BilateralCommitPhase::Prepared,
        })
    }

    fn attempt(&self) -> Result<[u8; 32], StoreError> {
        self.live
            .as_ref()
            .map(|live| live.fields().record.attempt_id)
            .or_else(|| self.receipt.as_ref().map(|receipt| receipt.attempt))
            .ok_or(StoreError::Invalid)
    }

    fn receipt(&self) -> Result<&AdmissionReceiptRecord, StoreError> {
        self.receipt.as_ref().ok_or(StoreError::Invalid)
    }

    pub(crate) fn stage_once(&mut self, peer_attempt: [u8; 32]) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Prepared || peer_attempt == [0; 32] {
            return Err(StoreError::Invalid);
        }
        let expected = self.store.version()?;
        let live = self.live.as_ref().ok_or(StoreError::Invalid)?;
        let fields = live.fields();
        let staged_revision = expected.revision.checked_add(1).ok_or(StoreError::Limit)?;
        let ownership = live.staged_ownership(staged_revision);
        let mut receipt = AdmissionReceiptRecord {
            attempt: fields.record.attempt_id,
            peer: fields.record.peer_fingerprint,
            peer_pin: fields.certificate_fingerprints[1 - fields.role.index()],
            durable_fc_hash: fields.durable_fc_hash,
            role: fields.role.index() as u8,
            suite: super::SUITE.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            transcript: fields.transcript,
            binding: fields.local_binding,
            revision: staged_revision,
            identity_generation: expected.identity_generation,
            revocation_generation: fields.record.revocation_generation,
            policy_revision: POLICY_REVISION,
            bilateral: prepared_bilateral_record(
                fields.certificate_fingerprints[fields.role.index()],
                fields.certificate_fingerprints[1 - fields.role.index()],
                fields.certificate_fingerprints[1 - fields.role.index()],
                fields.record.attempt_id,
                peer_attempt,
                fields.transcript,
                ownership.guard_token(),
                expected.identity_generation,
                fields.record.revocation_generation,
            ),
            ownership,
        };
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        let stored = self.store.stage_sealed_admission(expected, &fields.record, &receipt)?;
        self.receipt = Some(stored);
        self.phase = BilateralCommitPhase::Staged;
        // The endpoint remains the exact owner until freeze.  Record that the
        // durable receipt now exists so endpoint drop aborts this transaction
        // rather than applying legacy peer-wide revocation.
        self.live
            .as_ref()
            .ok_or(StoreError::Invalid)?
            .mark_staged()
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    fn local_finalization_receipt(
        &self,
    ) -> Result<super::provisional_tls::LocalFinalizationReceipt, StoreError> {
        if self.phase != BilateralCommitPhase::Staged {
            return Err(StoreError::Invalid);
        }
        let receipt = self.receipt()?;
        self.live
            .as_ref()
            .ok_or(StoreError::Invalid)?
            .local_receipt(receipt.bilateral.fields.peer_attempt, receipt.bilateral.local_receipt_hash)
            .map_err(|_| StoreError::Invalid)
    }

    async fn exchange_once(
        &mut self,
        local: super::provisional_tls::LocalFinalizationReceipt,
    ) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Staged {
            return Err(StoreError::Invalid);
        }
        let proof = self
            .live
            .as_mut()
            .ok_or(StoreError::Invalid)?
            .exchange(local)
            .await
            .map_err(|_| StoreError::Invalid)?;
        let receipt = self.receipt()?;
        if proof.transaction_id() != receipt.bilateral.transaction_id
            || proof.transcript() != receipt.transcript
        {
            return Err(StoreError::Invalid);
        }
        self.proof = Some(proof);
        self.phase = BilateralCommitPhase::ProofVerified;
        Ok(())
    }

    pub(crate) async fn freeze_once(&mut self) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::ProofVerified || self.proof.is_none() {
            return Err(StoreError::Invalid);
        }
        let live = self.live.take().ok_or(StoreError::Invalid)?;
        let frozen = live.freeze().await.map_err(|_| StoreError::Invalid)?;
        self.frozen = Some(frozen);
        self.phase = BilateralCommitPhase::Frozen;
        Ok(())
    }

    fn finalize_once(&mut self) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Frozen {
            return Err(StoreError::Invalid);
        }
        let attempt = self.attempt()?;
        let expected = self.store.version()?;
        let frozen = self.frozen.take().ok_or(StoreError::Invalid)?;
        let (stored, mut revoker) = self.store.finalize_staged_admission(expected, attempt, frozen.into_store_handoff().1)?;
        revoker.release_to_store()?;
        self.receipt = Some(stored);
        self.phase = BilateralCommitPhase::Finalized;
        Ok(())
    }

    fn confirm_once(&mut self) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Finalized {
            return Err(StoreError::Invalid);
        }
        let proof = self.proof.as_ref().ok_or(StoreError::Invalid)?;
        let receipt = self.receipt()?;
        let expected = self.store.version()?;
        let confirmed = self.store.confirm_bilateral_receipt(
            expected,
            receipt.attempt,
            receipt.bilateral.transaction_id,
            receipt.bilateral.local_receipt_hash,
            proof.peer_receipt_hash(),
        )?;
        self.receipt = Some(confirmed);
        self.phase = BilateralCommitPhase::Confirmed;
        Ok(())
    }

    fn abort_exact(&mut self) -> bool {
        if matches!(self.phase, BilateralCommitPhase::Aborted) {
            return false;
        }
        let mut staged = false;
        if let Some(receipt) = self.receipt.as_ref() {
            if let Ok(version) = self.store.version() {
                let result = self.store.abort_bilateral_transaction(
                    version,
                    receipt.attempt,
                    receipt.bilateral.transaction_id,
                    receipt.bilateral.guard_token,
                );
                if result.is_ok() {
                    staged = true;
                } else if let (Ok(version), Ok((_, Some(current), _))) =
                    (self.store.version(), self.store.admission_state(receipt.attempt))
                {
                    // Publication may have advanced the exact receipt after a
                    // local transition. Re-read only this attempt and retry
                    // its transaction/guard tuple; never peer-revoke.
                    staged = self
                        .store
                        .abort_bilateral_transaction(
                            version,
                            current.attempt,
                            current.bilateral.transaction_id,
                            current.bilateral.guard_token,
                        )
                        .is_ok();
                }
            }
        } else if let (Ok(version), Ok(attempt)) = (self.store.version(), self.attempt()) {
            let _ = self.store.cancel(version, attempt);
        }
        self.phase = BilateralCommitPhase::Aborted;
        staged
    }

    #[cfg(test)]
    pub(crate) fn test_staged_matches(&self, receipt: &AdmissionReceiptRecord) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| live.test_matches_ownership(&receipt.ownership))
    }
}

pub(crate) async fn commit_bilateral_foundation(
    left_store: &AdmissionAuthorityStore,
    left_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    right_store: &AdmissionAuthorityStore,
    right_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
) -> Result<(), StoreError> {
    commit_bilateral_foundation_inner(left_store, left_authority, right_store, right_authority, None)
        .await
}

async fn commit_bilateral_foundation_inner(
    left_store: &AdmissionAuthorityStore,
    left_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    right_store: &AdmissionAuthorityStore,
    right_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    #[cfg(test)] hook: Option<&BilateralCommitTestHook>,
    #[cfg(not(test))] _hook: Option<()>,
) -> Result<(), StoreError> {
    let left_attempt = left_authority.test_attempt_for_commit();
    let right_attempt = right_authority.test_attempt_for_commit();
    let mut left = match PreparedBilateralCommit::prepare(left_store, left_authority).await {
        Ok(prepared) => prepared,
        Err(error) => {
            // Preparation consumed the authority but did not stage anything.
            // Remove only that immutable attempt, never a peer-wide candidate.
            cancel_pending_attempt_exact(left_store, left_attempt);
            cancel_pending_attempt_exact(right_store, right_attempt);
            return Err(error);
        }
    };
    let mut right = match PreparedBilateralCommit::prepare(right_store, right_authority).await {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = left.abort_exact();
            cancel_pending_attempt_exact(right_store, right_attempt);
            return Err(error);
        }
    };
    #[cfg(test)] if let Err(error) = checkpoint(hook, BilateralCommitCheckpoint::PreflightComplete) {
        // A fault at preflight is before staging, but both authorities have
        // already consumed their live reservations.  Exact cancellation is
        // required so a fresh same-peer retry is not blocked by either
        // pending record or guard.
        let _ = right.abort_exact();
        let _ = left.abort_exact();
        return Err(error);
    }
    let outcome = async {
        left.stage_once(right_attempt)?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::LeftStaged)?;
        right.stage_once(left_attempt)?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::RightStaged)?;

        let left_local = left.local_finalization_receipt()?;
        let right_local = right.local_finalization_receipt()?;
        let (left_exchange, right_exchange) = tokio::join!(
            left.exchange_once(left_local),
            right.exchange_once(right_local),
        );
        left_exchange?;
        right_exchange?;
        let left_receipt = left.receipt()?;
        let right_receipt = right.receipt()?;
        let left_proof = left.proof.as_ref().ok_or(StoreError::Invalid)?;
        let right_proof = right.proof.as_ref().ok_or(StoreError::Invalid)?;
        if left_proof.peer_receipt_hash() != right_receipt.bilateral.local_receipt_hash
            || right_proof.peer_receipt_hash() != left_receipt.bilateral.local_receipt_hash
            || left_proof.identity_generation() != right_receipt.identity_generation
            || left_proof.revocation_generation() != right_receipt.revocation_generation
            || left_proof.policy_revision() != right_receipt.policy_revision
            || right_proof.identity_generation() != left_receipt.identity_generation
            || right_proof.revocation_generation() != left_receipt.revocation_generation
            || right_proof.policy_revision() != left_receipt.policy_revision
        {
            return Err(StoreError::Invalid);
        }
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::Task3ProofsVerified)?;

        let (left_freeze, right_freeze) = tokio::join!(left.freeze_once(), right.freeze_once());
        left_freeze?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::LeftFrozen)?;
        right_freeze?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::RightFrozen)?;

        left.finalize_once()?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::LeftFinalized)?;
        right.finalize_once()?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::RightFinalized)?;
        left.confirm_once()?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::LeftConfirmed)?;
        right.confirm_once()?;
        #[cfg(test)] checkpoint(hook, BilateralCommitCheckpoint::RightConfirmed)?;
        Ok(())
    }
    .await;
    if outcome.is_err() {
        let right_staged = right.abort_exact();
        #[cfg(test)] if right_staged { let _ = checkpoint(hook, BilateralCommitCheckpoint::RightAborted); }
        #[cfg(not(test))]
        let _ = right_staged;
        let left_staged = left.abort_exact();
        #[cfg(test)] if left_staged { let _ = checkpoint(hook, BilateralCommitCheckpoint::LeftAborted); }
        #[cfg(not(test))]
        let _ = left_staged;
    }
    outcome
}

/// Best-effort compensation for an authority consumed before a staged receipt
/// exists.  The key is the immutable attempt id, so this cannot revoke a
/// later same-peer admission or an active pin.
fn cancel_pending_attempt_exact(store: &AdmissionAuthorityStore, attempt: [u8; 32]) {
    if let Ok(version) = store.version() {
        let _ = store.cancel(version, attempt);
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BilateralCommitCheckpoint {
    PreflightComplete,
    LeftStaged,
    RightStaged,
    Task3ProofsVerified,
    LeftFrozen,
    RightFrozen,
    LeftFinalized,
    RightFinalized,
    LeftConfirmed,
    RightConfirmed,
    LeftAborted,
    RightAborted,
    LeftEndpointDropped,
}

#[cfg(test)]
pub(crate) struct BilateralCommitTestHook {
    checkpoints: std::sync::Mutex<Vec<BilateralCommitCheckpoint>>,
    fail_after: Option<BilateralCommitCheckpoint>,
    drop_at: Option<BilateralCommitCheckpoint>,
    left_endpoint: std::sync::Mutex<Option<super::provisional_tls::ProvisionalEndpoint>>,
}

#[cfg(test)]
impl BilateralCommitTestHook {
    pub(crate) fn recording() -> Self {
        Self {
            checkpoints: std::sync::Mutex::new(Vec::new()),
            fail_after: None,
            drop_at: None,
            left_endpoint: std::sync::Mutex::new(None),
        }
    }
    pub(crate) fn with_live_left_endpoint(
        endpoint: super::provisional_tls::ProvisionalEndpoint,
    ) -> Self {
        let hook = Self::recording();
        *hook.left_endpoint.lock().unwrap() = Some(endpoint);
        hook
    }
    pub(crate) fn fail_after(mut self, checkpoint: BilateralCommitCheckpoint) -> Self {
        self.fail_after = Some(checkpoint); self
    }
    pub(crate) fn reject_task3(self) -> Self { self.fail_after(BilateralCommitCheckpoint::RightStaged) }
    pub(crate) fn drop_real_left_endpoint_after(
        checkpoint: BilateralCommitCheckpoint,
        endpoint: super::provisional_tls::ProvisionalEndpoint,
    ) -> Self {
        let mut hook = Self::with_live_left_endpoint(endpoint);
        hook.drop_at = Some(checkpoint);
        hook
    }
    pub(crate) fn checkpoints(&self) -> Vec<BilateralCommitCheckpoint> {
        self.checkpoints.lock().unwrap().clone()
    }
}

#[cfg(test)]
fn checkpoint(
    hook: Option<&BilateralCommitTestHook>,
    point: BilateralCommitCheckpoint,
) -> Result<(), StoreError> {
    let Some(hook) = hook else { return Ok(()); };
    hook.checkpoints.lock().unwrap().push(point);
    if hook.drop_at == Some(point) {
        drop(hook.left_endpoint.lock().unwrap().take());
        hook.checkpoints
            .lock()
            .unwrap()
            .push(BilateralCommitCheckpoint::LeftEndpointDropped);
        return Err(StoreError::Invalid);
    }
    if hook.fail_after == Some(point) { Err(StoreError::Invalid) } else { Ok(()) }
}

#[cfg(test)]
pub(crate) async fn commit_bilateral_foundation_with_test_hook(
    left_store: &AdmissionAuthorityStore,
    left_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    right_store: &AdmissionAuthorityStore,
    right_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    hook: &BilateralCommitTestHook,
) -> Result<(), StoreError> {
    commit_bilateral_foundation_inner(left_store, left_authority, right_store, right_authority, Some(hook)).await
}

fn prepared_bilateral_record(
    local_identity: [u8; 32],
    peer_identity: [u8; 32],
    peer_pin: [u8; 32],
    local_attempt: [u8; 32],
    peer_attempt: [u8; 32],
    transcript: [u8; 32],
    guard_token: [u8; 32],
    identity_generation: u64,
    revocation_generation: u64,
) -> BilateralAdmissionRecord {
    BilateralAdmissionRecord::prepared(
        &BilateralTransactionFields {
            local_identity,
            peer_identity,
            local_attempt,
            peer_attempt,
            peer_pin,
            transcript,
            suite: super::SUITE.to_owned(),
            policy_revision: POLICY_REVISION,
        },
        guard_token,
        identity_generation,
        revocation_generation,
        POLICY_REVISION,
    )
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
        let observation = self.store.resolve_admission_guard(attempt)?;
        let mut state = self.store.admission_state(attempt)?;
        if observation
            .as_ref()
            .is_some_and(|guard| !self.store.admission_guard_still_active(guard))
        {
            // Drop crossed the in-memory linearization point while storage was
            // being read. Complete/retry durable revocation before interpreting
            // the ledger; never return a stale Promoted result.
            self.store.resolve_admission_guard(attempt)?;
            state = self.store.admission_state(attempt)?;
        }
        let (pending, receipt, active) = state;
        match (pending, receipt, active) {
            (true, None, false) => Ok(ReconcileAdmission::Pending),
            (false, Some(_), true) => Ok(ReconcileAdmission::Promoted),
            (false, Some(_), false) => Ok(ReconcileAdmission::Revoked),
            (false, None, false) => Ok(ReconcileAdmission::Absent),
            _ => Err(StoreError::Invalid),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_bilateral_receipt(
        &self,
        attempt: [u8; 32],
    ) -> Result<Option<AdmissionReceiptRecord>, StoreError> {
        Ok(self.store.admission_state(attempt)?.1)
    }

    #[cfg(test)]
    pub(crate) fn test_staged_receipt_uses_prepared_reservation(
        &self,
        attempt: [u8; 32],
        prepared: &PreparedBilateralCommit<'_>,
    ) -> Result<bool, StoreError> {
        Ok(self
            .store
            .admission_state(attempt)?
            .1
            .as_ref()
            .is_some_and(|receipt| prepared.test_staged_matches(receipt)))
    }

    /// Opens only a sealed, local operational preflight lease.  This is
    /// intentionally crate-private: it exposes neither a general durable-pin
    /// lookup nor a transport/input capability.
    #[allow(dead_code)] // Wired by the sealed V01 operational session only.
    pub(crate) fn acquire_operational_preflight_lease(
        &self,
        attempt: [u8; 32],
        view_hash: [u8; 32],
        connection_binding: [u8; 32],
    ) -> Result<crate::pairing_pending::OperationalPreflightLease, StoreError> {
        self.store
            .acquire_operational_preflight_lease(attempt, view_hash, connection_binding)
    }

    #[allow(dead_code)] // Sealed default-off V01 boundary.
    pub(crate) fn operational_admission_snapshot(
        &self,
        attempt: [u8; 32],
    ) -> Result<crate::pairing_pending::OperationalAdmissionSnapshot, StoreError> {
        self.store.operational_admission_snapshot(attempt)
    }

    /// Test-only synthetic entry point. Production can commit only a live sealed
    /// handshake witness through `commit_sealed_foundation`.
    #[cfg(test)]
    pub(crate) fn commit_operational_test_receipt(
        &self,
        record: &PendingRecord,
        peer_pin: [u8; 32],
    ) -> Result<PromotionReceipt, StoreError> {
        self.commit_metadata(
            self.version()?,
            record.revocation_generation,
            record,
            EvidenceFields {
                attempt: record.attempt_id,
                peer: record.peer_fingerprint,
                peer_pin,
                fc: [22; 32],
                role: 0,
                suite: super::SUITE,
                transcript: [23; 32],
                binding: [24; 32],
            },
        )
    }

    #[cfg(test)]
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
        let ownership = AdmissionOwnership::StoreOwned {
            guard_token: record.attempt_id,
            staged_revision: expected.revision,
            handoff_revision: expected.revision.checked_add(1).ok_or(StoreError::Limit)?,
        };
        let mut receipt = AdmissionReceiptRecord {
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
            ownership,
            bilateral: prepared_bilateral_record(
                evidence.peer_pin,
                record.peer_fingerprint,
                evidence.peer_pin,
                record.attempt_id,
                record.attempt_id,
                evidence.transcript,
                record.attempt_id,
                expected.identity_generation,
                expected_revocation_generation,
            ),
        };
        receipt.bilateral.state =
            crate::pairing_pending::BilateralAdmissionState::StoreOwnedAwaitingPeer;
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        let commit = SealedAdmissionCommit::synthetic(record.clone(), receipt, None);
        let stored = self.store.commit_sealed_admission(expected, commit)?;
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
        let commit =
            SealedAdmissionCommit::from_authority(expected, authority, &self.store).await?;
        commit.revalidate()?;
        let staged =
            self.store
                .stage_sealed_admission(expected, commit.record(), commit.receipt())?;
        let attempt = staged.attempt;
        let staged_version = StoreVersion {
            revision: staged.revision,
            identity_generation: staged.identity_generation,
        };
        let handoff = commit.into_live_handoff()?;
        let (stored, mut revoker) =
            match self
                .store
                .finalize_staged_admission(staged_version, attempt, handoff)
            {
                Ok(finalized) => finalized,
                Err(error) => {
                    // The endpoint may have won the one ownership election. A
                    // staged receipt remains ineligible; reconciliation either
                    // completes conservative revocation or reports the I/O error.
                    let _ = self.store.resolve_admission_guard(attempt);
                    return Err(error);
                }
            };
        // The durable final publication is authoritative. A failed exact-token
        // sidecar unlink deliberately returns no ordinary success; a later
        // reconciliation sees StoreOwned and performs cleanup only.
        revoker.release_to_store()?;
        let (_, _, active) = self.store.admission_state(attempt)?;
        if !active {
            return Err(StoreError::Conflict);
        }
        Ok(PromotionReceipt {
            attempt: stored.attempt,
            peer: stored.peer,
            peer_pin: stored.peer_pin,
            trust_revision: stored.revision,
            identity_generation: stored.identity_generation,
            revocation_generation: stored.revocation_generation,
        })
    }

    #[cfg(test)]
    fn commit_metadata_failing_on_validation(
        &self,
        expected: StoreVersion,
        record: &PendingRecord,
        evidence: EvidenceFields,
        fail_on: usize,
    ) -> Result<PromotionReceipt, StoreError> {
        let ownership = AdmissionOwnership::StoreOwned {
            guard_token: record.attempt_id,
            staged_revision: expected.revision,
            handoff_revision: expected.revision.checked_add(1).ok_or(StoreError::Limit)?,
        };
        let mut receipt = AdmissionReceiptRecord {
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
            revocation_generation: record.revocation_generation,
            policy_revision: POLICY_REVISION,
            ownership,
            bilateral: prepared_bilateral_record(
                evidence.peer_pin,
                record.peer_fingerprint,
                evidence.peer_pin,
                record.attempt_id,
                record.attempt_id,
                evidence.transcript,
                record.attempt_id,
                expected.identity_generation,
                record.revocation_generation,
            ),
        };
        receipt.bilateral.state =
            crate::pairing_pending::BilateralAdmissionState::StoreOwnedAwaitingPeer;
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        let commit = SealedAdmissionCommit::synthetic(record.clone(), receipt, Some(fail_on));
        let stored = self.store.commit_sealed_admission(expected, commit)?;
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

enum CommitWitness {
    Live,
    #[cfg(test)]
    Synthetic {
        validations: Cell<usize>,
        fail_on: Option<usize>,
    },
}

/// Unforgeable move-only input to durable admission publication. Fields and
/// constructors are private; production can obtain one only by consuming a
/// completed bilateral handshake authority.
pub(crate) struct SealedAdmissionCommit {
    record: PendingRecord,
    receipt: AdmissionReceiptRecord,
    witness: CommitWitness,
    live_handoff: Option<super::provisional_tls::FrozenAdmissionHandoff>,
}

impl SealedAdmissionCommit {
    async fn from_authority(
        expected: StoreVersion,
        authority: super::provisional_tls::HandshakeCompletePendingAuthority,
        store: &PendingStore,
    ) -> Result<Self, StoreError> {
        let evidence = authority
            .seal_for_promotion()
            .await
            .map_err(|_| StoreError::Invalid)?;
        evidence.revalidate().map_err(|_| StoreError::Invalid)?;
        let frozen = evidence
            .freeze(store)
            .await
            .map_err(|_| StoreError::Invalid)?;
        frozen.revalidate().map_err(|_| StoreError::Invalid)?;
        let (fields, handoff) = frozen.into_store_handoff();
        let ownership = handoff
            .awaiting_handoff_ownership(expected.revision.checked_add(1).ok_or(StoreError::Limit)?);
        let mut receipt = AdmissionReceiptRecord {
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
            bilateral: prepared_bilateral_record(
                fields.certificate_fingerprints[fields.role.index()],
                fields.certificate_fingerprints[1 - fields.role.index()],
                fields.certificate_fingerprints[1 - fields.role.index()],
                fields.record.attempt_id,
                fields.record.attempt_id,
                fields.transcript,
                ownership.guard_token(),
                expected.identity_generation,
                fields.record.revocation_generation,
            ),
            ownership,
        };
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        Ok(Self {
            record: fields.record,
            receipt,
            witness: CommitWitness::Live,
            live_handoff: Some(handoff),
        })
    }

    pub(crate) fn revalidate(&self) -> Result<(), StoreError> {
        match &self.witness {
            // A live witness was revalidated immediately before its immutable
            // fields and private handoff were separated. The handoff itself
            // remains one-shot and is claimed only after staging.
            CommitWitness::Live => Ok(()),
            #[cfg(test)]
            CommitWitness::Synthetic {
                validations,
                fail_on,
            } => {
                let next = validations.get() + 1;
                validations.set(next);
                if *fail_on == Some(next) {
                    Err(StoreError::Invalid)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub(crate) fn record(&self) -> &PendingRecord {
        &self.record
    }

    pub(crate) fn receipt(&self) -> &AdmissionReceiptRecord {
        &self.receipt
    }

    fn into_live_handoff(
        mut self,
    ) -> Result<super::provisional_tls::FrozenAdmissionHandoff, StoreError> {
        match self.witness {
            CommitWitness::Live => self.live_handoff.take().ok_or(StoreError::Invalid),
            #[cfg(test)]
            CommitWitness::Synthetic { .. } => Err(StoreError::Invalid),
        }
    }

    #[cfg(test)]
    fn synthetic(
        record: PendingRecord,
        receipt: AdmissionReceiptRecord,
        fail_on: Option<usize>,
    ) -> Self {
        Self {
            record,
            receipt,
            witness: CommitWitness::Synthetic {
                validations: Cell::new(0),
                fail_on,
            },
            live_handoff: None,
        }
    }
}

#[cfg(test)]
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

    fn awaiting_receipt(record: &PendingRecord, expected: StoreVersion) -> AdmissionReceiptRecord {
        let evidence = evidence(record);
        let revision = expected.revision.checked_add(1).unwrap();
        let ownership = AdmissionOwnership::AwaitingHandoff {
            guard_token: [46; 32],
            staged_revision: revision,
        };
        let mut receipt = AdmissionReceiptRecord {
            attempt: evidence.attempt,
            peer: evidence.peer,
            peer_pin: evidence.peer_pin,
            durable_fc_hash: evidence.fc,
            role: evidence.role,
            suite: evidence.suite.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            transcript: evidence.transcript,
            binding: evidence.binding,
            revision,
            identity_generation: expected.identity_generation,
            revocation_generation: record.revocation_generation,
            policy_revision: POLICY_REVISION,
            bilateral: prepared_bilateral_record(
                evidence.peer_pin,
                record.peer_fingerprint,
                evidence.peer_pin,
                record.attempt_id,
                record.attempt_id,
                evidence.transcript,
                ownership.guard_token(),
                expected.identity_generation,
                record.revocation_generation,
            ),
            ownership,
        };
        bind_prepared_bilateral_receipt_hash(&mut receipt);
        receipt
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
    fn incompatible_pin_retry_is_rejected_before_partial_consumption() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [31; 32], [32; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &first, evidence(&first))
            .unwrap();
        assert_eq!(
            store.prepare(store.version().unwrap(), [33; 32], first.peer_fingerprint),
            Err(StoreError::Conflict)
        );
        assert_eq!(
            store.reconcile(first.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
    }

    #[test]
    fn second_attempt_for_same_peer_and_pin_is_rejected_without_inheriting_pin() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [41; 32], [42; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &first, evidence(&first))
            .unwrap();
        assert_eq!(
            store.prepare(store.version().unwrap(), [43; 32], first.peer_fingerprint),
            Err(StoreError::Conflict)
        );
        assert_eq!(
            store.reconcile(first.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
    }

    #[test]
    fn staged_peer_reservation_rejects_retry_before_finalization() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [44; 32], [45; 32])
            .unwrap();
        let expected = store.version().unwrap();
        let staged = awaiting_receipt(&first, expected);
        store
            .store
            .stage_sealed_admission(expected, &first, &staged)
            .unwrap();

        let retry = [47; 32];
        assert_eq!(
            store.prepare(store.version().unwrap(), retry, first.peer_fingerprint),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.pending(retry).unwrap(), None);
    }

    #[test]
    fn cancellation_and_revocation_release_peer_reservations() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let pending = store
            .prepare(store.version().unwrap(), [48; 32], [49; 32])
            .unwrap();
        store
            .cancel(store.version().unwrap(), pending.attempt_id)
            .unwrap();
        store
            .prepare(store.version().unwrap(), [50; 32], pending.peer_fingerprint)
            .unwrap();

        let staged = store
            .prepare(store.version().unwrap(), [51; 32], [52; 32])
            .unwrap();
        let expected = store.version().unwrap();
        store
            .store
            .stage_sealed_admission(expected, &staged, &awaiting_receipt(&staged, expected))
            .unwrap();
        store
            .revoke_candidate(store.version().unwrap(), staged.peer_fingerprint)
            .unwrap();
        store
            .prepare(store.version().unwrap(), [53; 32], staged.peer_fingerprint)
            .unwrap();
    }

    #[test]
    fn stale_cancelled_guard_cannot_revoke_newer_promoted_peer() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [54; 32], [55; 32])
            .unwrap();
        let mut stale = store
            .store
            .admission_revoker(first.peer_fingerprint, first.attempt_id)
            .unwrap();
        stale.arm();
        store
            .cancel(store.version().unwrap(), first.attempt_id)
            .unwrap();

        let replacement = store
            .prepare(store.version().unwrap(), [56; 32], first.peer_fingerprint)
            .unwrap();
        store
            .commit_metadata(
                store.version().unwrap(),
                replacement.revocation_generation,
                &replacement,
                evidence(&replacement),
            )
            .unwrap();
        stale.revoke().unwrap();

        assert_eq!(
            store.reconcile(replacement.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
    }

    #[test]
    fn identity_rotation_releases_pending_peer_reservation() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let pending = store
            .prepare(store.version().unwrap(), [57; 32], [58; 32])
            .unwrap();
        store
            .store
            .rotate_identity(store.version().unwrap())
            .unwrap();
        store
            .prepare(store.version().unwrap(), [59; 32], pending.peer_fingerprint)
            .unwrap();
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
    fn store_owned_receipt_cannot_acquire_operational_lease_before_bilateral_confirmation() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [81; 32], [82; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();

        assert!(matches!(
            store.acquire_operational_preflight_lease(record.attempt_id, [83; 32], [84; 32]),
            Err(StoreError::Invalid)
        ));
        assert_eq!(
            store.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
    }

    #[test]
    fn store_owned_snapshot_is_inactive_before_bilateral_confirmation() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [79; 32], [78; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();
        assert_eq!(
            store.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn persisted_bilateral_confirmed_without_authenticated_proof_is_non_operational() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [80; 32], [81; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();

        let ledger_path = root.path().join("pairing-tombstones/ledger.json");
        let mut ledger: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
        ledger["admission_receipts"][0]["bilateral"]["state"] =
            serde_json::json!("bilateral_confirmed");
        ledger["admission_receipts"][0]["bilateral"]["peer_receipt_hash"] =
            serde_json::to_value([82u8; 32]).unwrap();
        std::fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();

        let reopened = AdmissionAuthorityStore::open(root.path()).unwrap();
        assert!(matches!(
            reopened.operational_admission_snapshot(record.attempt_id),
            Err(StoreError::Invalid)
        ));
        assert!(matches!(
            reopened.acquire_operational_preflight_lease(record.attempt_id, [83; 32], [84; 32]),
            Err(StoreError::Invalid)
        ));
    }

    #[test]
    fn inactive_store_owned_receipt_remains_non_operational_after_revoke_or_rotation() {
        for rotate in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let store = AdmissionAuthorityStore::open(root.path()).unwrap();
            let record = store
                .prepare(store.version().unwrap(), [85; 32], [86; 32])
                .unwrap();
            store
                .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
                .unwrap();
            assert!(matches!(
                store.acquire_operational_preflight_lease(record.attempt_id, [87; 32], [88; 32]),
                Err(StoreError::Invalid)
            ));

            if rotate {
                store
                    .store
                    .rotate_identity(store.version().unwrap())
                    .unwrap();
            } else {
                store
                    .revoke_candidate(store.version().unwrap(), record.peer_fingerprint)
                    .unwrap();
            }
            assert_eq!(
                store.operational_admission_snapshot(record.attempt_id),
                Err(StoreError::Invalid)
            );
        }
    }

    #[test]
    fn inactive_store_owned_receipt_cannot_race_into_an_operational_lease() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [91; 32], [92; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
            .unwrap();
        assert!(matches!(
            store.acquire_operational_preflight_lease(record.attempt_id, [93; 32], [94; 32]),
            Err(StoreError::Invalid)
        ));
        assert_eq!(
            store.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
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
    fn downgraded_or_impossible_receipt_fails_closed_on_reopen() {
        for (field, replacement) in [
            ("suite", serde_json::json!("legacy-suite")),
            ("protocol_version", serde_json::json!(99)),
            ("revision", serde_json::json!(u64::MAX)),
        ] {
            let root = tempfile::tempdir().unwrap();
            let store = AdmissionAuthorityStore::open(root.path()).unwrap();
            let record = store
                .prepare(store.version().unwrap(), [71; 32], [72; 32])
                .unwrap();
            store
                .commit_metadata(store.version().unwrap(), 0, &record, evidence(&record))
                .unwrap();
            let ledger_path = root.path().join("pairing-tombstones/ledger.json");
            let mut ledger: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
            ledger["admission_receipts"][0][field] = replacement;
            std::fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
            assert!(
                AdmissionAuthorityStore::open(root.path()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn ownership_schema_is_required_ordered_unique_and_store_owned_for_pins() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [101; 32], [102; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &first, evidence(&first))
            .unwrap();
        let ledger_path = root.path().join("pairing-tombstones/ledger.json");
        let valid = std::fs::read(&ledger_path).unwrap();

        let mutations: [fn(&mut serde_json::Value); 5] = [
            |ledger: &mut serde_json::Value| {
                ledger["schema"] = serde_json::json!(1);
            },
            |ledger: &mut serde_json::Value| {
                ledger["admission_receipts"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("ownership");
            },
            |ledger: &mut serde_json::Value| {
                ledger["admission_receipts"][0]["ownership"]["guard_token"] =
                    serde_json::to_value([0u8; 32]).unwrap();
            },
            |ledger: &mut serde_json::Value| {
                let revision = ledger["admission_receipts"][0]["revision"]
                    .as_u64()
                    .unwrap();
                ledger["admission_receipts"][0]["ownership"]["staged_revision"] =
                    serde_json::json!(revision);
            },
            |ledger: &mut serde_json::Value| {
                ledger["admission_receipts"][0]["ownership"]["state"] =
                    serde_json::json!("awaiting_handoff");
                ledger["admission_receipts"][0]["ownership"]
                    .as_object_mut()
                    .unwrap()
                    .remove("handoff_revision");
            },
        ];
        for mutate in mutations {
            let mut ledger: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
            mutate(&mut ledger);
            std::fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
            assert!(AdmissionAuthorityStore::open(root.path()).is_err());
            std::fs::write(&ledger_path, &valid).unwrap();
        }
    }

    #[test]
    fn pending_ledger_without_peer_reservation_fails_closed_on_reopen() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        store
            .prepare(store.version().unwrap(), [107; 32], [108; 32])
            .unwrap();
        let ledger_path = root.path().join("pairing-tombstones/ledger.json");
        let mut ledger: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
        ledger
            .as_object_mut()
            .unwrap()
            .remove("admission_reservations");
        std::fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        assert!(AdmissionAuthorityStore::open(root.path()).is_err());
    }

    #[test]
    fn repeated_admission_guard_tokens_fail_closed_on_reopen() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let first = store
            .prepare(store.version().unwrap(), [111; 32], [112; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &first, evidence(&first))
            .unwrap();
        let second = store
            .prepare(store.version().unwrap(), [113; 32], [114; 32])
            .unwrap();
        store
            .commit_metadata(store.version().unwrap(), 0, &second, evidence(&second))
            .unwrap();
        let ledger_path = root.path().join("pairing-tombstones/ledger.json");
        let mut ledger: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
        let token = ledger["admission_receipts"][0]["ownership"]["guard_token"].clone();
        ledger["admission_receipts"][1]["ownership"]["guard_token"] = token;
        std::fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
        assert!(AdmissionAuthorityStore::open(root.path()).is_err());
    }

    #[test]
    fn fourth_late_invalidation_never_reconciles_as_promoted() {
        let root = tempfile::tempdir().unwrap();
        let store = AdmissionAuthorityStore::open(root.path()).unwrap();
        let record = store
            .prepare(store.version().unwrap(), [73; 32], [74; 32])
            .unwrap();
        let result = store.commit_metadata_failing_on_validation(
            store.version().unwrap(),
            &record,
            evidence(&record),
            4,
        );
        assert_eq!(result, Err(StoreError::Invalid));
        assert_ne!(
            store.reconcile(record.attempt_id).unwrap(),
            ReconcileAdmission::Promoted
        );
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
        for (stage, expected, mode) in [
            ("before_write", ReconcileAdmission::Pending),
            ("after_write", ReconcileAdmission::Pending),
            ("before_file_sync", ReconcileAdmission::Pending),
            ("after_file_sync", ReconcileAdmission::Pending),
            ("before_rename", ReconcileAdmission::Pending),
            ("after_rename", ReconcileAdmission::Promoted),
            ("before_dir_sync", ReconcileAdmission::Promoted),
            ("after_dir_sync", ReconcileAdmission::Promoted),
            ("before_readback", ReconcileAdmission::Promoted),
            ("after_readback", ReconcileAdmission::Promoted),
            ("before_cleanup", ReconcileAdmission::Promoted),
            ("after_cleanup", ReconcileAdmission::Promoted),
        ]
        .into_iter()
        .flat_map(|(stage, expected)| [(stage, expected, "error"), (stage, expected, "crash")])
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
            assert_eq!(
                reopened.reconcile([51; 32]).unwrap(),
                expected,
                "{stage}:{mode}"
            );
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
