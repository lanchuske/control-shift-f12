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
    RemoteOutcomeUnknown,
    Revoked,
    Absent,
}

/// Opaque metadata result for G4. It is deliberately not a transport, input,
/// clipboard, layout or operational-session capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributedAdmissionSummary {
    attempt: [u8; 32],
    state: ReconcileAdmission,
}

/// Public G4 boundary for a UI: it exposes only user verification and the
/// durable admission outcome, never the pending store or transport authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DistributedPairingError {
    #[error("pairing was rejected")]
    Rejected,
    #[error("pairing was cancelled")]
    Cancelled,
    #[error("durable pairing state could not be committed")]
    Storage,
}

pub async fn handshake_and_commit_distributed<F, Fut>(
    store: &AdmissionAuthorityStore,
    channel: super::provisional_tls::ProvisionalChannel,
    config: super::provisional_tls::HandshakeConfig,
    confirm: F,
) -> Result<DistributedAdmissionSummary, DistributedPairingError>
where
    F: FnOnce(super::provisional_tls::VerificationPrompt) -> Fut,
    Fut: std::future::Future<Output = super::provisional_tls::VerificationDecision>,
{
    let authority = channel
        .handshake(config, &store.store, confirm)
        .await
        .map_err(|error| match error {
            super::provisional_tls::HandshakeError::Cancelled => DistributedPairingError::Cancelled,
            super::provisional_tls::HandshakeError::Rejected => DistributedPairingError::Rejected,
        })?;
    store
        .commit_distributed(authority)
        .await
        .map_err(|_| DistributedPairingError::Storage)
}

impl DistributedAdmissionSummary {
    pub fn attempt(&self) -> [u8; 32] {
        self.attempt
    }

    pub fn is_confirmed(&self) -> bool {
        self.state == ReconcileAdmission::Promoted
    }

    pub fn state(&self) -> ReconcileAdmission {
        self.state
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BilateralCommitPhase {
    Prepared,
    Staged,
    ProofVerified,
    Frozen,
    Finalized,
    PeerCommitVerified,
    Confirmed,
    Quarantined,
    Aborted,
}

/// The one private owner of a live authority and its exact durable reservation.
/// It has no public constructor, no clone/debug/serialization implementation,
/// and each phase transition is deliberately one-shot.
pub(crate) struct PreparedBilateralCommit<'a> {
    store: &'a PendingStore,
    live: Option<super::provisional_tls::PreparedHandshakeAuthority>,
    frozen: Option<super::provisional_tls::FrozenPromotionEvidence>,
    distributed_frozen: Option<super::provisional_tls::DistributedFrozenHandshakeAuthority>,
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
            distributed_frozen: None,
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
        let stored = self
            .store
            .stage_sealed_admission(expected, &fields.record, &receipt)?;
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
            .local_receipt(
                receipt.bilateral.fields.peer_attempt,
                receipt.bilateral.local_receipt_hash,
            )
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

    async fn freeze_distributed_once(&mut self) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::ProofVerified || self.proof.is_none() {
            return Err(StoreError::Invalid);
        }
        let live = self.live.take().ok_or(StoreError::Invalid)?;
        let frozen = live
            .freeze_distributed()
            .await
            .map_err(|_| StoreError::Invalid)?;
        self.distributed_frozen = Some(frozen);
        self.phase = BilateralCommitPhase::Frozen;
        Ok(())
    }

    async fn finalize_once(
        &mut self,
        #[cfg(test)] hook: Option<&BilateralCommitTestHook>,
        #[cfg(not(test))] _hook: Option<()>,
    ) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Frozen {
            return Err(StoreError::Invalid);
        }
        let attempt = self.attempt()?;
        let expected = self.store.version()?;
        let frozen = self.frozen.take().ok_or(StoreError::Invalid)?;
        let (stored, mut revoker) = self.store.finalize_staged_admission(
            expected,
            attempt,
            frozen.into_store_handoff().1,
        )?;
        #[cfg(test)]
        if hook.is_some_and(|hook| {
            hook.pause_at == Some(BilateralCommitCheckpoint::StoreOwnedBeforeRelease)
        }) {
            checkpoint(hook, BilateralCommitCheckpoint::StoreOwnedBeforeRelease)?;
            pause_at_checkpoint(hook, BilateralCommitCheckpoint::StoreOwnedBeforeRelease).await;
        }
        revoker.release_to_store()?;
        self.receipt = Some(stored);
        self.phase = BilateralCommitPhase::Finalized;
        Ok(())
    }

    async fn finalize_distributed_once(&mut self) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Frozen {
            return Err(StoreError::Invalid);
        }
        let attempt = self.attempt()?;
        let expected = self.store.version()?;
        let handoff = self
            .distributed_frozen
            .as_mut()
            .ok_or(StoreError::Invalid)?
            .take_store_handoff()
            .map_err(|_| StoreError::Invalid)?;
        let (stored, mut revoker) = self
            .store
            .finalize_staged_admission(expected, attempt, handoff)?;
        revoker.release_to_store()?;
        self.receipt = Some(stored);
        self.phase = BilateralCommitPhase::Finalized;
        Ok(())
    }

    async fn exchange_durable_commit_once(&mut self) -> Result<(), StoreError> {
        if self.phase != BilateralCommitPhase::Finalized {
            return Err(StoreError::Invalid);
        }
        let receipt = self.receipt()?.clone();
        let proof = self.proof.as_ref().ok_or(StoreError::Invalid)?;
        let statement = super::provisional_tls::LocalDurableCommit::new(
            receipt.bilateral.transaction_id,
            receipt.bilateral.local_receipt_hash,
            proof.peer_receipt_hash(),
            receipt.transcript,
            receipt.identity_generation,
            receipt.revocation_generation,
            proof.identity_generation(),
            proof.revocation_generation(),
            receipt.policy_revision,
        )
        .map_err(|_| StoreError::Invalid)?;
        self.distributed_frozen
            .as_mut()
            .ok_or(StoreError::Invalid)?
            .exchange_durable_commit(statement)
            .await
            .map_err(|_| StoreError::Invalid)?;
        self.phase = BilateralCommitPhase::PeerCommitVerified;
        Ok(())
    }

    fn confirm_once(&mut self) -> Result<(), StoreError> {
        if !matches!(
            self.phase,
            BilateralCommitPhase::Finalized | BilateralCommitPhase::PeerCommitVerified
        ) {
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
        if let Some(frozen) = self.distributed_frozen.take() {
            frozen.close_confirmed();
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        self.live = None;
        self.frozen = None;
        self.distributed_frozen = None;
        self.phase = BilateralCommitPhase::Quarantined;
    }

    fn abort_exact(&mut self) -> bool {
        if matches!(
            self.phase,
            BilateralCommitPhase::Aborted | BilateralCommitPhase::Quarantined
        ) {
            return false;
        }
        let mut staged = false;
        if let Some(frozen) = self.frozen.take() {
            staged = frozen.abort_exact().is_ok();
        } else if let Some(live) = self.live.take() {
            staged = live.abort_exact().is_ok();
        }
        if !staged {
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
                    } else if let (Ok(version), Ok((_, Some(current), _))) = (
                        self.store.version(),
                        self.store.admission_state(receipt.attempt),
                    ) {
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

// A coordinator future may be cancelled at any `.await` after it has consumed
// a live authority.  Its only safe terminal action is to remove the exact
// attempt/transaction/guard it owns; never infer a peer-wide revocation.
// Successful confirmation and an explicit abort both disarm this owner.
impl Drop for PreparedBilateralCommit<'_> {
    fn drop(&mut self) {
        if self.distributed_frozen.is_some()
            && matches!(
                self.phase,
                BilateralCommitPhase::Finalized | BilateralCommitPhase::PeerCommitVerified
            )
        {
            // Cancellation of the coordinator future after local publication
            // is an ambiguous remote outcome, never evidence that rollback is
            // safe. Dropping the channel preserves the store-owned receipt.
            self.quarantine();
            return;
        }
        if !matches!(
            self.phase,
            BilateralCommitPhase::Confirmed
                | BilateralCommitPhase::Quarantined
                | BilateralCommitPhase::Aborted
        ) {
            let _ = self.abort_exact();
        }
    }
}

pub(crate) async fn commit_bilateral_foundation(
    left_store: &AdmissionAuthorityStore,
    left_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    right_store: &AdmissionAuthorityStore,
    right_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
) -> Result<(), StoreError> {
    commit_bilateral_foundation_inner(
        left_store,
        left_authority,
        right_store,
        right_authority,
        None,
    )
    .await
}

async fn commit_bilateral_foundation_inner(
    left_store: &AdmissionAuthorityStore,
    left_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    right_store: &AdmissionAuthorityStore,
    right_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    #[cfg(test)] hook: Option<&BilateralCommitTestHook>,
    #[cfg(not(test))] hook: Option<()>,
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
    #[cfg(test)]
    if let Err(error) = checkpoint(hook, BilateralCommitCheckpoint::PreflightComplete) {
        // A fault at preflight is before staging, but both authorities have
        // already consumed their live reservations.  Exact cancellation is
        // required so a fresh same-peer retry is not blocked by either
        // pending record or guard.
        let _ = right.abort_exact();
        let _ = left.abort_exact();
        return Err(error);
    }
    #[cfg(test)]
    pause_at_checkpoint(hook, BilateralCommitCheckpoint::PreflightComplete).await;
    let outcome = async {
        left.stage_once(right_attempt)?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::LeftStaged)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::LeftStaged).await;
        right.stage_once(left_attempt)?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::RightStaged)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::RightStaged).await;

        #[cfg(test)]
        let mut left_local = left.local_finalization_receipt()?;
        #[cfg(not(test))]
        let left_local = left.local_finalization_receipt()?;
        let right_local = right.local_finalization_receipt()?;
        #[cfg(test)]
        if hook
            .as_ref()
            .is_some_and(|hook| hook.wrong_transaction_on_wire)
        {
            left_local.test_fault_wrong_transaction_on_wire();
        }
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::Task3ProofsAttempted)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::Task3ProofsAttempted).await;
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
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::Task3ProofsVerified)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::Task3ProofsVerified).await;

        let (left_freeze, right_freeze) = tokio::join!(left.freeze_once(), right.freeze_once());
        left_freeze?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::LeftFrozen)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::LeftFrozen).await;
        right_freeze?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::RightFrozen)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::RightFrozen).await;

        left.finalize_once(hook).await?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::LeftFinalized)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::LeftFinalized).await;
        right.finalize_once(hook).await?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::RightFinalized)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::RightFinalized).await;
        left.confirm_once()?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::LeftConfirmed)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::LeftConfirmed).await;
        right.confirm_once()?;
        #[cfg(test)]
        checkpoint(hook, BilateralCommitCheckpoint::RightConfirmed)?;
        #[cfg(test)]
        pause_at_checkpoint(hook, BilateralCommitCheckpoint::RightConfirmed).await;
        Ok(())
    }
    .await;
    if outcome.is_err() {
        let right_staged = right.abort_exact();
        #[cfg(test)]
        if right_staged {
            let _ = checkpoint(hook, BilateralCommitCheckpoint::RightAborted);
        }
        #[cfg(not(test))]
        let _ = right_staged;
        let left_staged = left.abort_exact();
        #[cfg(test)]
        if left_staged {
            let _ = checkpoint(hook, BilateralCommitCheckpoint::LeftAborted);
        }
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

/// Recovery-only counterpart of the bilateral foundation coordinator. The
/// caller owns the fresh control connections for both durable stores; absent
/// channels are an explicit failure, never evidence that a peer committed.
/// Success records reciprocal receipt hashes only and grants no runtime lease.
pub(crate) async fn recover_bilateral_foundation(
    left: &AdmissionAuthorityStore,
    left_attempt: [u8; 32],
    right: &AdmissionAuthorityStore,
    right_attempt: [u8; 32],
    channels: Option<(&quinn::Connection, &quinn::Connection)>,
) -> Result<(), StoreError> {
    // Reconcile stale guards before capturing receipts. A staged dead owner is
    // independently exact-aborted by the existing sidecar resolver.
    let left_receipt = capture_recovery_receipt(left, left_attempt);
    let right_receipt = capture_recovery_receipt(right, right_attempt);
    let outcome = async {
        let local_left = left_receipt
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or(StoreError::Invalid)?;
        let local_right = right_receipt
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or(StoreError::Invalid)?;
        let (left_channel, right_channel) = channels.ok_or(StoreError::Unavailable)?;
        if local_left.bilateral.transaction_id != local_right.bilateral.transaction_id
            || local_left.bilateral.fields.peer_attempt != right_attempt
            || local_right.bilateral.fields.peer_attempt != left_attempt
            || local_left.bilateral.fields.local_identity != local_right.peer
            || local_right.bilateral.fields.local_identity != local_left.peer
        {
            return Err(StoreError::Invalid);
        }
        let left_evidence = left.store.recovery_evidence(left_attempt)?;
        let right_evidence = right.store.recovery_evidence(right_attempt)?;
        let (left_peer, right_peer) = tokio::join!(
            super::recovery::exchange_exact_pair(
                left_channel,
                true,
                left_evidence.clone(),
                local_left.peer_pin
            ),
            super::recovery::exchange_exact_pair(
                right_channel,
                false,
                right_evidence.clone(),
                local_right.peer_pin
            ),
        );
        let left_peer = left_peer.map_err(|_| StoreError::Invalid)?;
        let right_peer = right_peer.map_err(|_| StoreError::Invalid)?;
        if left_peer.evidence() != &right_evidence || right_peer.evidence() != &left_evidence {
            return Err(StoreError::Invalid);
        }
        left.store
            .confirm_authenticated_peer_recovery(left_attempt, left_peer)?;
        right
            .store
            .confirm_authenticated_peer_recovery(right_attempt, right_peer)?;
        Ok(())
    }
    .await;
    if outcome.is_err() {
        if let Some((left, right)) = channels {
            left.close(0u32.into(), b"exact recovery aborted");
            right.close(0u32.into(), b"exact recovery aborted");
        }
        // Both cleanups run even when the first fails. Retain captured immutable
        // tuples across the await: never replace them with a newer peer receipt.
        let left_abort =
            abort_recovery_receipt(left, left_receipt.as_ref().ok().and_then(Option::as_ref));
        let right_abort =
            abort_recovery_receipt(right, right_receipt.as_ref().ok().and_then(Option::as_ref));
        left_abort?;
        right_abort?;
    }
    outcome
}

fn capture_recovery_receipt(
    store: &AdmissionAuthorityStore,
    attempt: [u8; 32],
) -> Result<Option<AdmissionReceiptRecord>, StoreError> {
    if store.store.resolve_admission_guard(attempt)?.is_some() {
        // An active owner must never become a compensation target. The peer
        // capture is independent, so its interrupted tuple can still abort.
        return Err(StoreError::Conflict);
    }
    Ok(store.store.admission_state(attempt)?.1)
}

fn abort_recovery_receipt(
    store: &AdmissionAuthorityStore,
    receipt: Option<&AdmissionReceiptRecord>,
) -> Result<(), StoreError> {
    let Some(receipt) = receipt else {
        return Ok(());
    };
    store.store.abort_bilateral_transaction(
        store.version()?,
        receipt.attempt,
        receipt.bilateral.transaction_id,
        receipt.bilateral.guard_token,
    )?;
    store
        .store
        .clear_admission_guard_exact(receipt.attempt, receipt.bilateral.guard_token)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BilateralCommitCheckpoint {
    PreflightComplete,
    LeftStaged,
    RightStaged,
    Task3ProofsAttempted,
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
    StoreOwnedBeforeRelease,
}

#[cfg(test)]
pub(crate) struct BilateralCommitTestHook {
    checkpoints: std::sync::Mutex<Vec<BilateralCommitCheckpoint>>,
    fail_after: Option<BilateralCommitCheckpoint>,
    drop_at: Option<BilateralCommitCheckpoint>,
    wrong_transaction_on_wire: bool,
    pause_at: Option<BilateralCommitCheckpoint>,
    pause: Option<BilateralCommitPause>,
    left_endpoint: std::sync::Mutex<Option<super::provisional_tls::ProvisionalEndpoint>>,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct BilateralCommitPause {
    reached: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reached_notify: std::sync::Arc<tokio::sync::Notify>,
    resume: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl BilateralCommitPause {
    async fn pause_here(&self) {
        self.reached
            .store(true, std::sync::atomic::Ordering::Release);
        self.reached_notify.notify_waiters();
        self.resume.notified().await;
    }

    pub(crate) async fn wait_until_reached(&self) {
        loop {
            if self.reached.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            self.reached_notify.notified().await;
        }
    }

    pub(crate) fn resume(&self) {
        self.resume.notify_waiters();
    }
}

#[cfg(test)]
impl BilateralCommitTestHook {
    pub(crate) fn recording() -> Self {
        Self {
            checkpoints: std::sync::Mutex::new(Vec::new()),
            fail_after: None,
            drop_at: None,
            wrong_transaction_on_wire: false,
            pause_at: None,
            pause: None,
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
        self.fail_after = Some(checkpoint);
        self
    }
    pub(crate) fn wrong_transaction_on_wire(mut self) -> Self {
        self.wrong_transaction_on_wire = true;
        self
    }
    pub(crate) fn pause_after(
        mut self,
        checkpoint: BilateralCommitCheckpoint,
    ) -> (Self, BilateralCommitPause) {
        let pause = BilateralCommitPause {
            reached: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reached_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            resume: std::sync::Arc::new(tokio::sync::Notify::new()),
        };
        self.pause_at = Some(checkpoint);
        self.pause = Some(pause.clone());
        (self, pause)
    }
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
    let Some(hook) = hook else {
        return Ok(());
    };
    hook.checkpoints.lock().unwrap().push(point);
    if hook.drop_at == Some(point) {
        drop(hook.left_endpoint.lock().unwrap().take());
        hook.checkpoints
            .lock()
            .unwrap()
            .push(BilateralCommitCheckpoint::LeftEndpointDropped);
        return Err(StoreError::Invalid);
    }
    if hook.fail_after == Some(point) {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
async fn pause_at_checkpoint(
    hook: Option<&BilateralCommitTestHook>,
    checkpoint: BilateralCommitCheckpoint,
) {
    if let Some(pause) = hook
        .filter(|hook| hook.pause_at == Some(checkpoint))
        .and_then(|hook| hook.pause.as_ref())
    {
        pause.pause_here().await;
    }
}

#[cfg(test)]
pub(crate) async fn commit_bilateral_foundation_with_test_hook(
    left_store: &AdmissionAuthorityStore,
    left_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    right_store: &AdmissionAuthorityStore,
    right_authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    hook: &BilateralCommitTestHook,
) -> Result<(), StoreError> {
    commit_bilateral_foundation_inner(
        left_store,
        left_authority,
        right_store,
        right_authority,
        Some(hook),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // Mirrors the immutable bilateral wire fields explicitly.
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

    pub(crate) fn pending_store_for_handshake(&self) -> &PendingStore {
        &self.store
    }

    pub async fn commit_distributed(
        &self,
        authority: super::provisional_tls::HandshakeCompletePendingAuthority,
    ) -> Result<DistributedAdmissionSummary, StoreError> {
        let attempt = authority.test_attempt_for_commit();
        let mut commit = match PreparedBilateralCommit::prepare(self, authority).await {
            Ok(commit) => commit,
            Err(error) => {
                cancel_pending_attempt_exact(self, attempt);
                return Err(error);
            }
        };
        let outcome = async {
            // Both halves derive the same attempt from the authenticated
            // transcript. The receipt exchange below rejects any asymmetric
            // transaction before either local handoff can be finalized.
            commit.stage_once(attempt)?;
            #[cfg(test)]
            distributed_process_checkpoint("after_stage");
            let local = commit.local_finalization_receipt()?;
            commit.exchange_once(local).await?;
            commit.freeze_distributed_once().await?;
            commit.finalize_distributed_once().await?;
            #[cfg(test)]
            distributed_process_checkpoint("after_local_commit");
            commit.exchange_durable_commit_once().await?;
            #[cfg(test)]
            distributed_process_checkpoint("after_durable_exchange");
            commit.confirm_once()?;
            Ok(DistributedAdmissionSummary {
                attempt,
                state: ReconcileAdmission::Promoted,
            })
        }
        .await;
        if outcome.is_err() {
            #[cfg(test)]
            eprintln!("distributed admission failed in phase {:?}", commit.phase);
            if matches!(
                commit.phase,
                BilateralCommitPhase::Finalized | BilateralCommitPhase::PeerCommitVerified
            ) {
                // The store now owns an active exact receipt. Transport loss
                // cannot prove the peer's final outcome, so retain quarantine
                // for authenticated recovery instead of pretending rollback.
                commit.quarantine();
                return Ok(DistributedAdmissionSummary {
                    attempt,
                    state: ReconcileAdmission::RemoteOutcomeUnknown,
                });
            } else {
                let _ = commit.abort_exact();
            }
        }
        outcome
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

    /// G4-only metadata classification. Unlike the legacy foundation view,
    /// store ownership without authenticated peer commit proof is quarantined.
    pub fn reconcile_distributed(
        &self,
        attempt: [u8; 32],
    ) -> Result<ReconcileAdmission, StoreError> {
        let state = self.reconcile(attempt)?;
        if state != ReconcileAdmission::Promoted {
            return Ok(state);
        }
        let (_, receipt, active) = self.store.admission_state(attempt)?;
        let receipt = receipt.ok_or(StoreError::Invalid)?;
        if !active {
            return Err(StoreError::Invalid);
        }
        if matches!(
            receipt.bilateral.state,
            crate::pairing_pending::BilateralAdmissionState::BilateralConfirmed
        ) {
            Ok(ReconcileAdmission::Promoted)
        } else {
            Ok(ReconcileAdmission::RemoteOutcomeUnknown)
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
    pub(crate) fn test_has_admission_guard(&self, attempt: [u8; 32]) -> Result<bool, StoreError> {
        Ok(self.store.resolve_admission_guard(attempt)?.is_some())
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

#[cfg(test)]
fn distributed_process_checkpoint(name: &str) {
    if let Ok(mode) = std::env::var("CSF12_DISTRIBUTED_COMMIT_CRASH") {
        if mode == name {
            std::process::exit(92);
        }
        if mode == format!("stall_{name}") {
            loop {
                std::thread::park();
            }
        }
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

    #[tokio::test]
    async fn recovery_malformed_sidecar_still_exact_aborts_the_other_store() {
        for malformed_left in [true, false] {
            let left_root = tempfile::tempdir().unwrap();
            let right_root = tempfile::tempdir().unwrap();
            let left = AdmissionAuthorityStore::open(left_root.path()).unwrap();
            let right = AdmissionAuthorityStore::open(right_root.path()).unwrap();
            let a = left
                .prepare(left.version().unwrap(), [191; 32], [192; 32])
                .unwrap();
            let b = right
                .prepare(right.version().unwrap(), [193; 32], [194; 32])
                .unwrap();
            left.commit_operational_test_receipt(&a, [195; 32]).unwrap();
            right
                .commit_operational_test_receipt(&b, [196; 32])
                .unwrap();
            let (bad_root, bad_attempt, valid, valid_record) = if malformed_left {
                (left_root.path(), a.attempt_id, &right, &b)
            } else {
                (right_root.path(), b.attempt_id, &left, &a)
            };
            let hex: String = bad_attempt
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            std::fs::write(
                bad_root
                    .join("pairing-tombstones")
                    .join(format!("admission-revocation-{hex}.json")),
                b"malformed sidecar",
            )
            .unwrap();
            assert!(
                recover_bilateral_foundation(&left, a.attempt_id, &right, b.attempt_id, None)
                    .await
                    .is_err()
            );
            assert_eq!(
                valid.reconcile(valid_record.attempt_id).unwrap(),
                ReconcileAdmission::Absent,
                "one malformed sidecar must not skip the other immutable transaction's cleanup"
            );
            assert!(
                valid
                    .operational_admission_snapshot(valid_record.attempt_id)
                    .is_err()
            );
            valid
                .prepare(
                    valid.version().unwrap(),
                    [197; 32],
                    valid_record.peer_fingerprint,
                )
                .unwrap();
        }
    }

    #[tokio::test]
    async fn recovery_active_owner_is_preserved_while_the_other_store_exact_aborts() {
        let left_root = tempfile::tempdir().unwrap();
        let right_root = tempfile::tempdir().unwrap();
        let left = AdmissionAuthorityStore::open(left_root.path()).unwrap();
        let right = AdmissionAuthorityStore::open(right_root.path()).unwrap();
        let a = left
            .prepare(left.version().unwrap(), [201; 32], [202; 32])
            .unwrap();
        let b = right
            .prepare(right.version().unwrap(), [203; 32], [204; 32])
            .unwrap();
        left.commit_operational_test_receipt(&a, [205; 32]).unwrap();
        right
            .commit_operational_test_receipt(&b, [206; 32])
            .unwrap();
        let mut live = left
            .store
            .admission_revoker(a.peer_fingerprint, a.attempt_id)
            .unwrap();
        live.arm();
        let before = left.test_bilateral_receipt(a.attempt_id).unwrap();
        assert!(
            recover_bilateral_foundation(&left, a.attempt_id, &right, b.attempt_id, None)
                .await
                .is_err()
        );
        assert_eq!(left.test_bilateral_receipt(a.attempt_id).unwrap(), before);
        assert!(left.test_has_admission_guard(a.attempt_id).unwrap());
        assert_eq!(
            right.reconcile(b.attempt_id).unwrap(),
            ReconcileAdmission::Absent
        );
        right
            .prepare(right.version().unwrap(), [207; 32], b.peer_fingerprint)
            .unwrap();
    }

    #[tokio::test]
    async fn recovery_without_authenticated_channels_exact_aborts_both_and_allows_retry() {
        let left_root = tempfile::tempdir().unwrap();
        let right_root = tempfile::tempdir().unwrap();
        let left = AdmissionAuthorityStore::open(left_root.path()).unwrap();
        let right = AdmissionAuthorityStore::open(right_root.path()).unwrap();
        let a = left
            .prepare(left.version().unwrap(), [161; 32], [162; 32])
            .unwrap();
        let b = right
            .prepare(right.version().unwrap(), [163; 32], [164; 32])
            .unwrap();
        left.commit_operational_test_receipt(&a, [165; 32]).unwrap();
        right
            .commit_operational_test_receipt(&b, [166; 32])
            .unwrap();
        assert!(
            recover_bilateral_foundation(&left, a.attempt_id, &right, b.attempt_id, None)
                .await
                .is_err()
        );
        for (store, record, retry) in [(&left, &a, [167; 32]), (&right, &b, [168; 32])] {
            assert_eq!(
                store.reconcile(record.attempt_id).unwrap(),
                ReconcileAdmission::Absent
            );
            assert!(
                store
                    .operational_admission_snapshot(record.attempt_id)
                    .is_err()
            );
            store
                .prepare(store.version().unwrap(), retry, record.peer_fingerprint)
                .unwrap();
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
