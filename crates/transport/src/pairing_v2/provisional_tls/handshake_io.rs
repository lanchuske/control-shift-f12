//! Operational pairing only; this module has no active-trust or application-I/O port.
use super::super::{
    CandidateHello, JournalClock, Role, SAS_FORMAT, SUITE, WORDLIST_HASH,
    codec::{Value, decode, encode},
    evidence::{b, t},
    handshake_binding::{CandidateTranscript, SHARED_EXPORTER_LABEL},
    handshake_machine::Machine,
    handshake_wire::{APPLICATION_ERROR, CandidateGuard, SCHEDULE, Status},
    operational_wire::{CandidateRequest, FrameKind, TransportFrame},
};
use super::*;
use crate::pairing_pending::{
    BilateralTransactionFields, BilateralTransactionId, PendingStore,
    derive_bilateral_transaction_id,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use zeroize::Zeroizing;
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct WireFault {
    pub sequence: usize,
    pub mutation: u8,
}
pub struct HandshakeConfig {
    pub device_name: String,
    pub os: String,
    pub local_rendezvous: [u8; 16],
    pub selected_rendezvous: [u8; 16],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationPrompt {
    pub attempt: [u8; 32],
    pub transcript: [u8; 32],
    pub ui_generation: u64,
    pub words: [String; 4],
    pub names: [String; 2],
    pub fingerprints: [[u8; 32]; 2],
}
pub struct VerificationDecision {
    pub attempt: [u8; 32],
    pub transcript: [u8; 32],
    pub ui_generation: u64,
    pub matches: bool,
}
impl VerificationPrompt {
    pub fn decision(&self, matches: bool) -> VerificationDecision {
        VerificationDecision {
            attempt: self.attempt,
            transcript: self.transcript,
            ui_generation: self.ui_generation,
            matches,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Rejected,
    Cancelled,
}

const FINALIZATION_DOMAIN: &[u8] = b"control-shift-f12/finalization-v1";
const FINALIZATION_EXPORTER_LABEL: &[u8] = b"EXPORTER-ControlShiftF12-Finalization-v1";
const FINALIZATION_DEADLINE: Duration = Duration::from_secs(5);

/// Local durable-commit statement used only after the exact staged receipt has
/// been transferred to the local store. It carries no runtime authority.
pub(crate) struct LocalDurableCommit {
    transaction_id: BilateralTransactionId,
    local_receipt_hash: [u8; 32],
    peer_receipt_hash: [u8; 32],
    transcript: [u8; 32],
    identity_generation: u64,
    revocation_generation: u64,
    peer_identity_generation: u64,
    peer_revocation_generation: u64,
    policy_revision: u64,
}

impl LocalDurableCommit {
    #[allow(clippy::too_many_arguments)] // Keeps both stores' generations explicit and ordered.
    pub(in crate::pairing_v2) fn new(
        transaction_id: BilateralTransactionId,
        local_receipt_hash: [u8; 32],
        peer_receipt_hash: [u8; 32],
        transcript: [u8; 32],
        identity_generation: u64,
        revocation_generation: u64,
        peer_identity_generation: u64,
        peer_revocation_generation: u64,
        policy_revision: u64,
    ) -> Result<Self, HandshakeError> {
        if local_receipt_hash == [0; 32] || peer_receipt_hash == [0; 32] {
            return Err(HandshakeError::Rejected);
        }
        Ok(Self {
            transaction_id,
            local_receipt_hash,
            peer_receipt_hash,
            transcript,
            identity_generation,
            revocation_generation,
            peer_identity_generation,
            peer_revocation_generation,
            policy_revision,
        })
    }
}

/// Local-only data prepared for the bounded finalization exchange.  It is not
/// a durable receipt and cannot activate any capability by itself.
#[derive(Clone)]
pub(crate) struct LocalFinalizationReceipt {
    transaction_id: BilateralTransactionId,
    receipt_hash: [u8; 32],
    fields: BilateralTransactionFields,
    identity_generation: u64,
    revocation_generation: u64,
    policy_revision: u64,
    #[cfg(test)]
    test_fault: Option<FinalizationTestFault>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum FinalizationTestFault {
    ExtraBi,
    ExtraUni,
    UnknownFrame,
    NoBidi,
    NoBody,
    StopAfterLocalPublished,
    StopBeforeFirstAck,
    StopBeforeAck,
    WrongTransactionOnWire,
}

impl LocalFinalizationReceipt {
    #[cfg(test)]
    pub(super) fn test_transaction_id(&self) -> BilateralTransactionId {
        self.transaction_id
    }

    #[cfg(test)]
    pub(super) fn test_fault(&mut self, fault: FinalizationTestFault) {
        self.test_fault = Some(fault);
    }

    #[cfg(test)]
    pub(in crate::pairing_v2) fn test_fault_wrong_transaction_on_wire(&mut self) {
        self.test_fault = Some(FinalizationTestFault::WrongTransactionOnWire);
    }
}

/// Authenticated observation of the peer's finalization publication.  This is
/// deliberately separated from store confirmation; Task 4 coordinates that
/// separately and Task 3 never opens an operational snapshot.
#[derive(Debug)]
pub(crate) struct PeerFinalizationReceipt {
    transaction_id: BilateralTransactionId,
    peer_receipt_hash: [u8; 32],
    transcript: [u8; 32],
    identity_generation: u64,
    revocation_generation: u64,
    policy_revision: u64,
}

#[derive(Clone, Copy)]
struct DecodedPeerReceipt {
    hash: [u8; 32],
    identity_generation: u64,
    revocation_generation: u64,
}

impl PeerFinalizationReceipt {
    pub(crate) fn transaction_id(&self) -> BilateralTransactionId {
        self.transaction_id
    }
    pub(crate) fn peer_receipt_hash(&self) -> [u8; 32] {
        self.peer_receipt_hash
    }
    pub(crate) fn transcript(&self) -> [u8; 32] {
        self.transcript
    }
    pub(crate) fn identity_generation(&self) -> u64 {
        self.identity_generation
    }
    pub(crate) fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }
    pub(crate) fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
}
/// Move-only protocol evidence that remains quarantined from product runtime.
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::HandshakeCompletePendingAuthority;
/// fn require_clone<T: Clone>() {}
/// require_clone::<HandshakeCompletePendingAuthority>();
/// ```
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::HandshakeCompletePendingAuthority;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<HandshakeCompletePendingAuthority>();
/// ```
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::HandshakeCompletePendingAuthority;
/// fn leak(value: &HandshakeCompletePendingAuthority) { let _ = value.local_binding(); }
/// ```
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::HandshakeCompletePendingAuthority;
/// async fn bypass(value: HandshakeCompletePendingAuthority) { let _ = value.seal_for_promotion().await; }
/// ```
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::HandshakeCompletePendingAuthority;
/// fn forge() -> HandshakeCompletePendingAuthority {
///     HandshakeCompletePendingAuthority { role: unsafe { std::mem::zeroed() } }
/// }
/// ```
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::HandshakeCompletePendingAuthority;
/// fn input_runtime_capability(_: [u8; 32]) {}
/// fn bypass(value: HandshakeCompletePendingAuthority) { input_runtime_capability(value); }
/// ```
///
/// ```compile_fail
/// use seamless_transport::pairing_v2::admission_authority::SealedAdmissionCommit;
/// fn inject(_: SealedAdmissionCommit) {}
/// ```
pub struct HandshakeCompletePendingAuthority {
    pub(super) role: Role,
    pub(super) durable_fc_hash: [u8; 32],
    local_binding: [u8; 32],
    pending: crate::pairing_pending::PendingRecord,
    transcript: [u8; 32],
    certificate_fingerprints: [[u8; 32]; 2],
    _channel: ProvisionalChannel,
    _request: Stream,
    failed: Arc<AtomicBool>,
    watcher: IngressWatcher,
    finalization_complete: bool,
    durable_commit_complete: bool,
}

/// Internal, move-only live authority reserved for a bilateral durable
/// transition. It is intentionally unavailable outside pairing-v2 internals.
pub(crate) struct PreparedHandshakeAuthority {
    authority: HandshakeCompletePendingAuthority,
    reservation: super::PreparedAdmissionHandoff,
}

/// Frozen local store handoff that deliberately retains the authenticated
/// provisional channel for the post-commit proof exchange.
pub(crate) struct DistributedFrozenHandshakeAuthority {
    authority: HandshakeCompletePendingAuthority,
    handoff: Option<super::FrozenAdmissionHandoff>,
}

impl PreparedHandshakeAuthority {
    pub(in crate::pairing_v2) fn fields(&self) -> SealedPromotionFields {
        SealedPromotionFields {
            record: self.authority.pending.clone(),
            role: self.authority.role,
            durable_fc_hash: self.authority.durable_fc_hash,
            local_binding: self.authority.local_binding,
            transcript: self.authority.transcript,
            certificate_fingerprints: self.authority.certificate_fingerprints,
        }
    }

    pub(in crate::pairing_v2) fn staged_ownership(
        &self,
        revision: u64,
    ) -> crate::pairing_pending::AdmissionOwnership {
        self.reservation.awaiting_handoff_ownership(revision)
    }

    pub(in crate::pairing_v2) fn mark_staged(&self) -> Result<(), HandshakeError> {
        self.reservation
            .mark_staged()
            .map_err(|_| HandshakeError::Rejected)
    }

    pub(in crate::pairing_v2) fn abort_exact(self) -> Result<(), HandshakeError> {
        self.reservation
            .abort_exact()
            .map_err(|_| HandshakeError::Rejected)
    }

    pub(in crate::pairing_v2) fn local_receipt(
        &self,
        peer_attempt: [u8; 32],
        receipt_hash: [u8; 32],
    ) -> Result<LocalFinalizationReceipt, HandshakeError> {
        self.authority
            .local_finalization_receipt(peer_attempt, receipt_hash)
    }

    pub(in crate::pairing_v2) async fn exchange(
        &mut self,
        receipt: LocalFinalizationReceipt,
    ) -> Result<PeerFinalizationReceipt, HandshakeError> {
        self.authority.exchange_local_receipt(receipt).await
    }

    pub(in crate::pairing_v2) async fn freeze(
        mut self,
    ) -> Result<FrozenPromotionEvidence, HandshakeError> {
        if !self.authority.is_protocol_valid() {
            return Err(HandshakeError::Rejected);
        }
        let handoff = self
            .reservation
            .freeze()
            .map_err(|_| HandshakeError::Rejected)?;
        self.authority
            ._channel
            .connection
            .close(APPLICATION_ERROR.into(), b"bilateral finalization frozen");
        if let Some(task) = self.authority.watcher.task.take() {
            task.abort();
        }
        Ok(FrozenPromotionEvidence {
            role: self.authority.role,
            durable_fc_hash: self.authority.durable_fc_hash,
            local_binding: Zeroizing::new(self.authority.local_binding),
            pending: self.authority.pending,
            transcript: self.authority.transcript,
            certificate_fingerprints: self.authority.certificate_fingerprints,
            handoff,
        })
    }

    pub(in crate::pairing_v2) async fn freeze_distributed(
        self,
    ) -> Result<DistributedFrozenHandshakeAuthority, HandshakeError> {
        if !self.authority.is_protocol_valid() {
            return Err(HandshakeError::Rejected);
        }
        tokio::task::yield_now().await;
        if !self.authority.is_protocol_valid() {
            return Err(HandshakeError::Rejected);
        }
        let handoff = self
            .reservation
            .freeze()
            .map_err(|_| HandshakeError::Rejected)?;
        Ok(DistributedFrozenHandshakeAuthority {
            authority: self.authority,
            handoff: Some(handoff),
        })
    }

    #[cfg(test)]
    pub(in crate::pairing_v2) fn test_matches_ownership(
        &self,
        ownership: &crate::pairing_pending::AdmissionOwnership,
    ) -> bool {
        self.reservation.test_matches_ownership(ownership)
    }
}

impl DistributedFrozenHandshakeAuthority {
    pub(in crate::pairing_v2) fn take_store_handoff(
        &mut self,
    ) -> Result<super::FrozenAdmissionHandoff, HandshakeError> {
        self.handoff.take().ok_or(HandshakeError::Rejected)
    }

    pub(in crate::pairing_v2) async fn exchange_durable_commit(
        &mut self,
        statement: LocalDurableCommit,
    ) -> Result<(), HandshakeError> {
        self.authority.exchange_durable_commit(statement).await
    }

    pub(in crate::pairing_v2) fn close_confirmed(mut self) {
        self.authority
            ._channel
            .connection
            .close(APPLICATION_ERROR.into(), b"distributed admission confirmed");
        if let Some(task) = self.authority.watcher.task.take() {
            task.abort();
        }
    }
}

impl Drop for DistributedFrozenHandshakeAuthority {
    fn drop(&mut self) {
        if let Some(handoff) = self.handoff.take() {
            let _ = handoff.abort_exact();
        }
    }
}
/// Move-only, non-serializable protocol evidence. It deliberately has no public
/// binding getter and cannot be reconstructed after restart.
#[allow(dead_code)] // Intentionally unreachable from product until admission receives a separate GO.
pub(crate) struct SealedPromotionEvidence {
    role: Role,
    durable_fc_hash: [u8; 32],
    local_binding: Zeroizing<[u8; 32]>,
    pending: crate::pairing_pending::PendingRecord,
    transcript: [u8; 32],
    certificate_fingerprints: [[u8; 32]; 2],
    channel: ProvisionalChannel,
    request: Stream,
    failed: Arc<AtomicBool>,
    watcher: IngressWatcher,
}
struct IngressWatcher {
    freeze: Option<oneshot::Sender<crate::pairing_pending::AdmissionRevoker>>,
    finalization: Option<oneshot::Sender<oneshot::Sender<Result<FinalizationAccess, Invalid>>>>,
    task: Option<tokio::task::JoinHandle<IngressDisposition>>,
}

enum FinalizationAccess {
    Initiator,
    Responder(Stream),
}

enum IngressDisposition {
    Frozen(super::FrozenAdmissionHandoff),
    FinalizationReady(Stream),
    Invalid,
}

/// Owns every post-handshake ingress path. The only non-freeze transition is
/// a one-shot finalization handoff: it preserves the already-open request
/// stream and grants exactly one fresh bidi stream to the finalization grammar.
fn spawn_ingress_watcher(
    role: Role,
    connection: quinn::Connection,
    scope: Arc<super::ConsentScope>,
    failed: Arc<AtomicBool>,
    incoming: Stream,
) -> IngressWatcher {
    let (freeze, mut freeze_request) = oneshot::channel();
    let (finalization, mut finalization_request) =
        oneshot::channel::<oneshot::Sender<Result<FinalizationAccess, Invalid>>>();
    let task = tokio::spawn(async move {
        let mut incoming = Some(incoming);
        let disposition = tokio::select! { biased;
            _ = watch_request(&mut incoming.as_mut().expect("ingress present").recv) => IngressDisposition::Invalid,
            extra = connection.accept_bi() => {
                if let Ok(pair) = extra { drop(Stream::new(pair)); }
                IngressDisposition::Invalid
            },
            extra = connection.accept_uni() => {
                if let Ok(mut recv) = extra { let _ = recv.stop(APPLICATION_ERROR.into()); }
                IngressDisposition::Invalid
            },
            request = &mut freeze_request => {
                let Ok(revoker) = request else {
                    failed.store(true, Ordering::Release);
                    return IngressDisposition::Invalid;
                };
                let handoff = match scope.freeze(revoker) {
                    Ok(handoff) => handoff,
                    Err(_) => {
                        failed.store(true, Ordering::Release);
                        return IngressDisposition::Invalid;
                    }
                };
                connection.close(APPLICATION_ERROR.into(), b"pairing ingress frozen");
                IngressDisposition::Frozen(handoff)
            },
            request = &mut finalization_request => {
                let Ok(reply) = request else {
                    failed.store(true, Ordering::Release);
                    return IngressDisposition::Invalid;
                };
                // This stream was cleanly finished by the handshake and must
                // survive the watcher transition; dropping it as unclean would
                // reset the peer before it can open/accept finalization.
                incoming.as_mut().expect("ingress present").clean = true;
                let access = if role == Role::A {
                    Ok(FinalizationAccess::Initiator)
                } else {
                    tokio::select! { biased;
                        pair = connection.accept_bi() => pair
                            .map(Stream::new)
                            .map(FinalizationAccess::Responder)
                            .map_err(|_| Invalid),
                        extra = connection.accept_uni() => {
                            if let Ok(mut recv) = extra { let _ = recv.stop(APPLICATION_ERROR.into()); }
                            Err(Invalid)
                        },
                        _ = connection.closed() => Err(Invalid),
                    }
                };
                if reply.send(access).is_err() {
                    failed.store(true, Ordering::Release);
                    return IngressDisposition::Invalid;
                }
                IngressDisposition::FinalizationReady(incoming.take().expect("ingress present"))
            },
            _ = connection.closed() => IngressDisposition::Invalid,
        };
        match disposition {
            IngressDisposition::Invalid => {
                let mut incoming = incoming.expect("invalid retains ingress");
                failed.store(true, Ordering::Release);
                incoming.clean = false;
                drop(incoming);
                connection.close(
                    APPLICATION_ERROR.into(),
                    b"post-completion pairing violation",
                );
                IngressDisposition::Invalid
            }
            IngressDisposition::Frozen(handoff) => IngressDisposition::Frozen(handoff),
            IngressDisposition::FinalizationReady(incoming) => {
                IngressDisposition::FinalizationReady(incoming)
            }
        }
    });
    IngressWatcher {
        freeze: Some(freeze),
        finalization: Some(finalization),
        task: Some(task),
    }
}
#[allow(dead_code)]
pub(in crate::pairing_v2) struct SealedPromotionFields {
    pub record: crate::pairing_pending::PendingRecord,
    pub role: Role,
    pub durable_fc_hash: [u8; 32],
    pub local_binding: [u8; 32],
    pub transcript: [u8; 32],
    pub certificate_fingerprints: [[u8; 32]; 2],
}
struct Completed {
    role: Role,
    durable_fc_hash: [u8; 32],
    local_binding: [u8; 32],
    pending: crate::pairing_pending::PendingRecord,
    transcript: [u8; 32],
    certificate_fingerprints: [[u8; 32]; 2],
    request: Stream,
    failed: Arc<AtomicBool>,
    watcher: IngressWatcher,
}
impl HandshakeCompletePendingAuthority {
    pub fn is_protocol_valid(&self) -> bool {
        !self.failed.load(Ordering::Acquire) && self._channel.connection.close_reason().is_none()
    }
    #[cfg(test)]
    pub(super) async fn test_late_extra(&self) {
        let (mut send, _recv) = self._channel.connection.open_bi().await.unwrap();
        send.write_all(&[1]).await.unwrap();
    }
    #[cfg(test)]
    pub(super) async fn test_try_late_extra(&self) -> bool {
        let Ok(Ok((mut send, _recv))) = tokio::time::timeout(
            Duration::from_millis(250),
            self._channel.connection.open_bi(),
        )
        .await
        else {
            return false;
        };
        matches!(
            tokio::time::timeout(Duration::from_millis(250), send.write_all(&[1])).await,
            Ok(Ok(()))
        )
    }
    #[cfg(test)]
    pub(super) async fn test_late_candidate(&mut self) {
        self._request.send.write_all(&[1]).await.unwrap();
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn durable_fc_hash(&self) -> Option<&[u8; 32]> {
        self.is_protocol_valid().then_some(&self.durable_fc_hash)
    }
    #[cfg(test)]
    pub(super) fn test_local_binding(&self) -> Option<&[u8; 32]> {
        self.is_protocol_valid().then_some(&self.local_binding)
    }
    #[cfg(test)]
    pub(super) fn test_attempt(&self) -> [u8; 32] {
        self.pending.attempt_id
    }
    pub(in crate::pairing_v2) fn test_attempt_for_commit(&self) -> [u8; 32] {
        self.pending.attempt_id
    }

    pub(crate) fn local_finalization_receipt(
        &self,
        peer_attempt: [u8; 32],
        receipt_hash: [u8; 32],
    ) -> Result<LocalFinalizationReceipt, HandshakeError> {
        if !self.is_protocol_valid() || peer_attempt == [0; 32] || receipt_hash == [0; 32] {
            return Err(HandshakeError::Rejected);
        }
        let local_identity = self.certificate_fingerprints[self.role.index()];
        let peer_identity = self.certificate_fingerprints[1 - self.role.index()];
        let fields = BilateralTransactionFields {
            local_identity,
            peer_identity,
            local_attempt: self.pending.attempt_id,
            peer_attempt,
            peer_pin: peer_identity,
            transcript: self.transcript,
            suite: SUITE.to_owned(),
            policy_revision: 0,
        };
        Ok(LocalFinalizationReceipt {
            transaction_id: derive_bilateral_transaction_id(&fields),
            receipt_hash,
            fields,
            identity_generation: self.pending.version.identity_generation,
            revocation_generation: self.pending.revocation_generation,
            policy_revision: 0,
            #[cfg(test)]
            test_fault: None,
        })
    }

    pub(in crate::pairing_v2) fn prepare_bilateral(
        self,
        store: &PendingStore,
    ) -> Result<PreparedHandshakeAuthority, HandshakeError> {
        if !self.is_protocol_valid() {
            return Err(HandshakeError::Rejected);
        }
        let revoker = store
            .admission_revoker(self.pending.peer_fingerprint, self.pending.attempt_id)
            .map_err(|_| HandshakeError::Rejected)?;
        let reservation = self
            ._channel
            .scope
            .reserve_live(revoker)
            .map_err(|_| HandshakeError::Rejected)?;
        Ok(PreparedHandshakeAuthority {
            authority: self,
            reservation,
        })
    }

    /// Runs a single fixed finalization exchange on a fresh stream, then
    /// closes the provisional channel.  It returns only an authenticated peer
    /// proof; it never calls the durable store and cannot activate a session.
    pub(crate) async fn exchange_local_receipt(
        &mut self,
        receipt: LocalFinalizationReceipt,
    ) -> Result<PeerFinalizationReceipt, HandshakeError> {
        let result = tokio::time::timeout(
            FINALIZATION_DEADLINE,
            self.exchange_local_receipt_bounded(receipt),
        )
        .await;
        match result {
            Ok(Ok(proof)) => Ok(proof),
            Ok(Err(_)) | Err(_) => {
                self.failed.store(true, Ordering::Release);
                self._channel.connection.close(
                    APPLICATION_ERROR.into(),
                    b"finalization rejected or timed out",
                );
                Err(HandshakeError::Rejected)
            }
        }
    }

    async fn exchange_local_receipt_bounded(
        &mut self,
        receipt: LocalFinalizationReceipt,
    ) -> Result<PeerFinalizationReceipt, HandshakeError> {
        if !self.is_protocol_valid()
            || self.finalization_complete
            || receipt.transaction_id != derive_bilateral_transaction_id(&receipt.fields)
            || receipt.fields.local_attempt != self.pending.attempt_id
            || receipt.fields.local_identity != self.certificate_fingerprints[self.role.index()]
            || receipt.fields.peer_identity != self.certificate_fingerprints[1 - self.role.index()]
            || receipt.fields.peer_pin != self.certificate_fingerprints[1 - self.role.index()]
            || receipt.fields.transcript != self.transcript
            || receipt.identity_generation != self.pending.version.identity_generation
            || receipt.revocation_generation != self.pending.revocation_generation
            || receipt.policy_revision != 0
        {
            // A local receipt mismatch is terminal for this one-shot channel.
            // Leaving the peer's watcher waiting would turn a rejected
            // transaction into an unbounded remote wait.
            self.failed.store(true, Ordering::Release);
            self._channel
                .connection
                .close(APPLICATION_ERROR.into(), b"invalid finalization receipt");
            return Err(HandshakeError::Rejected);
        }
        // Transition the owner of the post-handshake ingress stream instead
        // of aborting it. Aborting its task drops the stream and resets the
        // peer's QUIC stream, which is indistinguishable from a violation.
        let (reply, access) = oneshot::channel();
        let finalization = self
            .watcher
            .finalization
            .take()
            .ok_or(HandshakeError::Rejected)?;
        finalization
            .send(reply)
            .map_err(|_| HandshakeError::Rejected)?;
        let access = access
            .await
            .map_err(|_| HandshakeError::Rejected)?
            .map_err(|_| HandshakeError::Rejected)?;
        let task = self.watcher.task.take().ok_or(HandshakeError::Rejected)?;
        let incoming = match task.await.map_err(|_| HandshakeError::Rejected)? {
            IngressDisposition::FinalizationReady(incoming) => incoming,
            _ => return Err(HandshakeError::Rejected),
        };
        let mut stream = match access {
            FinalizationAccess::Initiator => {
                #[cfg(test)]
                if matches!(receipt.test_fault, Some(FinalizationTestFault::NoBidi)) {
                    std::future::pending::<()>().await;
                }
                Stream::new(
                    self._channel
                        .connection
                        .open_bi()
                        .await
                        .map_err(|_| HandshakeError::Rejected)?,
                )
            }
            FinalizationAccess::Responder(stream) => stream,
        };
        let key = finalization_key(
            &self._channel.connection,
            receipt.transaction_id,
            receipt.fields.transcript,
        )
        .map_err(|_| HandshakeError::Rejected)?;
        let protocol = async {
            #[cfg(test)]
            let local_kind = if matches!(
                receipt.test_fault,
                Some(FinalizationTestFault::UnknownFrame)
            ) {
                "finalization-unknown"
            } else {
                "finalization-local-published"
            };
            #[cfg(not(test))]
            let local_kind = "finalization-local-published";
            let local_values = local_values(&receipt);
            #[cfg(test)]
            let local_values = {
                let mut local_values = local_values;
                if matches!(
                    receipt.test_fault,
                    Some(FinalizationTestFault::WrongTransactionOnWire)
                ) {
                    local_values[0] = Value::Bytes([0xA5; 32].to_vec());
                }
                local_values
            };
            let local = finalization_record(local_kind, &local_values, &key)
                .map_err(|_| HandshakeError::Rejected)?;
            let peer = if self.role == Role::A {
                #[cfg(test)]
                if matches!(receipt.test_fault, Some(FinalizationTestFault::NoBody)) {
                    std::future::pending::<()>().await;
                }
                finalization_send(&mut stream, &local).await?;
                #[cfg(test)]
                if matches!(
                    receipt.test_fault,
                    Some(FinalizationTestFault::StopAfterLocalPublished)
                ) {
                    std::future::pending::<()>().await;
                }
                let remote = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                let peer = decode_local_receipt(&remote, &key, &receipt)
                    .map_err(|_| HandshakeError::Rejected)?;
                #[cfg(test)]
                if matches!(
                    receipt.test_fault,
                    Some(FinalizationTestFault::StopBeforeFirstAck)
                ) {
                    std::future::pending::<()>().await;
                }
                let ack = finalization_record(
                    "finalization-peer-ack",
                    &ack_values(&receipt, peer.hash),
                    &key,
                )
                .map_err(|_| HandshakeError::Rejected)?;
                finalization_send(&mut stream, &ack).await?;
                let remote_ack = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                decode_ack(&remote_ack, &key, &receipt, peer)
                    .map_err(|_| HandshakeError::Rejected)?;
                peer
            } else {
                let remote = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                let peer = decode_local_receipt(&remote, &key, &receipt)
                    .map_err(|_| HandshakeError::Rejected)?;
                finalization_send(&mut stream, &local).await?;
                let remote_ack = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                decode_ack(&remote_ack, &key, &receipt, peer)
                    .map_err(|_| HandshakeError::Rejected)?;
                #[cfg(test)]
                inject_finalization_extra(&self._channel.connection, receipt.test_fault).await?;
                #[cfg(test)]
                if matches!(
                    receipt.test_fault,
                    Some(FinalizationTestFault::StopBeforeAck)
                ) {
                    std::future::pending::<()>().await;
                }
                let ack = finalization_record(
                    "finalization-peer-ack",
                    &ack_values(&receipt, peer.hash),
                    &key,
                )
                .map_err(|_| HandshakeError::Rejected)?;
                finalization_send(&mut stream, &ack).await?;
                peer
            };
            stream.send.finish().map_err(|_| HandshakeError::Rejected)?;
            stream.clean = true;
            Ok::<_, HandshakeError>(peer)
        };
        let result = tokio::select! { biased;
            extra = self._channel.connection.accept_bi() => {
                if let Ok(pair) = extra { drop(Stream::new(pair)); }
                Err(HandshakeError::Rejected)
            },
            extra = self._channel.connection.accept_uni() => {
                if let Ok(mut recv) = extra { let _ = recv.stop(APPLICATION_ERROR.into()); }
                Err(HandshakeError::Rejected)
            },
            result = protocol => result,
            _ = self._channel.connection.closed() => Err(HandshakeError::Rejected),
        };
        let peer = match result {
            Ok(peer) => peer,
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                self._channel
                    .connection
                    .close(APPLICATION_ERROR.into(), b"finalization rejected");
                return Err(error);
            }
        };
        self.watcher = spawn_ingress_watcher(
            self.role,
            self._channel.connection.clone(),
            self._channel.scope.clone(),
            self.failed.clone(),
            incoming,
        );
        self.finalization_complete = true;
        Ok(PeerFinalizationReceipt {
            transaction_id: receipt.transaction_id,
            peer_receipt_hash: peer.hash,
            transcript: receipt.fields.transcript,
            identity_generation: peer.identity_generation,
            revocation_generation: peer.revocation_generation,
            policy_revision: receipt.policy_revision,
        })
    }

    async fn exchange_durable_commit(
        &mut self,
        statement: LocalDurableCommit,
    ) -> Result<(), HandshakeError> {
        let result = tokio::time::timeout(
            FINALIZATION_DEADLINE,
            self.exchange_durable_commit_bounded(statement),
        )
        .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => {
                #[cfg(test)]
                eprintln!(
                    "distributed durable exchange rejected for role {:?}",
                    self.role
                );
                self.failed.store(true, Ordering::Release);
                self._channel.connection.close(
                    APPLICATION_ERROR.into(),
                    b"durable commit proof rejected or timed out",
                );
                Err(HandshakeError::Rejected)
            }
            Err(_) => {
                #[cfg(test)]
                eprintln!(
                    "distributed durable exchange timed out for role {:?}",
                    self.role
                );
                self.failed.store(true, Ordering::Release);
                self._channel.connection.close(
                    APPLICATION_ERROR.into(),
                    b"durable commit proof rejected or timed out",
                );
                Err(HandshakeError::Rejected)
            }
        }
    }

    async fn exchange_durable_commit_bounded(
        &mut self,
        statement: LocalDurableCommit,
    ) -> Result<(), HandshakeError> {
        if !self.is_protocol_valid()
            || !self.finalization_complete
            || self.durable_commit_complete
            || statement.transcript != self.transcript
            || statement.identity_generation != self.pending.version.identity_generation
            || statement.revocation_generation != self.pending.revocation_generation
            || statement.policy_revision != 0
        {
            return Err(HandshakeError::Rejected);
        }
        let (reply, access) = oneshot::channel();
        let finalization = self
            .watcher
            .finalization
            .take()
            .ok_or(HandshakeError::Rejected)?;
        finalization
            .send(reply)
            .map_err(|_| HandshakeError::Rejected)?;
        let access = access
            .await
            .map_err(|_| HandshakeError::Rejected)?
            .map_err(|_| HandshakeError::Rejected)?;
        let task = self.watcher.task.take().ok_or(HandshakeError::Rejected)?;
        let incoming = match task.await.map_err(|_| HandshakeError::Rejected)? {
            IngressDisposition::FinalizationReady(incoming) => incoming,
            _ => return Err(HandshakeError::Rejected),
        };
        let mut stream = match access {
            FinalizationAccess::Initiator => Stream::new(
                self._channel
                    .connection
                    .open_bi()
                    .await
                    .map_err(|_| HandshakeError::Rejected)?,
            ),
            FinalizationAccess::Responder(stream) => stream,
        };
        let key = finalization_key(
            &self._channel.connection,
            statement.transaction_id,
            statement.transcript,
        )
        .map_err(|_| HandshakeError::Rejected)?;
        let local = finalization_record(
            "durable-commit-published",
            &durable_commit_values(&statement),
            &key,
        )
        .map_err(|_| HandshakeError::Rejected)?;
        let local_commit_hash: [u8; 32] = Sha256::digest(&local[4..]).into();
        let protocol = async {
            let peer_commit = if self.role == Role::A {
                finalization_send(&mut stream, &local).await?;
                let remote = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                decode_durable_commit(&remote, &key, &statement)
                    .map_err(|_| HandshakeError::Rejected)?
            } else {
                let remote = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                let decoded = decode_durable_commit(&remote, &key, &statement)
                    .map_err(|_| HandshakeError::Rejected)?;
                finalization_send(&mut stream, &local).await?;
                decoded
            };
            let ack = finalization_record(
                "durable-commit-peer-ack",
                &durable_commit_ack_values(&statement, peer_commit),
                &key,
            )
            .map_err(|_| HandshakeError::Rejected)?;
            if self.role == Role::A {
                finalization_send(&mut stream, &ack).await?;
                let remote_ack = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                decode_durable_commit_ack(&remote_ack, &key, &statement, local_commit_hash)
                    .map_err(|_| HandshakeError::Rejected)?;
                stream.send.finish().map_err(|_| HandshakeError::Rejected)?;
                let complete = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                decode_durable_commit_complete(&complete, &key, &statement)
                    .map_err(|_| HandshakeError::Rejected)?;
            } else {
                let remote_ack = finalization_read(&mut stream.recv)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                decode_durable_commit_ack(&remote_ack, &key, &statement, local_commit_hash)
                    .map_err(|_| HandshakeError::Rejected)?;
                finalization_send(&mut stream, &ack).await?;
                // The responder must not close the connection until the
                // initiator has consumed this final acknowledgement. The
                // initiator sends FIN only after successful validation.
                let mut trailing = [0u8; 1];
                if stream
                    .recv
                    .read(&mut trailing)
                    .await
                    .map_err(|_| HandshakeError::Rejected)?
                    .is_some()
                {
                    return Err(HandshakeError::Rejected);
                }
                let complete = finalization_record(
                    "durable-commit-complete",
                    &durable_commit_values(&statement),
                    &key,
                )
                .map_err(|_| HandshakeError::Rejected)?;
                finalization_send(&mut stream, &complete).await?;
                stream.send.finish().map_err(|_| HandshakeError::Rejected)?;
            }
            stream.clean = true;
            Ok::<_, HandshakeError>(())
        };
        let result = tokio::select! { biased;
            extra = self._channel.connection.accept_bi() => {
                if let Ok(pair) = extra { drop(Stream::new(pair)); }
                Err(HandshakeError::Rejected)
            },
            extra = self._channel.connection.accept_uni() => {
                if let Ok(mut recv) = extra { let _ = recv.stop(APPLICATION_ERROR.into()); }
                Err(HandshakeError::Rejected)
            },
            result = protocol => result,
            _ = self._channel.connection.closed() => Err(HandshakeError::Rejected),
        };
        result?;
        self.watcher = spawn_ingress_watcher(
            self.role,
            self._channel.connection.clone(),
            self._channel.scope.clone(),
            self.failed.clone(),
            incoming,
        );
        self.durable_commit_complete = true;
        Ok(())
    }

    #[allow(dead_code)] // Foundation-only boundary; product wiring remains disabled.
    pub(crate) async fn seal_for_promotion(
        self,
    ) -> Result<SealedPromotionEvidence, HandshakeError> {
        if !self.is_protocol_valid() {
            return Err(HandshakeError::Rejected);
        }
        // Give the permanently armed ingress watcher a scheduling boundary before
        // moving the authority across the promotion frontier.
        tokio::task::yield_now().await;
        if !self.is_protocol_valid() {
            return Err(HandshakeError::Rejected);
        }
        Ok(SealedPromotionEvidence {
            role: self.role,
            durable_fc_hash: self.durable_fc_hash,
            local_binding: Zeroizing::new(self.local_binding),
            pending: self.pending,
            transcript: self.transcript,
            certificate_fingerprints: self.certificate_fingerprints,
            channel: self._channel,
            request: self._request,
            failed: self.failed,
            watcher: self.watcher,
        })
    }
}

#[cfg(test)]
impl LocalFinalizationReceipt {
    pub(super) fn test_replace_transaction_id(&mut self, transaction_id: [u8; 32]) {
        self.transaction_id = BilateralTransactionId::from_bytes(transaction_id).unwrap();
    }
}

impl SealedPromotionEvidence {
    /// Atomically closes pairing ingress at the watcher that owns all possible
    /// post-handshake inputs. The biased state transition is the protocol
    /// linearization point: a queued violation wins; otherwise freeze wins,
    /// closes QUIC, and removes every channel from the resulting evidence.
    pub(crate) async fn freeze(
        mut self,
        store: &PendingStore,
    ) -> Result<FrozenPromotionEvidence, HandshakeError> {
        let signal = self.watcher.freeze.take().ok_or(HandshakeError::Rejected)?;
        let revoker = store
            .admission_revoker(self.pending.peer_fingerprint, self.pending.attempt_id)
            .map_err(|_| HandshakeError::Rejected)?;
        signal.send(revoker).map_err(|_| HandshakeError::Rejected)?;
        let static_result = self.revalidate_static();
        let task = self.watcher.task.take().ok_or(HandshakeError::Rejected)?;
        let handoff = match task.await.map_err(|_| HandshakeError::Rejected)? {
            IngressDisposition::Frozen(handoff) => handoff,
            IngressDisposition::FinalizationReady(_) | IngressDisposition::Invalid => {
                return Err(HandshakeError::Rejected);
            }
        };
        static_result?;
        Ok(FrozenPromotionEvidence {
            role: self.role,
            durable_fc_hash: self.durable_fc_hash,
            local_binding: self.local_binding,
            pending: self.pending,
            transcript: self.transcript,
            certificate_fingerprints: self.certificate_fingerprints,
            handoff,
        })
    }

    #[allow(dead_code)] // Called at each future promotion boundary, none of which is enabled yet.
    pub(crate) fn revalidate(&self) -> Result<(), HandshakeError> {
        if self.failed.load(Ordering::Acquire)
            || self.channel.connection.close_reason().is_some()
            || !self.request.clean
        {
            return Err(HandshakeError::Rejected);
        }
        self.revalidate_static()
    }

    fn revalidate_static(&self) -> Result<(), HandshakeError> {
        if !self.request.clean
            || self.pending.attempt_id == [0; 32]
            || self.pending.peer_fingerprint != self.certificate_fingerprints[1 - self.role.index()]
            || self.durable_fc_hash == [0; 32]
            || self.transcript == [0; 32]
            || *self.local_binding == [0; 32]
        {
            return Err(HandshakeError::Rejected);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(in crate::pairing_v2) fn fields(&self) -> SealedPromotionFields {
        SealedPromotionFields {
            record: self.pending.clone(),
            role: self.role,
            durable_fc_hash: self.durable_fc_hash,
            local_binding: *self.local_binding,
            transcript: self.transcript,
            certificate_fingerprints: self.certificate_fingerprints,
        }
    }
}

/// Frozen, move-only evidence contains no network channel and therefore cannot
/// observe a post-publication pairing event or act as runtime authority.
pub(crate) struct FrozenPromotionEvidence {
    role: Role,
    durable_fc_hash: [u8; 32],
    local_binding: Zeroizing<[u8; 32]>,
    pending: crate::pairing_pending::PendingRecord,
    transcript: [u8; 32],
    certificate_fingerprints: [[u8; 32]; 2],
    handoff: super::FrozenAdmissionHandoff,
}

impl FrozenPromotionEvidence {
    pub(crate) fn revalidate(&self) -> Result<(), HandshakeError> {
        if self.pending.attempt_id == [0; 32]
            || self.pending.peer_fingerprint != self.certificate_fingerprints[1 - self.role.index()]
            || self.durable_fc_hash == [0; 32]
            || self.transcript == [0; 32]
            || *self.local_binding == [0; 32]
        {
            return Err(HandshakeError::Rejected);
        }
        Ok(())
    }

    pub(in crate::pairing_v2) fn fields(&self) -> SealedPromotionFields {
        SealedPromotionFields {
            record: self.pending.clone(),
            role: self.role,
            durable_fc_hash: self.durable_fc_hash,
            local_binding: *self.local_binding,
            transcript: self.transcript,
            certificate_fingerprints: self.certificate_fingerprints,
        }
    }

    /// Separates immutable handshake fields from the one-shot, private guard
    /// witness. The caller can stage the former but cannot produce a durable
    /// admission until it consumes the latter under the consent mutex.
    pub(in crate::pairing_v2) fn into_store_handoff(
        self,
    ) -> (SealedPromotionFields, super::FrozenAdmissionHandoff) {
        let fields = self.fields();
        (fields, self.handoff)
    }

    pub(in crate::pairing_v2) fn abort_exact(self) -> Result<(), HandshakeError> {
        self.handoff
            .abort_exact()
            .map_err(|_| HandshakeError::Rejected)
    }

    #[cfg(test)]
    pub(super) fn test_claim_handoff(
        self,
    ) -> Result<crate::pairing_pending::AdmissionRevoker, super::Invalid> {
        self.handoff.claim()
    }
}
fn fresh<const N: usize>() -> Result<[u8; N], Invalid> {
    let mut out = [0; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| Invalid)?;
    Ok(out)
}
async fn bounded<T, E>(
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, Invalid> {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| Invalid)?
        .map_err(|_| Invalid)
}
struct LiveClock {
    epoch: [u8; 16],
    origin: Instant,
}
impl LiveClock {
    fn new() -> Result<Self, Invalid> {
        Ok(Self {
            epoch: fresh()?,
            origin: Instant::now(),
        })
    }
    fn now(&self) -> Result<JournalClock, Invalid> {
        Ok(JournalClock {
            boot: self.epoch,
            monotonic_ms: self
                .origin
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| Invalid)?,
            utc_seconds: utc()?,
        })
    }
}
struct Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    clean: bool,
}
#[cfg(test)]
pub(super) fn reject_test_stream(pair: (quinn::SendStream, quinn::RecvStream)) {
    drop(Stream::new(pair));
}
impl Stream {
    fn new((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self {
            send,
            recv,
            clean: false,
        }
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        if !self.clean {
            let _ = self.send.reset(APPLICATION_ERROR.into());
            let _ = self.recv.stop(APPLICATION_ERROR.into());
        }
    }
}
async fn read_exact(recv: &mut quinn::RecvStream, n: usize) -> Result<Vec<u8>, Invalid> {
    let mut raw = vec![0; n];
    recv.read_exact(&mut raw).await.map_err(|_| Invalid)?;
    Ok(raw)
}
async fn candidate_record(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Invalid> {
    let mut raw = read_exact(recv, 15).await?;
    if &raw[..8] != b"CSF12P2\0" || raw[8..10] != 2u16.to_be_bytes() {
        return Err(Invalid);
    }
    let cap = match raw[10] {
        1 => 1024,
        2 => 4096,
        _ => return Err(Invalid),
    };
    let n = u32::from_be_bytes(raw[11..15].try_into().map_err(|_| Invalid)?) as usize;
    if n == 0 || n > cap {
        return Err(Invalid);
    }
    raw.extend(read_exact(recv, n).await?);
    Ok(raw)
}
async fn control_record(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Invalid> {
    let mut raw = read_exact(recv, 20).await?;
    let n = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| Invalid)?) as usize;
    if n == 0 || n > 16384 {
        return Err(Invalid);
    }
    raw.extend(read_exact(recv, n).await?);
    Ok(raw)
}
async fn eof(recv: &mut quinn::RecvStream) -> Result<(), Invalid> {
    let mut byte = [0];
    if recv.read(&mut byte).await.map_err(|_| Invalid)?.is_some() {
        return Err(Invalid);
    }
    Ok(())
}

fn finalization_key(
    connection: &quinn::Connection,
    transaction_id: BilateralTransactionId,
    transcript: [u8; 32],
) -> Result<[u8; 32], Invalid> {
    let mut context = Sha256::new();
    context.update(FINALIZATION_DOMAIN);
    context.update(transaction_id.as_bytes());
    context.update(transcript);
    let mut key = [0; 32];
    connection
        .export_keying_material(&mut key, FINALIZATION_EXPORTER_LABEL, &context.finalize())
        .map_err(|_| Invalid)?;
    Ok(key)
}

fn finalization_mac(key: &[u8; 32], label: &[u8], body: &[u8]) -> Result<[u8; 32], Invalid> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Invalid)?;
    mac.update(FINALIZATION_DOMAIN);
    mac.update(label);
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn finalization_record(kind: &str, body: &[Value], key: &[u8; 32]) -> Result<Vec<u8>, Invalid> {
    let unsigned = encode(kind, body)?;
    let mut values = body.to_vec();
    values.push(Value::Bytes(
        finalization_mac(key, kind.as_bytes(), &unsigned)?.to_vec(),
    ));
    let payload = encode(kind, &values)?;
    if payload.is_empty() || payload.len() > 16_384 {
        return Err(Invalid);
    }
    let mut record = (payload.len() as u32).to_be_bytes().to_vec();
    record.extend(payload);
    Ok(record)
}

async fn finalization_read(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Invalid> {
    let length =
        u32::from_be_bytes(read_exact(recv, 4).await?.try_into().map_err(|_| Invalid)?) as usize;
    if length == 0 || length > 16_384 {
        return Err(Invalid);
    }
    read_exact(recv, length).await
}

async fn finalization_send(stream: &mut Stream, record: &[u8]) -> Result<(), HandshakeError> {
    stream
        .send
        .write_all(record)
        .await
        .map_err(|_| HandshakeError::Rejected)
}

#[cfg(test)]
async fn inject_finalization_extra(
    connection: &quinn::Connection,
    fault: Option<FinalizationTestFault>,
) -> Result<(), HandshakeError> {
    match fault {
        Some(FinalizationTestFault::ExtraBi) => {
            let (mut send, _recv) = connection
                .open_bi()
                .await
                .map_err(|_| HandshakeError::Rejected)?;
            send.write_all(&[1])
                .await
                .map_err(|_| HandshakeError::Rejected)?;
            // The test fault may not publish PeerAck until the opposite
            // watcher has rejected this second stream. `stopped` gives a
            // deterministic cross-endpoint barrier instead of a sleep.
            let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped())
                .await
                .map_err(|_| HandshakeError::Rejected)?;
            return Err(HandshakeError::Rejected);
        }
        Some(FinalizationTestFault::ExtraUni) => {
            let mut send = connection
                .open_uni()
                .await
                .map_err(|_| HandshakeError::Rejected)?;
            send.write_all(&[1])
                .await
                .map_err(|_| HandshakeError::Rejected)?;
            let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped())
                .await
                .map_err(|_| HandshakeError::Rejected)?;
            return Err(HandshakeError::Rejected);
        }
        _ => {}
    }
    Ok(())
}

fn bytes32(value: &Value) -> Result<[u8; 32], Invalid> {
    match value {
        Value::Bytes(bytes) => bytes.as_slice().try_into().map_err(|_| Invalid),
        _ => Err(Invalid),
    }
}

fn number(value: &Value) -> Result<u64, Invalid> {
    match value {
        Value::Number(value) => Ok(*value),
        _ => Err(Invalid),
    }
}

fn local_values(receipt: &LocalFinalizationReceipt) -> Vec<Value> {
    vec![
        Value::Bytes(receipt.transaction_id.as_bytes().to_vec()),
        Value::Bytes(receipt.receipt_hash.to_vec()),
        Value::Bytes(receipt.fields.local_identity.to_vec()),
        Value::Bytes(receipt.fields.peer_identity.to_vec()),
        Value::Bytes(receipt.fields.local_attempt.to_vec()),
        Value::Bytes(receipt.fields.peer_attempt.to_vec()),
        Value::Bytes(receipt.fields.peer_pin.to_vec()),
        Value::Bytes(receipt.fields.transcript.to_vec()),
        Value::Number(receipt.identity_generation),
        Value::Number(receipt.revocation_generation),
        Value::Number(receipt.policy_revision),
    ]
}

fn decode_local_receipt(
    raw: &[u8],
    key: &[u8; 32],
    expected: &LocalFinalizationReceipt,
) -> Result<DecodedPeerReceipt, Invalid> {
    let values = decode(
        "finalization-local-published",
        raw,
        &[2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2],
    )?;
    let mut unsigned = values.clone();
    let mac = bytes32(&unsigned.pop().ok_or(Invalid)?)?;
    let body = encode("finalization-local-published", &unsigned)?;
    if finalization_mac(key, b"finalization-local-published", &body)? != mac {
        return Err(Invalid);
    }
    let remote_transaction =
        BilateralTransactionId::from_bytes(bytes32(&unsigned[0])?).map_err(|_| Invalid)?;
    let remote_hash = bytes32(&unsigned[1])?;
    let invalid = remote_transaction != expected.transaction_id
        || remote_hash == [0; 32]
        || bytes32(&unsigned[2])? != expected.fields.peer_identity
        || bytes32(&unsigned[3])? != expected.fields.local_identity
        || bytes32(&unsigned[4])? != expected.fields.peer_attempt
        || bytes32(&unsigned[5])? != expected.fields.local_attempt
        || bytes32(&unsigned[6])? != expected.fields.local_identity
        || bytes32(&unsigned[7])? != expected.fields.transcript
        || number(&unsigned[10])? != expected.policy_revision;
    if invalid {
        #[cfg(test)]
        eprintln!("distributed finalization receipt rejected");
        return Err(Invalid);
    }
    Ok(DecodedPeerReceipt {
        hash: remote_hash,
        identity_generation: number(&unsigned[8])?,
        revocation_generation: number(&unsigned[9])?,
    })
}

fn ack_values(receipt: &LocalFinalizationReceipt, peer_receipt_hash: [u8; 32]) -> Vec<Value> {
    vec![
        Value::Bytes(receipt.transaction_id.as_bytes().to_vec()),
        Value::Bytes(receipt.receipt_hash.to_vec()),
        Value::Bytes(peer_receipt_hash.to_vec()),
        Value::Bytes(receipt.fields.transcript.to_vec()),
        Value::Number(receipt.identity_generation),
        Value::Number(receipt.revocation_generation),
        Value::Number(receipt.policy_revision),
    ]
}

fn decode_ack(
    raw: &[u8],
    key: &[u8; 32],
    expected: &LocalFinalizationReceipt,
    peer: DecodedPeerReceipt,
) -> Result<(), Invalid> {
    let values = decode("finalization-peer-ack", raw, &[2, 2, 2, 2, 1, 1, 1, 2])?;
    let mut unsigned = values.clone();
    let mac = bytes32(&unsigned.pop().ok_or(Invalid)?)?;
    let body = encode("finalization-peer-ack", &unsigned)?;
    let invalid = finalization_mac(key, b"finalization-peer-ack", &body)? != mac
        || BilateralTransactionId::from_bytes(bytes32(&unsigned[0])?).map_err(|_| Invalid)?
            != expected.transaction_id
        || bytes32(&unsigned[1])? != peer.hash
        || bytes32(&unsigned[2])? != expected.receipt_hash
        || bytes32(&unsigned[3])? != expected.fields.transcript
        || number(&unsigned[4])? != peer.identity_generation
        || number(&unsigned[5])? != peer.revocation_generation
        || number(&unsigned[6])? != expected.policy_revision;
    if invalid {
        #[cfg(test)]
        eprintln!("distributed finalization ack rejected");
        return Err(Invalid);
    }
    Ok(())
}

fn durable_commit_values(statement: &LocalDurableCommit) -> Vec<Value> {
    vec![
        Value::Bytes(statement.transaction_id.as_bytes().to_vec()),
        Value::Bytes(statement.local_receipt_hash.to_vec()),
        Value::Bytes(statement.peer_receipt_hash.to_vec()),
        Value::Bytes(statement.transcript.to_vec()),
        Value::Number(statement.identity_generation),
        Value::Number(statement.revocation_generation),
        Value::Number(statement.peer_identity_generation),
        Value::Number(statement.peer_revocation_generation),
        Value::Number(statement.policy_revision),
    ]
}

fn decode_durable_commit(
    raw: &[u8],
    key: &[u8; 32],
    expected: &LocalDurableCommit,
) -> Result<[u8; 32], Invalid> {
    let values = decode(
        "durable-commit-published",
        raw,
        &[2, 2, 2, 2, 1, 1, 1, 1, 1, 2],
    )?;
    let mut unsigned = values.clone();
    let mac = bytes32(&unsigned.pop().ok_or(Invalid)?)?;
    let body = encode("durable-commit-published", &unsigned)?;
    let invalid = finalization_mac(key, b"durable-commit-published", &body)? != mac
        || BilateralTransactionId::from_bytes(bytes32(&unsigned[0])?).map_err(|_| Invalid)?
            != expected.transaction_id
        || bytes32(&unsigned[1])? != expected.peer_receipt_hash
        || bytes32(&unsigned[2])? != expected.local_receipt_hash
        || bytes32(&unsigned[3])? != expected.transcript
        || number(&unsigned[4])? != expected.peer_identity_generation
        || number(&unsigned[5])? != expected.peer_revocation_generation
        || number(&unsigned[6])? != expected.identity_generation
        || number(&unsigned[7])? != expected.revocation_generation
        || number(&unsigned[8])? != expected.policy_revision;
    if invalid {
        #[cfg(test)]
        eprintln!("distributed durable commit record rejected");
        return Err(Invalid);
    }
    Ok(Sha256::digest(raw).into())
}

fn decode_durable_commit_complete(
    raw: &[u8],
    key: &[u8; 32],
    expected: &LocalDurableCommit,
) -> Result<(), Invalid> {
    let values = decode(
        "durable-commit-complete",
        raw,
        &[2, 2, 2, 2, 1, 1, 1, 1, 1, 2],
    )?;
    let mut unsigned = values.clone();
    let mac = bytes32(&unsigned.pop().ok_or(Invalid)?)?;
    let body = encode("durable-commit-complete", &unsigned)?;
    if finalization_mac(key, b"durable-commit-complete", &body)? != mac
        || BilateralTransactionId::from_bytes(bytes32(&unsigned[0])?).map_err(|_| Invalid)?
            != expected.transaction_id
        || bytes32(&unsigned[1])? != expected.peer_receipt_hash
        || bytes32(&unsigned[2])? != expected.local_receipt_hash
        || bytes32(&unsigned[3])? != expected.transcript
        || number(&unsigned[4])? != expected.peer_identity_generation
        || number(&unsigned[5])? != expected.peer_revocation_generation
        || number(&unsigned[6])? != expected.identity_generation
        || number(&unsigned[7])? != expected.revocation_generation
        || number(&unsigned[8])? != expected.policy_revision
    {
        return Err(Invalid);
    }
    Ok(())
}

fn durable_commit_ack_values(
    statement: &LocalDurableCommit,
    peer_commit_hash: [u8; 32],
) -> Vec<Value> {
    vec![
        Value::Bytes(statement.transaction_id.as_bytes().to_vec()),
        Value::Bytes(peer_commit_hash.to_vec()),
        Value::Bytes(statement.local_receipt_hash.to_vec()),
        Value::Bytes(statement.peer_receipt_hash.to_vec()),
        Value::Bytes(statement.transcript.to_vec()),
        Value::Number(statement.identity_generation),
        Value::Number(statement.revocation_generation),
        Value::Number(statement.peer_identity_generation),
        Value::Number(statement.peer_revocation_generation),
        Value::Number(statement.policy_revision),
    ]
}

fn decode_durable_commit_ack(
    raw: &[u8],
    key: &[u8; 32],
    expected: &LocalDurableCommit,
    local_commit_hash: [u8; 32],
) -> Result<(), Invalid> {
    let values = decode(
        "durable-commit-peer-ack",
        raw,
        &[2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 2],
    )?;
    let mut unsigned = values.clone();
    let mac = bytes32(&unsigned.pop().ok_or(Invalid)?)?;
    let body = encode("durable-commit-peer-ack", &unsigned)?;
    let invalid = finalization_mac(key, b"durable-commit-peer-ack", &body)? != mac
        || BilateralTransactionId::from_bytes(bytes32(&unsigned[0])?).map_err(|_| Invalid)?
            != expected.transaction_id
        || bytes32(&unsigned[1])? != local_commit_hash
        || bytes32(&unsigned[2])? != expected.peer_receipt_hash
        || bytes32(&unsigned[3])? != expected.local_receipt_hash
        || bytes32(&unsigned[4])? != expected.transcript
        || number(&unsigned[5])? != expected.peer_identity_generation
        || number(&unsigned[6])? != expected.peer_revocation_generation
        || number(&unsigned[7])? != expected.identity_generation
        || number(&unsigned[8])? != expected.revocation_generation
        || number(&unsigned[9])? != expected.policy_revision;
    if invalid {
        #[cfg(test)]
        eprintln!("distributed durable commit ack rejected");
        return Err(Invalid);
    }
    Ok(())
}
// A requester's FIN is neither required nor a response-FIN event. Any DATA is
// forbidden, even if it arrives while the other candidate stream is active.
async fn watch_request(recv: &mut quinn::RecvStream) -> Invalid {
    let mut byte = [0];
    match recv.read(&mut byte).await {
        Ok(None) => std::future::pending().await,
        _ => Invalid,
    }
}
fn candidate(
    config: &HandshakeConfig,
    request: &CandidateRequest,
    cert: &[u8],
) -> Result<Vec<u8>, Invalid> {
    if request.rendezvous != config.local_rendezvous {
        return Err(Invalid);
    }
    let mut suites = vec![0, 1, 0, SUITE.len() as u8];
    suites.extend(SUITE.as_bytes());
    let raw = encode(
        "candidate-hello",
        &[
            b(&config.local_rendezvous),
            b(&request.nonce),
            b(&fresh::<16>()?),
            t(&config.device_name),
            t(&config.os),
            b(&suites),
            b(&hash(cert)),
            Value::Number(30_000),
        ],
    )?;
    CandidateHello::decode(&raw)?;
    Ok(raw)
}
fn hello(candidate: &[u8], cert: &[u8]) -> Result<Vec<u8>, Invalid> {
    let c = decode("candidate-hello", candidate, &[2, 2, 2, 3, 3, 2, 2, 1])?;
    encode(
        "hello",
        &[
            Value::Number(2),
            b(&fresh::<16>()?),
            c[0].clone(),
            b(&fresh::<16>()?),
            b(&hash(candidate)),
            c[1].clone(),
            c[2].clone(),
            c[3].clone(),
            b(cert),
            t(SUITE),
            t(SAS_FORMAT),
            b(&WORDLIST_HASH),
            t("compare_v2_required"),
            Value::Number(300),
        ],
    )
}
async fn exchange(
    stream: &mut Stream,
    requester: Role,
    local: Role,
    config: &HandshakeConfig,
    cert: &[u8],
    guard: &mut CandidateGuard,
) -> Result<(Vec<u8>, Vec<u8>), Invalid> {
    let a = requester.index() as u8 + 1;
    let b_role = 3 - a;
    let request = if requester == local {
        let payload =
            CandidateRequest::new(fresh()?, config.selected_rendezvous, fresh()?).encode()?;
        let raw = TransportFrame {
            kind: FrameKind::CandidateRequest,
            payload: payload.clone(),
        }
        .encode()?;
        if !guard.receive(1, a, a, &raw, |_, _| true) {
            return Err(Invalid);
        }
        stream.send.write_all(&raw).await.map_err(|_| Invalid)?;
        payload
    } else {
        let raw = candidate_record(&mut stream.recv).await?;
        if !guard.receive(1, a, a, &raw, |_, _| true) {
            return Err(Invalid);
        }
        TransportFrame::decode(&raw)?.payload
    };
    let response = if requester != local {
        let payload = candidate(config, &CandidateRequest::decode(&request)?, cert)?;
        let raw = TransportFrame {
            kind: FrameKind::CandidateHello,
            payload: payload.clone(),
        }
        .encode()?;
        if !guard.receive(2, a, b_role, &raw, |_, _| true) {
            return Err(Invalid);
        }
        stream.send.write_all(&raw).await.map_err(|_| Invalid)?;
        stream.send.finish().map_err(|_| Invalid)?;
        payload
    } else {
        let raw = candidate_record(&mut stream.recv).await?;
        if !guard.receive(2, a, b_role, &raw, |_, _| true) {
            return Err(Invalid);
        }
        eof(&mut stream.recv).await?;
        TransportFrame::decode(&raw)?.payload
    };
    if !guard.receive(3, a, b_role, &[], |_, _| true) {
        return Err(Invalid);
    }
    Ok((request, response))
}
impl ProvisionalChannel {
    async fn write_control(
        &self,
        send: &mut quinn::SendStream,
        raw: &[u8],
        _seq: usize,
    ) -> Result<(), HandshakeError> {
        #[cfg(test)]
        if matches!(_seq, 12 | 13)
            && std::env::var("CSF12_BILATERAL_EMIT_CRASH").as_deref() == Ok("before")
        {
            std::process::exit(91);
        }
        #[cfg(test)]
        if let Some(fault) = self.fault
            && fault.sequence == _seq
        {
            let mut raw = raw.to_vec();
            match fault.mutation {
                0 => {
                    for byte in raw {
                        send.write_all(&[byte])
                            .await
                            .map_err(|_| HandshakeError::Rejected)?;
                        tokio::task::yield_now().await;
                    }
                    return Ok(());
                }
                1 => raw.push(1),
                2 => raw[16..20].copy_from_slice(&16385u32.to_be_bytes()),
                3 => raw[11] = 3 - raw[11],
                4 => raw[12..16].copy_from_slice(&((_seq + 1) as u32).to_be_bytes()),
                5 => {
                    raw.truncate(raw.len() / 2);
                    send.write_all(&raw)
                        .await
                        .map_err(|_| HandshakeError::Rejected)?;
                    send.finish().map_err(|_| HandshakeError::Rejected)?;
                    return Ok(());
                }
                6 => raw.extend(raw.clone()),
                _ => return Err(HandshakeError::Rejected),
            }
            return send
                .write_all(&raw)
                .await
                .map_err(|_| HandshakeError::Rejected);
        }
        send.write_all(raw)
            .await
            .map_err(|_| HandshakeError::Rejected)?;
        #[cfg(test)]
        if matches!(_seq, 12 | 13)
            && std::env::var("CSF12_BILATERAL_EMIT_CRASH").as_deref() == Ok("after")
        {
            std::process::exit(91);
        }
        Ok(())
    }
    /// One consumed sealed channel, two logical requester streams, one exporter.
    /// No RecoveryAuthority, active trust, admission or application stream is available.
    pub async fn handshake<F, Fut>(
        mut self,
        config: HandshakeConfig,
        store: &PendingStore,
        confirm: F,
    ) -> Result<HandshakeCompletePendingAuthority, HandshakeError>
    where
        F: FnOnce(VerificationPrompt) -> Fut,
        Fut: std::future::Future<Output = VerificationDecision>,
    {
        let result =
            tokio::time::timeout(Duration::from_secs(300), self.run(config, store, confirm)).await;
        match result {
            Ok(Ok(done)) => Ok(HandshakeCompletePendingAuthority {
                role: done.role,
                durable_fc_hash: done.durable_fc_hash,
                local_binding: done.local_binding,
                pending: done.pending,
                transcript: done.transcript,
                certificate_fingerprints: done.certificate_fingerprints,
                _channel: self,
                _request: done.request,
                failed: done.failed,
                watcher: done.watcher,
                finalization_complete: false,
                durable_commit_complete: false,
            }),
            Ok(Err(HandshakeError::Cancelled)) => Err(HandshakeError::Cancelled),
            _ => {
                self.connection
                    .close(APPLICATION_ERROR.into(), b"pairing rejected");
                Err(HandshakeError::Rejected)
            }
        }
    }
    fn active(&self) -> Result<std::sync::MutexGuard<'_, super::ConsentState>, Invalid> {
        let active = self.scope.0.lock().map_err(|_| Invalid)?;
        if active.phase != super::ConsentPhase::Active
            || self.connection.close_reason().is_some()
            || self.id != format!("quic-{}", self.connection.stable_id())
        {
            return Err(Invalid);
        }
        Ok(active)
    }
    async fn run<F, Fut>(
        &mut self,
        config: HandshakeConfig,
        store: &PendingStore,
        confirm: F,
    ) -> Result<Completed, HandshakeError>
    where
        F: FnOnce(VerificationPrompt) -> Fut,
        Fut: std::future::Future<Output = VerificationDecision>,
    {
        let reject = |_: Invalid| HandshakeError::Rejected;
        {
            let _active = self.active().map_err(reject)?;
            if self.attempted {
                return Err(HandshakeError::Rejected);
            }
        }
        self.attempted = true;
        let clock = LiveClock::new().map_err(reject)?;
        let version = store.version().map_err(|_| HandshakeError::Rejected)?;
        if self.local_identity.cert.len() != 1 {
            return Err(HandshakeError::Rejected);
        }
        let cert = self.local_identity.cert[0].as_ref();
        let local_fp = hash(cert);
        let peer_fp = hash(&self.leaf);
        if local_fp == peer_fp {
            return Err(HandshakeError::Rejected);
        }
        let role = if local_fp < peer_fp { Role::A } else { Role::B };
        let mut guard = CandidateGuard::new();
        let mut first = Stream::new(
            bounded(async {
                if role == Role::A {
                    self.connection.open_bi().await
                } else {
                    self.connection.accept_bi().await
                }
            })
            .await
            .map_err(|_| HandshakeError::Rejected)?,
        );
        let (request_a, candidate_b) = bounded(exchange(
            &mut first,
            Role::A,
            role,
            &config,
            cert,
            &mut guard,
        ))
        .await
        .map_err(reject)?;
        // The first response must be FIN before the second logical requester opens.
        let next = async {
            let mut second = Stream::new(
                bounded(async {
                    if role == Role::B {
                        self.connection.open_bi().await
                    } else {
                        self.connection.accept_bi().await
                    }
                })
                .await
                .map_err(|_| Invalid)?,
            );
            let pair = bounded(exchange(
                &mut second,
                Role::B,
                role,
                &config,
                cert,
                &mut guard,
            ))
            .await?;
            Ok::<_, Invalid>((second, pair))
        };
        let (mut second, (request_b, candidate_a)) = if role == Role::B {
            tokio::select! {biased;_ = watch_request(&mut first.recv)=>return Err(HandshakeError::Rejected),result=next=>result.map_err(reject)?}
        } else {
            next.await.map_err(reject)?
        };
        if !guard.complete() {
            return Err(HandshakeError::Rejected);
        }
        if clock.now().map_err(reject)?.monotonic_ms >= 30_000 {
            return Err(HandshakeError::Rejected);
        }
        let observed = if role == Role::A {
            [cert.to_vec(), self.leaf.clone()]
        } else {
            [self.leaf.clone(), cert.to_vec()]
        };
        let transcript = CandidateTranscript::new(
            [request_a, request_b],
            [candidate_a, candidate_b],
            observed,
            utc().map_err(reject)?,
        )
        .map_err(reject)?;
        let input = BindingInput::new(
            &transcript.requests[role.index()],
            &transcript.candidates[1 - role.index()],
            &self.leaf,
            &self.id,
            self.generation,
            ALPN,
        )
        .map_err(reject)?;
        self.owner.replay.consume_input(&input).map_err(reject)?;
        let mut exporter = Zeroizing::new([0; 32]);
        self.connection
            .export_keying_material(
                exporter.as_mut(),
                SHARED_EXPORTER_LABEL,
                &transcript.exporter_context().map_err(reject)?,
            )
            .map_err(|_| HandshakeError::Rejected)?;
        let binding = transcript
            .local_binding(role, &self.id, self.generation, &exporter)
            .map_err(reject)?;
        let own_hello = hello(&transcript.candidates[role.index()], cert).map_err(reject)?;
        let mut machine = Machine::new(
            transcript,
            role,
            own_hello,
            Zeroizing::new(fresh().map_err(reject)?),
            Zeroizing::new(fresh().map_err(reject)?),
            self.generation,
            version,
            clock.now().map_err(reject)?,
            &self.id,
            self.generation,
        )
        .map_err(reject)?;
        let signer = self
            .local_identity
            .key
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
            .ok_or(HandshakeError::Rejected)?;
        let sign = |body: &[u8]| signer.sign(body).map_err(|_| Invalid);
        let watch = if role == Role::A {
            &mut second.recv
        } else {
            &mut first.recv
        };
        let control = async {
            let pair = bounded(async {
                if role == Role::A {
                    self.connection.open_bi().await
                } else {
                    self.connection.accept_bi().await
                }
            })
            .await
            .map_err(|_| HandshakeError::Rejected)?;
            let mut control = Stream::new(pair);
            let protocol = async {
                let mut confirm = Some(confirm);
                while machine.sequence() < 17 {
                    // Yield to the biased request/extra-stream monitors before
                    // each durable transition, not just between network reads.
                    tokio::task::yield_now().await;
                    let seq = machine.sequence();
                    if seq == 8 {
                        let prompt = machine
                            .prompt(clock.now().map_err(reject)?)
                            .map_err(reject)?;
                        let decision =
                            confirm.take().ok_or(HandshakeError::Rejected)?(prompt.clone()).await;
                        if decision.attempt != prompt.attempt
                            || decision.transcript != prompt.transcript
                            || decision.ui_generation != prompt.ui_generation
                        {
                            return Err(HandshakeError::Rejected);
                        }
                        if !decision.matches {
                            let raw = machine
                                .cancel_local(&sign, store, clock.now().map_err(reject)?)
                                .map_err(reject)?;
                            control
                                .send
                                .write_all(&raw)
                                .await
                                .map_err(|_| HandshakeError::Rejected)?;
                            control
                                .send
                                .finish()
                                .map_err(|_| HandshakeError::Rejected)?;
                            return Err(HandshakeError::Cancelled);
                        }
                        machine
                            .confirm(true, clock.now().map_err(reject)?)
                            .map_err(reject)?;
                    }
                    if SCHEDULE[seq].1 == role.index() as u8 + 1 {
                        let raw = {
                            let _active = self.active().map_err(reject)?;
                            machine
                                .next_local(&sign, store, clock.now().map_err(reject)?)
                                .map_err(reject)?
                        };
                        bounded(self.write_control(&mut control.send, &raw, seq))
                            .await
                            .map_err(reject)?;
                    } else {
                        let raw = bounded(control_record(&mut control.recv))
                            .await
                            .map_err(reject)?;
                        let _active = self.active().map_err(reject)?;
                        machine
                            .receive_remote(&raw, store, clock.now().map_err(reject)?)
                            .map_err(reject)?;
                        if machine.status() == Status::Cancelled {
                            return Err(HandshakeError::Cancelled);
                        }
                    }
                }
                control
                    .send
                    .finish()
                    .map_err(|_| HandshakeError::Rejected)?;
                if !machine.half_close(role) {
                    return Err(HandshakeError::Rejected);
                }
                bounded(eof(&mut control.recv)).await.map_err(reject)?;
                if !machine.half_close(if role == Role::A { Role::B } else { Role::A }) {
                    return Err(HandshakeError::Rejected);
                }
                bounded(control.send.stopped())
                    .await
                    .map_err(|_| HandshakeError::Rejected)?;
                machine.durable_fc().ok_or(HandshakeError::Rejected)
            };
            let result = tokio::select! {biased;
                extra=self.connection.accept_bi()=>{if let Ok(pair)=extra{drop(Stream::new(pair));}Err(HandshakeError::Rejected)},
                extra=self.connection.accept_uni()=>{if let Ok(mut stream)=extra{let _=stream.stop(APPLICATION_ERROR.into());}Err(HandshakeError::Rejected)},
                result=protocol=>result,
            };
            if matches!(&result, Ok(_) | Err(HandshakeError::Cancelled)) {
                control.clean = true;
            }
            result
        };
        let result = tokio::select! {biased;_ = watch_request(watch)=>Err(HandshakeError::Rejected),result=control=>result};
        if result.is_err() {
            machine.reject();
            machine.dispose_pending(store);
        }
        if matches!(&result, Ok(_) | Err(HandshakeError::Cancelled)) {
            first.clean = true;
            second.clean = true;
        }
        let fc = result?;
        let (pending, transcript, certificate_fingerprints) = machine
            .promotion_context()
            .ok_or(HandshakeError::Rejected)?;
        let (request, incoming) = if role == Role::A {
            (first, second)
        } else {
            (second, first)
        };
        let failed = Arc::new(AtomicBool::new(false));
        Ok(Completed {
            role,
            durable_fc_hash: fc,
            local_binding: binding,
            pending,
            transcript,
            certificate_fingerprints,
            request,
            failed: failed.clone(),
            watcher: spawn_ingress_watcher(
                role,
                self.connection.clone(),
                self.scope.clone(),
                failed.clone(),
                incoming,
            ),
        })
    }
}
