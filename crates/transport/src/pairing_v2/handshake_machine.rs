//! Sealed-at-composition bilateral machine. Durable evidence never grants trust.
use super::{
    BoundHello, DOMAIN, FinalizationAction, Finalizer, Invalid, JournalClock, Role, SasSession,
    SessionMessage,
    codec::encode,
    evidence::{b, hash, t},
    handshake_binding::CandidateTranscript,
    handshake_evidence::{LiveEvidence, Sign, unwrap},
    handshake_wire::{Envelope, SCHEDULE, Status, WireGuard},
};
use crate::pairing_pending::{PendingStore, StoreVersion};
use zeroize::Zeroizing;
pub(super) struct Machine {
    guard: WireGuard,
    core: Core,
}
struct Core {
    candidates: CandidateTranscript,
    role: Role,
    hello: Vec<u8>,
    hellos: [Option<BoundHello>; 2],
    private: Option<Zeroizing<[u8; 32]>>,
    blind: Option<Zeroizing<[u8; 32]>>,
    session: Option<SasSession>,
    live: Option<LiveEvidence>,
    finalizer: Option<Finalizer>,
    ui: u64,
    approved: bool,
    p: Option<[u8; 32]>,
    version: StoreVersion,
    last: JournalClock,
    deadline: u64,
    connection: String,
    generation: u64,
    pending_attempt: Option<[u8; 32]>,
    durable_started: bool,
    storage_failed: bool,
}
impl Machine {
    pub fn dispose_pending(&mut self, store: &PendingStore) {
        if !self.core.durable_started
            && !self.core.storage_failed
            && let Some(attempt) = self.core.pending_attempt.take()
        {
            let _ = store.cancel(self.core.version, attempt);
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        c: CandidateTranscript,
        role: Role,
        hello: Vec<u8>,
        private: Zeroizing<[u8; 32]>,
        blind: Zeroizing<[u8; 32]>,
        ui: u64,
        version: StoreVersion,
        clock: JournalClock,
        connection: &str,
        generation: u64,
    ) -> Result<Self, Invalid> {
        if clock.boot == [0; 16] || clock.utc_seconds < 0 {
            return Err(Invalid);
        }
        c.bind_hello(role, &hello, connection, generation, clock.utc_seconds)?;
        Ok(Self {
            guard: WireGuard::new(),
            core: Core {
                candidates: c,
                role,
                hello,
                hellos: [None, None],
                private: Some(private),
                blind: Some(blind),
                session: None,
                live: None,
                finalizer: None,
                ui,
                approved: false,
                p: None,
                version,
                last: clock,
                deadline: clock.monotonic_ms.checked_add(300_000).ok_or(Invalid)?,
                connection: connection.into(),
                generation,
                pending_attempt: None,
                durable_started: false,
                storage_failed: false,
            },
        })
    }
    pub fn receive(
        &mut self,
        raw: &[u8],
        store: &PendingStore,
        clock: JournalClock,
    ) -> Result<(), Invalid> {
        let core = &mut self.core;
        if !self
            .guard
            .receive_bytes(raw, |_, e| core.accept(e, store, clock).is_ok())
        {
            self.core.clear();
            return Err(Invalid);
        }
        if self.guard.status() == Status::Cancelled {
            self.core.clear();
        }
        Ok(())
    }
    pub fn reject(&mut self) {
        self.guard.protocol_error();
        self.core.clear();
    }
    pub fn sequence(&self) -> usize {
        self.guard.sequence()
    }
    pub fn receive_remote(
        &mut self,
        raw: &[u8],
        store: &PendingStore,
        clock: JournalClock,
    ) -> Result<(), Invalid> {
        if !matches!(Envelope::decode(raw),Ok(e) if e.direction!=self.core.role.index() as u8+1) {
            self.reject();
            return Err(Invalid);
        }
        self.receive(raw, store, clock)
    }
    pub fn prompt(
        &mut self,
        clock: JournalClock,
    ) -> Result<super::provisional_tls::VerificationPrompt, Invalid> {
        self.core.check(clock)?;
        if self.sequence() != 8 || self.status() != Status::Active {
            return Err(Invalid);
        }
        let words = self
            .core
            .session
            .as_mut()
            .ok_or(Invalid)?
            .verification_words(clock.monotonic_ms)
            .ok_or(Invalid)?;
        let live = self.core.live.as_ref().ok_or(Invalid)?;
        let mut names = [String::new(), String::new()];
        for (i, name) in names.iter_mut().enumerate() {
            let f = super::codec::decode(
                "candidate-hello",
                &self.core.candidates.candidates[i],
                &[2, 2, 2, 3, 3, 2, 2, 1],
            )?;
            let super::codec::Value::Text(value) = &f[3] else {
                return Err(Invalid);
            };
            *name = value.clone();
        }
        Ok(super::provisional_tls::VerificationPrompt {
            attempt: live.context.attempt,
            transcript: live.context.transcript,
            ui_generation: self.core.ui,
            words,
            names,
            fingerprints: self
                .core
                .candidates
                .observed
                .each_ref()
                .map(|der| hash(der)),
        })
    }
    pub fn cancel_local(
        &mut self,
        sign: Sign<'_>,
        store: &PendingStore,
        clock: JournalClock,
    ) -> Result<Vec<u8>, Invalid> {
        if self.sequence() < 8 || self.status() != Status::Active {
            self.reject();
            return Err(Invalid);
        }
        let raw = Envelope {
            kind: 11,
            direction: self.core.role.index() as u8 + 1,
            sequence: self.sequence() as u32,
            payload: self
                .core
                .live
                .as_ref()
                .ok_or(Invalid)?
                .cancel(self.core.role, sign)?,
        }
        .encode()?;
        self.receive(&raw, store, clock)?;
        Ok(raw)
    }
    pub fn next_local(
        &mut self,
        sign: Sign<'_>,
        store: &PendingStore,
        clock: JournalClock,
    ) -> Result<Vec<u8>, Invalid> {
        let result = (|| {
            self.core.check(clock)?;
            if self.guard.status() != Status::Active {
                return Err(Invalid);
            }
            let seq = self.guard.sequence();
            let (kind, direction) = *SCHEDULE.get(seq).ok_or(Invalid)?;
            if direction != self.core.role.index() as u8 + 1 {
                return Err(Invalid);
            }
            let payload = self.core.outgoing(kind, sign)?;
            let raw = Envelope {
                kind,
                direction,
                sequence: seq as u32,
                payload,
            }
            .encode()?;
            // This invokes role-specific journal writes before returning bytes to I/O.
            self.receive(&raw, store, clock)?;
            Ok(raw)
        })();
        if result.is_err() {
            self.guard.protocol_error();
            self.core.clear();
        }
        result
    }
    pub fn confirm(&mut self, matches: bool, clock: JournalClock) -> Result<(), Invalid> {
        let result = (|| {
            self.core.check(clock)?;
            if self.guard.status() != Status::Active || self.guard.sequence() != 8 {
                return Err(Invalid);
            }
            let live = self.core.live.as_ref().ok_or(Invalid)?;
            self.core.session.as_mut().ok_or(Invalid)?.confirm(
                live.context.attempt,
                live.context.transcript,
                self.core.ui,
                matches,
                clock.monotonic_ms,
            )?;
            self.core.approved = true;
            Ok(())
        })();
        if result.is_err() {
            self.guard.protocol_error();
            self.core.clear();
        }
        result
    }
    pub fn half_close(&mut self, role: Role) -> bool {
        let ok = self.guard.half_close(role.index() as u8 + 1);
        if !ok || self.guard.status() == Status::CompletePendingAuthority {
            self.core.live = None;
            self.core.private = None;
            self.core.blind = None;
        }
        ok
    }
    pub fn status(&self) -> Status {
        self.guard.status()
    }
    pub fn durable_fc(&self) -> Option<[u8; 32]> {
        if matches!(self.status(), Status::Aborted | Status::Cancelled) {
            None
        } else {
            self.core.finalizer.as_ref()?.durable_fc_hash()
        }
    }
    pub fn promotion_context(
        &self,
    ) -> Option<(
        crate::pairing_pending::PendingRecord,
        [u8; 32],
        [[u8; 32]; 2],
    )> {
        if self.status() != Status::CompletePendingAuthority {
            return None;
        }
        self.core.finalizer.as_ref()?.promotion_context()
    }
}
impl Core {
    fn clear(&mut self) {
        self.private = None;
        self.blind = None;
        self.live = None;
        self.session = None;
        self.finalizer = None;
        self.p = None;
    }
    fn check(&mut self, clock: JournalClock) -> Result<(), Invalid> {
        if clock.boot != self.last.boot
            || clock.monotonic_ms < self.last.monotonic_ms
            || clock.utc_seconds < self.last.utc_seconds
            || clock.monotonic_ms >= self.deadline
        {
            return Err(Invalid);
        }
        self.last = clock;
        Ok(())
    }
    fn outgoing(&self, kind: u8, sign: Sign<'_>) -> Result<Vec<u8>, Invalid> {
        match kind {
            1 => Ok(self.hello.clone()),
            2 => self
                .session
                .as_ref()
                .ok_or(Invalid)?
                .local_commit(self.blind.as_ref().ok_or(Invalid)?),
            3 => self
                .session
                .as_ref()
                .ok_or(Invalid)?
                .local_reveal(self.blind.as_ref().ok_or(Invalid)?),
            4 => self
                .live
                .as_ref()
                .ok_or(Invalid)?
                .key_proof(self.role, sign),
            5 if self.approved => self.live.as_ref().ok_or(Invalid)?.approval(self.role, sign),
            6..=9 => self.live.as_ref().ok_or(Invalid)?.finalization(
                phase(kind)?,
                self.role,
                self.p.ok_or(Invalid)?,
                sign,
            ),
            10 => self.finalizer.as_ref().ok_or(Invalid)?.durable_fc_bytes(),
            _ => Err(Invalid),
        }
    }
    fn accept(
        &mut self,
        e: &Envelope,
        store: &PendingStore,
        clock: JournalClock,
    ) -> Result<(), Invalid> {
        self.check(clock)?;
        let role = if e.direction == 1 { Role::A } else { Role::B };
        match e.kind {
            1 => {
                self.hellos[role.index()] = Some(self.candidates.bind_hello(
                    role,
                    &e.payload,
                    &self.connection,
                    self.generation,
                    clock.utc_seconds,
                )?);
                if self.hellos.iter().all(Option::is_some) {
                    let a = self.hellos[0].take().ok_or(Invalid)?;
                    let b = self.hellos[1].take().ok_or(Invalid)?;
                    let local = hash(&self.candidates.observed[self.role.index()]);
                    let initiator = *a.fingerprint();
                    self.session = Some(SasSession::new(
                        [a, b],
                        local,
                        initiator,
                        self.private.take().ok_or(Invalid)?,
                        self.ui,
                        clock.monotonic_ms,
                    )?);
                }
            }
            2 => self.session.as_mut().ok_or(Invalid)?.receive(
                SessionMessage::Commit(role, e.payload.clone()),
                clock.monotonic_ms,
            )?,
            3 => {
                self.session.as_mut().ok_or(Invalid)?.receive(
                    SessionMessage::Reveal(role, e.payload.clone()),
                    clock.monotonic_ms,
                )?;
                if e.sequence == 5 {
                    self.live = Some(self.session.as_ref().ok_or(Invalid)?.live_evidence()?);
                    self.blind = None;
                }
            }
            4 => {
                let (record, tag) = unwrap("wire-key-proof-v1", &e.payload)?;
                let live = self.live.as_ref().ok_or(Invalid)?;
                if record.body
                    != encode(
                        "key-proof-body",
                        &[
                            t(DOMAIN),
                            b(&live.context.attempt),
                            b(&live.context.transcript),
                            t(role.text()),
                        ],
                    )?
                {
                    return Err(Invalid);
                }
                self.session.as_mut().ok_or(Invalid)?.receive(
                    SessionMessage::KeyProof(role, record.signature, tag),
                    clock.monotonic_ms,
                )?;
            }
            5 => {
                let (record, tag) = unwrap("wire-approval-v1", &e.payload)?;
                self.session.as_mut().ok_or(Invalid)?.receive(
                    SessionMessage::Approval(role, record, tag),
                    clock.monotonic_ms,
                )?;
                if e.sequence == 9 {
                    self.p = self
                        .session
                        .as_mut()
                        .ok_or(Invalid)?
                        .both_approved(clock.monotonic_ms);
                    let attempt = self.live.as_ref().ok_or(Invalid)?.context.attempt;
                    self.storage_failed = true;
                    let pending = store
                        .prepare(
                            self.version,
                            attempt,
                            hash(&self.candidates.observed[1 - self.role.index()]),
                        )
                        .map_err(|_| Invalid)?;
                    self.storage_failed = false;
                    self.pending_attempt = Some(attempt);
                    self.version = pending.version;
                    self.finalizer = Some(
                        self.session
                            .take()
                            .ok_or(Invalid)?
                            .begin_finalization(pending, clock)?,
                    );
                }
            }
            6..=9 => {
                let (record, tag) = unwrap("wire-finalization-v1", &e.payload)?;
                let finalizer = self.finalizer.as_mut().ok_or(Invalid)?;
                if finalizer.receive(phase(e.kind)?, role, record, &tag, clock)?
                    == FinalizationAction::NeedsDurability
                {
                    self.storage_failed = true;
                    finalizer.persist(store, self.version, clock)?;
                    self.storage_failed = false;
                    self.durable_started = true;
                    self.version.revision = self.version.revision.checked_add(1).ok_or(Invalid)?;
                }
            }
            10 => {
                let fc = self
                    .live
                    .as_ref()
                    .ok_or(Invalid)?
                    .context
                    .verify_fc(&e.payload)?;
                if Some(*fc.hash()) != self.finalizer.as_ref().ok_or(Invalid)?.durable_fc_hash() {
                    return Err(Invalid);
                }
            }
            11 => self
                .live
                .as_ref()
                .ok_or(Invalid)?
                .verify_cancel(role, &e.payload)?,
            _ => return Err(Invalid),
        }
        Ok(())
    }
}
fn phase(kind: u8) -> Result<&'static str, Invalid> {
    match kind {
        6 => Ok("ready"),
        7 => Ok("commit"),
        8 => Ok("commit_ack"),
        9 => Ok("complete"),
        _ => Err(Invalid),
    }
}
#[cfg(all(test, unix))]
mod tests;
