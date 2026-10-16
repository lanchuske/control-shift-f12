//! Role-specific quarantined finalization. No promotion or runtime admission.
#[cfg(all(test, unix))]
#[path = "journal_fault_tests.rs"]
mod fault_tests;
use super::{
    DerivedKeys, EvidenceContext, Invalid, PROTOCOL, ROLE_MAP, Role, SUITE, SignedEvidence,
    WORDLIST_HASH,
    codec::encode,
    evidence::{b, hash, t},
    validate_identity,
};
use crate::pairing_pending::{PendingRecord, PendingStore, StoreVersion};

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalClock {
    pub boot: [u8; 16],
    pub monotonic_ms: u64,
    pub utc_seconds: i64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum FinalizationAction {
    Accepted,
    NeedsDurability,
}
pub enum ReconcileOutcome {
    Discarded,
    RecoveryOnly(Box<RecoveryJournal>),
}
pub struct RecoveryJournal {
    pub(crate) journal: PublicJournal,
}
impl RecoveryJournal {
    pub fn durable_fc_hash(&self) -> Result<Option<[u8; 32]>, Invalid> {
        self.journal.validate()
    }
    pub fn local_role(&self) -> Role {
        self.journal.local
    }
    pub fn complete_signed(
        &mut self,
        store: &PendingStore,
        expected: StoreVersion,
        remaining: Vec<SignedEvidence>,
        clock: JournalClock,
    ) -> Result<[u8; 32], Invalid> {
        if !self.journal.retained(clock)
            || self.journal.messages.len() == 5
            || remaining.len() != 5 - self.journal.messages.len()
        {
            return Err(Invalid);
        };
        let mut next = self.journal.clone();
        next.messages.extend(remaining);
        let hash = next.validate()?.ok_or(Invalid)?;
        store
            .persist_pairing_journal(expected, &next)
            .map_err(|_| Invalid)?;
        self.journal = next;
        Ok(hash)
    }
}

/// Public signed evidence only. Not an active pin, secret container or admission.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicJournal {
    pub schema: u32,
    pub pending: PendingRecord,
    pub local: Role,
    pub certificates: [Vec<u8>; 2],
    pub transcript: [u8; 32],
    pub approvals: [SignedEvidence; 2],
    pub messages: Vec<SignedEvidence>,
    pub clock: JournalClock,
}
impl PublicJournal {
    pub(crate) fn retained(&self, now: JournalClock) -> bool {
        let utc_age = now.utc_seconds.checked_sub(self.clock.utc_seconds);
        let mono_age = now.monotonic_ms.checked_sub(self.clock.monotonic_ms);
        now.boot != [0; 16]
            && matches!(utc_age,Some(n) if (0..86_400).contains(&n))
            && (now.boot != self.clock.boot || matches!(mono_age,Some(n) if n<86_400_000))
    }
    pub(crate) fn validate(&self) -> Result<Option<[u8; 32]>, Invalid> {
        if self.schema != 1
            || self.clock.boot == [0; 16]
            || self.clock.utc_seconds < 0
            || !(3..=5).contains(&self.messages.len())
        {
            return Err(Invalid);
        };
        let identities = self.certificates.each_ref().map(|cert| {
            let fp = hash(cert);
            validate_identity(
                cert,
                fp[..16].try_into().map_err(|_| Invalid)?,
                self.clock.utc_seconds,
            )
        });
        let [a, b_id] = identities;
        let context = EvidenceContext::new([a?, b_id?], self.pending.attempt_id, self.transcript)?;
        if self.pending.peer_fingerprint
            != *context.identities[1 - self.local.index()].fingerprint()
            || (self.local == Role::B && self.messages.len() < 4)
        {
            return Err(Invalid);
        };
        let p = context.both_approved(&self.approvals[0], &self.approvals[1])?;
        for (index, (phase, role)) in [
            ("ready", Role::A),
            ("ready", Role::B),
            ("commit", Role::A),
            ("commit_ack", Role::B),
            ("complete", Role::A),
        ]
        .iter()
        .enumerate()
        .take(self.messages.len())
        {
            context.verify_finalization(phase, *role, p, &self.messages[index], None)?;
        }
        if self.messages.len() != 5 {
            return Ok(None);
        };
        let fps = [
            context.identities[0].fingerprint().as_slice(),
            context.identities[1].fingerprint().as_slice(),
        ]
        .concat();
        let mut fields = vec![
            t(PROTOCOL),
            t(SUITE),
            b(&WORDLIST_HASH),
            b(&self.pending.attempt_id),
            b(&self.transcript),
            t(ROLE_MAP),
            b(&fps),
        ];
        for record in self.approvals.iter().chain(self.messages.iter()) {
            fields.push(b(&record.encode()?));
        }
        Ok(Some(
            *context
                .verify_fc(&encode("finalization-certificate", &fields)?)?
                .hash(),
        ))
    }
    pub(crate) fn follows(&self, old: &Self) -> bool {
        if old.messages.len() >= self.messages.len() {
            return self == old;
        }
        let mut reduced = self.clone();
        reduced.messages.truncate(old.messages.len());
        reduced == *old
            && ((self.local == Role::A && old.messages.len() == 3)
                || (self.local == Role::B && old.messages.len() == 4))
            && self.messages.len() == 5
    }
}

pub struct Finalizer {
    context: EvidenceContext,
    keys: Option<DerivedKeys>,
    journal: PublicJournal,
    records: [Option<SignedEvidence>; 5],
    own_durable: bool,
    waiting: bool,
    failed: bool,
    deadline: u64,
    phase_deadline: u64,
    last: JournalClock,
    fc: Option<[u8; 32]>,
}
impl Finalizer {
    pub(super) fn start(
        context: EvidenceContext,
        keys: DerivedKeys,
        journal: PublicJournal,
        deadline: u64,
    ) -> Result<Self, Invalid> {
        let last = journal.clock;
        if last.boot == [0; 16] || last.utc_seconds < 0 {
            return Err(Invalid);
        };
        Ok(Self {
            context,
            keys: Some(keys),
            journal,
            records: [None, None, None, None, None],
            own_durable: false,
            waiting: false,
            failed: false,
            deadline,
            phase_deadline: last.monotonic_ms.checked_add(30_000).ok_or(Invalid)?,
            last,
            fc: None,
        })
    }
    fn fail(&mut self) {
        self.failed = true;
        self.keys = None;
    }
    pub fn receive(
        &mut self,
        phase: &str,
        role: Role,
        record: SignedEvidence,
        tag: &[u8],
        clock: JournalClock,
    ) -> Result<FinalizationAction, Invalid> {
        let result = self.receive_inner(phase, role, record, tag, clock);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn receive_inner(
        &mut self,
        phase: &str,
        role: Role,
        record: SignedEvidence,
        tag: &[u8],
        clock: JournalClock,
    ) -> Result<FinalizationAction, Invalid> {
        if self.failed
            || self.waiting
            || self.fc.is_some()
            || clock.boot != self.last.boot
            || clock.monotonic_ms < self.last.monotonic_ms
            || clock.utc_seconds < self.last.utc_seconds
            || clock.monotonic_ms >= self.phase_deadline
            || (!self.own_durable && clock.monotonic_ms >= self.deadline)
        {
            return Err(Invalid);
        };
        self.last = clock;
        let index = match (phase, role) {
            ("ready", Role::A) => 0,
            ("ready", Role::B) => 1,
            ("commit", Role::A) => 2,
            ("commit_ack", Role::B) => 3,
            ("complete", Role::A) => 4,
            _ => return Err(Invalid),
        };
        if self.records[index].is_some()
            || (index >= 2 && self.records[..index].iter().any(Option::is_none))
            || (index >= 3 && self.journal.local == Role::A && !self.own_durable)
            || (index == 4 && !self.own_durable)
        {
            return Err(Invalid);
        };
        let p = self
            .context
            .both_approved(&self.journal.approvals[0], &self.journal.approvals[1])?;
        self.keys.as_ref().ok_or(Invalid)?.verify_finalization(
            &self.context,
            phase,
            role,
            p,
            &record,
            tag,
        )?;
        self.records[index] = Some(record);
        self.phase_deadline = clock.monotonic_ms.checked_add(30_000).ok_or(Invalid)?;
        if index == 4
            || (index == 2 && self.journal.local == Role::A)
            || (index == 3 && self.journal.local == Role::B)
        {
            if !self.own_durable {
                self.journal.clock = clock;
            }
            self.journal.messages = self.records[..=index]
                .iter()
                .map(|r| r.clone().ok_or(Invalid))
                .collect::<Result<_, _>>()?;
            self.journal.validate()?;
            self.waiting = true;
            Ok(FinalizationAction::NeedsDurability)
        } else {
            Ok(FinalizationAction::Accepted)
        }
    }
    pub fn persist(
        &mut self,
        store: &PendingStore,
        expected: StoreVersion,
        clock: JournalClock,
    ) -> Result<(), Invalid> {
        if self.failed || !self.waiting {
            return Err(Invalid);
        };
        if clock.boot != self.last.boot
            || clock.monotonic_ms < self.last.monotonic_ms
            || clock.utc_seconds < self.last.utc_seconds
            || clock.monotonic_ms >= self.phase_deadline
            || (!self.own_durable && clock.monotonic_ms >= self.deadline)
        {
            self.fail();
            return Err(Invalid);
        };
        self.last = clock;
        if store
            .persist_pairing_journal(expected, &self.journal)
            .is_err()
        {
            self.fail();
            return Err(Invalid);
        };
        self.own_durable = true;
        self.waiting = false;
        self.fc = self.journal.validate()?;
        if self.fc.is_some() {
            self.keys = None;
        }
        Ok(())
    }
    pub fn durable_fc_hash(&self) -> Option<[u8; 32]> {
        if self.failed { None } else { self.fc }
    }
}
