//! Offline phase-order verifier. Inputs are already bounded frames; no emitter.
use super::{
    CandidateBinding, CandidateHello, DOMAIN, DerivedKeys, EvidenceContext, Identity, Invalid,
    Role, SAS_FORMAT, SUITE, SignedEvidence, WORDLIST_HASH,
    codec::{Value, decode, encode},
    derive_keys, detached_transcript,
    evidence::{b, hash, t},
    sas_words, validate_identity,
};
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct BoundHello {
    pub(super) identity: Identity,
    pub(super) bytes: Vec<u8>,
}
impl BoundHello {
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        candidate: &CandidateHello,
        binding: &CandidateBinding,
        hello: &[u8],
        tls: [u8; 32],
        connection: &str,
        generation: u64,
        node: [u8; 16],
        utc: i64,
    ) -> Result<Self, Invalid> {
        if !binding.verify(candidate, tls, connection, generation) {
            return Err(Invalid);
        }
        let candidate = decode(
            "candidate-hello",
            &candidate.encode()?,
            &[2, 2, 2, 3, 3, 2, 2, 1],
        )?;
        let fields = decode("hello", hello, &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1])?;
        let mut singleton = vec![0, 1, 0, SUITE.len() as u8];
        singleton.extend_from_slice(SUITE.as_bytes());
        if fields[0] != Value::Number(2)
            || candidate[5] != Value::Bytes(singleton)
            || fields[2] != candidate[0]
            || fields[4] != Value::Bytes(binding.digest().to_vec())
            || fields[5] != candidate[1]
            || fields[6] != candidate[2]
            || fields[7] != candidate[3]
            || fields[9..]
                != [
                    Value::Text(SUITE.into()),
                    Value::Text(SAS_FORMAT.into()),
                    Value::Bytes(WORDLIST_HASH.to_vec()),
                    Value::Text("compare_v2_required".into()),
                    Value::Number(300),
                ]
        {
            return Err(Invalid);
        }
        for index in [1, 3] {
            if !matches!(&fields[index], Value::Bytes(b) if b.len() == 16) {
                return Err(Invalid);
            }
        }
        let Value::Bytes(cert) = &fields[8] else {
            return Err(Invalid);
        };
        let identity = validate_identity(cert, node, utc)?;
        if *identity.fingerprint() != tls {
            return Err(Invalid);
        }
        Ok(Self {
            identity,
            bytes: hello.to_vec(),
        })
    }
    pub fn fingerprint(&self) -> &[u8; 32] {
        self.identity.fingerprint()
    }
}

pub enum SessionMessage {
    Commit(super::Role, Vec<u8>),
    Reveal(super::Role, Vec<u8>),
    KeyProof(super::Role, Vec<u8>, Vec<u8>),
    Approval(super::Role, super::SignedEvidence, Vec<u8>),
}
pub struct SasSession {
    hellos: [BoundHello; 2],
    local: Role,
    attempt: [u8; 32],
    context_hash: [u8; 32],
    transcript: Option<[u8; 32]>,
    context: Option<EvidenceContext>,
    keys: Option<Arc<DerivedKeys>>,
    private: Option<Zeroizing<[u8; 32]>>,
    ui: u64,
    local_confirmed: bool,
    commits: [Option<Vec<u8>>; 2],
    reveals: [Option<Vec<u8>>; 2],
    proofs: [Option<(Vec<u8>, Vec<u8>)>; 2],
    approvals: [Option<(SignedEvidence, Vec<u8>)>; 2],
    p: Option<[u8; 32]>,
    last: u64,
    deadline: u64,
    phase_deadline: u64,
    aborted: bool,
}
impl SasSession {
    pub(super) fn live_evidence(&self) -> Result<super::handshake_evidence::LiveEvidence, Invalid> {
        if self.aborted {
            return Err(Invalid);
        }
        Ok(super::handshake_evidence::LiveEvidence {
            context: self.context.as_ref().ok_or(Invalid)?.clone(),
            keys: self.keys.as_ref().ok_or(Invalid)?.clone(),
        })
    }
    pub(super) fn local_commit(&self, blind: &[u8; 32]) -> Result<Vec<u8>, Invalid> {
        if self.aborted || self.reveals.iter().any(Option::is_some) {
            return Err(Invalid);
        }
        let public = curve25519_dalek::constants::X25519_BASEPOINT
            .mul_clamped(**self.private.as_ref().ok_or(Invalid)?)
            .to_bytes();
        let commitment = hash(&encode(
            "commit-body",
            &[
                t(DOMAIN),
                b(&self.context_hash),
                t(self.local.text()),
                b(&public),
                b(blind),
            ],
        )?);
        encode(
            "commit",
            &[b(&self.attempt), t(self.local.text()), b(&commitment)],
        )
    }
    pub(super) fn local_reveal(&self, blind: &[u8; 32]) -> Result<Vec<u8>, Invalid> {
        if self.aborted || self.commits.iter().any(Option::is_none) {
            return Err(Invalid);
        }
        let public = curve25519_dalek::constants::X25519_BASEPOINT
            .mul_clamped(**self.private.as_ref().ok_or(Invalid)?)
            .to_bytes();
        encode(
            "reveal",
            &[b(&self.attempt), t(self.local.text()), b(&public), b(blind)],
        )
    }
    /// Explicit local cancel is terminal; retry requires a new attempt and keys.
    pub fn cancel(&mut self) {
        self.abort();
    }
    pub fn begin_finalization(
        mut self,
        pending: crate::pairing_pending::PendingRecord,
        clock: super::JournalClock,
    ) -> Result<super::Finalizer, Invalid> {
        self.check(clock.monotonic_ms)?;
        if pending.attempt_id != self.attempt
            || pending.peer_fingerprint != *self.hellos[1 - self.local.index()].fingerprint()
            || self.p.is_none()
        {
            return Err(Invalid);
        }
        let mut certificates = [vec![], vec![]];
        for (i, hello) in self.hellos.iter().enumerate() {
            let fields = decode(
                "hello",
                &hello.bytes,
                &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1],
            )?;
            let Value::Bytes(cert) = &fields[8] else {
                return Err(Invalid);
            };
            certificates[i] = cert.clone();
        }
        let [Some((a, _)), Some((b, _))] = self.approvals else {
            return Err(Invalid);
        };
        super::Finalizer::start(
            self.context.ok_or(Invalid)?,
            self.keys.ok_or(Invalid)?,
            super::PublicJournal {
                schema: 1,
                pending,
                local: self.local,
                certificates,
                transcript: self.transcript.ok_or(Invalid)?,
                approvals: [a, b],
                messages: vec![],
                clock,
            },
            self.deadline,
        )
    }
    pub fn new(
        mut hellos: [BoundHello; 2],
        local: [u8; 32],
        initiator: [u8; 32],
        private: Zeroizing<[u8; 32]>,
        ui: u64,
        now: u64,
    ) -> Result<Self, Invalid> {
        hellos.sort_by_key(|h| *h.fingerprint());
        if hellos[0].fingerprint() == hellos[1].fingerprint()
            || initiator != *hellos[0].fingerprint()
        {
            return Err(Invalid);
        }
        let local = if local == *hellos[0].fingerprint() {
            Role::A
        } else if local == *hellos[1].fingerprint() {
            Role::B
        } else {
            return Err(Invalid);
        };
        let context_hash = hash(&encode(
            "context",
            &[
                t(DOMAIN),
                b(&hellos[0].bytes),
                b(&hellos[1].bytes),
                t(SUITE),
                t("A,B"),
            ],
        )?);
        let attempt = hash(&encode("attempt", &[t(DOMAIN), b(&context_hash)])?);
        Ok(Self {
            hellos,
            local,
            attempt,
            context_hash,
            transcript: None,
            context: None,
            keys: None,
            private: Some(private),
            ui,
            local_confirmed: false,
            commits: [None, None],
            reveals: [None, None],
            proofs: [None, None],
            approvals: [None, None],
            p: None,
            last: now,
            deadline: now.checked_add(300_000).ok_or(Invalid)?,
            phase_deadline: now.checked_add(30_000).ok_or(Invalid)?,
            aborted: false,
        })
    }
    fn abort(&mut self) {
        self.aborted = true;
        self.private = None;
        self.keys = None;
        self.p = None;
    }
    fn check(&mut self, now: u64) -> Result<(), Invalid> {
        if self.aborted
            || now < self.last
            || now >= self.deadline
            || (self.proofs.iter().any(Option::is_none) && now >= self.phase_deadline)
        {
            self.abort();
            return Err(Invalid);
        }
        self.last = now;
        Ok(())
    }
    pub fn receive(&mut self, message: SessionMessage, now: u64) -> Result<(), Invalid> {
        self.check(now)?;
        let result = self.receive_inner(message, now);
        if result.is_err() {
            self.abort();
        }
        result
    }
    fn receive_inner(&mut self, message: SessionMessage, now: u64) -> Result<(), Invalid> {
        match message {
            SessionMessage::Commit(role, raw) => {
                let i = role.index();
                if let Some(old) = &self.commits[i] {
                    return if *old == raw { Ok(()) } else { Err(Invalid) };
                }
                if self.reveals.iter().any(Option::is_some) {
                    return Err(Invalid);
                }
                let fields = decode("commit", &raw, &[2, 3, 2])?;
                if fields[..2] != [b(&self.attempt), t(role.text())]
                    || !matches!(&fields[2],Value::Bytes(v) if v.len()==32)
                {
                    return Err(Invalid);
                }
                self.commits[i] = Some(raw);
                if self.commits.iter().all(Option::is_some) {
                    self.phase_deadline = now.checked_add(30_000).ok_or(Invalid)?;
                }
            }
            SessionMessage::Reveal(role, raw) => {
                let i = role.index();
                if let Some(old) = &self.reveals[i] {
                    return if *old == raw { Ok(()) } else { Err(Invalid) };
                }
                if self.commits.iter().any(Option::is_none) {
                    return Err(Invalid);
                }
                let fields = decode("reveal", &raw, &[2, 3, 2, 2])?;
                if fields[..2] != [b(&self.attempt), t(role.text())] {
                    return Err(Invalid);
                }
                let (Value::Bytes(pk), Value::Bytes(blind)) = (&fields[2], &fields[3]) else {
                    return Err(Invalid);
                };
                if pk.len() != 32 || blind.len() != 32 {
                    return Err(Invalid);
                };
                let commitment = hash(&encode(
                    "commit-body",
                    &[
                        t(DOMAIN),
                        b(&self.context_hash),
                        t(role.text()),
                        b(pk),
                        b(blind),
                    ],
                )?);
                let stored = decode(
                    "commit",
                    self.commits[i].as_ref().ok_or(Invalid)?,
                    &[2, 3, 2],
                )?;
                if stored[2] != b(&commitment) {
                    return Err(Invalid);
                }
                if role == self.local
                    && curve25519_dalek::constants::X25519_BASEPOINT
                        .mul_clamped(**self.private.as_ref().ok_or(Invalid)?)
                        .to_bytes()
                        .as_slice()
                        != pk
                {
                    return Err(Invalid);
                }
                self.reveals[i] = Some(raw);
                if self.reveals.iter().all(Option::is_some) {
                    let (_, _, transcript) = detached_transcript(
                        &self.hellos[0].bytes,
                        &self.hellos[1].bytes,
                        [
                            self.commits[0].as_deref().ok_or(Invalid)?,
                            self.commits[1].as_deref().ok_or(Invalid)?,
                        ],
                        [
                            self.reveals[0].as_deref().ok_or(Invalid)?,
                            self.reveals[1].as_deref().ok_or(Invalid)?,
                        ],
                    )?;
                    let peer = decode(
                        "reveal",
                        self.reveals[1 - self.local.index()]
                            .as_ref()
                            .ok_or(Invalid)?,
                        &[2, 3, 2, 2],
                    )?;
                    let Value::Bytes(peer) = &peer[2] else {
                        return Err(Invalid);
                    };
                    self.keys = Some(Arc::new(derive_keys(
                        self.private.take().ok_or(Invalid)?,
                        peer.as_slice().try_into().map_err(|_| Invalid)?,
                        transcript,
                    )?));
                    self.context = Some(EvidenceContext::new(
                        [
                            self.hellos[0].identity.clone(),
                            self.hellos[1].identity.clone(),
                        ],
                        self.attempt,
                        transcript,
                    )?);
                    self.transcript = Some(transcript);
                    self.phase_deadline = now.checked_add(30_000).ok_or(Invalid)?;
                }
            }
            SessionMessage::KeyProof(role, signature, tag) => {
                let i = role.index();
                if let Some(old) = &self.proofs[i] {
                    return if old == &(signature, tag) {
                        Ok(())
                    } else {
                        Err(Invalid)
                    };
                }
                self.context.as_ref().ok_or(Invalid)?.verify_key_proof(
                    role,
                    &signature,
                    &tag,
                    self.keys.as_ref().ok_or(Invalid)?,
                )?;
                self.proofs[i] = Some((signature, tag));
            }
            SessionMessage::Approval(role, record, tag) => {
                let i = role.index();
                if self.proofs.iter().any(Option::is_none)
                    || (role == self.local && !self.local_confirmed)
                {
                    return Err(Invalid);
                }
                if let Some((old, old_tag)) = &self.approvals[i] {
                    return if old.encode()? == record.encode()? && *old_tag == tag {
                        Ok(())
                    } else {
                        Err(Invalid)
                    };
                }
                let context = self.context.as_ref().ok_or(Invalid)?;
                self.keys
                    .as_ref()
                    .ok_or(Invalid)?
                    .verify_approval(context, role, &record, &tag)?;
                self.approvals[i] = Some((record, tag));
                if let [Some((a, _)), Some((b, _))] = &self.approvals {
                    self.p = Some(context.both_approved(a, b)?);
                }
            }
        }
        Ok(())
    }
    pub fn confirm(
        &mut self,
        attempt: [u8; 32],
        transcript: [u8; 32],
        ui: u64,
        matches: bool,
        now: u64,
    ) -> Result<(), Invalid> {
        self.check(now)?;
        if !matches
            || self.proofs.iter().any(Option::is_none)
            || self.attempt != attempt
            || self.transcript != Some(transcript)
            || self.ui != ui
        {
            self.abort();
            return Err(Invalid);
        }
        self.local_confirmed = true;
        Ok(())
    }
    pub fn verification_words(&mut self, now: u64) -> Option<[String; 4]> {
        self.check(now).ok()?;
        if self.proofs.iter().any(Option::is_none) {
            return None;
        }
        sas_words(&self.keys.as_ref()?.sas_digest(self.attempt).ok()?).ok()
    }
    pub fn both_approved(&mut self, now: u64) -> Option<[u8; 32]> {
        self.check(now).ok()?;
        self.p
    }
}
