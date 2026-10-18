//! Pure, injected-clock resource gate. No sockets or identity admission.
use super::Invalid;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

struct Bucket {
    credit: u64,
    updated: u64,
    rate: u64,
    burst: u64,
}
impl Bucket {
    fn new(now: u64, rate: u64, burst: u64) -> Self {
        Self {
            credit: burst * 60_000,
            updated: now,
            rate,
            burst,
        }
    }
    fn refill(&mut self, now: u64) {
        self.credit = (u128::from(self.credit)
            + u128::from(now - self.updated) * u128::from(self.rate))
        .min(u128::from(self.burst * 60_000)) as u64;
        self.updated = now;
    }
}
struct Connection {
    source: IpAddr,
    opened: u64,
    candidate_deadline: Option<u64>,
}
struct Attempt {
    connection: u64,
    deadline: u64,
    phase_deadline: u64,
}
/// Local scope resource accounting, not actual socket or peer authentication.
/// Keep one instance for the engine lifetime; closing a consent window does not
/// reset token buckets or consumed connection IDs. Clock rollback poisons it.
pub struct PairingLimits {
    last: u64,
    poisoned: bool,
    window: bool,
    global: Bucket,
    sources: BTreeMap<IpAddr, Bucket>,
    connections: BTreeMap<u64, Connection>,
    used: BTreeSet<u64>,
    attempt: Option<Attempt>,
}
impl Default for PairingLimits {
    fn default() -> Self {
        Self {
            last: 0,
            poisoned: false,
            window: false,
            global: Bucket::new(0, 20, 5),
            sources: BTreeMap::new(),
            connections: BTreeMap::new(),
            used: BTreeSet::new(),
            attempt: None,
        }
    }
}
impl PairingLimits {
    fn observe(&mut self, now: u64) -> Result<(), Invalid> {
        if self.poisoned || now < self.last {
            self.poisoned = true;
            self.window = false;
            self.attempt = None;
            self.connections.clear();
            return Err(Invalid);
        }
        self.last = now;
        Ok(())
    }
    pub fn open_window(&mut self, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        if self.window {
            return Err(Invalid);
        }
        self.window = true;
        Ok(())
    }
    pub fn close_window(&mut self, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        self.window = false;
        self.attempt = None;
        self.connections.clear();
        Ok(())
    }
    pub fn connect(&mut self, source: IpAddr, id: u64, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        if !self.window
            || self.used.contains(&id)
            || self.used.len() >= 1024
            || self.connections.len() >= 8
            || self
                .connections
                .values()
                .filter(|c| c.source == source)
                .count()
                >= 2
            || (!self.sources.contains_key(&source) && self.sources.len() >= 256)
        {
            return Err(Invalid);
        }
        self.global.refill(now);
        let bucket = self
            .sources
            .entry(source)
            .or_insert_with(|| Bucket::new(now, 5, 2));
        bucket.refill(now);
        if self.global.credit < 60_000 || bucket.credit < 60_000 {
            return Err(Invalid);
        }
        self.global.credit -= 60_000;
        bucket.credit -= 60_000;
        self.used.insert(id);
        self.connections.insert(
            id,
            Connection {
                source,
                opened: now,
                candidate_deadline: None,
            },
        );
        Ok(())
    }
    pub fn candidate(&mut self, id: u64, ttl: u64, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        let connection = self.connections.get_mut(&id).ok_or(Invalid)?;
        if !self.window
            || ttl == 0
            || ttl > 30_000
            || now - connection.opened >= 2000
            || connection.candidate_deadline.is_some()
        {
            return Err(Invalid);
        }
        connection.candidate_deadline = Some(now.checked_add(ttl).ok_or(Invalid)?);
        Ok(())
    }
    /// Called only on explicit local acceptance/selection, never on network receipt.
    pub fn select(&mut self, id: u64, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        let connection = self.connections.get(&id).ok_or(Invalid)?;
        if !self.window
            || self.attempt.is_some()
            || now >= connection.candidate_deadline.ok_or(Invalid)?
        {
            return Err(Invalid);
        }
        self.attempt = Some(Attempt {
            connection: id,
            deadline: now.checked_add(300_000).ok_or(Invalid)?,
            phase_deadline: now.checked_add(30_000).ok_or(Invalid)?,
        });
        Ok(())
    }
    /// Only a newly validated phase transition earns progress; duplicates do not.
    pub fn progress(&mut self, now: u64) -> Result<(), Invalid> {
        self.check(now)?;
        self.attempt.as_mut().ok_or(Invalid)?.phase_deadline =
            now.checked_add(30_000).ok_or(Invalid)?;
        Ok(())
    }
    pub fn check(&mut self, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        let attempt = self.attempt.as_ref().ok_or(Invalid)?;
        if !self.window || now >= attempt.deadline || now >= attempt.phase_deadline {
            let id = attempt.connection;
            self.attempt = None;
            self.connections.remove(&id);
            return Err(Invalid);
        }
        Ok(())
    }
    pub fn finish(&mut self, now: u64) -> Result<(), Invalid> {
        self.observe(now)?;
        if let Some(attempt) = self.attempt.take() {
            self.connections.remove(&attempt.connection);
        }
        Ok(())
    }
}
