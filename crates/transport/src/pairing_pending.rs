//! Quarantined setup metadata. Nothing in this module grants trust or input.
use serde::{Deserialize, Serialize};
use std::path::Path;

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

pub struct PendingStore {
    #[cfg(unix)]
    pending_dir: crate::private_fs::PrivateDir,
    #[cfg(unix)]
    ledger_dir: crate::private_fs::PrivateDir,
}

impl PendingStore {
    /// There is intentionally no boolean or caller-supplied "verified" bypass.
    /// A later reviewed protocol must introduce an unforgeable validated-proof type.
    pub fn promote(&self, _attempt: [u8; 32]) -> Result<(), StoreError> {
        Err(StoreError::VerificationUnavailable)
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::private_fs::PrivateDir;
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

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ledger {
        schema: u32,
        version: StoreVersion,
        pending: Vec<Reference>,
        tombstones: Vec<[u8; 32]>,
        revocations: Vec<Revocation>,
    }

    impl Ledger {
        fn new() -> Self {
            Self {
                schema: 1,
                version: StoreVersion {
                    revision: 0,
                    identity_generation: 0,
                },
                pending: vec![],
                tombstones: vec![],
                revocations: vec![],
            }
        }
        fn validate(&self) -> Result<(), StoreError> {
            if self.schema != 1
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

    impl PendingStore {
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
            ledger.tombstones.push(attempt);
            self.save(&ledger)?;
            // Durable tombstone is authoritative even if deletion fails: no resurrection on retry.
            self.pending_dir.remove(&filename(attempt))
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
            let removed: Vec<_> = ledger
                .pending
                .iter()
                .filter(|r| r.record.peer_fingerprint == peer)
                .map(|r| r.record.attempt_id)
                .collect();
            ledger.pending.retain(|r| r.record.peer_fingerprint != peer);
            ledger.tombstones.extend(&removed);
            self.save(&ledger)?;
            for attempt in removed {
                self.pending_dir.remove(&filename(attempt))?;
            }
            Ok(())
        }

        pub fn revocation_generation(&self, peer: [u8; 32]) -> Result<u64, StoreError> {
            let _lock = self.ledger_dir.lock()?;
            Ok(self.load_validated_manifest()?.revocation(peer))
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
            let removed: Vec<_> = ledger.pending.iter().map(|r| r.record.attempt_id).collect();
            ledger.tombstones.extend(&removed);
            ledger.pending.clear();
            self.save(&ledger)?;
            for attempt in removed {
                self.pending_dir.remove(&filename(attempt))?;
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
impl PendingStore {
    /// Windows must acquire tested owner-only ACL/reparse-point storage before writes are enabled.
    pub fn open(_root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
}
