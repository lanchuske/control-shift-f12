#!/usr/bin/env python3
"""Static boundary and mutation checks for the default-off admission foundation."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HANDSHAKE = ROOT / "crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs"
AUTHORITY = ROOT / "crates/transport/src/pairing_v2/admission_authority.rs"
PENDING = ROOT / "crates/transport/src/pairing_pending.rs"


def validate(handshake: str, authority: str, pending: str) -> None:
    assert "pub fn local_binding" not in handshake
    assert "pub(super) fn local_binding" not in handshake
    assert "pub(crate) fn local_binding" not in handshake
    assert "pub(crate) async fn seal_for_promotion(\n        self," in handshake
    assert "pub(crate) struct SealedPromotionEvidence" in handshake
    assert not re.search(
        r"#\[derive\([^]]*(?:Clone|Serialize)[^]]*\)\]\s*pub\(crate\) struct SealedPromotionEvidence",
        handshake,
    )
    assert authority.count("evidence.revalidate()") >= 2
    assert "use crate::identity_store::IdentityStore" not in authority
    assert ": IdentityStore" not in authority
    assert "pub(crate) async fn commit_sealed_foundation" in authority
    assert "active_pins: Vec<ActivePin>" in pending
    assert "consumed_attempts: Vec<[u8; 32]>" in pending
    assert "admission_receipts: Vec<AdmissionReceiptRecord>" in pending
    commit = pending.split("fn commit_admission_foundation", 1)[1]
    before_save = commit.split("self.save(&ledger)?", 1)[0]
    assert "ledger.active_pins.push" in before_save
    assert "ledger.consumed_attempts.push" in before_save
    assert "ledger.admission_receipts.push" in before_save
    assert "ledger.version != expected" in commit
    assert "record.version.identity_generation != expected.identity_generation" in commit
    assert "ledger.revocation(record.peer_fingerprint) != expected_revocation_generation" in commit
    assert "ledger.policy_revision != expected_policy_revision" in commit
    assert "StoreError::ConsumedAttempt" in pending


def main() -> None:
    sources = {
        "handshake": HANDSHAKE.read_text(),
        "authority": AUTHORITY.read_text(),
        "pending": PENDING.read_text(),
    }
    validate(**sources)
    mutants = {
        "public-binding-getter": ("handshake", "impl HandshakeCompletePendingAuthority {", "impl HandshakeCompletePendingAuthority {\n    pub fn local_binding(&self) {}"),
        "borrowed-seal": ("handshake", "pub(crate) async fn seal_for_promotion(\n        self,", "pub(crate) async fn seal_for_promotion(\n        &self,"),
        "clone-sealed": ("handshake", "pub(crate) struct SealedPromotionEvidence", "#[derive(Clone)]\npub(crate) struct SealedPromotionEvidence"),
        "single-revalidation": ("authority", "evidence.revalidate()", "Ok(())"),
        "legacy-identity-owner": ("authority", "use std::path::Path;", "use std::path::Path;\nuse crate::identity_store::IdentityStore;"),
        "drop-active-pin": ("pending", "ledger.active_pins.push", "ledger.active_pins.extend"),
        "drop-consumed": ("pending", "ledger.consumed_attempts.push", "ledger.consumed_attempts.extend"),
        "drop-receipt": ("pending", "ledger.admission_receipts.push", "ledger.admission_receipts.extend"),
        "drop-revision-cas": ("pending", "ledger.version != expected", "false"),
        "drop-identity-cas": ("pending", "record.version.identity_generation != expected.identity_generation", "false"),
        "drop-revocation-cas": ("pending", "ledger.revocation(record.peer_fingerprint) != expected_revocation_generation", "false"),
        "drop-policy-cas": ("pending", "ledger.policy_revision != expected_policy_revision", "false"),
    }
    for name, (key, old, new) in mutants.items():
        assert old in sources[key], f"mutant {name} did not match source"
        candidate = dict(sources)
        candidate[key] = candidate[key].replace(old, new, 1)
        try:
            validate(**candidate)
        except AssertionError:
            continue
        raise AssertionError(f"mutant {name} survived")
    print(f"PASS: base contract and {len(mutants)} mutants rejected")


if __name__ == "__main__":
    main()
