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
    assert "pub(crate) struct FrozenPromotionEvidence" in handshake
    assert not re.search(
        r"#\[derive\([^]]*(?:Clone|Serialize)[^]]*\)\]\s*pub\(crate\) struct SealedPromotionEvidence",
        handshake,
    )
    assert authority.count("evidence.revalidate()") >= 2
    assert "let frozen = evidence.freeze().await" in authority
    assert "CommitWitness::Live(Box::new(frozen))" in authority
    frozen_body = handshake.split("pub(crate) struct FrozenPromotionEvidence", 1)[1].split("}", 1)[0]
    assert "ProvisionalChannel" not in frozen_body
    assert "Stream" not in frozen_body
    watcher = handshake.split("let disposition = tokio::select!", 1)[1].split("};", 1)[0]
    assert watcher.find("watch_request") < watcher.find("_=&mut freeze_request")
    assert watcher.find("accept_bi") < watcher.find("_=&mut freeze_request")
    assert watcher.find("accept_uni") < watcher.find("_=&mut freeze_request")
    assert "connection.close(APPLICATION_ERROR.into(), b\"pairing ingress frozen\")" in watcher
    assert "use crate::identity_store::IdentityStore" not in authority
    assert ": IdentityStore" not in authority
    assert "pub(crate) async fn commit_sealed_foundation" in authority
    assert "commit_admission_foundation<F>" not in pending
    assert "FnMut() -> Result<(), StoreError>" not in pending
    metadata_at = authority.find("fn commit_metadata(")
    assert metadata_at < 0 or "#[cfg(test)]" in authority[max(0, metadata_at - 200) : metadata_at]
    assert "pub(crate) struct SealedAdmissionCommit" in authority
    assert "commit: crate::pairing_v2::admission_authority::SealedAdmissionCommit" in pending
    assert "active_pins: Vec<ActivePin>" in pending
    assert "consumed_attempts: Vec<[u8; 32]>" in pending
    assert "admission_receipts: Vec<AdmissionReceiptRecord>" in pending
    commit = pending.split("fn commit_sealed_admission", 1)[1]
    before_save = commit.split("self.save(&ledger)?", 1)[0]
    assert "ledger.active_pins.push" in before_save
    assert "ledger.consumed_attempts.push" in before_save
    assert "ledger.admission_receipts.push" in before_save
    assert commit.find("self.save(&ledger)?") < commit.find("Ok(receipt.clone())")
    assert "return Ok(receipt.clone());\n            self.save(&ledger)?;" not in commit
    assert "ledger.version != expected" in commit
    assert "record.version.identity_generation != expected.identity_generation" in commit
    assert "ledger.revocation(record.peer_fingerprint) != expected_revocation_generation" in commit
    assert "ledger.policy_revision != expected_policy_revision" in commit
    assert "receipt.suite != crate::pairing_v2::SUITE" in pending
    assert re.search(
        r"receipt\.protocol_version\s*!=\s*crate::pairing_v2::admission_authority::PROTOCOL_VERSION",
        pending,
    )
    assert "receipt.revision > self.version.revision" in pending
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
        "drop-freeze": ("authority", "let frozen = evidence.freeze().await", "let frozen = evidence"),
        "unfrozen-live-witness": ("authority", "CommitWitness::Live(Box::new(frozen))", "CommitWitness::Live(Box::new(evidence))"),
        "freeze-beats-queued-violation": ("handshake", "_=watch_request(&mut incoming.recv)=>true,", "_=&mut freeze_request=>{ connection.close(APPLICATION_ERROR.into(), b\"pairing ingress frozen\"); false },\n                _=watch_request(&mut incoming.recv)=>true,"),
        "freeze-without-closing-ingress": ("handshake", "connection.close(APPLICATION_ERROR.into(), b\"pairing ingress frozen\");", "let _ = &connection;"),
        "frozen-retains-runtime-channel": ("handshake", "pub(crate) struct FrozenPromotionEvidence {", "pub(crate) struct FrozenPromotionEvidence {\n    channel: ProvisionalChannel,"),
        "return-before-durability": ("pending", "self.save(&ledger)?;\n            self.pending_dir.remove(&filename(receipt.attempt))?;", "return Ok(receipt.clone());\n            self.save(&ledger)?;\n            self.pending_dir.remove(&filename(receipt.attempt))?;"),
        "legacy-identity-owner": ("authority", "use std::path::Path;", "use std::path::Path;\nuse crate::identity_store::IdentityStore;"),
        "drop-active-pin": ("pending", "ledger.active_pins.push", "ledger.active_pins.extend"),
        "drop-consumed": ("pending", "ledger.consumed_attempts.push", "ledger.consumed_attempts.extend"),
        "drop-receipt": ("pending", "ledger.admission_receipts.push", "ledger.admission_receipts.extend"),
        "drop-revision-cas": ("pending", "ledger.version != expected", "false"),
        "drop-identity-cas": ("pending", "record.version.identity_generation != expected.identity_generation", "false"),
        "drop-revocation-cas": ("pending", "ledger.revocation(record.peer_fingerprint) != expected_revocation_generation", "false"),
        "drop-policy-cas": ("pending", "ledger.policy_revision != expected_policy_revision", "false"),
        "unsealed-commit-input": ("pending", "commit: crate::pairing_v2::admission_authority::SealedAdmissionCommit", "commit: AdmissionReceiptRecord"),
        "drop-exact-suite": ("pending", "receipt.suite != crate::pairing_v2::SUITE", "receipt.suite.is_empty()"),
        "drop-protocol-bound": ("pending", "!= crate::pairing_v2::admission_authority::PROTOCOL_VERSION", "== 0"),
        "drop-revision-bound": ("pending", "receipt.revision > self.version.revision", "false"),
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
