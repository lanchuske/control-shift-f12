#!/usr/bin/env python3
"""Static boundary and mutation checks for the default-off admission foundation."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HANDSHAKE = ROOT / "crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs"
PROVISIONAL = ROOT / "crates/transport/src/pairing_v2/provisional_tls.rs"
AUTHORITY = ROOT / "crates/transport/src/pairing_v2/admission_authority.rs"
PENDING = ROOT / "crates/transport/src/pairing_pending.rs"


def validate(handshake: str, provisional: str, authority: str, pending: str) -> None:
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
    assert re.search(r"let frozen = evidence\s*\.freeze\(store\)\s*\.await", authority)
    assert "CommitWitness::Live(Box::new(frozen))" in authority
    frozen_body = handshake.split("pub(crate) struct FrozenPromotionEvidence", 1)[1].split("}", 1)[0]
    assert "ProvisionalChannel" not in frozen_body
    assert "Stream" not in frozen_body
    watcher = handshake.split("let disposition = tokio::select!", 1)[1].split("if disposition", 1)[0]
    freeze_arm = "request=&mut freeze_request"
    assert watcher.find("watch_request") < watcher.find(freeze_arm)
    assert watcher.find("accept_bi") < watcher.find(freeze_arm)
    assert watcher.find("accept_uni") < watcher.find(freeze_arm)
    assert "connection.close(APPLICATION_ERROR.into(), b\"pairing ingress frozen\")" in watcher
    assert watcher.find("scope.freeze(revoker)") < watcher.find("connection.close")
    assert "if state.phase != ConsentPhase::Active" in provisional
    freeze_scope = provisional.split("fn freeze(&self", 1)[1].split("fn revoke(&self)", 1)[0]
    assert freeze_scope.find("revoker.arm()") < freeze_scope.find("ConsentPhase::Frozen")
    revoke_scope = provisional.split("fn revoke(&self)", 1)[1].split("}\n}", 1)[0]
    mark_revoking_at = revoke_scope.find("revoker.mark_revoking()")
    revoked_at = revoke_scope.find("ConsentPhase::Revoked")
    assert 0 <= mark_revoking_at < revoked_at
    drop_body = provisional.split("impl Drop for ProvisionalEndpoint", 1)[1].split("impl Drop for ProvisionalChannel", 1)[0]
    revoke_scope_at = drop_body.find("let revoker = self.scope.revoke()")
    revoke_store_at = drop_body.find("revoker.revoke()")
    close_at = drop_body.find("self.endpoint.close")
    assert 0 <= revoke_scope_at < close_at
    assert 0 <= revoke_store_at < close_at
    assert "self.store.resolve_admission_guard(attempt)?" in authority
    assert re.search(
        r"self\.ledger_dir\s*\.replace\(&admission_guard_filename\(attempt\), &bytes\)\?",
        pending,
    )
    resolver = pending.split("fn resolve_admission_guard", 1)[1].split("fn revoke_current", 1)[0]
    assert "Some(AdmissionGuardPhase::Active)" in resolver
    assert "Some(AdmissionGuardPhase::RevokingOwned)" in resolver
    assert "return Err(StoreError::Unavailable)" in resolver
    assert "Some(AdmissionGuardPhase::RevokingRetryable)" in resolver
    assert "armed: true" in resolver
    assert "owns_revocation: false" in resolver
    assert "revoker.revoke()" in resolver
    transition = pending.split("pub(crate) fn mark_revoking", 1)[1].split("pub(crate) fn revoke", 1)[0]
    assert "revocation_guard_phases()" in transition
    assert "AdmissionGuardPhase::RevokingOwned" in transition
    assert "self.store" not in transition
    retry = pending.split("fn release_for_retry", 1)[1].split("impl Drop", 1)[0]
    assert "AdmissionGuardPhase::RevokingRetryable" in retry
    reconciliation = authority.split("pub fn reconcile(&self", 1)[1].split("/// Test-only", 1)[0]
    recheck_at = reconciliation.find("admission_guard_still_active")
    interpret_at = reconciliation.find("match (pending, receipt, active)")
    assert 0 <= recheck_at < interpret_at
    revocation = pending.split("fn revoke_current", 1)[1].split("fn reconcile_pairing", 1)[0]
    revocation_before_save = revocation.split("self.save(&ledger)?", 1)[0]
    assert "ledger.active_pins.retain(|pin| pin.peer != peer)" in revocation_before_save
    assert re.search(
        r"ledger\s*\.pending\s*\.retain\(\|entry\| entry\.record\.peer_fingerprint != peer\)",
        revocation_before_save,
    )
    assert "ledger.tombstones.extend(&removed)" in revocation_before_save
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
        "provisional": PROVISIONAL.read_text(),
        "authority": AUTHORITY.read_text(),
        "pending": PENDING.read_text(),
    }
    validate(**sources)
    mutants = {
        "public-binding-getter": ("handshake", "impl HandshakeCompletePendingAuthority {", "impl HandshakeCompletePendingAuthority {\n    pub fn local_binding(&self) {}"),
        "borrowed-seal": ("handshake", "pub(crate) async fn seal_for_promotion(\n        self,", "pub(crate) async fn seal_for_promotion(\n        &self,"),
        "clone-sealed": ("handshake", "pub(crate) struct SealedPromotionEvidence", "#[derive(Clone)]\npub(crate) struct SealedPromotionEvidence"),
        "single-revalidation": ("authority", "evidence.revalidate()", "Ok(())"),
        "drop-freeze": ("authority", ".freeze(store)\n            .await", ".freeze(store)"),
        "unfrozen-live-witness": ("authority", "CommitWitness::Live(Box::new(frozen))", "CommitWitness::Live(Box::new(evidence))"),
        "freeze-beats-queued-violation": ("handshake", "_=watch_request(&mut incoming.recv)=>true,", "request=&mut freeze_request=>{ let _ = request; false },\n                _=watch_request(&mut incoming.recv)=>true,"),
        "freeze-without-closing-ingress": ("handshake", "connection.close(APPLICATION_ERROR.into(), b\"pairing ingress frozen\");", "let _ = &connection;"),
        "drop-scope-check": ("provisional", "if state.phase != ConsentPhase::Active", "if false"),
        "freeze-before-scope-cas": ("handshake", "if scope.freeze(revoker).is_err()", "connection.close(APPLICATION_ERROR.into(), b\"pairing ingress frozen\");\n                    if scope.freeze(revoker).is_err()"),
        "omit-durable-drop-revocation": ("provisional", "let _revocation_result = revoker.revoke();", "let _revocation_result = Ok::<(), crate::pairing_pending::StoreError>(());"),
        "omit-revocation-guard": ("pending", "self.ledger_dir\n                .replace(&admission_guard_filename(attempt), &bytes)?;", "let _ = bytes;"),
        "consume-revocation-retry": ("pending", "armed: true", "armed: false"),
        "drop-synchronous-revoking-transition": ("provisional", "revoker.mark_revoking();", "let _ = revoker;"),
        "permit-concurrent-revocation-owner": ("pending", "Some(AdmissionGuardPhase::RevokingOwned) => {", "Some(AdmissionGuardPhase::Active) => {"),
        "drop-retryable-revocation": ("pending", "revocation_guard_phases().insert(self.token, AdmissionGuardPhase::RevokingRetryable);", "revocation_guard_phases().insert(self.token, AdmissionGuardPhase::Active);"),
        "drop-post-io-revocation-observation": ("authority", "!self.store.admission_guard_still_active(guard)", "false"),
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
    revocation_at = sources["pending"].find("fn revoke_current")
    assert revocation_at >= 0
    for name, old, new in [
        (
            "omit-revocation-active-pin-removal",
            "ledger.active_pins.retain(|pin| pin.peer != peer);",
            "ledger.active_pins.retain(|_| true);",
        ),
        (
            "omit-revocation-tombstones",
            "ledger.tombstones.extend(&removed);",
            "let _ = &removed;",
        ),
    ]:
        prefix = sources["pending"][:revocation_at]
        suffix = sources["pending"][revocation_at:]
        assert old in suffix, f"mutant {name} did not match revocation source"
        candidate = dict(sources)
        candidate["pending"] = prefix + suffix.replace(old, new, 1)
        try:
            validate(**candidate)
        except AssertionError:
            continue
        raise AssertionError(f"mutant {name} survived")
    print(f"PASS: base contract and {len(mutants) + 2} mutants rejected")


if __name__ == "__main__":
    main()
