#!/usr/bin/env python3
"""Static/mutation checks for the staged durable admission boundary."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HANDSHAKE = ROOT / "crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs"
PROVISIONAL = ROOT / "crates/transport/src/pairing_v2/provisional_tls.rs"
AUTHORITY = ROOT / "crates/transport/src/pairing_v2/admission_authority.rs"
PENDING = ROOT / "crates/transport/src/pairing_pending.rs"


def section(source: str, start: str, end: str) -> str:
    return source.split(start, 1)[1].split(end, 1)[0]


def validate(handshake: str, provisional: str, authority: str, pending: str) -> None:
    # The sealed witness remains private and non-cloneable; no product authority
    # leaks while the durable handoff is being staged.
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
    frozen_body = section(
        handshake,
        "pub(crate) struct FrozenPromotionEvidence",
        "}",
    )
    assert "ProvisionalChannel" not in frozen_body
    assert "Stream" not in frozen_body
    assert "if state.phase != ConsentPhase::Active" in provisional

    # The authority performs an explicit two-stage publication: the first
    # receipt is ineligible, then the frozen endpoint is claimed while the
    # store lock is held before StoreOwned metadata and the pin are published.
    assert "pub(crate) async fn commit_sealed_foundation" in authority
    assert ".stage_sealed_admission(expected, commit.record(), commit.receipt())?" in authority
    assert ".finalize_staged_admission(staged_version, attempt, handoff)" in authority
    assert "revoker.release_to_store()?" in authority
    assert "self.store.resolve_admission_guard(attempt)" in authority
    assert "use crate::identity_store::IdentityStore" not in authority
    assert ": IdentityStore" not in authority

    stage = section(pending, "pub(crate) fn stage_sealed_admission", "pub(crate) fn finalize_staged_admission")
    assert "AdmissionOwnership::AwaitingHandoff" in stage
    assert "ledger.admission_receipts.push(receipt.clone())" in stage
    assert "ledger.active_pins.push" not in stage
    assert stage.find("self.save(&ledger)?") < stage.find("Ok(receipt.clone())")

    finalizer = section(pending, "pub(crate) fn finalize_staged_admission", "pub(crate) fn admission_state")
    assert "AdmissionOwnership::StoreOwned" in finalizer
    assert "handoff.store_owned_ownership(expected.revision, final_revision)" in finalizer
    assert "let _lock = self.ledger_dir.lock()?;" in finalizer
    assert "let revoker = handoff.claim().map_err(|_| StoreError::Invalid)?;" in finalizer
    assert finalizer.find("let _lock = self.ledger_dir.lock()?;") < finalizer.find("handoff.claim()")
    assert "ledger.active_pins.push(ActivePin" in finalizer
    assert finalizer.find("ledger.active_pins.push(ActivePin") < finalizer.find("self.save(&ledger)?")
    assert finalizer.find("self.save(&ledger)?") < finalizer.find("Ok((finalized, revoker))")

    # A pin belongs to one durable admission receipt. A later attempt for the
    # same peer must fail closed even if it presents the same pin value.
    pin_for_peer = re.compile(
        r"ledger\s*\.active_pins\s*\.iter\(\)\s*\.any\(\|pin\| pin\.peer == receipt\.peer\)"
    )
    # One fail-closed check occurs before the legacy synthetic publication,
    # one guards its subsequent pin insertion, and one guards finalization.
    assert len(pin_for_peer.findall(pending)) >= 3

    # Every post-store sidecar removal reads and compares both attempt and
    # token under the ledger lock. An attempt-only cleanup could erase a newer
    # guard created for the same attempt.
    assert "fn clear_admission_guard(" not in pending
    exact_cleanup = section(pending, "fn clear_admission_guard_exact", "fn resolve_admission_guard")
    assert "let _lock = self.ledger_dir.lock()?;" in exact_cleanup
    assert "self.ledger_dir.read(&file, RECORD_LIMIT)?" in exact_cleanup
    assert "guard.attempt != attempt || guard.token != token" in exact_cleanup
    assert "self.ledger_dir.remove(&file)?" in exact_cleanup
    assert pending.count("clear_admission_guard_exact(") >= 4
    release = section(pending, "pub(crate) fn release_to_store", "pub(crate) fn arm")
    assert "clear_admission_guard_exact(self.attempt, self.token)" in release
    resolver = section(pending, "fn resolve_admission_guard", "fn admission_guard_still_active")
    assert "self.clear_admission_guard_exact(attempt, guard.token)?" in resolver
    assert "AdmissionOwnership::StoreOwned" in resolver

    # Pre-claim endpoint drop remains conservative: it owns revocation and
    # removes active pins/pending records, never turns a staged receipt into a
    # normal success.
    drop_body = section(provisional, "impl Drop for ProvisionalEndpoint", "impl Drop for ProvisionalChannel")
    assert drop_body.find("let revoker = self.scope.revoke()") < drop_body.find("self.endpoint.close")
    assert drop_body.find("revoker.revoke()") < drop_body.find("self.endpoint.close")
    revocation = section(pending, "fn revoke_current", "fn reconcile_pairing")
    before_save = revocation.split("self.save(&ledger)?", 1)[0]
    assert "ledger.active_pins.retain(|pin| pin.peer != peer)" in before_save
    assert re.search(
        r"ledger\s*\.pending\s*\.retain\(\|entry\| entry\.record\.peer_fingerprint != peer\)",
        before_save,
    )
    assert "ledger.tombstones.extend(&removed)" in before_save


def main() -> None:
    sources = {
        "handshake": HANDSHAKE.read_text(),
        "provisional": PROVISIONAL.read_text(),
        "authority": AUTHORITY.read_text(),
        "pending": PENDING.read_text(),
    }
    validate(**sources)
    mutants = {
        "public-binding-getter": (
            "handshake",
            "impl HandshakeCompletePendingAuthority {",
            "impl HandshakeCompletePendingAuthority {\n    pub fn local_binding(&self) {}",
        ),
        "borrowed-seal": (
            "handshake",
            "pub(crate) async fn seal_for_promotion(\n        self,",
            "pub(crate) async fn seal_for_promotion(\n        &self,",
        ),
        "clone-sealed": (
            "handshake",
            "pub(crate) struct SealedPromotionEvidence",
            "#[derive(Clone)]\npub(crate) struct SealedPromotionEvidence",
        ),
        "drop-staging": (
            "authority",
            ".stage_sealed_admission(expected, commit.record(), commit.receipt())?",
            "/* no durable stage */",
        ),
        "drop-finalization": (
            "authority",
            ".finalize_staged_admission(staged_version, attempt, handoff)",
            ".commit_sealed_admission(staged_version, commit)",
        ),
        "drop-handoff-claim": (
            "pending",
            "let revoker = handoff.claim().map_err(|_| StoreError::Invalid)?;",
            "let revoker = handoff.release_for_test_only()?;",
        ),
        "permit-pin-inheritance": (
            "pending",
            "ledger\n                .active_pins\n                .iter()\n                .any(|pin| pin.peer == receipt.peer)",
            "false",
        ),
        "attempt-only-cleanup": (
            "pending",
            "guard.attempt != attempt || guard.token != token",
            "guard.attempt != attempt",
        ),
        "unlock-exact-cleanup": (
            "pending",
            "let _lock = self.ledger_dir.lock()?;\n            let file = admission_guard_filename(attempt);",
            "let file = admission_guard_filename(attempt);",
        ),
        "cleanup-without-token": (
            "pending",
            "clear_admission_guard_exact(self.attempt, self.token)",
            "clear_admission_guard_exact(self.attempt, [0; 32])",
        ),
        "drop-conservative-revocation": (
            "pending",
            "ledger.active_pins.retain(|pin| pin.peer != peer);",
            "ledger.active_pins.retain(|_| true);",
        ),
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
    print(f"PASS: staged admission contract and {len(mutants)} mutants rejected")


if __name__ == "__main__":
    main()
