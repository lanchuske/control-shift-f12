#!/usr/bin/env python3
"""Static and model-only verifier for the native setup UX specification.

This has no production dependencies and does not implement a wire/UI.  It
checks the documentation's required security contracts and exercises the
documented durable prepare/commit crash states so future work cannot claim a
fictional cross-host atomic write.
"""

from pathlib import Path


SPEC = Path(__file__).resolve().parents[1] / "docs" / "native-setup-ux-specification.md"


class LayoutStore:
    def __init__(self) -> None:
        self.committed: tuple[str, int] | None = None
        self.prepared: tuple[str, int, int] | None = None
        self.inventory_cache = True
        self.diagnostics = True

    def prepare(self, digest: str, base: int, proposed: int) -> None:
        assert proposed == base + 1
        assert self.prepared in (None, (digest, base, proposed))
        assert self.committed is None or self.committed[1] == base
        self.prepared = (digest, base, proposed)

    def commit(self, digest: str, proposed: int) -> None:
        assert self.prepared is not None
        assert self.prepared[0] == digest and self.prepared[2] == proposed
        self.committed = (digest, proposed)
        self.prepared = None

    def purge(self) -> None:
        self.prepared = None
        self.committed = None
        self.inventory_cache = False
        self.diagnostics = False


def require(text: str, phrase: str) -> None:
    assert phrase in text, f"missing required UX contract phrase: {phrase!r}"


def main() -> None:
    text = SPEC.read_text(encoding="utf-8")
    for phrase in (
        "BOOTSTRAP_SAS_PENDING",
        "BOOTSTRAP_RECEIPT_PREPARED",
        "at most 30 seconds from V01 connection selection",
        "control-shift-f12-layout-proposal-v1",
        "Durable layout transaction and crash recovery",
        "LAYOUT_RECOVERY_PENDING",
        "Forget this computer and its layout",
        "Crash after prepare A/B or between commit write 1 and write 2",
    ):
        require(text, phrase)

    # Positive prepare/commit: exact digest/revision commits on each store.
    a, b = LayoutStore(), LayoutStore()
    a.prepare("d1", 7, 8)
    b.prepare("d1", 7, 8)
    a.commit("d1", 8)
    b.commit("d1", 8)
    assert a.committed == b.committed == ("d1", 8)

    # Mutation: crash between writes is a recovery-pending state, never success.
    a, b = LayoutStore(), LayoutStore()
    a.prepare("d2", 8, 9)
    b.prepare("d2", 8, 9)
    a.commit("d2", 9)
    assert a.committed == ("d2", 9) and b.committed is None
    assert b.prepared == ("d2", 8, 9)

    # Mutations: mismatched proposed revision or digest cannot commit.
    for digest, revision in (("d3", 10), ("wrong", 9)):
        trial = LayoutStore()
        trial.prepare("d3", 8, 9)
        try:
            trial.commit(digest, revision)
        except AssertionError:
            pass
        else:
            raise AssertionError("mutated commit unexpectedly succeeded")

    # Mutation: revocation/unpair purge removes correlatable local records.
    a = LayoutStore()
    a.prepare("d4", 9, 10)
    a.purge()
    assert a.prepared is None and a.committed is None
    assert not a.inventory_cache and not a.diagnostics

    print("PASS: native setup UX contract, prepare/commit crash and purge mutations")


if __name__ == "__main__":
    main()
