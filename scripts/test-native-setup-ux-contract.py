#!/usr/bin/env python3
"""Static/model verifier for the native setup certificate contract.

This is not cryptographic or shipping code. It models the documented guards and
mutation stages, including the rule that V01 is terminal after restart and a
unilateral CAS therefore remains fenced.
"""

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional


SPEC = Path(__file__).resolve().parents[1] / "docs" / "native-setup-ux-specification.md"


@dataclass(frozen=True)
class Certificate:
    digest: str
    base: int
    proposed: int
    receipt_a: int
    receipt_b: int
    inventory_a: int
    inventory_b: int
    attempt: str = "attempt-1"
    preconfirm: str = "preconfirm-1"
    commitment: str = "commitment-1"
    signature_a: str = ""
    signature_b: str = ""

    def unsigned(self) -> str:
        return "|".join(map(str, (
            self.digest, self.base, self.proposed, self.receipt_a, self.receipt_b,
            self.inventory_a, self.inventory_b, self.attempt, self.preconfirm,
            self.commitment, "ed25519",
        )))

    def signed(self) -> "Certificate":
        return replace(self, signature_a="sig:A:" + self.unsigned(), signature_b="sig:B:" + self.unsigned())

    def valid(self, a: "Store", b: "Store") -> bool:
        return (
            self.proposed == self.base + 1
            and self.receipt_a == a.receipt and self.receipt_b == b.receipt
            and self.inventory_a == a.inventory and self.inventory_b == b.inventory
            and a.v01_active and b.v01_active
            and self.attempt == a.attempt and self.attempt == b.attempt
            and self.preconfirm == a.preconfirm and self.preconfirm == b.preconfirm
            and self.commitment == a.commitment and self.commitment == b.commitment
            and self.signature_a == "sig:A:" + self.unsigned()
            and self.signature_b == "sig:B:" + self.unsigned()
        )


class Store:
    def __init__(self, receipt: int = 1, inventory: int = 1) -> None:
        self.receipt, self.inventory = receipt, inventory
        self.v01_active = True
        self.attempt = "attempt-1"
        self.preconfirm = "preconfirm-1"
        self.commitment = "commitment-1"
        self.prepared: Optional[Certificate] = None
        self.certificate: Optional[Certificate] = None
        self.committed: Optional[tuple[str, int]] = None
        self.fenced = False
        self.inventory_cache = True
        self.diagnostics = True

    def prepare(self, cert: Certificate, other: "Store") -> None:
        assert cert.valid(self, other)
        assert self.committed is None or self.committed[1] == cert.base
        assert self.prepared in (None, cert)
        self.certificate = self.prepared = cert

    def commit(self, cert: Certificate, other: "Store") -> None:
        # Atomic local guard immediately before the local CAS.
        assert self.prepared == cert and self.certificate == cert and not self.fenced
        assert cert.valid(self, other)
        self.committed = (cert.digest, cert.proposed)
        self.prepared = None

    def v01_terminal(self) -> None:
        self.v01_active = False
        self.prepared = None
        self.certificate = None
        self.fenced = self.committed is not None

    def receipt_revoked(self) -> None:
        self.receipt += 1
        self.prepared = self.certificate = None
        self.fenced = self.committed is not None

    def inventory_changed(self) -> None:
        self.inventory += 1
        self.prepared = self.certificate = None
        self.fenced = self.committed is not None

    def recover(self, cert: Optional[Certificate], other: "Store") -> str:
        # Restart makes V01 terminal. No old certificate may finish a CAS.
        if self.committed is not None:
            self.fenced = True
            return "fenced"
        if cert is None or self.certificate != cert or not cert.valid(self, other):
            self.prepared = self.certificate = None
            return "abort"
        raise AssertionError("recovery must not complete a live V01 certificate")

    def purge(self) -> None:
        self.prepared = self.certificate = None
        self.committed = None
        self.inventory_cache = self.diagnostics = False
        self.fenced = True


def require(text: str, phrase: str) -> None:
    assert phrase in text, f"missing required UX contract phrase: {phrase!r}"


def rejects(action) -> None:
    try:
        action()
    except AssertionError:
        return
    raise AssertionError("named mutation unexpectedly succeeded")


def certificate(digest: str = "d1", **changes: object) -> Certificate:
    values = dict(digest=digest, base=7, proposed=8, receipt_a=1, receipt_b=1, inventory_a=1, inventory_b=1)
    values.update(changes)
    return Certificate(**values).signed()


def main() -> None:
    text = SPEC.read_text(encoding="utf-8")
    for phrase in (
        "control-shift-f12-layout-commit-certificate-v1",
        "There is deliberately **no cross-host `expires_at_monotonic_ms` field**",
        "CSF12 layout commit certificate v1\\0",
        "approval_a_signature", "approval_b_signature",
        "revocation is inherently TOCTOU", "PURGE_TO_UNTRUSTED",
        "new explicitly specified protocol", "per-peer local deadlines",
    ):
        require(text, phrase)

    # Positive live V01 transaction: signatures/certificate precede both CAS.
    a, b, cert = Store(), Store(), certificate()
    a.prepare(cert, b); b.prepare(cert, a)
    a.commit(cert, b); b.commit(cert, a)
    assert a.committed == b.committed == ("d1", 8)

    # Crash/restart after unilateral CAS: V01 terminal; never finish old cert.
    a, b, cert = Store(), Store(), certificate("d2")
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b)
    a.v01_terminal(); b.v01_terminal()
    assert a.recover(cert, b) == "fenced"
    assert b.recover(cert, a) == "abort"

    # Explicit post-CAS remote revoke is fenced; it can race the final guard.
    a, b, cert = Store(), Store(), certificate("d3")
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b); b.receipt_revoked()
    assert a.recover(cert, b) == "fenced"

    # Guard mutations: signatures, role swap, epoch, V01 bindings, terminal and inventory.
    a, b = Store(), Store()
    rejects(lambda: a.prepare(replace(certificate("sig-a"), signature_a="bad"), b))
    rejects(lambda: a.prepare(replace(certificate("sig-b"), signature_b="bad"), b))
    swapped = certificate("swap")
    rejects(lambda: a.prepare(replace(swapped, signature_a=swapped.signature_b, signature_b=swapped.signature_a), b))
    rejects(lambda: a.prepare(certificate("epoch", receipt_b=2), b))
    rejects(lambda: a.prepare(certificate("attempt", attempt="old-attempt"), b))
    rejects(lambda: a.prepare(certificate("preconfirm", preconfirm="old-preconfirm"), b))
    rejects(lambda: a.prepare(certificate("commitment", commitment="old-commitment"), b))
    a, b, cert = Store(), Store(), certificate("d4")
    a.prepare(cert, b); b.prepare(cert, a); b.inventory_changed()
    rejects(lambda: a.commit(cert, b))
    a, b, cert = Store(), Store(), certificate("d5")
    a.prepare(cert, b); b.prepare(cert, a); b.v01_terminal()
    rejects(lambda: a.commit(cert, b))

    # Pre-CAS terminal abort/purge vs post-CAS fence.
    a, b, cert = Store(), Store(), certificate("d6")
    a.prepare(cert, b); b.prepare(cert, a); a.v01_terminal()
    assert a.recover(cert, b) == "abort"
    a, b, cert = Store(), Store(), certificate("d7")
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b); a.inventory_changed()
    assert a.recover(cert, b) == "fenced"

    # Unpair/revoke purge makes correlatable records unrecoverable.
    a = Store(); a.prepare(certificate("d8"), Store()); a.purge()
    assert a.prepared is None and a.certificate is None and a.committed is None
    assert not a.inventory_cache and not a.diagnostics and a.fenced

    print("PASS: native UX certificate terminal-V01 state-machine and 14 guard mutations")


if __name__ == "__main__":
    main()
