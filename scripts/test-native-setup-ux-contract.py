#!/usr/bin/env python3
"""Static/model verifier for the native setup UX transaction contract.

It is documentation-only: no shipping protocol, persistence or UI code is
shared. The state machine proves that a prepared record cannot become commit
authority and a one-sided CAS remains fenced without its exact certificate.
"""

from dataclasses import dataclass
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
    v01_active: bool = True
    expires: int = 30
    approvals: int = 2

    def valid(self, now: int, receipt_a: int, receipt_b: int, inventory_a: int, inventory_b: int) -> bool:
        return (
            self.proposed == self.base + 1
            and self.receipt_a == receipt_a and self.receipt_b == receipt_b
            and self.inventory_a == inventory_a and self.inventory_b == inventory_b
            and self.v01_active and now < self.expires and self.approvals == 2
        )


class Store:
    def __init__(self, receipt: int = 1, inventory: int = 1) -> None:
        self.receipt = receipt
        self.inventory = inventory
        self.prepared: Optional[Certificate] = None
        self.certificate: Optional[Certificate] = None
        self.committed: Optional[tuple[str, int]] = None
        self.fenced = False
        self.inventory_cache = True
        self.diagnostics = True

    def prepare(self, cert: Certificate, now: int, other: "Store") -> None:
        assert cert.valid(now, self.receipt, other.receipt, self.inventory, other.inventory)
        assert self.committed is None or self.committed[1] == cert.base
        assert self.prepared in (None, cert)
        self.certificate = cert
        self.prepared = cert

    def commit(self, cert: Certificate, now: int, other: "Store") -> None:
        # Atomic local guard immediately before the local CAS.
        assert self.prepared == cert and self.certificate == cert and not self.fenced
        assert cert.valid(now, self.receipt, other.receipt, self.inventory, other.inventory)
        self.committed = (cert.digest, cert.proposed)
        self.prepared = None

    def revoke_or_change(self) -> None:
        self.receipt += 1
        self.prepared = None
        self.certificate = None
        self.fenced = self.committed is not None

    def inventory_changed(self) -> None:
        self.inventory += 1
        self.prepared = None
        self.certificate = None
        self.fenced = self.committed is not None

    def recover(self, cert: Optional[Certificate], now: int, other: "Store") -> str:
        # Prepared data alone can never supply certificate or approval evidence.
        if cert is None or self.certificate != cert or not cert.valid(
            now, self.receipt, other.receipt, self.inventory, other.inventory
        ):
            self.fenced = self.committed is not None
            return "fenced" if self.fenced else "abort"
        if self.committed is not None and self.committed != (cert.digest, cert.proposed):
            self.fenced = True
            return "fenced"
        if other.committed is not None and other.committed != (cert.digest, cert.proposed):
            self.fenced = True
            return "fenced"
        return "finish"

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
    return Certificate(**values)


def main() -> None:
    text = SPEC.read_text(encoding="utf-8")
    for phrase in (
        "BOOTSTRAP_SAS_PENDING", "BOOTSTRAP_RECEIPT_PREPARED",
        "at most 30 seconds from V01 connection selection",
        "control-shift-f12-layout-proposal-v1",
        "control-shift-f12-layout-commit-certificate-v1",
        "No `CommitLayout` CAS", "LAYOUT_RECOVERY_PENDING",
        "Forget this computer and its layout", "After any unilateral CAS",
    ):
        require(text, phrase)

    # Happy transaction: same durable certificate precedes both CAS operations.
    a, b, cert = Store(), Store(), certificate()
    a.prepare(cert, 1, b); b.prepare(cert, 1, a)
    a.commit(cert, 2, b); b.commit(cert, 2, a)
    assert a.committed == b.committed == ("d1", 8)

    # Crash/restart between writes: exact certificate can finish the other side.
    a, b, cert = Store(), Store(), certificate("d2")
    a.prepare(cert, 1, b); b.prepare(cert, 1, a); a.commit(cert, 2, b)
    assert a.committed == ("d2", 8) and b.committed is None
    assert a.recover(cert, 3, b) == "finish"
    b.commit(cert, 3, a)
    assert b.committed == ("d2", 8)

    # Lost certificate after unilateral CAS is fenced, never inferred/aborted.
    a, b, cert = Store(), Store(), certificate("d3")
    a.prepare(cert, 1, b); b.prepare(cert, 1, a); a.commit(cert, 2, b)
    a.certificate = None
    assert a.recover(None, 3, b) == "fenced"

    # Real named guard mutations at prepare, CAS and recovery stages.
    rejects(lambda: Store().prepare(certificate("bad-revision", proposed=9), 1, Store()))
    a, b = Store(), Store(); rejects(lambda: a.prepare(certificate("expired", expires=2), 2, b))
    a, b, cert = Store(), Store(), certificate("d4")
    a.prepare(cert, 1, b); b.prepare(cert, 1, a); b.inventory_changed()
    rejects(lambda: a.commit(cert, 2, b))
    a, b, cert = Store(), Store(), certificate("d5")
    a.prepare(cert, 1, b); b.prepare(cert, 1, a); b.revoke_or_change()
    rejects(lambda: a.commit(cert, 2, b))
    a, b = Store(), Store(); rejects(lambda: a.prepare(certificate("d6", approvals=1), 1, b))
    a, b = Store(), Store(); rejects(lambda: a.prepare(certificate("d7", v01_active=False), 1, b))

    # Pre-commit missing certificate aborts; post-commit missing certificate fences.
    a, b, cert = Store(), Store(), certificate("d8")
    a.prepare(cert, 1, b); b.prepare(cert, 1, a)
    assert a.recover(None, 2, b) == "abort"
    a, b, cert = Store(), Store(), certificate("d9")
    a.prepare(cert, 1, b); b.prepare(cert, 1, a); a.commit(cert, 2, b)
    assert a.recover(None, 3, b) == "fenced"

    # Revoke/unpair purges correlatable local state rather than resurrecting it.
    a = Store(); a.prepare(certificate("d10"), 1, Store()); a.purge()
    assert a.prepared is None and a.certificate is None and a.committed is None
    assert not a.inventory_cache and not a.diagnostics and a.fenced

    print("PASS: native UX certificate state-machine and 10 guard mutations")


if __name__ == "__main__":
    main()
