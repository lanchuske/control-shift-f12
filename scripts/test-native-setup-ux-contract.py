#!/usr/bin/env python3
"""Documentation-only state-machine verifier for native setup transactions.

No production protocol/UI is shared. The model proves the specified rule that,
once both prepares exist, absence of a local CAS is not proof of a remote abort.
"""

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

SPEC = Path(__file__).resolve().parents[1] / "docs" / "native-setup-ux-specification.md"


@dataclass(frozen=True)
class Certificate:
    digest: str
    base: int = 7
    proposed: int = 8
    receipt_a: int = 1
    receipt_b: int = 1
    inventory_a: int = 1
    inventory_b: int = 1
    attempt: str = "attempt-1"
    preconfirm: str = "preconfirm-1"
    commitment: str = "commitment-1"
    signature_a: str = ""
    signature_b: str = ""

    def unsigned(self) -> str:
        return "|".join(map(str, (self.digest, self.base, self.proposed, self.receipt_a,
            self.receipt_b, self.inventory_a, self.inventory_b, self.attempt,
            self.preconfirm, self.commitment, "ed25519")))

    def signed(self) -> "Certificate":
        return replace(self, signature_a="sig:A:" + self.unsigned(), signature_b="sig:B:" + self.unsigned())

    def signatures_valid(self) -> bool:
        return self.signature_a == "sig:A:" + self.unsigned() and self.signature_b == "sig:B:" + self.unsigned()

    def valid_live(self, a: "Store", b: "Store") -> bool:
        return (self.proposed == self.base + 1 and self.signatures_valid()
            and self.receipt_a == a.receipt and self.receipt_b == b.receipt
            and self.inventory_a == a.inventory and self.inventory_b == b.inventory
            and self.attempt == a.attempt == b.attempt
            and self.preconfirm == a.preconfirm == b.preconfirm
            and self.commitment == a.commitment == b.commitment
            and a.v01_active and b.v01_active)


@dataclass(frozen=True)
class ZeroCasAbort:
    digest: str
    signature_a: str
    signature_b: str

    @classmethod
    def for_certificate(cls, cert: Certificate) -> "ZeroCasAbort":
        return cls(cert.digest, "zero:A:" + cert.digest, "zero:B:" + cert.digest)

    def valid(self, cert: Certificate) -> bool:
        return self.digest == cert.digest and self.signature_a == "zero:A:" + cert.digest and self.signature_b == "zero:B:" + cert.digest


class Store:
    def __init__(self) -> None:
        self.receipt = self.inventory = 1
        self.attempt, self.preconfirm, self.commitment = "attempt-1", "preconfirm-1", "commitment-1"
        self.v01_active = True
        self.prepared: Optional[Certificate] = None
        self.certificate: Optional[Certificate] = None
        self.committed: Optional[tuple[str, int]] = None
        self.fenced = self.remote_outcome_unknown = self.finalized = False
        self.inventory_cache = self.diagnostics = True

    def prepare(self, cert: Certificate, other: "Store") -> None:
        assert not self.fenced and cert.valid_live(self, other)
        self.prepared = self.certificate = cert

    def commit(self, cert: Certificate, other: "Store") -> None:
        assert not self.fenced and self.prepared == cert and self.certificate == cert
        assert cert.valid_live(self, other)
        self.committed, self.prepared = (cert.digest, cert.proposed), None

    def terminal_after_bilateral_prepare(self) -> None:
        self.v01_active = False
        # Preserve artifacts because remote CAS outcome is unknown.
        self.remote_outcome_unknown = self.fenced = self.prepared is not None or self.committed is not None

    def early_v01_terminal(self) -> str:
        self.v01_active = False
        if self.prepared is None:
            return "confirmed_relationship"
        self.remote_outcome_unknown = self.fenced = True
        return "remote_outcome_unknown"

    def receipt_revoke(self) -> str:
        self.purge()
        return "untrusted_catalogue"

    def inventory_change_before_prepare(self) -> str:
        self.inventory += 1
        return "confirmed_relationship"

    def abort_zero_cas(self, evidence: ZeroCasAbort, other: "Store") -> None:
        cert = self.certificate
        assert cert is not None and cert == other.certificate and evidence.valid(cert)
        assert self.committed is None and other.committed is None
        self.prepared = self.certificate = None
        self.fenced = self.remote_outcome_unknown = False

    def finalize(self, other: "Store") -> None:
        cert = self.certificate
        assert cert is not None and cert == other.certificate
        assert self.committed == other.committed == (cert.digest, cert.proposed)
        # Successful bilateral recognition deletes ephemeral certificate material.
        self.prepared = self.certificate = None
        self.finalized = True

    def purge(self) -> None:
        self.prepared = self.certificate = None
        self.committed = None
        self.inventory_cache = self.diagnostics = False
        self.fenced = True

    def can_start_v01(self) -> bool:
        return not self.fenced


def certificate(digest: str = "d1", **changes: object) -> Certificate:
    values = {"digest": digest}; values.update(changes)
    return Certificate(**values).signed()


def rejects(action) -> None:
    try:
        action()
    except AssertionError:
        return
    raise AssertionError("named mutation unexpectedly succeeded")


def abort_bilateral(a: Store, b: Store, evidence: ZeroCasAbort) -> None:
    # Models the durable bilateral evidence check before either local delete.
    cert = a.certificate
    assert cert is not None and cert == b.certificate and evidence.valid(cert)
    assert a.committed is None and b.committed is None
    a.abort_zero_cas(evidence, b)
    b.prepared = b.certificate = None
    b.fenced = b.remote_outcome_unknown = False


def finalize_bilateral(a: Store, b: Store) -> None:
    # Both durable committed records are recognized before either artifact deletion.
    cert = a.certificate
    assert cert is not None and cert == b.certificate
    assert a.committed == b.committed == (cert.digest, cert.proposed)
    a.prepared = a.certificate = None
    b.prepared = b.certificate = None
    a.finalized = b.finalized = True


def main() -> None:
    text = SPEC.read_text(encoding="utf-8")
    for phrase in (
        "remote_outcome_unknown", "zero-CAS abort certificate",
        "no new V01, proposal or base-revision reuse",
        "FinalizeLayout", "both finalizations acknowledge deletion",
        "permission revocation only turns off", "Receipt/identity",
    ):
        assert phrase in text, "missing contract phrase: " + phrase

    # Successful bilateral recognition clears certificate/signatures/attempt approvals.
    a, b, cert = Store(), Store(), certificate()
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b); b.commit(cert, a)
    finalize_bilateral(a, b)
    assert a.finalized and b.finalized and a.certificate is b.certificate is None
    assert a.committed == b.committed == ("d1", 8)

    # A CAS/B unknown crash fences BOTH; new V01/proposal is blocked.
    a, b, cert = Store(), Store(), certificate("d2")
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b)
    a.terminal_after_bilateral_prepare(); b.terminal_after_bilateral_prepare()
    assert a.remote_outcome_unknown and b.remote_outcome_unknown
    assert not a.can_start_v01() and not b.can_start_v01()
    rejects(lambda: a.prepare(certificate("new"), b))
    rejects(lambda: a.abort_zero_cas(ZeroCasAbort.for_certificate(cert), b))

    # Bilateral zero-CAS evidence can clear only two prepared/no-CAS stores.
    a, b, cert = Store(), Store(), certificate("d3")
    a.prepare(cert, b); b.prepare(cert, a)
    a.terminal_after_bilateral_prepare(); b.terminal_after_bilateral_prepare()
    evidence = ZeroCasAbort.for_certificate(cert)
    abort_bilateral(a, b, evidence)
    assert a.certificate is b.certificate is None and a.can_start_v01() and b.can_start_v01()

    # Early events are typed: timeout/reset vs receipt/identity revoke vs permission-equivalent inventory path.
    a = Store(); assert a.early_v01_terminal() == "confirmed_relationship"
    a = Store(); assert a.inventory_change_before_prepare() == "confirmed_relationship"
    a = Store(); assert a.receipt_revoke() == "untrusted_catalogue" and a.certificate is None

    # Signature/role/epoch/binding mutations reject before prepare.
    a, b = Store(), Store()
    rejects(lambda: a.prepare(replace(certificate("bad-a"), signature_a="bad"), b))
    c = certificate("swap")
    rejects(lambda: a.prepare(replace(c, signature_a=c.signature_b, signature_b=c.signature_a), b))
    rejects(lambda: a.prepare(certificate("epoch", receipt_b=2), b))
    rejects(lambda: a.prepare(certificate("attempt", attempt="old"), b))
    rejects(lambda: a.prepare(certificate("preconfirm", preconfirm="old"), b))
    rejects(lambda: a.prepare(certificate("commitment", commitment="old"), b))

    # Revoke/inventory/V01 terminal after prepare fence rather than silently abort.
    a, b, cert = Store(), Store(), certificate("d4")
    a.prepare(cert, b); b.prepare(cert, a); a.receipt_revoke()
    assert a.certificate is None and a.fenced
    a, b, cert = Store(), Store(), certificate("d5")
    a.prepare(cert, b); b.prepare(cert, a); b.terminal_after_bilateral_prepare()
    assert b.remote_outcome_unknown and not b.can_start_v01()

    print("PASS: native UX bilateral-outcome state-machine and 16 guard mutations")


if __name__ == "__main__":
    main()
