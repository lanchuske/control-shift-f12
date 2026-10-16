#!/usr/bin/env python3
"""Documentation-only state-machine verifier for native setup transactions.

No production protocol/UI is shared. The model proves the specified rule that,
once both prepares exist, absence of a local CAS is not proof of a remote abort.
"""

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
from typing import Optional

SPEC = Path(__file__).resolve().parents[1] / "docs" / "native-setup-ux-specification.md"
MUTATION_CHECKS = 0


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
    version: int
    commit_digest: str
    role_a: str
    role_b: str
    receipt_a: int
    receipt_b: int
    base: int
    proposed: int
    assertion_a: str
    assertion_b: str
    algorithm: str
    lock_state_a: str
    lock_version_a: int
    lock_state_b: str
    lock_version_b: int
    signature_a: str = ""
    signature_b: str = ""

    def unsigned(self) -> str:
        return "|".join(map(str, (
            self.version, self.commit_digest, self.role_a, self.role_b,
            self.receipt_a, self.receipt_b, self.base, self.proposed,
            self.assertion_a, self.assertion_b, self.algorithm, self.lock_state_a,
            self.lock_version_a, self.lock_state_b, self.lock_version_b)))

    def message(self) -> str:
        return "CSF12 layout zero-cas abort v1\\0" + self.unsigned()

    @classmethod
    def for_certificate(cls, cert: Certificate) -> "ZeroCasAbort":
        raw = cls(1, cert.digest, "leaf:A", "leaf:B", cert.receipt_a,
                  cert.receipt_b, cert.base, cert.proposed, "not_committed",
                  "not_committed", "ed25519", "ABORT_LOCKED", 2,
                  "ABORT_LOCKED", 2)
        return replace(raw, signature_a="zero:A:" + raw.message(),
                       signature_b="zero:B:" + raw.message())

    def valid(self, cert: Certificate) -> bool:
        return (
            self.version == 1 and self.commit_digest == cert.digest
            and self.role_a == "leaf:A" and self.role_b == "leaf:B"
            and self.receipt_a == cert.receipt_a and self.receipt_b == cert.receipt_b
            and self.base == cert.base and self.proposed == cert.proposed == cert.base + 1
            and self.assertion_a == self.assertion_b == "not_committed"
            and self.algorithm == "ed25519"
            and self.lock_state_a == self.lock_state_b == "ABORT_LOCKED"
            and self.lock_version_a == self.lock_version_b == 2
            and self.signature_a == "zero:A:" + self.message()
            and self.signature_b == "zero:B:" + self.message()
        )

    def digest(self) -> str:
        return hashlib.sha256((self.unsigned() + self.signature_a + self.signature_b).encode()).hexdigest()


@dataclass(frozen=True)
class AbortAck:
    version: int
    zero_digest: str
    commit_digest: str
    sender_role: str
    receipt_a: int
    receipt_b: int
    lock_a: int
    lock_b: int
    signature: str = ""

    def unsigned(self) -> str:
        return "|".join(map(str, (self.version, self.zero_digest, self.commit_digest,
                                    self.sender_role, "leaf:A", "leaf:B", self.receipt_a,
                                    self.receipt_b, self.lock_a, self.lock_b, "ed25519")))

    def message(self) -> str:
        return "CSF12 layout zero-cas abort ack v1\\0" + self.unsigned()

    @classmethod
    def for_abort(cls, abort: ZeroCasAbort, role: str) -> "AbortAck":
        raw = cls(1, abort.digest(), abort.commit_digest, role, abort.receipt_a,
                  abort.receipt_b, abort.lock_version_a, abort.lock_version_b)
        return replace(raw, signature="ack:" + role + ":" + raw.message())

    def valid(self, abort: ZeroCasAbort, expected_role: str) -> bool:
        return (self.version == 1 and self.zero_digest == abort.digest()
                and self.commit_digest == abort.commit_digest and self.sender_role == expected_role
                and self.receipt_a == abort.receipt_a and self.receipt_b == abort.receipt_b
                and self.lock_a == abort.lock_version_a and self.lock_b == abort.lock_version_b
                and self.signature == "ack:" + expected_role + ":" + self.message())


class Store:
    def __init__(self) -> None:
        self.receipt = self.inventory = 1
        self.attempt, self.preconfirm, self.commitment = "attempt-1", "preconfirm-1", "commitment-1"
        self.v01_active = True
        self.prepared: Optional[Certificate] = None
        self.certificate: Optional[Certificate] = None
        self.committed: Optional[tuple[str, int]] = None
        self.transaction_state: Optional[str] = None
        self.transaction_state_version = 0
        self.abort_ack: Optional[AbortAck] = None
        self.fenced = self.remote_outcome_unknown = self.finalized = False
        self.inventory_cache = self.diagnostics = True

    def prepare(self, cert: Certificate, other: "Store") -> None:
        assert not self.fenced and cert.valid_live(self, other)
        assert self.transaction_state is None
        self.prepared = self.certificate = cert
        self.transaction_state, self.transaction_state_version = "PREPARED", 1

    def commit(self, cert: Certificate, other: "Store") -> None:
        assert not self.fenced and self.prepared == cert and self.certificate == cert
        assert self.transaction_state == "PREPARED" and self.transaction_state_version == 1
        assert cert.valid_live(self, other)
        self.committed, self.prepared = (cert.digest, cert.proposed), None
        self.transaction_state, self.transaction_state_version = "COMMITTED", 2

    def abort_prepare(self, cert: Certificate) -> None:
        assert self.prepared == cert and self.certificate == cert
        assert self.committed is None and self.transaction_state == "PREPARED"
        assert self.transaction_state_version == 1
        self.transaction_state, self.transaction_state_version = "ABORT_LOCKED", 2

    def terminal_after_bilateral_prepare(self) -> None:
        self.v01_active = False
        # Preserve artifacts because remote CAS outcome is unknown.
        self.remote_outcome_unknown = self.fenced = self.prepared is not None or self.committed is not None

    def preprepare_v01_terminal(self, event: str) -> str:
        assert event in ("timeout", "reset", "disappear")
        self.v01_active = False
        if self.prepared is None:
            return "confirmed_relationship"
        self.remote_outcome_unknown = self.fenced = True
        return "remote_outcome_unknown"

    def permission_revoke_preprepare(self) -> str:
        self.v01_active = False
        assert self.prepared is None
        return "confirmed_relationship"

    def receipt_revoke(self) -> str:
        self.purge()
        return "untrusted_catalogue"

    def inventory_change_before_prepare(self) -> str:
        self.inventory += 1
        return "confirmed_relationship"

    @staticmethod
    def proposal_event(state: str, event: str) -> str:
        assert state in ("PROPOSAL_LOCAL", "PROPOSAL_REMOTE_REVIEW")
        assert event in ("permission_revoke", "receipt_revoke", "timeout", "reset", "disappear")
        if event == "receipt_revoke":
            return "untrusted_catalogue"
        return "confirmed_relationship"

    def abort_zero_cas(self, evidence: ZeroCasAbort, other: "Store") -> None:
        cert = self.certificate
        assert cert is not None and cert == other.certificate and evidence.valid(cert)
        assert self.committed is None and other.committed is None
        assert self.transaction_state == other.transaction_state == "ABORT_LOCKED"
        self.transaction_state, self.transaction_state_version = "ABORTED", 3
        self.abort_ack = None
        self.prepared = self.certificate = None
        self.fenced = self.remote_outcome_unknown = False

    def finalize(self, other: "Store") -> None:
        cert = self.certificate
        assert cert is not None and cert == other.certificate
        assert self.committed == other.committed == (cert.digest, cert.proposed)
        # Successful bilateral recognition deletes ephemeral certificate material.
        self.prepared = self.certificate = None
        self.finalized = True

    def asymmetric_finalization(self) -> None:
        # A local delete without the remote durable acknowledgement is not ready.
        self.remote_outcome_unknown = self.fenced = True
        self.finalized = False

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
    global MUTATION_CHECKS
    try:
        action()
    except AssertionError:
        MUTATION_CHECKS += 1
        return
    raise AssertionError("named mutation unexpectedly succeeded")


def record_abort_ack(local: Store, remote: Store, evidence: ZeroCasAbort, role: str) -> None:
    """Persist one ack; this deliberately cannot delete any local record."""
    cert = local.certificate
    assert cert is not None and cert == remote.certificate and evidence.valid(cert)
    assert local.committed is None and remote.committed is None
    assert local.transaction_state == remote.transaction_state == "ABORT_LOCKED"
    assert local.transaction_state_version == remote.transaction_state_version == 2
    assert role in ("A", "B") and local.abort_ack is None
    local.abort_ack = AbortAck.for_abort(evidence, role)


def final_delete_after_bilateral_abort_acks(a: Store, b: Store, evidence: ZeroCasAbort) -> None:
    """Terminal delete requires both independently persisted acknowledgements."""
    cert = a.certificate
    assert cert is not None and cert == b.certificate and evidence.valid(cert)
    assert a.committed is None and b.committed is None
    assert a.transaction_state == b.transaction_state == "ABORT_LOCKED"
    assert a.transaction_state_version == b.transaction_state_version == 2
    assert a.abort_ack is not None and b.abort_ack is not None
    assert a.abort_ack.valid(evidence, "A") and b.abort_ack.valid(evidence, "B")
    a.transaction_state, a.transaction_state_version = "ABORTED", 3
    b.transaction_state, b.transaction_state_version = "ABORTED", 3
    a.prepared = a.certificate = None
    b.prepared = b.certificate = None
    a.fenced = a.remote_outcome_unknown = False
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
        "CSF12 layout zero-cas abort v1\\0", "abort_certificate_version",
        "asymmetric\nfinalization", "not_committed",
        "AbortPrepare", "ABORT_LOCKED", "LAYOUT_ABORT_LOCKED", "transaction_state_version",
        "PROPOSAL_LOCAL / PROPOSAL_REMOTE_REVIEW",
        "zero-cas-abort-ack-v1", "zero_cas_certificate_digest",
        "Both persisted acknowledgements are required",
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
    a.abort_prepare(cert); b.abort_prepare(cert)
    a.terminal_after_bilateral_prepare(); b.terminal_after_bilateral_prepare()
    evidence = ZeroCasAbort.for_certificate(cert)
    record_abort_ack(a, b, evidence, "A")
    rejects(lambda: final_delete_after_bilateral_abort_acks(a, b, evidence))
    record_abort_ack(b, a, evidence, "B")
    final_delete_after_bilateral_abort_acks(a, b, evidence)
    assert a.certificate is b.certificate is None and a.can_start_v01() and b.can_start_v01()
    assert a.transaction_state == b.transaction_state == "ABORTED"

    # Early events are typed: permission vs receipt/identity revoke vs V01 terminal.
    for event in ("timeout", "reset", "disappear"):
        a = Store(); assert a.preprepare_v01_terminal(event) == "confirmed_relationship"
    rejects(lambda: Store().preprepare_v01_terminal("receipt_revoke"))
    a = Store(); assert a.permission_revoke_preprepare() == "confirmed_relationship" and a.receipt == 1
    a = Store(); assert a.inventory_change_before_prepare() == "confirmed_relationship"
    a = Store(); assert a.receipt_revoke() == "untrusted_catalogue" and a.certificate is None
    for proposal in ("PROPOSAL_LOCAL", "PROPOSAL_REMOTE_REVIEW"):
        assert Store.proposal_event(proposal, "permission_revoke") == "confirmed_relationship"
        assert Store.proposal_event(proposal, "receipt_revoke") == "untrusted_catalogue"
        for event in ("timeout", "reset", "disappear"):
            assert Store.proposal_event(proposal, event) == "confirmed_relationship"

    # Signature/role/epoch/binding mutations reject before prepare.
    a, b = Store(), Store()
    rejects(lambda: a.prepare(replace(certificate("bad-a"), signature_a="bad"), b))
    c = certificate("swap")
    rejects(lambda: a.prepare(replace(c, signature_a=c.signature_b, signature_b=c.signature_a), b))
    rejects(lambda: a.prepare(certificate("epoch", receipt_b=2), b))
    rejects(lambda: a.prepare(certificate("attempt", attempt="old"), b))
    rejects(lambda: a.prepare(certificate("preconfirm", preconfirm="old"), b))
    rejects(lambda: a.prepare(certificate("commitment", commitment="old"), b))

    # Actual zero-CAS evidence fields all authenticate the same canonical bytes.
    cert = certificate("zero")
    evidence = ZeroCasAbort.for_certificate(cert)
    rejects(lambda: replace(evidence, commit_digest="other").valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, role_a="leaf:B", role_b="leaf:A").valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, receipt_a=2).valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, receipt_b=2).valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, base=6).valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, proposed=9).valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, assertion_a="committed").valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, lock_state_a="PREPARED").valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, lock_version_b=3).valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, signature_a="bad").valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, signature_b="bad").valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, version=2).valid(cert) or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(evidence, algorithm="rsa").valid(cert) or (_ for _ in ()).throw(AssertionError()))

    # Ack bytes bind the full zero-CAS object, role, locks and signature.
    ack = AbortAck.for_abort(evidence, "A")
    assert ack.valid(evidence, "A")
    rejects(lambda: replace(ack, zero_digest="replay").valid(evidence, "A") or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(ack, sender_role="B").valid(evidence, "A") or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(ack, lock_b=3).valid(evidence, "A") or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(ack, receipt_a=2).valid(evidence, "A") or (_ for _ in ()).throw(AssertionError()))
    rejects(lambda: replace(ack, signature="bad").valid(evidence, "A") or (_ for _ in ()).throw(AssertionError()))

    # Independent-store interleavings: whichever versioned transition wins blocks the other.
    a, b, cert = Store(), Store(), certificate("race-a")
    a.prepare(cert, b); b.prepare(cert, a); a.abort_prepare(cert)
    rejects(lambda: a.commit(cert, b))
    assert a.transaction_state == "ABORT_LOCKED" and a.transaction_state_version == 2
    a, b, cert = Store(), Store(), certificate("race-b")
    a.prepare(cert, b); b.prepare(cert, a); b.commit(cert, a)
    rejects(lambda: b.abort_prepare(cert))
    a.abort_prepare(cert)
    rejects(lambda: record_abort_ack(a, b, ZeroCasAbort.for_certificate(cert), "A"))
    assert a.transaction_state == "ABORT_LOCKED" and b.transaction_state == "COMMITTED"

    # Zero-CAS cannot be started from prepared/committed/unknown records lacking exact locks.
    a, b, cert = Store(), Store(), certificate("no-lock-prepared")
    a.prepare(cert, b); b.prepare(cert, a)
    rejects(lambda: record_abort_ack(a, b, ZeroCasAbort.for_certificate(cert), "A"))
    a, b, cert = Store(), Store(), certificate("no-lock-committed")
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b)
    rejects(lambda: record_abort_ack(a, b, ZeroCasAbort.for_certificate(cert), "A"))
    a, b, cert = Store(), Store(), certificate("no-lock-unknown")
    a.prepare(cert, b); b.prepare(cert, a); a.terminal_after_bilateral_prepare(); b.terminal_after_bilateral_prepare()
    rejects(lambda: record_abort_ack(a, b, ZeroCasAbort.for_certificate(cert), "A"))

    # Revoke/inventory/V01 terminal after prepare fence rather than silently abort.
    a, b, cert = Store(), Store(), certificate("d4")
    a.prepare(cert, b); b.prepare(cert, a); a.receipt_revoke()
    assert a.certificate is None and a.fenced
    for event in ("timeout", "reset", "disappear"):
        a, b, cert = Store(), Store(), certificate("d5-" + event)
        a.prepare(cert, b); b.prepare(cert, a); b.terminal_after_bilateral_prepare()
        assert b.remote_outcome_unknown and not b.can_start_v01()

    # A crash/ack loss during finalization is fenced, never a local ready signal.
    a, b, cert = Store(), Store(), certificate("d6")
    a.prepare(cert, b); b.prepare(cert, a); a.commit(cert, b); b.commit(cert, a)
    a.asymmetric_finalization(); b.asymmetric_finalization()
    assert not a.finalized and not b.finalized and not a.can_start_v01() and not b.can_start_v01()

    # Tombstones reject a delayed CommitLayout after both abort acks and deletion.
    a, b, cert = Store(), Store(), certificate("delayed")
    a.prepare(cert, b); b.prepare(cert, a); a.abort_prepare(cert); b.abort_prepare(cert)
    evidence = ZeroCasAbort.for_certificate(cert)
    record_abort_ack(a, b, evidence, "A"); record_abort_ack(b, a, evidence, "B")
    final_delete_after_bilateral_abort_acks(a, b, evidence)
    rejects(lambda: a.commit(cert, b))

    print("PASS: native UX bilateral-outcome state-machine and %d executed guard mutations" % MUTATION_CHECKS)


if __name__ == "__main__":
    main()
