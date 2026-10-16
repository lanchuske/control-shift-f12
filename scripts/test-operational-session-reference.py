#!/usr/bin/env python3
"""Independent static verifier for the frozen operational-session V01 bytes.

This is test-only. It deliberately shares no shipping code with a future parser
and proves fixture consistency plus every named mutation listed below.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "operational-session-interoperability.md"
FIXTURE = ROOT / "crates/transport/tests/fixtures/pairing-v2/operational-session-v01.json"
MAGIC = b"CSF12S1\x00"
VERSION = 1
PAIRING_RECEIPT_VERSION = 2
ALPN = "csf12-operational/1"
EXPORTER_LABEL = "EXPORTER-ControlShiftF12-OperationalSession-v1"
LIMIT = 4096
HEADER = 20
SCHEDULE = ((1, 1), (2, 2), (3, 1), (4, 2), (5, 1), (5, 2))
KINDS = (
    "operational-session-preflight-open-v1",
    "operational-session-preflight-accept-v1",
    "operational-session-open-v1",
    "operational-session-accept-v1",
    "operational-session-confirm-v1",
    "operational-session-confirm-v1",
)


def canonical(kind: str, fields: list[tuple[int, int, bytes]]) -> bytes:
    name = kind.encode("ascii")
    assert len(name) <= 255
    out = bytearray(b"CSF12E01" + bytes([len(name)]) + name + struct.pack(">H", len(fields)))
    previous = 0
    for tag, value_type, value in fields:
        assert tag > previous and value_type in (1, 2, 3)
        assert value_type != 1 or len(value) == 8
        out.extend(struct.pack(">HBI", tag, value_type, len(value)))
        out.extend(value)
        previous = tag
    return bytes(out)


def decode_canonical(kind: str, data: bytes) -> dict[int, tuple[int, bytes]]:
    assert data.startswith(b"CSF12E01")
    offset = 8
    length = data[offset]
    offset += 1
    assert data[offset : offset + length] == kind.encode("ascii")
    offset += length
    count = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    out: dict[int, tuple[int, bytes]] = {}
    previous = 0
    for _ in range(count):
        assert offset + 7 <= len(data)
        tag, value_type, item_length = struct.unpack_from(">HBI", data, offset)
        offset += 7
        assert tag > previous and value_type in (1, 2, 3)
        assert offset + item_length <= len(data)
        value = data[offset : offset + item_length]
        offset += item_length
        assert tag not in out and (value_type != 1 or item_length == 8)
        out[tag] = (value_type, value)
        previous = tag
    assert offset == len(data)
    return out


def frame(message_type: int, direction: int, sequence: int, payload: bytes) -> bytes:
    assert message_type in (1, 2, 3, 4, 5)
    assert direction in (1, 2) and 0 < len(payload) <= LIMIT
    return MAGIC + struct.pack(">HBBII", VERSION, message_type, direction, sequence, len(payload)) + payload


def decode_frame(data: bytes) -> tuple[int, int, int, bytes]:
    assert len(data) >= HEADER and data[:8] == MAGIC
    version, message_type, direction, sequence, length = struct.unpack_from(">HBBII", data, 8)
    assert version == VERSION and message_type in (1, 2, 3, 4, 5) and direction in (1, 2)
    assert 0 < length <= LIMIT and len(data) == HEADER + length
    return message_type, direction, sequence, data[HEADER:]


def hx(value: str) -> bytes:
    result = bytes.fromhex(value)
    assert value == result.hex()
    return result


def authority_view(fields: dict[str, str | int]) -> bytes:
    return canonical(
        "operational-authority-view-v1",
        [
            (1, 2, hx(str(fields["self_fingerprint_sha256_hex"]))),
            (2, 2, hx(str(fields["peer_fingerprint_sha256_hex"]))),
            (3, 3, str(fields["suite"]).encode("ascii")),
            (4, 1, struct.pack(">Q", int(fields["pairing_receipt_protocol_version"]))),
            (5, 1, struct.pack(">Q", int(fields["policy_revision"]))),
            (6, 1, struct.pack(">Q", int(fields["identity_generation"]))),
            (7, 1, struct.pack(">Q", int(fields["revocation_generation"]))),
            (8, 1, struct.pack(">Q", int(fields["receipt_revision"]))),
            (9, 2, hx(str(fields["admission_attempt_sha256_hex"]))),
        ],
    )


def authority_commitment(vector: dict[str, object]) -> bytes:
    a_view = authority_view(vector["authority_view_a"])
    b_view = authority_view(vector["authority_view_b"])
    return canonical(
        "operational-admission-commitment-v1",
        [
            (1, 2, hx(vector["role_a_fingerprint_sha256_hex"])),
            (2, 2, hx(vector["role_b_fingerprint_sha256_hex"])),
            (3, 2, hashlib.sha256(a_view).digest()),
            (4, 2, hashlib.sha256(b_view).digest()),
            (5, 3, b"x25519-hkdf-sha256-ed25519-v1"),
            (6, 1, struct.pack(">Q", 1)),
        ],
    )


def context(vector: dict[str, object]) -> bytes:
    return canonical(
        "operational-session-exporter-context-v1",
        [
            (1, 3, ALPN.encode("ascii")),
            (2, 2, hx(vector["role_a_fingerprint_sha256_hex"])),
            (3, 2, hx(vector["role_b_fingerprint_sha256_hex"])),
            (4, 2, hashlib.sha256(authority_commitment(vector)).digest()),
            (5, 2, hx(vector["nonce_a_hex"])),
            (6, 2, hx(vector["nonce_b_hex"])),
            (7, 2, MAGIC),
            (8, 1, struct.pack(">Q", VERSION)),
        ],
    )


def confirmation_key(vector: dict[str, object]) -> tuple[bytes, bytes]:
    context_hash = hashlib.sha256(context(vector)).digest()
    prk = hmac.new(context_hash, hx(vector["expected_exporter_output_hex"]), hashlib.sha256).digest()
    key = hmac.new(prk, b"CSF12 operational session confirm key v1\x00" + context_hash + b"\x01", hashlib.sha256).digest()
    return context_hash, key


def preflight_lease_context(vector: dict[str, object], role: bytes) -> bytes:
    assert role in (b"A", b"B")
    view = authority_view(vector["authority_view_a" if role == b"A" else "authority_view_b"])
    return canonical(
        "operational-session-preflight-lease-context-v1",
        [
            (1, 3, ALPN.encode("ascii")),
            (2, 3, role),
            (3, 2, hx(vector["role_a_fingerprint_sha256_hex"])),
            (4, 2, hx(vector["role_b_fingerprint_sha256_hex"])),
            (5, 2, hashlib.sha256(view).digest()),
        ],
    )


def preflight_lease_binding(vector: dict[str, object], role: bytes) -> bytes:
    lease = vector["preflight_lease"]
    output = hx(lease["a_exporter_output_hex" if role == b"A" else "b_exporter_output_hex"])
    view = authority_view(vector["authority_view_a" if role == b"A" else "authority_view_b"])
    return canonical(
        "operational-session-preflight-lease-binding-v1",
        [
            (1, 3, role),
            (2, 2, hashlib.sha256(view).digest()),
            (3, 2, hashlib.sha256(preflight_lease_context(vector, role)).digest()),
            (4, 2, hashlib.sha256(output).digest()),
        ],
    )


def mac(key: bytes, role: bytes, attempt: bytes, session: bytes, prior: bytes) -> bytes:
    return hmac.new(key, b"CSF12 operational session confirm v1\x00" + role + attempt + session + prior, hashlib.sha256).digest()


def transcript(vector: dict[str, object], records: list[bytes]) -> bytes:
    commitment = authority_commitment(vector)
    material = (
        b"CSF12-operational-session-transcript-v1\x00"
        + struct.pack(">H", len(ALPN)) + ALPN.encode("ascii")
        + struct.pack(">I", len(commitment)) + commitment
        + struct.pack(">I", len(records))
        + b"".join(struct.pack(">I", len(record)) + record for record in records)
    )
    return hashlib.sha256(material).digest()


def preconfirm_transcript(vector: dict[str, object], records: list[bytes]) -> bytes:
    assert len(records) >= 4
    commitment = authority_commitment(vector)
    material = (
        b"CSF12-operational-session-preconfirm-v1\x00"
        + struct.pack(">H", len(ALPN)) + ALPN.encode("ascii")
        + struct.pack(">I", len(commitment)) + commitment
        + struct.pack(">I", 4)
        + b"".join(struct.pack(">I", len(record)) + record for record in records[:4])
    )
    return hashlib.sha256(material).digest()


def validate(vector: dict[str, object], spec: str) -> None:
    assert vector["format"] == "control-shift-f12-operational-session-v01"
    assert vector["alpn"] == ALPN and vector["wire_magic_hex"] == MAGIC.hex() and vector["wire_version"] == VERSION
    assert vector["wire_header"] == "magic:8|version:u16be|type:u8|direction:u8|sequence:u32be|length:u32be"
    assert vector["record_payload_limit"] == LIMIT and vector["exporter_label"] == EXPORTER_LABEL
    assert vector["exporter_output_length"] == 32
    assert vector["resumption"] == {"zero_rtt": "forbidden", "tickets": "forbidden", "resumption": "forbidden"}
    assert vector["wire_attempt_source"] == "A-csprng-32-bytes-one-use-not-durable"
    assert vector["quic_client_role"] == "A-lower-fingerprint"
    assert vector["stream_count"] == 1
    assert vector["operational_wire_version"] == VERSION
    assert vector["authority_view_a"]["pairing_receipt_protocol_version"] == PAIRING_RECEIPT_VERSION
    assert vector["authority_view_b"]["pairing_receipt_protocol_version"] == PAIRING_RECEIPT_VERSION
    assert hx(vector["role_a_fingerprint_sha256_hex"]) < hx(vector["role_b_fingerprint_sha256_hex"])
    a_view, b_view = authority_view(vector["authority_view_a"]), authority_view(vector["authority_view_b"])
    assert a_view.hex() == vector["authority_commitment_a_view_hex"]
    assert b_view.hex() == vector["authority_commitment_b_view_hex"]
    assert hashlib.sha256(a_view).hexdigest() == vector["authority_view_a_sha256_hex"]
    assert hashlib.sha256(b_view).hexdigest() == vector["authority_view_b_sha256_hex"]
    assert len(a_view) <= 512 and len(b_view) <= 512
    assert vector["authority_view_a"]["self_fingerprint_sha256_hex"] == vector["role_a_fingerprint_sha256_hex"]
    assert vector["authority_view_a"]["peer_fingerprint_sha256_hex"] == vector["role_b_fingerprint_sha256_hex"]
    assert vector["authority_view_b"]["self_fingerprint_sha256_hex"] == vector["role_b_fingerprint_sha256_hex"]
    assert vector["authority_view_b"]["peer_fingerprint_sha256_hex"] == vector["role_a_fingerprint_sha256_hex"]
    commitment = authority_commitment(vector)
    assert commitment.hex() == vector["authority_commitment_hex"]
    assert hashlib.sha256(commitment).hexdigest() == vector["authority_commitment_sha256_hex"]
    exporter_context = context(vector)
    assert exporter_context.hex() == vector["exporter_context_hex"]
    assert hashlib.sha256(exporter_context).hexdigest() == vector["exporter_context_sha256_hex"]
    assert len(hx(vector["expected_exporter_output_hex"])) == 32
    payloads = [hx(item) for item in vector["canonical_payloads_hex"]]
    records = [hx(item) for item in vector["records_hex"]]
    assert len(payloads) == len(records) == len(SCHEDULE)
    decoded = []
    for sequence, (record, payload, (message_type, direction), kind) in enumerate(zip(records, payloads, SCHEDULE, KINDS)):
        assert record == frame(message_type, direction, sequence, payload)
        assert decode_frame(record) == (message_type, direction, sequence, payload)
        decoded.append(decode_canonical(kind, payload))
    assert actual_remote_receipt_version(vector, 0, 5) == PAIRING_RECEIPT_VERSION
    assert actual_remote_receipt_version(vector, 1, 6) == PAIRING_RECEIPT_VERSION
    lease = vector["preflight_lease"]
    assert lease["stage"] == "local-view-plus-selected-tls-before-stream"
    assert lease["promotion"] == "atomic-revalidate-after-bilateral-preflight"
    assert lease["exporter_label"] == "EXPORTER-ControlShiftF12-OperationalPreflightLease-v1"
    assert len(hx(lease["a_exporter_output_hex"])) == len(hx(lease["b_exporter_output_hex"])) == 32
    assert preflight_lease_context(vector, b"A").hex() == lease["a_context_hex"]
    assert preflight_lease_context(vector, b"B").hex() == lease["b_context_hex"]
    assert preflight_lease_binding(vector, b"A").hex() == lease["a_binding_hex"]
    assert preflight_lease_binding(vector, b"B").hex() == lease["b_binding_hex"]
    attempt, session = hx(vector["wire_attempt_hex"]), hx(vector["session_id_hex"])
    nonce_a, nonce_b = hx(vector["nonce_a_hex"]), hx(vector["nonce_b_hex"])
    commitment_hash = hashlib.sha256(commitment).digest()
    context_hash, key = confirmation_key(vector)
    bilateral = vector["bilateral_derivation"]
    assert bilateral == {
        "a_authority_commitment_sha256_hex": hashlib.sha256(commitment).hexdigest(),
        "b_authority_commitment_sha256_hex": hashlib.sha256(commitment).hexdigest(),
        "a_exporter_context_sha256_hex": hashlib.sha256(exporter_context).hexdigest(),
        "b_exporter_context_sha256_hex": hashlib.sha256(exporter_context).hexdigest(),
        "a_confirmation_key_sha256_hex": hashlib.sha256(key).hexdigest(),
        "b_confirmation_key_sha256_hex": hashlib.sha256(key).hexdigest(),
    }
    role_a, role_b = hx(vector["role_a_fingerprint_sha256_hex"]), hx(vector["role_b_fingerprint_sha256_hex"])
    assert decoded[0] == {1:(2,attempt),2:(3,b"A"),3:(2,session),4:(2,nonce_a),5:(2,a_view),6:(2,role_a),7:(2,role_b)}
    assert decoded[1] == {1:(2,attempt),2:(3,b"B"),3:(2,session),4:(2,nonce_a),5:(2,nonce_b),6:(2,b_view),7:(2,role_a),8:(2,role_b)}
    assert decode_canonical("operational-authority-view-v1", decoded[0][5][1]) == decode_canonical("operational-authority-view-v1", a_view)
    assert decode_canonical("operational-authority-view-v1", decoded[1][6][1]) == decode_canonical("operational-authority-view-v1", b_view)
    assert decoded[2] == {1:(2,attempt),2:(3,b"A"),3:(2,session),4:(2,commitment_hash),5:(2,context_hash)}
    assert decoded[3] == {1:(2,attempt),2:(3,b"B"),3:(2,session),4:(2,hashlib.sha256(payloads[2]).digest()),5:(2,commitment_hash),6:(2,context_hash)}
    assert decoded[4] == {1:(2,attempt),2:(3,b"A"),3:(2,session),4:(2,hashlib.sha256(payloads[3]).digest()),5:(2,mac(key,b"A",attempt,session,hashlib.sha256(payloads[3]).digest()))}
    assert decoded[5] == {1:(2,attempt),2:(3,b"B"),3:(2,session),4:(2,hashlib.sha256(payloads[4]).digest()),5:(2,mac(key,b"B",attempt,session,hashlib.sha256(payloads[4]).digest()))}
    assert preconfirm_transcript(vector, records).hex() == vector["preconfirm_transcript_sha256_hex"]
    assert transcript(vector, records).hex() == vector["transcript_sha256_hex"]
    assert set(vector["negative_mutations"]) == set(MUTATIONS)
    for phrase in (
        "not `csf12-pair/2`",
        "No downgrade",
        "input, clipboard, topology",
        "independent security/protocol review",
        "AcquirePreflightLease",
        "PromoteSessionLease",
        "A hash alone is never treated as evidence",
        "canonical A authority view(5 bytes≤512)",
        "pairing_receipt_protocol_version",
        "They are never compared for equality",
        "linearization",
    ):
        assert phrase in spec


def record_byte(index: int, byte_index: int, replacement: int):
    def apply(vector: dict[str, object]) -> None:
        raw = bytearray(hx(vector["records_hex"][index]))
        raw[byte_index] = replacement
        vector["records_hex"][index] = raw.hex()
    return apply


def rewrite_frame_version(index: int, version: int):
    def apply(vector: dict[str, object]) -> None:
        raw = bytearray(hx(vector["records_hex"][index]))
        struct.pack_into(">H", raw, 8, version)
        vector["records_hex"][index] = raw.hex()
    return apply


def mutate_preflight_receipt(index: int, outer_tag: int, version: int):
    """Mutate tag 4 inside the authority view carried by a real preflight frame."""
    def apply(vector: dict[str, object]) -> None:
        message_type, direction, sequence, payload = decode_frame(hx(vector["records_hex"][index]))
        outer = decode_canonical(KINDS[index], payload)
        remote = decode_canonical("operational-authority-view-v1", outer[outer_tag][1])
        remote[4] = (1, struct.pack(">Q", version))
        rebuilt_remote = canonical("operational-authority-view-v1", [(tag, value_type, value) for tag, (value_type, value) in remote.items()])
        outer[outer_tag] = (2, rebuilt_remote)
        rebuilt_payload = canonical(KINDS[index], [(tag, value_type, value) for tag, (value_type, value) in outer.items()])
        vector["canonical_payloads_hex"][index] = rebuilt_payload.hex()
        vector["records_hex"][index] = frame(message_type, direction, sequence, rebuilt_payload).hex()
    return apply


def mutate_framed_payload_field(index: int, tag: int):
    """Mutate one canonical field inside a real frame and rebuild its header."""
    def apply(vector: dict[str, object]) -> None:
        message_type, direction, sequence, payload = decode_frame(hx(vector["records_hex"][index]))
        offset = 8
        kind_length = payload[offset]
        offset += 1 + kind_length
        count = struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        mutated = bytearray(payload)
        for _ in range(count):
            current_tag, _value_type, length = struct.unpack_from(">HBI", payload, offset)
            offset += 7
            if current_tag == tag:
                mutated[offset + length - 1] ^= 1
                rebuilt = bytes(mutated)
                vector["canonical_payloads_hex"][index] = rebuilt.hex()
                vector["records_hex"][index] = frame(message_type, direction, sequence, rebuilt).hex()
                return
            offset += length
        raise AssertionError(f"tag {tag} missing")
    return apply


def actual_remote_receipt_version(vector: dict[str, object], index: int, outer_tag: int) -> int:
    _message_type, _direction, _sequence, payload = decode_frame(hx(vector["records_hex"][index]))
    outer = decode_canonical(KINDS[index], payload)
    remote = decode_canonical("operational-authority-view-v1", outer[outer_tag][1])
    value_type, value = remote[4]
    assert value_type == 1 and len(value) == 8
    return struct.unpack(">Q", value)[0]


def frame_rejected(vector: dict[str, object], index: int) -> bool:
    try:
        decode_frame(hx(vector["records_hex"][index]))
    except (AssertionError, ValueError, struct.error, IndexError):
        return True
    return False


def schedule_rejected(vector: dict[str, object], index: int) -> bool:
    try:
        message_type, direction, sequence, _payload = decode_frame(hx(vector["records_hex"][index]))
    except (AssertionError, ValueError, struct.error, IndexError):
        return True
    return (message_type, direction) != SCHEDULE[index] or sequence != index


MUTATION_STAGES = {
    "alpn-downgrade": "metadata",
    "wire-version-downgrade": "frame",
    "operational-wire-version-two": "frame",
    "magic-substitution": "frame",
    "type-substitution": "frame",
    "direction-substitution": "frame",
    "sequence-replay": "frame",
    "payload-trailing": "frame",
    "payload-oversize": "frame",
    "tuple-revision-substitution": "preflight-local",
    "tuple-revocation-substitution": "preflight-local",
    "pairing-receipt-version-one": "preflight-remote",
    "pairing-receipt-version-three": "preflight-remote",
    "observed-leaf-substitution": "preflight-local",
    "exporter-label-substitution": "exporter",
    "exporter-context-substitution": "exporter",
    "exporter-cross-connection-substitution": "exporter",
    "nonce-substitution": "exporter",
    "open-hash-substitution": "accept",
    "confirm-mac-substitution": "confirm",
    "one-sided-confirm": "confirm",
    "early-fin": "confirm",
    "extra-stream": "metadata",
    "zero-rtt": "metadata",
    "resumption-ticket": "metadata",
    "reconnect-reuse": "metadata",
    "post-revocation-reconnect": "preflight-local",
}


def mutation_stage(name: str, vector: dict[str, object]) -> str:
    if name == "alpn-downgrade":
        assert vector["alpn"] != ALPN
    elif name in {"wire-version-downgrade", "operational-wire-version-two", "magic-substitution", "payload-trailing", "payload-oversize"}:
        assert frame_rejected(vector, 0)
    elif name in {"type-substitution", "direction-substitution"}:
        assert schedule_rejected(vector, 0)
    elif name == "sequence-replay":
        assert schedule_rejected(vector, 1)
    elif name == "tuple-revision-substitution":
        assert vector["authority_view_a"]["receipt_revision"] != 12
    elif name == "tuple-revocation-substitution":
        assert vector["authority_view_b"]["revocation_generation"] != 5
    elif name == "pairing-receipt-version-one":
        assert actual_remote_receipt_version(vector, 0, 5) == 1
    elif name == "pairing-receipt-version-three":
        assert actual_remote_receipt_version(vector, 1, 6) == 3
    elif name == "observed-leaf-substitution":
        assert vector["role_b_fingerprint_sha256_hex"] != "22" * 32
    elif name == "exporter-label-substitution":
        assert vector["exporter_label"] != EXPORTER_LABEL
    elif name == "exporter-context-substitution":
        assert vector["exporter_context_hex"] != context(vector).hex()
    elif name == "exporter-cross-connection-substitution":
        assert vector["expected_exporter_output_hex"] != "66" * 32
    elif name == "nonce-substitution":
        assert vector["nonce_b_hex"] != "44" * 32
    elif name == "open-hash-substitution":
        assert decode_canonical(KINDS[3], decode_frame(hx(vector["records_hex"][3]))[3])[4][1] != hashlib.sha256(hx(vector["canonical_payloads_hex"][2])).digest()
    elif name == "confirm-mac-substitution":
        assert decode_canonical(KINDS[4], decode_frame(hx(vector["records_hex"][4]))[3])[5][1] != mac(*confirmation_key(vector)[1:], b"A", hx(vector["wire_attempt_hex"]), hx(vector["session_id_hex"]), hashlib.sha256(hx(vector["canonical_payloads_hex"][3])).digest())
    elif name == "one-sided-confirm":
        assert len(vector["records_hex"]) == 5
    elif name == "early-fin":
        assert len(vector["canonical_payloads_hex"]) == 5
    elif name == "extra-stream":
        assert vector["stream_count"] != 1
    elif name == "zero-rtt":
        assert vector["resumption"]["zero_rtt"] != "forbidden"
    elif name == "resumption-ticket":
        assert vector["resumption"]["tickets"] != "forbidden"
    elif name == "reconnect-reuse":
        assert vector["wire_attempt_source"] != "A-csprng-32-bytes-one-use-not-durable"
    elif name == "post-revocation-reconnect":
        assert vector["authority_view_a"]["revocation_generation"] != 3
    else:
        raise AssertionError(f"missing stage probe for {name}")
    return MUTATION_STAGES[name]


MUTATIONS = {
    "alpn-downgrade": lambda v: v.__setitem__("alpn", "csf12-pair/2"),
    "wire-version-downgrade": rewrite_frame_version(0, 0),
    "operational-wire-version-two": rewrite_frame_version(0, 2),
    "magic-substitution": record_byte(0, 0, 0),
    "type-substitution": record_byte(0, 10, 5),
    "direction-substitution": record_byte(0, 11, 2),
    "sequence-replay": record_byte(1, 15, 0),
    "payload-trailing": lambda v: v["records_hex"].__setitem__(0, v["records_hex"][0] + "00"),
    "payload-oversize": lambda v: v["records_hex"].__setitem__(0, v["records_hex"][0][:32] + "00001001" + v["records_hex"][0][40:]),
    "tuple-revision-substitution": lambda v: v["authority_view_a"].__setitem__("receipt_revision", 13),
    "tuple-revocation-substitution": lambda v: v["authority_view_b"].__setitem__("revocation_generation", 4),
    "pairing-receipt-version-one": mutate_preflight_receipt(0, 5, 1),
    "pairing-receipt-version-three": mutate_preflight_receipt(1, 6, 3),
    "observed-leaf-substitution": lambda v: v.__setitem__("role_b_fingerprint_sha256_hex", "99" * 32),
    "exporter-label-substitution": lambda v: v.__setitem__("exporter_label", "wrong"),
    "exporter-context-substitution": lambda v: v.__setitem__("exporter_context_hex", "00"),
    "exporter-cross-connection-substitution": lambda v: v.__setitem__("expected_exporter_output_hex", "99" * 32),
    "nonce-substitution": lambda v: v.__setitem__("nonce_b_hex", "99" * 32),
    "open-hash-substitution": mutate_framed_payload_field(3, 4),
    "confirm-mac-substitution": mutate_framed_payload_field(4, 5),
    "one-sided-confirm": lambda v: v["records_hex"].pop(),
    "early-fin": lambda v: v["canonical_payloads_hex"].pop(),
    "extra-stream": lambda v: v.__setitem__("stream_count", 2),
    "zero-rtt": lambda v: v["resumption"].__setitem__("zero_rtt", "allowed"),
    "resumption-ticket": lambda v: v["resumption"].__setitem__("tickets", "allowed"),
    "reconnect-reuse": lambda v: v.__setitem__("wire_attempt_source", "reused"),
    "post-revocation-reconnect": lambda v: v["authority_view_a"].__setitem__("revocation_generation", 4),
}


def main() -> None:
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    spec = SPEC.read_text(encoding="utf-8")
    validate(vector, spec)
    for name, change in MUTATIONS.items():
        candidate = deepcopy(vector)
        change(candidate)
        assert mutation_stage(name, candidate) == MUTATION_STAGES[name]
        try:
            validate(candidate, spec)
        except (AssertionError, ValueError, struct.error, IndexError):
            continue
        raise AssertionError(f"mutant {name} survived")
    print(f"PASS: operational-session-v01 reference, vectors, and {len(MUTATIONS)} executed mutants")


if __name__ == "__main__":
    main()
