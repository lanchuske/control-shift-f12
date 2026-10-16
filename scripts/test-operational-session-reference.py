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
            (4, 1, struct.pack(">Q", int(fields["protocol_version"]))),
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
    assert hx(vector["role_a_fingerprint_sha256_hex"]) < hx(vector["role_b_fingerprint_sha256_hex"])
    a_view, b_view = authority_view(vector["authority_view_a"]), authority_view(vector["authority_view_b"])
    assert a_view.hex() == vector["authority_commitment_a_view_hex"]
    assert b_view.hex() == vector["authority_commitment_b_view_hex"]
    assert hashlib.sha256(a_view).hexdigest() == vector["authority_view_a_sha256_hex"]
    assert hashlib.sha256(b_view).hexdigest() == vector["authority_view_b_sha256_hex"]
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
    assert decoded[0] == {1:(2,attempt),2:(3,b"A"),3:(2,session),4:(2,nonce_a),5:(2,hashlib.sha256(a_view).digest()),6:(2,role_a),7:(2,role_b)}
    assert decoded[1] == {1:(2,attempt),2:(3,b"B"),3:(2,session),4:(2,nonce_a),5:(2,nonce_b),6:(2,hashlib.sha256(b_view).digest()),7:(2,role_a),8:(2,role_b)}
    assert decoded[2] == {1:(2,attempt),2:(3,b"A"),3:(2,session),4:(2,commitment_hash),5:(2,context_hash)}
    assert decoded[3] == {1:(2,attempt),2:(3,b"B"),3:(2,session),4:(2,hashlib.sha256(payloads[2]).digest()),5:(2,commitment_hash),6:(2,context_hash)}
    assert decoded[4] == {1:(2,attempt),2:(3,b"A"),3:(2,session),4:(2,hashlib.sha256(payloads[3]).digest()),5:(2,mac(key,b"A",attempt,session,hashlib.sha256(payloads[3]).digest()))}
    assert decoded[5] == {1:(2,attempt),2:(3,b"B"),3:(2,session),4:(2,hashlib.sha256(payloads[4]).digest()),5:(2,mac(key,b"B",attempt,session,hashlib.sha256(payloads[4]).digest()))}
    assert preconfirm_transcript(vector, records).hex() == vector["preconfirm_transcript_sha256_hex"]
    assert transcript(vector, records).hex() == vector["transcript_sha256_hex"]
    assert set(vector["negative_mutations"]) == set(MUTATIONS)
    for phrase in ("not `csf12-pair/2`", "No downgrade", "input, clipboard, topology", "independent security/protocol review", "linearization"):
        assert phrase in spec


def record_byte(index: int, byte_index: int, replacement: int):
    def apply(vector: dict[str, object]) -> None:
        raw = bytearray(hx(vector["records_hex"][index]))
        raw[byte_index] = replacement
        vector["records_hex"][index] = raw.hex()
    return apply


MUTATIONS = {
    "alpn-downgrade": lambda v: v.__setitem__("alpn", "csf12-pair/2"),
    "wire-version-downgrade": lambda v: v.__setitem__("wire_version", 0),
    "magic-substitution": lambda v: v.__setitem__("wire_magic_hex", "00" * 8),
    "type-substitution": record_byte(0, 10, 5),
    "direction-substitution": record_byte(0, 11, 2),
    "sequence-replay": record_byte(1, 15, 0),
    "payload-trailing": lambda v: v["records_hex"].__setitem__(0, v["records_hex"][0] + "00"),
    "payload-oversize": lambda v: v["records_hex"].__setitem__(0, v["records_hex"][0][:32] + "00001001" + v["records_hex"][0][40:]),
    "tuple-revision-substitution": lambda v: v["authority_view_a"].__setitem__("receipt_revision", 13),
    "tuple-revocation-substitution": lambda v: v["authority_view_b"].__setitem__("revocation_generation", 4),
    "observed-leaf-substitution": lambda v: v.__setitem__("role_b_fingerprint_sha256_hex", "99" * 32),
    "exporter-label-substitution": lambda v: v.__setitem__("exporter_label", "wrong"),
    "exporter-context-substitution": lambda v: v.__setitem__("exporter_context_hex", "00"),
    "exporter-cross-connection-substitution": lambda v: v.__setitem__("expected_exporter_output_hex", "99" * 32),
    "nonce-substitution": lambda v: v.__setitem__("nonce_b_hex", "99" * 32),
    "open-hash-substitution": lambda v: v["canonical_payloads_hex"].__setitem__(3, v["canonical_payloads_hex"][3][:-2] + "00"),
    "confirm-mac-substitution": lambda v: v["canonical_payloads_hex"].__setitem__(4, v["canonical_payloads_hex"][4][:-2] + "00"),
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
        try:
            validate(candidate, spec)
        except (AssertionError, ValueError, struct.error, IndexError):
            continue
        raise AssertionError(f"mutant {name} survived")
    print(f"PASS: operational-session-v01 reference, vectors, and {len(MUTATIONS)} executed mutants")


if __name__ == "__main__":
    main()
