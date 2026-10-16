#!/usr/bin/env python3
"""Static verifier for the frozen, non-runtime operational-session reference.

The fixture is intentionally test-only: no shipping target imports it.  This
guard makes byte order, fixed limits, downgrade rules and mutation claims
machine-checkable before a separately reviewed parser exists.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "operational-session-interoperability.md"
FIXTURE = (
    ROOT
    / "crates"
    / "transport"
    / "tests"
    / "fixtures"
    / "pairing-v2"
    / "operational-session-v01.json"
)

MAGIC = b"CSF12S1\x00"
VERSION = 1
ALPN = "csf12-operational/1"
EXPORTER_LABEL = "EXPORTER-ControlShiftF12-OperationalSession-v1"
RECORD_LIMIT = 4096
HEADER_LEN = 20


def canonical(kind: str, fields: list[tuple[int, int, bytes]]) -> bytes:
    """Encode the established CSF12E01 TLV subset used by this fixture."""
    encoded_kind = kind.encode("ascii")
    assert len(encoded_kind) <= 255
    out = bytearray(b"CSF12E01" + bytes([len(encoded_kind)]) + encoded_kind)
    out.extend(struct.pack(">H", len(fields)))
    previous = 0
    for tag, value_type, value in fields:
        assert tag > previous
        assert value_type in (1, 2, 3)
        if value_type == 1:
            assert len(value) == 8
        out.extend(struct.pack(">HBI", tag, value_type, len(value)))
        out.extend(value)
        previous = tag
    return bytes(out)


def frame(message_type: int, direction: int, sequence: int, payload: bytes) -> bytes:
    assert message_type in (1, 2, 3)
    assert direction in (1, 2)
    assert 0 <= sequence <= 0xFFFFFFFF
    assert 0 < len(payload) <= RECORD_LIMIT
    return (
        MAGIC
        + struct.pack(">HBBII", VERSION, message_type, direction, sequence, len(payload))
        + payload
    )


def decode_canonical(expected_kind: str, encoded: bytes) -> dict[int, tuple[int, bytes]]:
    """Strict independent decoder for the fixture's canonical bytes."""
    assert encoded.startswith(b"CSF12E01")
    offset = 8
    assert offset < len(encoded)
    kind_length = encoded[offset]
    offset += 1
    assert encoded[offset : offset + kind_length] == expected_kind.encode("ascii")
    offset += kind_length
    assert offset + 2 <= len(encoded)
    count = struct.unpack_from(">H", encoded, offset)[0]
    offset += 2
    fields: dict[int, tuple[int, bytes]] = {}
    previous = 0
    for _ in range(count):
        assert offset + 7 <= len(encoded)
        tag, value_type, length = struct.unpack_from(">HBI", encoded, offset)
        offset += 7
        assert tag > previous
        assert value_type in (1, 2, 3)
        assert offset + length <= len(encoded)
        value = encoded[offset : offset + length]
        offset += length
        assert tag not in fields
        if value_type == 1:
            assert length == 8
        fields[tag] = (value_type, value)
        previous = tag
    assert offset == len(encoded)
    return fields


def decode_frame(encoded: bytes) -> tuple[int, int, int, bytes]:
    assert len(encoded) >= HEADER_LEN
    assert encoded[:8] == MAGIC
    version, message_type, direction, sequence, length = struct.unpack_from(">HBBII", encoded, 8)
    assert version == VERSION
    assert message_type in (1, 2, 3)
    assert direction in (1, 2)
    assert 0 < length <= RECORD_LIMIT
    assert len(encoded) == HEADER_LEN + length
    return message_type, direction, sequence, encoded[HEADER_LEN:]


def authority_tuple(fields: dict[str, str | int]) -> bytes:
    return canonical(
        "operational-authority-tuple-v1",
        [
            (1, 2, bytes.fromhex(str(fields["peer_fingerprint_sha256_hex"]))),
            (2, 3, str(fields["suite"]).encode("ascii")),
            (3, 1, struct.pack(">Q", int(fields["protocol_version"]))),
            (4, 1, struct.pack(">Q", int(fields["policy_revision"]))),
            (5, 1, struct.pack(">Q", int(fields["identity_generation"]))),
            (6, 1, struct.pack(">Q", int(fields["revocation_generation"]))),
            (7, 1, struct.pack(">Q", int(fields["receipt_revision"]))),
            (8, 2, bytes.fromhex(str(fields["admission_attempt_sha256_hex"]))),
        ],
    )


def exporter_context(vector: dict[str, object]) -> bytes:
    authority = authority_tuple(vector["durable_authority_tuple"])
    return canonical(
        "operational-session-exporter-context-v1",
        [
            (1, 3, ALPN.encode("ascii")),
            (2, 2, bytes.fromhex(vector["role_a_fingerprint_sha256_hex"])),
            (3, 2, bytes.fromhex(vector["role_b_fingerprint_sha256_hex"])),
            (4, 2, hashlib.sha256(authority).digest()),
            (5, 2, bytes.fromhex(vector["nonce_a_hex"])),
            (6, 2, bytes.fromhex(vector["nonce_b_hex"])),
            (7, 2, MAGIC),
            (8, 1, struct.pack(">Q", VERSION)),
        ],
    )


def transcript(vector: dict[str, object], records: list[bytes]) -> bytes:
    authority = authority_tuple(vector["durable_authority_tuple"])
    material = (
        b"CSF12-operational-session-transcript-v1\x00"
        + struct.pack(">H", len(ALPN))
        + ALPN.encode("ascii")
        + struct.pack(">I", len(authority))
        + authority
        + struct.pack(">I", len(records))
        + b"".join(struct.pack(">I", len(record)) + record for record in records)
    )
    return hashlib.sha256(material).digest()


def derive_confirmation_key(vector: dict[str, object]) -> tuple[bytes, bytes]:
    context_hash = hashlib.sha256(exporter_context(vector)).digest()
    exporter = bytes.fromhex(vector["expected_exporter_output_hex"])
    prk = hmac.new(context_hash, exporter, hashlib.sha256).digest()
    key = hmac.new(
        prk,
        b"CSF12 operational session confirm key v1\x00" + context_hash + b"\x01",
        hashlib.sha256,
    ).digest()
    return context_hash, key


def confirmation(key: bytes, role: bytes, attempt: bytes, session_id: bytes, prior: bytes) -> bytes:
    return hmac.new(
        key,
        b"CSF12 operational session confirm v1\x00" + role + attempt + session_id + prior,
        hashlib.sha256,
    ).digest()


def validate(vector: dict[str, object], spec: str) -> None:
    assert vector["format"] == "control-shift-f12-operational-session-v01"
    assert vector["alpn"] == ALPN
    assert vector["wire_magic_hex"] == MAGIC.hex()
    assert vector["wire_version"] == VERSION
    assert vector["wire_header"] == "magic:8|version:u16be|type:u8|direction:u8|sequence:u32be|length:u32be"
    assert vector["record_payload_limit"] == RECORD_LIMIT
    assert vector["exporter_label"] == EXPORTER_LABEL
    assert vector["exporter_output_length"] == 32
    assert vector["resumption"] == {"zero_rtt": "forbidden", "tickets": "forbidden", "resumption": "forbidden"}
    assert "not `csf12-pair/2`" in spec
    assert "No downgrade" in spec
    assert "input, clipboard, topology" in spec
    assert "independent security/protocol review" in spec
    authority = authority_tuple(vector["durable_authority_tuple"])
    assert authority.hex() == vector["durable_authority_tuple_hex"]
    assert hashlib.sha256(authority).hexdigest() == vector["durable_authority_tuple_sha256_hex"]
    context = exporter_context(vector)
    assert context.hex() == vector["exporter_context_hex"]
    assert hashlib.sha256(context).hexdigest() == vector["exporter_context_sha256_hex"]
    assert len(bytes.fromhex(vector["expected_exporter_output_hex"])) == 32
    payloads = [bytes.fromhex(value) for value in vector["canonical_payloads_hex"]]
    records = [bytes.fromhex(value) for value in vector["records_hex"]]
    expected_schedule = [(1, 1), (2, 2), (3, 1), (3, 2)]
    assert len(records) == len(payloads) == len(expected_schedule)
    decoded: list[dict[int, tuple[int, bytes]]] = []
    kinds = [
        "operational-session-open-v1",
        "operational-session-accept-v1",
        "operational-session-confirm-v1",
        "operational-session-confirm-v1",
    ]
    for sequence, (record, payload, (message_type, direction), kind) in enumerate(
        zip(records, payloads, expected_schedule, kinds)
    ):
        assert record == frame(message_type, direction, sequence, payload)
        assert decode_frame(record) == (message_type, direction, sequence, payload)
        decoded.append(decode_canonical(kind, payload))
    context_hash, key = derive_confirmation_key(vector)
    authority_hash = hashlib.sha256(authority).digest()
    attempt = bytes.fromhex("77" * 32)
    session_id = bytes.fromhex("88" * 16)
    assert decoded[0] == {
        1: (2, attempt), 2: (3, b"A"), 3: (2, session_id),
        4: (2, bytes.fromhex(vector["nonce_a_hex"])), 5: (2, authority_hash),
        6: (2, context_hash),
    }
    assert decoded[1] == {
        1: (2, attempt), 2: (3, b"B"), 3: (2, session_id),
        4: (2, bytes.fromhex(vector["nonce_b_hex"])), 5: (2, hashlib.sha256(payloads[0]).digest()),
        6: (2, authority_hash), 7: (2, context_hash),
    }
    assert decoded[2] == {
        1: (2, attempt), 2: (3, b"A"), 3: (2, session_id),
        4: (2, hashlib.sha256(payloads[1]).digest()),
        5: (2, confirmation(key, b"A", attempt, session_id, hashlib.sha256(payloads[1]).digest())),
    }
    assert decoded[3] == {
        1: (2, attempt), 2: (3, b"B"), 3: (2, session_id),
        4: (2, hashlib.sha256(payloads[2]).digest()),
        5: (2, confirmation(key, b"B", attempt, session_id, hashlib.sha256(payloads[2]).digest())),
    }
    actual_transcript = transcript(vector, records)
    assert actual_transcript.hex() == vector["transcript_sha256_hex"]
    for mutation in vector["negative_mutations"]:
        assert mutation in spec


def main() -> None:
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    validate(vector, SPEC.read_text(encoding="utf-8"))
    mutations = {
        "alpn-downgrade": lambda v: v.__setitem__("alpn", "csf12-pair/2"),
        "wire-version-downgrade": lambda v: v.__setitem__("wire_version", 0),
        "magic-substitution": lambda v: v.__setitem__("wire_magic_hex", "00" * 8),
        "payload-trailing": lambda v: v["records_hex"].__setitem__(0, v["records_hex"][0] + "00"),
        "sequence-replay": lambda v: v["records_hex"].__setitem__(1, v["records_hex"][1][:24] + "00000000" + v["records_hex"][1][32:]),
        "tuple-revision-substitution": lambda v: v["durable_authority_tuple"].__setitem__("receipt_revision", 13),
        "exporter-label-substitution": lambda v: v.__setitem__("exporter_label", "wrong"),
        "nonce-substitution": lambda v: v.__setitem__("nonce_b_hex", "99" * 32),
        "confirm-mac-substitution": lambda v: v["canonical_payloads_hex"].__setitem__(2, v["canonical_payloads_hex"][2][:-2] + "00"),
    }
    for name, mutate in mutations.items():
        candidate = deepcopy(vector)
        mutate(candidate)
        try:
            validate(candidate, SPEC.read_text(encoding="utf-8"))
        except (AssertionError, ValueError, struct.error):
            continue
        raise AssertionError(f"mutant {name} survived")
    print(f"PASS: operational-session-v01 reference, vectors, and {len(mutations)} executed mutants")


if __name__ == "__main__":
    main()
