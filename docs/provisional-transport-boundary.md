# Experimental provisional transport boundary — phase5 restricted slice

This is **not full operational pairing and not release approval**. It implements
only the independently reviewed transport primitives and isolated real QUIC/TLS
tests. The application still terminates selection at
`handshake_envelope_pending`; it never opens this transport, emits a handshake,
shows a live SAS, finalizes a live pair, promotes trust, or enables input/clipboard.

## Frozen dependency and deliberate exclusions

Consumed reference: `dc3750bdbc824abf7320ecfbd5c9cc241466239f`,
`tools/pairing_reference_v2/TRANSPORT-INTEROPERABILITY.md` and
`vectors/transport-v01-operational.json`. Original JSON SHA256:
`92f6a32c59f276877c69b2ae1fc52dd74af14becd5f3505583dd9d5d2dfd8025`.

The consumer fixture is a **field-value projection**, not a byte-identical copy
of the whole JSON. Frozen transport hex values are retained unchanged.
Recovery-authority bodies, compatibility data and authority-negative cases are
excluded; provenance fields are added. No `recovery-authority/1` is consumed,
persisted or emitted. No newer bilateral reference, including `d978a4f`, is
consumed. The existing phase3 authoritative recovery interface is unchanged and
has no production bootstrap/provider.

Type3 framing is bounded but its payload is deliberately opaque. There is no
invented message envelope, signature envelope, stream choreography, candidate
stream-role policy, shared connection ID, shared generation, or Hello-hash
substitution. A separately reviewed bilateral-envelope contract and integration
review are prerequisites for advancing beyond this slice.

## Implemented interfaces

- `operational_wire::CandidateRequest`: exact six canonical fields, strict
  version/ALPN/limit and fixed 16-byte IDs/nonces. Boolean is not an integer.
- `TransportFrame`: magic `CSF12P2\0`, version2, types1/2/3, payload bounds
  1024/4096/16384; exact length, no trailing bytes. Header bounds are checked
  before body allocation.
- `read_record`: externally delimited single record, requires EOF, one absolute
  tokio monotonic deadline across header/body/EOF. It does not assign records to
  production QUIC streams. Extra frames, truncation, reset and oversize reject.
- `operational_binding::BindingInput`: fixture-level codec primitive, **not a
  TLS-provenance capability**. Checks request echo/rendezvous, singleton suite,
  actual-leaf hash claim and local connection grammar; constructs frozen
  exporter context, binding digest and replay token.
- `provisional_tls::configs`: strict Ed25519 self-signed identity profile on both
  peers, current wall-clock validity, exactly one leaf, real TLS CertificateVerify,
  mandatory client certificate, TLS1.3, exact ALPN `csf12-pair/2`.
  No early data, resumption or tickets. One concurrent stream of each direction,
  bounded receive windows, 30-second idle timeout. It opens no socket itself.
- `ProvisionalChannel::observe`: observes negotiated ALPN and actual leaf from
  quinn; derives opaque local ID from the selected connection. Caller supplies
  its trusted **local** generation, not a remote claim.
- `ProvisionalChannel::bind`: uses the real TLS exporter with frozen label
  `EXPORTER-ControlShiftF12-Pairing-v2`, canonical context and 32-byte output.
  Each channel gets one attempt. Errors and drop close the connection.
- `TransportReplayRegistry`: injected shared mutex registry, atomic one-winner
  consumption after validation, 1024 entries, no eviction, poison/capacity
  fail-closed. It is process-local, not durable/global recovery authority.
- Typed control error/status/transport status now serialize as
  `handshake_envelope_pending`. Selection stops browsing; `compare_match`
  remains `invalid_state`, authenticated sessions remain zero and all
  promotion/admission/input/clipboard flags remain false.

`LocalBinding` only exposes a digest and replay token. It cannot construct
`PeerSession`, invoke admission, or modify active pins. Exporter output and
canonical binding buffer are zeroizing buffers; this is not an OS-wide
memory-erasure claim.

## Trust and lifecycle boundaries

Provisional self-signed TLS establishes key possession, **not human confirmation
or trusted identity**. The Rust caller must use the strict configs: the public
observer cannot prove that an externally supplied quinn connection was built
with them. It independently checks observed leaf profile/ALPN, but that does not
seal an operational coordinator. The adapter remains disconnected from the app.

Replay registry ownership must be shared by all channels in an eventual
operational owner. Creating independent registries is not a global replay guard.
No registry restart recovery is implemented: restart or absent approved
authority requires a new connection, fresh nonces and full fresh SAS flow; that
future flow is not an implemented emitter here. Current application gate rejects
all such advancement. No automatic legacy/manual/TOFU fallback exists.

Connection IDs/generations are local. Tests compare TLS exporter outputs only
when explicitly supplying the same context; they do not infer bilateral context
symmetry. Public codec inputs alone do not establish remote-generation authority.

Consent-gated mDNS remains browse-only from phase4; this slice adds no advertiser
or listener. A future transport owner needs bounded consent/listener leases,
pending-connection budgets and an approved ingress controller. Windows application
setup remains `unsupported_platform` before backend invocation; no Windows
persistence changes are included.

## Verification and evidence

Fresh workspace results: default **220 passed / 0 failed / 2 ignored**;
experimental **308 passed / 0 failed / 3 ignored**. Both workspace/all-target
clippy modes passed with warnings denied; formatting passed. The additional
ignored test is a subprocess worker explicitly invoked by the passing parent
two-process loopback test, not untested coverage.

New tests: wire4, binding/replay5, real provisional QUIC7. They include literal
independent request/frame/context/binding/replay fixture equality; malformed
fields, all frame truncations, trailing/limit edges, fragmented streams and
absolute deadline; binding substitutions, eight concurrent replay consumers
(one winner), capacity without eviction; actual mutual leaf observation,
real exporter binding, repeated channel rejection, observed-leaf substitution,
ALPN downgrade, missing KeyUsage, key mismatch, forged CertificateVerify,
actual QUIC reset/oversize, and two OS processes over loopback.

TDD behavior cycles were observed before implementation: wire3 failures,
binding3 failures, provisional4 failures and the typed snapshot's old-status
failure; each became green. Thirteen individually restored mutants all produced
test assertion failures (exit101), not compilation failures: observed leaf,
echo nonce, rendezvous, ALPN, omitted replay consumption, atomic consume,
exporter label/context, TLS CertificateVerify, frame limit, frame trailing,
record trailing, mandatory client authentication. Raw results and full fresh
verification output are in [QA evidence](qa/provisional-transport-boundary-evidence.json).

Existing phase3 durable-journal fault tests passed in the experimental regression
suite. This slice adds **no new durable-write boundary** and claims no live
pairing/FC crash recovery, operational simultaneous initiation, bilateral
message-order/fault schedule, cross-machine LAN interoperability, or native
macOS/Windows UI test. Test-only stream exchanges are not a production protocol.

## Handoff / remaining gates

The narrowed slice is ready for independent code/security review, not release.
Keep the feature off by default and promotion deny. Next work requires a reviewed
bilateral ingress/envelope contract, then explicit authorization for transport
ownership/coordinator composition and fresh-SAS finalization. Production durable
recovery authority remains separately prohibited until its own crypto/authority
review. External cryptographic audit, native OS interoperability/persistence and
human UX validation remain mandatory release gates.
