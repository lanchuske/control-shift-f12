# Experimental guided-discovery boundary (phase 4 narrowed slice)

This is **not operational pairing or release approval**. It composes a real,
consent-gated browse-only mDNS adapter, an OS monotonic clock, and a typed private
control/UI contract. It does not implement a candidate TLS connection, emit a
pairing message, authenticate a discovered device, or create a trust pin.

The parent task narrowed phase 4 because the approved design/reference fixtures
do not freeze the live CandidateRequest/framing/ALPN/exporter contract or the
authenticated bootstrap of expected remote generations. Those decisions must
come from an independently authored and reviewed addendum, not this slice.

## Build and ownership

- Default build has no `pairing.v2` command. Opt-in application feature
  `pairing-v2-experimental` enables the discovery and transport feature flags.
- `control --stdio` remains a setup-only process. Default foundations snapshot
  is unchanged. It may create its existing `setup-control/writer.lock`; it does
  not write product configuration, identities, active pins, or pending records.
- Constructing the controller or requesting a snapshot creates no discovery
  backend. A local `open_discovery` gesture is required. This is a private
  inherited-pipe IPC command, not a network message or a remote confirmation.
- Windows/non-Unix open returns `unsupported_platform` before invoking the
  backend factory, even with the experimental feature. Windows persistence is
  another workstream and is not modified here.
- No elevation, firewall change, policy change, scanning, or alternative-network
  workaround is performed. OS/enterprise blocking is not bypassed. Permission,
  policy and network health remain unmeasured; an empty browse result is not a
  healthy-network assertion.

## Typed contract

Request envelope remains v1 private IPC with existing request-ID replay/conflict
semantics, 256 KiB frame bound and 256 unique-request bound. Command is
`pairing.v2`, with strictly typed `args` and unknown fields rejected:

| `action` | Result |
| --- | --- |
| `snapshot` | Current closed/browsing/contract-pending view; no new backend |
| `open_discovery` | Explicit 300-second browse consent window |
| `refresh` | Bounded poll and refreshed locator view |
| `close_discovery`, `cancel` | Drop backend and clear locators |
| `select` + `handle` | Validate current locator, stop discovery, then error `operational_contract_pending` |
| `compare_match` | `invalid_state`; no SAS is available in this slice |

Handle contains `{scope, window, sequence}`: random 128-bit local controller
scope, consent-window generation and monotonically allocated local sequence.
It is not an identity or a secret. Restart, a new window, expiry, removal or
changed locator metadata revokes the old handle. Address/identity/name fields
are not accepted from UI commands. Only anonymous handle, protocol version and
pairability reach the candidate view; no address, rendezvous token or untrusted
friendly name is rendered as identity evidence.

Every snapshot has `authenticated_sessions: 0`, `promotion_enabled: false`,
`input_enabled: false`, `clipboard_enabled: false`, and
`pairing_transport: "contract_pending"`. A successful state-changing command
emits `PairingV2Changed`; selected-contract-pending, expiry and unavailable
errors also emit the resulting snapshot when readable. A repeated request ID
returns its original response without reexecuting or emitting another event.
Cached responses are acknowledgments, not fresh liveness evidence; the client
must use a new request ID for a current snapshot. EOF/shutdown drops resources.
Watchdog expiry is reflected on the next request; no unsolicited idle IPC
notification is claimed. Clock rollback permanently poisons that controller.

Frozen closed snapshot: `apps/seamless-input/tests/fixtures/guided-snapshot.json`.
Interfaces for native UI tests are `SetupClock`, `DiscoveryBackend`,
`BackendFactory`, `SetupCommand`, `SetupSnapshot`, `SetupController`.
Native UI is not connected or changed.

## Discovery resource and privacy boundaries

`ConsentCatalog` is independent of the existing legacy unbounded `PeerCache`.
It keeps at most 20 locators and accepts at most eight address records each,
with local freshness at most 30 seconds and a 300-second consent window. Zero
TTL, malformed rendezvous, unspecified/multicast/broadcast endpoints or zero
ports are rejected. Identical observations refresh one handle; metadata/address
drift allocates a new handle. Version 1 may be visible but is not selectable;
there is no negotiation, automatic downgrade or legacy fallback.

`GuidedMdns` uses the existing service type and accepts only a 32-hex opaque
instance with matching opaque `.local.` hostname, exactly the two existing TXT
fields `v` and `pairable`, canonical supported version text and a bounded address
set. Unknown/additional metadata is dropped. It exposes no publication or
connect method. **The application does not advertise pairability**, since no
reviewed provisional listener exists yet. Test publication is synthetic and
restricted to loopback/custom-port discovery.

Each adapter poll drains at most 16 monitor and 16 service events. Catalogue
overflow/malformed peers are dropped without displacing existing peers. Backend
errors, disconnected/stopped browse channels, or an injected oversized batch
close the controller's backend and return an error, not a successful empty
result. A dedicated cancellation watchdog requests browse stop and daemon
shutdown after 300 seconds even if no further UI/control request arrives. Drop
also cancels and joins that watchdog; shutdown is through mdns-sd's command
API, not a claim of independently verified kernel socket destruction.

These are **application-owned storage/work bounds**, not a hard cap on all DNS
daemon memory or OS packets. The locked mdns-sd 0.21.5 library owns its internal
DNS cache and bounded event queues; no complete internal-cache/flood memory
bound is claimed. This dependency boundary needs resource audit before release.
The code neither measures a peer's network reachability nor authenticates its
advertisement. All selected endpoints remain untrusted until a future reviewed
transport binding and bilateral SAS flow complete.

`OsSetupClock` measures elapsed `std::time::Instant` from one immutable local
origin, checked into u64 milliseconds. It is not UTC or a boot identifier; no
cross-boot, wall-clock, suspend-duration, or durable-recovery timing claim is
made. Controller clocks and backends can be injected for deterministic tests.

## Gates intentionally left closed

The next reviewed addendum must specify all of:

1. CandidateRequest and subsequent wire framing, stream roles, ordering and
   exact size limits; provisional pairing and recovery ALPN values.
2. TLS exporter label, context, length and binding to the connection/session;
   handshake certificate verification without TOFU or accept-all admission.
3. How the two parties authenticate and durably accept each other's identity,
   attempt and revocation generations. Existing signed Hello/FC records do not
   carry this bootstrap. The first RecoveryProof cannot authorize its own
   expected generation values.
4. Atomic durable-authority context and proof/challenge consumption with the
   PendingStore CAS/tombstone domain. Do not derive remote generations from
   local counters or use two unsynchronized ledgers.
5. Independent byte-for-byte fixtures/negatives and review for those contracts.

Until then, there is no QUIC/TLS provisional emitter, no production
RecoveryAuthority provider/bootstrap, no real-network coordinator integration,
and no new phase-4 handshake/finalization crash schedule. The prior pure
coordinator, durable journal/recovery tests and 192 real subprocess I/O-error/
process-exit fault schedules are regression evidence only. They are not proof of
operational pairing or physical power-loss recovery.

Even after that addendum, promotion/admission/input/clipboard remain blocked
until their separate gates. External cryptographic audit, actual Mac/Windows
interoperability, enterprise-network testing, native UI and release approval
remain outstanding.

## Verification handoff — 2026-10-16

Isolated worktree: `.worktrees/guided-setup-foundations`; baseline phase 3
`e3576697b343544a8f1d587dc3fcd676d909cc80`. Offline macOS/aarch64 verification:

- Default workspace: **220 passed, 0 failed, 2 existing ignored subprocess helpers**.
- Application experimental workspace: **292 passed, 0 failed, 2 existing ignored
  subprocess helpers**, including the prior 192 real subprocess fault schedules.
- Default and experimental `clippy --workspace --all-targets -- -D warnings`:
  passed. `cargo fmt --all --check` and `git diff --check`: passed.
- Ten separate restored mutants were killed by the expected assertion: missing
  consent; capacity 21; inclusive expiry; current-handle bypass; extra TXT
  acceptance; cross-controller scope bypass; closed-state clock rollback bypass;
  retained backend after cancellation; batch size 33; successful closed transport
  result. Raw commands, mutation deltas and failure output are in
  `docs/qa/guided-discovery-boundary-evidence.json`.
- Real new discovery evidence: custom-port IPv4 loopback resolve and goodbye;
  idle-watchdog daemon stop. Controller faults are injected backend failure,
  oversized batch and clock rollback, not a new phase-4 crash schedule.
- Test-first RED was observed for the absent catalogue/controller modules and
  mDNS adapter/parser; a behavioral restart RED exposed handle reuse across
  controller lifetimes before scope binding was added. IPC behavior RED was
  re-observed with its dispatch disabled after correcting the harness to allow
  the existing control ownership lock; restored dispatch then passed.

Frozen closed-snapshot SHA-256:
`3684c8f8da537874e37743175ab63d274af2df0e69073a77477c3f5dcd76353e`.
No crypto/transport fixture or PendingStore source changed in this slice.
No native Windows build/runtime, LAN cross-machine pairing, UI, authentication,
policy effectiveness or release readiness is implied by these test results.
