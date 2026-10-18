# Provisional transport owner — phase5 security correction

This document supersedes the ownership/API sections and verification verdict of
[the initial slice report](provisional-transport-boundary.md). Baseline
`c283e39cdadb434167466d1b9911f2b620bec12f` received NO-GO for arbitrary QUIC
connection adoption and caller-selected replay registries. Both were reproduced
with failing behavior tests before changing the implementation.

## Sealed boundary

`provisional_tls::ProvisionalEndpoint::bind(address, certificate, private_key)`
builds the strict configurations **inside** the module and opens the endpoint.
Its only connection creation APIs are `connect(peer)` and `accept()`, each with
a 30-second absolute completion timeout. They return an opaque, non-Clone
`ProvisionalChannel`. Raw endpoint/connection fields and the configuration
factory are private. No raw-connection adoption, config replacement, caller
generation, registry argument, or public channel constructor exists.

Strict TLS1.3/mutual Ed25519 profile, CertificateVerify, exact ALPN, disabled
early-data/resumption/tickets and existing flow-control bounds are preserved.
Every outgoing connection receives a fresh private client-certificate resolver
wrapper. Successful TLS alone is insufficient: the wrapper must have resolved
the client certificate for that connection's CertificateRequest. A server that
does not request client authentication is closed/rejected even with a valid
server leaf. A previous authenticated connection on the same endpoint cannot
supply that evidence. Incoming channels originate only from the private endpoint
configured with mandatory strict client-certificate authentication.

The existing public BindingInput remains a codec/fixture primitive, not a channel
capability or authentication assertion. It cannot reach the private process replay
owner or admit peers.

## One replay owner, local generations and scope revocation

A private OnceLock process singleton owns the replay registry and local generation
allocator. Every endpoint references that same owner; creating/dropping endpoints
cannot create, inject, clear, or reset a registry. The registry type and consume
method are not external APIs. Consumption is atomic, after binding verification,
capacity-bounded at 1024 with no eviction and fail-closed on poison/capacity.

The singleton assigns unique increasing local generations using checked atomic
updates. Exhaustion fails without wrapping. No remote generation or bilateral
symmetry is inferred. The canonical request/exporter/context/binding/replay schemas
and approved fixture bytes from dc3750b are unchanged.

A private scope mutex is shared by an endpoint and its channels. Drop revokes the
scope synchronously before requesting asynchronous QUIC closure. Bind holds the
same lock throughout validation/consumption, so binding and revocation have a
defined local ordering. Revoked or poisoned scope rejects even before a network
close notification. This extra boundary was introduced after a test reproduced
that Endpoint::close alone does not immediately change Connection::close_reason.

This is **process-local**, not durable recovery or cross-process global state.
Process restart still requires a new connection and fresh SAS flow (not emitted
here). The registry is intentionally not reset when an endpoint/consent scope ends;
capacity exhaustion fails closed until process restart. A future authorized
controller still must enforce user consent, listener/admission budgets and lease
expiry. This slice's endpoint lifetime is not proof of a UI consent gesture.

## Tests and TDD evidence

Before implementation, both attacks failed their intended rejection assertions:
(1) a valid unilateral TLS connection was accepted by public observe;
(2) two separately supplied registries accepted the same live binding.
Two initial compile-fail cases also failed because those old APIs compiled.
After sealing, tests retain the real no-client-auth server and external QUIC
client as an attack precondition, then prove the owned connect path rejects it.
External adoption/config mutation/registry construction/raw-endpoint replacement
and channel cloning are covered by five compile-fail tests.

Real transport tests moved under the module's test-only child so they can inspect
actual exporter/leaf/streams **without exposing production raw connection access**.
The existing two-process test now uses the owned connect/accept paths and still
passes; test-only stream choreography remains non-production.

Owner/provisional tests: **13 PASS, 1 ignored subprocess helper**; the helper is
invoked explicitly by the passing parent test. Five compile-fail tests PASS.
Replay concurrency/capacity tests remain and now exercise the private registry
as module tests. The singleton lifecycle test consumes a binding, closes its
endpoints, creates another endpoint and proves the same token remains consumed.

**21/21 mutants killed and restored**, with assertion failures or expected
compile-fail tests detecting a newly public API, not build errors:
leaf/nonce/rendezvous/ALPN, consumption/atomicity, exporter label/context,
CertificateVerify, frame size/trailing/record EOF, mandatory client auth,
fresh owner per endpoint, omitted CertificateRequest evidence, missing scope
guard/revocation, public registry/raw endpoint/config factory, generation reuse.

## Fresh verification verdict: slice PASS, workspace NOT GREEN

- Default full workspace, no fail-fast: **219 PASS, 1 FAIL, 2 ignored**.
- Experimental full workspace, no fail-fast: **318 PASS, 1 FAIL, 3 ignored**.
- The sole failure in each is the unchanged native macOS test
  `native_non_admin_permission_and_display_probe_is_safe` at
  `crates/platform-macos/tests/permissions.rs:310`: OS inventory returned an empty
  display list. It also failed in isolation. No platform source changed.
  Root cause of the host's empty inventory was not established; this report does
  not replace that observation with an assumed healthy native environment.
- Both full workspace/all-target clippy modes PASS with warnings denied.
- Formatting and diff whitespace checks PASS.
- Existing durable-journal fault schedules PASS in the experimental run.
  No new durable write boundary or live-pairing crash claim was added.

Full logs, initial REDs, mutations and commands:
[QA evidence](qa/provisional-transport-owner-evidence.json).
The initial slice's formerly green workspace evidence remains historical only;
this correction does **not** claim a globally green suite on the current host.

## Unchanged gates / next step

Feature remains off by default. The typed application/controller remains
`HandshakeEnvelopePending` and never instantiates the new endpoint. No 49e7137
reference, RecoveryAuthority, application handshake emitter, promotion, admission,
input or clipboard was added. No push, merge, CI, signing or publication.

Request independent review of this correction, and resolve/re-run the native
display verification separately before claiming workspace GO. Only after explicit
authorization should a separate delta consume 49e7137 for bilateral handshake.
External crypto audit, native OS persistence/interoperability, consent/resource
integration and release approval remain outstanding.
