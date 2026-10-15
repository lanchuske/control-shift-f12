# SeamlessInput MVP Specification

## Goal

SeamlessInput is a free, open-source, peer-to-peer terminal application that
lets one keyboard and mouse move across multiple macOS and Windows computers and
synchronizes text and PNG clipboards.

## Symmetric peer model

- Every machine runs the same `seamless-input start` command.
- Every machine can capture local input, inject remote input, accept a connection,
  and initiate one. There are no permanent server or client roles.
- Peers on the same LAN are discovered with mDNS/DNS-SD under
  `_seamless-input._udp.local`, matching the QUIC transport.
- A deterministic node-ID tie-breaker collapses simultaneous connections to one
  authenticated session.
- If discovery is unavailable, users may connect by address. All peers use the
  same native QUIC channel; there is no SSH or external remote-control dependency.

## Pairing

- `seamless-input pair new` creates a short-lived six-word code and advertises
  only that the node is pairable, never the code itself. It also prints the
  temporary LAN address locally for manual fallback.
- `seamless-input pair <six-word-code>` on another discovered machine runs a
  password-authenticated key exchange and mutually pins both device identities.
- If mDNS is unavailable, `seamless-input pair <six-word-code> --address
  <host:port>` runs the same authenticated exchange against the printed address.
- Pairing is one-time. Later connections use mutual TLS 1.3 identities stored in
  the current user's config directory.
- `seamless-input peers` lists paired, available, unavailable, and incompatible
  peers without exposing keys or clipboard data.
- `seamless-input unpair <peer>` removes only that trust relationship.

## User experience

- `seamless-input tui` shows discovered and paired machines as movable screen
  tiles. Arrow keys place a selected screen above, below, left, or right of
  another screen.
- A screen has at most one neighbor per cardinal edge. Reciprocal edges are
  generated atomically; invalid overlaps are rejected.
- Moving the pointer through a shared edge transfers control to that peer with
  proportional vertical or horizontal coordinate mapping.
- Keyboard input follows the peer containing the active pointer.
- Text and PNG clipboard contents synchronize in both directions with loop
  suppression.
- An emergency chord always returns control to the local machine.

## Commands

```text
seamless-input start
seamless-input pair new
seamless-input pair <six-word-code>
seamless-input pair <six-word-code> --address <host:port>
seamless-input peers
seamless-input unpair <peer>
seamless-input tui
seamless-input doctor
seamless-input config show
seamless-input config path
```

## Supported topology

- Mixed macOS and Windows peers; two or more machines.
- Cardinal topology graph with cycles allowed and diagonal-only placement denied.
- Different display sizes and scaling factors map proportionally.
- A peer may have several displays; the TUI treats each display as a tile owned
  by one peer.

## Installation and permissions

- Installation is one copyable terminal command per operating system. There is
  no graphical wizard, `.pkg`, `.dmg`, `.msi`, or machine-wide package.
- The bootstrap command downloads a pinned release installer over HTTPS; the
  installer selects the native binary, verifies its published SHA-256 checksum,
  installs it in the current user's directory, and updates only the user PATH.
- Running the command again is idempotent. `seamless-input uninstall` removes
  the user installation and its PATH entry without deleting paired identities
  unless the user explicitly requests a full data removal.
- macOS installer writes the binary under `~/.local/bin` and adds that directory
  to the user's shell PATH when missing.
- Windows installer writes under `%LOCALAPPDATA%\\SeamlessInput\\bin` and updates
  only the user's PATH environment value.
- No administrator elevation, system PATH, service, driver, scheduled task,
  firewall rule, or policy change is requested.
- On first use, macOS explains and requests only the user-granted Accessibility
  permission required for global input capture and injection. It never requests
  an administrator password or attempts to bypass a denial.
- Clipboard access follows the operating system's consent model. If macOS asks
  before programmatic General pasteboard access, the user may allow or deny it;
  denial disables clipboard sync without affecting pairing or local input.
- Windows uses the current user's desktop and `SendInput` without elevation.
- Secure desktop, UAC, login screens, elevated applications, and other users are
  outside scope.
- Enterprise policy can still block execution, discovery, or networking. The
  product reports the restriction and never attempts to bypass it.

## Security and privacy

- Pairing uses a PAKE so the six-word code is not usable as a long-term key and
  is not exposed to passive observers.
- Normal transport is QUIC with TLS 1.3 and mutual pinned identities. Both peers
  send discovery probes before connection so ordinary stateful firewalls can
  associate replies with peer-originated traffic; policy blocks still fail closed.
- Clipboard data is memory-only, limited to 1 MiB text or 8 MiB PNG,
  hash-deduplicated, and never logged.
- Input frames have monotonic sequence numbers; stale and duplicate frames fail
  closed.
- Only the peer currently selected by the topology controller may inject input.
- Disconnect, timeout, permission loss, or exit releases all modifiers and
  returns control locally.

## Architecture

One Rust workspace produces one `seamless-input` binary and focused libraries:

- `protocol`: bounded MessagePack frames and capability negotiation.
- `core`: peer registry, topology graph, pointer mapping, session state, clipboard dedupe.
- `discovery`: mDNS publish/browse plus manual-address fallback.
- `transport`: PAKE pairing and mutually authenticated QUIC/TLS peer sessions.
- `platform-macos`: CoreGraphics input and macOS clipboard.
- `platform-windows`: Windows hooks/`SendInput` and Windows clipboard.
- `cli`: commands, diagnostics, and Ratatui topology interface.

## Non-goals

- Screenshots, general file transfer, audio, video, remote desktop, web UI,
  mobile platforms, Linux, login-screen control, and enterprise-policy evasion.

## Open-source governance

- The repository is public under the MIT license and welcomes issues, design
  discussions, documentation, tests, and pull requests.
- Contributions must preserve this specification's scope and security model.
  A feature request outside the MVP belongs in a separate proposal and cannot
  silently expand an implementation pull request.
- Every behavior change requires tests, platform impact notes, and an explicit
  statement about administrator privileges, user consent, networking, and data
  handling.
- Maintainers review and merge changes; public collaboration never grants
  direct write access or bypasses CI, review, or release evidence.
- GitHub Discussions receives questions, ideas, hardware compatibility reports,
  and open-ended product feedback. Confirmed reproducible work is promoted to a
  scoped Issue rather than leaving Discussions as an execution backlog.
- Structured Issue Forms collect bugs and feature proposals. Security findings
  use GitHub private vulnerability reporting and must not be filed publicly.
- `seamless-input doctor --report` produces a local, redacted, copyable report;
  it never uploads automatically and excludes clipboard contents, keys, user
  names, addresses, and stable machine identifiers.

## Acceptance evidence

- Unit tests cover framing limits, PAKE expiry/replay, identity pinning, discovery
  dedupe, topology validation, pointer mapping, sequences, modifier release, and
  clipboard-loop prevention.
- TUI snapshot tests cover every cardinal placement and multi-display peers.
- Installer tests prove user-only destinations and PATH updates with no elevation.
- Clean-user smoke tests prove each operating system installs from exactly one
  terminal command, verifies the checksum, works from a new terminal, upgrades
  idempotently, and uninstalls without a GUI or administrator prompt.
- Platform integration tests prove normal-session capture/injection and safe
  permission-denied behavior, including a degraded mode when macOS Accessibility
  or pasteboard consent is unavailable.
- A two-machine E2E proves discovery, pairing, reconnect, pointer crossing both
  ways, typing, text clipboard, PNG clipboard, and safe disconnect.
- A mixed three-machine E2E proves multi-peer routing.
- Results are recorded as PASS, FAIL, or NO MEDIDO per acceptance item.
