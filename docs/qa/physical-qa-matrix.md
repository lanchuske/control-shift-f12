# Control Shift F12 physical QA matrix

This matrix is the single authoritative record for release-candidate physical
QA on one real Mac and one real Windows PC. Passing CI, a successful build, a
signature produced by CI, or a remote process check does not make any row pass.

Allowed status values are **PASS**, **FAIL**, and **NOT MEASURED**. Start every
row as **NOT MEASURED** and change it only after observing the expected result
on the named machines. **Every row in this matrix blocks promotion to a stable
or generally available release** until it is PASS. NOT MEASURED rows are
allowed in an explicitly labeled QA Preview whose purpose is to run this
physical matrix, but that preview must not be represented as physically
validated. A FAIL also blocks stable/GA promotion and must be resolved before
the affected behavior can be represented as working.

For every row:

- **PASS** requires a concise non-sensitive observation plus an evidence
  reference, such as a screenshot filename, photo filename, or test-session
  note.
- **FAIL** requires the observed failure, a non-sensitive evidence reference,
  and a follow-up issue link.
- **NOT MEASURED** requires a reason. An empty evidence/gap cell is invalid in
  a completed test record.

## Test record

- Release/tag:
- Reviewed commit:
- Mac model and macOS version:
- Windows model and Windows version:
- Network used (private/home/work; do not record addresses):
- Tester:
- Date:

Do not record pairing codes, clipboard contents, usernames, IP addresses,
tokens, keys, or stable machine identifiers. Stop immediately if local control
cannot be recovered with **Control+Shift+F12**.

## 0. Candidate artifacts and provenance

Record the exact downloaded filenames and full SHA-256 values; do not shorten
hashes. Verify the downloaded files, not similarly named local copies.

- Mac DMG exact filename:
- Mac DMG full SHA-256:
- Mac observed Developer ID and notarization result:
- Windows installer exact filename:
- Windows installer full SHA-256:
- Windows observed Authenticode publisher and timestamp result:

| ID | Platform | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| ART-01 | Mac | Identify the candidate | Exact DMG filename, release tag, source commit, download URL, and full SHA-256 are recorded and agree with the release metadata | NOT MEASURED | Reason: candidate artifact not selected |
| ART-02 | Mac | Verify signing and notarization | After mounting the exact recorded DMG, `codesign --verify --deep --strict` and `spctl --assess --type execute` succeed on its app, and `xcrun stapler validate` succeeds on the DMG; the observed Developer ID identity is recorded without certificate secrets | NOT MEASURED | Reason: physical candidate not verified |
| ART-03 | Windows | Identify the candidate | Exact installer filename, release tag, source commit, download URL, and full SHA-256 are recorded and agree with the release metadata | NOT MEASURED | Reason: candidate artifact not selected |
| ART-04 | Windows | Verify Authenticode | `Get-AuthenticodeSignature` reports `Valid` for the exact recorded installer; the observed publisher and timestamp status are recorded; the full SHA-256 from `Get-FileHash` matches release metadata | NOT MEASURED | Reason: physical candidate not verified |

## 1. Installation and local experience

| ID | Platform | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| MAC-01 | Mac | Open the universal DMG | The disk image opens without a corruption or unidentified-developer warning | NOT MEASURED | Reason: physical QA not run |
| MAC-02 | Mac | Install from the DMG | `Control Shift F12.app` can be copied to Applications without administrator access | NOT MEASURED | Reason: physical QA not run |
| MAC-03 | Mac | Product identity | The app, Finder entry, Dock/menu entry, and dialogs use the Control Shift F12 name and product icon | NOT MEASURED | Reason: physical QA not run |
| MAC-04 | Mac | First launch | A visible first-start window appears; the app does not silently exit | NOT MEASURED | Reason: physical QA not run |
| MAC-05 | Mac | Permissions | The app explains the required Accessibility permission and opens the correct macOS settings pane | NOT MEASURED | Reason: physical QA not run |
| MAC-06 | Mac | Grant Accessibility while the app remains open | The app detects the newly granted permission automatically, visibly continues to its ready state, and does not require a relaunch | NOT MEASURED | Reason: physical QA not run |
| MAC-07 | Mac | Permission denied | Declining Accessibility leaves local input usable and shows a clear, recoverable state | NOT MEASURED | Reason: physical QA not run |
| MAC-08 | Mac | Relaunch | Launching from Applications starts the app again without reinstalling | NOT MEASURED | Reason: physical QA not run |
| MAC-09 | Mac | Dependency-free, user-only operation | Install and first start require no separate runtime/toolchain, administrator elevation, service, driver, firewall or policy change, or SSH | NOT MEASURED | Reason: physical QA not run |
| MAC-10 | Mac | Uninstall | Removing the app from Applications removes the product without changing system policy or unrelated files | NOT MEASURED | Reason: physical QA not run |
| WIN-01 | Windows | Run the signed installer | Setup completes on a standard user account and identifies the verified publisher | NOT MEASURED | Reason: physical QA not run |
| WIN-02 | Windows | Product identity | Setup, Installed apps, Start menu, desktop shortcut, dialogs, and uninstaller use the Control Shift F12 name and product icon | NOT MEASURED | Reason: physical QA not run |
| WIN-03 | Windows | First launch | Finishing setup or opening the main shortcut visibly starts the product; it does not silently exit | NOT MEASURED | Reason: physical QA not run |
| WIN-04 | Windows | Main shortcut | The Start menu/desktop shortcut starts the running product, not a help-only command | NOT MEASURED | Reason: physical QA not run |
| WIN-05 | Windows | Diagnostics shortcut | The diagnostics entry opens visible results without starting remote control | NOT MEASURED | Reason: physical QA not run |
| WIN-06 | Windows | Relaunch | Opening the shortcut again leaves one healthy running instance | NOT MEASURED | Reason: physical QA not run |
| WIN-07 | Windows | Dependency-free, user-only operation | Install and first start require no separate runtime/toolchain, administrator elevation, service, driver, firewall or policy change, or SSH | NOT MEASURED | Reason: physical QA not run |
| WIN-08 | Windows | Uninstall | Installed apps removes the product and its shortcuts without changing system policy or unrelated files | NOT MEASURED | Reason: physical QA not run |

## 2. Safety shortcut and permissions

Run these checks before pairing or transferring control.

| ID | Direction | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| SAFE-01 | Local Mac | Press Control+Shift+F12 | The Control Shift F12 surface opens or local control is recovered, with no unrelated system action | NOT MEASURED | Reason: physical QA not run |
| SAFE-02 | Local Windows | Press Control+Shift+F12 | The Control Shift F12 surface opens or local control is recovered, with no unrelated system action | NOT MEASURED | Reason: physical QA not run |
| SAFE-03 | Mac receiving input | Press Control+Shift+F12 during a session | The session releases input and returns reliable local control to the Mac | NOT MEASURED | Reason: physical QA not run |
| SAFE-04 | Windows receiving input | Press Control+Shift+F12 during a session | The session releases input and returns reliable local control to Windows | NOT MEASURED | Reason: physical QA not run |
| SAFE-05 | Both | Permission unavailable or revoked | The affected direction is blocked clearly; the other machine and local control remain usable | NOT MEASURED | Reason: physical QA not run |

## 3. Pairing and topology

| ID | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|
| PAIR-01 | Discover the other machine on the same network | Each machine shows the intended peer once, with enough non-sensitive information to distinguish it | NOT MEASURED | Reason: physical QA not run |
| PAIR-02 | Pair with the displayed code | Both sides show the same intent and reach an authenticated paired state only after confirmation | NOT MEASURED | Reason: physical QA not run |
| PAIR-03 | Reject an incorrect code | Pairing fails safely and can be retried without restarting either app | NOT MEASURED | Reason: physical QA not run |
| PAIR-04 | Manual fallback | When discovery is unavailable, the documented manual path pairs the same two machines without weakening security | NOT MEASURED | Reason: physical QA not run |
| PAIR-05 | Configure relative screen position | The selected Mac/Windows layout is visible and persists for the active test | NOT MEASURED | Reason: physical QA not run |

## 4. Bidirectional input and clipboard

Use disposable, non-sensitive sample text and an ordinary test image. Confirm
the effect on the physical destination screen; internal logs alone are not
evidence.

| ID | Direction | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| IO-01 | Mac to Windows | Cross the configured edge | The cursor appears at the corresponding Windows edge without sticking or jumping to an unrelated position | NOT MEASURED | Reason: physical QA not run |
| IO-02 | Mac to Windows | Move and click | Pointer motion and left/right clicks affect only the intended Windows target | NOT MEASURED | Reason: physical QA not run |
| IO-03 | Mac to Windows | Type and use modifiers | Text, Shift, Control, Alt/Option, and key-up state arrive correctly without stuck keys | NOT MEASURED | Reason: physical QA not run |
| IO-04 | Mac to Windows | Copy and paste text | The disposable text arrives once and unchanged | NOT MEASURED | Reason: physical QA not run |
| IO-05 | Mac to Windows | Copy and paste an image | The test image arrives once and remains usable | NOT MEASURED | Reason: physical QA not run |
| IO-06 | Windows to Mac | Cross the configured edge | The cursor appears at the corresponding Mac edge without sticking or jumping to an unrelated position | NOT MEASURED | Reason: physical QA not run |
| IO-07 | Windows to Mac | Move and click | Pointer motion and left/right clicks affect only the intended Mac target | NOT MEASURED | Reason: physical QA not run |
| IO-08 | Windows to Mac | Type and use modifiers | Text, Shift, Control, Alt/Option, and key-up state arrive correctly without stuck keys | NOT MEASURED | Reason: physical QA not run |
| IO-09 | Windows to Mac | Copy and paste text | The disposable text arrives once and unchanged | NOT MEASURED | Reason: physical QA not run |
| IO-10 | Windows to Mac | Copy and paste an image | The test image arrives once and remains usable | NOT MEASURED | Reason: physical QA not run |

## 5. Crossing, return, and recovery

| ID | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|
| FLOW-01 | Cross Mac to Windows and return | The cursor crosses and returns through the configured edges without becoming trapped | NOT MEASURED | Reason: physical QA not run |
| FLOW-02 | Cross Windows to Mac and return | The cursor crosses and returns through the configured edges without becoming trapped | NOT MEASURED | Reason: physical QA not run |
| FLOW-03 | Repeat edge crossings | Ten alternating crossings complete without drift, duplicate transitions, or lost local control | NOT MEASURED | Reason: physical QA not run |
| FLOW-04 | Disconnect the active peer | Held buttons/modifiers are released and control returns locally on both machines | NOT MEASURED | Reason: physical QA not run |
| FLOW-05 | Reconnect after an app restart | The peer becomes usable again without reinstalling or re-pairing unless the UI explicitly requires it | NOT MEASURED | Reason: physical QA not run |
| FLOW-06 | Reconnect after a brief network interruption | The apps report the interruption, recover safely, and do not send stale input | NOT MEASURED | Reason: physical QA not run |
| FLOW-07 | Emergency recovery | Control+Shift+F12 recovers local control during an intentional interrupted-transfer scenario | NOT MEASURED | Reason: physical QA not run |

## Result

- Overall result: **NOT MEASURED**
- Blocking failures:
- Rows not measured and why:
- Follow-up issue links:

Overall **PASS** requires every row above to be **PASS** with the required
evidence. All rows block promotion to stable/GA and any claim of complete
physical validation. NOT MEASURED rows may remain only in an explicitly
labeled QA Preview used to execute this matrix; they must stay visible and
cannot be represented as passing coverage. Any FAIL must remain explicit, link
to its follow-up issue, and blocks the affected behavior from being represented
as working.
