# Control Shift F12 physical QA matrix

Use this matrix for a release candidate installed on one real Mac and one real
Windows PC. It records physical behavior; passing CI, a successful build, or a
remote process check does not make any row pass.

Allowed status values are **PASS**, **FAIL**, and **NOT MEASURED**. Start every
row as **NOT MEASURED** and change it only after observing the expected result
on the named machines.

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

## 1. Installation and local experience

| ID | Platform | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| MAC-01 | Mac | Open the universal DMG | The disk image opens without a corruption or unidentified-developer warning | NOT MEASURED | |
| MAC-02 | Mac | Install from the DMG | `Control Shift F12.app` can be copied to Applications without administrator access | NOT MEASURED | |
| MAC-03 | Mac | Product identity | The app, Finder entry, Dock/menu entry, and dialogs use the Control Shift F12 name and product icon | NOT MEASURED | |
| MAC-04 | Mac | First launch | A visible first-start window appears; the app does not silently exit | NOT MEASURED | |
| MAC-05 | Mac | Permissions | The app explains the required Accessibility permission and opens the correct macOS settings pane | NOT MEASURED | |
| MAC-06 | Mac | Permission denied | Declining Accessibility leaves local input usable and shows a clear, recoverable state | NOT MEASURED | |
| MAC-07 | Mac | Relaunch | Launching from Applications starts the app again without reinstalling | NOT MEASURED | |
| MAC-08 | Mac | Uninstall | Removing the app from Applications removes the product without changing system policy or unrelated files | NOT MEASURED | |
| WIN-01 | Windows | Run the signed installer | Setup completes on a standard user account and identifies the verified publisher | NOT MEASURED | |
| WIN-02 | Windows | Product identity | Setup, Installed apps, Start menu, desktop shortcut, dialogs, and uninstaller use the Control Shift F12 name and product icon | NOT MEASURED | |
| WIN-03 | Windows | First launch | Finishing setup or opening the main shortcut visibly starts the product; it does not silently exit | NOT MEASURED | |
| WIN-04 | Windows | Main shortcut | The Start menu/desktop shortcut starts the running product, not a help-only command | NOT MEASURED | |
| WIN-05 | Windows | Diagnostics shortcut | The diagnostics entry opens visible results without starting remote control | NOT MEASURED | |
| WIN-06 | Windows | Relaunch | Opening the shortcut again leaves one healthy running instance | NOT MEASURED | |
| WIN-07 | Windows | Uninstall | Installed apps removes the product and its shortcuts without changing system policy or unrelated files | NOT MEASURED | |

## 2. Safety shortcut and permissions

Run these checks before pairing or transferring control.

| ID | Direction | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| SAFE-01 | Local Mac | Press Control+Shift+F12 | The Control Shift F12 surface opens or local control is recovered, with no unrelated system action | NOT MEASURED | |
| SAFE-02 | Local Windows | Press Control+Shift+F12 | The Control Shift F12 surface opens or local control is recovered, with no unrelated system action | NOT MEASURED | |
| SAFE-03 | Mac receiving input | Press Control+Shift+F12 during a session | The session releases input and returns reliable local control to the Mac | NOT MEASURED | |
| SAFE-04 | Windows receiving input | Press Control+Shift+F12 during a session | The session releases input and returns reliable local control to Windows | NOT MEASURED | |
| SAFE-05 | Both | Permission unavailable or revoked | The affected direction is blocked clearly; the other machine and local control remain usable | NOT MEASURED | |

## 3. Pairing and topology

| ID | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|
| PAIR-01 | Discover the other machine on the same network | Each machine shows the intended peer once, with enough non-sensitive information to distinguish it | NOT MEASURED | |
| PAIR-02 | Pair with the displayed code | Both sides show the same intent and reach an authenticated paired state only after confirmation | NOT MEASURED | |
| PAIR-03 | Reject an incorrect code | Pairing fails safely and can be retried without restarting either app | NOT MEASURED | |
| PAIR-04 | Manual fallback | When discovery is unavailable, the documented manual path pairs the same two machines without weakening security | NOT MEASURED | |
| PAIR-05 | Configure relative screen position | The selected Mac/Windows layout is visible and persists for the active test | NOT MEASURED | |

## 4. Bidirectional input and clipboard

Use disposable, non-sensitive sample text and an ordinary test image. Confirm
the effect on the physical destination screen; internal logs alone are not
evidence.

| ID | Direction | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|---|
| IO-01 | Mac to Windows | Cross the configured edge | The cursor appears at the corresponding Windows edge without sticking or jumping to an unrelated position | NOT MEASURED | |
| IO-02 | Mac to Windows | Move and click | Pointer motion and left/right clicks affect only the intended Windows target | NOT MEASURED | |
| IO-03 | Mac to Windows | Type and use modifiers | Text, Shift, Control, Alt/Option, and key-up state arrive correctly without stuck keys | NOT MEASURED | |
| IO-04 | Mac to Windows | Copy and paste text | The disposable text arrives once and unchanged | NOT MEASURED | |
| IO-05 | Mac to Windows | Copy and paste an image | The test image arrives once and remains usable | NOT MEASURED | |
| IO-06 | Windows to Mac | Cross the configured edge | The cursor appears at the corresponding Mac edge without sticking or jumping to an unrelated position | NOT MEASURED | |
| IO-07 | Windows to Mac | Move and click | Pointer motion and left/right clicks affect only the intended Mac target | NOT MEASURED | |
| IO-08 | Windows to Mac | Type and use modifiers | Text, Shift, Control, Alt/Option, and key-up state arrive correctly without stuck keys | NOT MEASURED | |
| IO-09 | Windows to Mac | Copy and paste text | The disposable text arrives once and unchanged | NOT MEASURED | |
| IO-10 | Windows to Mac | Copy and paste an image | The test image arrives once and remains usable | NOT MEASURED | |

## 5. Crossing, return, and recovery

| ID | Check | Expected observable result | Status | Evidence / gap |
|---|---|---|---|---|
| FLOW-01 | Cross Mac to Windows and return | The cursor crosses and returns through the configured edges without becoming trapped | NOT MEASURED | |
| FLOW-02 | Cross Windows to Mac and return | The cursor crosses and returns through the configured edges without becoming trapped | NOT MEASURED | |
| FLOW-03 | Repeat edge crossings | Ten alternating crossings complete without drift, duplicate transitions, or lost local control | NOT MEASURED | |
| FLOW-04 | Disconnect the active peer | Held buttons/modifiers are released and control returns locally on both machines | NOT MEASURED | |
| FLOW-05 | Reconnect after an app restart | The peer becomes usable again without reinstalling or re-pairing unless the UI explicitly requires it | NOT MEASURED | |
| FLOW-06 | Reconnect after a brief network interruption | The apps report the interruption, recover safely, and do not send stale input | NOT MEASURED | |
| FLOW-07 | Emergency recovery | Control+Shift+F12 recovers local control during an intentional interrupted-transfer scenario | NOT MEASURED | |

## Result

- Overall result: **NOT MEASURED**
- Blocking failures:
- Rows not measured and why:
- Follow-up issue links:

Overall **PASS** requires every release-blocking row above to be **PASS**.
Any **FAIL** keeps the candidate out of stable release. Any **NOT MEASURED**
must remain explicit and cannot be represented as passing coverage.
