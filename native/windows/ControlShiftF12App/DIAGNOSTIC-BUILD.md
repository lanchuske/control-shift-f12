# Windows diagnostic build

This branch adds local JSONL diagnostics for the Windows host-to-engine lifecycle. It does not
change pairing authority, retry commands, enable sharing, or record protocol payloads.

By default, the host writes one file per launch under:

`%LOCALAPPDATA%\ControlShiftF12\Diagnostics\host-<pid>-<utc>.jsonl`

For an isolated QA run, set `CSF12_DIAGNOSTIC_LOG_DIR` to a new directory inside the approved QA
state root before starting `ControlShiftF12App.exe`.

The schema contains only fixed enums and numeric metadata: timestamps, event/operation categories,
process ID, session phase, projection generation, byte counts, exit code, exception category,
terminal reason, and a fixed stderr category. It never writes frame bodies, candidate handles,
verification words, identities, keys, configuration values, environment values, or raw stderr.

Events distinguish expected polling silence (`operation=observe`) from command timeouts such as
`operation=start_discovery`. A subsequent `session_terminal` with
`terminal_reason=host_command_failure` shows that the host disabled pairing while the child process
was still owned by the launcher. `read_end_of_file`, `invalid_frame`, and classified stderr remain
separate outcomes.
