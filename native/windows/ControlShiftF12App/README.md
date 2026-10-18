# Control Shift F12 WinForms host manifest

`ControlShiftF12App.csproj` is a non-shipping WinForms host declaration. Its
intended application identifier is `ai.lanchuske.control-shift-f12.windows-host`.
It contains no C# source and must not be built or launched until the
parent/child boundary has a reviewed typed adapter and the Windows host
toolchain is verified.

When implementation is admitted, it uses WinForms and the argument-array,
anonymous-inherited-pipe boundary described in [the native host
record](../../README.md). It does not create a socket, browser surface,
terminal fallback, or shell command.
