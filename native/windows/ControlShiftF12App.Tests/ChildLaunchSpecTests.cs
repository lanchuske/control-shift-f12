using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class ChildLaunchSpecTests
{
    [Fact]
    public void Package_child_uses_only_the_reviewed_command_and_allowlisted_environment()
    {
        var environment = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = @"C:\Windows",
            ["WINDIR"] = @"C:\Windows",
            ["TEMP"] = @"C:\Users\Darío\AppData\Local\Temp",
            ["TMP"] = @"C:\Users\Darío\AppData\Local\Temp",
            ["LOCALAPPDATA"] = @"C:\Users\Darío\AppData\Local",
            ["APPDATA"] = @"C:\Users\Darío\AppData\Roaming",
            ["USERPROFILE"] = @"C:\Users\Darío",
            ["PATH"] = @"C:\Windows\System32",
            ["CSF12_G4_TEST_PEER_ADDRESS"] = "must-not-pass",
            ["CSF12_G4_TEST_RENDEZVOUS"] = "must-not-pass",
            ["UNRELATED_SECRET"] = "must-not-pass",
        };

        var spec = ChildLaunchSpec.Create(
            packageRoot: @"C:\Program Files\Control Shift F12",
            childPath: @"C:\Program Files\Control Shift F12\Resources\seamless-input.exe",
            environment: environment
        );

        Assert.Equal(["control", "--ui-stdio"], spec.Arguments);
        Assert.True(new HashSet<string>(spec.Environment.Keys, StringComparer.OrdinalIgnoreCase).SetEquals([
            "SystemRoot", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PATH",
        ]));
        Assert.Equal(@"C:\Windows", spec.Environment["SystemRoot"]);
        Assert.Equal(@"C:\Users\Darío\AppData\Roaming", spec.Environment["APPDATA"]);
    }

    [Fact]
    public void Child_outside_the_package_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => ChildLaunchSpec.Create(
            packageRoot: @"C:\Program Files\Control Shift F12",
            childPath: @"C:\Users\Darío\Downloads\seamless-input.exe",
            environment: new Dictionary<string, string?>()
        ));
    }
}
