using ControlShiftF12App;
using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class WindowsUiChildOwnerTests
{
    [Fact]
    public async Task Owned_child_returns_a_valid_initial_projection_and_is_reaped_on_close()
    {
        var executable = FindEngineExecutable();
        var root = new FileInfo(executable).Directory!.Parent!.Parent!.FullName;
        var environment = Environment.GetEnvironmentVariables()
            .Keys.Cast<object>()
            .ToDictionary(
                key => key.ToString()!,
                key => Environment.GetEnvironmentVariable(key.ToString()!)
            );
        var spec = ChildLaunchSpec.Create(root, executable, environment);
        await using var owner = await WindowsUiChildOwner.StartAsync(spec);

        var session = await owner.ReadInitialProjectionAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.NotNull(session.Snapshot);
        await owner.CloseAsync();
        Assert.True(owner.HasExited);
        Assert.Equal(ChildSessionPhase.Terminal, owner.Session.State.Phase);
    }

    private static string FindEngineExecutable()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, "target", "debug", "seamless-input.exe");
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new Xunit.Sdk.XunitException("The target Windows engine executable is unavailable.");
    }
}
