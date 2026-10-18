using ControlShiftF12App;
using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class WindowsUiChildOwnerTests
{
    [Fact]
    public async Task Owned_child_drains_more_than_two_mebibytes_of_stderr_before_stdout()
    {
        var executable = FindProbeExecutable();
        var environment = Environment.GetEnvironmentVariables()
            .Keys.Cast<object>()
            .ToDictionary(
                key => key.ToString()!,
                key => Environment.GetEnvironmentVariable(key.ToString()!)
            );
        var spec = new ChildLaunchSpec(executable, [], environment!);
        await using var owner = await WindowsUiChildOwner.StartAsync(spec);

        var session = await owner.ReadInitialProjectionAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.NotNull(session.Snapshot);
        await owner.CloseAsync();
        Assert.True(owner.HasExited);
    }

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

        var browsing = await owner.StartDiscoveryAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("browsing", browsing.Snapshot!.State);
        Assert.Empty(browsing.Snapshot.Nearby);
        Assert.False(browsing.Snapshot.InputEnabled);
        Assert.False(browsing.Snapshot.ClipboardEnabled);

        var stopped = await owner.StopDiscoveryAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("not_started", stopped.Snapshot!.State);
        Assert.Empty(stopped.Snapshot.Nearby);
        var previousGeneration = stopped.Snapshot.Generation;
        var restarted = await owner.StartDiscoveryAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("browsing", restarted.Snapshot!.State);
        Assert.True(restarted.Snapshot.Generation > previousGeneration);
        for (var refresh = 0; refresh < 2; refresh++)
        {
            previousGeneration = owner.Session.Snapshot!.Generation;
            var refreshed = await owner.RefreshAsync(TimeSpan.FromSeconds(5));
            Assert.True(refreshed.Snapshot!.Generation > previousGeneration);
            Assert.Equal("browsing", refreshed.Snapshot.State);
        }
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

    private static string FindProbeExecutable()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(
                current.FullName,
                "native", "windows", "ControlShiftF12App.StderrProbe", "bin", "Debug", "net8.0",
                "ControlShiftF12App.StderrProbe.exe"
            );
            if (File.Exists(candidate)) return candidate;
            current = current.Parent;
        }
        throw new Xunit.Sdk.XunitException("The stderr probe executable is unavailable.");
    }
}
