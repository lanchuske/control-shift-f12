using ControlShiftF12App;
using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class WindowsUiChildOwnerTests
{
    [Fact]
    public async Task Dispose_releases_both_owned_resources_when_close_fails_and_preserves_failure()
    {
        var childDisposed = false;
        var gateDisposed = false;
        var expected = new InvalidOperationException("close failed");

        var actual = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WindowsUiChildOwner.DisposeAfterCloseAsync(
                () => Task.FromException(expected),
                () => childDisposed = true,
                () => gateDisposed = true
            )
        );

        Assert.Same(expected, actual);
        Assert.True(childDisposed);
        Assert.True(gateDisposed);
    }

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
    public async Task Concurrent_close_is_idempotent_and_finishes_the_stderr_reader()
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
        await owner.ReadInitialProjectionAsync(TimeSpan.FromSeconds(5));

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => owner.CloseAsync()));

        Assert.True(owner.HasExited);
        Assert.True(owner.StderrBytesDiscarded > 2 * 1024 * 1024);
        Assert.Equal(ChildSessionPhase.Terminal, owner.Session.State.Phase);
    }

    [Fact]
    public async Task Close_coordinates_an_active_stdout_read_and_observes_its_completion()
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
        await owner.ReadInitialProjectionAsync(TimeSpan.FromSeconds(5));
        var blockedRead = owner.ObserveAsync(TimeSpan.FromSeconds(30));
        await Task.Delay(50);

        var close = owner.CloseAsync();
        await close.WaitAsync(TimeSpan.FromSeconds(5));
        var terminal = await blockedRead.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(ChildSessionPhase.Terminal, terminal.State.Phase);
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
        var isolatedHome = Path.Combine(Path.GetTempPath(), "csf12-g4-owner-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(isolatedHome);
        var productSpec = ChildLaunchSpec.Create(root, executable, environment);
        var isolatedEnvironment = productSpec.Environment.ToDictionary(entry => entry.Key, entry => entry.Value);
        isolatedEnvironment["SEAMLESS_INPUT_HOME"] = isolatedHome;
        var spec = productSpec with { Environment = isolatedEnvironment };
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
            var refreshed = await owner.ObserveAsync(TimeSpan.FromSeconds(5));
            Assert.True(refreshed.Snapshot!.Generation > previousGeneration);
            Assert.Equal("browsing", refreshed.Snapshot.State);
        }
        await owner.CloseAsync();
        Assert.True(owner.HasExited);
        Assert.Equal(ChildSessionPhase.Terminal, owner.Session.State.Phase);
        Directory.Delete(isolatedHome, recursive: true);
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
