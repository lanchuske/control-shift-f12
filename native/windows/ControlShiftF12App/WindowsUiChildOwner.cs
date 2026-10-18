using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using ControlShiftF12App.Core;

namespace ControlShiftF12App;

/// <summary>
/// The sole owner for one local engine child. It has no network, shell or
/// capability API: it can only request fixed, redacted UI projections.
/// </summary>
public sealed class WindowsUiChildOwner : IAsyncDisposable
{
    private readonly Process child;
    private bool closed;

    private WindowsUiChildOwner(Process child)
    {
        this.child = child;
    }

    public UiChildSession Session { get; } = new();
    public bool HasExited => child.HasExited;

    public static Task<WindowsUiChildOwner> StartAsync(ChildLaunchSpec spec)
    {
        if (!File.Exists(spec.ExecutablePath))
        {
            throw new FileNotFoundException("The reviewed local engine is unavailable.", spec.ExecutablePath);
        }

        var start = new ProcessStartInfo(spec.ExecutablePath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.Environment.Clear();
        foreach (var (name, value) in spec.Environment)
        {
            start.Environment[name] = value;
        }
        foreach (var argument in spec.Arguments)
        {
            start.ArgumentList.Add(argument);
        }

        var child = Process.Start(start)
            ?? throw new InvalidOperationException("The reviewed local engine did not start.");
        return Task.FromResult(new WindowsUiChildOwner(child));
    }

    public async Task<UiChildSession> ReadInitialProjectionAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Starting)
        {
            throw new InvalidOperationException("The initial projection has already been requested.");
        }

        await WriteFixedRequestAsync(Session.InitialRefreshFrame(), timeout);
        return await ReadUntilProjectionAsync(previousGeneration: null, timeout);
    }

    public async Task<UiChildSession> StartDiscoveryAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Snapshot is not { State: "not_started" } previous)
        {
            throw new InvalidOperationException("Discovery is unavailable outside the reviewed local starting state.");
        }

        await WriteFixedRequestAsync(Session.StartDiscoveryFrame(), timeout);
        return await ReadUntilProjectionAsync(previous.Generation, timeout);
    }

    public async Task<UiChildSession> StopDiscoveryAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Snapshot is not { State: "browsing" } previous)
        {
            throw new InvalidOperationException("Discovery is not active.");
        }

        await WriteFixedRequestAsync(Session.StopDiscoveryFrame(), timeout);
        return await ReadUntilProjectionAsync(previous.Generation, timeout);
    }

    public async Task<UiChildSession> RefreshAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Snapshot is not { } previous)
        {
            throw new InvalidOperationException("The local child has no current projection.");
        }
        await WriteFixedRequestAsync(Session.InitialRefreshFrame(), timeout);
        return await ReadUntilProjectionAsync(previous.Generation, timeout);
    }

    private async Task WriteFixedRequestAsync(byte[] request, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        await child.StandardInput.BaseStream.WriteAsync(request, cancellation.Token);
        await child.StandardInput.BaseStream.FlushAsync(cancellation.Token);
    }

    private async Task<UiChildSession> ReadUntilProjectionAsync(ulong? previousGeneration, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        var buffer = new byte[8192];
        while (Session.State.Phase != ChildSessionPhase.Terminal)
        {
            var read = await child.StandardOutput.BaseStream.ReadAsync(buffer, cancellation.Token);
            if (read == 0)
            {
                Session.CompleteOutput();
                return Session;
            }
            Session.ReceiveOutput(buffer.AsSpan(0, read).ToArray());
            if (Session.Snapshot is { } snapshot
                && (previousGeneration is null || snapshot.Generation > previousGeneration))
            {
                return Session;
            }
        }
        return Session;
    }

    public async Task CloseAsync()
    {
        if (closed)
        {
            return;
        }
        closed = true;
        child.StandardInput.Close();
        child.StandardOutput.Close();
        child.StandardError.Close();
        Session.CompleteOutput();

        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        try
        {
            await child.WaitForExitAsync(cancellation.Token);
        }
        catch (OperationCanceledException) when (!child.HasExited)
        {
            child.Kill(entireProcessTree: false);
            await child.WaitForExitAsync();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync();
        child.Dispose();
    }

    private void ThrowIfClosed()
    {
        if (closed)
        {
            throw new InvalidOperationException("The local engine session is closed.");
        }
    }
}
