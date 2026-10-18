using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ControlShiftF12App.Core;

namespace ControlShiftF12App;

internal sealed class UiGestureRejectedException(string message) : InvalidOperationException(message);

/// <summary>
/// The sole owner for one local engine child. It has no network, shell or
/// capability API: it can only request fixed, redacted UI projections.
/// </summary>
public sealed class WindowsUiChildOwner : IAsyncDisposable
{
    private readonly Process child;
    private readonly Task stderrDrain;
    private readonly SemaphoreSlim stdoutGate = new(1, 1);
    private readonly object closeSync = new();
    private Task closeTask = null!;
    private long stderrBytesDiscarded;
    private bool closed;

    private WindowsUiChildOwner(Process child)
    {
        this.child = child;
        stderrDrain = DrainStderrAsync(child.StandardError.BaseStream);
    }

    public UiChildSession Session { get; } = new();
    public bool HasExited => child.HasExited;
    public long StderrBytesDiscarded => Interlocked.Read(ref stderrBytesDiscarded);

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
            || Session.Snapshot is not { State: "not_started" } || Session.Pairing is not null)
        {
            throw new UiGestureRejectedException("Discovery is unavailable outside the reviewed local starting state.");
        }

        return await SendAndReadResponseAsync(Session.StartDiscoveryFrame(), timeout);
    }

    public async Task<UiChildSession> StopDiscoveryAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Snapshot is not { State: "browsing" } || Session.Pairing is not null)
        {
            throw new UiGestureRejectedException("Discovery is not active.");
        }

        return await SendAndReadResponseAsync(Session.StopDiscoveryFrame(), timeout);
    }

    public async Task<UiChildSession> SelectCandidateAsync(string handle, TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Snapshot is not { State: "browsing" }
            || Session.Pairing is not null || !Session.Snapshot.Nearby.Contains(handle))
        {
            throw new UiGestureRejectedException("Candidate selection requires current discovery.");
        }
        return await SendAndReadResponseAsync(Session.SelectCandidateFrame(handle), timeout);
    }

    public async Task<UiChildSession> ApproveSasAsync(ulong generation, bool matches, TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Pairing is not { Phase: PairingBridgePhase.AwaitingLocalConfirmation } pairing
            || pairing.Generation != generation)
        {
            throw new UiGestureRejectedException("No current pairing comparison is visible.");
        }
        return await SendAndReadResponseAsync(Session.ApproveSasFrame(generation, matches), timeout);
    }

    public async Task<UiChildSession> CancelPairingAsync(ulong generation, TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Pairing?.Generation != generation)
            throw new UiGestureRejectedException("No current pairing comparison is visible.");
        return await SendAndReadResponseAsync(Session.CancelPairingFrame(generation), timeout);
    }

    public async Task<UiChildSession> RefreshAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Snapshot is null)
        {
            throw new InvalidOperationException("The local child has no current projection.");
        }
        return await SendAndReadResponseAsync(Session.InitialRefreshFrame(), timeout);
    }

    public async Task<UiChildSession> ObserveAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Snapshot is null)
            throw new InvalidOperationException("The local child has no current projection.");
        var previousGeneration = Session.Snapshot.Generation;
        try
        {
            return await ReadUntilProjectionAsync(previousGeneration, timeout);
        }
        catch (OperationCanceledException)
        {
            // Silence is a valid observation: no request or replay ID is
            // consumed, and a later timer tick can continue reading.
            return Session;
        }
    }

    private async Task<UiChildSession> SendAndReadResponseAsync(byte[] request, TimeSpan timeout)
    {
        using var document = JsonDocument.Parse(request.AsMemory(4));
        var requestId = document.RootElement.GetProperty("id").GetString()!;
        await WriteFixedRequestAsync(request, timeout);
        return await ReadUntilProjectionAsync(previousGeneration: null, timeout, requestId);
    }

    private async Task WriteFixedRequestAsync(byte[] request, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        await child.StandardInput.BaseStream.WriteAsync(request, cancellation.Token);
        await child.StandardInput.BaseStream.FlushAsync(cancellation.Token);
    }

    private async Task<UiChildSession> ReadUntilProjectionAsync(ulong? previousGeneration, TimeSpan timeout, string requestId = null)
    {
        await stdoutGate.WaitAsync();
        try
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
                if (Session.Snapshot is not null
                    && (requestId is not null ? !Session.IsAwaitingResponse(requestId)
                        : previousGeneration is null || Session.Snapshot.Generation > previousGeneration))
                {
                    return Session;
                }
            }
            return Session;
        }
        finally
        {
            stdoutGate.Release();
        }
    }

    public Task CloseAsync()
    {
        lock (closeSync)
        {
            return closeTask ??= CloseCoreAsync();
        }
    }

    private async Task CloseCoreAsync()
    {
        closed = true;
        Exception failure = null!;
        try
        {
            child.StandardInput.Close();
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
        catch (Exception error)
        {
            failure = error;
        }
        finally
        {
            if (!child.HasExited)
            {
                try { child.StandardOutput.Close(); } catch (Exception error) { failure ??= error; }
                try { child.StandardError.Close(); } catch (Exception error) { failure ??= error; }
            }
            await stdoutGate.WaitAsync();
            try
            {
                Session.CompleteOutput();
            }
            finally
            {
                stdoutGate.Release();
            }
            try { await stderrDrain; } catch (Exception error) { failure ??= error; }
            try { child.StandardOutput.Close(); } catch (Exception error) { failure ??= error; }
            try { child.StandardError.Close(); } catch (Exception error) { failure ??= error; }
        }
        if (failure is not null) throw failure;
    }

    private async Task DrainStderrAsync(Stream stream)
    {
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0) return;
            Interlocked.Add(ref stderrBytesDiscarded, read);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DisposeAfterCloseAsync(CloseAsync, child.Dispose, stdoutGate.Dispose);
    }

    internal static async Task DisposeAfterCloseAsync(
        Func<Task> close,
        Action disposeChild,
        Action disposeStdoutGate
    )
    {
        Exception failure = null!;
        try { await close(); } catch (Exception error) { failure = error; }
        try { disposeChild(); } catch (Exception error) { failure ??= error; }
        try { disposeStdoutGate(); } catch (Exception error) { failure ??= error; }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private void ThrowIfClosed()
    {
        if (closed)
        {
            throw new InvalidOperationException("The local engine session is closed.");
        }
    }
}
