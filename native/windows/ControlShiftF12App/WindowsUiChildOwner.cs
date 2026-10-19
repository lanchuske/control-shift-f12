#nullable enable

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
    private readonly IChildDiagnosticSink diagnostics;
    private readonly ChildStderrClassifier stderrClassifier = new();
    private readonly Task stderrDrain;
    private readonly SemaphoreSlim stdoutGate = new(1, 1);
    private readonly object closeSync = new();
    private Task closeTask = null!;
    private long stderrBytesDiscarded;
    private bool closed;

    private WindowsUiChildOwner(Process child, IChildDiagnosticSink diagnostics)
    {
        this.child = child;
        this.diagnostics = diagnostics;
        stderrDrain = DrainStderrAsync(child.StandardError.BaseStream);
        WriteDiagnostic(ChildDiagnosticKind.EngineStarted, ChildDiagnosticOperation.Lifecycle);
    }

    public UiChildSession Session { get; } = new();
    public bool HasExited => child.HasExited;
    public long StderrBytesDiscarded => Interlocked.Read(ref stderrBytesDiscarded);

    public static Task<WindowsUiChildOwner> StartAsync(
        ChildLaunchSpec spec,
        IChildDiagnosticSink? diagnostics = null
    )
    {
        diagnostics ??= NullChildDiagnosticSink.Instance;
        TryWrite(diagnostics, ChildDiagnosticEvent.Create(
            ChildDiagnosticKind.EngineStartRequested,
            ChildDiagnosticOperation.Lifecycle
        ));
        if (!File.Exists(spec.ExecutablePath))
        {
            TryWrite(diagnostics, ChildDiagnosticEvent.Create(
                ChildDiagnosticKind.EngineStartFailed,
                ChildDiagnosticOperation.Lifecycle,
                exceptionClass: ChildDiagnosticExceptionClass.Io
            ));
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

        try
        {
            var child = Process.Start(start)
                ?? throw new InvalidOperationException("The reviewed local engine did not start.");
            return Task.FromResult(new WindowsUiChildOwner(child, diagnostics));
        }
        catch (Exception error)
        {
            TryWrite(diagnostics, ChildDiagnosticEvent.Create(
                ChildDiagnosticKind.EngineStartFailed,
                ChildDiagnosticOperation.Lifecycle,
                exceptionClass: ChildDiagnosticException.Classify(error)
            ));
            throw;
        }
    }

    public async Task<UiChildSession> ReadInitialProjectionAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Starting)
        {
            throw new InvalidOperationException("The initial projection has already been requested.");
        }

        await WriteFixedRequestAsync(Session.InitialRefreshFrame(), timeout, ChildDiagnosticOperation.InitialRefresh);
        return await ReadUntilProjectionAsync(previousGeneration: null, timeout, ChildDiagnosticOperation.InitialRefresh);
    }

    public async Task<UiChildSession> StartDiscoveryAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Snapshot is not { State: "not_started" } || Session.Pairing is not null)
        {
            throw new UiGestureRejectedException("Discovery is unavailable outside the reviewed local starting state.");
        }

        return await SendAndReadResponseAsync(Session.StartDiscoveryFrame(), timeout, ChildDiagnosticOperation.StartDiscovery);
    }

    public async Task<UiChildSession> StopDiscoveryAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running
            || Session.Snapshot is not { State: "browsing" } || Session.Pairing is not null)
        {
            throw new UiGestureRejectedException("Discovery is not active.");
        }

        return await SendAndReadResponseAsync(Session.StopDiscoveryFrame(), timeout, ChildDiagnosticOperation.StopDiscovery);
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
        return await SendAndReadResponseAsync(Session.SelectCandidateFrame(handle), timeout, ChildDiagnosticOperation.SelectCandidate);
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
        return await SendAndReadResponseAsync(Session.ApproveSasFrame(generation, matches), timeout, ChildDiagnosticOperation.ApproveComparison);
    }

    public async Task<UiChildSession> CancelPairingAsync(ulong generation, TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Pairing?.Generation != generation)
            throw new UiGestureRejectedException("No current pairing comparison is visible.");
        return await SendAndReadResponseAsync(Session.CancelPairingFrame(generation), timeout, ChildDiagnosticOperation.CancelPairing);
    }

    public async Task<UiChildSession> RefreshAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Snapshot is null)
        {
            throw new InvalidOperationException("The local child has no current projection.");
        }
        return await SendAndReadResponseAsync(Session.InitialRefreshFrame(), timeout, ChildDiagnosticOperation.Refresh);
    }

    public async Task<UiChildSession> ObserveAsync(TimeSpan timeout)
    {
        ThrowIfClosed();
        if (Session.State.Phase != ChildSessionPhase.Running || Session.Snapshot is null)
            throw new InvalidOperationException("The local child has no current projection.");
        var previousGeneration = Session.Snapshot.Generation;
        try
        {
            return await ReadUntilProjectionAsync(previousGeneration, timeout, ChildDiagnosticOperation.Observe);
        }
        catch (OperationCanceledException)
        {
            // Silence is a valid observation: no request or replay ID is
            // consumed, and a later timer tick can continue reading.
            return Session;
        }
    }

    private async Task<UiChildSession> SendAndReadResponseAsync(
        byte[] request,
        TimeSpan timeout,
        ChildDiagnosticOperation operation
    )
    {
        using var document = JsonDocument.Parse(request.AsMemory(4));
        var requestId = document.RootElement.GetProperty("id").GetString()!;
        await WriteFixedRequestAsync(request, timeout, operation);
        return await ReadUntilProjectionAsync(previousGeneration: null, timeout, operation, requestId);
    }

    private async Task WriteFixedRequestAsync(
        byte[] request,
        TimeSpan timeout,
        ChildDiagnosticOperation operation
    )
    {
        WriteDiagnostic(ChildDiagnosticKind.RequestWriteStarted, operation, byteCount: request.Length);
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            await child.StandardInput.BaseStream.WriteAsync(request, cancellation.Token);
            await child.StandardInput.BaseStream.FlushAsync(cancellation.Token);
            WriteDiagnostic(ChildDiagnosticKind.RequestWriteCompleted, operation, byteCount: request.Length);
        }
        catch (Exception error)
        {
            WriteDiagnostic(
                ChildDiagnosticKind.RequestWriteFailed,
                operation,
                exceptionClass: ChildDiagnosticException.Classify(error)
            );
            throw;
        }
    }

    private async Task<UiChildSession> ReadUntilProjectionAsync(
        ulong? previousGeneration,
        TimeSpan timeout,
        ChildDiagnosticOperation operation,
        string? requestId = null
    )
    {
        await stdoutGate.WaitAsync();
        try
        {
            WriteDiagnostic(ChildDiagnosticKind.ReadStarted, operation);
            using var cancellation = new CancellationTokenSource(timeout);
            var buffer = new byte[8192];
            while (Session.State.Phase != ChildSessionPhase.Terminal)
            {
                var read = await child.StandardOutput.BaseStream.ReadAsync(buffer, cancellation.Token);
                if (read == 0)
                {
                    Session.CompleteOutput();
                    WriteDiagnostic(ChildDiagnosticKind.ReadEndOfFile, operation);
                    WriteDiagnostic(ChildDiagnosticKind.SessionTerminal, operation);
                    return Session;
                }
                WriteDiagnostic(ChildDiagnosticKind.ReadCompleted, operation, byteCount: read);
                Session.ReceiveOutput(buffer.AsSpan(0, read).ToArray());
                if (Session.State.Phase == ChildSessionPhase.Terminal)
                {
                    WriteDiagnostic(ChildDiagnosticKind.SessionTerminal, operation);
                    return Session;
                }
                if (Session.Snapshot is not null
                    && (requestId is not null ? !Session.IsAwaitingResponse(requestId)
                        : previousGeneration is null || Session.Snapshot.Generation > previousGeneration))
                {
                    WriteDiagnostic(ChildDiagnosticKind.ProjectionAccepted, operation);
                    return Session;
                }
            }
            return Session;
        }
        catch (OperationCanceledException)
        {
            WriteDiagnostic(
                ChildDiagnosticKind.ReadTimedOut,
                operation,
                exceptionClass: ChildDiagnosticExceptionClass.Timeout
            );
            throw;
        }
        catch (Exception error)
        {
            WriteDiagnostic(
                ChildDiagnosticKind.ReadFailed,
                operation,
                exceptionClass: ChildDiagnosticException.Classify(error)
            );
            throw;
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
        WriteDiagnostic(ChildDiagnosticKind.EngineCloseStarted, ChildDiagnosticOperation.Close);
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
                Session.CompleteLocalClose();
                WriteDiagnostic(ChildDiagnosticKind.SessionTerminal, ChildDiagnosticOperation.Close);
            }
            finally
            {
                stdoutGate.Release();
            }
            try { await stderrDrain; } catch (Exception error) { failure ??= error; }
            try { child.StandardOutput.Close(); } catch (Exception error) { failure ??= error; }
            try { child.StandardError.Close(); } catch (Exception error) { failure ??= error; }
        }
        WriteDiagnostic(
            ChildDiagnosticKind.EngineClosed,
            ChildDiagnosticOperation.Close,
            exitCode: child.HasExited ? child.ExitCode : null
        );
        if (failure is not null) throw failure;
    }

    private async Task DrainStderrAsync(Stream stream)
    {
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0)
            {
                WriteDiagnostic(
                    ChildDiagnosticKind.StderrCompleted,
                    ChildDiagnosticOperation.Lifecycle,
                    byteCount: stderrClassifier.ByteCount,
                    stderrCategory: stderrClassifier.Category
                );
                return;
            }
            stderrClassifier.Observe(buffer.AsSpan(0, read));
            Interlocked.Add(ref stderrBytesDiscarded, read);
        }
    }

    private void WriteDiagnostic(
        ChildDiagnosticKind kind,
        ChildDiagnosticOperation operation,
        long? byteCount = null,
        int? exitCode = null,
        ChildDiagnosticExceptionClass exceptionClass = ChildDiagnosticExceptionClass.None,
        ChildStderrCategory stderrCategory = ChildStderrCategory.None
    )
    {
        TryWrite(diagnostics, ChildDiagnosticEvent.Create(
            kind,
            operation,
            processId: child.Id,
            phase: Session.State.Phase,
            generation: Session.State.CurrentProjectionGeneration,
            byteCount: byteCount,
            exitCode: exitCode,
            exceptionClass: exceptionClass,
            terminalReason: Session.TerminalReason,
            stderrCategory: stderrCategory
        ));
    }

    private static void TryWrite(IChildDiagnosticSink sink, ChildDiagnosticEvent item)
    {
        try { sink.Write(item); }
        catch (Exception) { /* Diagnostics must never change fail-closed behavior. */ }
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
