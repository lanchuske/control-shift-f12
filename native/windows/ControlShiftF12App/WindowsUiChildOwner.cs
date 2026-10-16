using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using ControlShiftF12App.Core;

namespace ControlShiftF12App;

/// <summary>
/// The sole owner for one local engine child. It has no network, shell or
/// capability API: it can only request the initial, redacted UI projection.
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
        using var cancellation = new CancellationTokenSource(timeout);
        var request = UiChildSession.InitialRefreshFrame();
        await child.StandardInput.BaseStream.WriteAsync(request, cancellation.Token);
        await child.StandardInput.BaseStream.FlushAsync(cancellation.Token);

        var buffer = new byte[8192];
        while (Session.State.Phase == ChildSessionPhase.Starting)
        {
            var read = await child.StandardOutput.BaseStream.ReadAsync(buffer, cancellation.Token);
            if (read == 0)
            {
                Session.CompleteOutput();
                return Session;
            }
            Session.ReceiveOutput(buffer.AsSpan(0, read).ToArray());
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
