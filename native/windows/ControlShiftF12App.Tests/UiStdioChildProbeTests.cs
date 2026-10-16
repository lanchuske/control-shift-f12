using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class UiStdioChildProbeTests
{
    [Fact]
    public async Task Reviewed_ui_child_emits_a_snapshot_then_exits_when_its_input_closes()
    {
        var executable = FindEngineExecutable();
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("control");
        start.ArgumentList.Add("--ui-stdio");

        using var child = Process.Start(start);
        Assert.NotNull(child);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var request = JsonSerializer.SerializeToUtf8Bytes(new
        {
            v = 1,
            id = "windows-child-probe",
            command = "ui.refresh",
            args = new { },
        });
        await child!.StandardInput.BaseStream.WriteAsync(Frame(request), timeout.Token);
        await child.StandardInput.BaseStream.FlushAsync(timeout.Token);

        var payload = await ReadFrameAsync(child.StandardOutput.BaseStream, timeout.Token);
        using var document = JsonDocument.Parse(payload);
        Assert.Equal("ui_snapshot_v1", document.RootElement.GetProperty("kind").GetString());

        child.StandardInput.Close();
        await child.WaitForExitAsync(timeout.Token);
        Assert.True(child.HasExited);
    }

    private static byte[] Frame(byte[] payload)
    {
        var frame = new byte[sizeof(uint) + payload.Length];
        var length = (uint)payload.Length;
        frame[0] = (byte)(length >> 24);
        frame[1] = (byte)(length >> 16);
        frame[2] = (byte)(length >> 8);
        frame[3] = (byte)length;
        payload.CopyTo(frame, sizeof(uint));
        return frame;
    }

    private static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = await ReadExactlyAsync(stream, sizeof(uint), cancellationToken);
        var length = (prefix[0] << 24) | (prefix[1] << 16) | (prefix[2] << 8) | prefix[3];
        Assert.InRange(length, 1, 256 * 1024);
        return await ReadExactlyAsync(stream, length, cancellationToken);
    }

    private static async Task<byte[]> ReadExactlyAsync(
        Stream stream,
        int count,
        CancellationToken cancellationToken
    )
    {
        var result = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(result.AsMemory(offset, count - offset), cancellationToken);
            Assert.NotEqual(0, read);
            offset += read;
        }
        return result;
    }

    private static string FindEngineExecutable()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, "target", "debug", "seamless-input.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            current = current.Parent;
        }
        throw new Xunit.Sdk.XunitException("The target Windows engine executable is unavailable.");
    }
}
