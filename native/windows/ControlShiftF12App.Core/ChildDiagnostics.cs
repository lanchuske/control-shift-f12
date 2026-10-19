using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ControlShiftF12App.Core;

public enum ChildDiagnosticKind
{
    HostStarted,
    EngineStartRequested,
    EngineStarted,
    EngineStartFailed,
    RequestWriteStarted,
    RequestWriteCompleted,
    RequestWriteFailed,
    ReadStarted,
    ReadCompleted,
    ReadTimedOut,
    ReadFailed,
    ReadEndOfFile,
    ProjectionAccepted,
    SessionTerminal,
    StderrCompleted,
    EngineCloseStarted,
    EngineClosed,
}

public enum ChildDiagnosticOperation
{
    None,
    Lifecycle,
    InitialRefresh,
    StartDiscovery,
    StopDiscovery,
    SelectCandidate,
    ApproveComparison,
    CancelPairing,
    Refresh,
    Observe,
    Close,
}

public enum ChildDiagnosticExceptionClass
{
    None,
    Timeout,
    Io,
    InvalidOperation,
    Disposed,
    Unauthorized,
    Unknown,
}

public enum ChildSessionTerminalReason
{
    None,
    EndOfFile,
    InvalidFrame,
    HostCommandFailure,
    LocalClose,
}

public enum ChildStderrCategory
{
    None,
    PairingOwnerUnavailable,
    RuntimeShutdownPanic,
    Other,
}

public sealed record ChildDiagnosticEvent(
    DateTimeOffset TimestampUtc,
    ChildDiagnosticKind Kind,
    ChildDiagnosticOperation Operation,
    int? ProcessId,
    ChildSessionPhase? Phase,
    ulong? Generation,
    long? ByteCount,
    int? ExitCode,
    ChildDiagnosticExceptionClass ExceptionClass,
    ChildSessionTerminalReason TerminalReason,
    ChildStderrCategory StderrCategory
)
{
    public static ChildDiagnosticEvent Create(
        ChildDiagnosticKind kind,
        ChildDiagnosticOperation operation = ChildDiagnosticOperation.None,
        int? processId = null,
        ChildSessionPhase? phase = null,
        ulong? generation = null,
        long? byteCount = null,
        int? exitCode = null,
        ChildDiagnosticExceptionClass exceptionClass = ChildDiagnosticExceptionClass.None,
        ChildSessionTerminalReason terminalReason = ChildSessionTerminalReason.None,
        ChildStderrCategory stderrCategory = ChildStderrCategory.None
    ) => new(
        DateTimeOffset.UtcNow,
        kind,
        operation,
        processId,
        phase,
        generation,
        byteCount,
        exitCode,
        exceptionClass,
        terminalReason,
        stderrCategory
    );
}

public static class ChildDiagnosticJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static string Serialize(ChildDiagnosticEvent item) => JsonSerializer.Serialize(item, Options);
}

public interface IChildDiagnosticSink
{
    void Write(ChildDiagnosticEvent item);
}

public sealed class NullChildDiagnosticSink : IChildDiagnosticSink
{
    public static NullChildDiagnosticSink Instance { get; } = new();
    private NullChildDiagnosticSink() { }
    public void Write(ChildDiagnosticEvent item) { }
}

public sealed class JsonLineChildDiagnosticSink : IChildDiagnosticSink, IDisposable
{
    private readonly StreamWriter writer;
    private readonly object sync = new();

    private JsonLineChildDiagnosticSink(string path)
    {
        writer = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
    }

    public string Path { get; private init; } = "";

    public static JsonLineChildDiagnosticSink Create(string directory, int hostProcessId)
    {
        Directory.CreateDirectory(directory);
        var filename = $"host-{hostProcessId}-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffZ}.jsonl";
        var path = System.IO.Path.Combine(directory, filename);
        return new JsonLineChildDiagnosticSink(path) { Path = path };
    }

    public void Write(ChildDiagnosticEvent item)
    {
        lock (sync)
        {
            writer.WriteLine(ChildDiagnosticJson.Serialize(item));
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            writer.Dispose();
        }
    }
}

public sealed class ChildStderrClassifier
{
    private const int MaxClassificationBytes = 4096;
    private readonly MemoryStream sample = new();

    public long ByteCount { get; private set; }

    public ChildStderrCategory Category
    {
        get
        {
            if (ByteCount == 0) return ChildStderrCategory.None;
            var value = Encoding.UTF8.GetString(sample.ToArray());
            if (value.Contains("G4 pairing owner unavailable", StringComparison.Ordinal))
                return ChildStderrCategory.PairingOwnerUnavailable;
            if (value.Contains("Cannot drop a runtime in a context where blocking is not allowed", StringComparison.Ordinal))
                return ChildStderrCategory.RuntimeShutdownPanic;
            return ChildStderrCategory.Other;
        }
    }

    public void Observe(ReadOnlySpan<byte> bytes)
    {
        ByteCount += bytes.Length;
        var remaining = MaxClassificationBytes - (int)sample.Length;
        if (remaining > 0)
        {
            sample.Write(bytes[..Math.Min(remaining, bytes.Length)]);
        }
    }
}

public static class ChildDiagnosticException
{
    public static ChildDiagnosticExceptionClass Classify(Exception error) => error switch
    {
        OperationCanceledException => ChildDiagnosticExceptionClass.Timeout,
        IOException => ChildDiagnosticExceptionClass.Io,
        ObjectDisposedException => ChildDiagnosticExceptionClass.Disposed,
        InvalidOperationException => ChildDiagnosticExceptionClass.InvalidOperation,
        UnauthorizedAccessException => ChildDiagnosticExceptionClass.Unauthorized,
        _ => ChildDiagnosticExceptionClass.Unknown,
    };
}
