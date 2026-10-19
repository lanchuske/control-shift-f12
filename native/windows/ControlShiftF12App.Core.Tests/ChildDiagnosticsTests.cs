using System.Text.Json;
using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Core.Tests;

public sealed class ChildDiagnosticsTests
{
    [Fact]
    public void Malformed_frame_exposes_only_a_typed_terminal_reason()
    {
        var session = new UiChildSession();
        session.ReceiveOutput([0, 0, 0, 1, (byte)'{']);

        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
        Assert.Equal(ChildSessionTerminalReason.InvalidFrame, session.TerminalReason);
    }

    [Fact]
    public void Clean_eof_exposes_a_distinct_terminal_reason()
    {
        var session = new UiChildSession();
        session.CompleteOutput();

        Assert.Equal(ChildSessionTerminalReason.EndOfFile, session.TerminalReason);
    }

    [Fact]
    public void Diagnostic_json_has_an_allowlisted_schema_and_no_free_form_payload_field()
    {
        var item = new ChildDiagnosticEvent(
            TimestampUtc: new DateTimeOffset(2026, 10, 19, 9, 15, 0, TimeSpan.Zero),
            Kind: ChildDiagnosticKind.ReadFailed,
            Operation: ChildDiagnosticOperation.StartDiscovery,
            ProcessId: 1234,
            Phase: ChildSessionPhase.Terminal,
            Generation: 17,
            ByteCount: 8192,
            ExitCode: null,
            ExceptionClass: ChildDiagnosticExceptionClass.Timeout,
            TerminalReason: ChildSessionTerminalReason.None,
            StderrCategory: ChildStderrCategory.None
        );

        using var document = JsonDocument.Parse(ChildDiagnosticJson.Serialize(item));
        var names = document.RootElement.EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            ["timestamp_utc", "kind", "operation", "process_id", "phase", "generation",
             "byte_count", "exit_code", "exception_class", "terminal_reason", "stderr_category"],
            names
        );
        Assert.DoesNotContain("payload", ChildDiagnosticJson.Serialize(item), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("words", ChildDiagnosticJson.Serialize(item), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("handle", ChildDiagnosticJson.Serialize(item), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("error: G4 pairing owner unavailable\r\n", ChildStderrCategory.PairingOwnerUnavailable)]
    [InlineData("unclassified detail that must not be logged", ChildStderrCategory.Other)]
    public void Stderr_is_reduced_to_a_fixed_category(string stderr, ChildStderrCategory expected)
    {
        var classifier = new ChildStderrClassifier();
        classifier.Observe(System.Text.Encoding.UTF8.GetBytes(stderr));

        Assert.Equal(expected, classifier.Category);
        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(stderr), classifier.ByteCount);
    }

    [Fact]
    public void Json_line_sink_writes_complete_independent_events()
    {
        var directory = Path.Combine(Path.GetTempPath(), "csf12-diagnostics-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using (var sink = JsonLineChildDiagnosticSink.Create(directory, 4321))
            {
                sink.Write(ChildDiagnosticEvent.Create(
                    ChildDiagnosticKind.EngineStarted,
                    ChildDiagnosticOperation.Lifecycle,
                    processId: 4321
                ));
                sink.Write(ChildDiagnosticEvent.Create(
                    ChildDiagnosticKind.ReadTimedOut,
                    ChildDiagnosticOperation.Observe,
                    processId: 4321,
                    exceptionClass: ChildDiagnosticExceptionClass.Timeout
                ));
            }

            var path = Assert.Single(Directory.GetFiles(directory, "host-4321-*.jsonl"));
            var lines = File.ReadAllLines(path);
            Assert.Equal(2, lines.Length);
            Assert.Equal("engine_started", JsonDocument.Parse(lines[0]).RootElement.GetProperty("kind").GetString());
            Assert.Equal("read_timed_out", JsonDocument.Parse(lines[1]).RootElement.GetProperty("kind").GetString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
