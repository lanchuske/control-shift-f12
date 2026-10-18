using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class FramedPayloadReaderTests
{
    [Fact]
    public void Zero_length_frame_is_terminal_and_never_emits_a_payload()
    {
        var reader = new FramedPayloadReader();
        reader.Append([0, 0, 0, 0]);

        var outcome = reader.TryRead(out var payload);

        Assert.Equal(FrameReadOutcome.Invalid, outcome);
        Assert.Null(payload);
    }

    [Fact]
    public void Partial_frame_at_end_of_input_is_terminal_and_never_emits_a_payload()
    {
        var reader = new FramedPayloadReader();
        reader.Append([0, 0, 0, 5, (byte)'{', (byte)'}']);

        var outcome = reader.CompleteInput(out var payload);

        Assert.Equal(FrameReadOutcome.Invalid, outcome);
        Assert.Null(payload);
    }
}
