namespace ControlShiftF12App.Core;

public enum FrameReadOutcome
{
    NeedMore,
    Complete,
    Invalid,
}

public sealed class FramedPayloadReader
{
    private const int MaxFrameBytes = 256 * 1024;
    private readonly List<byte> buffer = [];
    private bool isTerminal;

    public void Append(IEnumerable<byte> bytes)
    {
        if (isTerminal)
        {
            return;
        }

        buffer.AddRange(bytes);
        if (buffer.Count > MaxFrameBytes + sizeof(uint))
        {
            isTerminal = true;
        }
    }

    public FrameReadOutcome TryRead(out byte[]? payload)
    {
        payload = null;
        if (isTerminal)
        {
            return FrameReadOutcome.Invalid;
        }
        if (buffer.Count < sizeof(uint))
        {
            return FrameReadOutcome.NeedMore;
        }

        var length = (uint)(
            (buffer[0] << 24)
            | (buffer[1] << 16)
            | (buffer[2] << 8)
            | buffer[3]
        );
        if (length == 0 || length > MaxFrameBytes)
        {
            isTerminal = true;
            return FrameReadOutcome.Invalid;
        }
        if (buffer.Count < sizeof(uint) + length)
        {
            return FrameReadOutcome.NeedMore;
        }

        payload = buffer.GetRange(sizeof(uint), checked((int)length)).ToArray();
        buffer.RemoveRange(0, sizeof(uint) + checked((int)length));
        return FrameReadOutcome.Complete;
    }

    public FrameReadOutcome CompleteInput(out byte[]? payload)
    {
        var outcome = TryRead(out payload);
        if (outcome == FrameReadOutcome.NeedMore)
        {
            isTerminal = true;
            payload = null;
            return FrameReadOutcome.Invalid;
        }
        return outcome;
    }
}
