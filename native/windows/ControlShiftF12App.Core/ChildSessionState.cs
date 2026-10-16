namespace ControlShiftF12App.Core;

public enum ChildSessionPhase
{
    Starting,
    Running,
    Terminal,
}

public sealed record ChildSessionState(
    ChildSessionPhase Phase,
    ulong? CurrentProjectionGeneration
)
{
    public bool CanRefresh => Phase == ChildSessionPhase.Running;
    public bool CanRestart => Phase == ChildSessionPhase.Terminal;

    public static ChildSessionState Starting() => new(ChildSessionPhase.Starting, null);

    public ChildSessionState ReceiveCurrentProjection(ulong generation)
    {
        if (Phase == ChildSessionPhase.Terminal || generation == 0)
        {
            return this;
        }

        if (CurrentProjectionGeneration is ulong current && generation <= current)
        {
            return this;
        }

        return new ChildSessionState(ChildSessionPhase.Running, generation);
    }

    public ChildSessionState EndOfFile() => new(ChildSessionPhase.Terminal, null);

    public ChildSessionState ChannelFailure() => new(ChildSessionPhase.Terminal, null);
}
