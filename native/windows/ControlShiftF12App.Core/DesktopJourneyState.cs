namespace ControlShiftF12App.Core;

public sealed record DesktopJourneyState(
    string Header,
    bool CanFindNearby,
    bool CanConfirmCode,
    bool CanArrangeDisplays,
    bool CanSaveLayout,
    bool CanShareInput,
    IReadOnlyList<string> Nearby,
    string ConnectionHealth
)
{
    public static DesktopJourneyState Initial() => new(
        Header: "Set up another computer",
        CanFindNearby: true,
        CanConfirmCode: false,
        CanArrangeDisplays: false,
        CanSaveLayout: false,
        CanShareInput: false,
        Nearby: [],
        ConnectionHealth: "Not measured"
    );

    public DesktopJourneyState ReceiveCurrentNearby(IReadOnlyList<string> candidates)
    {
        if (!CanFindNearby || candidates.Count is 0 or > 32 || candidates.Any(candidate =>
            string.IsNullOrWhiteSpace(candidate) || candidate.Length > 64))
        {
            return this;
        }

        return this with {
            Header = "Nearby computers",
            Nearby = candidates.ToArray(),
            ConnectionHealth = "Not connected",
        };
    }
}
