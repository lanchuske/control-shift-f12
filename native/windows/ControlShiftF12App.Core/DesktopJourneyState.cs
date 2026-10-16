namespace ControlShiftF12App.Core;

public sealed record DesktopJourneyState(
    string Header,
    bool CanFindNearby,
    bool CanConfirmCode,
    bool CanArrangeDisplays,
    bool CanSaveLayout,
    bool CanShareInput,
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
        ConnectionHealth: "Not measured"
    );
}
