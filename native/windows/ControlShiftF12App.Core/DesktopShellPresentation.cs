namespace ControlShiftF12App.Core;

public sealed record DesktopShellPresentation(
    string Title,
    string Status,
    IReadOnlyList<string> Nearby,
    bool FindNearbyEnabled,
    bool PairEnabled,
    bool InputEnabled,
    bool ClipboardEnabled,
    bool AutoUpdateEnabled,
    bool SaveLayoutEnabled
)
{
    public static DesktopShellPresentation From(DesktopJourneyState journey) => new(
        Title: journey.Header,
        Status: journey.ConnectionHealth == "Not measured"
            ? "Choose a nearby computer to begin"
            : journey.ConnectionHealth,
        Nearby: journey.Nearby,
        FindNearbyEnabled: journey.CanFindNearby,
        PairEnabled: journey.CanConfirmCode,
        InputEnabled: journey.CanShareInput,
        ClipboardEnabled: false,
        AutoUpdateEnabled: false,
        SaveLayoutEnabled: journey.CanSaveLayout
    );
}
