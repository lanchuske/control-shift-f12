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

/// <summary>Only comparison gestures, never operational relationship authority.</summary>
public sealed record G4PairingPresentation(
    IReadOnlyList<string> Candidates, ulong? Generation, string Words, string Status,
    bool CanSelect, bool CanMatch, bool CanCancel)
{
    public static G4PairingPresentation From(UiChildSession session)
    {
        if (session.State.Phase != ChildSessionPhase.Running || session.Snapshot is not { } snapshot)
            return new([], null, "", "Local engine unavailable — pairing disabled", false, false, false);
        if (session.Pairing is { } pairing)
            return new([], pairing.Generation, string.Join("  ", pairing.VerificationWords),
                pairing.Phase switch
                {
                    PairingBridgePhase.AwaitingLocalConfirmation => "Compare all four words on both computers.",
                    PairingBridgePhase.AwaitingRemoteConfirmation => "Waiting for the other computer — sharing remains off.",
                    _ => "Saving confirmation — sharing remains off.",
                }, false, pairing.Phase == PairingBridgePhase.AwaitingLocalConfirmation, true);
        var status = snapshot.State switch
        {
            "confirmed_relationship" => "Confirmed — sharing unavailable",
            "remote_outcome_unknown" => "Outcome unknown — quarantined",
            "browsing" => "Choose a current nearby computer to compare",
            "bootstrap_connecting" or "bootstrap_sas_pending" or "bootstrap_receipt_prepared" => "Pairing pending — sharing remains off",
            _ => "Not connected",
        };
        return new(snapshot.Nearby, null, "", status,
            snapshot.State == "browsing" && snapshot.Nearby.Count > 0, false, false);
    }
}
