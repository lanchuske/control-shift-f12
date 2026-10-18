namespace ControlShiftF12App.Core;

/// <summary>
/// Presentation-side state for a pairing attempt. It contains only opaque
/// candidate handles and a short verification display; addresses, credentials,
/// input and persistence are deliberately outside this type.
/// </summary>
public enum PairingBridgePhase
{
    Browsing,
    AwaitingLocalConfirmation,
    AwaitingRemoteConfirmation,
    ReadyForDurableAdmission,
}

public sealed record PairingBridgeState(
    PairingBridgePhase Phase,
    string? SelectedCandidate,
    IReadOnlyList<string> VerificationWords
)
{
    public static PairingBridgeState Browsing() => new(PairingBridgePhase.Browsing, null, []);

    public PairingBridgeState BeginVerification(string candidate, IReadOnlyList<string> words)
    {
        if (Phase != PairingBridgePhase.Browsing || !IsHandle(candidate) || !AreVerificationWords(words))
        {
            return this;
        }
        return new(PairingBridgePhase.AwaitingLocalConfirmation, candidate, words.ToArray());
    }

    public PairingBridgeState ConfirmLocal(bool matches)
    {
        if (Phase != PairingBridgePhase.AwaitingLocalConfirmation)
        {
            return this;
        }
        return matches
            ? this with { Phase = PairingBridgePhase.AwaitingRemoteConfirmation }
            : Browsing();
    }

    public PairingBridgeState ConfirmRemote()
    {
        return Phase == PairingBridgePhase.AwaitingRemoteConfirmation
            ? this with { Phase = PairingBridgePhase.ReadyForDurableAdmission }
            : this;
    }

    public PairingBridgeState Cancel() => Browsing();

    private static bool IsHandle(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 64
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool AreVerificationWords(IReadOnlyList<string> words) =>
        words.Count == 4
        && words.All(word => word.Length is > 0 and <= 24
            && word.All(character => character is >= 'a' and <= 'z'));
}
