using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class PairingBridgeStateTests
{
    [Fact]
    public void Durable_admission_requires_the_same_valid_code_and_both_confirmations()
    {
        var state = PairingBridgeState.Browsing()
            .BeginVerification("mac-studio", ["ember", "ocean", "violet", "copper"]);

        Assert.Equal(PairingBridgePhase.AwaitingLocalConfirmation, state.Phase);
        Assert.Equal("mac-studio", state.SelectedCandidate);

        state = state.ConfirmLocal(true);
        Assert.Equal(PairingBridgePhase.AwaitingRemoteConfirmation, state.Phase);

        state = state.ConfirmRemote();
        Assert.Equal(PairingBridgePhase.ReadyForDurableAdmission, state.Phase);
    }

    [Fact]
    public void Rejection_or_invalid_code_cannot_reach_durable_admission()
    {
        var rejected = PairingBridgeState.Browsing()
            .BeginVerification("mac-studio", ["ember", "ocean", "violet", "copper"])
            .ConfirmLocal(false)
            .ConfirmRemote();
        var invalid = PairingBridgeState.Browsing()
            .BeginVerification("mac studio", ["not", "a", "four-word", "code"]);

        Assert.Equal(PairingBridgePhase.Browsing, rejected.Phase);
        Assert.Equal(PairingBridgePhase.Browsing, invalid.Phase);
    }
}
