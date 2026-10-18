using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class PairingProjectionTests
{
    [Fact]
    public void Exact_redacted_pairing_projection_is_accepted()
    {
        var json = """{"v":1,"kind":"ui_pairing_v1","generation":4,"phase":"awaiting_local_confirmation","candidate_handle":"mac-studio","verification_words":["ember","ocean","violet","copper"]}""";

        Assert.True(PairingProjection.TryParse(json, out var projection));
        Assert.Equal(PairingBridgePhase.AwaitingLocalConfirmation, projection!.Phase);
        Assert.Equal("mac-studio", projection.CandidateHandle);
        Assert.Equal(["ember", "ocean", "violet", "copper"], projection.VerificationWords);
    }

    [Fact]
    public void Address_or_wrong_word_count_is_rejected()
    {
        var address = """{"v":1,"kind":"ui_pairing_v1","generation":4,"phase":"awaiting_local_confirmation","candidate_handle":"mac-studio","verification_words":["ember","ocean","violet","copper"],"address":"192.0.2.1"}""";
        var words = """{"v":1,"kind":"ui_pairing_v1","generation":4,"phase":"awaiting_local_confirmation","candidate_handle":"mac-studio","verification_words":["ember"]}""";

        Assert.False(PairingProjection.TryParse(address, out _));
        Assert.False(PairingProjection.TryParse(words, out _));
    }
}
