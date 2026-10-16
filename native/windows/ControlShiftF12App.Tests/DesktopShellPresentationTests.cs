using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class DesktopShellPresentationTests
{
    [Fact]
    public void Initial_shell_invites_setup_but_cannot_pair_or_share_yet()
    {
        var presentation = DesktopShellPresentation.From(DesktopJourneyState.Initial());

        Assert.Equal("Set up another computer", presentation.Title);
        Assert.Equal("Choose a nearby computer to begin", presentation.Status);
        Assert.True(presentation.FindNearbyEnabled);
        Assert.False(presentation.PairEnabled);
        Assert.False(presentation.InputEnabled);
        Assert.False(presentation.ClipboardEnabled);
        Assert.False(presentation.AutoUpdateEnabled);
        Assert.False(presentation.SaveLayoutEnabled);
    }

    [Fact]
    public void Nearby_shell_shows_candidates_without_claiming_a_connection()
    {
        var journey = DesktopJourneyState.Initial().ReceiveCurrentNearby(["office-windows"]);

        var presentation = DesktopShellPresentation.From(journey);

        Assert.Equal("Nearby computers", presentation.Title);
        Assert.Equal("Not connected", presentation.Status);
        Assert.Equal(["office-windows"], presentation.Nearby);
        Assert.False(presentation.PairEnabled);
        Assert.False(presentation.InputEnabled);
        Assert.False(presentation.ClipboardEnabled);
        Assert.False(presentation.SaveLayoutEnabled);
    }
}
