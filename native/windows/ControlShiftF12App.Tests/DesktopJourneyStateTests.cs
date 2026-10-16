using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class DesktopJourneyStateTests
{
    [Fact]
    public void Initial_state_invites_pairing_without_claiming_a_connection_or_saved_layout()
    {
        var state = DesktopJourneyState.Initial();

        Assert.Equal("Set up another computer", state.Header);
        Assert.True(state.CanFindNearby);
        Assert.False(state.CanConfirmCode);
        Assert.False(state.CanArrangeDisplays);
        Assert.False(state.CanSaveLayout);
        Assert.False(state.CanShareInput);
        Assert.Equal("Not measured", state.ConnectionHealth);
    }
}
