using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class ChildSessionStateTests
{
    [Fact]
    public void End_of_file_clears_the_projection_and_requires_a_fresh_restart()
    {
        var state = ChildSessionState.Starting();

        state = state.ReceiveCurrentProjection(generation: 1);
        state = state.EndOfFile();

        Assert.Equal(ChildSessionPhase.Terminal, state.Phase);
        Assert.Null(state.CurrentProjectionGeneration);
        Assert.False(state.CanRefresh);
        Assert.True(state.CanRestart);
    }

    [Fact]
    public void Channel_failure_clears_the_projection_and_never_leaves_refresh_enabled()
    {
        var state = ChildSessionState.Starting()
            .ReceiveCurrentProjection(generation: 1);

        state = state.ChannelFailure();

        Assert.Equal(ChildSessionPhase.Terminal, state.Phase);
        Assert.Null(state.CurrentProjectionGeneration);
        Assert.False(state.CanRefresh);
        Assert.True(state.CanRestart);
    }

    [Fact]
    public void Local_close_clears_the_projection_before_a_restart_is_possible()
    {
        var state = ChildSessionState.Starting()
            .ReceiveCurrentProjection(generation: 1);

        state = state.LocalClose();

        Assert.Equal(ChildSessionPhase.Terminal, state.Phase);
        Assert.Null(state.CurrentProjectionGeneration);
        Assert.False(state.CanRefresh);
        Assert.True(state.CanRestart);
    }
}
