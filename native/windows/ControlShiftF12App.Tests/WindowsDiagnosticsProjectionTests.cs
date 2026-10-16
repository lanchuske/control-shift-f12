using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class WindowsDiagnosticsProjectionTests
{
    [Fact]
    public void Unknown_frame_is_rejected_without_a_projection()
    {
        Assert.False(DiagnosticsProjection.TryParse("{\"v\":1,\"kind\":\"unknown\"}", out _));
    }
}
