using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class WindowsDiagnosticsProjectionTests
{
    private const string ValidEmptyFrame = "{\"v\":1,\"kind\":\"ui_diagnostics_v1\",\"generation\":1,\"rows\":[]}";

    [Fact]
    public void Unknown_frame_is_rejected_without_a_projection()
    {
        Assert.False(DiagnosticsProjection.TryParse("{\"v\":1,\"kind\":\"unknown\"}", out _));
    }

    [Fact]
    public void Duplicate_frame_field_is_rejected_without_a_projection()
    {
        const string duplicateGeneration = "{\"v\":1,\"kind\":\"ui_diagnostics_v1\",\"generation\":1,\"generation\":2,\"rows\":[]}";

        Assert.False(DiagnosticsProjection.TryParse(duplicateGeneration, out _));
    }

    [Fact]
    public void Frame_larger_than_the_engine_limit_is_rejected_before_projection()
    {
        var oversized = ValidEmptyFrame + new string(' ', (256 * 1024) + 1);

        Assert.False(DiagnosticsProjection.TryParse(oversized, out _));
    }

    [Fact]
    public void Negative_generation_is_rejected_without_a_projection()
    {
        const string negativeGeneration = "{\"v\":1,\"kind\":\"ui_diagnostics_v1\",\"generation\":-1,\"rows\":[]}";

        Assert.False(DiagnosticsProjection.TryParse(negativeGeneration, out _));
    }
}
