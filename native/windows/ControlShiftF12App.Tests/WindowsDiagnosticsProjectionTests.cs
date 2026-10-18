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

    [Fact]
    public void Extra_or_sensitive_frame_field_is_rejected_without_a_projection()
    {
        const string injectedV01 = "{\"v\":1,\"kind\":\"ui_diagnostics_v1\",\"generation\":1,\"rows\":[],\"v01\":{}}";

        Assert.False(DiagnosticsProjection.TryParse(injectedV01, out _));
    }

    [Fact]
    public void Invalid_row_enum_is_rejected_without_a_projection()
    {
        const string invalidState = "{\"v\":1,\"kind\":\"ui_diagnostics_v1\",\"generation\":1,\"rows\":[{\"id\":\"runtime\",\"label\":\"runtime\",\"state\":\"running\",\"detail\":\"ready\",\"action\":null,\"failure_code\":null}]}";

        Assert.False(DiagnosticsProjection.TryParse(invalidState, out _));
    }

    [Fact]
    public void More_than_32_rows_is_rejected_without_a_projection()
    {
        var row = "{\"id\":\"runtime\",\"label\":\"runtime\",\"state\":\"pass\",\"detail\":\"ready\",\"action\":null,\"failure_code\":null}";
        var tooManyRows = "{\"v\":1,\"kind\":\"ui_diagnostics_v1\",\"generation\":1,\"rows\":[" + string.Join(',', Enumerable.Repeat(row, 33)) + "]}";

        Assert.False(DiagnosticsProjection.TryParse(tooManyRows, out _));
    }
}
