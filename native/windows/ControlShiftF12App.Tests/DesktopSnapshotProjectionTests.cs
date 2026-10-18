using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class DesktopSnapshotProjectionTests
{
    [Fact]
    public void Initial_snapshot_projects_setup_without_enabling_sharing()
    {
        const string snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":1,"state":"not_started",
          "diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false}
        }}
        """;

        Assert.True(DesktopSnapshotProjection.TryParse(snapshot, out var projection));
        Assert.NotNull(projection);
        Assert.Equal("not_started", projection.State);
        Assert.Empty(projection.Nearby);
        Assert.False(projection.InputEnabled);
        Assert.False(projection.ClipboardEnabled);
        Assert.Equal("Not measured", projection.ConnectionHealth);
    }

    [Fact]
    public void Browsing_snapshot_projects_only_a_neutral_current_candidate()
    {
        const string snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":2,"state":"browsing",
          "diagnostics":[],"candidates":[
            {"handle":"nearby_1","compatibility":"compatible","freshness":"current"}
          ],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false}
        }}
        """;

        Assert.True(DesktopSnapshotProjection.TryParse(snapshot, out var projection));
        Assert.NotNull(projection);
        Assert.Equal("browsing", projection.State);
        Assert.Equal(["nearby_1"], projection.Nearby);
        Assert.False(projection.InputEnabled);
        Assert.False(projection.ClipboardEnabled);
    }

    [Fact]
    public void Browsing_snapshot_with_duplicate_candidate_handle_is_rejected()
    {
        const string snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":2,"state":"browsing",
          "diagnostics":[],"candidates":[
            {"handle":"nearby_1","compatibility":"compatible","freshness":"current"},
            {"handle":"nearby_1","compatibility":"compatible","freshness":"current"}
          ],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false}
        }}
        """;

        Assert.False(DesktopSnapshotProjection.TryParse(snapshot, out _));
    }

    [Theory]
    [InlineData("compatible", "stale")]
    [InlineData("compatible", "gone")]
    [InlineData("incompatible", "current")]
    [InlineData("needs_update", "current")]
    public void Noncurrent_or_incompatible_candidates_cannot_be_selected(string compatibility, string freshness)
    {
        var snapshot = $$"""{"v":1,"kind":"ui_snapshot_v1","snapshot":{"schema_version":1,"generation":2,"state":"browsing","diagnostics":[],"candidates":[{"handle":"peer-1","compatibility":"{{compatibility}}","freshness":"{{freshness}}"}],"confirmed":[],"inventory":null,"layout":{"state":"not_configured"},"capabilities":{"input_enabled":false,"clipboard_enabled":false}}}""";
        Assert.True(DesktopSnapshotProjection.TryParse(snapshot, out var projection));
        Assert.Empty(projection!.Nearby);
    }
}
