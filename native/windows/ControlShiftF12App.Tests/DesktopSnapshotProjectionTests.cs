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
}
