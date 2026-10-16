using System.Text;
using System.Text.Json;
using ControlShiftF12App.Core;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class UiChildSessionTests
{
    [Fact]
    public void Initial_request_is_only_a_framed_refresh()
    {
        var request = UiChildSession.InitialRefreshFrame();
        var length = (request[0] << 24) | (request[1] << 16) | (request[2] << 8) | request[3];
        using var document = JsonDocument.Parse(request.Skip(4).Take(length).ToArray());

        Assert.Equal("ui.refresh", document.RootElement.GetProperty("command").GetString());
        Assert.Equal("windows-refresh", document.RootElement.GetProperty("id").GetString());
        Assert.Equal(JsonValueKind.Object, document.RootElement.GetProperty("args").ValueKind);
        Assert.False(document.RootElement.GetProperty("args").EnumerateObject().Any());
    }

    [Fact]
    public void Discovery_request_is_a_fixed_empty_command()
    {
        var request = UiChildSession.StartDiscoveryFrame();
        var length = (request[0] << 24) | (request[1] << 16) | (request[2] << 8) | request[3];
        using var document = JsonDocument.Parse(request.Skip(4).Take(length).ToArray());

        Assert.Equal("ui.start_discovery", document.RootElement.GetProperty("command").GetString());
        Assert.Equal("windows-start-discovery", document.RootElement.GetProperty("id").GetString());
        Assert.False(document.RootElement.GetProperty("args").EnumerateObject().Any());
    }

    [Fact]
    public void Discovery_response_is_accepted_only_after_a_current_projection()
    {
        var session = new UiChildSession();

        session.ReceiveOutput(Frame("""
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":2,"state":"browsing",
          "diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false}
        }}
        """));
        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_response_v1","id":"windows-start-discovery","ok":true}"""));

        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.Equal("browsing", session.Snapshot!.State);
        Assert.False(session.Snapshot.InputEnabled);
        Assert.False(session.Snapshot.ClipboardEnabled);
    }

    [Fact]
    public void Unknown_response_id_terminates_the_session()
    {
        var session = new UiChildSession();

        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_response_v1","id":"anything-else","ok":true}"""));

        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
    }

    [Fact]
    public void Current_snapshot_advances_then_eof_clears_every_projection()
    {
        var session = new UiChildSession();

        session.ReceiveOutput(Frame("""
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":1,"state":"not_started",
          "diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false}
        }}
        """));

        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.NotNull(session.Snapshot);

        session.CompleteOutput();

        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
        Assert.Null(session.Snapshot);
        Assert.Null(session.Diagnostics);
    }

    [Fact]
    public void Unknown_or_malformed_child_frame_terminates_without_a_fallback()
    {
        var session = new UiChildSession();

        session.ReceiveOutput(Frame("""{"v":1,"kind":"unexpected","payload":{}}"""));

        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
        Assert.Null(session.Snapshot);
        Assert.Null(session.Diagnostics);
    }

    private static byte[] Frame(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var frame = new byte[sizeof(uint) + payload.Length];
        var length = (uint)payload.Length;
        frame[0] = (byte)(length >> 24);
        frame[1] = (byte)(length >> 16);
        frame[2] = (byte)(length >> 8);
        frame[3] = (byte)length;
        payload.CopyTo(frame, sizeof(uint));
        return frame;
    }
}
