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
        var request = new UiChildSession().InitialRefreshFrame();
        var length = (request[0] << 24) | (request[1] << 16) | (request[2] << 8) | request[3];
        using var document = JsonDocument.Parse(request.Skip(4).Take(length).ToArray());

        Assert.Equal("ui.refresh", document.RootElement.GetProperty("command").GetString());
        Assert.StartsWith("windows-", document.RootElement.GetProperty("id").GetString());
        Assert.Equal(JsonValueKind.Object, document.RootElement.GetProperty("args").ValueKind);
        Assert.False(document.RootElement.GetProperty("args").EnumerateObject().Any());
    }

    [Fact]
    public void Discovery_request_is_a_fixed_empty_command()
    {
        var request = new UiChildSession().StartDiscoveryFrame();
        var length = (request[0] << 24) | (request[1] << 16) | (request[2] << 8) | request[3];
        using var document = JsonDocument.Parse(request.Skip(4).Take(length).ToArray());

        Assert.Equal("ui.start_discovery", document.RootElement.GetProperty("command").GetString());
        Assert.StartsWith("windows-", document.RootElement.GetProperty("id").GetString());
        Assert.False(document.RootElement.GetProperty("args").EnumerateObject().Any());
    }

    [Fact]
    public void Stop_discovery_request_is_a_fixed_empty_command()
    {
        var request = new UiChildSession().StopDiscoveryFrame();
        var length = (request[0] << 24) | (request[1] << 16) | (request[2] << 8) | request[3];
        using var document = JsonDocument.Parse(request.Skip(4).Take(length).ToArray());

        Assert.Equal("ui.stop_discovery", document.RootElement.GetProperty("command").GetString());
        Assert.StartsWith("windows-", document.RootElement.GetProperty("id").GetString());
        Assert.False(document.RootElement.GetProperty("args").EnumerateObject().Any());
    }

    [Fact]
    public void Pairing_actions_send_only_opaque_handle_and_bound_decision()
    {
        var session = new UiChildSession();
        using var selected = JsonDocument.Parse(session.SelectCandidateFrame("nearby-7").Skip(4).ToArray());
        var selectArgs = selected.RootElement.GetProperty("args");
        Assert.Equal("ui.select_candidate", selected.RootElement.GetProperty("command").GetString());
        Assert.Equal("nearby-7", selectArgs.GetProperty("handle").GetString());
        Assert.Single(selectArgs.EnumerateObject());

        using var approved = JsonDocument.Parse(session.ApproveSasFrame(9, false).Skip(4).ToArray());
        var approveArgs = approved.RootElement.GetProperty("args");
        Assert.Equal("ui.approve_sas", approved.RootElement.GetProperty("command").GetString());
        Assert.Equal((ulong)9, approveArgs.GetProperty("generation").GetUInt64());
        Assert.False(approveArgs.GetProperty("matches").GetBoolean());
        Assert.Equal(2, approveArgs.EnumerateObject().Count());
    }

    [Fact]
    public void Cancel_pairing_contains_only_a_nonzero_generation()
    {
        var session = new UiChildSession();
        using var cancelled = JsonDocument.Parse(session.CancelPairingFrame(9).Skip(4).ToArray());
        Assert.Equal("ui.cancel_pairing", cancelled.RootElement.GetProperty("command").GetString());
        var args = cancelled.RootElement.GetProperty("args");
        Assert.Single(args.EnumerateObject());
        Assert.Equal(9UL, args.GetProperty("generation").GetUInt64());
        Assert.Throws<ArgumentOutOfRangeException>(() => session.CancelPairingFrame(0));
    }

    [Theory]
    [InlineData("confirmed_relationship", "[{\"handle\":\"peer-1\",\"state\":\"unavailable\"}]")]
    [InlineData("remote_outcome_unknown", "[]")]
    [InlineData("not_started", "[]")]
    public void New_snapshot_erases_sas_and_preserves_no_operational_authority(string state, string confirmed)
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame(Snapshot(1, "browsing")));
        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_pairing_v1","generation":7,"phase":"awaiting_local_confirmation","candidate_handle":"peer-1","verification_words":["ember","ocean","violet","copper"]}"""));
        session.ReceiveOutput(Frame(Snapshot(6, "not_started")));
        Assert.NotNull(session.Pairing);
        session.ReceiveOutput(Frame(Snapshot(8, state).Replace("\"confirmed\":[]", $"\"confirmed\":{confirmed}")));
        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.Null(session.Pairing);
        Assert.Equal(state, session.Snapshot!.State);
        Assert.False(session.Snapshot.InputEnabled);
        Assert.False(session.Snapshot.ClipboardEnabled);
    }

    [Fact]
    public void G4_rejects_an_operational_relationship()
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame(Snapshot(1, "confirmed_relationship").Replace(
            "\"confirmed\":[]", "\"confirmed\":[{\"handle\":\"peer-1\",\"state\":\"active\"}]")));
        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
    }

    [Fact]
    public void Nonterminal_refresh_preserves_the_original_sas_and_action_generation()
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame(Snapshot(1, "browsing")));
        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_pairing_v1","generation":7,"phase":"awaiting_local_confirmation","candidate_handle":"peer-1","verification_words":["ember","ocean","violet","copper"]}"""));
        ulong generation = 8;
        foreach (var state in new[] { "bootstrap_connecting", "bootstrap_sas_pending", "bootstrap_receipt_prepared", "browsing" })
        {
            session.ReceiveOutput(Frame(Snapshot(generation++, state)));
            Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
            Assert.Equal(7UL, session.Pairing!.Generation);
            Assert.Equal(new[] { "ember", "ocean", "violet", "copper" }, session.Pairing.VerificationWords);
            var presentation = G4PairingPresentation.From(session);
            Assert.Equal(7UL, presentation.Generation);
            Assert.True(presentation.CanMatch);
            Assert.False(presentation.CanSelect);
        }
        session.ReceiveOutput(Frame(Snapshot(generation, "not_started")));
        Assert.Null(session.Pairing);
    }

    [Fact]
    public void Discovery_response_is_accepted_only_after_a_current_projection()
    {
        var session = new UiChildSession();
        var id = RequestId(session.StartDiscoveryFrame());

        session.ReceiveOutput(Frame("""
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":2,"state":"browsing",
          "diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false}
        }}
        """));
        session.ReceiveOutput(Frame(JsonSerializer.Serialize(new { v = 1, kind = "ui_response_v1", id, ok = true })));

        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.Equal("browsing", session.Snapshot!.State);
        Assert.False(session.Snapshot.InputEnabled);
        Assert.False(session.Snapshot.ClipboardEnabled);
    }

    [Fact]
    public void Repeated_gestures_use_fresh_bounded_ids_and_replies_are_single_use()
    {
        var session = new UiChildSession();
        var requests = new[] { session.StartDiscoveryFrame(), session.StopDiscoveryFrame(),
            session.StartDiscoveryFrame(), session.InitialRefreshFrame(), session.InitialRefreshFrame() };
        var ids = requests.Select(RequestId).ToArray();
        Assert.Equal(requests.Length, ids.Distinct().Count());
        Assert.All(ids, id => Assert.InRange(id.Length, 1, 64));
        foreach (var id in ids)
        {
            session.ReceiveOutput(Frame(JsonSerializer.Serialize(new { v = 1, kind = "ui_response_v1", id, ok = true })));
            Assert.NotEqual(ChildSessionPhase.Terminal, session.State.Phase);
        }
        session.ReceiveOutput(Frame(JsonSerializer.Serialize(new { v = 1, kind = "ui_response_v1", id = ids[0], ok = true })));
        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
    }

    [Fact]
    public void Unknown_response_id_terminates_the_session()
    {
        var session = new UiChildSession();

        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_response_v1","id":"anything-else","ok":true}"""));

        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
    }

    [Fact]
    public void Autonomous_projection_does_not_complete_a_pending_gesture_response()
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame(Snapshot(1, "browsing")));
        var older = RequestId(session.InitialRefreshFrame());
        var current = RequestId(session.CancelPairingFrame(7));
        session.ReceiveOutput(Frame(Snapshot(8, "not_started")));
        session.ReceiveOutput(Frame(JsonSerializer.Serialize(new { v = 1, kind = "ui_response_v1", id = older, ok = true })));
        Assert.True(session.IsAwaitingResponse(current));
        Assert.False(session.IsAwaitingResponse(older));
        session.ReceiveOutput(Frame(JsonSerializer.Serialize(new { v = 1, kind = "ui_response_v1", id = current, ok = true })));
        Assert.False(session.IsAwaitingResponse(current));
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

    [Fact]
    public void Projection_generation_is_global_and_stale_snapshots_cannot_regress_discovery()
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame(Snapshot(10, "browsing", "current-peer")));
        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_diagnostics_v1","generation":11,"rows":[]}"""));

        session.ReceiveOutput(Frame(Snapshot(10, "not_started")));
        session.ReceiveOutput(Frame(Snapshot(11, "not_started")));

        Assert.Equal(ChildSessionPhase.Running, session.State.Phase);
        Assert.Equal("browsing", session.Snapshot!.State);
        Assert.Equal(["current-peer"], session.Snapshot.Nearby);

        session.ReceiveOutput(Frame(Snapshot(12, "not_started")));
        Assert.Equal("not_started", session.Snapshot!.State);
        Assert.Empty(session.Snapshot.Nearby);
    }

    [Fact]
    public void Malformed_stale_snapshot_is_terminal_instead_of_hidden_by_generation()
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame(Snapshot(10, "not_started")));
        session.ReceiveOutput(Frame("""
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":9,"state":"not_started",
          "diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":true,"clipboard_enabled":false}
        }}
        """));

        Assert.Equal(ChildSessionPhase.Terminal, session.State.Phase);
        Assert.Null(session.Snapshot);
    }

    private static string RequestId(byte[] frame)
    {
        using var document = JsonDocument.Parse(frame.AsMemory(4));
        return document.RootElement.GetProperty("id").GetString()!;
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

    private static string Snapshot(ulong generation, string state, string? candidate = null)
    {
        var candidates = candidate is null
            ? "[]"
            : $$"""[{"handle":"{{candidate}}","compatibility":"compatible","freshness":"current"}]""";
        return $"{{\"v\":1,\"kind\":\"ui_snapshot_v1\",\"snapshot\":{{"
            + $"\"schema_version\":1,\"generation\":{generation},\"state\":\"{state}\","
            + $"\"diagnostics\":[],\"candidates\":{candidates},\"confirmed\":[],\"inventory\":null,"
            + "\"layout\":{\"state\":\"not_configured\"},"
            + "\"capabilities\":{\"input_enabled\":false,\"clipboard_enabled\":false}}}";
    }
}
