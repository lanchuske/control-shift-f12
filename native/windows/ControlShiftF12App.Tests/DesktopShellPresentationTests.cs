using ControlShiftF12App.Core;
using System.Text;
using System.Text.Json;
using ControlShiftF12App;
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

    [Fact]
    public void G4_controls_follow_current_projection_generation_and_clear_terminal_sas()
    {
        var session = new UiChildSession();
        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_snapshot_v1","snapshot":{"schema_version":1,"generation":1,"state":"browsing","diagnostics":[],"candidates":[{"handle":"peer-1","compatibility":"compatible","freshness":"current"}],"confirmed":[],"inventory":null,"layout":{"state":"not_configured"},"capabilities":{"input_enabled":false,"clipboard_enabled":false}}}"""));
        var browsing = G4PairingPresentation.From(session);
        Assert.Equal(["peer-1"], browsing.Candidates);
        Assert.True(browsing.CanSelect);
        Assert.False(browsing.CanMatch);
        Assert.False(browsing.CanCancel);

        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_pairing_v1","generation":7,"phase":"awaiting_local_confirmation","candidate_handle":"peer-1","verification_words":["ember","ocean","violet","copper"]}"""));
        var comparison = G4PairingPresentation.From(session);
        Assert.Equal(7UL, comparison.Generation);
        Assert.Equal("ember  ocean  violet  copper", comparison.Words);
        Assert.True(comparison.CanMatch);
        Assert.True(comparison.CanCancel);
        Assert.False(comparison.CanSelect);

        session.ReceiveOutput(Frame("""{"v":1,"kind":"ui_snapshot_v1","snapshot":{"schema_version":1,"generation":8,"state":"confirmed_relationship","diagnostics":[],"candidates":[],"confirmed":[{"handle":"peer-1","state":"unavailable"}],"inventory":null,"layout":{"state":"not_configured"},"capabilities":{"input_enabled":false,"clipboard_enabled":false}}}"""));
        var confirmed = G4PairingPresentation.From(session);
        Assert.Equal("Confirmed — sharing unavailable", confirmed.Status);
        Assert.Equal("", confirmed.Words);
        Assert.Null(confirmed.Generation);
        Assert.False(confirmed.CanMatch);
        Assert.False(confirmed.CanCancel);
        Assert.False(confirmed.CanSelect);
    }

    [Fact]
    public void Native_controls_select_current_candidates_and_bind_actions_to_displayed_sas()
    {
        // WinForms controls require an STA; no process, transport, or capability is substituted.
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var session = new UiChildSession();
                var selected = new List<string>();
                var decisions = new List<(ulong Generation, bool Matches)>();
                var cancellations = new List<ulong>();
                using var controls = new WindowsPairingControls(() => session,
                    selected.Add, (generation, matches) => decisions.Add((generation, matches)), cancellations.Add);
                using var host = new System.Windows.Forms.Form();
                host.Controls.Add(controls);
                host.Show();
                session.ReceiveOutput(Frame(Snapshot(1, "browsing", "[{\"handle\":\"peer-1\",\"compatibility\":\"compatible\",\"freshness\":\"current\"},{\"handle\":\"stale-peer\",\"compatibility\":\"compatible\",\"freshness\":\"stale\"}]")));
                controls.Render();
                Assert.Equal(new[] { "peer-1" }, controls.Candidates.Items.Cast<string>());
                controls.SelectButton.PerformClick();
                Assert.Equal(new[] { "peer-1" }, selected);

                session.ReceiveOutput(Frame(Pairing(7)));
                controls.Render();
                Assert.Equal("ember  ocean  violet  copper", controls.Words.Text);
                session.ReceiveOutput(Frame(Pairing(8)));
                controls.MatchButton.PerformClick();
                Assert.Empty(decisions); // Stale rendered generation cannot approve the newer phrase.
                controls.Render();
                controls.MismatchButton.PerformClick();
                Assert.Equal(new[] { (8UL, false) }, decisions);

                session.ReceiveOutput(Frame(Pairing(9)));
                controls.Render();
                controls.MatchButton.PerformClick();
                controls.MatchButton.PerformClick();
                Assert.Equal(new[] { (8UL, false), (9UL, true) }, decisions);
                session.ReceiveOutput(Frame(Snapshot(10, "bootstrap_receipt_prepared")));
                controls.Render();
                Assert.False(controls.MatchButton.Enabled);
                Assert.True(controls.CancelButton.Enabled);
                controls.CancelButton.PerformClick();
                controls.CancelButton.PerformClick();
                Assert.Equal(new[] { 9UL }, cancellations);

                session.ReceiveOutput(Frame(Snapshot(11, "remote_outcome_unknown")));
                controls.Render();
                Assert.Equal("", controls.Words.Text);
                Assert.False(controls.SelectButton.Enabled);
                Assert.False(controls.MatchButton.Enabled);
                Assert.False(controls.MismatchButton.Enabled);
                Assert.False(controls.CancelButton.Enabled);
            }
            catch (Exception error) { failure = error; }
        });
        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "Native control assertions did not finish.");
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static string Pairing(ulong generation) => JsonSerializer.Serialize(new
    {
        v = 1, kind = "ui_pairing_v1", generation, phase = "awaiting_local_confirmation",
        candidate_handle = "peer-1", verification_words = new[] { "ember", "ocean", "violet", "copper" },
    });

    private static string Snapshot(ulong generation, string state, string candidates = "[]") => JsonSerializer.Serialize(new
    {
        v = 1, kind = "ui_snapshot_v1", snapshot = new
        {
            schema_version = 1, generation, state, diagnostics = Array.Empty<object>(),
            candidates = JsonSerializer.Deserialize<JsonElement>(candidates), confirmed = Array.Empty<object>(),
            inventory = (object?)null, layout = new { state = "not_configured" },
            capabilities = new { input_enabled = false, clipboard_enabled = false },
        },
    });

    private static byte[] Frame(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var frame = new byte[payload.Length + 4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(frame, payload.Length);
        payload.CopyTo(frame, 4);
        return frame;
    }
}
