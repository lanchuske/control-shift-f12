using ControlShiftF12App.Core;
using System.Text;
using System.Text.Json;
using ControlShiftF12App;
using Xunit;

namespace ControlShiftF12App.Tests;

public sealed class DesktopShellPresentationTests
{
    [Fact]
    public void Background_observation_does_not_present_the_controls_as_busy()
    {
        Assert.True(DesktopShellForm.ShouldDisableControls(gesturePending: true));
        Assert.False(DesktopShellForm.ShouldDisableControls(gesturePending: false));
        Assert.False(DesktopShellForm.ShouldTerminateCommand(new UiGestureRejectedException("stale")));
        Assert.True(DesktopShellForm.ShouldTerminateCommand(new IOException("transport")));
    }

    [Fact]
    public async Task Visible_gesture_waits_for_observation_while_additional_observations_are_dropped()
    {
        var gate = new UiCommandGate();
        var observationEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseObservation = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var gestureRuns = 0;

        var observation = gate.RunAsync(waitForTurn: false, async () =>
        {
            observationEntered.SetResult();
            await releaseObservation.Task;
        });
        await observationEntered.Task;

        var gesture = gate.RunAsync(waitForTurn: true, () =>
        {
            gestureRuns++;
            return Task.CompletedTask;
        });
        var duplicateGesture = gate.RunAsync(waitForTurn: true, () => Task.CompletedTask);
        var skippedObservation = await gate.RunAsync(waitForTurn: false, () => Task.CompletedTask);
        Assert.False(skippedObservation);
        Assert.False(gesture.IsCompleted);
        Assert.True(duplicateGesture.IsCompleted);
        Assert.False(await duplicateGesture);

        releaseObservation.SetResult();
        Assert.True(await observation);
        Assert.True(await gesture);
        Assert.Equal(1, gestureRuns);
    }

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
                Assert.Equal(string.Join(Environment.NewLine, "ember", "ocean", "violet", "copper"), controls.Words.Text);
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

    [Fact]
    public void Native_controls_require_all_four_verification_words_to_be_visibly_laid_out()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var session = new UiChildSession();
                var decisions = new List<(ulong Generation, bool Matches)>();
                using var controls = new WindowsPairingControls(() => session,
                    _ => { }, (generation, matches) => decisions.Add((generation, matches)), _ => { });
                using var setupGroup = new System.Windows.Forms.GroupBox
                {
                    Width = 300,
                    Height = 600,
                    Padding = new System.Windows.Forms.Padding(0),
                };
                using var setupColumn = new System.Windows.Forms.FlowLayoutPanel
                {
                    FlowDirection = System.Windows.Forms.FlowDirection.TopDown,
                    WrapContents = false,
                    Dock = System.Windows.Forms.DockStyle.Fill,
                    Padding = new System.Windows.Forms.Padding(14),
                    AutoScroll = true,
                };
                using var host = new System.Windows.Forms.Form
                {
                    ClientSize = new System.Drawing.Size(1024, 680),
                };
                setupColumn.Controls.Add(controls);
                setupGroup.Controls.Add(setupColumn);
                host.Controls.Add(setupGroup);
                host.Show();

                session.ReceiveOutput(Frame(Snapshot(11, "browsing",
                    "[{\"handle\":\"peer-1\",\"compatibility\":\"compatible\",\"freshness\":\"current\"}]")));
                session.ReceiveOutput(Frame(Pairing(12,
                    ["abcdefghijklmnop", "qrstuvwxyzabcdef", "ghijklmnopqrstuv", "wxyzabcdefghijkl"])));
                Assert.NotNull(session.Pairing);
                Assert.Equal(4, session.Pairing!.VerificationWords.Count);
                controls.Render();
                host.PerformLayout();

                Assert.Equal(4, controls.Words.Text.Split(Environment.NewLine).Length);
                Assert.True(controls.VerificationWordsAreFullyVisible());
                Assert.True(controls.MatchButton.Enabled);

                foreach (var emSize in new[] { 12F, 18F, 24F })
                {
                    var scale = emSize / 12F;
                    setupGroup.Width = (int)Math.Round(300 * scale);
                    controls.Words.Width = (int)Math.Round(244 * scale);
                    controls.Words.Font = new System.Drawing.Font("Segoe UI Semibold", emSize);
                    controls.Render();
                    host.PerformLayout();
                    Assert.Equal(controls.Words.GetPreferredSize(System.Drawing.Size.Empty).Height,
                        controls.Words.ClientSize.Height);
                    Assert.True(controls.VerificationWordsAreFullyVisible());
                    Assert.True(controls.MatchButton.Enabled);
                }
                setupGroup.Width = 300;
                controls.Words.Width = 244;
                controls.Words.Font = new System.Drawing.Font("Segoe UI Semibold", 12F);
                controls.Render();
                host.PerformLayout();

                setupGroup.Height = 150;
                setupColumn.AutoScrollPosition = new System.Drawing.Point(0, controls.Words.Bottom);
                host.PerformLayout();
                Assert.Equal(244, controls.Words.ClientSize.Width);
                Assert.False(controls.VerificationWordsAreFullyVisible());
                Assert.False(controls.MatchButton.Enabled);
                setupGroup.Height = 600;
                setupColumn.AutoScrollPosition = System.Drawing.Point.Empty;
                host.PerformLayout();
                controls.Render();
                Assert.True(controls.MatchButton.Enabled);

                setupGroup.Width = 120;
                host.PerformLayout();
                Assert.Equal(244, controls.Words.ClientSize.Width);
                Assert.False(controls.VerificationWordsAreFullyVisible());
                Assert.False(controls.MatchButton.Enabled);

                setupGroup.Width = 300;
                host.PerformLayout();
                controls.Render();
                Assert.True(controls.MatchButton.Enabled);
                setupGroup.Width = 120;
                host.PerformLayout();
                controls.MatchButton.Enabled = true; // falsifies stale visual state; dispatch must re-check geometry.
                controls.MatchButton.PerformClick();
                Assert.Empty(decisions);
            }
            catch (Exception error) { failure = error; }
        });
        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "Native layout assertions did not finish.");
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static string Pairing(ulong generation) => Pairing(generation, ["ember", "ocean", "violet", "copper"]);

    private static string Pairing(ulong generation, string[] words) => JsonSerializer.Serialize(new
    {
        v = 1,
        kind = "ui_pairing_v1",
        generation,
        phase = "awaiting_local_confirmation",
        candidate_handle = "peer-1",
        verification_words = words,
    });

    private static string Snapshot(ulong generation, string state, string candidates = "[]") => JsonSerializer.Serialize(new
    {
        v = 1,
        kind = "ui_snapshot_v1",
        snapshot = new
        {
            schema_version = 1,
            generation,
            state,
            diagnostics = Array.Empty<object>(),
            candidates = JsonSerializer.Deserialize<JsonElement>(candidates),
            confirmed = Array.Empty<object>(),
            inventory = (object?)null,
            layout = new { state = "not_configured" },
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
