#nullable enable

using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using ControlShiftF12App.Core;

namespace ControlShiftF12App;

/// <summary>
/// Presentation-only shell. Pairing gestures use only the reviewed local pipe;
/// operational input, clipboard and layout controls have no action bindings.
/// </summary>
internal sealed class DesktopShellForm : Form
{
    private static readonly Color Accent = Color.FromArgb(0, 103, 192);
    private WindowsUiChildOwner? childOwner;
    private Button? findNearbyButton;
    private Label? engineStatus;
    private WindowsPairingControls? pairingControls;
    private readonly UiCommandGate commandGate = new();
    private readonly Timer refreshTimer = new() { Interval = 1000 };
    private bool commandAffectsControls;
    private bool closing;
    private bool closeReady;

    public DesktopShellForm()
    {
        var presentation = DesktopShellPresentation.From(DesktopJourneyState.Initial());

        Text = "Control Shift F12";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1024, 680);
        Size = new Size(1280, 800);
        Font = new Font("Segoe UI", 10F);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(28),
            ColumnCount = 2,
            RowCount = 3,
            BackColor = Color.White,
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 300));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        root.Controls.Add(BuildHeader(presentation), 0, 0);
        root.SetColumnSpan(root.GetControlFromPosition(0, 0)!, 2);
        root.Controls.Add(BuildSetupPanel(presentation), 0, 1);
        root.Controls.Add(BuildLayoutPanel(), 1, 1);
        root.Controls.Add(BuildFooter(presentation), 0, 2);
        root.SetColumnSpan(root.GetControlFromPosition(0, 2)!, 2);
        Controls.Add(root);
        refreshTimer.Tick += async (_, _) => await RunChildCommandAsync(
            owner => owner.ObserveAsync(TimeSpan.FromMilliseconds(100)), affectsControls: false);
        Shown += async (_, _) => await ConnectLocalEngineAsync();
    }

    private Control BuildHeader(DesktopShellPresentation presentation)
    {
        var panel = new Panel { Dock = DockStyle.Fill, Height = 94, Margin = new Padding(0, 0, 0, 24) };
        panel.Controls.Add(new Label
        {
            Text = "Control Shift F12",
            Font = new Font("Segoe UI Semibold", 22F),
            AutoSize = true,
            Location = new Point(0, 0),
        });
        panel.Controls.Add(new Label
        {
            Text = $"{Environment.MachineName}  •  Windows  •  {presentation.Status}",
            ForeColor = Color.DimGray,
            AutoSize = true,
            Location = new Point(2, 43),
        });
        engineStatus = new Label
        {
            Text = "Connection health: Not connected",
            ForeColor = Color.FromArgb(122, 79, 0),
            AutoSize = true,
            Location = new Point(2, 68),
        };
        panel.Controls.Add(engineStatus);
        return panel;
    }

    private Control BuildSetupPanel(DesktopShellPresentation presentation)
    {
        var group = CreateGroup("1. Pair computers");
        var content = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(14),
            AutoScroll = true,
        };
        content.Controls.Add(new Label
        {
            Text = presentation.Title,
            Font = new Font("Segoe UI Semibold", 13F),
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 8),
        });
        content.Controls.Add(new Label
        {
            Text = "Nearby computers will appear here. Both computers will show the same short code before either one is paired.",
            AutoSize = false,
            Size = new Size(244, 68),
            ForeColor = Color.DimGray,
            Margin = new Padding(0, 0, 0, 16),
        });
        findNearbyButton = CreateDisabledButton("Find nearby computers");
        findNearbyButton.Click += async (_, _) => await StartLocalDiscoveryAsync();
        content.Controls.Add(findNearbyButton);
        pairingControls = new WindowsPairingControls(() => childOwner?.Session,
            async handle => await RunChildCommandAsync(owner => owner.SelectCandidateAsync(handle, TimeSpan.FromSeconds(3))),
            async (generation, matches) => await RunChildCommandAsync(owner => owner.ApproveSasAsync(generation, matches, TimeSpan.FromSeconds(3))),
            async generation => await RunChildCommandAsync(owner => owner.CancelPairingAsync(generation, TimeSpan.FromSeconds(3))));
        content.Controls.Add(pairingControls);
        content.Controls.Add(new Label
        {
            Text = "Discovery becomes available when the verified local engine session is connected.",
            AutoSize = false,
            Size = new Size(244, 55),
            ForeColor = Color.DimGray,
            Margin = new Padding(0, 14, 0, 0),
        });
        group.Controls.Add(content);
        return group;
    }

    private static Control BuildLayoutPanel()
    {
        var group = CreateGroup("2. Arrange displays");
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, Padding = new Padding(16) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.Controls.Add(new Label
        {
            Text = "Drag displays into their physical positions. The arrangement is shared and confirmed by both computers.",
            Dock = DockStyle.Fill,
            AutoSize = true,
            ForeColor = Color.DimGray,
            Margin = new Padding(0, 0, 0, 14),
        }, 0, 0);
        root.Controls.Add(BuildDisplayPreview(), 0, 1);
        root.Controls.Add(BuildShareControls(), 0, 2);
        group.Controls.Add(root);
        return group;
    }

    private static Control BuildDisplayPreview()
    {
        var canvas = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(246, 248, 251),
            BorderStyle = BorderStyle.FixedSingle,
            MinimumSize = new Size(500, 310),
            Margin = new Padding(0, 0, 0, 18),
        };
        var screen = new Panel
        {
            BackColor = Color.FromArgb(29, 50, 82),
            BorderStyle = BorderStyle.FixedSingle,
            Size = new Size(390, 220),
            Location = new Point(58, 42),
        };
        screen.Controls.Add(new Label
        {
            Text = $"{Environment.MachineName}\nWindows • Display 1\nLocal preview",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 12F),
            AutoSize = true,
            Location = new Point(20, 22),
        });
        canvas.Controls.Add(screen);
        canvas.Controls.Add(new Label
        {
            Text = "Pair another computer to enable the shared display map.",
            ForeColor = Color.DimGray,
            AutoSize = true,
            Location = new Point(56, 278),
        });
        return canvas;
    }

    private static Control BuildShareControls()
    {
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        panel.Controls.Add(CreateDisabledCheckBox("Input sharing", true));
        panel.Controls.Add(CreateDisabledCheckBox("Clipboard sharing", true));
        panel.Controls.Add(CreateDisabledCheckBox("Automatic updates", true));
        return panel;
    }

    private static Control BuildFooter(DesktopShellPresentation presentation)
    {
        var panel = new Panel { Dock = DockStyle.Fill, Height = 50, Margin = new Padding(0, 20, 0, 0) };
        panel.Controls.Add(new Label
        {
            Text = "Technical details are unavailable until a verified local session provides redacted evidence.",
            ForeColor = Color.DimGray,
            AutoSize = true,
            Location = new Point(0, 14),
        });
        return panel;
    }

    private static GroupBox CreateGroup(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        Font = new Font("Segoe UI Semibold", 11F),
        Margin = new Padding(0, 0, 22, 0),
    };

    private static Button CreateDisabledButton(string text) => new()
    {
        Text = text,
        Enabled = false,
        AutoSize = false,
        Size = new Size(244, 38),
        Margin = new Padding(0, 0, 0, 10),
        BackColor = Accent,
        ForeColor = Color.White,
        UseVisualStyleBackColor = false,
    };

    private static CheckBox CreateDisabledCheckBox(string text, bool selected) => new()
    {
        Text = text,
        Checked = selected,
        Enabled = false,
        AutoSize = true,
        Margin = new Padding(0, 0, 24, 0),
    };

    private async Task ConnectLocalEngineAsync()
    {
        var packageRoot = AppContext.BaseDirectory;
        var enginePath = Path.Combine(packageRoot, "Resources", "seamless-input.exe");
        if (!File.Exists(enginePath))
        {
            SetEngineStatus("Local engine unavailable — pairing is safely disabled.", Color.FromArgb(122, 79, 0));
            return;
        }

        try
        {
            var environment = Environment.GetEnvironmentVariables()
                .Keys.Cast<object>()
                .ToDictionary(key => key.ToString()!, key => Environment.GetEnvironmentVariable(key.ToString()!));
            var spec = ChildLaunchSpec.Create(packageRoot, enginePath, environment);
            childOwner = await WindowsUiChildOwner.StartAsync(spec);
            var session = await childOwner.ReadInitialProjectionAsync(TimeSpan.FromSeconds(3));
            if (closing) return;
            if (session.State.Phase != ChildSessionPhase.Running || session.Snapshot is null)
            {
                await childOwner.DisposeAsync();
                childOwner = null;
                SetEngineStatus("Local engine did not provide a valid state — pairing is disabled.", Color.Firebrick);
                return;
            }

            RenderCurrentState();
            refreshTimer.Start();
        }
        catch (Exception)
        {
            if (closing) return;
            if (childOwner is not null)
            {
                await childOwner.DisposeAsync();
                childOwner = null;
            }
            SetEngineStatus("Local engine could not start — pairing is disabled.", Color.Firebrick);
        }
    }

    private async Task StartLocalDiscoveryAsync()
    {
        var currentOwner = childOwner;
        if (currentOwner is null || currentOwner.Session.Pairing is not null) return;
        var stopDiscovery = currentOwner.Session.Snapshot?.State == "browsing";
        await RunChildCommandAsync(owner => stopDiscovery
            ? owner.StopDiscoveryAsync(TimeSpan.FromSeconds(3))
            : owner.StartDiscoveryAsync(TimeSpan.FromSeconds(3)));
    }

    private async Task RunChildCommandAsync(
        Func<WindowsUiChildOwner, Task<UiChildSession>> command,
        bool affectsControls = true)
    {
        if (closing || childOwner is null) return;
        if (affectsControls)
        {
            if (commandAffectsControls) return;
            commandAffectsControls = affectsControls;
            RenderCurrentState();
        }
        try
        {
            await commandGate.RunAsync(waitForTurn: affectsControls, async () =>
            {
                if (closing || childOwner is not { } owner) return;
                try
                {
                    await command(owner);
                    if (owner.Session.State.Phase == ChildSessionPhase.Terminal) refreshTimer.Stop();
                }
                catch (Exception error)
                {
                    // A stale queued gesture is rejected before it writes. Real transport failures
                    // remain terminal and are never replayed automatically.
                    if (ShouldTerminateCommand(error))
                    {
                        refreshTimer.Stop();
                        owner.Session.CompleteOutput();
                    }
                }
                if (!closing) RenderCurrentState();
            });
        }
        finally
        {
            if (affectsControls)
            {
                commandAffectsControls = false;
                if (!closing) RenderCurrentState();
            }
        }
    }

    internal static bool ShouldDisableControls(bool gesturePending) => gesturePending;

    internal static bool ShouldTerminateCommand(Exception error) =>
        error is not UiGestureRejectedException;

    private void RenderCurrentState()
    {
        var controlsBusy = ShouldDisableControls(commandAffectsControls);
        pairingControls?.Render(controlsBusy);
        if (childOwner is not { } owner || findNearbyButton is null) return;
        var session = owner.Session;
        var state = session.Snapshot?.State;
        findNearbyButton.Text = state == "browsing" ? "Stop searching" : "Find nearby computers";
        findNearbyButton.Enabled = !controlsBusy && session.State.Phase == ChildSessionPhase.Running
            && session.Pairing is null && state is "not_started" or "browsing";
        SetEngineStatus(G4PairingPresentation.From(session).Status,
            session.State.Phase == ChildSessionPhase.Running ? Color.FromArgb(0, 103, 80) : Color.Firebrick);
    }

    private void SetEngineStatus(string text, Color color)
    {
        if (engineStatus is null) return;
        engineStatus.Text = text;
        engineStatus.ForeColor = color;
    }

    protected override async void OnFormClosing(FormClosingEventArgs e)
    {
        if (closeReady || childOwner is null) { base.OnFormClosing(e); return; }
        e.Cancel = true;
        base.OnFormClosing(e);
        if (closing) return;
        closing = true;
        refreshTimer.Stop();
        try { await childOwner.DisposeAsync(); }
        catch (Exception) { /* Closing never exposes raw child detail or replays a gesture. */ }
        childOwner = null;
        closeReady = true;
        Close();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        closing = true;
        refreshTimer.Stop();
        refreshTimer.Dispose();
        base.OnFormClosed(e);
    }
}

internal sealed class UiCommandGate
{
    private readonly System.Threading.SemaphoreSlim gate = new(1, 1);
    private int foregroundQueued;

    internal async Task<bool> RunAsync(bool waitForTurn, Func<Task> command)
    {
        var ownsForegroundSlot = waitForTurn
            && System.Threading.Interlocked.CompareExchange(ref foregroundQueued, 1, 0) == 0;
        if (waitForTurn && !ownsForegroundSlot) return false;
        try
        {
            var entered = waitForTurn
                ? await WaitForTurnAsync()
                : await gate.WaitAsync(0);
            if (!entered) return false;
            try
            {
                await command();
                return true;
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            if (ownsForegroundSlot)
                System.Threading.Volatile.Write(ref foregroundQueued, 0);
        }
    }

    private async Task<bool> WaitForTurnAsync()
    {
        await gate.WaitAsync();
        return true;
    }
}

/// <summary>The real pairing surface, shared by the form and native-control tests.</summary>
internal sealed class WindowsPairingControls : FlowLayoutPanel
{
    internal ComboBox Candidates { get; } = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 244 };
    internal Button SelectButton { get; } = Button("Compare selected computer");
    internal Label Words { get; } = new() { AutoSize = false, Width = 244, Height = 56, AccessibleName = "Verification words" };
    internal Button MatchButton { get; } = Button("Match");
    internal Button MismatchButton { get; } = Button("Mismatch");
    internal Button CancelButton { get; } = Button("Cancel");
    private readonly Label status = new() { AutoSize = false, Width = 244, Height = 54 };
    private readonly Func<UiChildSession?> session;
    private readonly Action<string> select;
    private readonly Action<ulong, bool> approve;
    private readonly Action<ulong> cancel;
    private ulong? displayedGeneration;
    private ulong? displayedSnapshotGeneration;
    private ulong? submittedGeneration;
    private ulong? cancelledGeneration;
    private ulong? submittedSnapshotGeneration;
    private bool busy;
    private Control? observedParent;

    internal WindowsPairingControls(Func<UiChildSession?> session, Action<string> select,
        Action<ulong, bool> approve, Action<ulong> cancel)
    {
        this.session = session;
        this.select = select;
        this.approve = approve;
        this.cancel = cancel;
        FlowDirection = FlowDirection.TopDown;
        WrapContents = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Candidates.AccessibleName = "Current nearby computer";
        Words.Font = new Font("Segoe UI Semibold", 12F);
        Controls.AddRange([Candidates, SelectButton, status, Words, MatchButton, MismatchButton, CancelButton]);
        SelectButton.Click += (_, _) => SelectCurrentCandidate();
        MatchButton.Click += (_, _) => Decide(true);
        MismatchButton.Click += (_, _) => Decide(false);
        CancelButton.Click += (_, _) => CancelCurrentPairing();
        Render();
    }

    internal void Render(bool busy = false)
    {
        this.busy = busy;
        var current = session();
        var presentation = current is null ? null : G4PairingPresentation.From(current);
        displayedGeneration = presentation?.Generation;
        displayedSnapshotGeneration = current?.Snapshot?.Generation;
        var selected = Candidates.SelectedItem as string;
        Candidates.Items.Clear();
        foreach (var handle in presentation?.Candidates ?? []) Candidates.Items.Add(handle);
        if (selected is not null && Candidates.Items.Contains(selected)) Candidates.SelectedItem = selected;
        else if (Candidates.Items.Count > 0) Candidates.SelectedIndex = 0;
        SelectButton.Enabled = !busy && presentation?.CanSelect == true
            && displayedSnapshotGeneration != submittedSnapshotGeneration;
        Candidates.Enabled = SelectButton.Enabled;
        Words.Text = current?.Pairing?.VerificationWords is { Count: 4 } words
            ? string.Join(Environment.NewLine, words)
            : "";
        Words.Height = Words.GetPreferredSize(Size.Empty).Height;
        UpdateDecisionAvailability(presentation);
        CancelButton.Enabled = !busy && presentation?.CanCancel == true && displayedGeneration != cancelledGeneration;
        status.Text = presentation?.Status ?? "Local engine unavailable — pairing disabled";
        if (displayedGeneration is { } generation)
        {
            if (generation == cancelledGeneration) status.Text = "Waiting for cancellation — sharing remains off.";
            else if (generation == submittedGeneration) status.Text = "Waiting for the other computer — sharing remains off.";
        }
    }

    private void SelectCurrentCandidate()
    {
        var current = session();
        if (!SelectButton.Enabled || current?.State.Phase != ChildSessionPhase.Running
            || current.Snapshot is not { State: "browsing" } snapshot || current.Pairing is not null
            || snapshot.Generation != displayedSnapshotGeneration
            || Candidates.SelectedItem is not string handle || !snapshot.Nearby.Contains(handle)) return;
        submittedSnapshotGeneration = displayedSnapshotGeneration;
        Render(busy);
        select(handle);
    }

    private void Decide(bool matches)
    {
        var current = session();
        if (!MatchButton.Enabled || !VerificationWordsAreFullyVisible()
            || current?.State.Phase != ChildSessionPhase.Running
            || displayedGeneration is not { } generation
            || current.Pairing is not { Phase: PairingBridgePhase.AwaitingLocalConfirmation } pairing
            || pairing.Generation != generation) return;
        submittedGeneration = generation;
        if (!matches) cancelledGeneration = generation;
        Render(busy);
        approve(generation, matches);
    }

    internal bool VerificationWordsAreFullyVisible()
    {
        var lines = Words.Text.Split(Environment.NewLine);
        if (lines.Length != 4 || lines.Any(string.IsNullOrWhiteSpace)
            || !Words.Visible || !Words.IsHandleCreated) return false;
        var required = Words.GetPreferredSize(Size.Empty);
        var textBounds = new Rectangle(Words.PointToScreen(Point.Empty), required);
        var visibleBounds = Words.RectangleToScreen(Words.ClientRectangle);
        for (Control? ancestor = Words.Parent; ancestor is not null; ancestor = ancestor.Parent)
        {
            if (!ancestor.Visible || !ancestor.IsHandleCreated) return false;
            visibleBounds.Intersect(ancestor.RectangleToScreen(ancestor.ClientRectangle));
        }
        return visibleBounds.Contains(textBounds);
    }

    protected override void OnParentChanged(EventArgs e)
    {
        if (observedParent is not null)
        {
            observedParent.Layout -= ParentGeometryChanged;
            observedParent.SizeChanged -= ParentGeometryChanged;
            if (observedParent is ScrollableControl scrollable) scrollable.Scroll -= ParentScrolled;
        }
        base.OnParentChanged(e);
        observedParent = Parent;
        if (observedParent is not null)
        {
            observedParent.Layout += ParentGeometryChanged;
            observedParent.SizeChanged += ParentGeometryChanged;
            if (observedParent is ScrollableControl scrollable) scrollable.Scroll += ParentScrolled;
        }
    }

    protected override void OnLayout(LayoutEventArgs levent)
    {
        base.OnLayout(levent);
        UpdateDecisionAvailability();
    }

    private void ParentGeometryChanged(object? sender, EventArgs e) => UpdateDecisionAvailability();

    private void ParentScrolled(object? sender, ScrollEventArgs e) => UpdateDecisionAvailability();

    private void UpdateDecisionAvailability(G4PairingPresentation? presentation = null)
    {
        var current = session();
        presentation ??= current is null ? null : G4PairingPresentation.From(current);
        MatchButton.Enabled = !busy && presentation?.CanMatch == true
            && displayedGeneration != submittedGeneration && VerificationWordsAreFullyVisible();
        MismatchButton.Enabled = MatchButton.Enabled;
    }

    private void CancelCurrentPairing()
    {
        var current = session();
        if (!CancelButton.Enabled || current?.State.Phase != ChildSessionPhase.Running
            || displayedGeneration is not { } generation || current.Pairing?.Generation != generation) return;
        submittedGeneration = generation;
        cancelledGeneration = generation;
        Render(busy);
        cancel(generation);
    }

    private static Button Button(string text) => new() { Text = text, Width = 244, Height = 34, Enabled = false };
}
