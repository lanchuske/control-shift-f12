using System;
using System.Drawing;
using System.Windows.Forms;
using ControlShiftF12App.Core;

namespace ControlShiftF12App;

/// <summary>
/// Presentation-only shell. It intentionally owns no engine, network, input,
/// clipboard, or pairing capability until the reviewed local pipe owner exists.
/// </summary>
internal sealed class DesktopShellForm : Form
{
    private static readonly Color Accent = Color.FromArgb(0, 103, 192);

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
    }

    private static Control BuildHeader(DesktopShellPresentation presentation)
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
        panel.Controls.Add(new Label
        {
            Text = "Connection health: Not connected",
            ForeColor = Color.FromArgb(122, 79, 0),
            AutoSize = true,
            Location = new Point(2, 68),
        });
        return panel;
    }

    private static Control BuildSetupPanel(DesktopShellPresentation presentation)
    {
        var group = CreateGroup("1. Pair computers");
        var content = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(14),
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
        content.Controls.Add(CreateDisabledButton("Find nearby computers"));
        content.Controls.Add(CreateDisabledButton("Confirm code on both computers"));
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
}
