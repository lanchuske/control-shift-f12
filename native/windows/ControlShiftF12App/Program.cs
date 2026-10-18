using System;
using System.Windows.Forms;

namespace ControlShiftF12App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new DesktopShellForm());
    }
}
