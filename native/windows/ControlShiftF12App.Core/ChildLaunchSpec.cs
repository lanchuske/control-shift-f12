namespace ControlShiftF12App.Core;

public sealed record ChildLaunchSpec(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    IReadOnlyDictionary<string, string> Environment
)
{
    private static readonly string[] AllowedEnvironmentNames =
    [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "PATH",
    ];

    public static ChildLaunchSpec Create(
        string packageRoot,
        string childPath,
        IReadOnlyDictionary<string, string?> environment
    )
    {
        var normalizedRoot = Path.GetFullPath(packageRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedChild = Path.GetFullPath(childPath);
        var relativeChild = Path.GetRelativePath(normalizedRoot, normalizedChild);

        if (relativeChild is "." or ""
            || Path.IsPathRooted(relativeChild)
            || relativeChild.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || relativeChild.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal)
            || relativeChild == "..")
        {
            throw new ArgumentException("The child must be inside the installed package.", nameof(childPath));
        }

        var allowlisted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in AllowedEnvironmentNames)
        {
            if (environment.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                allowlisted[name] = value;
            }
        }

        return new ChildLaunchSpec(
            ExecutablePath: normalizedChild,
            Arguments: ["control", "--ui-stdio"],
            Environment: allowlisted
        );
    }
}
