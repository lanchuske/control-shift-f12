using System.Text;
using System.Text.Json;

namespace ControlShiftF12App.Core;

public sealed record DesktopSnapshotProjection(
    string State,
    IReadOnlyList<string> Nearby,
    bool InputEnabled,
    bool ClipboardEnabled,
    string ConnectionHealth
)
{
    private const int MaxFrameBytes = 256 * 1024;

    public static bool TryParse(string json, out DesktopSnapshotProjection? projection)
    {
        projection = null;
        if (Encoding.UTF8.GetByteCount(json) > MaxFrameBytes)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var frame = document.RootElement;
            if (!HasExactly(frame, ["v", "kind", "snapshot"])
                || !HasInteger(frame, "v", 1)
                || !HasString(frame, "kind", "ui_snapshot_v1")
                || !frame.TryGetProperty("snapshot", out var snapshot)
                || !HasExactly(snapshot, [
                    "schema_version", "generation", "state", "diagnostics", "candidates",
                    "confirmed", "inventory", "layout", "capabilities",
                ])
                || !HasInteger(snapshot, "schema_version", 1)
                || !HasNonzeroUInt64(snapshot, "generation")
                || !HasString(snapshot, "state", "not_started")
                || !EmptyArray(snapshot, "diagnostics")
                || !EmptyArray(snapshot, "candidates")
                || !EmptyArray(snapshot, "confirmed")
                || !IsNull(snapshot, "inventory")
                || !HasExactlyObject(snapshot, "layout", ["state"], "state", "not_configured")
                || !HasCapabilitiesDisabled(snapshot))
            {
                return false;
            }

            projection = new DesktopSnapshotProjection(
                State: "not_started",
                Nearby: [],
                InputEnabled: false,
                ClipboardEnabled: false,
                ConnectionHealth: "Not measured"
            );
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasCapabilitiesDisabled(JsonElement snapshot)
    {
        if (!snapshot.TryGetProperty("capabilities", out var capabilities)
            || !HasExactly(capabilities, ["input_enabled", "clipboard_enabled"]))
        {
            return false;
        }
        return capabilities.TryGetProperty("input_enabled", out var input)
            && input.ValueKind == JsonValueKind.False
            && capabilities.TryGetProperty("clipboard_enabled", out var clipboard)
            && clipboard.ValueKind == JsonValueKind.False;
    }

    private static bool HasExactlyObject(
        JsonElement parent,
        string property,
        string[] keys,
        string requiredKey,
        string requiredValue
    ) =>
        parent.TryGetProperty(property, out var value)
        && HasExactly(value, keys)
        && HasString(value, requiredKey, requiredValue);

    private static bool EmptyArray(JsonElement parent, string property) =>
        parent.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.Array
        && value.GetArrayLength() == 0;

    private static bool IsNull(JsonElement parent, string property) =>
        parent.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.Null;

    private static bool HasInteger(JsonElement objectValue, string property, int expected) =>
        objectValue.TryGetProperty(property, out var value)
        && value.TryGetInt32(out var actual)
        && actual == expected;

    private static bool HasNonzeroUInt64(JsonElement objectValue, string property) =>
        objectValue.TryGetProperty(property, out var value)
        && value.TryGetUInt64(out var actual)
        && actual > 0;

    private static bool HasString(JsonElement objectValue, string property, string expected) =>
        objectValue.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
        && value.GetString() == expected;

    private static bool HasExactly(JsonElement objectValue, IReadOnlyCollection<string> expected)
    {
        if (objectValue.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in objectValue.EnumerateObject())
        {
            if (!expected.Contains(property.Name) || !seen.Add(property.Name))
            {
                return false;
            }
        }
        return seen.Count == expected.Count;
    }
}
