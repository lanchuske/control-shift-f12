using System.Text;
using System.Text.Json;

namespace ControlShiftF12App.Core;

public sealed record DesktopSnapshotProjection(
    ulong Generation,
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
                || !EmptyArray(snapshot, "diagnostics")
                || !IsNull(snapshot, "inventory")
                || !HasExactlyObject(snapshot, "layout", ["state"], "state", "not_configured")
                || !HasCapabilitiesDisabled(snapshot))
            {
                return false;
            }

            if (!snapshot.TryGetProperty("state", out var stateValue)
                || stateValue.ValueKind != JsonValueKind.String
                || stateValue.GetString() is not { } state
                || !ValidRelationships(snapshot, state))
            {
                return false;
            }

            IReadOnlyList<string> nearby;
            switch (state)
            {
                case "not_started" when EmptyArray(snapshot, "candidates"):
                    nearby = [];
                    break;
                case "browsing" when TryParseCurrentCandidates(snapshot, out var currentCandidates):
                    nearby = currentCandidates;
                    break;
                case "confirmed_relationship" or "remote_outcome_unknown"
                    or "bootstrap_connecting" or "bootstrap_sas_pending" or "bootstrap_receipt_prepared"
                    when TryParseCurrentCandidates(snapshot, out _):
                    nearby = [];
                    break;
                default:
                    return false;
            }

            projection = new DesktopSnapshotProjection(
                Generation: snapshot.GetProperty("generation").GetUInt64(),
                State: state,
                Nearby: nearby,
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

    private static bool ValidRelationships(JsonElement snapshot, string state)
    {
        if (state != "confirmed_relationship") return EmptyArray(snapshot, "confirmed");
        if (!snapshot.TryGetProperty("confirmed", out var relationships)
            || relationships.ValueKind != JsonValueKind.Array
            || relationships.GetArrayLength() is 0 or > 32) return false;
        var handles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var relationship in relationships.EnumerateArray())
        {
            if (!HasExactly(relationship, ["handle", "state"])
                || !HasString(relationship, "state", "unavailable")
                || !relationship.TryGetProperty("handle", out var handle)
                || handle.ValueKind != JsonValueKind.String
                || handle.GetString() is not { Length: > 0 and <= 64 } value
                || !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')
                || !handles.Add(value)) return false;
        }
        return true;
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

    private static bool TryParseCurrentCandidates(
        JsonElement snapshot,
        out IReadOnlyList<string> candidates
    )
    {
        candidates = [];
        if (!snapshot.TryGetProperty("candidates", out var values)
            || values.ValueKind != JsonValueKind.Array
            || values.GetArrayLength() > 32)
        {
            return false;
        }

        var handles = new List<string>();
        var uniqueHandles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var candidate in values.EnumerateArray())
        {
            if (!HasExactly(candidate, ["handle", "compatibility", "freshness"])
                || !candidate.TryGetProperty("handle", out var handle)
                || handle.ValueKind != JsonValueKind.String
                || string.IsNullOrEmpty(handle.GetString())
                || handle.GetString()!.Length > 64
                || !handle.GetString()!.All(character =>
                    char.IsAsciiLetterOrDigit(character) || character is '-' or '_')
                || !(HasString(candidate, "compatibility", "compatible")
                    || HasString(candidate, "compatibility", "needs_update")
                    || HasString(candidate, "compatibility", "incompatible"))
                || !(HasString(candidate, "freshness", "current")
                    || HasString(candidate, "freshness", "stale")
                    || HasString(candidate, "freshness", "gone")))
            {
                return false;
            }
            if (!uniqueHandles.Add(handle.GetString()!))
            {
                return false;
            }
            if (HasString(candidate, "compatibility", "compatible") && HasString(candidate, "freshness", "current"))
                handles.Add(handle.GetString()!);
        }

        candidates = handles;
        return true;
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
