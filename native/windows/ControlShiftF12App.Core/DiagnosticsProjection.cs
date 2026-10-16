using System.Text.Json;

namespace ControlShiftF12App.Core;

public sealed record DiagnosticsProjection(ulong Generation, IReadOnlyList<DiagnosticRow> Rows)
{
    private static readonly HashSet<string> FrameProperties = ["v", "kind", "generation", "rows"];
    private static readonly HashSet<string> RowProperties = ["id", "label", "state", "detail", "action", "failure_code"];
    private static readonly HashSet<string> DiagnosticIds = ["runtime", "input", "clipboard", "displays", "relationship", "session", "layout", "policy"];
    private static readonly HashSet<string> States = ["pass", "fail", "unknown", "not_configured"];
    private static readonly HashSet<string> Details = ["ready", "not_measured", "not_configured", "stale", "unavailable", "policy_blocked", "fault"];
    private static readonly HashSet<string> Actions = ["refresh", "review_local_permission", "review_private_network", "retry"];
    private static readonly HashSet<string> FailureCodes = [
        "runtime_status_unavailable", "input_permission_denied", "clipboard_unavailable",
        "clipboard_fault", "displays_unavailable", "discovery_unavailable", "session_unavailable",
    ];

    public static bool TryParse(string json, out DiagnosticsProjection? projection)
    {
        projection = null;
        try
        {
            using var document = JsonDocument.Parse(json);
            var frame = document.RootElement;
            if (frame.ValueKind != JsonValueKind.Object || !HasExactly(frame, FrameProperties)
                || !HasString(frame, "kind", "ui_diagnostics_v1")
                || !HasInt(frame, "v", 1)
                || !frame.TryGetProperty("generation", out var generationElement)
                || !generationElement.TryGetUInt64(out var generation)
                || !frame.TryGetProperty("rows", out var rowsElement)
                || rowsElement.ValueKind != JsonValueKind.Array
                || rowsElement.GetArrayLength() > 32)
            {
                return false;
            }

            var rows = new List<DiagnosticRow>();
            foreach (var row in rowsElement.EnumerateArray())
            {
                if (!TryParseRow(row, out var parsed)) return false;
                rows.Add(parsed!);
            }

            projection = new DiagnosticsProjection(generation, rows);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryParseRow(JsonElement row, out DiagnosticRow? parsed)
    {
        parsed = null;
        if (row.ValueKind != JsonValueKind.Object || !HasExactly(row, RowProperties)
            || !TryString(row, "id", DiagnosticIds, out var id)
            || !TryString(row, "label", DiagnosticIds, out var label)
            || !TryString(row, "state", States, out var state)
            || !TryString(row, "detail", Details, out var detail)
            || !TryOptionalString(row, "action", Actions, out var action)
            || !TryOptionalString(row, "failure_code", FailureCodes, out var failureCode))
        {
            return false;
        }

        parsed = new DiagnosticRow(id!, label!, state!, detail!, action, failureCode);
        return true;
    }

    private static bool HasExactly(JsonElement value, HashSet<string> expected) =>
        value.EnumerateObject().Select(property => property.Name).ToHashSet().SetEquals(expected);

    private static bool HasString(JsonElement value, string name, string expected) =>
        value.TryGetProperty(name, out var child) && child.ValueKind == JsonValueKind.String && child.GetString() == expected;

    private static bool HasInt(JsonElement value, string name, int expected) =>
        value.TryGetProperty(name, out var child) && child.TryGetInt32(out var actual) && actual == expected;

    private static bool TryString(JsonElement value, string name, HashSet<string> values, out string? text)
    {
        text = null;
        if (!value.TryGetProperty(name, out var child) || child.ValueKind != JsonValueKind.String) return false;
        text = child.GetString();
        return text is not null && values.Contains(text);
    }

    private static bool TryOptionalString(JsonElement value, string name, HashSet<string> values, out string? text)
    {
        text = null;
        if (!value.TryGetProperty(name, out var child)) return false;
        if (child.ValueKind == JsonValueKind.Null) return true;
        if (child.ValueKind != JsonValueKind.String) return false;
        text = child.GetString();
        return text is not null && values.Contains(text);
    }
}

public sealed record DiagnosticRow(string Id, string Label, string State, string Detail, string? Action, string? FailureCode);
