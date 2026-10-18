using System.Text;
using System.Text.Json;

namespace ControlShiftF12App.Core;

public sealed record PairingProjection(
    ulong Generation,
    PairingBridgePhase Phase,
    string CandidateHandle,
    IReadOnlyList<string> VerificationWords
)
{
    public static bool TryParse(string json, out PairingProjection? projection)
    {
        projection = null;
        if (Encoding.UTF8.GetByteCount(json) > 256 * 1024) return false;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (!Exact(root, ["v", "kind", "generation", "phase", "candidate_handle", "verification_words"])
                || !Int(root, "v", 1) || !Text(root, "kind", "ui_pairing_v1")
                || !root.TryGetProperty("generation", out var generation) || !generation.TryGetUInt64(out var value) || value == 0
                || !root.TryGetProperty("phase", out var phase) || phase.GetString() is not { } phaseText
                || !root.TryGetProperty("candidate_handle", out var handle) || handle.ValueKind != JsonValueKind.String || !ValidHandle(handle.GetString()!)
                || !root.TryGetProperty("verification_words", out var words) || !ValidWords(words, out var parsed)) return false;
            if (phaseText != "awaiting_local_confirmation") throw new JsonException();
            var parsedPhase = PairingBridgePhase.AwaitingLocalConfirmation;
            projection = new(value, parsedPhase, handle.GetString()!, parsed);
            return true;
        }
        catch (JsonException) { return false; }
    }

    private static bool ValidHandle(string value) => value.Length is > 0 and <= 64 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    private static bool ValidWords(JsonElement value, out IReadOnlyList<string> words)
    {
        words = [];
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() != 4) return false;
        var values = value.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : null).ToArray();
        if (values.Any(word => word is null || word.Length is 0 or > 16 || word.Any(c => c is < 'a' or > 'z'))) return false;
        words = values!;
        return true;
    }
    private static bool Int(JsonElement value, string name, int expected) => value.TryGetProperty(name, out var item) && item.TryGetInt32(out var actual) && actual == expected;
    private static bool Text(JsonElement value, string name, string expected) => value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String && item.GetString() == expected;
    private static bool Exact(JsonElement value, IReadOnlyCollection<string> expected) => value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal).SetEquals(expected);
}
