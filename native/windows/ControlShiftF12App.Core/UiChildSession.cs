using System.Text;
using System.Text.Json;

namespace ControlShiftF12App.Core;

/// <summary>
/// Owns only the validated child-to-host projection state. A future platform
/// pipe owner may feed it bytes, but this type never starts a process, opens a
/// pipe, or enables a product capability on its own.
/// </summary>
public sealed class UiChildSession
{
    private const int MaxFrameBytes = 256 * 1024;
    private readonly FramedPayloadReader reader = new();
    private readonly HashSet<string> pendingRequestIds = new(StringComparer.Ordinal);
    private ulong nextRequestId;
    private ulong highestProjectionGeneration;

    public ChildSessionState State { get; private set; } = ChildSessionState.Starting();
    public DesktopSnapshotProjection? Snapshot { get; private set; }
    public DiagnosticsProjection? Diagnostics { get; private set; }
    public PairingProjection? Pairing { get; private set; }
    public bool IsAwaitingResponse(string requestId) => pendingRequestIds.Contains(requestId);

    public byte[] InitialRefreshFrame()
        => CreateRequest("ui.refresh");

    public byte[] StartDiscoveryFrame()
        => CreateRequest("ui.start_discovery");

    public byte[] StopDiscoveryFrame()
        => CreateRequest("ui.stop_discovery");

    public byte[] SelectCandidateFrame(string handle)
    {
        if (!IsHandle(handle)) throw new ArgumentException("Invalid opaque candidate handle.", nameof(handle));
        return CreateRequest("ui.select_candidate", new { handle });
    }

    public byte[] ApproveSasFrame(ulong generation, bool matches)
    {
        if (generation == 0) throw new ArgumentOutOfRangeException(nameof(generation));
        return CreateRequest("ui.approve_sas", new { generation, matches });
    }

    public byte[] CancelPairingFrame(ulong generation)
    {
        if (generation == 0) throw new ArgumentOutOfRangeException(nameof(generation));
        return CreateRequest("ui.cancel_pairing", new { generation });
    }

    private byte[] CreateRequest(string command, object? args = null)
    {
        if (State.Phase == ChildSessionPhase.Terminal || pendingRequestIds.Count >= 256
            || nextRequestId == ulong.MaxValue)
        {
            throw new InvalidOperationException("The local child request limit was reached.");
        }
        var id = $"windows-{++nextRequestId}";
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { v = 1, id, command, args = args ?? new { } });
        var frame = new byte[sizeof(uint) + payload.Length];
        frame[0] = (byte)(payload.Length >> 24);
        frame[1] = (byte)(payload.Length >> 16);
        frame[2] = (byte)(payload.Length >> 8);
        frame[3] = (byte)payload.Length;
        payload.CopyTo(frame, sizeof(uint));
        pendingRequestIds.Add(id);
        return frame;
    }

    private static bool IsHandle(string value) =>
        !string.IsNullOrEmpty(value) && value.Length <= 64
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    public void ReceiveOutput(IEnumerable<byte> bytes)
    {
        if (State.Phase == ChildSessionPhase.Terminal)
        {
            return;
        }
        reader.Append(bytes);
        Drain();
    }

    public void CompleteOutput()
    {
        if (State.Phase == ChildSessionPhase.Terminal)
        {
            return;
        }

        var outcome = reader.CompleteInput(out var payload);
        if (outcome == FrameReadOutcome.Complete && payload is not null)
        {
            Accept(payload);
            if (State.Phase != ChildSessionPhase.Terminal)
            {
                State = State.EndOfFile();
                ClearProjection();
            }
            return;
        }

        State = State.EndOfFile();
        ClearProjection();
    }

    private void Drain()
    {
        while (State.Phase != ChildSessionPhase.Terminal)
        {
            var outcome = reader.TryRead(out var payload);
            if (outcome == FrameReadOutcome.NeedMore)
            {
                return;
            }
            if (outcome == FrameReadOutcome.Invalid || payload is null)
            {
                State = State.ChannelFailure();
                ClearProjection();
                return;
            }
            Accept(payload);
        }
    }

    private void Accept(byte[] payload)
    {
        if (payload.Length is 0 or > MaxFrameBytes)
        {
            Fault();
            return;
        }
        try
        {
            using var document = JsonDocument.Parse(payload);
            if (!document.RootElement.TryGetProperty("kind", out var kind)
                || kind.ValueKind != JsonValueKind.String)
            {
                Fault();
                return;
            }

            var json = Encoding.UTF8.GetString(payload);
            switch (kind.GetString())
            {
                case "ui_snapshot_v1" when DesktopSnapshotProjection.TryParse(json, out var snapshot):
                    if (!AcceptProjectionGeneration(snapshot!.Generation))
                    {
                        return;
                    }
                    Snapshot = snapshot;
                    if (snapshot.State is "not_started" or "confirmed_relationship" or "remote_outcome_unknown")
                        Pairing = null;
                    State = State.ReceiveCurrentProjection(snapshot.Generation);
                    return;
                case "ui_diagnostics_v1" when DiagnosticsProjection.TryParse(json, out var diagnostics):
                    if (State.Phase != ChildSessionPhase.Running)
                    {
                        Fault();
                        return;
                    }
                    if (!AcceptProjectionGeneration(diagnostics!.Generation)) return;
                    Diagnostics = diagnostics;
                    return;
                case "ui_pairing_v1" when PairingProjection.TryParse(json, out var pairing):
                    if (State.Phase != ChildSessionPhase.Running)
                    {
                        Fault();
                        return;
                    }
                    if (!AcceptProjectionGeneration(pairing!.Generation)) return;
                    Pairing = pairing;
                    return;
                case "ui_response_v1" when IsRecognizedResponse(document.RootElement):
                    return;
                default:
                    Fault();
                    return;
            }
        }
        catch (JsonException)
        {
            Fault();
        }
    }

    private bool AcceptProjectionGeneration(ulong generation)
    {
        if (generation <= highestProjectionGeneration) return false;
        highestProjectionGeneration = generation;
        return true;
    }

    private bool IsRecognizedResponse(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object
        && root.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(["v", "kind", "id", "ok"])
        && root.TryGetProperty("v", out var version) && version.TryGetInt32(out var v) && v == 1
        && root.TryGetProperty("kind", out var kind) && kind.GetString() == "ui_response_v1"
        && root.TryGetProperty("id", out var id)
        && id.ValueKind == JsonValueKind.String
        && root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True
        && pendingRequestIds.Remove(id.GetString()!);

    private void Fault()
    {
        State = State.ChannelFailure();
        ClearProjection();
    }

    private void ClearProjection()
    {
        pendingRequestIds.Clear();
        Snapshot = null;
        Diagnostics = null;
        Pairing = null;
    }
}
