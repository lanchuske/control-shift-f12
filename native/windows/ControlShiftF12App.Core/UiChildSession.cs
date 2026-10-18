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

    public ChildSessionState State { get; private set; } = ChildSessionState.Starting();
    public DesktopSnapshotProjection? Snapshot { get; private set; }
    public DiagnosticsProjection? Diagnostics { get; private set; }
    public PairingProjection? Pairing { get; private set; }

    public byte[] InitialRefreshFrame()
        => CreateRequest("ui.refresh");

    public byte[] StartDiscoveryFrame()
        => CreateRequest("ui.start_discovery");

    public byte[] StopDiscoveryFrame()
        => CreateRequest("ui.stop_discovery");

    private byte[] CreateRequest(string command)
    {
        if (State.Phase == ChildSessionPhase.Terminal || pendingRequestIds.Count >= 256
            || nextRequestId == ulong.MaxValue)
        {
            throw new InvalidOperationException("The local child request limit was reached.");
        }
        var id = $"windows-{++nextRequestId}";
        var payload = Encoding.UTF8.GetBytes($"{{\"v\":1,\"id\":\"{id}\",\"command\":\"{command}\",\"args\":{{}}}}");
        var frame = new byte[sizeof(uint) + payload.Length];
        frame[0] = (byte)(payload.Length >> 24);
        frame[1] = (byte)(payload.Length >> 16);
        frame[2] = (byte)(payload.Length >> 8);
        frame[3] = (byte)payload.Length;
        payload.CopyTo(frame, sizeof(uint));
        pendingRequestIds.Add(id);
        return frame;
    }

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
                    Snapshot = snapshot;
                    State = State.ReceiveCurrentProjection(snapshot!.Generation);
                    return;
                case "ui_diagnostics_v1" when DiagnosticsProjection.TryParse(json, out var diagnostics):
                    if (State.Phase != ChildSessionPhase.Running
                        || Diagnostics is { Generation: var previous } && diagnostics!.Generation <= previous)
                    {
                        Fault();
                        return;
                    }
                    Diagnostics = diagnostics;
                    return;
                case "ui_pairing_v1" when PairingProjection.TryParse(json, out var pairing):
                    if (State.Phase != ChildSessionPhase.Running
                        || Pairing is { Generation: var previousPairing } && pairing!.Generation <= previousPairing)
                    {
                        Fault();
                        return;
                    }
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
