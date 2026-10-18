using System.Text;

var block = new string('e', 8192);
for (var written = 0; written < (2 * 1024 * 1024) + 8192; written += block.Length)
{
    Console.Error.Write(block);
}
Console.Error.Flush();

const string json = """
{"v":1,"kind":"ui_snapshot_v1","snapshot":{"schema_version":1,"generation":1,"state":"not_started","diagnostics":[],"candidates":[],"confirmed":[],"inventory":null,"layout":{"state":"not_configured"},"capabilities":{"input_enabled":false,"clipboard_enabled":false}}}
""";
var payload = Encoding.UTF8.GetBytes(json);
var prefix = new byte[]
{
    (byte)(payload.Length >> 24),
    (byte)(payload.Length >> 16),
    (byte)(payload.Length >> 8),
    (byte)payload.Length,
};
await Console.OpenStandardOutput().WriteAsync(prefix);
await Console.OpenStandardOutput().WriteAsync(payload);
await Console.OpenStandardOutput().FlushAsync();
_ = Console.In.ReadToEnd();
