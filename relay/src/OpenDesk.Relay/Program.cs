using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("connections", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 20, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
var app = builder.Build();
app.UseRateLimiter();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
var hosts = new ConcurrentDictionary<string, Peer>(StringComparer.Ordinal);
var gate = new object();
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.Map("/ws", async context =>
{
    if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }
    using var socket = await context.WebSockets.AcceptWebSocketAsync();
    var peer = new Peer(socket);
    try
    {
        while (socket.State == WebSocketState.Open)
        {
            var raw = await peer.Receive(context.RequestAborted);
            if (raw is null) break;
            using var document = JsonDocument.Parse(raw);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) continue;
            if (!root.TryGetProperty("type", out var typeNode) || typeNode.ValueKind != JsonValueKind.String) continue;
            var type = typeNode.GetString();
            if (type == "register")
            {
                if (!root.TryGetProperty("code", out var c) || c.ValueKind != JsonValueKind.String) { await peer.Send(new { type = "error", message = "Invalid code." }); continue; }
                var code = c.GetString()!;
                if (code.Length < 12 || code.Length > 64 || !code.All(char.IsAsciiLetterOrDigit)) { await peer.Send(new { type = "error", message = "Code must contain 12 to 64 letters or digits." }); continue; }
                bool registered;
                lock (gate)
                {
                    registered = peer.Code is null && peer.Other is null && hosts.TryAdd(code, peer);
                    if (registered) peer.Code = code;
                }
                await peer.Send(registered ? new { type = "registered", message = "Ready." } : new { type = "error", message = "Registration unavailable." });
            }
            else if (type == "join")
            {
                if (!peer.AllowJoin()) { await peer.Send(new { type = "error", message = "Too many attempts. Wait one minute." }); continue; }
                var code = root.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
                Peer? host = null;
                lock (gate)
                {
                    if (peer.Code is null && peer.Other is null && code is not null && hosts.TryGetValue(code, out var candidate) && candidate.Other is null && candidate != peer && candidate.Socket.State == WebSocketState.Open)
                    { host = candidate; host.Other = peer; peer.Other = host; host.Generation++; peer.Generation++; }
                }
                if (host is null) await peer.Send(new { type = "error", message = "Connection unavailable." });
                else { await peer.Send(new { type = "pending" }); await host.Send(new { type = "request" }); }
            }
            else if (type == "approve" || type == "reject")
            {
                Peer? viewer;
                lock (gate)
                {
                    viewer = peer.Code is not null && !peer.Approved ? peer.Other : null;
                    if (viewer is not null)
                    {
                        if (type == "approve") { peer.Approved = true; viewer.Approved = true; }
                        else { Unpair(peer); }
                    }
                }
                if (viewer is not null)
                {
                    await viewer.Send(new { type = type == "approve" ? "connected" : "rejected" });
                    if (type == "approve") await peer.Send(new { type = "connected" });
                }
            }
            else if (type == "disconnect")
            {
                Peer? other;
                lock (gate) { other = Unpair(peer); }
                if (other is not null) await other.Send(new { type = "peer-left" });
                await peer.Send(new { type = "disconnected" });
            }
            // Only endpoint handshakes and ciphertext cross the relay. No plaintext fallback.
            else if (type is "handshake" or "secure")
            {
                Peer? other; long generation;
                lock (gate) { other = peer.Approved ? peer.Other : null; generation = peer.Generation; }
                if (other is not null) await other.SendPairedRaw(raw, gate, () => peer.Approved && peer.Generation == generation && ReferenceEquals(peer.Other, other) && ReferenceEquals(other.Other, peer));
            }
        }
    }
    catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or JsonException or InvalidDataException) { }
    finally
    {
        Peer? other;
        lock (gate)
        {
            if (peer.Code is not null) hosts.TryRemove(peer.Code, out _);
            other = Unpair(peer);
        }
        if (other is not null) await other.Send(new { type = "peer-left" });
        if (socket.State == WebSocketState.Open) try { await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Session ended", CancellationToken.None); } catch (WebSocketException) { }
    }
}).RequireRateLimiting("connections");
app.Run();

static Peer? Unpair(Peer peer)
{
    var other = peer.Other;
    peer.Other = null; peer.Approved = false; peer.Generation++;
    if (other is not null) { other.Other = null; other.Approved = false; other.Generation++; }
    return other;
}

sealed class Peer(WebSocket socket)
{
    public WebSocket Socket { get; } = socket;
    public string? Code { get; set; }
    public Peer? Other { get; set; }
    public bool Approved { get; set; }
    public long Generation { get; set; }
    private readonly SemaphoreSlim sendGate = new(1, 1);
    private readonly Queue<DateTime> joins = new();
    public bool AllowJoin()
    {
        var now = DateTime.UtcNow;
        while (joins.TryPeek(out var t) && now - t > TimeSpan.FromMinutes(1)) joins.Dequeue();
        if (joins.Count >= 5) return false;
        joins.Enqueue(now); return true;
    }
    public Task Send(object value) => SendRaw(JsonSerializer.SerializeToUtf8Bytes(value));
    // Re-check pairing after the send queue, so packets waiting from an older
    // pairing cannot be forwarded into a newer connection on the same host socket.
    public async Task SendPairedRaw(byte[] bytes, object pairingGate, Func<bool> isCurrent)
    {
        await sendGate.WaitAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            ValueTask operation;
            lock (pairingGate)
            {
                if (!isCurrent() || Socket.State != WebSocketState.Open) return;
                // Submit before pairing can change; later control messages use sendGate too.
                operation = Socket.SendAsync(bytes.AsMemory(), WebSocketMessageType.Text, true, timeout.Token);
            }
            await operation;
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException) { Socket.Abort(); }
        finally { sendGate.Release(); }
    }
    public async Task SendRaw(byte[] bytes)
    {
        await sendGate.WaitAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            if (Socket.State == WebSocketState.Open) await Socket.SendAsync(bytes.AsMemory(), WebSocketMessageType.Text, true, timeout.Token);
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException) { Socket.Abort(); }
        finally { sendGate.Release(); }
    }
    public async Task<byte[]?> Receive(CancellationToken token)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var result = await Socket.ReceiveAsync(buffer.AsMemory(), token);
            if (result.MessageType == WebSocketMessageType.Close) return null;
            if (result.MessageType != WebSocketMessageType.Text || stream.Length + result.Count > 12 * 1024 * 1024) throw new InvalidDataException("Message limit exceeded.");
            stream.Write(buffer, 0, result.Count);
            if (result.EndOfMessage) return stream.ToArray();
        }
    }
}


