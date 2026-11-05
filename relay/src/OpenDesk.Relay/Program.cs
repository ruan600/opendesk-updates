using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var limits = RelayLimits.Read(builder.Configuration);
// Disable ASP.NET's permissive environment opt-in; only explicitly listed proxy IPs
// may affect rate-limit identities. A caller's X-Forwarded-For alone is never trusted.
builder.Configuration["FORWARDEDHEADERS_ENABLED"] = "false";
var trustedProxies = builder.Configuration.GetSection("Relay:TrustedProxies").Get<string[]>() ?? [];
builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = trustedProxies.Length == 0 ? Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.None : Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor;
    options.KnownIPNetworks.Clear(); options.KnownProxies.Clear(); options.ForwardLimit = 1;
    foreach (var value in trustedProxies)
        options.KnownProxies.Add(System.Net.IPAddress.TryParse(value, out var ip) ? ip : throw new InvalidDataException("Relay trusted proxies must be literal IP addresses."));
});
builder.WebHost.UseSockets(options =>
{
    options.Backlog = 128;
    options.MaxReadBufferSize = 64 * 1024;
    options.MaxWriteBufferSize = 64 * 1024;
});
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxConcurrentConnections = limits.MaxConnections * 2;
    options.Limits.MaxConcurrentUpgradedConnections = limits.MaxConnections;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
    options.Limits.MaxRequestBodySize = 1024;
    options.Limits.MaxRequestLineSize = 2048;
    options.Limits.MaxRequestHeadersTotalSize = 8192;
    options.Limits.MaxRequestHeaderCount = 32;
    options.Limits.Http2.MaxStreamsPerConnection = 32;
});
var app = builder.Build();
app.UseForwardedHeaders();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20), KeepAliveTimeout = TimeSpan.FromSeconds(20) });
var resources = new RelayResources(limits);
var hosts = new ConcurrentDictionary<string, Peer>(StringComparer.Ordinal);
var gate = new object();
app.MapGet("/health", () => Results.Ok(new { status = "ok", version = "0.4.0", securityRevision = "2026-11-05-review-1" }));
app.Map("/ws", async context =>
{
    if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }
    string address = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    using var admission = resources.TryAdmit(address);
    if (admission is null) { context.Response.StatusCode = 429; return; }
    using var socket = await context.WebSockets.AcceptWebSocketAsync();
    var peer = new Peer(socket, resources, limits);
    using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
    var watchdog = peer.Watch(gate, lifetime.Token);
    try
    {
        while (socket.State == WebSocketState.Open)
        {
            using var received = await peer.Receive(lifetime.Token);
            if (received is null) break;
            if (!peer.AllowMessage()) throw new InvalidDataException("Message rate exceeded.");
            var raw = received.Bytes;
            var envelope = ReadEnvelope(raw);
            var type = envelope.Type;
            bool approved; lock (gate) approved = peer.Approved;
            if ((type is not ("handshake" or "secure") || !approved) && !peer.AllowControl()) throw new InvalidDataException("Control message rate exceeded.");
            if (type == "register")
            {
                if (envelope.Code is null) { await peer.Send(new { type = "error", message = "Invalid code." }); continue; }
                var code = envelope.Code;
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
                if (!peer.AllowJoin() || !resources.AllowJoin(address)) { await peer.Send(new { type = "error", message = "Too many attempts. Wait one minute." }); continue; }
                var code = envelope.Code;
                Peer? host = null;
                lock (gate)
                {
                    if (peer.Code is null && peer.Other is null && code is not null && hosts.TryGetValue(code, out var candidate) && candidate.Other is null && candidate != peer && candidate.Socket.State == WebSocketState.Open)
                    { host = candidate; host.Other = peer; peer.Other = host; host.Generation++; peer.Generation++; peer.PairDeadline = DateTimeOffset.UtcNow.AddSeconds(limits.PendingSeconds); }
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
                        if (type == "approve") { peer.Approved = true; viewer.Approved = true; viewer.PairDeadline = null; }
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
        lifetime.Cancel();
        try { await watchdog; } catch (OperationCanceledException) { }
        Peer? other;
        lock (gate)
        {
            if (peer.Code is not null) hosts.TryRemove(peer.Code, out _);
            other = Unpair(peer);
        }
        if (other is not null) await other.Send(new { type = "peer-left" });
        if (socket.State == WebSocketState.Open) try { using var closeDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2)); await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Session ended", closeDeadline.Token); } catch (Exception ex) when (ex is WebSocketException or OperationCanceledException) { socket.Abort(); }
    }
});
app.Run();

static Peer? Unpair(Peer peer)
{
    var other = peer.Other;
    peer.Other = null; peer.Approved = false; peer.Generation++; peer.BecameUnpaired();
    if (other is not null) { other.Other = null; other.Approved = false; other.Generation++; other.BecameUnpaired(); }
    return other;
}

// Parse routing metadata without materializing attacker-controlled JSON trees or ciphertext.
static (string Type, string? Code) ReadEnvelope(ReadOnlySpan<byte> bytes)
{
    var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 8 });
    if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) throw new InvalidDataException("Invalid envelope.");
    string? type = null, code = null; bool sawCode = false; int properties = 0;
    while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
    {
        if (reader.TokenType != JsonTokenType.PropertyName || reader.ValueSpan.Length > 128 || ++properties > 16) throw new InvalidDataException("Invalid envelope properties.");
        bool isType = reader.ValueTextEquals("type"u8), isCode = reader.ValueTextEquals("code"u8);
        if (!reader.Read()) throw new InvalidDataException("Incomplete envelope.");
        if (isType || isCode)
        {
            if (reader.TokenType != JsonTokenType.String || reader.ValueSpan.Length > 128 || (isType && type is not null) || (isCode && sawCode)) throw new InvalidDataException("Invalid routing metadata.");
            if (isType) type = reader.GetString(); else { code = reader.GetString(); sawCode = true; }
        }
        else reader.Skip();
    }
    if (reader.TokenType != JsonTokenType.EndObject || reader.Read() || string.IsNullOrEmpty(type)) throw new InvalidDataException("Invalid envelope.");
    return (type, code);
}

sealed record RelayLimits(int MaxConnections, int PerAddressConnections, int ConnectionsPerMinute, int JoinsPerMinute, int GlobalJoinsPerMinute, int UnregisteredSeconds, int PendingSeconds, int MessageSeconds, int SendSeconds, int MaxMessageBytes, int MaxBufferedBytes)
{
    public static RelayLimits Read(IConfiguration config)
    {
        int Read(string name, int fallback, int min, int max)
        {
            string? value = config["Relay:" + name];
            if (value is null) return fallback;
            if (!int.TryParse(value, out int result) || result < min || result > max) throw new InvalidDataException("Invalid Relay:" + name);
            return result;
        }
        int connections = Read("MaxConnections", 128, 2, 256);
        return new(connections, Read("PerAddressConnections", connections, 1, connections), Read("ConnectionsPerMinute", 240, 1, 1000), Read("JoinsPerMinute", 60, 1, 1000), Read("GlobalJoinsPerMinute", 240, 1, 1000), Read("UnregisteredSeconds", 15, 1, 60), Read("PendingSeconds", 30, 1, 60), Read("MessageSeconds", 20, 1, 60), Read("SendSeconds", 15, 1, 30), Read("MaxMessageBytes", 12 * 1024 * 1024, 1024, 12 * 1024 * 1024), Read("MaxBufferedBytes", 64 * 1024 * 1024, 4096, 256 * 1024 * 1024));
    }
}

// All address accounting is bounded, expires after inactivity, and survives reconnects.
sealed class RelayResources(RelayLimits limits)
{
    sealed class AddressState
    {
        public int Active;
        public long LastUsed;
        public readonly Queue<long> Connections = new(), Joins = new();
    }
    readonly object gate = new();
    readonly Dictionary<string, AddressState> addresses = new(StringComparer.Ordinal);
    readonly Queue<long> globalJoins = new();
    int active;
    long buffered;
    static void Prune(Queue<long> timestamps, long now) { while (timestamps.TryPeek(out var time) && now - time >= 60_000) timestamps.Dequeue(); }
    public IDisposable? TryAdmit(string address)
    {
        lock (gate)
        {
            long now = Environment.TickCount64;
            foreach (var stale in addresses.Where(pair => pair.Value.Active == 0 && now - pair.Value.LastUsed >= 120_000).Select(pair => pair.Key).ToArray()) addresses.Remove(stale);
            if (!addresses.TryGetValue(address, out var state))
            {
                if (addresses.Count >= 1024) return null;
                addresses.Add(address, state = new());
            }
            state.LastUsed = now; Prune(state.Connections, now);
            if (active >= limits.MaxConnections || state.Active >= limits.PerAddressConnections || state.Connections.Count >= limits.ConnectionsPerMinute) return null;
            active++; state.Active++; state.Connections.Enqueue(now);
            return new Lease(() => { lock (gate) { active--; state.Active--; state.LastUsed = Environment.TickCount64; } });
        }
    }
    public bool AllowJoin(string address)
    {
        lock (gate)
        {
            if (!addresses.TryGetValue(address, out var state)) return false;
            long now = Environment.TickCount64; state.LastUsed = now;
            Prune(state.Joins, now); Prune(globalJoins, now);
            if (state.Joins.Count >= limits.JoinsPerMinute || globalJoins.Count >= limits.GlobalJoinsPerMinute) return false;
            state.Joins.Enqueue(now); globalJoins.Enqueue(now); return true;
        }
    }
    public bool Reserve(int amount)
    {
        long current;
        do { current = Volatile.Read(ref buffered); if (amount > limits.MaxBufferedBytes - current) return false; }
        while (Interlocked.CompareExchange(ref buffered, current + amount, current) != current);
        return true;
    }
    public void Release(long amount) => Interlocked.Add(ref buffered, -amount);
    sealed class Lease(Action release) : IDisposable
    {
        Action? action = release;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
}

sealed class RelayMessage(byte[] bytes, RelayResources resources, long charge) : IDisposable
{
    public byte[] Bytes { get; } = bytes;
    long reserved = charge;
    public void Dispose() => resources.Release(Interlocked.Exchange(ref reserved, 0));
}

sealed class Peer(WebSocket socket, RelayResources resources, RelayLimits limits)
{
    public WebSocket Socket { get; } = socket;
    public string? Code { get; set; }
    public Peer? Other { get; set; }
    public bool Approved { get; set; }
    public long Generation { get; set; }
    public DateTimeOffset? PairDeadline { get; set; }
    DateTimeOffset unpairedDeadline = DateTimeOffset.UtcNow.AddSeconds(limits.UnregisteredSeconds);
    readonly SemaphoreSlim sendGate = new(1, 1);
    readonly Queue<long> joins = new(), controls = new();
    readonly byte[] receiveBuffer = new byte[65536];
    long messageWindow = Environment.TickCount64;
    int messages, pendingSends;
    public void BecameUnpaired() { PairDeadline = null; unpairedDeadline = DateTimeOffset.UtcNow.AddSeconds(limits.UnregisteredSeconds); }
    public async Task Watch(object pairingGate, CancellationToken token)
    {
        while (true)
        {
            await Task.Delay(250, token);
            bool expired;
            lock (pairingGate) expired = Code is null && ((Other is null && DateTimeOffset.UtcNow >= unpairedDeadline) || (!Approved && PairDeadline is DateTimeOffset deadline && DateTimeOffset.UtcNow >= deadline));
            if (expired) { Socket.Abort(); return; }
        }
    }
    bool Allow(Queue<long> timestamps, int limit)
    {
        long now = Environment.TickCount64;
        while (timestamps.TryPeek(out var time) && now - time >= 60_000) timestamps.Dequeue();
        if (timestamps.Count >= limit) return false;
        timestamps.Enqueue(now); return true;
    }
    public bool AllowJoin() => Allow(joins, 5);
    public bool AllowControl() => Allow(controls, 60);
    public bool AllowMessage()
    {
        long now = Environment.TickCount64;
        if (now - messageWindow >= 1000) { messageWindow = now; messages = 0; }
        return ++messages <= 400;
    }
    public Task Send(object value) => SendRaw(JsonSerializer.SerializeToUtf8Bytes(value));
    public Task SendRaw(byte[] bytes) => SendCore(bytes, null, null);
    public Task SendPairedRaw(byte[] bytes, object pairingGate, Func<bool> isCurrent) => SendCore(bytes, pairingGate, isCurrent);
    async Task SendCore(byte[] bytes, object? pairingGate, Func<bool>? isCurrent)
    {
        if (Interlocked.Increment(ref pendingSends) > 8) { Interlocked.Decrement(ref pendingSends); Socket.Abort(); return; }
        bool acquired = false;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(limits.SendSeconds));
        try
        {
            await sendGate.WaitAsync(timeout.Token); acquired = true;
            ValueTask operation;
            if (pairingGate is not null)
            {
                lock (pairingGate)
                {
                    if (!isCurrent!() || Socket.State != WebSocketState.Open) return;
                    operation = Socket.SendAsync(bytes.AsMemory(), WebSocketMessageType.Text, true, timeout.Token);
                }
            }
            else
            {
                if (Socket.State != WebSocketState.Open) return;
                operation = Socket.SendAsync(bytes.AsMemory(), WebSocketMessageType.Text, true, timeout.Token);
            }
            await operation.AsTask().WaitAsync(timeout.Token);
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException) { Socket.Abort(); }
        finally { if (acquired) sendGate.Release(); Interlocked.Decrement(ref pendingSends); }
    }
    public async Task<RelayMessage?> Receive(CancellationToken token)
    {
        using var stream = new MemoryStream();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        long charge = 0; int fragments = 0;
        try
        {
            while (true)
            {
                var result = await Socket.ReceiveAsync(receiveBuffer.AsMemory(), deadline.Token);
                if (result.MessageType == WebSocketMessageType.Close) return null;
                if (++fragments == 1) deadline.CancelAfter(TimeSpan.FromSeconds(limits.MessageSeconds));
                if (result.MessageType != WebSocketMessageType.Text || stream.Length + result.Count > limits.MaxMessageBytes || fragments > 16384) throw new InvalidDataException("Message limit exceeded.");
                // Account for MemoryStream growth plus the immutable forwarding copy.
                int reservation = 3 * Math.Max(result.Count, 256);
                if (!resources.Reserve(reservation)) throw new InvalidDataException("Relay buffer budget exceeded.");
                charge += reservation;
                stream.Write(receiveBuffer, 0, result.Count);
                if (result.EndOfMessage)
                {
                    var message = new RelayMessage(stream.ToArray(), resources, charge); charge = 0; return message;
                }
            }
        }
        finally { resources.Release(charge); }
    }
}
