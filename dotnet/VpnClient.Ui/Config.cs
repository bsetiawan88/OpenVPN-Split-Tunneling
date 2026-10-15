using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VpnClient.Ui;

public class Config
{
    public List<OvpnEntry> OvpnFiles { get; set; } = new();
    public string? ActiveOvpnId { get; set; }
    public List<AppEntry> TunneledApps { get; set; } = new();

    /// <summary>Rotate VPN profile on a timer (round-robin through discovered .ovpn files).</summary>
    public bool RotateEnabled { get; set; } = false;

    /// <summary>Rotate interval in minutes. Clamped to 5..720 on load.</summary>
    public int RotateIntervalMinutes { get; set; } = 30;

    /// <summary>Show the activity-log panel on the main window.</summary>
    public bool LoggingEnabled { get; set; } = false;

    /// <summary>
    /// Full tunnel: accept the server-pushed redirect-gateway so ALL traffic
    /// egresses via the VPN (like the plain openvpn launch). When false, the
    /// redirect is filtered and only listed apps are pinned to the tunnel
    /// (split-tunnel — known broken on some Proton+DCO setups where the
    /// tunnel itself dies right after handshake when redirect is stripped).
    /// Default true: a working tunnel beats a principled-but-dead split.
    /// </summary>
    public bool FullTunnel { get; set; } = true;

    [JsonIgnore]
    public static string AppDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VpnClient");

    [JsonIgnore]
    public static string ConfigPath => Path.Combine(AppDataDir, "config.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static Config Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                var cfg = JsonSerializer.Deserialize<Config>(json, JsonOpts);
                if (cfg is not null)
                {
                    cfg.MigrateInPlace();
                    return cfg;
                }
            }
        }
        catch (Exception ex)
        {
            // Bad config — start fresh, log to stderr for diagnostics
            Console.Error.WriteLine($"config load failed: {ex.Message}");
        }
        return new Config();
    }

    /// <summary>
    /// Drop any legacy "host:port" stored under ServerHostname down to just the host.
    /// We now display hostname-only to match OpenVPN Connect's convention.
    /// Also clamps the rotate interval into range.
    /// </summary>
    private void MigrateInPlace()
    {
        var dirty = false;
        foreach (var entry in OvpnFiles)
        {
            // Strip legacy "host:port" down to host. Guard bracketed/bare
            // IPv6 (multiple colons) — truncating those would corrupt them.
            var h = entry.ServerHostname;
            if (!string.IsNullOrEmpty(h) && h.IndexOf(':') == h.LastIndexOf(':'))
            {
                var idx = h.IndexOf(':');
                if (idx > 0)
                {
                    entry.ServerHostname = h[..idx];
                    dirty = true;
                }
            }
        }
        if (RotateIntervalMinutes < 5) { RotateIntervalMinutes = 5; dirty = true; }
        if (RotateIntervalMinutes > 720) { RotateIntervalMinutes = 720; dirty = true; }
        if (dirty)
        {
            try { Save(); } catch { }
        }
    }

    /// <summary>
    /// Reconcile saved credentials/overrides with the .ovpn files actually on
    /// disk under the OpenVPN config dir. Files are the source of truth; the
    /// JSON store only keeps per-file credentials + server override.
    /// </summary>
    public void RefreshFromDisk()
    {
        try
        {
            var scanned = OpenVpnConfigSource.Scan(OvpnFiles);
            OvpnFiles = scanned;
            if (!string.IsNullOrEmpty(ActiveOvpnId)
                && OvpnFiles.All(p => p.Id != ActiveOvpnId))
            {
                ActiveOvpnId = OvpnFiles.FirstOrDefault()?.Id;
            }
            if (string.IsNullOrEmpty(ActiveOvpnId))
            {
                ActiveOvpnId = OvpnFiles.FirstOrDefault()?.Id;
            }
            Save();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"config refresh-from-disk failed: {ex.Message}");
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(AppDataDir);
        var json = JsonSerializer.Serialize(this, JsonOpts);
        File.WriteAllText(ConfigPath, json);
    }
}

public class OvpnEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string DisplayName { get; set; } = "";
    public string FilePath { get; set; } = "";

    /// <summary>The `remote &lt;host&gt; &lt;port&gt;` line parsed from the .ovpn file. Read-only display.</summary>
    public string ServerHostname { get; set; } = "";

    /// <summary>If set, used at connect time instead of <see cref="ServerHostname"/>. Format `host[:port]`.</summary>
    public string ServerOverride { get; set; } = "";

    /// <summary>Plaintext username (per `auth-user-pass`). Stored in user-scope config.</summary>
    public string Username { get; set; } = "";

    /// <summary>DPAPI-encrypted, base64-encoded password. Never set this directly — use SetPassword / GetPassword.</summary>
    public string PasswordEncrypted { get; set; } = "";

    public DateTime ImportedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    public string EffectiveServer => string.IsNullOrWhiteSpace(ServerOverride) ? ServerHostname : ServerOverride;

    public void SetPassword(string plain)
    {
        PasswordEncrypted = Crypto.Encrypt(plain);
    }

    public string GetPassword()
    {
        return Crypto.Decrypt(PasswordEncrypted);
    }
}

public class AppEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string DisplayName { get; set; } = "";
    public string ExePath { get; set; } = "";
    public DateTime AddedAt { get; set; } = DateTime.UtcNow;
}
