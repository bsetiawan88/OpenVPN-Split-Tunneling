using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

/// <summary>
/// Launches openvpn.exe with the active profile and exposes stop via
/// OpenVPN's --management TCP interface, with Process.Kill as fallback.
///
/// Reconnect policy (mandatory): while <see cref="WantConnected"/> is true
/// the connector treats ANY unexpected openvpn exit — or an explicit
/// <see cref="NotifyVpnDownAsync"/> from the UI watchdog — as a failure to
/// repair, not a state to display. It restarts openvpn with exponential
/// backoff (5s → 60s cap) and keeps the same profile, forever, until the
/// user hits Disconnect. AUTH_FAILED in the log stops the loop: retrying a
/// bad password in a tight loop gets accounts locked.
/// </summary>
public class VpnConnector
{
    public string? ActiveProfileId { get; private set; }
    public OvpnEntry? CurrentProfile { get; private set; }
    public int ManagementPort { get; private set; }

    /// <summary>True between Connect and manual Disconnect. Drives auto-reconnect.</summary>
    public bool WantConnected { get; private set; }

    /// <summary>Master switch for auto-reconnect. Always true in production; tests can flip it.</summary>
    public bool ReconnectEnabled { get; set; } = true;

    public int ReconnectAttempt { get; private set; }
    public string LastError { get; private set; } = "";
    public DateTime? LastReconnectAt { get; private set; }

    /// <summary>Bumped on every DisconnectAsync: lets rotate detect an interleaved manual stop.</summary>
    public int DisconnectCount { get { lock (_lock) return _disconnectCount; } }
    private int _disconnectCount;

    public event EventHandler? StateChanged;
    public event EventHandler<string>? StatusMessage;

    private Process? _process;
    private CancellationTokenSource? _reconnectCts;
    private readonly object _lock = new();
    private bool _reconnecting;
    private int _epoch;

    private static readonly string[] OpenVpnPaths =
    {
        @"C:\Program Files\OpenVPN\bin\openvpn.exe",
        @"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
    };

    private static readonly TimeSpan[] ReconnectBackoff =
    {
        TimeSpan.FromSeconds(5),
        TimeSpan.FromSeconds(10),
        TimeSpan.FromSeconds(20),
        TimeSpan.FromSeconds(30),
        TimeSpan.FromSeconds(60),
    };

    public static bool OpenVpnInstalled() => FindOpenVpn() is not null;

    public static string? FindOpenVpn()
    {
        foreach (var p in OpenVpnPaths)
            if (File.Exists(p)) return p;
        return null;
    }

    public async Task ConnectAsync(OvpnEntry profile)
    {
        CancelPendingReconnect();
        // Never stack tunnels: a Connect while already connected (e.g. the
        // profile window's Connect button) must retire the old openvpn
        // first, otherwise the orphan keeps its routes/ports untracked.
        await DisconnectAsync().ConfigureAwait(false);
        WantConnected = true;
        ReconnectAttempt = 0;
        LastError = "";
        await StartOpenVpnAsync(profile).ConfigureAwait(false);
    }

    /// <summary>
    /// Called by the UI watchdog when the redirector reports VPN down while
    /// we still want to be connected (adapter lost, but openvpn.exe may
    /// still be running in a wedged state). Kills + restarts the tunnel.
    /// Debounced: at most one restart in flight.
    /// </summary>
    public async Task NotifyVpnDownAsync()
    {
        lock (_lock)
        {
            if (!WantConnected || _reconnecting) return;
            _reconnecting = true;
        }
        try
        {
            // Recover a null profile (e.g. a failed rotate/disconnect race
            // nulled it while WantConnected stayed true): resolve the
            // configured active profile from disk instead of giving up.
            // Disk IO happens outside the lock.
            bool needFallback;
            lock (_lock) { needFallback = CurrentProfile is null; }
            if (needFallback)
            {
                try
                {
                    var cfg = Config.Load();
                    cfg.RefreshFromDisk();
                    var active = cfg.OvpnFiles.FirstOrDefault(p => p.Id == cfg.ActiveOvpnId)
                        ?? cfg.OvpnFiles.FirstOrDefault();
                    lock (_lock)
                    {
                        if (CurrentProfile is null) CurrentProfile = active;
                    }
                }
                catch { }
                lock (_lock)
                {
                    if (CurrentProfile is null) return;
                }
            }
            // Same AUTH_FAILED guard as the Exited path: a wedged-but-alive
            // openvpn with bad credentials must stop, not loop forever.
            if (LogIndicatesAuthFailure())
            {
                LastError = "Authentication failed (check username/password). Auto-reconnect stopped.";
                Status(LastError);
                await DisconnectAsync().ConfigureAwait(false);
                return;
            }
            Status("VPN down — reconnecting…");
            await RestartWithBackoffAsync("vpn-adapter-down").ConfigureAwait(false);
        }
        finally
        {
            lock (_lock) { _reconnecting = false; }
        }
    }

    /// <summary>Called when the redirector reports the adapter back up: the tunnel is healthy, reset the backoff ladder.</summary>
    public void NotifyVpnUp()
    {
        lock (_lock) { ReconnectAttempt = 0; }
    }

    private async Task StartOpenVpnAsync(OvpnEntry profile)
    {
        var openvpn = FindOpenVpn()
            ?? throw new FileNotFoundException(
                "openvpn.exe not found. Install the OpenVPN Community client from openvpn.net.");

        if (!File.Exists(profile.FilePath))
            throw new FileNotFoundException(
                $"Profile file not found:\n{profile.FilePath}\n" +
                $"OpenVPN config dir is: {OpenVpnConfigSource.DescribeDirs()}");

        var runtimeDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "VpnClient", "runtime");
        Directory.CreateDirectory(runtimeDir);

        var logFile = Path.Combine(runtimeDir, "openvpn.log");
        // Start every run with a fresh log: openvpn --log truncates on open,
        // but a run that fails before openvpn starts (missing file, bad
        // args) would otherwise leave a STALE log behind and the
        // AUTH_FAILED tail check could false-positive on the next exit.
        try { File.Delete(logFile); } catch { }
        ManagementPort = GetFreePort();

        // WorkingDirectory MUST be the .ovpn's folder: profiles reference
        // ca/cert/key/tls-auth by relative path. The old code launched with
        // the UI's CWD, so any profile with relative includes failed to start
        // — openvpn exited instantly and the UI sat on "Connecting…" with no
        // tunnel. This was the #1 "connected but nothing works" cause.
        var workDir = Path.GetDirectoryName(profile.FilePath) ?? runtimeDir;

        // True server override: rewrite `remote` lines into a runtime copy so
        // the override host is actually dialed first. (Appending --remote on
        // the CLI would only ADD a fallback tried after the config's own
        // remotes, not override them.) No override → use the file as-is.
        var configPath = ResolveEffectiveConfig(profile, runtimeDir);

        var args = new StringBuilder();
        args.Append($"--config \"{configPath}\" ");

        // Only pass --auth-user-pass when the profile actually needs it.
        // Unconditional auth with an empty file broke cert-only profiles and
        // turned missing-credential cases into silent AUTH_FAILED loops.
        // Both username AND password are required: a half-filled auth file
        // (one empty line) fails server-side just as opaquely.
        var needsAuth = OvpnParser.RequiresAuth(profile.FilePath);
        var hasCreds = !string.IsNullOrWhiteSpace(profile.Username)
            && !string.IsNullOrWhiteSpace(profile.GetPassword());
        if (needsAuth && hasCreds)
        {
            var authFile = Path.Combine(runtimeDir, "auth.txt");
            await File.WriteAllTextAsync(
                authFile,
                $"{profile.Username}\n{profile.GetPassword()}\n").ConfigureAwait(false);
            args.Append($"--auth-user-pass \"{authFile}\" ");
        }
        else if (needsAuth && !hasCreds)
        {
            // Let openvpn fail with a readable log line instead of feeding it
            // an empty auth file; the UI pre-checks this too.
            throw new InvalidOperationException(
                $"Profile \"{profile.DisplayName}\" needs a username + password.\n" +
                "Open the gear icon to add credentials and try again.");
        }

        // --windows-driver wintun bypasses the TAP-Windows6 DHCP path that
        // sometimes leaves the adapter stuck on 169.254.x.x even after
        // "Initialization Sequence Completed". Wintun does its own IP
        // configuration via SetIpInterfaceEntry.
        //
        // --pull-filter ignore redirect-gateway tells openvpn to drop the
        // server-pushed "default route via VPN" directive. Without it the
        // tunnel acts as a full-system VPN even for processes we don't want
        // to route through it. The redirector pins tunneled processes to
        // the VPN adapter via IP_UNICAST_IF, so they egress through the
        // tunnel without us hijacking the default route.
        args.Append($"--management 127.0.0.1 {ManagementPort} ");
        args.Append("--windows-driver wintun ");
        args.Append("--pull-filter ignore \"redirect-gateway\" ");
        args.Append("--pull-filter ignore \"block-outside-dns\" ");
        args.Append($"--log \"{logFile}\" ");
        args.Append("--verb 3");

        var psi = new ProcessStartInfo
        {
            FileName = openvpn,
            Arguments = args.ToString(),
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true,
            WorkingDirectory = workDir,
        };

        lock (_lock)
        {
            // A manual Disconnect during the awaits above (auth file write)
            // must not be followed by a fresh Process.Start — that would
            // resurrect the tunnel with WantConnected=false.
            if (!WantConnected) throw new OperationCanceledException("Connect cancelled (disconnected before start).");
        }

        var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start openvpn.exe");
        try
        {
            // Lift openvpn into the UI's Job Object so it dies when we do.
            JobManager.Assign(proc);
        }
        catch { }

        int epoch;
        lock (_lock)
        {
            _process = proc;
            _epoch++;
            epoch = _epoch;
        }
        try { proc.EnableRaisingEvents = true; } catch { }
        proc.Exited += (_, _) => _ = OnProcessExitedAsync(epoch);

        ActiveProfileId = profile.Id;
        CurrentProfile = profile;
        StateChanged?.Invoke(this, EventArgs.Empty);
        Status($"Connecting via \"{profile.DisplayName}\"…");

        await Task.CompletedTask.ConfigureAwait(false);
    }

    /// <summary>
    /// Returns the --config path to launch. When ServerOverride is set
    /// (format `host[:port]`), copies the .ovpn to the runtime dir with its
    /// `remote` lines replaced so the override is actually dialed. Relative
    /// ca/cert/key includes keep resolving because WorkingDirectory stays
    /// pointed at the original folder.
    /// </summary>
    private static string ResolveEffectiveConfig(OvpnEntry profile, string runtimeDir)
    {
        var ov = (profile.ServerOverride ?? "").Trim();
        if (string.IsNullOrEmpty(ov)) return profile.FilePath;

        // Parse host[:port], tolerating bracketed IPv6 ([::1]:1194) and bare
        // IPv6 literals (no port split — too ambiguous, keep whole as host).
        var host = ov;
        string? port = null;
        if (ov.StartsWith("["))
        {
            var close = ov.IndexOf(']');
            if (close > 0)
            {
                host = ov[..(close + 1)];
                var rest = ov[(close + 1)..].TrimStart();
                if (rest.StartsWith(":"))
                {
                    port = rest[1..].Trim();
                    if (string.IsNullOrEmpty(port)) return profile.FilePath;
                }
            }
        }
        else if (ov.IndexOf(':') == ov.LastIndexOf(':') && ov.Contains(':'))
        {
            var colon = ov.LastIndexOf(':');
            host = ov[..colon].Trim();
            port = ov[(colon + 1)..].Trim();
            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(port)) return profile.FilePath;
        }

        string[] lines;
        try { lines = File.ReadAllLines(profile.FilePath); }
        catch { return profile.FilePath; }

        // Preserve the original remote port when the override carries none
        // (e.g. override "vpn.example.com" keeps the .ovpn's 1194/443).
        var fallbackPort = port;
        if (string.IsNullOrEmpty(fallbackPort))
        {
            foreach (var raw in lines)
            {
                var t = raw.TrimStart();
                if (!t.StartsWith("remote ", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3 && ushort.TryParse(parts[2], out _))
                {
                    fallbackPort = parts[2];
                    break;
                }
            }
        }

        var replaced = 0;
        var sb = new StringBuilder();
        foreach (var raw in lines)
        {
            var t = raw.TrimStart();
            if (t.StartsWith("remote ", StringComparison.OrdinalIgnoreCase))
            {
                sb.Append("remote ").Append(host);
                if (!string.IsNullOrEmpty(fallbackPort)) sb.Append(' ').Append(fallbackPort);
                sb.AppendLine();
                replaced++;
            }
            else
            {
                sb.AppendLine(raw);
            }
        }
        if (replaced == 0)
        {
            // Files using only <connection> blocks have no top-level remote
            // lines — overriding silently would lie, so keep the original.
            System.Diagnostics.Debug.WriteLine($"server override ignored for \"{profile.DisplayName}\": no remote lines to replace");
            return profile.FilePath;
        }

        try
        {
            var dest = Path.Combine(runtimeDir, $"override-{profile.Id}.ovpn");
            File.WriteAllText(dest, sb.ToString());
            return dest;
        }
        catch
        {
            return profile.FilePath;
        }
    }

    private async Task OnProcessExitedAsync(int epoch)
    {
        OvpnEntry? profile;
        bool want;
        lock (_lock)
        {
            // Stale exit (we already killed this instance during a planned
            // restart/rotate/disconnect) — ignore so one failure doesn't
            // cascade into duplicate reconnect loops.
            if (epoch != _epoch) return;
            want = WantConnected;
            profile = CurrentProfile;
        }
        if (!want || profile is null) return;
        if (!ReconnectEnabled) return;
        lock (_lock)
        {
            if (_reconnecting) return;
            _reconnecting = true;
        }
        try
        {
            // Quick AUTH_FAILED check: retrying bad creds locks accounts.
            if (LogIndicatesAuthFailure())
            {
                LastError = "Authentication failed (check username/password). Auto-reconnect stopped.";
                Status(LastError);
                // Full teardown (not a partial flag reset) so no stale
                // CurrentProfile/ManagementPort/_process lingers.
                await DisconnectAsync().ConfigureAwait(false);
                return;
            }
            Status("VPN process exited — reconnecting…");
            await RestartWithBackoffAsync("process-exit").ConfigureAwait(false);
        }
        finally
        {
            lock (_lock) { _reconnecting = false; }
        }
    }

    private async Task RestartWithBackoffAsync(string reason)
    {
        OvpnEntry? profile;
        lock (_lock) { profile = CurrentProfile; }
        if (profile is null || !WantConnected) return;

        var cts = new CancellationTokenSource();
        lock (_lock)
        {
            // Cancel+replace any previous CTS: without this, an older
            // delayed retry (10s/30s fire-and-forget) could wake into the
            // new session and restart a tunnel the user already stopped.
            try { _reconnectCts?.Cancel(); } catch { }
            try { _reconnectCts?.Dispose(); } catch { }
            _reconnectCts = cts;
        }
        var ct = cts.Token;

        int attempt;
        lock (_lock) { attempt = ReconnectAttempt++; }
        var delay = ReconnectBackoff[Math.Min(attempt, ReconnectBackoff.Length - 1)];
        LastReconnectAt = DateTime.UtcNow;
        Status($"Reconnecting in {delay.TotalSeconds:0}s (attempt {ReconnectAttempt}, {reason})…");
        StateChanged?.Invoke(this, EventArgs.Empty);
        try
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        lock (_lock)
        {
            if (!WantConnected) return;
        }

        // Kill any wedged survivor before starting fresh.
        await KillProcessAsync().ConfigureAwait(false);

        lock (_lock)
        {
            // Manual Disconnect (or a rotate away) during the backoff/Kill
            // must NOT resurrect the tunnel after the user stopped it.
            if (!WantConnected) return;
        }

        // A wedged run may have written AUTH_FAILED while staying alive;
        // check again now that the process is dead, before burning another
        // backoff round on bad credentials.
        if (LogIndicatesAuthFailure())
        {
            LastError = "Authentication failed (check username/password). Auto-reconnect stopped.";
            Status(LastError);
            await DisconnectAsync().ConfigureAwait(false);
            return;
        }

        // Re-read credentials from disk (user may have fixed them mid-outage).
        try
        {
            var fresh = Config.Load();
            fresh.RefreshFromDisk();
            var match = fresh.OvpnFiles.Find(p => p.Id == profile.Id)
                ?? fresh.OvpnFiles.Find(p => string.Equals(p.FilePath, profile.FilePath, StringComparison.OrdinalIgnoreCase));
            if (match is not null) profile = match;
        }
        catch { }

        lock (_lock)
        {
            if (!WantConnected) return;
        }

        try
        {
            await StartOpenVpnAsync(profile).ConfigureAwait(false);
            Status($"Reconnected via \"{profile.DisplayName}\" (attempt {ReconnectAttempt})");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("username"))
        {
            LastError = ex.Message;
            Status("Waiting for credentials — add them via the gear icon.");
            // The caller's finally resets _reconnecting; schedule the next
            // round after a pause so the user has time to save creds.
            // CTS-linked via the run's token: manual Disconnect cancels it.
            _ = Task.Run(async () =>
            {
                try { await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                await NotifyVpnDownAsync().ConfigureAwait(false);
            });
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Status($"Reconnect failed: {ex.Message}");
            // Keep WantConnected true — schedule another round; the
            // caller's finally resets _reconnecting so it can proceed.
            _ = Task.Run(async () =>
            {
                try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                await NotifyVpnDownAsync().ConfigureAwait(false);
            });
        }
    }

    public async Task DisconnectAsync()
    {
        CancelPendingReconnect();
        WantConnected = false;
        ReconnectAttempt = 0;
        lock (_lock) { _disconnectCount++; _reconnecting = false; }

        // Graceful via management socket first; fall through to Kill if that
        // doesn't take openvpn down within ~1.5s.
        if (ManagementPort != 0)
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync("127.0.0.1", ManagementPort).ConfigureAwait(false);
                using var stream = tcp.GetStream();
                var sig = Encoding.ASCII.GetBytes("signal SIGTERM\n");
                await stream.WriteAsync(sig).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
                await Task.Delay(1500).ConfigureAwait(false);
            }
            catch { }
        }

        await KillProcessAsync().ConfigureAwait(false);

        ManagementPort = 0;
        ActiveProfileId = null;
        CurrentProfile = null;
        LastError = "";
        Status("Disconnected");
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private async Task KillProcessAsync()
    {
        Process? proc;
        lock (_lock)
        {
            proc = _process;
            _process = null;
            // Invalidate any Exited event this instance will raise: the
            // kill is deliberate (restart/rotate/disconnect), not a crash.
            _epoch++;
        }
        bool exited = true;
        if (proc is not null)
        {
            try { exited = proc.HasExited; } catch { exited = true; }
        }
        if (!exited)
        {
            try
            {
                proc!.Kill(entireProcessTree: true);
                await Task.Run(() => proc.WaitForExit(2000)).ConfigureAwait(false);
            }
            catch { }
        }
        try { proc?.Dispose(); } catch { }
    }

    private void CancelPendingReconnect()
    {
        lock (_lock)
        {
            try { _reconnectCts?.Cancel(); } catch { }
            try { _reconnectCts?.Dispose(); } catch { }
            _reconnectCts = null;
        }
    }

    private bool LogIndicatesAuthFailure()
    {
        try
        {
            var logFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "VpnClient", "runtime", "openvpn.log");
            if (!File.Exists(logFile)) return false;
            // Read only the tail — the log can be large.
            const int tail = 64 * 1024;
            var info = new FileInfo(logFile);
            using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var skip = Math.Max(0, info.Length - tail);
            fs.Seek(skip, SeekOrigin.Begin);
            using var sr = new StreamReader(fs);
            var text = sr.ReadToEnd();
            return text.Contains("AUTH_FAILED", StringComparison.OrdinalIgnoreCase)
                || text.Contains("auth-failure", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private void Status(string msg) => StatusMessage?.Invoke(this, msg);

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
