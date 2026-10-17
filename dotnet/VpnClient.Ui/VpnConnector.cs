using System;
using System.Collections.Generic;
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
/// Reconnect policy (mandatory failover): while <see cref="WantConnected"/> is true
/// the connector treats ANY unexpected openvpn exit — or an explicit
/// <see cref="NotifyVpnDownAsync"/> from the UI watchdog — as a signal to
/// switch to a different profile, not a state to display. It fails over with
/// a short delay and keeps hunting across profiles until the user hits
/// Disconnect. AUTH_FAILED in the log stops the loop: retrying a bad
/// password in a tight loop gets accounts locked.
/// </summary>
public class VpnConnector
{
    public string? ActiveProfileId { get; private set; }
    public OvpnEntry? CurrentProfile { get; private set; }
    public int ManagementPort { get; private set; }

    /// <summary>True between Connect and manual Disconnect. Drives auto-reconnect.</summary>
    public bool WantConnected => _wantConnected;
    private volatile bool _wantConnected;

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
    /// <summary>Serializes openvpn starts: a manual Connect racing a
    /// post-backoff Restart must not interleave kill/settle/Start.</summary>
    private readonly SemaphoreSlim _startGate = new(1, 1);

    private static readonly string[] OpenVpnPaths =
    {
        @"C:\Program Files\OpenVPN\bin\openvpn.exe",
        @"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
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
        _wantConnected = true;
        lock (_lock) { ReconnectAttempt = 0; }
        LastError = "";
        await StartOpenVpnAsync(profile).ConfigureAwait(false);
    }

    /// <summary>
    /// Called by the UI watchdog when the redirector reports VPN down while
    /// we still want to be connected (adapter lost, but openvpn.exe may
    /// still be running in a wedged state). Kills + restarts the tunnel.
    /// Debounced: at most one restart in flight.
    /// </summary>
    public async Task NotifyVpnDownAsync(string reason = "vpn-adapter-down")
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
            // (Set the message AFTER teardown: DisconnectAsync clears it.)
            if (LogIndicatesAuthFailure())
            {
                await DisconnectAsync().ConfigureAwait(false);
                LastError = "Authentication failed (check username/password). Auto-reconnect stopped.";
                Status(LastError);
                StateChanged?.Invoke(this, EventArgs.Empty);
                return;
            }
            Status("VPN down — switching profile…");
            await FailoverAsync(reason).ConfigureAwait(false);
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

    private long _linkLastLen = -1;
    private DateTime _linkLastCheck = DateTime.MinValue;
    private DateTime _linkLastTrigger = DateTime.MinValue;

    /// <summary>
    /// Link-health watchdog, polled from the UI snapshot tick AND the 2s
    /// openvpn-log timer tick (the latter fires even with a dead
    /// redirector, when there are no snapshots at all — and failover
    /// doesn't need the redirector). The adapter can be UP with an IP
    /// while the tunnel itself is brain-dead (link socket getting 1232
    /// network-unreachable, TLS errors) — the old code showed green
    /// forever in that state because nothing watched the data path. Counts fresh fatal markers in the
    /// openvpn log tail; on a believable cluster, fails over to another
    /// profile instead of sitting on a dead tunnel.
    /// Throttled (≤1 scan/15s), cooldown-gated (≥90s between triggers),
    /// best-effort: never throws, never fights an in-flight reconnect
    /// (NotifyVpnDownAsync already debounces via _reconnecting).
    /// </summary>
    public async Task CheckLinkHealthAsync()
    {
        if (!WantConnected) return;
        var now = DateTime.UtcNow;
        lock (_lock)
        {
            if (now - _linkLastCheck < TimeSpan.FromSeconds(15)) return;
            _linkLastCheck = now;
        }
        try
        {
            var logFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "VpnClient", "runtime", "openvpn.log");
            if (!File.Exists(logFile)) return;
            var len = new FileInfo(logFile).Length;
            long prev;
            lock (_lock) { prev = _linkLastLen; _linkLastLen = len; }
            // First sight or rotated/truncated (new run): baseline only.
            if (prev < 0 || len < prev) return;
            if (len == prev) return;
            DateTime lastTrigger;
            lock (_lock) { lastTrigger = _linkLastTrigger; }
            if (now - lastTrigger < TimeSpan.FromSeconds(90)) return;

            const long maxScan = 64 * 1024;
            var start = Math.Max(prev, len - maxScan);
            string tail;
            using (var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                fs.Seek(start, SeekOrigin.Begin);
                using var sr = new StreamReader(fs);
                tail = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            int hitLines = 0;
            // Count distinct LINES, not marker occurrences: a single openvpn
            // line routinely contains two markers at once
            // ("...cannot be reached... (code=1232)") and must not trigger
            // alone as if it were two independent failures.
            foreach (var line in tail.Split('\n'))
            {
                foreach (var marker in LinkFatalMarkers)
                {
                    if (line.Contains(marker, StringComparison.OrdinalIgnoreCase))
                    {
                        hitLines++;
                        break;
                    }
                }
                if (hitLines >= 2) break;
            }
            if (hitLines < 2) return;
            lock (_lock) { _linkLastTrigger = now; }
            Status("Link looks dead (openvpn errors) — switching profile…");
            await NotifyVpnDownAsync("link-unhealthy").ConfigureAwait(false);
        }
        catch { }
    }

    private static readonly string[] LinkFatalMarkers =
    {
        "code=1232",
        "cannot be reached",
        "is unreachable",
        "TLS Error",
        "Connection reset",
        "ping-restart",
    };

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
        // Credential validation BEFORE log rotation: a throw here starts no
        // openvpn, so it must not consume the previous run's evidence.
        var hasCreds = !string.IsNullOrWhiteSpace(profile.Username)
            && !string.IsNullOrWhiteSpace(profile.GetPassword());
        var needsUi = OvpnParser.NeedsUiCredentials(profile.FilePath);
        if (needsUi && !hasCreds)
        {
            // Let openvpn fail with a readable log line instead of feeding it
            // an empty auth file; the UI pre-checks this too.
            throw new InvalidOperationException(
                $"Profile \"{profile.DisplayName}\" needs a username + password.\n" +
                "Open the gear icon to add credentials and try again.");
        }
        // Preserve the previous run's log before truncating: failover and
        // rotate delete-and-restart on every attempt, which used to destroy
        // the exact evidence (TLS errors, AUTH_FAILED context, pushed
        // options) needed to diagnose "won't connect". One generation only.
        // Copy and delete are independent: a failed copy (locked, disk full)
        // must still truncate, or the stale-log AUTH_FAILED false-positive
        // the old code fixed comes back.
        try
        {
            if (File.Exists(logFile))
            {
                File.Copy(logFile, Path.Combine(runtimeDir, "openvpn.prev.log"), true);
            }
        }
        catch { }
        try { File.Delete(logFile); } catch { }
        // Port picked here, consumed below inside the start gate via a local
        // copy (never the field mid-flight between concurrent starters).
        var mgmtPort = GetFreePort();
        lock (_lock) { ManagementPort = mgmtPort; }

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

        // Only pass --auth-user-pass when the credentials MUST come from our
        // UI. Profiles that already carry auth (existing auth file or filled
        // inline block) are left alone: forcing our flag would override the
        // working credential the .ovpn already points at.
        if (needsUi && hasCreds)
        {
            // Per-profile filename: concurrent starts for different profiles
            // must not cross-contaminate one shared auth.txt.
            var authFile = Path.Combine(runtimeDir, $"auth-{profile.Id}.txt");
            await File.WriteAllTextAsync(
                authFile,
                $"{profile.Username}\n{profile.GetPassword()}\n").ConfigureAwait(false);
            args.Append($"--auth-user-pass \"{authFile}\" ");
        }
        // (needsUi && !hasCreds already threw above, before log rotation.)

        // NOTE: no --windows-driver flag on purpose. OpenVPN 2.7 picks DCO
        // by default (proven by working setups); forcing wintun had no
        // effect (DCO was opened anyway) and only added a fallback variable.
        //
        // Split tunnel is the only mode: traffic goes through the VPN only
        // for apps the user listed (pinned via IP_UNICAST_IF + the
        // redirector's per-app routing). The server-pushed redirect-gateway is
        // filtered so it can't drag ALL traffic into the tunnel.
        //
        // Pushed DNS (dhcp-option) is IGNORED. Accepting it registers
        // 10.96.0.1 as system DNS, and Windows then sends EVERY app's lookups
        // into the tunnel: measured 2s x 2 timeouts per fresh hostname vs
        // instant on LAN DNS, plus geo-mismatched answers (CDN edges near the
        // VPN country, not the user). Untunneled apps felt this as "internet
        // lambat". Tunneled apps keep working because the redirector passes
        // port-53 through to the kernel (see divert.rs) instead of bridging it
        // into the tunnel blackhole. Trade-off, stated openly: DNS names of
        // tunneled apps are visible to the LAN resolver; their traffic stays
        // in the tunnel.
        //
        // block-outside-dns is filtered: it would install WFP rules forcing
        // ALL host DNS through the tunnel, breaking untunneled apps whenever
        // the tunnel DNS is unreachable from LAN.
        //
        // --auth-nocache avoids caching passwords in memory (also silences
        // the openvpn warning); reconnects re-read our auth file anyway.
        //
        // Tell the redirector which mode we run: split mode makes it clean up
        // stale full-tunnel leftovers and install its own per-app route.
        // Written before openvpn starts so it is always fresh when the adapter
        // appears.
        try { File.WriteAllText(Path.Combine(runtimeDir, "mode.txt"), "split"); } catch { }
        args.Append($"--management 127.0.0.1 {mgmtPort} ");
        args.Append("--auth-nocache ");
        args.Append("--pull-filter ignore \"redirect-gateway\" ");
        args.Append("--pull-filter ignore \"dhcp-option\" ");
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

        // Serialized: a manual Connect racing a post-backoff Restart must not
        // interleave stray-kill/settle/Start (one side's kill would reap the
        // other's fresh process). Held from stray-kill through assignment.
        await _startGate.WaitAsync().ConfigureAwait(false);
        try
        {
            // Kill stray openvpn.exe instances left by script runs, crashes, or
            // half-torn-down reconnects. Two managers fighting over the DCO
            // device and routes is exactly how you get a tunnel that completes
            // its handshake and then dies with "network location cannot be
            // reached". Our own tracked instance is already dead at this point
            // (Connect/Restart killed it), so anything still alive is stray.
            // Mirror the working script: wait briefly for tunnel cleanup when
            // we actually killed something.
            if (KillStrayOpenVpnProcesses())
            {
                Status("Waiting for previous tunnel cleanup…");
                await Task.Delay(2000).ConfigureAwait(false);
            }

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

            // Close the micro-window between the pre-Start Want check and
            // Process.Start: a Disconnect landing exactly there must not
            // leave a resurrected tunnel behind.
            bool cancelled;
            lock (_lock) { cancelled = !_wantConnected; }
            if (cancelled)
            {
                await KillProcessAsync().ConfigureAwait(false);
                throw new OperationCanceledException("Connect cancelled (disconnected right after start).");
            }
        }
        finally
        {
            _startGate.Release();
        }

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
            // (Message set AFTER teardown: DisconnectAsync clears it.)
            if (LogIndicatesAuthFailure())
            {
                await DisconnectAsync().ConfigureAwait(false);
                LastError = "Authentication failed (check username/password). Auto-reconnect stopped.";
                Status(LastError);
                StateChanged?.Invoke(this, EventArgs.Empty);
                return;
            }
            Status("VPN process exited — switching profile…");
            await FailoverAsync("process-exit").ConfigureAwait(false);
        }
        finally
        {
            lock (_lock) { _reconnecting = false; }
        }
    }

    /// <summary>
    /// Failover: on any failure while <see cref="WantConnected"/> is true,
    /// switch to a DIFFERENT profile instead of retrying the dead one.
    /// Same-profile retry is only the damped last resort when nothing else
    /// is connectable; AUTH_FAILED still stops everything (credentials are
    /// shared across profiles, so rotating cannot fix it).
    /// </summary>
    private async Task FailoverAsync(string reason)
    {
        OvpnEntry? failed;
        lock (_lock) { failed = CurrentProfile; }
        if (failed is null || !WantConnected) return;

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

        // Pick a random DIFFERENT connectable profile from a fresh scan.
        List<OvpnEntry> others;
        int total;
        try
        {
            var fresh = Config.Load();
            fresh.RefreshFromDisk();
            total = fresh.OvpnFiles.Count;
            others = fresh.OvpnFiles
                .Where(p => p.Id != failed.Id && IsConnectableProfile(p))
                .ToList();
        }
        catch { others = new List<OvpnEntry>(); total = 0; }

        OvpnEntry target;
        TimeSpan delay;
        // Sweep-damping counter read under lock (written under lock too).
        int seen;
        lock (_lock) { seen = ReconnectAttempt; }
        if (others.Count > 0)
        {
            target = others[Random.Shared.Next(others.Count)];
            delay = TimeSpan.FromSeconds(3);
            // Full sweep without success: back off hard instead of hot-looping
            // through dead profiles.
            if (total > 0 && seen > 0
                && seen % Math.Max(1, total) == 0)
            {
                delay = TimeSpan.FromSeconds(30);
            }
        }
        else
        {
            // Sole survivor: retry it, heavily damped.
            target = failed;
            delay = TimeSpan.FromSeconds(20);
        }

        int attempt;
        lock (_lock) { attempt = ReconnectAttempt++; }
        LastReconnectAt = DateTime.UtcNow;
        var what = target.Id == failed.Id ? "Retrying" : "Switching";
        Status($"{what} \"{target.DisplayName}\" in {delay.TotalSeconds:0}s (attempt {attempt + 1}, {reason})…");
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
        // round on bad credentials (shared across all profiles: stop, don't
        // rotate). Message set after teardown (DisconnectAsync clears it).
        if (LogIndicatesAuthFailure())
        {
            await DisconnectAsync().ConfigureAwait(false);
            LastError = "Authentication failed (check username/password). Auto-reconnect stopped.";
            Status(LastError);
            StateChanged?.Invoke(this, EventArgs.Empty);
            return;
        }

        // Re-read target credentials from disk (user may have fixed them
        // mid-outage).
        try
        {
            var fresh = Config.Load();
            fresh.RefreshFromDisk();
            var match = fresh.OvpnFiles.Find(p => p.Id == target.Id)
                ?? fresh.OvpnFiles.Find(p => string.Equals(p.FilePath, target.FilePath, StringComparison.OrdinalIgnoreCase));
            if (match is not null) target = match;
        }
        catch { }

        lock (_lock)
        {
            if (!WantConnected) return;
        }

        try
        {
            await StartOpenVpnAsync(target).ConfigureAwait(false);
            // Persist the switch so rotate, watchdog and UI follow the live
            // profile instead of pointing at the dead one.
            try
            {
                var cfg = Config.Load();
                cfg.ActiveOvpnId = target.Id;
                cfg.Save();
            }
            catch { }
            Status($"Connected via \"{target.DisplayName}\" (attempt {attempt + 1})");
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
            Status($"Failover failed: {ex.Message}");
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

    /// <summary>Same connectability rule as the UI rotation: file must exist
    /// and required credentials must already be saved.</summary>
    private static bool IsConnectableProfile(OvpnEntry p) =>
        System.IO.File.Exists(p.FilePath)
        && (!OvpnParser.NeedsUiCredentials(p.FilePath)
            || (!string.IsNullOrWhiteSpace(p.Username) && !string.IsNullOrWhiteSpace(p.GetPassword())));

    public async Task DisconnectAsync()
    {
        CancelPendingReconnect();
        _wantConnected = false;
        lock (_lock) { ReconnectAttempt = 0; }
        lock (_lock) { _disconnectCount++; _reconnecting = false; }

        // Graceful via management socket first; fall through to Kill if that
        // doesn't take openvpn down within ~1.5s. Port snapshotted under
        // lock: a concurrent starter may already have assigned the next one.
        int mgmtPort;
        lock (_lock) { mgmtPort = ManagementPort; }
        if (mgmtPort != 0)
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync("127.0.0.1", mgmtPort).ConfigureAwait(false);
                using var stream = tcp.GetStream();
                var sig = Encoding.ASCII.GetBytes("signal SIGTERM\n");
                await stream.WriteAsync(sig).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
                await Task.Delay(1500).ConfigureAwait(false);
            }
            catch { }
        }

        await KillProcessAsync().ConfigureAwait(false);

        lock (_lock) { ManagementPort = 0; }
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

    /// <summary>
    /// Kill every openvpn.exe on the box by process name; returns true when
    /// something was killed. Relies on the caller having already cleared our
    /// own tracked instance, so anything still alive is stray by definition
    /// (nothing here filters "ours" vs "theirs"). Never throws.
    /// </summary>
    private static bool KillStrayOpenVpnProcesses()
    {
        var killed = false;
        Process[] strays;
        try { strays = Process.GetProcessesByName("openvpn"); }
        catch { return false; }
        foreach (var p in strays)
        {
            try
            {
                bool exited;
                try { exited = p.HasExited; } catch { exited = true; }
                if (!exited)
                {
                    p.Kill(entireProcessTree: true);
                    killed = true;
                }
            }
            catch { }
            finally { try { p.Dispose(); } catch { } }
        }
        return killed;
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

    public static string RuntimeDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "VpnClient", "runtime");

    public static string LogPath => Path.Combine(RuntimeDir, "openvpn.log");

    /// <summary>Redirector's persistent activity log (same lines as the
    /// in-app Activity panel). Cleared on every app start.</summary>
    public static string ActivityLogPath => Path.Combine(RuntimeDir, "activity.log");

    /// <summary>
    /// Fresh logs per app start: deletes stale activity.log + openvpn.log so
    /// a saved file always belongs to exactly one session. Called once from
    /// App.OnStartup, before the redirector is (re)started. Never throws.
    /// (openvpn.log is additionally truncated on every connect inside
    /// StartOpenVpnAsync so AUTH_FAILED tails can't leak across runs.)
    /// </summary>
    public static void ClearLogsOnAppStart()
    {
        foreach (var path in new[] { ActivityLogPath, LogPath, Path.Combine(RuntimeDir, "openvpn.prev.log") })
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch { }
        }
    }

    /// <summary>
    /// Last N lines of the openvpn log. Shared-read so it works while
    /// openvpn is still writing. Caps the scan at the final 256 KB so a
    /// multi-day verb-3 log doesn't jank the caller. No in-app viewer
    /// consumes this anymore (logs are file-only); kept as a diagnostic
    /// helper for support bundles and future tooling.
    /// </summary>
    public static string ReadLogTail(int maxLines = 400)
    {
        const long maxTailBytes = 256 * 1024;
        try
        {
            if (!File.Exists(LogPath))
                return "(no log yet — hit Connect first)";
            using var fs = new FileStream(LogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length > maxTailBytes)
            {
                fs.Seek(-maxTailBytes, SeekOrigin.End);
            }
            using var sr = new StreamReader(fs);
            if (fs.Position > 0) sr.ReadLine(); // discard partial first line
            var queue = new Queue<string>(maxLines + 1);
            string? line;
            while ((line = sr.ReadLine()) is not null)
            {
                queue.Enqueue(line);
                while (queue.Count > maxLines) queue.Dequeue();
            }
            var text = string.Join(Environment.NewLine, queue);
            return string.IsNullOrEmpty(text) ? "(log is empty)" : text;
        }
        catch (Exception ex)
        {
            return $"(cannot read log: {ex.Message})";
        }
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
