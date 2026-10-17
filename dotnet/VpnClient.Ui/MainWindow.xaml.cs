using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Vpnclient.Status;
using Wpf.Ui.Controls;

namespace VpnClient.Ui;

public partial class MainWindow : FluentWindow
{
    private readonly StatusClient _statusClient = new();
    private Config _config = Config.Load();
    private readonly ObservableCollection<AppRow> _appRows = new();

    private bool _lastVpnUp;
    private bool _connecting;
    private DateTime? _vpnDownSince;
    private bool _watchdogFiring;
    private bool _pipeConnected;
    private DateTime? _pipeLostSince;
    private DateTime _pipeLastRelaunch = DateTime.MinValue;
    private string _connectorStatus = "";
    private DispatcherTimer? _rotateTimer;
    private DispatcherTimer? _healthTimer;

    private static readonly int[] RotateChoices = { 5, 10, 15, 30, 60, 120, 180, 360 };

    public MainWindow()
    {
        InitializeComponent();
        _statusClient.SnapshotReceived += OnSnapshot;
        _statusClient.ConnectionChanged += OnConnectionChanged;
        App.Connector.StatusMessage += OnConnectorStatus;
        App.Connector.StateChanged += OnConnectorStateChanged;
        Loaded += (_, _) => {
            _config.RefreshFromDisk();
            InitRotateControls();
            InitLogFooter();
            _statusClient.Start();
            // Link-health watchdog tick (independent of the status pipe and
            // of any log UI — the check is throttled inside). Also supervises
            // the redirector itself (see SuperviseRedirector): with the pipe
            // dead there are no snapshots, so this tick is the only observer.
            _healthTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _healthTimer.Tick += (_, _) =>
            {
                _ = App.Connector.CheckLinkHealthAsync();
                SuperviseRedirector();
            };
            _healthTimer.Start();
            RefreshAppList();
            UpdateConnectButtonState(false);
            UpdateRotateHint();
        };
        Closed += (_, _) =>
        {
            _rotateTimer?.Stop();
            _healthTimer?.Stop();
            _statusClient.Stop();
        };
    }

    private void OnConnectorStatus(object? sender, string msg)
    {
        Dispatcher.BeginInvoke(() =>
        {
            _connectorStatus = msg;
            if (!string.IsNullOrEmpty(msg))
            {
                // Surface reconnect progress in the header without clobbering
                // the green "VPN connected" state when the tunnel is up.
                if (!_lastVpnUp)
                    AdapterText.Text = msg;
                else
                    FooterText.Text = msg;
            }
        });
    }

    private void OnConnectorStateChanged(object? sender, EventArgs e)
    {
        Dispatcher.BeginInvoke(() =>
        {
            _config = Config.Load();
            // NOTE: no RestartRotateTimer here on purpose. StateChanged fires
            // on every (re)connect attempt; restarting the DispatcherTimer
            // each time would postpone rotation indefinitely under flaps.
            // The timer only restarts when the rotate SETTINGS change.
            UpdateConnectButtonState(_lastVpnUp);
            UpdateRotateHint();
        });
    }

    private void OnConnectionChanged(object? sender, bool connected)
    {
        Dispatcher.BeginInvoke(() =>
        {
            _pipeConnected = connected;
            if (connected)
            {
                _pipeLostSince = null;
            }
            else
            {
                _pipeLostSince ??= DateTime.UtcNow;
                StateText.Text = "Disconnected from redirector";
                StateDot.Fill = new SolidColorBrush(Color.FromRgb(0x6B, 0x6B, 0x6B));
                AdapterText.Text = "redirector service not running, or pipe ACL denies access";
            }
        });
    }

    /// <summary>
    /// Redirector supervisor (UI side). If the status pipe stays down while
    /// we still need the tunnel, the redirector is gone (clean exit, crash,
    /// external kill — reason unknown by design) and everything downstream
    /// of it (bridge, split route, cleanup, snapshots) is dead with it.
    /// Relaunch it and leave a forensic line in activity.log. Safe when a
    /// zombie still holds the pipe: the newcomer FATAL-exits loudly instead
    /// of splitting brain. Throttled to one attempt per 30s.
    /// </summary>
    private void SuperviseRedirector()
    {
        try
        {
            if (_pipeConnected) return;
            if (_pipeLostSince is null) return;
            if (DateTime.UtcNow - _pipeLostSince < TimeSpan.FromSeconds(10)) return;
            if (DateTime.UtcNow - _pipeLastRelaunch < TimeSpan.FromSeconds(30)) return;
            bool want = App.Connector.WantConnected;
            bool ovpnAlive = OpenVpnRunning();
            if (!want && !ovpnAlive) return;
            _pipeLastRelaunch = DateTime.UtcNow;
            AppendActivityLine(
                $"UI: redirector pipe lost for {(DateTime.UtcNow - _pipeLostSince.Value).TotalSeconds:0}s " +
                $"while tunnel needed (wantConnected={want} openvpnAlive={ovpnAlive}) — relaunching redirector");
            // Don't KillOrphans here: that would also kill a live openvpn.
            // If a zombie holds the pipe, the newcomer exits FATAL-loud.
            Redirector.TryStart();
        }
        catch { }
    }

    private static bool OpenVpnRunning()
    {
        try { return System.Diagnostics.Process.GetProcessesByName("openvpn").Any(); }
        catch { return false; }
    }

    private static void AppendActivityLine(string line)
    {
        // Explicit ReadWrite share: the redirector may still hold the file
        // open (pipe down while process alive corner) — default AppendAllText
        // share (Read) would throw there and lose the line.
        try
        {
            using var fs = new System.IO.FileStream(
                VpnConnector.ActivityLogPath,
                System.IO.FileMode.Append,
                System.IO.FileAccess.Write,
                System.IO.FileShare.ReadWrite);
            using var sw = new System.IO.StreamWriter(fs);
            sw.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [UI] {line}");
        }
        catch { }
    }

    private void OnSnapshot(object? sender, Snapshot snapshot)
    {
        Dispatcher.BeginInvoke(() =>
        {
            var vpn = snapshot.Vpn;
            if (vpn is null)
            {
                StateText.Text = "Unknown VPN state";
                StateDot.Fill = new SolidColorBrush(Color.FromRgb(0x6B, 0x6B, 0x6B));
                AdapterText.Text = string.Empty;
                ProfileText.Text = string.Empty;
            }
            else if (vpn.Up)
            {
                _connecting = false;
                _vpnDownSince = null;
                App.Connector.NotifyVpnUp();
                // Link-health watchdog: adapter-up does not imply the tunnel
                // passes traffic (1232-dead link shows green otherwise).
                // Throttled inside; fire-and-forget.
                _ = App.Connector.CheckLinkHealthAsync();
                StateSpinner.Visibility = Visibility.Collapsed;
                StateDot.Visibility = Visibility.Visible;
                if (vpn.RouteOk)
                {
                    StateText.Text = "VPN connected";
                    StateDot.Fill = new SolidColorBrush(Color.FromRgb(0x10, 0xA1, 0x6B));
                    AdapterText.Text = EgressLine(vpn.AdapterIp, "");
                }
                else
                {
                    // Adapter is up but the split-tunnel route is missing:
                    // tunneled apps have no path. Amber, not green — the
                    // redirector keeps retrying the install on its poll tick.
                    StateText.Text = "VPN connected — tunnel route missing";
                    StateDot.Fill = new SolidColorBrush(Color.FromRgb(0xC5, 0x84, 0x1A));
                    AdapterText.Text = EgressLine(vpn.AdapterIp, "repairing split-tunnel route…");
                }
                UpdateProfileText();
                UptimeText.Text = FormatUptime(vpn.UptimeMs);
                UpdateConnectButtonState(true);
            }
            else if (_connecting)
            {
                StateSpinner.Visibility = Visibility.Visible;
                StateDot.Visibility = Visibility.Collapsed;
                StateText.Text = "Connecting…";
                AdapterText.Text = string.IsNullOrEmpty(_connectorStatus)
                    ? "openvpn handshake in progress"
                    : _connectorStatus;
                UpdateProfileText();
                UptimeText.Text = "—";
            }
            else
            {
                StateSpinner.Visibility = Visibility.Collapsed;
                StateDot.Visibility = Visibility.Visible;
                if (App.Connector.WantConnected)
                {
                    // We want the tunnel but the adapter is down → reconnect
                    // watchdog (covers network blips where openvpn.exe is
                    // still alive but wedged, so no Exited event fires).
                    StateText.Text = string.IsNullOrEmpty(App.Connector.LastError)
                        ? "VPN down — switching profile…"
                        : App.Connector.LastError;
                    StateDot.Fill = new SolidColorBrush(Color.FromRgb(0xC5, 0x84, 0x1A));
                    AdapterText.Text = string.IsNullOrEmpty(_connectorStatus)
                        ? "waiting for VPN adapter…"
                        : _connectorStatus;
                    ArmWatchdog();
                }
                else
                {
                    StateText.Text = "VPN disconnected";
                    StateDot.Fill = new SolidColorBrush(Color.FromRgb(0xC5, 0x42, 0x42));
                    AdapterText.Text = string.Empty;
                    ProfileText.Text = string.Empty;
                    _vpnDownSince = null;
                }
                UptimeText.Text = "—";
                UpdateConnectButtonState(false);
            }

            var totals = snapshot.Totals;
            if (totals is not null)
            {
                BytesOutText.Text = FormatBytes(totals.BytesAppToRemote);
                BytesInText.Text = FormatBytes(totals.BytesRemoteToApp);
            }

            ApplyAppStats(snapshot.Apps);
        });
    }

    /// <summary>
    /// Watchdog: when the user wants the tunnel but the adapter stays down,
    /// poke the connector to restart openvpn. Debounced to one in-flight
    /// restart; the connector itself applies backoff.
    /// </summary>
    private void ArmWatchdog()
    {
        _vpnDownSince ??= DateTime.UtcNow;
        if (_watchdogFiring) return;
        // Give the handshake a grace period before declaring failure.
        if (DateTime.UtcNow - _vpnDownSince < TimeSpan.FromSeconds(15)) return;
        _watchdogFiring = true;
        _ = System.Threading.Tasks.Task.Run(async () =>
        {
            try { await App.Connector.NotifyVpnDownAsync(); }
            catch { }
            finally
            {
                await Dispatcher.BeginInvoke(() => { _watchdogFiring = false; });
            }
        });
    }

    private void ApplyAppStats(IEnumerable<AppStats> apps)
    {
        var byPath = new Dictionary<string, AppStats>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in apps) byPath[s.ExePath] = s;

        foreach (var row in _appRows)
        {
            if (byPath.TryGetValue(row.ExePath, out var s))
            {
                var pidTuples = s.Pids
                    .Select(p => (p.Pid, p.BytesOut, p.BytesIn, p.BytesOutPerSec, p.BytesInPerSec))
                    .ToList();
                row.UpdateStats(s.BytesOut, s.BytesIn, s.BytesOutPerSec, s.BytesInPerSec, s.ActivePids, pidTuples);
            }
            else
            {
                row.ResetStats();
            }
        }
    }

    private void SettingsBtn_Click(object sender, RoutedEventArgs e)
    {
        var settings = new SettingsWindow(_config) { Owner = this };
        settings.ConfigChanged += (_, _) => RefreshAppList();
        settings.ShowDialog();
    }

    /// <summary>
    /// Prominent connected line: tunnel IP plus egress server, e.g.
    /// "VPN IP 10.96.0.21 · via 93.190.142.102". The server part comes
    /// from the live profile (may be empty on stale snapshots).
    /// </summary>
    private static string EgressLine(string ip, string suffix)
    {
        var server = App.Connector.CurrentProfile?.EffectiveServer;
        var via = string.IsNullOrWhiteSpace(server) ? "" : $" · via {server}";
        return string.IsNullOrEmpty(suffix) ? $"VPN IP {ip}{via}" : $"VPN IP {ip}{via} — {suffix}";
    }

    /// <summary>
    /// Connected profile name under the egress IP. Prefers the live
    /// connector profile, falls back to the configured active one.
    /// </summary>
    private void UpdateProfileText()
    {
        var name = App.Connector.CurrentProfile?.DisplayName
            ?? ResolveActiveProfile()?.DisplayName;
        ProfileText.Text = string.IsNullOrEmpty(name) ? string.Empty : $"profile \"{name}\"";
    }

    private void VpnSettingsBtn_Click(object sender, RoutedEventArgs e)
    {
        var vpn = new VpnConfigWindow(_config) { Owner = this };        vpn.ConfigChanged += (_, _) =>
        {
            _config = Config.Load();
            UpdateConnectButtonState(_lastVpnUp);
            UpdateRotateHint();
        };
        vpn.ShowDialog();
        // also refresh after close in case ActiveOvpnId changed
        _config = Config.Load();
        UpdateConnectButtonState(_lastVpnUp);
        UpdateRotateHint();
    }

    private void UpdateConnectButtonState(bool vpnUp)
    {
        _lastVpnUp = vpnUp;
        var hasProfiles = _config.OvpnFiles.Count > 0;
        if (vpnUp || (App.Connector.WantConnected && _connecting))
        {
            var reconnecting = App.Connector.WantConnected && !vpnUp;
            ConnectBtn.Content = reconnecting ? "Switching…" : "Disconnect";
            ConnectBtn.Icon = new SymbolIcon(SymbolRegular.Stop20);
            ConnectBtn.Appearance = ControlAppearance.Secondary;
            ConnectBtn.IsEnabled = true;
            ConnectBtn.ToolTip = "Stop the VPN tunnel (cancels auto-reconnect)";
        }
        else if (App.Connector.WantConnected && !vpnUp)
        {
            ConnectBtn.Content = "Cancel";
            ConnectBtn.Icon = new SymbolIcon(SymbolRegular.Stop20);
            ConnectBtn.Appearance = ControlAppearance.Secondary;
            ConnectBtn.IsEnabled = true;
            ConnectBtn.ToolTip = "Cancel auto-reconnect";
        }
        else
        {
            ConnectBtn.Content = "Connect";
            ConnectBtn.Icon = new SymbolIcon(SymbolRegular.Play20);
            ConnectBtn.Appearance = ControlAppearance.Primary;
            ConnectBtn.IsEnabled = hasProfiles && !_connecting;
            if (!hasProfiles)
            {
                ConnectBtn.ToolTip = "No .ovpn found — copy files to C:\\Program Files\\OpenVPN\\config, then open the gear icon and Refresh";
            }
            else
            {
                ConnectBtn.ToolTip = "Connect using a random profile";
            }
        }
        RotateNowBtn.IsEnabled = App.Connector.WantConnected;
        RotateNowBtn.ToolTip = App.Connector.WantConnected
            ? "Switch to a random profile now"
            : "Connect first, then rotate";
    }

    private OvpnEntry? ResolveActiveProfile()
    {
        if (!string.IsNullOrEmpty(_config.ActiveOvpnId))
        {
            var active = _config.OvpnFiles.FirstOrDefault(p => p.Id == _config.ActiveOvpnId);
            if (active is not null) return active;
        }
        return _config.OvpnFiles.FirstOrDefault();
    }

    /// <summary>A profile is connectable when its file exists and any
    /// required credentials are already saved.</summary>
    private static bool IsConnectable(OvpnEntry p) =>
        System.IO.File.Exists(p.FilePath)
        && (!OvpnParser.NeedsUiCredentials(p.FilePath)
            || (!string.IsNullOrWhiteSpace(p.Username) && !string.IsNullOrWhiteSpace(p.GetPassword())));

    /// <summary>
    /// Random connectable profile. Falls back to any profile (so the user
    /// still gets the meaningful missing-file/credentials error) and null
    /// when nothing exists at all.
    /// </summary>
    private OvpnEntry? PickRandomProfile()
    {
        var pool = _config.OvpnFiles.Where(IsConnectable).ToList();
        if (pool.Count == 0) pool = _config.OvpnFiles.ToList();
        if (pool.Count == 0) return null;
        return pool[Random.Shared.Next(pool.Count)];
    }

    private async void ConnectBtn_Click(object sender, RoutedEventArgs e)
    {
        // Toggle: if we want the tunnel (up OR reconnecting), this click
        // means "stop everything".
        if (App.Connector.WantConnected || _lastVpnUp)
        {
            ConnectBtn.IsEnabled = false;
            try
            {
                await App.Connector.DisconnectAsync();
                _connecting = false;
                _vpnDownSince = null;
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"Disconnect failed:\n{ex.Message}",
                    "Disconnect error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
            finally
            {
                UpdateConnectButtonState(false);
            }
            return;
        }

        _config.RefreshFromDisk();
        var profile = PickRandomProfile();
        if (profile is null)
        {
            System.Windows.MessageBox.Show(
                "No .ovpn profiles found.\n\n" +
                $"Copy your provider's .ovpn files to:\n{OpenVpnConfigSource.DescribeDirs()}\n\n" +
                "Then open the gear icon and hit Refresh.",
                "No profiles",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }

        if (OvpnParser.NeedsUiCredentials(profile.FilePath)
            && (string.IsNullOrWhiteSpace(profile.Username)
                || string.IsNullOrWhiteSpace(profile.GetPassword())))
        {
            System.Windows.MessageBox.Show(
                $"Profile \"{profile.DisplayName}\" needs a username + password.\n" +
                "Open the gear icon to add them and try again.",
                "Missing credentials",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }

        if (!System.IO.File.Exists(profile.FilePath))
        {
            System.Windows.MessageBox.Show(
                $"Profile file is missing:\n{profile.FilePath}",
                "Missing file",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }

        _connecting = true;
        _vpnDownSince = DateTime.UtcNow;
        _config.ActiveOvpnId = profile.Id;
        _config.Save();
        StateSpinner.Visibility = Visibility.Visible;
        StateDot.Visibility = Visibility.Collapsed;
        StateText.Text = "Connecting…";
        AdapterText.Text = $"using profile \"{profile.DisplayName}\"";
        ConnectBtn.IsEnabled = false;
        try
        {
            await App.Connector.ConnectAsync(profile);
            if (!App.Connector.WantConnected)
            {
                _connecting = false;
                StateSpinner.Visibility = Visibility.Collapsed;
                StateDot.Visibility = Visibility.Visible;
                UpdateConnectButtonState(false);
                return;
            }
            // Status snapshot will flip _connecting off once the VPN adapter is detected.
            // The watchdog (not a fixed 30s timer) owns the failure path now:
            // as long as WantConnected is true, drops trigger reconnect.
            // After a grace period, drop the "Connecting…" spinner so the
            // snapshot falls through to the watchdog branch which shows
            // reconnect progress instead of spinning forever on a wedged
            // handshake (process alive, no adapter).
            _ = System.Threading.Tasks.Task.Run(async () =>
            {
                await System.Threading.Tasks.Task.Delay(TimeSpan.FromSeconds(45));
                await Dispatcher.BeginInvoke(() =>
                {
                    if (_connecting && !_lastVpnUp)
                    {
                        _connecting = false;
                        StateSpinner.Visibility = Visibility.Collapsed;
                        StateDot.Visibility = Visibility.Visible;
                        UpdateConnectButtonState(false);
                    }
                });
            });
        }
        catch (Exception ex)
        {
            _connecting = false;
            StateSpinner.Visibility = Visibility.Collapsed;
            StateDot.Visibility = Visibility.Visible;
            System.Windows.MessageBox.Show(
                $"Connect failed:\n{ex.Message}",
                "Connect error",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
            UpdateConnectButtonState(false);
        }
    }

    #region Log files (automatic — no checkbox)

    // Logging is always on, straight to files (one set per app start):
    //   activity.log  — redirector events (admissions, bridges, closes)
    //   openvpn.log / openvpn.prev.log — current + previous openvpn run
    // This region only shows WHERE they live and opens the folder.

    private void InitLogFooter()
    {
        LogPathText.Text = VpnConnector.RuntimeDir;
        LogPathText.ToolTip = VpnConnector.RuntimeDir;
    }

    private void OpenLogFolderBtn_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.IO.Directory.CreateDirectory(VpnConnector.RuntimeDir);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = VpnConnector.RuntimeDir,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            FooterText.Text = $"Cannot open log folder: {ex.Message}";
        }
    }

    #endregion

    #region Rotate every

    private void InitRotateControls()
    {
        RotateIntervalBox.ItemsSource = RotateChoices.Select(m => $"{m} min").ToList();
        // Snap custom/legacy values to the nearest choice so the displayed
        // interval always matches the timer interval.
        var nearest = 0;
        for (int i = 1; i < RotateChoices.Length; i++)
        {
            if (Math.Abs(RotateChoices[i] - _config.RotateIntervalMinutes)
                < Math.Abs(RotateChoices[nearest] - _config.RotateIntervalMinutes))
                nearest = i;
        }
        _config.RotateIntervalMinutes = RotateChoices[nearest];
        _config.Save();
        RotateIntervalBox.SelectedIndex = nearest;
        RotateCheck.IsChecked = _config.RotateEnabled;
        RestartRotateTimer();
    }

    private void RotateCheck_Changed(object sender, RoutedEventArgs e)
    {
        _config.RotateEnabled = RotateCheck.IsChecked == true;
        _config.Save();
        RestartRotateTimer();
        UpdateRotateHint();
    }

    private void RotateIntervalBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (RotateIntervalBox.SelectedIndex < 0) return;
        _config.RotateIntervalMinutes = RotateChoices[Math.Min(RotateIntervalBox.SelectedIndex, RotateChoices.Length - 1)];
        _config.Save();
        RestartRotateTimer();
        UpdateRotateHint();
    }

    private void RestartRotateTimer()
    {
        _rotateTimer?.Stop();
        _rotateTimer = null;
        if (!_config.RotateEnabled) return;
        var interval = TimeSpan.FromMinutes(Math.Clamp(_config.RotateIntervalMinutes, 5, 720));
        _rotateTimer = new DispatcherTimer { Interval = interval };
        _rotateTimer.Tick += async (_, _) => await RotateToNextAsync();
        _rotateTimer.Start();
    }

    private void UpdateRotateHint()
    {
        if (RotateHintText is null) return;
        if (!_config.RotateEnabled)
        {
            RotateHintText.Text = "Rotate off";
        }
        else if (_config.OvpnFiles.Count <= 1)
        {
            RotateHintText.Text = $"Rotate every {_config.RotateIntervalMinutes} min — needs 2+ profiles";
        }
        else
        {
            RotateHintText.Text = $"Rotates every {_config.RotateIntervalMinutes} min across {_config.OvpnFiles.Count} profiles";
        }
    }

    private bool _rotating;

    private async System.Threading.Tasks.Task RotateToNextAsync()
    {
        if (!_config.RotateEnabled) return;
        // Rotate whenever the user wants the tunnel — including while the
        // adapter is down. A dead server must rotate to a healthy profile
        // instead of reconnecting to the same dead one forever.
        if (!App.Connector.WantConnected) return;
        if (_rotating) return;
        _rotating = true;
        try
        {
            _config.RefreshFromDisk();
            if (_config.OvpnFiles.Count <= 1) return;

            // Walk forward from the live profile and take the first
            // connectable candidate (file exists + creds when required).
            // Single-pass over all profiles: no starvation, no sticking on
            // one credential-less entry for a whole interval.
            var liveId = App.Connector.ActiveProfileId ?? _config.ActiveOvpnId;
            var start = _config.OvpnFiles.FindIndex(p => p.Id == liveId);
            OvpnEntry? next = null;
            for (int i = 1; i <= _config.OvpnFiles.Count; i++)
            {
                var cand = _config.OvpnFiles[(start + i + _config.OvpnFiles.Count) % _config.OvpnFiles.Count];
                if (!IsConnectable(cand)) continue;
                next = cand;
                break;
            }
            if (next is null)
            {
                FooterText.Text = "Rotate skipped — no other connectable profile (missing files or credentials)";
                return;
            }
            if (next.Id == liveId) return; // only ourselves connectable

            await SwitchProfileAsync(next, liveId);
        }
        finally
        {
            _rotating = false;
        }
    }

    private async void RotateNowBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!App.Connector.WantConnected) return;
        if (_rotating) return;
        _rotating = true;
        try
        {
            _config.RefreshFromDisk();
            var liveId = App.Connector.ActiveProfileId ?? _config.ActiveOvpnId;
            var others = _config.OvpnFiles
                .Where(p => p.Id != liveId && IsConnectable(p))
                .ToList();
            if (others.Count == 0)
            {
                FooterText.Text = "No other connectable profile to rotate to";
                return;
            }
            var next = others[Random.Shared.Next(others.Count)];
            await SwitchProfileAsync(next, liveId);
        }
        finally
        {
            _rotating = false;
        }
    }

    /// <summary>
    /// Switch the live tunnel to another profile: disconnect, connect, and
    /// fall back to the previous profile on failure so a bad rotate never
    /// leaves the tunnel dead. Honors an interleaved manual Disconnect.
    /// </summary>
    private async System.Threading.Tasks.Task SwitchProfileAsync(OvpnEntry next, string? prevId)
    {
        // NOTE: callers own the _rotating guard; this method only switches.
        try
        {
            FooterText.Text = $"Rotating to \"{next.DisplayName}\"…";
            var dc = App.Connector.DisconnectCount;
            await App.Connector.DisconnectAsync();
            // A manual Disconnect interleaved with our own (user hit
            // Disconnect/Cancel while we awaited) must NOT be
            // resurrected by the Connect below.
            if (App.Connector.DisconnectCount != dc + 1) return;
            _config.ActiveOvpnId = next.Id;
            _config.Save();
            await App.Connector.ConnectAsync(next);
            if (!App.Connector.WantConnected)
            {
                // Stopped while connecting — leave it stopped.
                _connecting = false;
                _vpnDownSince = null;
                return;
            }
            _connecting = true;
            _vpnDownSince = DateTime.UtcNow;
            UpdateProfileText();
        }
        catch (Exception ex)
        {
            // A concurrent manual Disconnect (WantConnected==false) wins:
            // do not restore anything, leave the tunnel stopped.
            if (!App.Connector.WantConnected)
            {
                _connecting = false;
                _vpnDownSince = null;
                return;
            }
            // Never leave the tunnel dead after a failed rotate: fall
            // back to the previous profile (WantConnected stays true
            // either way so the watchdog keeps repairing).
            FooterText.Text = $"Rotate to \"{next.DisplayName}\" failed: {ex.Message} — restoring previous";
            // Same interleave guard as above: a manual Disconnect during
            // the restore connect must win — honor it instead of leaving
            // a resurrected tunnel behind.
            try
            {
                var prev = _config.OvpnFiles.FirstOrDefault(p => p.Id == prevId);
                if (prev is not null && System.IO.File.Exists(prev.FilePath))
                {
                    var dc2 = App.Connector.DisconnectCount;
                    _config.ActiveOvpnId = prev.Id;
                    _config.Save();
                    await App.Connector.ConnectAsync(prev);
                    if (App.Connector.DisconnectCount != dc2)
                    {
                        await App.Connector.DisconnectAsync();
                        _connecting = false;
                        _vpnDownSince = null;
                    }
                    else
                    {
                        _connecting = true;
                        _vpnDownSince = DateTime.UtcNow;
                        UpdateProfileText();
                    }
                }
            }
            catch (Exception ex2)
            {
                FooterText.Text = $"Rotate failed: {ex.Message} / restore failed: {ex2.Message}";
            }
        }
    }

    #endregion

    private void RefreshAppList()
    {
        _config = Config.Load();
        // Rebuild AppRow set, preserving any rows whose path is still in the config.
        var existing = _appRows.ToDictionary(r => r.ExePath, StringComparer.OrdinalIgnoreCase);
        _appRows.Clear();
        foreach (var entry in _config.TunneledApps)
        {
            var row = existing.GetValueOrDefault(entry.ExePath) ?? new AppRow(entry);
            _appRows.Add(row);
        }
        AppsList.ItemsSource = _appRows;
        EmptyAppsText.Visibility = _config.TunneledApps.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private static string FormatBytes(ulong bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double v = bytes;
        string[] units = { "KB", "MB", "GB", "TB" };
        int i = -1;
        do
        {
            v /= 1024.0;
            i++;
        } while (v >= 1024.0 && i < units.Length - 1);
        return $"{v:0.##} {units[i]}";
    }

    private static string FormatUptime(ulong ms)
    {
        if (ms == 0) return "—";
        var span = TimeSpan.FromMilliseconds(ms);
        if (span.TotalDays >= 1) return $"{(int)span.TotalDays}d {span.Hours:D2}h {span.Minutes:D2}m";
        if (span.TotalHours >= 1) return $"{(int)span.TotalHours}h {span.Minutes:D2}m {span.Seconds:D2}s";
        if (span.TotalMinutes >= 1) return $"{(int)span.TotalMinutes}m {span.Seconds:D2}s";
        return $"{(int)span.TotalSeconds}s";
    }
}
