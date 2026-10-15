using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Wpf.Ui.Controls;

namespace VpnClient.Ui;

/// <summary>
/// Profiles come straight from the OpenVPN Community config dir
/// (C:\Program Files\OpenVPN\config). No import step: drop .ovpn files in
/// that folder (or a subfolder) and hit Refresh. This window only edits
/// per-profile credentials + server override, stored in our JSON.
/// </summary>
public partial class VpnConfigWindow : FluentWindow
{
    private Config _cfg;
    public ObservableCollection<OvpnEntry> Profiles { get; private set; } = new();
    public event EventHandler? ConfigChanged;

    private OvpnEntry? _editing;

    public VpnConfigWindow(Config cfg)
    {
        InitializeComponent();
        _cfg = cfg;
        RefreshFromDisk();
    }

    private void RefreshFromDisk()
    {
        _cfg.RefreshFromDisk();
        Profiles = new ObservableCollection<OvpnEntry>(_cfg.OvpnFiles);
        ProfileList.ItemsSource = Profiles;
        if (Profiles.Count > 0)
            ProfileList.SelectedIndex = 0;
        else
        {
            _editing = null;
            DetailGrid.Visibility = Visibility.Collapsed;
            EmptyText.Visibility = Visibility.Visible;
            EmptyText.Text = $"No .ovpn files found in:\n{OpenVpnConfigSource.DescribeDirs()}\n\n" +
                             "Copy your provider's .ovpn files there (plus ca/cert/key files they reference), then hit Refresh.";
        }
        DirHintText.Text = OpenVpnConfigSource.DescribeDirs();
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }

    private void RefreshBtn_Click(object sender, RoutedEventArgs e) => RefreshFromDisk();

    private void OpenFolderBtn_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            foreach (var dir in OpenVpnConfigSource.ConfigDirs)
            {
                if (System.IO.Directory.Exists(dir))
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = dir,
                        UseShellExecute = true,
                    });
                    return;
                }
            }
            System.Windows.MessageBox.Show(
                $"OpenVPN config folder not found:\n{OpenVpnConfigSource.DescribeDirs()}",
                "Folder not found",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Cannot open folder:\n{ex.Message}", "Error",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    private void ProfileList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ProfileList.SelectedItem is OvpnEntry entry)
        {
            _editing = entry;
            DetailGrid.Visibility = Visibility.Visible;
            EmptyText.Visibility = Visibility.Collapsed;
            DisplayNameBox.Text = entry.DisplayName;
            ServerHostnameBox.Text = entry.ServerHostname;
            ServerOverrideBox.Text = entry.ServerOverride;
            UsernameBox.Text = entry.Username;
            PasswordBox.Password = entry.GetPassword();
            FilePathText.Text = entry.FilePath;
            SaveHintText.Text = "";
            UpdateAuthHint(entry.FilePath);
        }
        else
        {
            _editing = null;
            DetailGrid.Visibility = Visibility.Collapsed;
            EmptyText.Visibility = Visibility.Visible;
        }
    }

    private void UpdateAuthHint(string filePath)
    {
        var mode = OvpnParser.GetAuthMode(filePath);
        switch (mode)
        {
            case OvpnParser.OvpnAuthMode.None:
                NeedsAuthHint.Visibility = Visibility.Collapsed;
                break;
            case OvpnParser.OvpnAuthMode.ExternalFile:
            case OvpnParser.OvpnAuthMode.Inline:
                NeedsAuthHint.Visibility = Visibility.Visible;
                NeedsAuthHint.Text = "Uses auth from the .ovpn itself — no username/password needed.";
                break;
            default:
                NeedsAuthHint.Visibility = Visibility.Visible;
                NeedsAuthHint.Text = "This profile requires username + password.";
                break;
        }
    }

    private void SaveBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        var current = _editing;
        current.DisplayName = DisplayNameBox.Text.Trim();
        if (string.IsNullOrEmpty(current.DisplayName))
            current.DisplayName = System.IO.Path.GetFileNameWithoutExtension(current.FilePath);
        current.ServerOverride = ServerOverrideBox.Text.Trim();
        current.Username = UsernameBox.Text.Trim();
        current.SetPassword(PasswordBox.Password);
        Persist();

        SaveHintText.Text = $"Saved ✓ {DateTime.Now:HH:mm:ss}";

        // OvpnEntry isn't observable; force the ListView to re-render in place.
        ProfileList.Items.Refresh();
    }

    private async void ConnectProfileBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        if (OvpnParser.NeedsUiCredentials(_editing.FilePath)
            && (string.IsNullOrWhiteSpace(_editing.Username)
                || string.IsNullOrWhiteSpace(_editing.GetPassword())))
        {
            System.Windows.MessageBox.Show(
                "This profile needs a username + password.\n" +
                "Save credentials first — openvpn runs hidden and cannot prompt interactively.",
                "Missing credentials",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }

        _cfg.ActiveOvpnId = _editing.Id;
        _cfg.Save();

        try
        {
            await App.Connector.ConnectAsync(_editing);
            Close();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                $"Connect failed:\n{ex.Message}",
                "Connect error",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
        }
    }

    private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();

    private void Persist()
    {
        _cfg.OvpnFiles = Profiles.ToList();
        _cfg.Save();
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }
}
