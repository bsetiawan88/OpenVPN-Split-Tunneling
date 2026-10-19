using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace VpnClient.Ui;

public partial class SettingsWindow : FluentWindow
{
    private readonly Config _cfg;
    public ObservableCollection<AppEntry> Apps { get; }
    public event EventHandler? ConfigChanged;

    public SettingsWindow(Config cfg)
    {
        InitializeComponent();
        _cfg = cfg;
        var mitm = new System.Collections.Generic.HashSet<string>(
            cfg.MitmApps, System.StringComparer.OrdinalIgnoreCase);
        foreach (var a in cfg.TunneledApps) a.MitmDecrypt = mitm.Contains(a.ExePath);
        Apps = new ObservableCollection<AppEntry>(cfg.TunneledApps);
        AppList.ItemsSource = Apps;
        MitmMasterCheck.IsChecked = cfg.MitmEnabled;
        // Repair sentinel files if they were deleted manually.
        VpnConnector.SetMitmEnabled(cfg.MitmEnabled);
        VpnConnector.WriteMitmApps(cfg.MitmApps);
        RefreshCaStatus();
    }

    private void MitmMaster_Changed(object sender, RoutedEventArgs e)
    {
        _cfg.MitmEnabled = MitmMasterCheck.IsChecked == true;
        _cfg.Save();
        VpnConnector.SetMitmEnabled(_cfg.MitmEnabled);
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }

    private void MitmCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.CheckBox cb || cb.Tag is not string id) return;
        var entry = Apps.FirstOrDefault(a => a.Id == id);
        if (entry is null) return;
        entry.MitmDecrypt = cb.IsChecked == true;
        Persist();
    }

    private void InstallCaBtn_Click(object sender, RoutedEventArgs e)
    {
        CaStatusText.Text = VpnConnector.InstallMitmCa();
    }

    private void RemoveCaBtn_Click(object sender, RoutedEventArgs e)
    {
        CaStatusText.Text = VpnConnector.RemoveMitmCa();
    }

    private void RefreshCaStatus() => CaStatusText.Text = VpnConnector.MitmCaStatus();

    private void AddAppBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            // Default to All files so .ark, .com, repackaged executables etc.
            // can be registered too. Games sometimes ship binaries under custom
            // extensions (Lost Ark's LOSTARKWeb64.ark for the in-game browser
            // is a common case).
            Filter = "All files (*.*)|*.*|Executables (*.exe)|*.exe",
            Title = "Pick the file to tunnel",
        };
        if (dlg.ShowDialog(this) != true) return;

        var entry = new AppEntry
        {
            DisplayName = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName),
            ExePath = dlg.FileName,
        };
        Apps.Add(entry);
        Persist();
    }

    private void RemoveApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        var entry = Apps.FirstOrDefault(a => a.Id == id);
        if (entry is null) return;
        Apps.Remove(entry);
        Persist();
    }

    private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();

    private void Persist()
    {
        _cfg.TunneledApps = Apps.ToList();
        _cfg.MitmApps = Apps.Where(a => a.MitmDecrypt).Select(a => a.ExePath).ToList();
        _cfg.Save();
        VpnConnector.WriteMitmApps(_cfg.MitmApps);
        RefreshCaStatus();
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }
}
