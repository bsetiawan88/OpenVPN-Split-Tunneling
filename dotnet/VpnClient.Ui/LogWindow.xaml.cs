using System;
using System.Windows;
using System.Windows.Threading;
using Wpf.Ui.Controls;

namespace VpnClient.Ui;

/// <summary>
/// Live viewer for %LocalAppData%\VpnClient\runtime\openvpn.log.
/// The single fastest way to see WHY a connection fails: look for
/// "Initialization Sequence Completed" (tunnel up), AUTH_FAILED
/// (bad credentials), TLS errors (server unreachable / bad certs),
/// or "Cannot open" / "Options error" (broken .ovpn references).
/// </summary>
public partial class LogWindow : FluentWindow
{
    private readonly DispatcherTimer _timer;

    public LogWindow()
    {
        InitializeComponent();
        RefreshLog();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => RefreshLog();
        _timer.Start();
        Closed += (_, _) => _timer.Stop();
    }

    private void RefreshLog()
    {
        LogText.Text = VpnConnector.ReadLogTail(400);
        if (AutoScrollCheck.IsChecked == true)
            LogScroller.ScrollToBottom();
    }

    private void RefreshBtn_Click(object sender, RoutedEventArgs e) => RefreshLog();

    private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();
}
