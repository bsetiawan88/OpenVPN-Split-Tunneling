using System.Windows;

namespace VpnClient.Ui;

public partial class App : Application
{
    public static VpnConnector Connector { get; } = new VpnConnector();

    protected override void OnStartup(StartupEventArgs e)
    {
        // 1. Kill any redirector/openvpn left behind by a previous UI
        //    session that didn't have the job-object teardown.
        // 2. Fresh logs per app start (AFTER the kill so no surviving
        //    orphan can append to the fresh file): a saved
        //    activity.log/openvpn.log always belongs to exactly one
        //    session (analyzable from disk). Must precede TryStart: the
        //    redirector appends a marker on boot that belongs at the top
        //    of the fresh file.
        // 3. Start a fresh redirector and lift it into the UI's job so
        //    it dies with us — clean exit or crash.
        // Failure is silent; the UI will surface "Disconnected from
        //    redirector" in the header if step 3 fails.
        Redirector.KillOrphans();
        VpnConnector.ClearLogsOnAppStart();
        Redirector.TryStart();
        base.OnStartup(e);
    }
}
