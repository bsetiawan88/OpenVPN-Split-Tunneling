; Inno Setup script for VpnClient
;
; Build everything first:
;   cd C:\Projects\vpn
;   cargo build --release --manifest-path redirector/Cargo.toml
;   dotnet publish dotnet/VpnClient.Ui/VpnClient.Ui.csproj -c Release
;
; Then compile this script with the Inno Setup IDE or:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\VpnClient.iss
;
; Output:  installer\Output\VpnClientSetup-1.0.0.exe

#define MyAppName      "OpenVPN Split Tunneling Client"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "ena"
#define MyAppExeName   "VpnClient.Ui.exe"
#define MyAppId        "{{A6A4F2D2-6E1E-4D6F-A2D6-9E1F7B3B8FCC}"

#define UiPublishDir   "..\dotnet\VpnClient.Ui\bin\Release\net8.0-windows10.0.19041.0\win-x64\publish"
#define RedirectorDir  "..\target\release"
#define OpenVpnVersion "2.7.4-I001"
#define OpenVpnMsi     "OpenVPN-" + OpenVpnVersion + "-amd64.msi"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\VpnClient
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=VpnClientSetup-{#MyAppVersion}
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
; UI (single self-contained exe — bundles .NET runtime + WPF + Wpf.Ui)
Source: "{#UiPublishDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Redirector + WinDivert (default backend). The two WinDivert files MUST live
; next to redirector.exe — WinDivert resolves its driver path relative to DLL.
; Kept even after WFP lands: --backend=windivert is the fail-safe default
; until VpnWfpCallout is attestation-signed (Secure Boot/HVCI).
Source: "{#RedirectorDir}\redirector.exe";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#RedirectorDir}\WinDivert.dll";    DestDir: "{app}"; Flags: ignoreversion
Source: "{#RedirectorDir}\WinDivert64.sys";  DestDir: "{app}"; Flags: ignoreversion

; WFP callout driver (opt-in backend, --backend=wfp). Non-PnP WFPCALLOUTS:
; installed via InstallHinfSection + sc.exe (see DriverInstall.ps1), not
; pnputil. Files staged under {app}\driver for the post-install step.
Source: "..\driver\VpnWfpCallout.inf";     DestDir: "{app}\driver"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\driver\VpnWfpCallout.sys";     DestDir: "{app}\driver"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\driver\ioctl.h";               DestDir: "{app}\driver"; Flags: ignoreversion skipifsourcedoesntexist
Source: "DriverInstall.ps1";               DestDir: "{app}\driver"; Flags: ignoreversion

; Bundled OpenVPN Community MSI. Only installed if openvpn.exe isn't found
; at the standard path. Extracted to {tmp} and deleted after.
Source: "deps\{#OpenVpnMsi}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: not OpenVpnInstalled

[Icons]
Name: "{group}\{#MyAppName}";          Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";    Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Install bundled OpenVPN first, if not already present. Quiet install
; ADDLOCAL covers the components we need: core binaries, Wintun driver,
; and the TAP driver (fallback for boxes where Wintun won't load).
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\{#OpenVpnMsi}"" /quiet /norestart ADDLOCAL=OpenVPN.Service,Drivers,Drivers.Wintun,Drivers.TAPWindows6"; StatusMsg: "Installing OpenVPN Community ({#OpenVpnVersion}) ..."; Flags: waituntilterminated; Check: not OpenVpnInstalled

; shellexec is required because the UI exe is marked requireAdministrator in
; its manifest. CreateProcess from the installer fails with ERROR_ELEVATION_
; REQUIRED (740); ShellExecute triggers the UAC prompt the way Explorer would.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: shellexec postinstall skipifsilent

[UninstallRun]
; Make sure nothing is holding the drivers open before uninstall removes the
; files. taskkill releases user-mode handles; sc stop/delete unloads the
; kernel drivers — without that, .sys files stay locked.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM VpnClient.Ui.exe /T"; Flags: runhidden; RunOnceId: "KillUi"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM redirector.exe /T";  Flags: runhidden; RunOnceId: "KillRedirector"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM openvpn.exe /T";     Flags: runhidden; RunOnceId: "KillOpenvpn"
Filename: "{sys}\sc.exe";       Parameters: "stop WinDivert";            Flags: runhidden; RunOnceId: "StopWinDivert"
Filename: "{sys}\sc.exe";       Parameters: "delete WinDivert";          Flags: runhidden; RunOnceId: "DeleteWinDivert"
Filename: "{sys}\sc.exe";       Parameters: "stop VpnWfpCallout";        Flags: runhidden; RunOnceId: "StopWfp"
Filename: "{sys}\sc.exe";       Parameters: "delete VpnWfpCallout";       Flags: runhidden; RunOnceId: "DeleteWfp"

[Code]
function OpenVpnInstalled: Boolean;
begin
  // Match VpnConnector.OpenVpnPaths — if either location has openvpn.exe,
  // we skip the bundled MSI install entirely.
  Result := FileExists(ExpandConstant('{commonpf}\OpenVPN\bin\openvpn.exe'))
         or FileExists(ExpandConstant('{commonpf32}\OpenVPN\bin\openvpn.exe'));
end;

procedure CleanupBeforeInstall;
var
  ResultCode: Integer;
begin
  // Same teardown the uninstaller does, but pre-install: any leftover
  // redirector / loaded driver from a previous version would lock the
  // .sys file we're about to overwrite (DeleteFile code 5).
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM VpnClient.Ui.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM redirector.exe',   '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM openvpn.exe',      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'),       'stop WinDivert',             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'),       'delete WinDivert',           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'),       'stop VpnWfpCallout',         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'),       'delete VpnWfpCallout',       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // SCM is async — give it a beat to finish unloading before we replace files.
  Sleep(750);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    CleanupBeforeInstall;
end;
