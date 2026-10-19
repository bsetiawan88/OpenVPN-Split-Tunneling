# Installs / uninstalls VpnWfpCallout.sys (WFP backend, non-PnP WFPCALLOUTS).
# Requires admin. Driver must be attestation-signed for Secure Boot/HVCI;
# test-signed loads only with `bcdedit /set testsigning on` + reboot.
#
# NOTE: VpnWfpCallout.inf is DefaultInstall-only (no Manufacturer/Models),
# so pnputil /add-driver /install will reject it. Correct path for
# WFPCALLOUTS is InstallHinfSection + sc.exe create/start.
param(
    [switch]$Install,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$driverDir = Join-Path $PSScriptRoot "..\driver"
$inf = Join-Path $driverDir "VpnWfpCallout.inf"
$sys = Join-Path $driverDir "VpnWfpCallout.sys"
$svc = "VpnWfpCallout"

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run as administrator."
    }
}

function Test-Bfe {
    $bfe = & sc.exe query BFE 2>&1 | Out-String
    if ($bfe -notmatch "RUNNING") {
        throw "BFE (Base Filtering Engine) is not RUNNING. Start it first: sc.exe start BFE. Output:`n$bfe"
    }
}

Require-Admin

if ($Install) {
    Test-Bfe
    if (-not (Test-Path $inf)) {
        throw "Missing $inf — generate the WDM driver project first (see driver/README.md)."
    }
    if (-not (Test-Path $sys)) {
        throw "Missing $sys — build the driver with WDK first (see driver/README.md). WinDivert backend remains default until then."
    }
    Write-Host "[wfp] InstallHinfSection DefaultInstall 132 $inf" -ForegroundColor Cyan
    & rundll32.exe SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 $inf
    if ($LASTEXITCODE -ne 0) { throw "InstallHinfSection failed: $LASTEXITCODE" }

    # Ensure kernel service entry exists (INF AddService path varies by OS build).
    $exists = (& sc.exe query $svc 2>&1 | Out-String) -match "SERVICE_NAME"
    if (-not $exists) {
        Write-Host "[wfp] sc.exe create $svc (INF AddService fallback)" -ForegroundColor Cyan
        & sc.exe create $svc binPath= "$env:SystemRoot\System32\drivers\VpnWfpCallout.sys" type= kernel start= auto error= normal group= "Extended Base" depend= BFE | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed: $LASTEXITCODE" }
    }
    Write-Host "[wfp] sc.exe start $svc" -ForegroundColor Cyan
    $startOut = & sc.exe start $svc 2>&1 | Out-String
    Write-Host $startOut
    if ($startOut -match "FAILED 577|INVALID SIGNATURE|unsigned") {
        throw "Driver start failed — signature rejected. Prod needs attestation signing; dev needs testsigning on + reboot. See driver/README.md. Output:`n$startOut"
    }
    & sc.exe query $svc
    & sc.exe query BFE
}
elseif ($Uninstall) {
    Write-Host "[wfp] sc.exe stop/delete $svc" -ForegroundColor Cyan
    & sc.exe stop $svc 2>$null | Out-Null
    Start-Sleep -Milliseconds 750
    & sc.exe delete $svc 2>$null | Out-Null
    Write-Host "INF copy under %WinDir%\\INF can stay; it is inert without the service."
}
else {
    Write-Host "Usage: DriverInstall.ps1 -Install | -Uninstall"
}
