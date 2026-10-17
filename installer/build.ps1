# Builds redirector + UI + installer in one shot.
#
# Usage (from anywhere):
#   powershell -ExecutionPolicy Bypass -File C:\Projects\vpn\installer\build.ps1
#
# Output: installer\Output\VpnClientSetup-<version>.exe

param(
    [switch]$SkipBuild,
    [switch]$BuildDriver
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

# Bundled OpenVPN MSI — used at install time if the target machine doesn't
# already have OpenVPN. Pin to a known-good version; bump as needed.
$openvpnVersion = "2.7.4-I001"
$openvpnMsi = "OpenVPN-$openvpnVersion-amd64.msi"
$openvpnUrl = "https://swupdate.openvpn.org/community/releases/$openvpnMsi"
$openvpnDest = Join-Path $PSScriptRoot "deps\$openvpnMsi"

if (-not (Test-Path $openvpnDest)) {
    Write-Host "[0/3] Downloading OpenVPN $openvpnVersion MSI..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path (Split-Path $openvpnDest) -Force | Out-Null
    Invoke-WebRequest -Uri $openvpnUrl -OutFile $openvpnDest -UseBasicParsing
}

if (-not $SkipBuild) {
    Write-Host "[1/3] cargo build --release (redirector)" -ForegroundColor Cyan
    & cargo build --release --manifest-path "$root\redirector\Cargo.toml"
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    Write-Host "[1b/3] WFP driver (optional, needs WDK; -BuildDriver to attempt)" -ForegroundColor Cyan
    if ($BuildDriver) {
        $vcxproj = Get-ChildItem "$root\driver\*.vcxproj" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $vcxproj) {
            Write-Host "  (skip: no driver .vcxproj — see driver/README.md)" -ForegroundColor Yellow
        } else {
            $msbuild = Get-Command msbuild -ErrorAction SilentlyContinue
            if (-not $msbuild) {
                Write-Host "  (skip: msbuild not in PATH — install VS2022+WDK or run without -BuildDriver; WinDivert default unaffected)" -ForegroundColor Yellow
            } else {
                try {
                    & msbuild $vcxproj.FullName /p:Configuration=Release /p:Platform=x64
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "  WARNING: driver build failed ($LASTEXITCODE) — continuing without driver (WinDivert default unaffected)" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "  WARNING: driver build threw ($_) — continuing without driver" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "  (skip: pass -BuildDriver to attempt WDK build; WinDivert backend is default)" -ForegroundColor Yellow
    }

    Write-Host "[2/3] dotnet publish (UI, single-file self-contained)" -ForegroundColor Cyan
    & dotnet publish "$root\dotnet\VpnClient.Ui\VpnClient.Ui.csproj" -c Release --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
}

Write-Host "[3/3] Inno Setup compile" -ForegroundColor Cyan
$iscc = @(
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    throw "Inno Setup not found. Install from https://jrsoftware.org/isdl.php"
}

& $iscc "$PSScriptRoot\VpnClient.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

$out = Get-ChildItem "$PSScriptRoot\Output\*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host ""
Write-Host "OK  $($out.FullName)  ($([math]::Round($out.Length / 1MB, 1)) MB)" -ForegroundColor Green
