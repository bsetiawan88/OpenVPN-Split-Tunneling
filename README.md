# OpenVPN Split Tunneling Client

Route specific Windows applications through an OpenVPN tunnel. Everything else
stays on your regular default route.

Built for the case where you want, say, your game launcher and the game
itself to come out of a foreign IP — without bending your whole machine
through the tunnel.

---

## What it does

Pick a list of `.exe`s. They (and any child processes they spawn) egress
through your OpenVPN tunnel. Everything not on the list — your browser, your
chat apps, Windows Update, Steam — keeps using your normal internet
connection at full speed.

No system-wide routing changes. No "kill switch" required for unlisted apps.
No DNS leaks for the apps you care about because they're pinned to the
tunnel's adapter at the socket level (`IP_UNICAST_IF`), not the route
table.

When the VPN goes down, listed apps fall back to the default route (fail-open)
so they keep working — just without the tunnel.

## Who it's for

- **Region-locked launchers** — Korean / Japanese / Chinese games (Lost Ark
  via STOVE, FFXIV, Genshin's gacha clients) that geofence to a specific
  country's IP, where you only want the game on the VPN and not your
  Discord call sitting on top of it.
- **One-off region-tied apps** — banking, streaming, regional
  e-commerce — where you don't want the latency tax of tunneling every
  packet on your box.
- **Anyone fighting the limitations of full-tunnel VPN** — OpenVPN
  Community pushes a `redirect-gateway` directive that hijacks the
  default route. This client strips that directive and pins only the apps
  you choose to the VPN adapter.

## What it isn't

- Not a VPN provider — you bring your own `.ovpn` profile (paid VPN
  service, self-hosted on a VPS, a friend's router, whatever).
- Not a proxy. There's no SOCKS server, no userland injection. Tunneling
  happens at the network layer via WinDivert + smoltcp.
- Not cross-platform. Windows 10 1607+ only.

---

## Install

### From the Release

1. Download `VpnClientSetup-X.Y.Z.exe` from the
   [Releases page](../../releases).
2. Run it. Windows SmartScreen warns about an unverified publisher — click
   **More info → Run anyway** (the installer is unsigned because
   code-signing certs cost ~$220/yr and this is a hobby project).
3. The installer drops everything into `C:\Program Files\VpnClient\` and
   silently installs OpenVPN Community 2.7.4 if you don't already have it.

### Requires

- Windows 10 1607 (build 14393) or newer, x64
- Admin rights at install time *and* at launch time (the redirector needs
  to load the WinDivert capture driver)

That's the whole prereq list. The installer bundles OpenVPN.

---

## Quick start

1. **Launch** the app from the Start Menu.
2. **Import an .ovpn profile** via the gear icon next to the Connect
   button. Add username + password if your provider requires them. They're
   stored DPAPI-encrypted, per-user.
3. **Add apps to tunnel** via the **Manage** button under "Tunneled
   Apps." Point it at any `.exe`. The picker accepts any file type — some
   games use custom extensions (e.g. Lost Ark's `LOSTARKWeb64.ark`).
4. **Hit Connect.** Once the header turns green and shows "VPN
   connected," every listed app egresses through the tunnel.

Live stats in the main window show per-app and per-PID bandwidth + the
total bytes pushed through.

---

## How it works

```
┌──────────────────────────────────────────────────────────────────────┐
│  VpnClient.Ui.exe   (WPF + Wpf.Ui, requireAdministrator)            │
│   ├─ Status pipe       ────► redirector.exe                          │
│   ├─ Policy pipe       ────► redirector.exe                          │
│   └─ Job Object holds: redirector, openvpn  (KILL_ON_JOB_CLOSE)     │
└──────────────────────────────────────────────────────────────────────┘
                                  ▲
                                  │ named pipes (protobuf framed)
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│  redirector.exe   (Rust + tokio)                                     │
│   ├─ WinDivert NETWORK layer   ── captures outbound IPv4 packets    │
│   ├─ Observer (SOCKET layer)   ── populates PID-from-port table     │
│   ├─ ProcWatcher (sysinfo)     ── path-based PID admission          │
│   ├─ smoltcp                   ── user-space TCP termination        │
│   └─ Bridge sockets (IP_UNICAST_IF) ── re-emit on VPN adapter       │
└──────────────────────────────────────────────────────────────────────┘
                                  ▲
                                  │
┌──────────────────────────────────────────────────────────────────────┐
│  openvpn.exe   (Community 2.7.x, --windows-driver wintun)            │
│   └─ Wintun / TAP-Windows6 adapter                                   │
└──────────────────────────────────────────────────────────────────────┘
```

### Why smoltcp instead of just `route ADD ... IF`?

Windows won't accept reinjected packets whose source is a non-loopback
address and destination is a loopback. That kills the naive "DNAT a
tunneled flow to 127.0.0.1, run a SOCKS server there, reinject" approach.
Same reason mitmproxy_rs uses smoltcp on Windows — terminate TCP in
userspace, open a fresh kernel socket to the original destination, bridge
the two.

### How fast-launching apps get admitted

Some apps (game launchers especially) make their first outbound connection
within microseconds of spawning. A polling process watcher loses that race
every time. Admission happens in three layers, in order of preference:

1. **Observer fast path** — WinDivert SOCKET layer fires on `connect()`
   with full PID context. Usually beats the SYN.
2. **Packet-time path match** — when a captured SYN has no known PID
   yet, we look it up synchronously via `GetExtendedTcpTable`, then
   match its exe path against the user's tunneled list. Admits the PID
   on the spot.
3. **Tight retry** — if both miss, we hold the packet (it's in
   WinDivert's queue, hasn't hit the wire) and re-poll every 200 µs for
   up to 1 ms.

If after all of that the kernel still can't tell us who owns the socket,
the packet passes through to the default route. In practice that doesn't
happen for any user-mode process.

### Process lifecycle

The UI owns a Win32 Job Object with `KILL_ON_JOB_CLOSE`. Both
`redirector.exe` and `openvpn.exe` are assigned to it. Closing the UI —
clean exit or crash — kills both via the kernel, guaranteed. No
"redirector is still running from yesterday" orphan state.

---

## Build from source

### Requires

- [Rust](https://rustup.rs/) (stable, 1.75+)
- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- [Inno Setup 6](https://jrsoftware.org/isdl.php) (only for `build.ps1`'s
  installer step; `winget install JRSoftware.InnoSetup` works)

### One-shot

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1
```

Builds redirector, publishes the UI as a single self-contained `.exe`,
downloads the OpenVPN MSI to `installer\deps\` (cached across rebuilds),
and produces `installer\Output\VpnClientSetup-<version>.exe`.

### Just iterate on the UI

```
dotnet build dotnet\VpnClient.Ui\VpnClient.Ui.csproj
```

### Just iterate on the redirector

```
cargo build --release --manifest-path redirector\Cargo.toml
```

For dev runs, `VpnClient.Ui\Redirector.cs` falls back to
`target\release\redirector.exe` and then `target\debug\redirector.exe` if
no `redirector.exe` is next to the UI binary, so you can edit and rebuild
either side independently without reinstalling.

---

## Layout

```
dotnet/VpnClient.Ui/     C# WPF UI. Talks to redirector over named pipes.
redirector/              Rust packet redirector — WinDivert + smoltcp.
ipc/                     Shared protobuf definitions + framing helpers.
installer/               Inno Setup script + build pipeline.
supervisor/              (Reserved; future service-mode redirector wrapper.)
```

---

## Known limitations

- **No code signing.** First-run SmartScreen warning. Some antivirus
  products flag the WinDivert driver as suspicious on principle.
- **TCP-table race for kernel-mode sockets.** Sockets opened by a driver
  (almost no user-mode app does this) skip our PID admission and pass
  through. Not an issue for normal apps.
- **No IPv6 tunneling.** The redirector captures IPv4 only. Tunneled apps
  with both IPv4 and IPv6 connectivity will see their IPv6 traffic egress
  directly. Disable IPv6 on the VPN profile or accept the leak — your
  call.
- **Wintun-vs-TAP fallback.** Wintun is preferred; if it isn't installed
  (rare, since our bundled MSI installs it), OpenVPN falls back to
  TAP-Windows6 with a working but slower path.
- **Anti-cheat-compatible.** WinDivert is a NDIS callout, not a
  kernel-mode socket hook, so EAC / Vanguard / BattlEye don't flag it.
  But this hasn't been broadly tested with every game.

---

## Request logging (HTTP log + opt-in MITM)

- **HTTP log** (footer checkbox): passive, no decrypt. Plain HTTP logs
  `METHOD host/path`; HTTPS logs `SNI` only. File-only
  `%LocalAppData%\VpnClient\runtime\http.log`, cleared on every app start.
- **Decrypt HTTPS (MITM)**: opt-in per app in **Manage → Tunneled Apps**.
  The redirector generates a local CA (`%AppData%\VpnClient\ca\ca.crt`),
  terminates opted apps' TLS with per-SNI leaves, logs the decrypted
  request line + headers (never bodies) to the same `http.log`, and
  re-encrypts toward the server over the VPN. Steps: tick the master
  switch, tick Decrypt on the app, hit **Install CA** (adds it to Trusted
  Root — required, otherwise the app errors), generate traffic.
  Non-HTTP TLS (custom protocols) logs as `(non-HTTP)`. Apps with
  certificate pinning fail while opted in — untick Decrypt for them.
  Remove trust anytime via **Remove CA** (or `certmgr.msc`).

---

## License

The Rust and C# code in this repository is released under the MIT license
(see [LICENSE](LICENSE)).

This project redistributes:

- [WinDivert](https://reqrypt.org/windivert.html) — LGPLv3 — kernel
  driver + DLL bundled in the installer.
- [OpenVPN Community](https://openvpn.net/community/) — GPLv2 (with
  OpenSSL exception) — MSI bundled in the installer; installs to its own
  `C:\Program Files\OpenVPN\` and is independently uninstallable.

---

## Acknowledgements

- [mitmproxy_rs](https://github.com/mitmproxy/mitmproxy_rs) for the
  smoltcp-on-WinDivert architecture that made user-space TCP termination
  on Windows actually work.
- [Wpf.Ui](https://github.com/lepoco/wpfui) for the Fluent v2 / Mica
  treatment — the entire reason this app doesn't look like Windows XP.
- The OpenVPN community devs for the `--pull-filter` machinery that lets
  us strip `redirect-gateway` cleanly.
