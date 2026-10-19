# VpnWfpCallout driver — full WFP redirect implementation.

Thin kernel redirector mirroring ProxifierDrv.sys (REA: `WFPCALLOUTS`,
`BFE` dependency, `FwpsCalloutRegister` + `Fwpm{EngineOpen,ProviderAdd,
SubLayerAdd,CalloutAdd,FilterAdd}`, `FwpsRedirectHandleCreate`,
`FwpsAcquireWritableLayerDataPointer`, `ALE_CONNECT_REDIRECT`,
`DATAGRAM_DATA`, `PROCESS_ID`, `INJECTED_BY_SELF` guard):

- Kernel only redirects allowlisted PIDs to `127.0.0.1:P_tcp/P_udp`.
- All proxy/auth/chain/DNS logic stays in user-mode Rust
  (`redirector/src/wfp/`), reusing `IP_UNICAST_IF` pinning.
- Fail-open preserved: empty allowlist/target, driver stopped, or VPN
  down all fall back to `FWP_ACTION_CONTINUE` / clean close.

## Layout

- `VpnWfpCallout.inf` — non-PnP `DefaultInstall` (no Manufacturer/Models;
  install via `InstallHinfSection + sc.exe`, not `pnputil`).
- `VpnWfpCallout.vcxproj` — WDM Empty (WDK 10.0.22621+, VS2022).
- `ioctl.h` — `\\.\VpnWfpCallout` contract (0x800 QUERY, 0x801 ALLOWLIST,
  0x802 FLUSH, 0x803 REDIRECT_TARGET; 512-PID chunks).
- `callout.c` — full: secure control device (SY+BA SDDL), 3 callouts
  (REDIRECT_V4/V6 + DATAGRAM_V4), provider/sublayer/callouts/filters via
  `FwpmTransaction`, injection + redirect handles, allowlist (replace),
  flow table (srcPort→{dst,pid}, 2048 slots), `QUERY/FLUSH/TARGET` dispatch.

## Data plane

- TCP: `ALE_CONNECT_REDIRECT_V4` — PID allowlist → skip loopback/DNS
  (53/5353/5355) + TCP/UDP gate → rewrite remote to `127.0.0.1:P`, stash
  `{(srcPort,proto)→dst,pid}`. `V6 CONTINUE` until IPv6 parity lands.
- UDP: `DATAGRAM_DATA_V4` outbound — PID allowlist → skip DNS/mDNS/LLMNR
  + loopback → record flow then **`BLOCK` (fail-closed)**. Without NBL
  rewrite an unconnected `sendto` would egress via the default route
  (leak); connected UDP already went through `REDIRECT_V4`. The relay's
  own sockets run under `redirector.exe` (not allowlisted) so `BLOCK`
  never stops relay traffic. User-mode `udp_relay` serves connected UDP
  via its NAT table; unconnected UDP stays blocked loudly until the
  Phase-2b NBL rewrite lands.
- Flow table is `(port,proto)`-keyed with tombstones; `FLUSH` on VPN
  down/rotate; `QUERY` carries proto in `Reserved` low byte (0=wildcard).

## Build

```powershell
msbuild driver\VpnWfpCallout.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Signing

- Dev: `bcdedit /set testsigning on` + reboot, self-signed test cert.
- Prod: attestation via Partner Center. Required for Secure Boot/HVCI.
  Without it the driver will not load and `--backend=wfp` bails with
  guidance; default stays `--backend=windivert`.

## Install / uninstall (non-PnP)

```powershell
# needs admin, BFE running
powershell -ExecutionPolicy Bypass -File installer\DriverInstall.ps1 -Install
sc.exe query VpnWfpCallout
sc.exe query BFE
netsh wfp show state
redirector wfp-status
redirector observe --backend=wfp   # needs admin + VPN up
# uninstall:
powershell -ExecutionPolicy Bypass -File installer\DriverInstall.ps1 -Uninstall
```

## Testing

1. `redirector wfp-status` → `installed/running/bfe/device_openable`.
2. `redirector observe --backend=wfp` with driver stopped → clean bail message.
3. Driver running, VPN up: listed `.exe` TCP → `BridgeOpened ... via VPN (wfp)`;
   unlisted → kernel `CONTINUE`, zero userspace trip.
4. `route.exe print -4` split route still via `IP_UNICAST_IF`; kill openvpn
   → `VpnDown + FLUSH`, app reconnect fail-open.
5. `pktmon` / `netsh wfp show state` shows provider/sublayer/callouts/filters.

## Limits (by design)

- IPv4 only (V6 `CONTINUE`); DNS 53/5353/5355 never tunneled.
- Allowlist snapshot ≤512 per push (covers launcher+game trees).
- UDP unconnected without prior DATAGRAM record is dropped loudly
  (needs `connect()` form or driver mapping).
