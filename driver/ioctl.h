#pragma once

// Shared user/kernel contract for \\.\VpnWfpCallout
// Mirrors the Proxifier pattern (\\.\ProxifierDrv + DeviceIoControl)
// observed via REA strings, but with our own service name and
// versioned IOCTLs so both drivers can coexist.

#define VPN_WFP_DEVICE_NAME L"\\\\.\\VpnWfpCallout"
#define VPN_WFP_DOS_DEVICE_NAME L"\\DosDevices\\VpnWfpCallout"

#define FILE_DEVICE_VPN_WFP 0x8001

#define VPN_WFP_IOCTL_QUERY_ORIGINAL_DST \
    CTL_CODE(FILE_DEVICE_VPN_WFP, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VPN_WFP_IOCTL_SET_PID_ALLOWLIST \
    CTL_CODE(FILE_DEVICE_VPN_WFP, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VPN_WFP_IOCTL_FLUSH_FLOWS \
    CTL_CODE(FILE_DEVICE_VPN_WFP, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Loopback target publish: written by redirect_listener immediately after
// bind(127.0.0.1:0). Separate from the PID allowlist (no side-channel).
#define VPN_WFP_IOCTL_SET_REDIRECT_TARGET \
    CTL_CODE(FILE_DEVICE_VPN_WFP, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _VPN_WFP_REDIRECT_TARGET {
    UINT32 LoopbackIp; // network order, must be 127.0.0.1
    UINT16 LoopbackPort; // host order, ephemeral port from user-mode bind
    UINT16 Reserved;
} VPN_WFP_REDIRECT_TARGET;

// Query: input = app src port + proto, output = original dst.
// Reserved low byte carries IPPROTO (6/17); 0 = legacy wildcard match-any
// (proto-agnostic) for backward compat with Phase-1 clients.
typedef struct _VPN_WFP_ORIGINAL_DST_QUERY {
    UINT32 LocalIp;   // network order, expected 127.0.0.1 (unused, kept for compat)
    UINT16 LocalPort; // host order = app src port (peer port of accepted socket)
    UINT16 Reserved;  // low byte = IPPROTO_TCP/UDP, 0 = wildcard
} VPN_WFP_ORIGINAL_DST_QUERY;

typedef struct _VPN_WFP_ORIGINAL_DST_REPLY {
    UINT32 DstIp;     // network order IPv4
    UINT16 DstPort;   // host order
    UINT32 Pid;       // owning PID from ALE metadata
} VPN_WFP_ORIGINAL_DST_REPLY;

// Allowlist push: fixed-size batch to keep METHOD_BUFFERED small.
#define VPN_WFP_MAX_PIDS_PER_PUSH 512

typedef struct _VPN_WFP_ALLOWLIST_PUSH {
    UINT32 Count;
    UINT32 Pids[VPN_WFP_MAX_PIDS_PER_PUSH];
} VPN_WFP_ALLOWLIST_PUSH;
