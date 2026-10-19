// VpnWfpCallout.sys — WFP redirect callout (full implementation).
//
// Mirrors ProxifierDrv.sys as observed via REA:
//   FwpsCalloutRegister1 + Fwpm{EngineOpen,ProviderAdd,SubLayerAdd,
//   CalloutAdd,FilterAdd}, FwpsRedirectHandleCreate,
//   FwpsAcquireWritableLayerDataPointer / FwpsApplyModifiedLayerData,
//   FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, FWPS_LAYER_DATAGRAM_DATA_V4,
//   FWPS_METADATA_FIELD_PROCESS_ID, FLOW_HANDLE, INJECTED_BY_SELF guard,
//   PendClassify + abandoned-request guard.
//
// Data plane:
//   TCP (connected + unconnected via CONNECT_REDIRECT): allowlisted PID
//     -> rewrite remote to 127.0.0.1:P_local, stash {dst,pid} in flow
//     table keyed by redirect flowContext + localPort for QUERY.
//   UDP (DATAGRAM_DATA outbound): allowlisted PID -> BLOCK original and
//     forward payload to user-mode relay via inversion (Phase 2b); until
//     the inversion channel lands, UDP is redirected by rewriting the
//     datagram remote to loopback (same port) so unconnected sendto()
//     still reaches redirect_listener without NBL surgery.
//
// Build: WDK 10.0.22621+ + VS2022, WDM Empty template.
// Sign: attestation for prod (Secure Boot/HVCI); testsigning for dev.

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <guiddef.h>
#include <dontuse.h>
#include "ioctl.h"

// --- GUIDs (run uuidgen before first signing, keep stable after) ---
static const GUID VPN_WFP_PROVIDER_GUID =
    { 0x7c2e9e10, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 } };
static const GUID VPN_WFP_SUBLAYER_GUID =
    { 0x7c2e9e11, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x78 } };
static const GUID VPN_WFP_CALLOUT_REDIRECT_V4_GUID =
    { 0x7c2e9e12, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x79 } };
static const GUID VPN_WFP_CALLOUT_REDIRECT_V6_GUID =
    { 0x7c2e9e14, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x7b } };
static const GUID VPN_WFP_CALLOUT_DATAGRAM_V4_GUID =
    { 0x7c2e9e13, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x7a } };
// Filter GUIDs (for FwpmFilterDelete on unload).
static const GUID VPN_WFP_FILTER_REDIRECT_V4_GUID =
    { 0x7c2e9e20, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x80 } };
static const GUID VPN_WFP_FILTER_REDIRECT_V6_GUID =
    { 0x7c2e9e21, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x81 } };
static const GUID VPN_WFP_FILTER_DATAGRAM_V4_GUID =
    { 0x7c2e9e22, 0x4a1b, 0x4e2a, { 0x9c, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x82 } };

// --- state ---
static PDEVICE_OBJECT g_ControlDevice = NULL;
static HANDLE g_RedirectHandleV4 = NULL;
static HANDLE g_RedirectHandleV6 = NULL;
static HANDLE g_InjectionTransportHandleV4 = NULL;
static HANDLE g_EngineHandle = NULL;
static UINT32 g_CalloutRedirectV4Id = 0;
static UINT32 g_CalloutRedirectV6Id = 0;
static UINT32 g_CalloutDatagramV4Id = 0;

// Loopback target from user-mode (IOCTL_SET_REDIRECT_TARGET).
// TCP and UDP share the SAME numeric port: the relay binds TCP 127.0.0.1:P
// then binds UDP 127.0.0.1:P (same P, different protocol — allowed on
// Windows). One publish therefore serves both. g_UdpRelayPortV4 is kept
// as an alias for readability; SET writes both to the same value.
static volatile LONG g_RedirectPortV4 = 0;
static volatile LONG g_UdpRelayPortV4 = 0;

// Allowlist: full snapshot replace (<=512 PIDs, fits one METHOD_BUFFERED).
#define VPN_WFP_MAX_ALLOWLIST 2048
static UINT32 g_Allowlist[VPN_WFP_MAX_ALLOWLIST];
static volatile LONG g_AllowlistCount = 0;
static KSPIN_LOCK g_AllowlistLock;

// Flow table: (srcPort,proto) -> {dstIp, dstPort, pid}. 2048 slots.
// TCP and UDP port spaces are independent, so the same numeric port can
// coexist — key MUST include IPPROTO or TCP+UDP alias and misroute.
// Tombstones: Valid 0=empty (stop probe), 1=occupied, 2=deleted.
#define VPN_WFP_FLOW_TABLE_SIZE 2048
#define VPN_WFP_ENTRY_EMPTY 0
#define VPN_WFP_ENTRY_LIVE 1
#define VPN_WFP_ENTRY_DEAD 2
typedef struct _VPN_WFP_FLOW_ENTRY {
    volatile LONG Valid; // EMPTY/LIVE/DEAD via Interlocked
    UINT16 LocalPort;    // host order (app src port, preserved across redirect)
    UINT8 Proto;         // IPPROTO_TCP(6)/UDP(17), 0=unknown (legacy)
    UINT8 Reserved2;
    UINT32 DstIp;        // network order
    UINT16 DstPort;      // host order
    UINT32 Pid;
} VPN_WFP_FLOW_ENTRY;
static VPN_WFP_FLOW_ENTRY g_FlowTable[VPN_WFP_FLOW_TABLE_SIZE];
static KSPIN_LOCK g_FlowLock;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD VpnWfpUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH VpnWfpDispatch;

// Forward decls for WFP callbacks.
void NTAPI VpnWfpClassifyRedirectV4(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut);
void NTAPI VpnWfpClassifyRedirectV6(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut);
void NTAPI VpnWfpClassifyDatagramV4(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut);
NTSTATUS NTAPI VpnWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER *filter);
void NTAPI VpnWfpFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext);

static BOOLEAN VpnWfpIsPidAllowed(UINT32 pid)
{
    LONG count = g_AllowlistCount;
    if (count <= 0 || count > VPN_WFP_MAX_ALLOWLIST) {
        return FALSE;
    }
    KIRQL irql;
    KeAcquireSpinLock(&g_AllowlistLock, &irql);
    BOOLEAN found = FALSE;
    for (LONG i = 0; i < count; i++) {
        if (g_Allowlist[i] == pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_AllowlistLock, irql);
    return found;
}

static UINT32 VpnWfpHashKey(UINT16 port, UINT8 proto)
{
    return (((UINT32)port * 2654435761u) ^ ((UINT32)proto * 2246822519u)) % VPN_WFP_FLOW_TABLE_SIZE;
}

static void VpnWfpFlowInsert(UINT16 localPort, UINT8 proto, UINT32 dstIp, UINT16 dstPort, UINT32 pid)
{
    if (localPort == 0) return;
    if (proto == 0) proto = IPPROTO_TCP; // legacy callers without proto
    UINT32 idx = VpnWfpHashKey(localPort, proto);
    KIRQL irql;
    KeAcquireSpinLock(&g_FlowLock, &irql);
    INT firstDead = -1;
    for (UINT32 n = 0; n < VPN_WFP_FLOW_TABLE_SIZE; n++) {
        UINT32 i = (idx + n) % VPN_WFP_FLOW_TABLE_SIZE;
        LONG v = g_FlowTable[i].Valid;
        if (v == VPN_WFP_ENTRY_LIVE && g_FlowTable[i].LocalPort == localPort && g_FlowTable[i].Proto == proto) {
            g_FlowTable[i].DstIp = dstIp;
            g_FlowTable[i].DstPort = dstPort;
            g_FlowTable[i].Pid = pid;
            KeReleaseSpinLock(&g_FlowLock, irql);
            return;
        }
        if (v == VPN_WFP_ENTRY_DEAD && firstDead < 0) firstDead = (INT)i;
        if (v == VPN_WFP_ENTRY_EMPTY) {
            UINT32 slot = (firstDead >= 0) ? (UINT32)firstDead : i;
            g_FlowTable[slot].LocalPort = localPort;
            g_FlowTable[slot].Proto = proto;
            g_FlowTable[slot].DstIp = dstIp;
            g_FlowTable[slot].DstPort = dstPort;
            g_FlowTable[slot].Pid = pid;
            InterlockedExchange(&g_FlowTable[slot].Valid, VPN_WFP_ENTRY_LIVE);
            KeReleaseSpinLock(&g_FlowLock, irql);
            return;
        }
    }
    // Table full with no EMPTY: reuse first DEAD if any (avoids silent drop).
    if (firstDead >= 0) {
        UINT32 slot = (UINT32)firstDead;
        g_FlowTable[slot].LocalPort = localPort;
        g_FlowTable[slot].Proto = proto;
        g_FlowTable[slot].DstIp = dstIp;
        g_FlowTable[slot].DstPort = dstPort;
        g_FlowTable[slot].Pid = pid;
        InterlockedExchange(&g_FlowTable[slot].Valid, VPN_WFP_ENTRY_LIVE);
    }
    // Else: table truly full — drop loudly (caller CONTINUEs fail-open).
    KeReleaseSpinLock(&g_FlowLock, irql);
}

static BOOLEAN VpnWfpFlowLookup(UINT16 localPort, UINT8 proto, UINT32 *dstIp, UINT16 *dstPort, UINT32 *pid)
{
    UINT32 idx = VpnWfpHashKey(localPort, proto ? proto : IPPROTO_TCP);
    KIRQL irql;
    KeAcquireSpinLock(&g_FlowLock, &irql);
    BOOLEAN found = FALSE;
    for (UINT32 n = 0; n < VPN_WFP_FLOW_TABLE_SIZE; n++) {
        UINT32 i = (idx + n) % VPN_WFP_FLOW_TABLE_SIZE;
        LONG v = g_FlowTable[i].Valid;
        if (v == VPN_WFP_ENTRY_EMPTY) break; // end of chain
        if (v == VPN_WFP_ENTRY_LIVE && g_FlowTable[i].LocalPort == localPort) {
            // proto==0 (legacy query) matches any; else exact match.
            if (proto != 0 && g_FlowTable[i].Proto != 0 && g_FlowTable[i].Proto != proto) continue;
            if (dstIp) *dstIp = g_FlowTable[i].DstIp;
            if (dstPort) *dstPort = g_FlowTable[i].DstPort;
            if (pid) *pid = g_FlowTable[i].Pid;
            found = TRUE;
            break;
        }
        // DEAD slots are skipped, not terminal.
    }
    KeReleaseSpinLock(&g_FlowLock, irql);
    return found;
}

static void VpnWfpFlowRemove(UINT16 localPort, UINT8 proto)
{
    UINT32 idx = VpnWfpHashKey(localPort, proto ? proto : IPPROTO_TCP);
    KIRQL irql;
    KeAcquireSpinLock(&g_FlowLock, &irql);
    for (UINT32 n = 0; n < VPN_WFP_FLOW_TABLE_SIZE; n++) {
        UINT32 i = (idx + n) % VPN_WFP_FLOW_TABLE_SIZE;
        LONG v = g_FlowTable[i].Valid;
        if (v == VPN_WFP_ENTRY_EMPTY) break;
        if (v == VPN_WFP_ENTRY_LIVE && g_FlowTable[i].LocalPort == localPort) {
            if (proto != 0 && g_FlowTable[i].Proto != 0 && g_FlowTable[i].Proto != proto) continue;
            InterlockedExchange(&g_FlowTable[i].Valid, VPN_WFP_ENTRY_DEAD);
            break;
        }
    }
    KeReleaseSpinLock(&g_FlowLock, irql);
}

static void VpnWfpFlowFlushAll(void)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_FlowLock, &irql);
    for (UINT32 i = 0; i < VPN_WFP_FLOW_TABLE_SIZE; i++) {
        InterlockedExchange(&g_FlowTable[i].Valid, VPN_WFP_ENTRY_EMPTY);
    }
    KeReleaseSpinLock(&g_FlowLock, irql);
}

NTSTATUS
VpnWfpDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    case IRP_MJ_DEVICE_CONTROL: {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buf = Irp->AssociatedIrp.SystemBuffer;
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case VPN_WFP_IOCTL_FLUSH_FLOWS:
            VpnWfpFlowFlushAll();
            break;
        case VPN_WFP_IOCTL_SET_REDIRECT_TARGET: {
            if (inLen < sizeof(VPN_WFP_REDIRECT_TARGET)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            VPN_WFP_REDIRECT_TARGET *t = (VPN_WFP_REDIRECT_TARGET *)buf;
            if (t->LoopbackIp != 0x0100007F || t->LoopbackPort == 0) { status = STATUS_INVALID_PARAMETER; break; }
            // Single shared numeric port for TCP+UDP (separate sockets may
            // bind the same port number on different protocols). The relay
            // binds TCP 127.0.0.1:P then UDP 127.0.0.1:P and publishes P once.
            InterlockedExchange(&g_RedirectPortV4, (LONG)t->LoopbackPort);
            InterlockedExchange(&g_UdpRelayPortV4, (LONG)t->LoopbackPort);
            break;
        }
        case VPN_WFP_IOCTL_SET_PID_ALLOWLIST: {
            if (inLen < sizeof(UINT32)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            if (inLen > sizeof(VPN_WFP_ALLOWLIST_PUSH)) { status = STATUS_INVALID_PARAMETER; break; }
            VPN_WFP_ALLOWLIST_PUSH *p = (VPN_WFP_ALLOWLIST_PUSH *)buf;
            if (p->Count > VPN_WFP_MAX_PIDS_PER_PUSH) { status = STATUS_INVALID_PARAMETER; break; }
            if (inLen < sizeof(UINT32) + p->Count * sizeof(UINT32)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            KIRQL irql;
            KeAcquireSpinLock(&g_AllowlistLock, &irql);
            LONG n = (LONG)p->Count;
            if (n > VPN_WFP_MAX_ALLOWLIST) n = VPN_WFP_MAX_ALLOWLIST;
            for (LONG i = 0; i < n; i++) g_Allowlist[i] = p->Pids[i];
            InterlockedExchange(&g_AllowlistCount, n);
            KeReleaseSpinLock(&g_AllowlistLock, irql);
            break;
        }
        case VPN_WFP_IOCTL_QUERY_ORIGINAL_DST: {
            if (inLen < sizeof(VPN_WFP_ORIGINAL_DST_QUERY)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            if (outLen < sizeof(VPN_WFP_ORIGINAL_DST_REPLY)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            VPN_WFP_ORIGINAL_DST_QUERY *q = (VPN_WFP_ORIGINAL_DST_QUERY *)buf;
            VPN_WFP_ORIGINAL_DST_REPLY *r = (VPN_WFP_ORIGINAL_DST_REPLY *)buf;
            // Reserved low byte carries IPPROTO (6/17); 0 = legacy wildcard.
            UINT8 proto = (UINT8)(q->Reserved & 0xFF);
            if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) proto = 0;
            UINT32 dstIp = 0; UINT16 dstPort = 0; UINT32 pid = 0;
            if (!VpnWfpFlowLookup(q->LocalPort, proto, &dstIp, &dstPort, &pid)) { status = STATUS_NOT_FOUND; break; }
            r->DstIp = dstIp; r->DstPort = dstPort; r->Pid = pid;
            info = sizeof(VPN_WFP_ORIGINAL_DST_REPLY);
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Helper: rewrite IPv4 connect-request remote to 127.0.0.1:port.
// Returns original dst via out params. FALSE = continue unmodified.
static BOOLEAN VpnWfpRewriteConnectV4(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _Inout_ FWPS_CONNECT_REQUEST *req,
    _Out_ UINT32 *origIp,
    _Out_ UINT16 *origPort)
{
    if (!req || !req->remoteAddrAndPort) return FALSE;
    SOCKADDR_IN *remote = (SOCKADDR_IN *)req->remoteAddrAndPort;
    if (remote->sin_family != AF_INET) return FALSE;
    // Skip loopback (our own reinjection target) + DNS bypass ports.
    UINT32 ipBE = remote->sin_addr.S_un.S_addr; // network order
    UINT16 portBE = remote->sin_port;
    UINT16 port = _byteswap_ushort(portBE);
    if ((ipBE & 0xFF) == 0x7F) return FALSE; // 127/8
    if (port == 53 || port == 5353 || port == 5355) return FALSE;
    // Protocol gate: only TCP/UDP (mirrors Proxifier log strings).
    UINT16 ipProto = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
    if (ipProto != IPPROTO_TCP && ipProto != IPPROTO_UDP) return FALSE;

    LONG redir = g_RedirectPortV4;
    if (redir <= 0 || redir > 65535) return FALSE;

    *origIp = ipBE;
    *origPort = port;
    remote->sin_addr.S_un.S_addr = 0x0100007F; // 127.0.0.1 BE
    remote->sin_port = _byteswap_ushort((UINT16)redir);
    return TRUE;
}

void NTAPI
VpnWfpClassifyRedirectV4(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    if (inMetaValues->packetInjectionState == FWPS_PACKET_INJECTED_BY_SELF ||
        inMetaValues->packetInjectionState == FWPS_PACKET_INJECTED_BY_OTHER) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    UINT32 pid = (UINT32)inMetaValues->processId;
    if (pid == 0 || pid == 4) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }
    if (!VpnWfpIsPidAllowed(pid)) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }

    FWPS_CONNECT_REQUEST *req = (FWPS_CONNECT_REQUEST *)layerData;
    if (!req) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }

    UINT32 origIp = 0; UINT16 origPort = 0;
    if (!VpnWfpRewriteConnectV4(inFixedValues, req, &origIp, &origPort)) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    // Key the flow table by the app's SOURCE port (known at REDIRECT time
    // via IP_LOCAL_PORT). The user-mode relay recovers it as the peer port
    // of the accepted 127.0.0.1 socket (source preserved across redirect),
    // then QUERY_ORIGINAL_DST(srcPort) -> {dst,pid}. This multiplexes many
    // concurrent connects onto one loopback listener port.
    UINT16 srcPort = (UINT16)inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT16 ipProto = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
    UINT8 protoKey = (ipProto == IPPROTO_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
    UINT16 key = srcPort ? srcPort : (UINT16)((flowContext ^ origPort ^ (origIp & 0xFFFF)) & 0xFFFF);
    if (key == 0) key = origPort;
    VpnWfpFlowInsert(key, protoKey, origIp, origPort, pid);
    // NOTE: no FwpsFlowAssociateContext here by design. The srcPort-keyed
    // table is lifecycle-bounded by (a) port-reuse overwrite on insert,
    // (b) FlowDelete -> VpnWfpFlowRemove is not possible (REDIRECT
    // flowContext is not the ESTABLISHED key), so we rely on (c) explicit
    // FLUSH on VPN down/rotate from user-mode + eventual overwrite.
    // This avoids the classic leak (ExAllocate per flow never freed) and
    // the wrong-layer/hardcoded-calloutId bug. See VpnWfpFlowDelete below.
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

void NTAPI
VpnWfpClassifyRedirectV6(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(inMetaValues);
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    // Phase 2: IPv6 redirect mirrors V4 (loopback ::1). Disabled until
    // redirector gains IPv6 bridge parity (currently IPv4-only by design).
    classifyOut->actionType = FWP_ACTION_CONTINUE;
}

void NTAPI
VpnWfpClassifyDatagramV4(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    if (inMetaValues->packetInjectionState == FWPS_PACKET_INJECTED_BY_SELF ||
        inMetaValues->packetInjectionState == FWPS_PACKET_INJECTED_BY_OTHER) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    UINT32 pid = (UINT32)inMetaValues->processId;
    if (!VpnWfpIsPidAllowed(pid)) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }

    UINT16 ipProto = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;
    if (ipProto != IPPROTO_UDP) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
    if (remotePort == 53 || remotePort == 5353 || remotePort == 5355) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    LONG udpPort = g_UdpRelayPortV4 ? g_UdpRelayPortV4 : g_RedirectPortV4;
    if (udpPort <= 0) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }
    // Fail-closed for tunneled unconnected UDP: without NBL rewrite the
    // datagram would egress via the default route (leak). Connected UDP
    // already went through REDIRECT_V4 (remote rewritten to loopback), and
    // the relay's own sockets run under redirector.exe (not allowlisted),
    // so BLOCK here only stops the leaking original path. Record the flow
    // first for QUERY diagnostics, then BLOCK.
    // Loopback (relay traffic) always CONTINUEs.
    {
        UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
        UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
        if ((remoteIp & 0xFF) == 0x7F) { classifyOut->actionType = FWP_ACTION_CONTINUE; return; }
        // Only record a trustworthy key. This layer has no valid flowContext
        // (association happens at the REDIRECT layer for connected UDP, and
        // this datagram filter has none of its own), so the old
        // `localPort ? localPort : flowContext & 0xFFFF` fallback could
        // insert a port-0/garbage entry. FlowInsert is diagnostics-only
        // (QUERY path); skipping it never changes the BLOCK decision.
        if (localPort) VpnWfpFlowInsert(localPort, IPPROTO_UDP, remoteIp, remotePort, pid);
    }
    UNREFERENCED_PARAMETER(layerData);
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

NTSTATUS NTAPI
VpnWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

void NTAPI
VpnWfpFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
    // No per-flow pool to free (see ClassifyRedirectV4: associate removed
    // by design). Table entries live until port reuse overwrite or explicit
    // FLUSH from user-mode on VPN down/rotate. Keeping FlowDelete as a
    // no-op avoids the prior bug (hardcoded calloutId 0x7c2e9e13 + wrong
    // ESTABLISHED layer + leaked ExAllocate per TCP).
}

static void VpnWfpCleanupEngine(void)
{
    if (!g_EngineHandle) return;
    // Best-effort teardown in reverse order; ignore NOT_FOUND (already gone).
    FwpmFilterDeleteByKey0(g_EngineHandle, &VPN_WFP_FILTER_REDIRECT_V4_GUID);
    FwpmFilterDeleteByKey0(g_EngineHandle, &VPN_WFP_FILTER_REDIRECT_V6_GUID);
    FwpmFilterDeleteByKey0(g_EngineHandle, &VPN_WFP_FILTER_DATAGRAM_V4_GUID);
    FwpmCalloutDeleteByKey0(g_EngineHandle, &VPN_WFP_CALLOUT_REDIRECT_V4_GUID);
    FwpmCalloutDeleteByKey0(g_EngineHandle, &VPN_WFP_CALLOUT_REDIRECT_V6_GUID);
    FwpmCalloutDeleteByKey0(g_EngineHandle, &VPN_WFP_CALLOUT_DATAGRAM_V4_GUID);
    FwpmSubLayerDeleteByKey0(g_EngineHandle, &VPN_WFP_SUBLAYER_GUID);
    FwpmProviderDeleteByKey0(g_EngineHandle, &VPN_WFP_PROVIDER_GUID);
    FwpmEngineClose0(g_EngineHandle);
    g_EngineHandle = NULL;
}

static NTSTATUS VpnWfpSetupEngine(void)
{
    NTSTATUS status;
    FWPM_SESSION session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) goto fail;

    // Provider + sublayer (persistent, weight max for redirect priority).
    {
        FWPM_PROVIDER provider = { 0 };
        provider.providerKey = VPN_WFP_PROVIDER_GUID;
        provider.displayData.name = L"VpnWfpCallout Provider";
        provider.displayData.description = L"Split-tunnel redirect provider";
        status = FwpmProviderAdd0(g_EngineHandle, &provider, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    {
        FWPM_SUBLAYER sub = { 0 };
        sub.subLayerKey = VPN_WFP_SUBLAYER_GUID;
        sub.displayData.name = L"VpnWfpCallout Sublayer";
        sub.displayData.description = L"Redirect sublayer (weight max)";
        sub.providerKey = (GUID *)&VPN_WFP_PROVIDER_GUID;
        sub.weight = 0xFFFF;
        status = FwpmSubLayerAdd0(g_EngineHandle, &sub, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    // Callouts.
    {
        FWPM_CALLOUT c = { 0 };
        c.calloutKey = VPN_WFP_CALLOUT_REDIRECT_V4_GUID;
        c.displayData.name = L"VpnWfp Redirect V4";
        c.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
        status = FwpmCalloutAdd0(g_EngineHandle, &c, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    {
        FWPM_CALLOUT c = { 0 };
        c.calloutKey = VPN_WFP_CALLOUT_REDIRECT_V6_GUID;
        c.displayData.name = L"VpnWfp Redirect V6";
        c.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
        status = FwpmCalloutAdd0(g_EngineHandle, &c, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    {
        FWPM_CALLOUT c = { 0 };
        c.calloutKey = VPN_WFP_CALLOUT_DATAGRAM_V4_GUID;
        c.displayData.name = L"VpnWfp Datagram V4";
        c.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
        status = FwpmCalloutAdd0(g_EngineHandle, &c, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    // Filters: redirect V4/V6 at max weight, datagram outbound only.
    {
        FWPM_FILTER f = { 0 };
        f.filterKey = VPN_WFP_FILTER_REDIRECT_V4_GUID;
        f.displayData.name = L"VpnWfp Filter Redirect V4";
        f.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
        f.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        f.action.calloutKey = VPN_WFP_CALLOUT_REDIRECT_V4_GUID;
        f.subLayerKey = VPN_WFP_SUBLAYER_GUID;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 0xFF;
        f.numFilterConditions = 0;
        status = FwpmFilterAdd0(g_EngineHandle, &f, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    {
        FWPM_FILTER f = { 0 };
        f.filterKey = VPN_WFP_FILTER_REDIRECT_V6_GUID;
        f.displayData.name = L"VpnWfp Filter Redirect V6";
        f.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
        f.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        f.action.calloutKey = VPN_WFP_CALLOUT_REDIRECT_V6_GUID;
        f.subLayerKey = VPN_WFP_SUBLAYER_GUID;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 0xFF;
        f.numFilterConditions = 0;
        status = FwpmFilterAdd0(g_EngineHandle, &f, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }
    {
        FWPM_FILTER f = { 0 };
        FWPM_FILTER_CONDITION cond = { 0 };
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond.matchType = FWP_MATCH_NOT_EQUAL;
        cond.conditionValue.type = FWP_UINT16;
        cond.conditionValue.uint16 = 53; // DNS bypass (TCP+UDP 53 handled in classify too)
        f.filterKey = VPN_WFP_FILTER_DATAGRAM_V4_GUID;
        f.displayData.name = L"VpnWfp Filter Datagram V4";
        f.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
        f.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        f.action.calloutKey = VPN_WFP_CALLOUT_DATAGRAM_V4_GUID;
        f.subLayerKey = VPN_WFP_SUBLAYER_GUID;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 0xFE;
        f.numFilterConditions = 1;
        f.filterCondition = &cond;
        status = FwpmFilterAdd0(g_EngineHandle, &f, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) goto abort;
    }

    status = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(status)) goto fail;
    return STATUS_SUCCESS;

abort:
    FwpmTransactionAbort0(g_EngineHandle);
fail:
    VpnWfpCleanupEngine();
    return status;
}

VOID
VpnWfpUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    VpnWfpCleanupEngine();
    if (g_CalloutRedirectV4Id) { FwpsCalloutUnregisterById(g_CalloutRedirectV4Id); g_CalloutRedirectV4Id = 0; }
    if (g_CalloutRedirectV6Id) { FwpsCalloutUnregisterById(g_CalloutRedirectV6Id); g_CalloutRedirectV6Id = 0; }
    if (g_CalloutDatagramV4Id) { FwpsCalloutUnregisterById(g_CalloutDatagramV4Id); g_CalloutDatagramV4Id = 0; }
    if (g_RedirectHandleV4) { FwpsRedirectHandleDestroy(g_RedirectHandleV4); g_RedirectHandleV4 = NULL; }
    if (g_RedirectHandleV6) { FwpsRedirectHandleDestroy(g_RedirectHandleV6); g_RedirectHandleV6 = NULL; }
    if (g_InjectionTransportHandleV4) { FwpsInjectionHandleDestroy(g_InjectionTransportHandleV4); g_InjectionTransportHandleV4 = NULL; }
    if (g_ControlDevice) {
        UNICODE_STRING symLink;
        RtlInitUnicodeString(&symLink, VPN_WFP_DOS_DEVICE_NAME);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING devName, symLink, sddl;

    KeInitializeSpinLock(&g_AllowlistLock);
    KeInitializeSpinLock(&g_FlowLock);
    RtlZeroMemory(g_FlowTable, sizeof(g_FlowTable));

    RtlInitUnicodeString(&devName, L"\\Device\\VpnWfpCallout");
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(DriverObject, 0, &devName,
                            FILE_DEVICE_VPN_WFP, 0, FALSE,
                            &sddl, NULL, &g_ControlDevice);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&symLink, VPN_WFP_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_ControlDevice); g_ControlDevice = NULL; return status; }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) DriverObject->MajorFunction[i] = VpnWfpDispatch;
    DriverObject->DriverUnload = VpnWfpUnload;

    // Kernel callout registration (must precede FwpmCalloutAdd).
    {
        FWPS_CALLOUT sCallout = { 0 };
        sCallout.calloutKey = VPN_WFP_CALLOUT_REDIRECT_V4_GUID;
        sCallout.classifyFn = VpnWfpClassifyRedirectV4;
        sCallout.notifyFn = VpnWfpNotify;
        sCallout.flowDeleteFn = VpnWfpFlowDelete;
        status = FwpsCalloutRegister1(g_ControlDevice, &sCallout, &g_CalloutRedirectV4Id);
        if (!NT_SUCCESS(status)) goto fail_device;
    }
    {
        FWPS_CALLOUT sCallout = { 0 };
        sCallout.calloutKey = VPN_WFP_CALLOUT_REDIRECT_V6_GUID;
        sCallout.classifyFn = VpnWfpClassifyRedirectV6;
        sCallout.notifyFn = VpnWfpNotify;
        sCallout.flowDeleteFn = VpnWfpFlowDelete;
        status = FwpsCalloutRegister1(g_ControlDevice, &sCallout, &g_CalloutRedirectV6Id);
        if (!NT_SUCCESS(status)) goto fail_callouts;
    }
    {
        FWPS_CALLOUT sCallout = { 0 };
        sCallout.calloutKey = VPN_WFP_CALLOUT_DATAGRAM_V4_GUID;
        sCallout.classifyFn = VpnWfpClassifyDatagramV4;
        sCallout.notifyFn = VpnWfpNotify;
        sCallout.flowDeleteFn = VpnWfpFlowDelete;
        status = FwpsCalloutRegister1(g_ControlDevice, &sCallout, &g_CalloutDatagramV4Id);
        if (!NT_SUCCESS(status)) goto fail_callouts;
    }

    status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_InjectionTransportHandleV4);
    if (!NT_SUCCESS(status)) goto fail_callouts;

    {
        GUID provider = VPN_WFP_PROVIDER_GUID;
        UNREFERENCED_PARAMETER(provider);
        status = FwpsRedirectHandleCreate0(&VPN_WFP_CALLOUT_REDIRECT_V4_GUID, 0, &g_RedirectHandleV4);
        if (!NT_SUCCESS(status)) goto fail_inject;
        status = FwpsRedirectHandleCreate0(&VPN_WFP_CALLOUT_REDIRECT_V6_GUID, 0, &g_RedirectHandleV6);
        if (!NT_SUCCESS(status)) goto fail_inject;
    }

    status = VpnWfpSetupEngine();
    if (!NT_SUCCESS(status)) goto fail_inject;

    return STATUS_SUCCESS;

fail_inject:
    if (g_InjectionTransportHandleV4) { FwpsInjectionHandleDestroy(g_InjectionTransportHandleV4); g_InjectionTransportHandleV4 = NULL; }
    if (g_RedirectHandleV4) { FwpsRedirectHandleDestroy(g_RedirectHandleV4); g_RedirectHandleV4 = NULL; }
    if (g_RedirectHandleV6) { FwpsRedirectHandleDestroy(g_RedirectHandleV6); g_RedirectHandleV6 = NULL; }
fail_callouts:
    if (g_CalloutRedirectV4Id) { FwpsCalloutUnregisterById(g_CalloutRedirectV4Id); g_CalloutRedirectV4Id = 0; }
    if (g_CalloutRedirectV6Id) { FwpsCalloutUnregisterById(g_CalloutRedirectV6Id); g_CalloutRedirectV6Id = 0; }
    if (g_CalloutDatagramV4Id) { FwpsCalloutUnregisterById(g_CalloutDatagramV4Id); g_CalloutDatagramV4Id = 0; }
fail_device:
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(g_ControlDevice);
    g_ControlDevice = NULL;
    return status;
}
