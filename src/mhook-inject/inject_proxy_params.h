// inject_proxy_params.h — the documented, stable wire contract between the 32-bit
// Mhook_Inject launcher and the native x64 proxy executable used for 32-bit -> 64-bit
// injection (a WOW64 process has no ntdll-only way to create a 64-bit thread, so it
// delegates to a same-arch proxy).
//
// This contract is PUBLIC and versioned: a third party may implement their own proxy
// without linking the mhook libraries, as long as they honour the layout and protocol
// below.  It is also used by the bundled proxy (src/mhook_inject_proxy/).
//
// ===========================================================================
// PROTOCOL
// ===========================================================================
//
// 1. The launcher creates a page-file-backed section (shared memory) of BlockSize
//    bytes and maps it read/write.  It fills an MHOOK_PROXY_BLOCK at offset 0,
//    followed by the variable-length data (paths / function name / user data) that
//    the offset/length fields point at.
//
// 2. The launcher creates a manual-reset completion event and duplicates the target
//    process handle.  The section handle, the event handle and the target handle are
//    all made INHERITABLE (OBJ_INHERIT); the launcher then spawns the proxy with
//    InheritHandles=TRUE, so the proxy inherits all three at the SAME numeric values.
//    The event and target handle values are carried inside the block; only the SECTION
//    handle is passed on the command line (the proxy needs it before it can map the
//    block).
//
// 3. Proxy command line:
//        "<image path>" <sectionHandleHex>
//    The inherited section handle is the LAST whitespace-delimited token, written as
//    hex with no "0x" prefix (e.g. "1A4").  Parsing the last token (rather than a
//    fixed position) keeps it robust against spaces in the image path.  The proxy maps
//    that section, validates Magic/Version, and reads EventHandle / TargetHandle from
//    the block.  All paths inside the block are ABSOLUTE (the launcher resolves them
//    before serialising), so the proxy never depends on its own working directory.
//
// 4. The proxy performs the injection into TargetHandle (a same-arch 64->64 inject),
//    then writes ResultHr (and ResultStatus), publishes ProxyState = DONE, and signals
//    EventHandle.  MEMORY ORDERING: ResultHr/ResultStatus MUST be written before
//    ProxyState=DONE, and all three before NtSetEvent(EventHandle) — the event signal
//    is the synchronizing edge the launcher waits on.
//
// 5. The launcher waits on {EventHandle, proxyProcess} (bounded by TimeoutMs).  Event
//    signalled -> read ResultHr.  Proxy exited without signalling -> proxy crashed.
//
// All multi-byte fields are little-endian and the layout is identical for x86 and x64
// (only fixed-width ULONG/LONG/ULONGLONG, pack(1)), so the 32-bit launcher and the
// 64-bit proxy agree byte-for-byte.

#pragma once

#include <stddef.h>  // offsetof
#include "../nt_defs.h"

// Portable compile-time assert (this header is included from C11 and C++ TUs).
#ifdef __cplusplus
#define MHOOK_PROXY_SASSERT(c, m) static_assert(c, m)
#else
#define MHOOK_PROXY_SASSERT(c, m) _Static_assert(c, m)
#endif

// 'MPXY' as a little-endian ULONG ('M' is the lowest byte).
#define MHOOK_PROXY_MAGIC   ((ULONG)('M') | ((ULONG)'P' << 8) | ((ULONG)'X' << 16) | ((ULONG)'Y' << 24))
#define MHOOK_PROXY_VERSION 1u

// ProxyState — lets the launcher tell "proxy never got going" from "injection ran".
#define MHOOK_PROXY_STATE_INIT          0u  // launcher's initial value
#define MHOOK_PROXY_STATE_PARSED        1u  // proxy mapped + validated the block
#define MHOOK_PROXY_STATE_INJECT_CALLED 2u  // proxy is calling Mhook_Inject
#define MHOOK_PROXY_STATE_DONE          3u  // ResultHr is final

// ---------------------------------------------------------------------------
// MHOOK_PROXY_BLOCK — header at section offset 0; variable data follows it.
//
//   Offset  Size  Field
//      0      4    Magic            = MHOOK_PROXY_MAGIC
//      4      4    Version          = MHOOK_PROXY_VERSION
//      8      4    BlockSize        total section bytes (header + variable region)
//     12      4    Flags            MHOOK_INJECT_FLAG_* subset (DELAY_UNTIL_INIT only)
//     16      4    TimeoutMs        pass-through (informational; launcher owns the clock)
//     20      4    Reserved0        = 0
//     24      8    EventHandle      inherited completion event (proxy-valid handle value)
//     32      8    TargetHandle     inherited target process handle (proxy-valid)
//     40      4    DllPathOff       byte offset (from block base) of the x64 DLL path
//     44      4    DllPathLen       byte length incl. terminating NUL (UTF-16)
//     48      4    FuncNameOff      byte offset of the ANSI export name
//     52      4    FuncNameLen      byte length incl. terminating NUL (ANSI)
//     56      4    MhookPathOff     byte offset of the x64 mhook.dll path (0 if none)
//     60      4    MhookPathLen     byte length incl. terminating NUL (UTF-16), 0 if none
//     64      4    UserDataOff      byte offset of the user-data blob (0 if none)
//     68      4    UserDataLen      raw byte length of the user-data blob (0 if none)
//     72      4    ResultHr         OUT: final HRESULT from the proxy's Mhook_Inject
//     76      4    ResultStatus     OUT: raw NTSTATUS diagnostic (0 if N/A)
//     80      4    ProxyState       OUT: MHOOK_PROXY_STATE_*
//     84      4    Reserved1        = 0
//   sizeof = 88;  variable data region begins at offset 88 (8-byte aligned)
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _MHOOK_PROXY_BLOCK {
    ULONG     Magic;
    ULONG     Version;
    ULONG     BlockSize;
    ULONG     Flags;
    ULONG     TimeoutMs;
    ULONG     Reserved0;
    ULONGLONG EventHandle;
    ULONGLONG TargetHandle;
    ULONG     DllPathOff;
    ULONG     DllPathLen;
    ULONG     FuncNameOff;
    ULONG     FuncNameLen;
    ULONG     MhookPathOff;
    ULONG     MhookPathLen;
    ULONG     UserDataOff;
    ULONG     UserDataLen;
    LONG      ResultHr;
    LONG      ResultStatus;
    ULONG     ProxyState;
    ULONG     Reserved1;
} MHOOK_PROXY_BLOCK;
#pragma pack(pop)

// First aligned offset for the variable-data region.
#define MHOOK_PROXY_DATA_BASE 88u

MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, Magic)        ==  0, "Magic@0");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, Version)      ==  4, "Version@4");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, BlockSize)    ==  8, "BlockSize@8");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, Flags)        == 12, "Flags@12");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, TimeoutMs)    == 16, "TimeoutMs@16");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, EventHandle)  == 24, "EventHandle@24");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, TargetHandle) == 32, "TargetHandle@32");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, DllPathOff)   == 40, "DllPathOff@40");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, FuncNameOff)  == 48, "FuncNameOff@48");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, MhookPathOff) == 56, "MhookPathOff@56");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, UserDataOff)  == 64, "UserDataOff@64");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, ResultHr)     == 72, "ResultHr@72");
MHOOK_PROXY_SASSERT(offsetof(MHOOK_PROXY_BLOCK, ProxyState)   == 80, "ProxyState@80");
MHOOK_PROXY_SASSERT(sizeof(MHOOK_PROXY_BLOCK)                 == 88, "sizeof block == 88");
MHOOK_PROXY_SASSERT(sizeof(MHOOK_PROXY_BLOCK)                 == MHOOK_PROXY_DATA_BASE, "data base follows header");
