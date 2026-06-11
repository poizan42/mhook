// proxy_main.c — MhookInjectProxyMain(): the body of the native x64 proxy used for
// 32-bit -> 64-bit injection.
//
// The 32-bit Mhook_Inject launcher spawns this proxy (see InjectViaProxy in
// mhook_inject.cpp) and hands over a shared section describing the injection request.
// The proxy is same-arch with the 64-bit target, so it simply reconstructs an x64
// MHOOK_INJECT_PARAMS and calls the ordinary same-arch Mhook_Inject, then publishes
// the result back through the section and signals the completion event.
//
// ntdll-only: no CRT, no kernel32.  See inject_proxy_params.h for the wire contract.

#include "../nt_defs.h"
#include "../mhook-inject/mhook_inject.h"
#include "../mhook-inject/inject_proxy_params.h"

#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif

// ---------------------------------------------------------------------------
// Minimal helpers (no CRT)
// ---------------------------------------------------------------------------

// Parse the trailing whitespace-delimited token of a UTF-16 command line as an
// unsigned hex value.  Returns FALSE if no token / no valid hex digits.
static BOOLEAN ParseTrailingHex(const WCHAR *buf, ULONG cch, ULONGLONG *out)
{
    if (!buf || cch == 0)
        return FALSE;

    // Trim trailing whitespace.
    ULONG end = cch;
    while (end > 0 && (buf[end - 1] == L' ' || buf[end - 1] == L'\t' ||
                       buf[end - 1] == L'\r' || buf[end - 1] == L'\n'))
        --end;
    if (end == 0)
        return FALSE;

    // Find the start of the last token.
    ULONG start = end;
    while (start > 0 && buf[start - 1] != L' ' && buf[start - 1] != L'\t')
        --start;

    ULONGLONG value = 0;
    BOOLEAN   any   = FALSE;
    for (ULONG i = start; i < end; ++i) {
        WCHAR c = buf[i];
        ULONG d;
        if (c >= L'0' && c <= L'9')      d = (ULONG)(c - L'0');
        else if (c >= L'a' && c <= L'f') d = (ULONG)(c - L'a') + 10u;
        else if (c >= L'A' && c <= L'F') d = (ULONG)(c - L'A') + 10u;
        else return FALSE;  // unexpected char inside the token
        value = (value << 4) | d;
        any = TRUE;
    }
    if (!any)
        return FALSE;
    *out = value;
    return TRUE;
}

// ---------------------------------------------------------------------------
// MhookInjectProxyMain — entry body.  Returns the HRESULT of the injection (or a
// failure HRESULT if the handover could not be parsed).
// ---------------------------------------------------------------------------

HRESULT __cdecl MhookInjectProxyMain(void)
{
    // 1. Read our own command line from the PEB.
    NT_PEB *peb = RtlCurrentPeb();
    if (!peb || !peb->ProcessParameters)
        return E_FAIL;
    PRTL_USER_PROCESS_PARAMETERS_CMDLINE pp =
        (PRTL_USER_PROCESS_PARAMETERS_CMDLINE)peb->ProcessParameters;

    const WCHAR *cmd    = pp->CommandLine.Buffer;
    ULONG        cmdcch = (ULONG)(pp->CommandLine.Length / sizeof(WCHAR));

    // 2. The inherited section handle is the trailing hex token.
    ULONGLONG secVal = 0;
    if (!ParseTrailingHex(cmd, cmdcch, &secVal) || secVal == 0)
        return E_INVALIDARG;
    HANDLE hSection = (HANDLE)(ULONG_PTR)secVal;

    // 3. Map the shared block.
    PVOID  base     = NULL;
    SIZE_T viewSize = 0;
    NTSTATUS st = NtMapViewOfSection(hSection, NtCurrentProcess(), &base, 0, 0,
                                     NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(st))
        return (HRESULT)((ULONG)st | 0x10000000u);  // FACILITY_NT_BIT

    volatile MHOOK_PROXY_BLOCK *blk = (volatile MHOOK_PROXY_BLOCK *)base;
    if (blk->Magic != MHOOK_PROXY_MAGIC || blk->Version != MHOOK_PROXY_VERSION ||
        blk->BlockSize < sizeof(MHOOK_PROXY_BLOCK) || (SIZE_T)blk->BlockSize > viewSize) {
        NtUnmapViewOfSection(NtCurrentProcess(), base);
        return E_INVALIDARG;
    }
    blk->ProxyState = MHOOK_PROXY_STATE_PARSED;

    HANDLE hEvent  = (HANDLE)(ULONG_PTR)blk->EventHandle;

    // 4. Reconstruct an x64 MHOOK_INJECT_PARAMS.  The variable data lives in the
    //    mapped section (valid for the whole call), and all paths are absolute, so we
    //    can point straight at it.
    BYTE *bytes = (BYTE *)base;
    MHOOK_INJECT_PARAMS p;
    // zero-init without memset dependency
    for (SIZE_T i = 0; i < sizeof(p); ++i) ((BYTE *)&p)[i] = 0;
    p.Size          = sizeof(p);
    p.Flags         = blk->Flags & MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;  // never ASYNC
    p.TargetProcess = (HANDLE)(ULONG_PTR)blk->TargetHandle;
    p.DllPath       = (PCWSTR)(bytes + blk->DllPathOff);
    p.FunctionName  = (PCSTR)(bytes + blk->FuncNameOff);
    p.MhookDllPath  = blk->MhookPathLen ? (PCWSTR)(bytes + blk->MhookPathOff) : NULL;
    p.UserData      = blk->UserDataLen ? (PVOID)(bytes + blk->UserDataOff) : NULL;
    p.UserDataSize  = blk->UserDataLen;
    p.TimeoutMs     = INFINITE;   // the launcher owns the timeout; the proxy waits out the inject
    p.ProxyPath     = NULL;

    blk->ProxyState = MHOOK_PROXY_STATE_INJECT_CALLED;

    // 5. Perform the same-arch (64->64) injection.
    HRESULT hr = Mhook_Inject(&p);

    // 6. Publish the result, then signal completion.  Ordering matters: ResultHr and
    //    ResultStatus before ProxyState=DONE, and all of them before NtSetEvent (the
    //    event signal is the synchronizing edge the launcher waits on).  blk is
    //    volatile (ordered stores under MSVC's default /volatile:ms), and NtSetEvent is
    //    an opaque call the compiler cannot reorder the stores past.
    blk->ResultHr     = (LONG)hr;
    blk->ResultStatus = 0;
    blk->ProxyState   = MHOOK_PROXY_STATE_DONE;
    if (hEvent)
        NtSetEvent(hEvent, NULL);

    NtUnmapViewOfSection(NtCurrentProcess(), base);
    return hr;
}
