// companion.c — mhook_inject_test_companion
//
// Minimal injection companion for Mhook_Inject tests.  Loaded into the
// target process by Mhook_Inject; writes a known marker string to the
// process stdout and returns.  No hooks are installed.
//
// _internal_Execute (from mhook_inject.lib in static builds, or from
// mhook_inject.dll in dynamic builds) calls the target function and then
// resumes all suspended threads.
//
// Only ntdll.dll is required.

#include "../nt_defs.h"
#include "../mhook-inject/mhook_inject.h"

void __cdecl Inject_WriteMarkerAndResume(MHOOK_INJECT_CONTEXT *ctx)
{
    PRTL_USER_PROCESS_PARAMETERS_MIN pp =
        (PRTL_USER_PROCESS_PARAMETERS_MIN)RtlCurrentPeb()->ProcessParameters;
    HANDLE hOut = pp ? pp->StandardOutput : NULL;

    if (hOut && hOut != INVALID_HANDLE_VALUE) {
        static CHAR marker[] = "MHOOK_INJECT_OK\n";
        IO_STATUS_BLOCK iosb;
        NtWriteFile(hOut, NULL, NULL, NULL, &iosb,
                    marker, sizeof(marker) - 1, NULL, NULL);
    }

    (void)ctx;  // SetHook/Unhook not used in this test
}

// ---------------------------------------------------------------------------
// Inject_LoadWin32DllAndResume
//
// Locates mhook_inject_win32_test_companion.dll (which lives alongside this
// DLL in the test output directory), loads it using LdrLoadDll, and calls
// Inject_Win32MarkerAndResume from it via LdrGetProcedureAddress.
//
// This proves that a static companion (ntdll-only import table) can
// dynamically load and call a standard Win32 DLL at runtime — as long as
// the call happens after process initialisation (i.e. via the delay flag).
//
// The path buffer is heap-allocated to support the full UNICODE_STRING range.
// ---------------------------------------------------------------------------

void __cdecl Inject_LoadWin32DllAndResume(MHOOK_INJECT_CONTEXT *ctx)
{
    static const WCHAR kName[] = L"mhook_inject_win32_test_companion.dll";
    const USHORT kNameLen = (USHORT)(sizeof(kName)/sizeof(WCHAR) - 1);

    // Walk the PEB LDR to find the entry that contains this function, then
    // extract the directory path.
    USHORT dirLen = 0;
    WCHAR *dirBuf = NULL;

    NT_PEB *peb = RtlCurrentPeb();
    if (peb && peb->Ldr) {
        PEB_LDR_DATA_MIN *ldr = (PEB_LDR_DATA_MIN *)peb->Ldr;
        LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
        LIST_ENTRY *cur  = head->Flink;
        while (cur != head) {
            LDR_DATA_TABLE_ENTRY_MIN *e =
                CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_MIN, InMemoryOrderLinks);
            if ((ULONG_PTR)&Inject_LoadWin32DllAndResume >= (ULONG_PTR)e->DllBase &&
                (ULONG_PTR)&Inject_LoadWin32DllAndResume <
                    (ULONG_PTR)e->DllBase + e->SizeOfImage)
            {
                USHORT nchars = e->FullDllName.Length / sizeof(WCHAR);
                USHORT lastSlash = 0;
                USHORT i;
                for (i = 0; i < nchars; ++i)
                    if (e->FullDllName.Buffer[i] == L'\\') lastSlash = i + 1;
                dirLen = lastSlash;
                /* Allocate enough for directory + filename + null terminator */
                SIZE_T total = (SIZE_T)(dirLen + kNameLen + 1) * sizeof(WCHAR);
                dirBuf = (WCHAR *)RtlAllocateHeap(RtlProcessHeap(), 0, total);
                if (dirBuf) {
                    for (i = 0; i < dirLen; ++i)
                        dirBuf[i] = e->FullDllName.Buffer[i];
                }
                break;
            }
            cur = cur->Flink;
        }
    }

    if (!dirBuf) return;

    /* Append filename and null terminator */
    {
        USHORT i;
        for (i = 0; i < kNameLen; ++i)
            dirBuf[dirLen + i] = kName[i];
        dirBuf[dirLen + kNameLen] = 0;
    }

    UNICODE_STRING uPath;
    uPath.Buffer        = dirBuf;
    uPath.Length        = (USHORT)((dirLen + kNameLen) * sizeof(WCHAR));
    uPath.MaximumLength = uPath.Length + (USHORT)sizeof(WCHAR);

    HANDLE hDll = NULL;
    if (NT_SUCCESS(LdrLoadDll(NULL, NULL, &uPath, &hDll)) && hDll) {
        static CHAR kFn[] = "Inject_Win32MarkerAndResume";
        ANSI_STRING asFn;
        asFn.Buffer        = kFn;
        asFn.Length        = sizeof(kFn) - 1;
        asFn.MaximumLength = sizeof(kFn);
        PVOID pFn = NULL;
        if (NT_SUCCESS(LdrGetProcedureAddress(hDll, &asFn, 0, &pFn)) && pFn)
            ((MhookInjectedFn)pFn)(ctx);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, dirBuf);
}
