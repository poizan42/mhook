// inject.c — companion DLL for the uninitialized-process hook test.
//
// Loaded by shellcode injected into a suspended process before the main
// thread has executed a single instruction.  Imports only from ntdll.dll.
//
// Static configurations  (Debug, Release):       mhook statically linked.
// Dynamic configurations (DebugDynamic, ReleaseDynamic): mhook.dll handle
//                                                  received via hMhook param.

#include "../nt_defs.h"

#ifndef MHOOK_INJECT_DYNAMIC
#include "../mhook-lib/mhook.h"
#endif

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// mhook.h declares Mhook_SetHook/Unhook as EXTERN_C with no explicit calling
// convention, so they default to __cdecl — use a plain function pointer.
typedef BOOL (*MhookSetHookFn)(PVOID *ppSystemFunction, PVOID pHookFunction);
typedef BOOL (*MhookUnhookFn)(PVOID *ppHookedFunction);
typedef NTSTATUS (NTAPI *NtTerminateProcessFn)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

// ---------------------------------------------------------------------------
// Module-level state (zero-initialised by loader; no CRT init needed)
// ---------------------------------------------------------------------------

static MhookSetHookFn   g_SetHook;
static MhookUnhookFn    g_Unhook;
static NtTerminateProcessFn g_TrueNtTerminateProcess;
static volatile LONG    g_MarkerWritten;   // 0 = not yet written

// ---------------------------------------------------------------------------
// NtTerminateProcess hook
//
// Fires when cmd.exe exits.  Writes the test marker to stdout via a direct
// NtWriteFile call (no recursion risk), then calls through to the original.
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI HookNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    if (InterlockedCompareExchange(&g_MarkerWritten, 1, 0) == 0) {
        PRTL_USER_PROCESS_PARAMETERS_MIN procParams =
            (PRTL_USER_PROCESS_PARAMETERS_MIN)RtlCurrentPeb()->ProcessParameters;

        HANDLE hStdOut = procParams ? procParams->StandardOutput : NULL;

        if (hStdOut && hStdOut != INVALID_HANDLE_VALUE) {
            static char MARKER[] = "MHOOK_EARLY_HOOK_OK\n";
            IO_STATUS_BLOCK iosb;
            NtWriteFile(hStdOut, NULL, NULL, NULL, &iosb,
                        MARKER, sizeof(MARKER) - 1, NULL, NULL);
        }
    }
    return g_TrueNtTerminateProcess(ProcessHandle, ExitStatus);
}

// ---------------------------------------------------------------------------
// ResumeOtherThreads — resumes every thread in this process except the caller
// ---------------------------------------------------------------------------

static void ResumeOtherThreads(void)
{
    CLIENT_ID callerCid = NtCurrentClientId();
    HANDLE hPrev = NULL, hNext;

    while (NT_SUCCESS(NtGetNextThread(NtCurrentProcess(), hPrev,
            THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, 0, 0, &hNext)))
    {
        if (hPrev)
            NtClose(hPrev);
        hPrev = hNext;

        THREAD_BASIC_INFORMATION tbi;
        NtQueryInformationThread(hNext, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
        if (tbi.ClientId.UniqueThread != callerCid.UniqueThread)
            NtResumeThread(hNext, NULL);
    }
    if (hPrev)
        NtClose(hPrev);
}

// ---------------------------------------------------------------------------
// Execute — entry point called by the injected shellcode
//
// hMhook:  handle to loaded mhook.dll (dynamic builds only); NULL for static.
//
// Called __cdecl so the shellcode does not need to know how many bytes of
// argument to clean from the stack (on x86 the caller cleans).
// ---------------------------------------------------------------------------

void __cdecl Execute(HANDLE hMhook)
{
#ifdef MHOOK_INJECT_DYNAMIC
    // Resolve Mhook functions from the loaded mhook.dll handle.
    static CHAR szSetHook[]  = "Mhook_SetHook";
    static CHAR szUnhook[]   = "Mhook_Unhook";
    ANSI_STRING asSetHook, asUnhook;

    asSetHook.Buffer        = szSetHook;
    asSetHook.Length        = sizeof(szSetHook) - 1;
    asSetHook.MaximumLength = sizeof(szSetHook);

    asUnhook.Buffer        = szUnhook;
    asUnhook.Length        = sizeof(szUnhook) - 1;
    asUnhook.MaximumLength = sizeof(szUnhook);

    LdrGetProcedureAddress(hMhook, &asSetHook, 0, (PVOID *)&g_SetHook);
    LdrGetProcedureAddress(hMhook, &asUnhook,  0, (PVOID *)&g_Unhook);
#else
    (void)hMhook;
    g_SetHook = Mhook_SetHook;
    g_Unhook  = Mhook_Unhook;
#endif

    if (!g_SetHook || !g_Unhook)
        return;

    // Install hook on NtTerminateProcess.
    g_TrueNtTerminateProcess = NtTerminateProcess;
    g_SetHook((PVOID *)&g_TrueNtTerminateProcess, HookNtTerminateProcess);

    // Resume all other threads so the process continues normally.
    ResumeOtherThreads();
}
