// inject_entry.c — code that runs inside the target process.
//
// _internal_Execute is called by the shellcode after the companion DLL
// (and, for dynamic builds, mhook.dll) has been loaded.  It resolves the
// user-supplied injection function, builds a MhookInjectContext, calls the
// function, and resumes all suspended threads.
//
// Only ntdll.dll is imported.

#include "../nt_defs.h"
#include "inject_params.h"

#ifndef MHOOK_INJECT_DYNAMIC
#include "../mhook-lib/mhook.h"
#endif

// ---------------------------------------------------------------------------
// IsProcessInitialized — check whether loader initialisation is complete
// ---------------------------------------------------------------------------
//
// PEB_LDR_DATA.Initialized is set to TRUE by the Windows loader after all
// import DLLs have run DLL_PROCESS_ATTACH, immediately before the process
// entry point is called.  Once this returns TRUE, Win32 APIs are safe to use.
// It is safe to call from any thread, including one injected before the main
// thread has started.

static BOOLEAN IsProcessInitialized(void)
{
    NT_PEB *peb = RtlCurrentPeb();
    if (!peb || !peb->Ldr) return FALSE;
    return ((PEB_LDR_DATA_MIN *)peb->Ldr)->Initialized;
}

// ---------------------------------------------------------------------------
// ResumeOtherThreads — resume every thread in this process except the caller
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
// _internal_Execute — called by the shellcode
//
// pParams points to the MHOOK_INJECT_REMOTE_PARAMS block in the remote
// allocation.  The function resolves the user's injection function, builds
// a MhookInjectContext on the stack, calls the function, and resumes threads.
// ---------------------------------------------------------------------------

NTSTATUS __cdecl _internal_Execute(MHOOK_INJECT_REMOTE_PARAMS *pParams)
{
    // --- Resolve the target function ---
    PVOID  pTargetFunc = NULL;
    HANDLE hTargetDll  = pParams->CompanionHandle;

    // For dynamic builds the user's DLL may be separate from the companion;
    // load it if a path was supplied.
    if (pParams->TargetDllPath.Length > 0) {
        UNICODE_STRING targetPath = pParams->TargetDllPath;
        LdrLoadDll(NULL, NULL, &targetPath, &hTargetDll);
    }

    if (pParams->FunctionRva != 0) {
        // FunctionPointer form: base + RVA
        pTargetFunc = (PVOID)((ULONG_PTR)hTargetDll + pParams->FunctionRva);
    } else if (pParams->FunctionName.Length > 0) {
        // DllPath+FunctionName form: look up by name
        ANSI_STRING fn = pParams->FunctionName;
        LdrGetProcedureAddress(hTargetDll, &fn, 0, &pTargetFunc);
    }

    if (!pTargetFunc)
        goto done;

    // --- Resolve Mhook_SetHook / Mhook_Unhook ---
    MhookSetHookFn pSetHook = NULL;
    MhookUnhookFn  pUnhook  = NULL;
#ifdef MHOOK_INJECT_DYNAMIC
    if (pParams->MhookHandle) {
        static CHAR szSetHook[]  = "Mhook_SetHook";
        static CHAR szUnhook[]   = "Mhook_Unhook";
        ANSI_STRING as;

        as.Buffer        = szSetHook;
        as.Length        = sizeof(szSetHook) - 1;
        as.MaximumLength = sizeof(szSetHook);
        LdrGetProcedureAddress(pParams->MhookHandle, &as, 0, (PVOID *)&pSetHook);

        as.Buffer        = szUnhook;
        as.Length        = sizeof(szUnhook) - 1;
        as.MaximumLength = sizeof(szUnhook);
        LdrGetProcedureAddress(pParams->MhookHandle, &as, 0, (PVOID *)&pUnhook);
    }
#else
    pSetHook = Mhook_SetHook;
    pUnhook  = Mhook_Unhook;
#endif

    // --- Build the context and call the user's injection function ---
    {
        MHOOK_INJECT_CONTEXT ctx;
        ctx.Size         = sizeof(ctx);
        ctx.SetHook      = pSetHook;
        ctx.Unhook       = pUnhook;
        ctx.UserData     = pParams->UserData;
        ctx.UserDataSize = pParams->UserDataSize;

        ((MhookInjectedFn)pTargetFunc)(&ctx);

        pParams->InjectStatus = STATUS_SUCCESS;   // also set in-memory for cdb inspection
    }

done:
    ResumeOtherThreads();
    // Return the status as the thread exit code so Mhook_Inject can read it
    // via NtQueryInformationThread after the process has exited.
    return pParams->InjectStatus;
}
