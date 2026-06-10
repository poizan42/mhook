// inject_entry.c — code that runs inside the target process.
//
// _internal_Execute is called by the bootstrap thunk after the companion DLL
// (and, for dynamic builds, mhook.dll) has been loaded.  It resolves the
// user-supplied injection function, builds a MhookInjectContext, and calls
// the function.  Thread management (suspend/resume) is the caller's
// responsibility; this code never suspends or resumes threads.
//
// Only ntdll.dll is imported.

#include "../nt_defs.h"
#include "inject_params.h"

#ifndef MHOOK_INJECT_DYNAMIC
#include "../mhook-lib/mhook.h"
#endif

// ---------------------------------------------------------------------------
// Forward declarations for the MASM entry-point thunk
// ---------------------------------------------------------------------------

// Defined in inject_delayed_entry_thunk_x64/x86.asm.  The thunk calls DoDelayedEntry
// then JMPs to the returned address so no hook frame is left on the stack.
extern void DelayedEntryThunk(void);

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
// GetProcessEntryPoint — read the process entry point from mapped PE headers
// ---------------------------------------------------------------------------

static PVOID GetProcessEntryPoint(void)
{
    NT_PEB *peb = RtlCurrentPeb();
    if (!peb) return NULL;
    PVOID imageBase = peb->ImageBaseAddress;
    if (!imageBase) return NULL;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)imageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)imageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    ULONG epRva = nt->OptionalHeader.AddressOfEntryPoint;
    if (!epRva) return NULL;

    return (BYTE *)imageBase + epRva;
}

// ---------------------------------------------------------------------------
// Delayed-execution state
//
// Set by _internal_Execute when MHOOK_REMOTE_FLAG_DELAY_UNTIL_INIT is active
// and the process is not yet initialised.  Used by DoDelayedEntry / the hook
// thunk when the entry point fires.
// ---------------------------------------------------------------------------

typedef int (*EntryPointFn)(void);

static LONG               g_DelayedCallDone;      // atomic: 0=not called, 1=called
static MhookSetHookFn     g_DelayedSetHook;
static MhookUnhookFn      g_DelayedUnhook;
static MHOOK_INJECT_CONTEXT g_DelayedCtx;
static PVOID              g_DelayedTargetFunc;    // resolved pointer (static path)
static WCHAR             *g_DelayedTargetDllPath; // heap copy for LdrLoadDll
static CHAR              *g_DelayedFunctionName;  // heap copy for LdrGetProcedureAddress
static ULONG              g_DelayedFunctionRva;
static EntryPointFn       g_TrueEntryPoint;       // set by Mhook_SetHook on EP hook

// ---------------------------------------------------------------------------
// CallDelayedTargetFunction — load DLL if needed, resolve and call the
// injection function.  Called from DoDelayedEntry and the post-hook
// race-check path.
// ---------------------------------------------------------------------------

static void CallDelayedTargetFunction(void)
{
    PVOID pFunc = g_DelayedTargetFunc;

    if (!pFunc) {
        /* Dynamic path: load the target DLL now that Win32 is available */
        HANDLE hDll = NULL;
        if (g_DelayedTargetDllPath) {
            USHORT nchars = 0;
            while (g_DelayedTargetDllPath[nchars]) ++nchars;
            UNICODE_STRING path;
            path.Buffer        = g_DelayedTargetDllPath;
            path.Length        = (USHORT)(nchars * sizeof(WCHAR));
            path.MaximumLength = path.Length + (USHORT)sizeof(WCHAR);
            LdrLoadDll(NULL, NULL, &path, &hDll);
        }
        if (hDll) {
            if (g_DelayedFunctionRva) {
                pFunc = (PVOID)((ULONG_PTR)hDll + g_DelayedFunctionRva);
            } else if (g_DelayedFunctionName) {
                USHORT fnLen = 0;
                while (g_DelayedFunctionName[fnLen]) ++fnLen;
                ANSI_STRING fn;
                fn.Buffer        = g_DelayedFunctionName;
                fn.Length        = fnLen;
                fn.MaximumLength = fnLen + 1;
                LdrGetProcedureAddress(hDll, &fn, 0, &pFunc);
            }
        }
    }

    if (pFunc)
        ((MhookInjectedFn)pFunc)(&g_DelayedCtx);

    /* Free heap copies */
    if (g_DelayedCtx.UserData) {
        RtlFreeHeap(RtlProcessHeap(), 0, g_DelayedCtx.UserData);
        g_DelayedCtx.UserData = NULL;
    }
    if (g_DelayedTargetDllPath) {
        RtlFreeHeap(RtlProcessHeap(), 0, g_DelayedTargetDllPath);
        g_DelayedTargetDllPath = NULL;
    }
    if (g_DelayedFunctionName) {
        RtlFreeHeap(RtlProcessHeap(), 0, g_DelayedFunctionName);
        g_DelayedFunctionName = NULL;
    }
}

// ---------------------------------------------------------------------------
// DoDelayedEntry — called by the MASM thunk when the hooked entry point fires
//
// Calls the injection function (if not already called), unhooks the entry
// point, and returns the original entry point address for the thunk to JMP to.
// ---------------------------------------------------------------------------

PVOID __cdecl DoDelayedEntry(void)
{
    /* Call injection function exactly once (race-safe) */
    if (InterlockedCompareExchange(&g_DelayedCallDone, 1, 0) == 0)
        CallDelayedTargetFunction();

    /* Always unhook — we ARE the hook function, so we must remove the hook */
    if (g_DelayedUnhook)
        g_DelayedUnhook((PVOID *)&g_TrueEntryPoint);

    return (PVOID)g_TrueEntryPoint;   /* original entry point for the thunk's JMP */
}

// ---------------------------------------------------------------------------
// _internal_Execute — called by the bootstrap thunk
//
// pParams points to the MHOOK_INJECT_REMOTE_PARAMS block in the remote
// allocation.  The function resolves the user's injection function, builds
// a MhookInjectContext, and calls the function.
// ---------------------------------------------------------------------------

NTSTATUS __cdecl _internal_Execute(MHOOK_INJECT_REMOTE_PARAMS *pParams)
{
    // Authoritative decision: prefer the caller's pre-injection observation
    // (MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED).  This injection thread runs
    // LdrpInitializeProcess as a side effect of loading the companion DLL, so by
    // now IsProcessInitialized() may report TRUE even for a target that was
    // created suspended and never ran — the caller-set bit captures the truth.
    // Fall back to the in-thread self-check only when the caller couldn't read
    // the state (bit absent).
    BOOLEAN needDelay = (pParams->RemoteFlags & MHOOK_REMOTE_FLAG_DELAY_UNTIL_INIT)
                        && ((pParams->RemoteFlags & MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED)
                            || !IsProcessInitialized());

    // --- Resolve the target function ---
    //
    // For the delayed dynamic path (needDelay + separate target DLL), skip
    // loading the target DLL now — it may import Win32 and can't be loaded
    // until the process is initialised.  The DLL is loaded later in
    // DoDelayedEntry / CallDelayedTargetFunction.
    //
    // For all other paths (non-delayed, or static delayed where the target
    // function is already in the companion DLL), resolve immediately.
    PVOID  pTargetFunc = NULL;
    HANDLE hTargetDll  = pParams->CompanionHandle;

    if (!needDelay || pParams->TargetDllPath.Length == 0) {
        if (pParams->TargetDllPath.Length > 0) {
            UNICODE_STRING targetPath = pParams->TargetDllPath;
            LdrLoadDll(NULL, NULL, &targetPath, &hTargetDll);
        }
        if (pParams->FunctionRva != 0)
            pTargetFunc = (PVOID)((ULONG_PTR)hTargetDll + pParams->FunctionRva);
        else if (pParams->FunctionName.Length > 0) {
            ANSI_STRING fn = pParams->FunctionName;
            LdrGetProcedureAddress(hTargetDll, &fn, 0, &pTargetFunc);
        }
    }

    /* For non-delayed path: nothing to do if the function wasn't found */
    if (!needDelay && !pTargetFunc)
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

    if (needDelay) {
        // -------------------------------------------------------------------
        // Delayed path: hook the process entry point and defer the call until
        // the loader has run all DllMains and Win32 is available.
        // -------------------------------------------------------------------

        /* Persist state: the remote allocation is freed by Mhook_Inject after
           this thread exits, so heap-copy everything the deferred call needs. */
        g_DelayedSetHook     = pSetHook;
        g_DelayedUnhook      = pUnhook;
        g_DelayedTargetFunc  = pTargetFunc;   /* NULL for dynamic */
        g_DelayedFunctionRva = pParams->FunctionRva;

        g_DelayedCtx.Size        = sizeof(g_DelayedCtx);
        g_DelayedCtx.SetHook     = pSetHook;
        g_DelayedCtx.Unhook      = pUnhook;
        g_DelayedCtx.UserDataSize = pParams->UserDataSize;

        if (pParams->TargetDllPath.Length > 0) {
            USHORT nchars = pParams->TargetDllPath.Length / sizeof(WCHAR);
            SIZE_T nbytes = (SIZE_T)(nchars + 1) * sizeof(WCHAR);
            g_DelayedTargetDllPath = (WCHAR *)RtlAllocateHeap(
                                         RtlProcessHeap(), 0, nbytes);
            if (g_DelayedTargetDllPath) {
                memcpy(g_DelayedTargetDllPath, pParams->TargetDllPath.Buffer,
                       pParams->TargetDllPath.Length);
                g_DelayedTargetDllPath[nchars] = 0;
            }
        }

        if (pParams->FunctionName.Length > 0) {
            USHORT len = pParams->FunctionName.Length;
            g_DelayedFunctionName = (CHAR *)RtlAllocateHeap(
                                        RtlProcessHeap(), 0, (SIZE_T)len + 1);
            if (g_DelayedFunctionName) {
                memcpy(g_DelayedFunctionName, pParams->FunctionName.Buffer, len);
                g_DelayedFunctionName[len] = 0;
            }
        }

        if (pParams->UserDataSize > 0 && pParams->UserData) {
            PVOID copy = RtlAllocateHeap(RtlProcessHeap(), 0,
                                          pParams->UserDataSize);
            if (copy)
                memcpy(copy, pParams->UserData, pParams->UserDataSize);
            g_DelayedCtx.UserData = copy;
        }

        /* x64: wrap in __try/__except so a crash surfaces as 0xDE00'00NN
         * (step 1-4) rather than a raw AV.  Not used on x86: __except_handler3/4
         * and __load_config_used are CRT symbols unavailable in ntdll-only DLLs. */
#ifdef _M_X64
        pParams->InjectStatus = 1;
        __try {
            PVOID ep = GetProcessEntryPoint();
            pParams->InjectStatus = 2;
            if (ep && pSetHook && pUnhook) {
                g_TrueEntryPoint = (EntryPointFn)ep;
                pSetHook((PVOID *)&g_TrueEntryPoint, DelayedEntryThunk);
            }
            pParams->InjectStatus = 3;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return (NTSTATUS)(0xDE000000 | (ULONG)pParams->InjectStatus);
        }
#else
        {
            PVOID ep = GetProcessEntryPoint();
            if (ep && pSetHook && pUnhook) {
                g_TrueEntryPoint = (EntryPointFn)ep;
                pSetHook((PVOID *)&g_TrueEntryPoint, DelayedEntryThunk);
            }
        }
#endif

        /* Race check (fallback path only): the process may have finished
           initialising between the needDelay check above and the hook
           installation.  If so, call the function now; otherwise DoDelayedEntry
           fires and wins the CAS.

           This must NOT run when the caller authoritatively observed the target
           uninitialized: in that case THIS injection thread is what set
           Initialized = TRUE (by loading the companion DLL), the target's own
           main thread is still parked before the entry point, and the entry-point
           hook is the correct — and only safe — trigger.  Calling here would run
           the user function on the injection thread mid-loader-activity, which is
           the original source of the flakiness. */
        if (!(pParams->RemoteFlags & MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED)
            && IsProcessInitialized()) {
            if (InterlockedCompareExchange(&g_DelayedCallDone, 1, 0) == 0)
                CallDelayedTargetFunction();
        }

        pParams->InjectStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    // --- Immediate (non-delayed) path ---
    {
        MHOOK_INJECT_CONTEXT ctx;
        ctx.Size         = sizeof(ctx);
        ctx.SetHook      = pSetHook;
        ctx.Unhook       = pUnhook;
        ctx.UserData     = pParams->UserData;
        ctx.UserDataSize = pParams->UserDataSize;

        ((MhookInjectedFn)pTargetFunc)(&ctx);

        pParams->InjectStatus = STATUS_SUCCESS;   /* also set in-memory for cdb inspection */
    }

done:
    /* Return the status as the thread exit code so Mhook_Inject can read it
       via NtQueryInformationThread after the process has exited. */
    return pParams->InjectStatus;
}
