// mhook_inject.h — public API for mhook_inject.
//
// Mhook_Inject injects a function into a remote process using a small
// bootstrap-thunk stub that loads a companion DLL and calls _internal_Execute,
// which in turn sets up a MhookInjectContext and calls the user-supplied
// injection function.
//
// Only ntdll.dll is required at runtime.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Minimal NT types used by the async-completion fields below.
// Provided here under guards so this header is self-contained — callers do not
// need <winternl.h>.  The guard names match src/nt_defs.h so the library's own
// translation units (which include nt_defs.h) do not get a double definition.
// ---------------------------------------------------------------------------

#ifndef __NTSTATUS_DEFINED
#define __NTSTATUS_DEFINED
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#ifndef _IO_STATUS_BLOCK_DEFINED
#define _IO_STATUS_BLOCK_DEFINED
typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#endif

#ifndef _IO_APC_ROUTINE_DEFINED
#define _IO_APC_ROUTINE_DEFINED
typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            Reserved);
#endif

// ---------------------------------------------------------------------------
// Flags for MHOOK_INJECT_PARAMS.Flags
// ---------------------------------------------------------------------------

// Defer calling the injection function until the process has completed loader
// initialisation (PEB_LDR_DATA.Initialized == TRUE, i.e. Win32 APIs are safe).
// The injection function is guaranteed to run before the process entry point
// executes any code.  If the process is already initialised when Mhook_Inject
// injects the thread, the function is called immediately.
// For dynamic builds the target DLL is not loaded until that moment either.
#define MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT  0x00000001u

// Return immediately after creating the remote thread; the injection function
// runs in the background.  Completion is reported via the Event / IoStatusBlock /
// ApcRoutine fields below (all optional; all NULL = pure fire-and-forget).
// Without this flag Mhook_Inject blocks until the injection function has returned
// (now true even when combined with MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT).
#define MHOOK_INJECT_FLAG_ASYNC             0x00000002u

// ---------------------------------------------------------------------------
// Failure HRESULTs returned by Mhook_Inject
//
// These set the Customer (C) bit (0x20000000) together with the severity bit, so
// they belong to the mhook library as a whole rather than to a Microsoft facility
// (FACILITY_*).  Other failures are propagated as-is (e.g. an NTSTATUS mapped to
// an HRESULT), so always test with FAILED(hr) and only compare against these for
// specific handling.
//
// Dynamic builds (mhook_inject.dll) embed a message-table resource for these codes,
// so the text can be retrieved with FormatMessage:
//   FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandleW(L"mhook_inject.dll"),
//                  hr, 0, buf, cch, NULL);
// Static builds carry no resource (the consumer's own module would have to supply one).
// ---------------------------------------------------------------------------

#define MHOOK_INJECT_E_PARAMS    ((HRESULT)0xA0000001L)  // bad/incompatible params
#define MHOOK_INJECT_E_NO_NTDLL  ((HRESULT)0xA0000002L)  // ntdll not found in target
#define MHOOK_INJECT_E_NO_EXEC   ((HRESULT)0xA0000003L)  // _internal_Execute not found in companion DLL
#define MHOOK_INJECT_E_TIMEOUT   ((HRESULT)0xA0000004L)  // remote thread timed out
#define MHOOK_INJECT_E_ACCESS    ((HRESULT)0xA0000005L)  // target handle lacks PROCESS_ALL_ACCESS
// 32-bit -> 64-bit injection requires an x64 proxy executable (see ProxyPath and the
// "32-bit caller -> 64-bit target" notes on Mhook_Inject below).
#define MHOOK_INJECT_E_NO_PROXY  ((HRESULT)0xA0000006L)  // no x64 proxy executable found; 32->64 unavailable
#define MHOOK_INJECT_E_PROXY     ((HRESULT)0xA0000007L)  // proxy found but failed to launch / crashed before reporting

// ---------------------------------------------------------------------------
// MHOOK_INJECT_PARAMS — input to Mhook_Inject (calling process)
// ---------------------------------------------------------------------------

typedef struct _MHOOK_INJECT_PARAMS {
    // sizeof(MHOOK_INJECT_PARAMS) — version guard; must be set by the caller.
    ULONG  Size;

    // Combination of MHOOK_INJECT_FLAG_* values; 0 = default behaviour.
    ULONG  Flags;

    // Handle to the target process.  Must be a PROCESS_ALL_ACCESS handle.
    // (Mhook_Inject deliberately requires full access — it is not meant to be a
    // privilege-escalation aid — and fails if the handle was granted anything
    // less.  The underlying operations only need PROCESS_VM_OPERATION |
    // PROCESS_VM_WRITE | PROCESS_CREATE_THREAD; the stricter requirement is an
    // intentional guard.)
    HANDLE TargetProcess;

    // Target injection function — set EXACTLY ONE of the two forms below.
    //
    // FunctionPointer form:
    //   A VA in the CALLING process.  Mhook_Inject finds which loaded module
    //   contains the address, computes RVA = pointer - moduleBase, and that
    //   module's path becomes the DLL to load in the target process.
    //   For static builds the companion DLL is this same module (it must
    //   export _internal_Execute).  For dynamic builds mhook_inject.dll is
    //   the companion and the pointed-to module is loaded additionally.
    PVOID  FunctionPointer;

    // DllPath + FunctionName form:
    //   DllPath  — path relative to the module containing Mhook_Inject, or
    //              an absolute Win32 path.  NOT limited to MAX_PATH.
    //   FunctionName — exported function name to call in DllPath.
    //   For static builds DllPath is the companion (must export _internal_Execute).
    //   For dynamic builds mhook_inject.dll is the companion; DllPath is loaded
    //   additionally inside the target process.
    PCWSTR DllPath;
    PCSTR  FunctionName;

    // Path to mhook.dll matching the TARGET process architecture.
    //   NULL   → search for mhook.dll in the same directory as the companion DLL.
    //   Static builds: this field is reserved; set to NULL.
    PCWSTR MhookDllPath;

    // Optional opaque data block.  The bytes are copied verbatim into the
    // target process and a pointer to the copy is handed to the injected
    // function via MhookInjectContext.UserData.
    PVOID  UserData;
    SIZE_T UserDataSize;

    // Completion timeout for the SYNCHRONOUS modes, in milliseconds.  Ignored
    // when MHOOK_INJECT_FLAG_ASYNC is set (that mode never waits).
    //   0          → default of 30 000 ms (30 s).
    //   INFINITE   → no timeout; wait forever.
    //   other      → that many milliseconds.
    // Values with the sign bit set other than INFINITE (0x80000000–0xFFFFFFFE,
    // i.e. would-be-negative) are rejected with MHOOK_INJECT_E_PARAMS.
    // This is the TOTAL budget across both internal wait phases (the bootstrap
    // thread, then — under DELAY_UNTIL_INIT — the entry-point hook): time spent
    // waiting on the first reduces what remains for the second.  The wait is
    // measured against the monotonic unbiased interrupt time, so it is immune to
    // wall-clock changes and does not count time the system spent asleep.
    // (DWORD millisecond count, as the Win32 wait APIs use; max ~24.85 days.)
    DWORD  TimeoutMs;

    // -----------------------------------------------------------------------
    // Async completion — only meaningful when MHOOK_INJECT_FLAG_ASYNC is set.
    // All fields are optional; set unused ones to NULL.  When all are NULL and
    // ASYNC is set, the call is pure fire-and-forget.
    // -----------------------------------------------------------------------

    // Optional.  Event handle set to the signaled state after the injection
    // function returns.  Duplicated into the target internally; the caller keeps
    // ownership of the original.  NULL if unused.
    HANDLE             Event;

    // Optional.  APC routine queued to the CALLING thread after the injection
    // function returns.  The calling thread must enter an alertable wait (e.g.
    // SleepEx(.,TRUE)) for the APC to run, as with ReadFileEx.  The APC receives
    // (ApcContext, IoStatusBlock, Reserved).  NULL if unused.
    PIO_APC_ROUTINE    ApcRoutine;

    // Optional.  Context value passed verbatim to ApcRoutine.  Ignored when
    // ApcRoutine is NULL.
    PVOID              ApcContext;

    // Optional.  Pointer to an IO_STATUS_BLOCK in the CALLING process.  Its
    // Status member receives the final NTSTATUS of the injection function; it is
    // set to STATUS_PENDING before Mhook_Inject returns.  Because the target
    // writes it across the process boundary, delivering it grants the target a
    // write handle to the calling process (acceptable: Mhook_Inject already
    // requires PROCESS_ALL_ACCESS on the target).  NULL if unused.
    PIO_STATUS_BLOCK   IoStatusBlock;

    // -----------------------------------------------------------------------
    // Proxy — only meaningful on the 32-bit caller -> 64-bit target path.
    // -----------------------------------------------------------------------

    // Optional.  Path to the x64 proxy executable used for 32-bit -> 64-bit
    // injection (a WOW64 process cannot create a 64-bit thread, so the work is
    // delegated to a native 64-bit helper process — see the notes on Mhook_Inject).
    //   NULL → look for "mhook_inject_proxy.exe" in the same directory as the
    //          module that contains Mhook_Inject.
    //   else → resolved relative to that module's directory (an absolute path
    //          passes through), consistent with DllPath / MhookDllPath.
    // If no proxy is found Mhook_Inject returns MHOOK_INJECT_E_NO_PROXY — the
    // expected way to detect that 32->64 injection is not configured on this
    // install.  Ignored on every path other than 32-bit caller -> 64-bit target.
    PCWSTR             ProxyPath;

} MHOOK_INJECT_PARAMS;

// ---------------------------------------------------------------------------
// Function-pointer types for Mhook_SetHook and Mhook_Unhook.
// Matches the declarations in mhook-lib/mhook.h.
// ---------------------------------------------------------------------------

typedef BOOL (__cdecl *MhookSetHookFn)(PVOID *ppSystemFunction, PVOID pHookFunction);
typedef BOOL (__cdecl *MhookUnhookFn)(PVOID *ppHookedFunction);

// ---------------------------------------------------------------------------
// MHOOK_INJECT_CONTEXT — delivered to the injected function in the target
// ---------------------------------------------------------------------------

typedef struct _MHOOK_INJECT_CONTEXT {
    // sizeof(MHOOK_INJECT_CONTEXT) — version guard.
    ULONG          Size;

    // Mhook_SetHook / Mhook_Unhook function pointers.
    // Dynamic builds: resolved from mhook.dll loaded in the target process.
    // Static builds:  point to the statically linked implementations.
    MhookSetHookFn SetHook;
    MhookUnhookFn  Unhook;

    // Pointer to the UserData copy inside the target process (NULL if none).
    PVOID          UserData;
    SIZE_T         UserDataSize;

} MHOOK_INJECT_CONTEXT;

typedef void (__cdecl *MhookInjectedFn)(MHOOK_INJECT_CONTEXT *ctx);

// ---------------------------------------------------------------------------
// Mhook_Inject
//
// Injects a thread into TargetProcess that loads the companion DLL and calls
// the user-supplied injection function.
//
// Returns S_OK on success, or an HRESULT error code.
//
// Cross-architecture: a 64-bit caller may inject into a 32-bit (WOW64) target.
// In that case everything loaded into the target must be 32-bit — use the
// DllPath + FunctionName form naming the x86 companion (the FunctionPointer form
// is rejected with MHOOK_INJECT_E_PARAMS), and for dynamic builds set MhookDllPath
// to the x86 mhook.dll (the x86 mhook_inject.dll companion must sit next to it).
// All completion modes work cross-arch: synchronous, Event, IoStatusBlock and
// ApcRoutine.  Because a 32-bit target cannot write back into the 64-bit caller,
// async IoStatusBlock/ApcRoutine completion is delivered by an internal caller-side
// helper thread once the target signals completion — so it is bounded by TimeoutMs
// (a target that dies before completing surfaces as a timeout NTSTATUS), and the
// delivery happens a moment after completion rather than from the target directly.
//
// The reverse — a 32-bit (WOW64) caller injecting into a 64-bit target — is also
// supported, but indirectly: a WOW64 process has no ntdll-only way to create a
// 64-bit thread, so Mhook_Inject launches a native x64 proxy executable (see
// ProxyPath) that performs the injection on its behalf and reports the result back.
// Use the DllPath + FunctionName form naming an x64 companion (the FunctionPointer
// form is rejected with MHOOK_INJECT_E_PARAMS).  The companion requirements mirror
// the same-arch ones for your build flavour:
//   - dynamic builds: set MhookDllPath to the x64 mhook.dll; DllPath is your x64
//     function DLL (loaded into the target alongside the x64 mhook_inject.dll
//     companion).  The bundled proxy is the matching x64 mhook_inject_proxy bundle.
//   - static builds: DllPath names a self-contained x64 companion that exports
//     _internal_Execute (built linking the x64 mhook_inject.lib + mhook.lib);
//     MhookDllPath is unused.
// All completion modes work (synchronous, Event, IoStatusBlock, ApcRoutine — the
// latter delivered by a caller-side helper thread).  If no proxy executable is found
// the call returns MHOOK_INJECT_E_NO_PROXY (the expected result when 32->64 is not
// configured); if a proxy is found but fails to launch or crashes before reporting,
// MHOOK_INJECT_E_PROXY.
//
// Deployment: the dynamic proxy ships as a self-contained x64 bundle
// (mhook_inject_proxy.exe + x64 mhook_inject.dll + mhook.dll) — drop it as a
// `mhook_inject_proxy\` subdirectory next to your x86 module; the static proxy is a
// single self-contained exe placed flat.  With ProxyPath = NULL, Mhook_Inject probes
// both (`mhook_inject_proxy.exe`, then `mhook_inject_proxy\mhook_inject_proxy.exe`).
// Consumers can also supply their own proxy via ProxyPath that implements the
// documented wire contract in inject_proxy_params.h, or link mhook_inject_proxy.lib
// into their own executable.
// ---------------------------------------------------------------------------

HRESULT __cdecl Mhook_Inject(MHOOK_INJECT_PARAMS *params);

#ifdef __cplusplus
}
#endif
