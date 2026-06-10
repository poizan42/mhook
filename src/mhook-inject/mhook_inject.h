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
// Flags for MHOOK_INJECT_PARAMS.Flags
// ---------------------------------------------------------------------------

// Defer calling the injection function until the process has completed loader
// initialisation (PEB_LDR_DATA.Initialized == TRUE, i.e. Win32 APIs are safe).
// The injection function is guaranteed to run before the process entry point
// executes any code.  If the process is already initialised when Mhook_Inject
// injects the thread, the function is called immediately.
// For dynamic builds the target DLL is not loaded until that moment either.
#define MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT  0x00000001u

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
// ---------------------------------------------------------------------------

HRESULT __cdecl Mhook_Inject(MHOOK_INJECT_PARAMS *params);

#ifdef __cplusplus
}
#endif
