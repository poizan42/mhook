// inject_params.h — internal struct shared between mhook_inject.cpp (calling
// side) and inject_entry.c (_internal_Execute, target-process side).
//
// This header is NOT part of the public API.

#pragma once

#include <stddef.h>  // offsetof
#include "../nt_defs.h"
#include "mhook_inject.h"

// ---------------------------------------------------------------------------
// LdrLoadDll function-pointer type (used as the first field of the params)
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI *LdrLoadDllFn)(
    PWSTR           SearchPath,
    PULONG          DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID          *DllHandle);

// Flags propagated into the remote params; mirrors MHOOK_INJECT_FLAG_* values.
#define MHOOK_REMOTE_FLAG_DELAY_UNTIL_INIT  0x00000001u

// Set by the caller when the target was observed UNINITIALIZED before the
// injection thread was created.  Authoritative: the injection thread itself
// initializes the process as a side effect of loading the companion DLL, so by
// the time _internal_Execute runs IsProcessInitialized() can no longer
// distinguish "the target's own main thread initialized it" from "our injection
// thread initialized it".  This bit captures the pre-injection truth.
#define MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED  0x00000002u

// ---------------------------------------------------------------------------
// MhookInjectRemoteParams
//
// Written by Mhook_Inject into the remote process immediately after the
// bootstrap-thunk bytes.  Read and updated by _internal_Execute.
//
// Layout (pack=1, see static_asserts in mhook_inject.cpp):
//
//   x64 offsets:                               x86 offsets:
//     LdrLoadDll              @  0  (8)          @  0  (4)
//     CompanionPath           @  8  (16)          @  4  (8)
//     CompanionHandle         @ 24  (8)           @ 12  (4)
//     ExecuteOffset           @ 32  (8)           @ 16  (4)
//     IsDynamic               @ 40  (4)           @ 20  (4)
//     RemoteFlags             @ 44  (4)           @ 24  (4)   MHOOK_REMOTE_FLAG_*
//     MhookPath               @ 48  (16)          @ 28  (8)
//     MhookHandle             @ 64  (8)           @ 36  (4)
//     TargetDllPath           @ 72  (16)          @ 40  (8)
//     FunctionName            @ 88  (16)          @ 48  (8)
//     FunctionRva             @104  (4)           @ 56  (4)
//     _rvapad                 @108  (4)           @ 60  (4)
//     UserData                @112  (8)           @ 64  (4)
//     UserDataSize            @120  (8)           @ 68  (4)
//     InjectStatus            @128  (4)           @ 72  (4)
//     LdrCompanionStatus      @132  (4)           @ 76  (4)
//   --- x64 only: bootstrap-thunk unwind tail @136..180 (see struct below) ---
//     CompletionEvent         @180  (8)           @ 80  (4)
//     CallerProcess           @188  (8)           @ 84  (4)
//     CallerThread            @196  (8)           @ 88  (4)
//     ApcRoutine              @204  (8)           @ 92  (4)
//     ApcContext              @212  (8)           @ 96  (4)
//     IoStatusBlock           @220  (8)           @100  (4)
//     sizeof                  =228                =104
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _MHOOK_INJECT_REMOTE_PARAMS {
    LdrLoadDllFn    LdrLoadDll;           // fn ptr      8 / 4
    UNICODE_STRING  CompanionPath;        // DLL path   16 / 8
    HANDLE          CompanionHandle;      // output      8 / 4
    ULONG_PTR       ExecuteOffset;        // RVA         8 / 4
    ULONG           IsDynamic;            // flag        4
    ULONG           RemoteFlags;          // MHOOK_REMOTE_FLAG_*  4
    UNICODE_STRING  MhookPath;            // mhook.dll  16 / 8
    HANDLE          MhookHandle;          // output      8 / 4
    UNICODE_STRING  TargetDllPath;        // user DLL   16 / 8 (empty for static)
    ANSI_STRING     FunctionName;         // fn name    16 / 8
    ULONG           FunctionRva;          // RVA form    4
    ULONG           _rvapad;              //             4
    PVOID           UserData;             // remote ptr  8 / 4
    SIZE_T          UserDataSize;         //             8 / 4
    NTSTATUS        InjectStatus;         // from exec   4
    NTSTATUS        LdrCompanionStatus;   // diagnostic  4
#ifdef _M_X64
    /* x64 bootstrap-thunk-frame unwind registration.
     * Filled by the host (mhook_inject.cpp) before the remote thread starts.
     * BootstrapThunkRF (a RUNTIME_FUNCTION, all offsets relative to
     * BootstrapThunkBase) describes the thunk's extent and points at the
     * UNWIND_INFO for InjectBootstrapThunkEntry's prolog.  The prolog has two
     * unwind codes; UNWIND_INFO declares UnwindCode[1] inline, so the second
     * code is stored in the trailing BootstrapThunkUC field (contiguous).
     * RtlDeleteFunctionTable is called by the bootstrap thunk on every exit path so
     * the registration is cleaned up before the host frees the allocation. */
    PVOID             RtlAddFunctionTable;     // @136 (8) remote ntdll!RtlAddFunctionTable
    PVOID             RtlDeleteFunctionTable;  // @144 (8) remote ntdll!RtlDeleteFunctionTable
    ULONG64           BootstrapThunkBase;      // @152 (8) = rCode (remote allocation base)
    RUNTIME_FUNCTION  BootstrapThunkRF;        // @160 (12)
    UNWIND_INFO       BootstrapThunkUI;        // @172 (6)  prolog descriptor + UnwindCode[0]
    UNWIND_CODE       BootstrapThunkUC;        // @178 (2)  UnwindCode[1] (CountOfCodes == 2)
    // x64 prefix sizeof (without the common completion tail below) = 180
#endif
    // Completion plumbing (common to both arches; filled by Mhook_Inject).
    //   CompletionEvent: signalled when the injection fn returns — either the
    //     sync+delay internal event or the async user Event, duplicated into the
    //     target.  NULL when no completion signal is needed.
    //   CallerProcess:   handle to the calling process (for the IoStatusBlock
    //     cross-process write).  NULL otherwise.
    //   CallerThread:    handle to the calling thread (async APC).  Populated in
    //     subtask 2; NULL otherwise.
    //   ApcRoutine/ApcContext: caller-side APC routine + context.  Subtask 2.
    //   IoStatusBlock:   caller-side IO_STATUS_BLOCK VA to receive the status.
    HANDLE          CompletionEvent;      // @180 / @80
    HANDLE          CallerProcess;        // @188 / @84
    HANDLE          CallerThread;         // @196 / @88
    PVOID           ApcRoutine;           // @204 / @92
    PVOID           ApcContext;           // @212 / @96
    PVOID           IoStatusBlock;        // @220 / @100
} MHOOK_INJECT_REMOTE_PARAMS;
#pragma pack(pop)

// Portable static assertion: C11 uses _Static_assert, C++ uses static_assert.
// inject_entry.c is compiled with /std:c11 (set in mhook_inject.vcxproj).
#ifdef __cplusplus
#  define INJECT_STATIC_ASSERT(e,m) static_assert(e,m)
#else
#  define INJECT_STATIC_ASSERT(e,m) _Static_assert(e,m)
#endif

#ifdef _M_X64
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionPath)      ==   8, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionHandle)    ==  24, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ExecuteOffset)      ==  32, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, IsDynamic)          ==  40, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, RemoteFlags)        ==  44, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookPath)          ==  48, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookHandle)        ==  64, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, TargetDllPath)      ==  72, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionName)       ==  88, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionRva)        == 104, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserData)           == 112, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserDataSize)       == 120, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, InjectStatus)          == 128, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, LdrCompanionStatus)    == 132, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, RtlAddFunctionTable)   == 136, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, RtlDeleteFunctionTable)== 144, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, BootstrapThunkBase)         == 152, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, BootstrapThunkRF)           == 160, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, BootstrapThunkUI)           == 172, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, BootstrapThunkUC)           == 178, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompletionEvent)            == 180, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CallerProcess)              == 188, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CallerThread)               == 196, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ApcRoutine)                 == 204, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ApcContext)                 == 212, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, IoStatusBlock)              == 220, "layout");
INJECT_STATIC_ASSERT(sizeof(MHOOK_INJECT_REMOTE_PARAMS)                          == 228, "layout");
INJECT_STATIC_ASSERT(sizeof(UNWIND_CODE)                                         ==   2, "unwind layout");
INJECT_STATIC_ASSERT(sizeof(UNWIND_INFO)                                         ==   6, "unwind layout");
INJECT_STATIC_ASSERT(sizeof(RUNTIME_FUNCTION)                                    ==  12, "unwind layout");
#else
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionPath)      ==  4,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionHandle)    == 12,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ExecuteOffset)      == 16,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, IsDynamic)          == 20,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, RemoteFlags)        == 24,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookPath)          == 28,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookHandle)        == 36,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, TargetDllPath)      == 40,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionName)       == 48,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionRva)        == 56,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserData)           == 64,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserDataSize)       == 68,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, InjectStatus)       == 72,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, LdrCompanionStatus) == 76,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompletionEvent)    == 80,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CallerProcess)      == 84,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CallerThread)       == 88,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ApcRoutine)         == 92,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ApcContext)         == 96,  "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, IoStatusBlock)      == 100, "layout");
INJECT_STATIC_ASSERT(sizeof(MHOOK_INJECT_REMOTE_PARAMS)                       == 104, "layout");
#endif

// ---------------------------------------------------------------------------
// MHOOK_INJECT_REMOTE_PARAMS_X86 — explicit, fixed-width x86 layout.
//
// Used by an x64 injector to build the remote params for a 32-bit (WOW64)
// target (cross-architecture 64-bit -> 32-bit injection): every pointer/handle/
// SIZE_T is 4 bytes and the strings are the 8-byte x86 UNICODE_STRING/ANSI_STRING
// shape, so the struct is binary-identical to what the native x86
// MHOOK_INJECT_REMOTE_PARAMS (above) would produce when compiled for Win32.
// There is no x64 unwind tail (an x86 target registers no function table).
//
// The asserts below are compiled in BOTH builds so the x86 ABI this injector
// writes stays pinned regardless of which architecture mhook_inject is built for.
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _MHOOK_STR32 {     // x86 UNICODE_STRING / ANSI_STRING (8 bytes)
    USHORT Length;
    USHORT MaximumLength;
    ULONG  Buffer;                // 32-bit pointer in the target
} MHOOK_STR32;

typedef struct _MHOOK_INJECT_REMOTE_PARAMS_X86 {
    ULONG       LdrLoadDll;            // @  0  fn ptr (remote 32-bit ntdll!LdrLoadDll)
    MHOOK_STR32 CompanionPath;         // @  4
    ULONG       CompanionHandle;       // @ 12
    ULONG       ExecuteOffset;         // @ 16  RVA of _internal_Execute
    ULONG       IsDynamic;             // @ 20
    ULONG       RemoteFlags;           // @ 24  MHOOK_REMOTE_FLAG_*
    MHOOK_STR32 MhookPath;             // @ 28
    ULONG       MhookHandle;           // @ 36
    MHOOK_STR32 TargetDllPath;         // @ 40
    MHOOK_STR32 FunctionName;          // @ 48
    ULONG       FunctionRva;           // @ 56
    ULONG       _rvapad;               // @ 60
    ULONG       UserData;              // @ 64  remote 32-bit ptr
    ULONG       UserDataSize;          // @ 68
    NTSTATUS    InjectStatus;          // @ 72
    NTSTATUS    LdrCompanionStatus;    // @ 76
    ULONG       CompletionEvent;       // @ 80
    ULONG       CallerProcess;         // @ 84
    ULONG       CallerThread;          // @ 88
    ULONG       ApcRoutine;            // @ 92
    ULONG       ApcContext;            // @ 96
    ULONG       IoStatusBlock;         // @100
} MHOOK_INJECT_REMOTE_PARAMS_X86;      // 104 bytes
#pragma pack(pop)

INJECT_STATIC_ASSERT(sizeof(MHOOK_STR32)                                          ==   8, "x86 string");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, CompanionPath)      ==   4, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, CompanionHandle)    ==  12, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, ExecuteOffset)      ==  16, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, IsDynamic)          ==  20, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, RemoteFlags)        ==  24, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, MhookPath)          ==  28, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, MhookHandle)        ==  36, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, TargetDllPath)      ==  40, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, FunctionName)       ==  48, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, FunctionRva)        ==  56, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, UserData)           ==  64, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, UserDataSize)       ==  68, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, InjectStatus)       ==  72, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, LdrCompanionStatus) ==  76, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, CompletionEvent)    ==  80, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, CallerProcess)      ==  84, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, CallerThread)       ==  88, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, ApcRoutine)         ==  92, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, ApcContext)         ==  96, "x86 layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS_X86, IoStatusBlock)      == 100, "x86 layout");
INJECT_STATIC_ASSERT(sizeof(MHOOK_INJECT_REMOTE_PARAMS_X86)                        == 104, "x86 layout");
