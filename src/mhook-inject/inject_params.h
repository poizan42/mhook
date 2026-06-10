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
// shellcode bytes.  Read and updated by _internal_Execute.
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
//     sizeof                  =136                = 80
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
    /* x64 shellcode-frame unwind registration.
     * Filled by the host (mhook_inject.cpp) before the remote thread starts.
     * ShellcodeRF[3] holds a RUNTIME_FUNCTION (BeginAddress / EndAddress /
     * UnwindData, all relative to ShellcodeBase).  ShellcodeUI[8] holds the
     * UNWIND_INFO bytes for InjectShellcodeEntry's prolog.
     * RtlDeleteFunctionTable is called by the shellcode on every exit path so
     * the registration is cleaned up before the host frees the allocation. */
    PVOID           RtlAddFunctionTable;     // @136 (8) remote ntdll!RtlAddFunctionTable
    PVOID           RtlDeleteFunctionTable;  // @144 (8) remote ntdll!RtlDeleteFunctionTable
    ULONG64         ShellcodeBase;           // @152 (8) = rCode (remote allocation base)
    ULONG           ShellcodeRF[3];          // @160 (12) RUNTIME_FUNCTION {Begin,End,UnwindData}
    BYTE            ShellcodeUI[8];          // @172 (8)  UNWIND_INFO + 2 unwind codes
    // sizeof = 180
#endif
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
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ShellcodeBase)         == 152, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ShellcodeRF)           == 160, "layout");
INJECT_STATIC_ASSERT(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ShellcodeUI)           == 172, "layout");
INJECT_STATIC_ASSERT(sizeof(MHOOK_INJECT_REMOTE_PARAMS)                          == 180, "layout");
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
INJECT_STATIC_ASSERT(sizeof(MHOOK_INJECT_REMOTE_PARAMS)                       == 80,  "layout");
#endif
