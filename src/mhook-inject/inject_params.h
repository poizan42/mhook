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
//     _pad                    @ 44  (4)           @ 24  (4)
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
    ULONG           _pad;                 //             4
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
} MHOOK_INJECT_REMOTE_PARAMS;
#pragma pack(pop)

// Layout assertions are guarded for C++ only; inject_entry.c is plain C and
// does not need them (the offsets are verified by the C++ compilation unit).
#ifdef __cplusplus
#  ifdef _M_X64
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionPath)      ==   8, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionHandle)    ==  24, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ExecuteOffset)      ==  32, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, IsDynamic)          ==  40, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookPath)          ==  48, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookHandle)        ==  64, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, TargetDllPath)      ==  72, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionName)       ==  88, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionRva)        == 104, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserData)           == 112, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserDataSize)       == 120, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, InjectStatus)       == 128, "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, LdrCompanionStatus) == 132, "layout");
static_assert(sizeof(MHOOK_INJECT_REMOTE_PARAMS)                       == 136, "layout");
#  else
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionPath)      ==  4,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, CompanionHandle)    == 12,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, ExecuteOffset)      == 16,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, IsDynamic)          == 20,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookPath)          == 28,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, MhookHandle)        == 36,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, TargetDllPath)      == 40,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionName)       == 48,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, FunctionRva)        == 56,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserData)           == 64,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, UserDataSize)       == 68,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, InjectStatus)       == 72,  "layout");
static_assert(offsetof(MHOOK_INJECT_REMOTE_PARAMS, LdrCompanionStatus) == 76,  "layout");
static_assert(sizeof(MHOOK_INJECT_REMOTE_PARAMS)                       == 80,  "layout");
#  endif
#endif
