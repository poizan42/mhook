//
// nt_defs.h — NT-native type definitions and function declarations.
// Replaces <windows.h> across the mhook library. The only DLL dependency
// introduced here is ntdll.dll.
//
// Include chain: <winnt.h> only — avoids pulling in the full Win32 surface
// so that IDE IntelliSense does not offer kernel32/user32/etc. APIs.
// winnt.h's own dependencies (ctype.h, winapifamily.h, basetsd.h, specstrings.h
// etc.) do not pull in ntdef.h, so there are no struct redefinition conflicts.
//

#ifndef NT_DEFS_H
#define NT_DEFS_H

//
// winnt.h checks for _AMD64_ / _X86_ / _ARM64_ / _ARM_ rather than the
// compiler's predefined _M_xxx macros.  Bridge them here.
//
#if defined(_M_AMD64) && !defined(_AMD64_)
#define _AMD64_
#elif defined(_M_IX86) && !defined(_X86_)
#define _X86_
#elif defined(_M_ARM64) && !defined(_ARM64_)
#define _ARM64_
#elif defined(_M_ARM) && !defined(_ARM_)
#define _ARM_
#endif

//
// minwindef.h + winnt.h: provides CONST, BOOL, BYTE, WORD, DWORD, CONTEXT,
// LARGE_INTEGER, ACCESS_MASK, LDT_ENTRY, RTL_CRITICAL_SECTION,
// MEMORY_BASIC_INFORMATION, MEM_*/PAGE_* constants, RtlZeroMemory, etc.
//
// Save and reset packing before including these headers.  cpu.h wraps its
// own content in #pragma pack(push,1) and includes nt_defs.h from within
// that block; without this guard, winnt.h would be processed with pack=1
// active, breaking the alignment of LARGE_INTEGER and other types.
//
#pragma pack(push)
#pragma pack()
#include <minwindef.h>
#include <winnt.h>
#pragma pack(pop)

//
// va_list (compiler-intrinsic header, no DLL dependency).
//
#include <stdarg.h>

//
// memset/memcpy: release builds use /Oi intrinsics (no DLL import).
// Debug builds may reference UCRTBASE but never kernel32.
//
#include <string.h>

//
// INVALID_HANDLE_VALUE is in handleapi.h (not winnt.h).
//
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif

// ---------------------------------------------------------------------------
// Pseudo-handles
// ---------------------------------------------------------------------------

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()   ((HANDLE)(LONG_PTR)-2)

// ---------------------------------------------------------------------------
// NTSTATUS  (winnt.h does not define it; that lives in ntdef.h)
// ---------------------------------------------------------------------------

#ifndef __NTSTATUS_DEFINED
#define __NTSTATUS_DEFINED
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED  ((NTSTATUS)0xC0000002L)
#endif

// ---------------------------------------------------------------------------
// UNICODE_STRING / OBJECT_ATTRIBUTES  (ntdef.h, not winnt.h)
// ---------------------------------------------------------------------------

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
#endif

#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

// ---------------------------------------------------------------------------
// ANSI_STRING  (ntdef.h, not winnt.h)
// ---------------------------------------------------------------------------

#ifndef _ANSI_STRING_DEFINED
#define _ANSI_STRING_DEFINED
typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;
#endif

// ---------------------------------------------------------------------------
// CLIENT_ID  (ntdef.h, not winnt.h)
// ---------------------------------------------------------------------------

#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
#endif

// ---------------------------------------------------------------------------
// KPRIORITY  (ntdef.h, not winnt.h)
// ---------------------------------------------------------------------------

#ifndef _KPRIORITY_DEFINED
#define _KPRIORITY_DEFINED
typedef LONG KPRIORITY;
#endif

// ---------------------------------------------------------------------------
// PCSZ  (ntdef.h, not winnt.h — used in RtlCharToInteger)
// ---------------------------------------------------------------------------

#ifndef _PCSZ_DEFINED
#define _PCSZ_DEFINED
typedef CONST char *PCSZ;
#endif

// ---------------------------------------------------------------------------
// Process Environment Block — fields up to and including ProcessHeap.
//
// Layout (phnt ntpebteb.h):
//   BOOLEAN[4] + implicit pad → HANDLE Mutant → PVOID×4 → PVOID ProcessHeap
//
// Offsets verified against ntpebteb.h:
//   x64: ProcessHeap at 0x30  (4×BOOLEAN + 4-byte pad + HANDLE(8) + 4×PVOID(8))
//   x86: ProcessHeap at 0x18  (4×BOOLEAN        + HANDLE(4) + 4×PVOID(4))
// ---------------------------------------------------------------------------

typedef struct _NT_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    // Implicit 4-byte pad on x64 aligns Mutant to an 8-byte boundary.
    HANDLE  Mutant;
    PVOID   ImageBaseAddress;
    PVOID   Ldr;
    PVOID   ProcessParameters;
    PVOID   SubSystemData;
    PVOID   ProcessHeap;
} NT_PEB, *PNT_PEB;

// ---------------------------------------------------------------------------
// Thread Environment Block — fields up to and including ProcessEnvironmentBlock.
//
// Layout (phnt ntpebteb.h):
//   NT_TIB + EnvironmentPointer → ClientId → ActiveRpcHandle →
//   ThreadLocalStoragePointer → ProcessEnvironmentBlock
//
// x64: NT_TIB=0x38, EnvironmentPointer=0x08 → ClientId@0x40
//      ClientId=0x10 → ActiveRpcHandle@0x50 → TLS@0x58 → PEB*@0x60
// x86: NT_TIB=0x1C, EnvironmentPointer=0x04 → ClientId@0x20
//      ClientId=0x08 → ActiveRpcHandle@0x28 → TLS@0x2C → PEB*@0x30
// ---------------------------------------------------------------------------

typedef struct _NT_TEB_MINIMAL {
#ifdef _M_X64
    BYTE     Reserved1[0x40];           // NT_TIB (0x38) + EnvironmentPointer (0x08)
    CLIENT_ID ClientId;                 // offset 0x40
    PVOID    ActiveRpcHandle;           // offset 0x50
    PVOID    ThreadLocalStoragePointer; // offset 0x58
    NT_PEB  *ProcessEnvironmentBlock;   // offset 0x60
#else
    BYTE     Reserved1[0x20];           // NT_TIB (0x1C) + EnvironmentPointer (0x04)
    CLIENT_ID ClientId;                 // offset 0x20
    PVOID    ActiveRpcHandle;           // offset 0x28
    PVOID    ThreadLocalStoragePointer; // offset 0x2C
    NT_PEB  *ProcessEnvironmentBlock;   // offset 0x30
#endif
} NT_TEB_MINIMAL;

FORCEINLINE NT_TEB_MINIMAL *NtCurrentTeb_nt(void) {
#ifdef _M_X64
    return (NT_TEB_MINIMAL *)__readgsqword(0x30);
#else
    return (NT_TEB_MINIMAL *)__readfsdword(0x18);
#endif
}

FORCEINLINE NT_PEB *RtlCurrentPeb(void) {
    return NtCurrentTeb_nt()->ProcessEnvironmentBlock;
}

#define NtCurrentClientId() (NtCurrentTeb_nt()->ClientId)

// RtlProcessHeap is not exported by ntdll.dll; it is defined in phnt as a
// macro that reads ProcessHeap from the PEB (ntrtl.h).
#define RtlProcessHeap() (RtlCurrentPeb()->ProcessHeap)

// ---------------------------------------------------------------------------
// Information class enumerations
// ---------------------------------------------------------------------------

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation          = 0,
    ThreadBasePriority              = 3,
    ThreadDescriptorTableEntry      = 6,
} THREADINFOCLASS;

typedef enum _NT_SYSTEMINFOCLASS {
    SystemBasicInformation          = 0,
} NT_SYSTEMINFOCLASS;

typedef enum _NT_MEMORYINFOCLASS {
    MemoryBasicInformation          = 0,
} NT_MEMORYINFOCLASS;

// ---------------------------------------------------------------------------
// Thread / process information structures
// ---------------------------------------------------------------------------

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS    ExitStatus;
    PVOID       TebBaseAddress;
    CLIENT_ID   ClientId;
    ULONG_PTR   AffinityMask;
    KPRIORITY   Priority;
    KPRIORITY   BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG       Reserved;
    ULONG       TimerResolution;
    ULONG       PageSize;
    ULONG       NumberOfPhysicalPages;
    ULONG       LowestPhysicalPageNumber;
    ULONG       HighestPhysicalPageNumber;
    ULONG       AllocationGranularity;
    ULONG_PTR   MinimumUserModeAddress;
    ULONG_PTR   MaximumUserModeAddress;
    ULONG_PTR   ActiveProcessorsAffinityMask;
    CCHAR       NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// Used with NtQueryInformationThread(ThreadDescriptorTableEntry).
// LDT_ENTRY is defined in <winnt.h>.
typedef struct _DESCRIPTOR_TABLE_ENTRY {
    ULONG       Selector;
    LDT_ENTRY   Descriptor;
} DESCRIPTOR_TABLE_ENTRY, *PDESCRIPTOR_TABLE_ENTRY;

// ---------------------------------------------------------------------------
// I/O types  (not in winnt.h; normally from ntdef.h / winternl.h)
// ---------------------------------------------------------------------------

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS    Status;
        PVOID       Pointer;
    };
    ULONG_PTR   Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    PVOID           ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG           Reserved);

// ---------------------------------------------------------------------------
// RTL_USER_PROCESS_PARAMETERS — minimal layout to reach StandardOutput.
//
// Offsets verified against phnt ntrtl.h:
//   x64: StandardOutput at 0x28  (4×ULONG=0x10, HANDLE=8 → ConsoleHandle@0x10,
//         ULONG ConsoleFlags@0x18, pad(4), StandardInput@0x20, StandardOutput@0x28)
//   x86: StandardOutput at 0x1C  (no padding; each HANDLE = 4 bytes)
// ---------------------------------------------------------------------------

typedef struct _RTL_USER_PROCESS_PARAMETERS_MIN {
    ULONG   MaximumLength;
    ULONG   Length;
    ULONG   Flags;
    ULONG   DebugFlags;
    HANDLE  ConsoleHandle;
    ULONG   ConsoleFlags;
    HANDLE  StandardInput;
    HANDLE  StandardOutput;
    HANDLE  StandardError;
} RTL_USER_PROCESS_PARAMETERS_MIN, *PRTL_USER_PROCESS_PARAMETERS_MIN;

// ---------------------------------------------------------------------------
// Debug output constants
// ---------------------------------------------------------------------------

#define DPFLTR_DEFAULT_ID               0UL
#define DPFLTR_INFO_LEVEL               3UL
#define THREAD_PRIORITY_TIME_CRITICAL   15

// ---------------------------------------------------------------------------
// Assert replacement — no CRT dependency
// ---------------------------------------------------------------------------

#ifdef _DEBUG
#define MHOOK_ASSERT(x) do { if (!(x)) { __debugbreak(); } } while(0)
#else
#define MHOOK_ASSERT(x) ((void)0)
#endif

// ---------------------------------------------------------------------------
// NT function declarations  (all exported from ntdll.dll)
// ---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

// Virtual memory
NTSTATUS NTAPI NtAllocateVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect);

NTSTATUS NTAPI NtFreeVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       FreeType);

NTSTATUS NTAPI NtProtectVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtect,
    PULONG      OldProtect);

NTSTATUS NTAPI NtQueryVirtualMemory(
    HANDLE                  ProcessHandle,
    PVOID                   BaseAddress,
    NT_MEMORYINFOCLASS      MemoryInformationClass,
    PVOID                   MemoryInformation,
    SIZE_T                  MemoryInformationLength,
    PSIZE_T                 ReturnLength);

// Instruction cache
NTSTATUS NTAPI NtFlushInstructionCache(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    SIZE_T      Length);

// System information
NTSTATUS NTAPI NtQuerySystemInformation(
    NT_SYSTEMINFOCLASS  SystemInformationClass,
    PVOID               SystemInformation,
    ULONG               SystemInformationLength,
    PULONG              ReturnLength);

// Handles
NTSTATUS NTAPI NtClose(HANDLE Handle);

// Threads
NTSTATUS NTAPI NtOpenThread(
    PHANDLE             ThreadHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PCLIENT_ID          ClientId);

NTSTATUS NTAPI NtSuspendThread(
    HANDLE  ThreadHandle,
    PULONG  PreviousSuspendCount);

NTSTATUS NTAPI NtResumeThread(
    HANDLE  ThreadHandle,
    PULONG  PreviousSuspendCount);

NTSTATUS NTAPI NtGetContextThread(
    HANDLE      ThreadHandle,
    PCONTEXT    ThreadContext);

NTSTATUS NTAPI NtSetContextThread(
    HANDLE      ThreadHandle,
    PCONTEXT    ThreadContext);

NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength);

NTSTATUS NTAPI NtSetInformationThread(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength);

NTSTATUS NTAPI NtGetNextThread(
    HANDLE      ProcessHandle,
    HANDLE      ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Flags,
    PHANDLE     NewThreadHandle);

NTSTATUS NTAPI NtDelayExecution(
    BOOLEAN         Alertable,
    PLARGE_INTEGER  DelayInterval);

NTSTATUS NTAPI NtTerminateProcess(
    HANDLE  ProcessHandle,
    NTSTATUS ExitStatus);

// I/O
NTSTATUS NTAPI NtWriteFile(
    HANDLE          FileHandle,
    HANDLE          Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID           ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID           Buffer,
    ULONG           Length,
    PLARGE_INTEGER  ByteOffset,
    PULONG          Key);

// Loader
NTSTATUS NTAPI LdrLoadDll(
    PWSTR           SearchPath,
    PULONG          DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID          *DllHandle);

NTSTATUS NTAPI LdrGetProcedureAddress(
    PVOID       DllHandle,
    PANSI_STRING ProcedureName,
    ULONG       ProcedureNumber,
    PVOID      *ProcedureAddress);

// Heap  (RtlProcessHeap is a macro above — not an ntdll export)
PVOID   NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
PVOID   NTAPI RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);

// Critical section  (RTL_CRITICAL_SECTION defined in winnt.h)
NTSTATUS NTAPI RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
NTSTATUS NTAPI RtlEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
NTSTATUS NTAPI RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);

// String conversion
NTSTATUS NTAPI RtlCharToInteger(PCSZ String, ULONG Base, PULONG Value);

// Debug output
ULONG NTAPI   DbgPrint(PCSTR Format, ...);
// vDbgPrintEx takes a fixed va_list argument (not variadic), so it uses the
// standard __stdcall (NTAPI) calling convention on x86 — verified by
// disassembling 32-bit ntdll.dll which ends the function with "retn 16".
ULONG NTAPI   vDbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, va_list arglist);

// ntdll exports its own _snprintf/_vsnprintf (used in preference to the CRT
// so that debug builds have no CRT dependency).
int __cdecl _snprintf(char *Buffer, size_t Count, const char *Format, ...);
int __cdecl _vsnprintf(char *Buffer, size_t Count, const char *Format, va_list ArgList);

#ifdef __cplusplus
}
#endif

#pragma comment(lib, "ntdll.lib")
// In debug builds, ntdll_extra.lib provides symbols absent from the SDK's
// ntdll.lib (_snprintf, RtlProcessHeap, etc.) so debug builds have no CRT
// dependency.
#ifdef _DEBUG
#pragma comment(lib, "ntdll_extra.lib")
#endif

#endif // NT_DEFS_H
