//
// nt_defs.h — NT-native type definitions and function declarations.
// Replaces <windows.h> across the mhook library. The only DLL dependency
// introduced here is ntdll.dll.
//

#ifndef NT_DEFS_H
#define NT_DEFS_H

//
// Pull in basic Windows types (CONTEXT, LARGE_INTEGER, ACCESS_MASK, MEM_*/PAGE_*
// constants, LDT_ENTRY, RTL_CRITICAL_SECTION, etc.).  <winnt.h> is pure type
// definitions — it adds zero import-library dependencies of its own.
//
#include <winnt.h>

//
// va_list support (compiler-intrinsic header, no DLL dependency).
//
#include <vadefs.h>
#include <stdarg.h>

//
// String/memory intrinsics.  In release builds (/Oi) these become compiler
// intrinsics with no DLL dependency.  Debug builds may reference UCRTBASE but
// never kernel32.
//
#include <string.h>

//
// INVALID_HANDLE_VALUE is normally in winbase.h (not winnt.h).
//
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif

// ---------------------------------------------------------------------------
// Basic NT types  (winnt.h already provides NTSTATUS, KPRIORITY, PBOOLEAN,
// PCSZ — guard everything to avoid redefinition errors)
// ---------------------------------------------------------------------------

#ifndef __NTSTATUS_DEFINED
#define __NTSTATUS_DEFINED
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#endif

#ifndef PNTSTATUS
typedef NTSTATUS *PNTSTATUS;
#endif

// KPRIORITY is in ntdef.h / winnt.h on Windows 10 SDK — guard it
#ifndef _KPRIORITY_DEFINED
#define _KPRIORITY_DEFINED
typedef LONG KPRIORITY;
#endif

// PCSZ is in winnt.h — guard it
#ifndef _PCSZ_DEFINED
#define _PCSZ_DEFINED
typedef CONST char *PCSZ;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED  ((NTSTATUS)0xC0000002L)
#endif

// Pseudo-handles
#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()   ((HANDLE)(LONG_PTR)-2)

// ---------------------------------------------------------------------------
// CLIENT_ID and TEB (minimal — only fields we access)
// ---------------------------------------------------------------------------

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

//
// NtCurrentTeb() — return pointer to the Thread Environment Block.
// The TEB address lives at GS:[0x30] on x64 and FS:[0x18] on x86.
// We only need ClientId (offset 0x40 on x64, 0x20 on x86), so define a
// minimal layout sufficient to reach it.
//
typedef struct _NT_TEB_MINIMAL {
#ifdef _M_X64
    BYTE        Reserved1[0x40];    // NT_TIB (0x38) + EnvironmentPointer (0x8) = 0x40
#else
    BYTE        Reserved1[0x20];    // NT_TIB (0x1C) + EnvironmentPointer (0x4) = 0x20
#endif
    CLIENT_ID   ClientId;
} NT_TEB_MINIMAL;

FORCEINLINE NT_TEB_MINIMAL* NtCurrentTeb_nt(void) {
#ifdef _M_X64
    return (NT_TEB_MINIMAL*)__readgsqword(0x30);
#else
    return (NT_TEB_MINIMAL*)__readfsdword(0x18);
#endif
}

#define NtCurrentClientId() (NtCurrentTeb_nt()->ClientId)

// ---------------------------------------------------------------------------
// OBJECT_ATTRIBUTES (needed for NtOpenThread prototype)
// ---------------------------------------------------------------------------

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

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
// NT memory constants not in winnt.h
// ---------------------------------------------------------------------------

#ifndef HEAP_ZERO_MEMORY
#define HEAP_ZERO_MEMORY    0x00000008UL
#endif

// ---------------------------------------------------------------------------
// Debug output constants
// ---------------------------------------------------------------------------

#define DPFLTR_DEFAULT_ID           0UL
#define DPFLTR_INFO_LEVEL           3UL
#define THREAD_PRIORITY_TIME_CRITICAL  15

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

// Heap
PVOID   NTAPI RtlProcessHeap(void);
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
ULONG __cdecl vDbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, va_list arglist);

#ifdef __cplusplus
}
#endif

#pragma comment(lib, "ntdll.lib")

#endif // NT_DEFS_H
