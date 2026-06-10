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

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED      ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY            ((NTSTATUS)0xC0000017L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND            ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INVALID_IMAGE_FORMAT
#define STATUS_INVALID_IMAGE_FORMAT ((NTSTATUS)0xC000007BL)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT              ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#endif

// Common HRESULT values (normally from winerror.h)
#ifndef S_OK
#define S_OK        ((HRESULT)0x00000000L)
#define S_FALSE     ((HRESULT)0x00000001L)
#define E_FAIL      ((HRESULT)0x80004005L)
#define E_NOTIMPL   ((HRESULT)0x80004001L)
#define E_INVALIDARG ((HRESULT)0x80070057L)
#define E_OUTOFMEMORY ((HRESULT)0x8007000EL)
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

// Helper macro — standard phnt pattern for initialising OBJECT_ATTRIBUTES on the stack
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p,n,a,r,s) do { \
    (p)->Length                   = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory            = (r);                        \
    (p)->Attributes               = (a);                        \
    (p)->ObjectName               = (n);                        \
    (p)->SecurityDescriptor       = (s);                        \
    (p)->SecurityQualityOfService = NULL;                       \
} while(0)
#endif

// OBJ_CASE_INSENSITIVE — passed as Attributes to InitializeObjectAttributes
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040UL
#endif
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
// NtOpenFile / NtCreateFile option flags (winternl.h or ntioapi.h in WDK)
// ---------------------------------------------------------------------------

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020UL
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE         0x00000040UL
#endif
#ifndef FILE_GENERIC_READ
// winnt.h defines the building-block masks; combine them here.
#define FILE_GENERIC_READ  (STANDARD_RIGHTS_READ | FILE_READ_DATA | \
                            FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE)
#endif

// ---------------------------------------------------------------------------
// NtQueryInformationProcess information-class values (processthreadsapi.h / ntpsapi.h)
// ---------------------------------------------------------------------------

#ifndef ProcessWow64Information
#define ProcessWow64Information  26UL
#endif

#ifndef ProcessBasicInformation
#define ProcessBasicInformation  0UL
#endif

// Returned by NtQueryInformationProcess(ProcessBasicInformation).  We only need
// PebBaseAddress (to locate the target's PEB), but the full struct must be passed
// so the information length matches.
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

// ---------------------------------------------------------------------------
// NtQueryObject(ObjectBasicInformation) — used to read a handle's GRANTED
// access mask (the GrantedAccess field).  Only GrantedAccess is consumed, but
// the full struct must be declared so the query buffer is correctly sized.
// ---------------------------------------------------------------------------

#ifndef ObjectBasicInformation
#define ObjectBasicInformation  0UL
#endif

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG         Attributes;
    ACCESS_MASK   GrantedAccess;
    ULONG         HandleCount;
    ULONG         PointerCount;
    ULONG         PagedPoolCharge;
    ULONG         NonPagedPoolCharge;
    ULONG         Reserved[3];
    ULONG         NameInfoSize;
    ULONG         TypeInfoSize;
    ULONG         SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

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
// PEB loader data — minimal layout to walk InMemoryOrderModuleList.
//
// When walking PEB.Ldr->InMemoryOrderModuleList each LIST_ENTRY flink/blink
// points to the InMemoryOrderLinks field of an LDR_DATA_TABLE_ENTRY.  The MIN
// struct is laid out starting from InMemoryOrderLinks so that
// CONTAINING_RECORD with InMemoryOrderLinks as the member works correctly.
//
// Full offsets from InMemoryOrderLinks (= offset 0 in MIN struct):
//   x64: Reserved2@16  DllBase@32  EntryPoint@40  SizeOfImage@48
//        FullDllName@56  BaseDllName@72
//   x86: Reserved2@8   DllBase@16  EntryPoint@20  SizeOfImage@24
//        FullDllName@28  BaseDllName@36
// ---------------------------------------------------------------------------

typedef struct _PEB_LDR_DATA_MIN {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
} PEB_LDR_DATA_MIN, *PPEB_LDR_DATA_MIN;

typedef struct _LDR_DATA_TABLE_ENTRY_MIN {
    LIST_ENTRY      InMemoryOrderLinks;  // offset 0 in this struct
    PVOID           Reserved2[2];        // InInitializationOrderLinks (LIST_ENTRY)
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
} LDR_DATA_TABLE_ENTRY_MIN, *PLDR_DATA_TABLE_ENTRY_MIN;

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
    MemoryMappedFileInformation     = 2,
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

// Virtual memory — remote-process variants
NTSTATUS NTAPI NtWriteVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToWrite,
    PSIZE_T     NumberOfBytesWritten);

NTSTATUS NTAPI NtReadVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToRead,
    PSIZE_T     NumberOfBytesRead);

// Thread creation in a remote (or current) process
//   CreateFlags: 0 = run immediately, 1 = CREATE_SUSPENDED
NTSTATUS NTAPI NtCreateThreadEx(
    PHANDLE             ThreadHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    HANDLE              ProcessHandle,
    PVOID               StartRoutine,
    PVOID               Argument,
    ULONG               CreateFlags,
    SIZE_T              ZeroBits,
    SIZE_T              StackSize,
    SIZE_T              MaximumStackSize,
    PVOID               AttributeList);

// Wait for a single kernel object
NTSTATUS NTAPI NtWaitForSingleObject(
    HANDLE          Handle,
    BOOLEAN         Alertable,
    PLARGE_INTEGER  Timeout);

// File I/O
NTSTATUS NTAPI NtOpenFile(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions);

NTSTATUS NTAPI NtReadFile(
    HANDLE              FileHandle,
    HANDLE              Event,
    PIO_APC_ROUTINE     ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PVOID               Buffer,
    ULONG               Length,
    PLARGE_INTEGER      ByteOffset,
    PULONG              Key);

// Process information
//   ProcessWow64Information (class 26): returns PVOID; non-NULL means WOW64 (32-bit process)
NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE      ProcessHandle,
    ULONG       ProcessInformationClass,
    PVOID       ProcessInformation,
    ULONG       ProcessInformationLength,
    PULONG      ReturnLength);

// Object query — used to read a handle's granted access (ObjectBasicInformation)
NTSTATUS NTAPI NtQueryObject(
    HANDLE      Handle,
    ULONG       ObjectInformationClass,
    PVOID       ObjectInformation,
    ULONG       ObjectInformationLength,
    PULONG      ReturnLength);

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
// RtlReAllocateHeap — resize a heap block in place or by moving it.
//   HeapHandle  : heap owning the block (e.g. RtlProcessHeap())
//   Flags       : HEAP_* flags (0 for defaults)
//   BaseAddress : existing block to resize — MUST be a pointer previously
//                 returned by RtlAllocateHeap / RtlReAllocateHeap.
//                 NOTE: passing NULL does NOT behave like RtlAllocateHeap;
//                 RtlpReAllocateHeapInternal detects NULL, sets last-error to
//                 success, and returns NULL — i.e. it silently reports failure.
//                 Use RtlAllocateHeap for the initial allocation.
//   Size        : new size in bytes
//   Returns NULL on failure; original block is unchanged.
PVOID   NTAPI RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);

// Critical section  (RTL_CRITICAL_SECTION defined in winnt.h)
NTSTATUS NTAPI RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
NTSTATUS NTAPI RtlEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
NTSTATUS NTAPI RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);

// String conversion
NTSTATUS NTAPI RtlCharToInteger(PCSZ String, ULONG Base, PULONG Value);

// Debug output
ULONG NTAPI   DbgPrint(PCSTR Format, ...);
// vDbgPrintEx — documented at:
//   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-vdbgprintex
// The format parameter is PCCH (const char*, no null-termination SAL annotation) per the
// WDM docs.  The NTAPI (__stdcall) calling convention is confirmed by the x86 decorated
// export name _vDbgPrintEx@16 in ntdll.dll (4 args × 4 bytes = 16 bytes of arguments).
ULONG NTAPI   vDbgPrintEx(ULONG ComponentId, ULONG Level, PCCH Format, va_list arglist);

// ntdll exports its own _snprintf/_vsnprintf (used in preference to the CRT
// so that debug builds have no CRT dependency).
int __cdecl _snprintf(char *Buffer, size_t Count, const char *Format, ...);
int __cdecl _vsnprintf(char *Buffer, size_t Count, const char *Format, va_list ArgList);

// x64 SEH frame handler — called by OS exception dispatch for __try/__except/
// __finally.  ntdll.dll (x64) exports this; ntdll.lib omits the entry.
// ntdll_extra_stub.vcxproj provides the import lib stub for ntdll-only binaries.
// x86 uses frame-based SEH and never calls this symbol.
#ifdef _M_X64
EXCEPTION_DISPOSITION __cdecl __C_specific_handler(
    EXCEPTION_RECORD    *ExceptionRecord,
    void                *EstablisherFrame,
    CONTEXT             *ContextRecord,
    DISPATCHER_CONTEXT  *DispatcherContext);
#endif

#ifdef __cplusplus
}
#endif

#pragma comment(lib, "ntdll.lib")

#endif // NT_DEFS_H
