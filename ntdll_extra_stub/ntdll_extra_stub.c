// ntdll_extra_stub.c — link-time-only stub for ntdll.dll exports absent from the
// Windows SDK's ntdll.lib.  This DLL is never shipped or loaded at runtime;
// the .def file sets LIBRARY ntdll.dll so the import lib records the real
// system DLL name as the load-time dependency.

#include "../nt_defs.h"

NTSTATUS NTAPI NtGetNextThread(
    HANDLE      ProcessHandle,
    HANDLE      ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Flags,
    PHANDLE     NewThreadHandle)
{
    (void)ProcessHandle; (void)ThreadHandle; (void)DesiredAccess;
    (void)HandleAttributes; (void)Flags; (void)NewThreadHandle;
    return STATUS_NOT_IMPLEMENTED;
}

ULONG __cdecl vDbgPrintEx(
    ULONG   ComponentId,
    ULONG   Level,
    PCSTR   Format,
    va_list arglist)
{
    (void)ComponentId; (void)Level; (void)Format; (void)arglist;
    return 0;
}

int __cdecl _snprintf(char *Buffer, size_t Count, const char *Format, ...)
{
    (void)Buffer; (void)Count; (void)Format;
    return 0;
}

int __cdecl _vsnprintf(char *Buffer, size_t Count, const char *Format, va_list ArgList)
{
    (void)Buffer; (void)Count; (void)Format; (void)ArgList;
    return 0;
}

void * __cdecl memset(void *Dst, int Val, size_t Size)
{
    (void)Dst; (void)Val; (void)Size;
    return Dst;
}

void * __cdecl memcpy(void *Dst, const void *Src, size_t Size)
{
    (void)Dst; (void)Src; (void)Size;
    return Dst;
}

void * __cdecl memmove(void *Dst, const void *Src, size_t Size)
{
    (void)Dst; (void)Src; (void)Size;
    return Dst;
}

int __cdecl memcmp(const void *Buf1, const void *Buf2, size_t Size)
{
    (void)Buf1; (void)Buf2; (void)Size;
    return 0;
}

