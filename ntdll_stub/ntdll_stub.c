// ntdll_stub.c — link-time-only stub for ntdll.dll exports absent from the
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
