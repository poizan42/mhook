// proxy_entry.c — optional ready-made, ntdll-only entry point for the proxy exe.
//
// Kept in its own translation unit so a consumer who links mhook_inject_proxy.lib
// into their OWN executable can supply their own entry instead: this object is only
// pulled in when the linker is told /ENTRY:MhookInjectProxyEntry.
//
// The bundled mhook_inject_proxy.exe uses it.

#include "../nt_defs.h"
#include "../mhook-inject/mhook_inject.h"

HRESULT __cdecl MhookInjectProxyMain(void);

// Process entry (no CRT).  Run the proxy body, then exit with the injection HRESULT
// as the process exit status (the launcher reads it as a fallback if the completion
// event was somehow lost).
VOID __cdecl MhookInjectProxyEntry(void)
{
    HRESULT hr = MhookInjectProxyMain();
    RtlExitUserProcess((NTSTATUS)hr);
}
