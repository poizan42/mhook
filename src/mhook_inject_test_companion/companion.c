// companion.c — mhook_inject_test_companion
//
// Minimal injection companion for Mhook_Inject tests.  Loaded into the
// target process by Mhook_Inject; writes a known marker string to the
// process stdout and returns.  No hooks are installed.
//
// _internal_Execute (from mhook_inject.lib in static builds, or from
// mhook_inject.dll in dynamic builds) calls Inject_WriteMarkerAndResume
// and then resumes all suspended threads.
//
// Only ntdll.dll is required.

#include "../nt_defs.h"
#include "../mhook-inject/mhook_inject.h"

void __cdecl Inject_WriteMarkerAndResume(MHOOK_INJECT_CONTEXT *ctx)
{
    PRTL_USER_PROCESS_PARAMETERS_MIN pp =
        (PRTL_USER_PROCESS_PARAMETERS_MIN)RtlCurrentPeb()->ProcessParameters;
    HANDLE hOut = pp ? pp->StandardOutput : NULL;

    if (hOut && hOut != INVALID_HANDLE_VALUE) {
        static CHAR marker[] = "MHOOK_INJECT_OK\n";
        IO_STATUS_BLOCK iosb;
        NtWriteFile(hOut, NULL, NULL, NULL, &iosb,
                    marker, sizeof(marker) - 1, NULL, NULL);
    }

    (void)ctx;  // SetHook/Unhook not used in this test
    // _internal_Execute calls ResumeOtherThreads() after this returns
}
