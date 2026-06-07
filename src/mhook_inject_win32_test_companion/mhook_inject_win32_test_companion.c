// mhook_inject_win32_test_companion.c — Win32 companion DLL for Mhook_Inject tests.
//
// Uses regular Win32 APIs (kernel32.dll) to write a marker to stdout.
// This DLL is only safe to load after process initialisation is complete.
// It is used with MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT to prove that the
// delayed-injection path can load a standard kernel32-dependent DLL.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../mhook-inject/mhook_inject.h"

void __cdecl Inject_Win32MarkerAndResume(MHOOK_INJECT_CONTEXT *ctx)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut && hOut != INVALID_HANDLE_VALUE) {
        static const char marker[] = "MHOOK_INJECT_WIN32_OK\n";
        DWORD written;
        WriteFile(hOut, marker, sizeof(marker) - 1, &written, NULL);
    }
    (void)ctx;
}
