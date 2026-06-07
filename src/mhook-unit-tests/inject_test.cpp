// inject_test.cpp — basic Mhook_Inject functional test
//
// Verifies that Mhook_Inject can execute a function inside a freshly created,
// still-suspended cmd.exe before its main thread runs, without installing any
// hooks.  The injected function writes a marker string to the process stdout;
// the test reads the pipe and asserts the marker was received.

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <string>
#include "../mhook-inject/mhook_inject.h"

// ---------------------------------------------------------------------------
// Helpers (self-contained; not shared with uninit_test.cpp)
// ---------------------------------------------------------------------------

// Returns the directory containing the running test executable, with
// trailing backslash.  No MAX_PATH limit.
static std::wstring GetTestExeDir()
{
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(NULL, &buf[0], static_cast<DWORD>(buf.size()));
        if (n == 0) return L"";
        if (n < static_cast<DWORD>(buf.size())) { buf.resize(n); break; }
        buf.resize(buf.size() * 2);
    }
    auto slash = buf.rfind(L'\\');
    return (slash == std::wstring::npos) ? L"" : buf.substr(0, slash + 1);
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

TEST(MhookInjectTest, ExecutesInUninitializedProcess)
{
    // --- Create stdout/stderr pipe ---
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    ASSERT_TRUE(CreatePipe(&hReadPipe, &hWritePipe, &sa, 0));

    // Null stdin so cmd.exe gets EOF immediately and exits on its own.
    HANDLE hNullIn = CreateFileW(L"nul", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, NULL);

    // --- Create cmd.exe suspended ---
    wchar_t cmdLine[] = L"cmd.exe";
    STARTUPINFOW si   = { sizeof(si) };
    si.dwFlags        = STARTF_USESTDHANDLES;
    si.hStdInput      = hNullIn;
    si.hStdOutput     = hWritePipe;
    si.hStdError      = hWritePipe;

    PROCESS_INFORMATION pi = {};
    BOOL created = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
                                  CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                  NULL, NULL, &si, &pi);
    CloseHandle(hNullIn);

    if (!created) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";
    }

    // --- Call Mhook_Inject ---
    // DllPath is relative to the module containing Mhook_Inject:
    //   static builds  → Mhook_Inject is in the test exe, companion in same dir
    //   dynamic builds → Mhook_Inject is in mhook_inject.dll (also in same dir)
    // Either way, "mhook_inject_test_companion.dll" resolves correctly.
    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";

    HRESULT hr = Mhook_Inject(&params);

    // Mhook_Inject is synchronous: the marker has been written and cmd.exe's
    // main thread resumed by the time Mhook_Inject returns.
    ASSERT_HRESULT_SUCCEEDED(hr)
        << "Mhook_Inject failed with HRESULT 0x" << std::hex << hr;

    // --- Close write end in our process so ReadFile returns at EOF ---
    CloseHandle(hWritePipe);
    hWritePipe = NULL;

    // --- Read stdout with timeout, look for marker ---
    std::string output;
    struct ReadState { HANDLE pipe; std::string *out; };
    ReadState rs = { hReadPipe, &output };

    struct ReadThread {
        static DWORD WINAPI Run(LPVOID p) {
            ReadState *rs = static_cast<ReadState *>(p);
            char tmp[1024];
            DWORD got;
            while (ReadFile(rs->pipe, tmp, sizeof(tmp), &got, NULL) && got > 0)
                rs->out->append(tmp, got);
            return 0;
        }
    };

    HANDLE hReadThread = CreateThread(NULL, 0, ReadThread::Run, &rs, 0, NULL);
    if (hReadThread) {
        WaitForSingleObject(hReadThread, 15000);
        CloseHandle(hReadThread);
    }

    bool markerFound = (output.find("MHOOK_INJECT_OK") != std::string::npos);

    // --- Cleanup ---
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    EXPECT_TRUE(markerFound)
        << "Inject_WriteMarkerAndResume did not write the marker."
        << " hr=0x" << std::hex << hr
        << " Output: [" << output << "]";
}
