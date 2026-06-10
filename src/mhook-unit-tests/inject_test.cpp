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

    // Mhook_Inject is synchronous: the injection function has run and the marker
    // has been written by the time Mhook_Inject returns.  Resume the main thread
    // so cmd.exe can run and exit, which closes its copy of the write pipe end.
    ASSERT_HRESULT_SUCCEEDED(hr)
        << "Mhook_Inject failed with HRESULT 0x" << std::hex << hr;
    ResumeThread(pi.hThread);

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

// ---------------------------------------------------------------------------
// Mhook_Inject deliberately requires a PROCESS_ALL_ACCESS target handle (a basic
// anti-exploitation guard).  A handle with only the minimal injection rights
// must be rejected.
// ---------------------------------------------------------------------------

TEST(MhookInjectTest, RejectsLimitedAccessHandle)
{
    // Create cmd.exe suspended.  We never resume it — injection must be refused
    // up front, before anything is written to the target.
    wchar_t cmdLine[] = L"cmd.exe";
    STARTUPINFOW si   = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    BOOL created = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                                  CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                  NULL, NULL, &si, &pi);
    if (!created)
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    // Derive a handle with only the rights a minimal injector would want — less
    // than PROCESS_ALL_ACCESS.
    HANDLE hLimited = NULL;
    BOOL dup = DuplicateHandle(GetCurrentProcess(), pi.hProcess,
                               GetCurrentProcess(), &hLimited,
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                               FALSE, 0);
    ASSERT_TRUE(dup) << "DuplicateHandle failed (" << GetLastError() << ")";

    // Otherwise-valid params, so the access guard is the only reason to reject.
    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = hLimited;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";

    HRESULT hr = Mhook_Inject(&params);

    EXPECT_EQ(hr, MHOOK_INJECT_E_ACCESS)
        << "Mhook_Inject must reject a target handle without PROCESS_ALL_ACCESS;"
        << " hr=0x" << std::hex << hr;

    CloseHandle(hLimited);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// ---------------------------------------------------------------------------
// Helper shared by both delayed tests
// ---------------------------------------------------------------------------

static bool RunDelayedInjectTest(const wchar_t *dllPath,
                                  const char    *functionName,
                                  const char    *expectedMarker)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return false;

    HANDLE hNullIn = CreateFileW(L"nul", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, NULL);

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
        return false;  // caller will GTEST_SKIP
    }

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = dllPath;
    params.FunctionName  = functionName;
    params.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;

    HRESULT hr = Mhook_Inject(&params);
    // Start the process: it will initialize, fire the entry-point hook, call
    // the injection function, and write the marker.
    ResumeThread(pi.hThread);

    CloseHandle(hWritePipe);

    std::string output;
    struct ReadState { HANDLE pipe; std::string *out; };
    ReadState rs = { hReadPipe, &output };
    struct ReadThread {
        static DWORD WINAPI Run(LPVOID p) {
            ReadState *rs = static_cast<ReadState *>(p);
            char tmp[1024]; DWORD got;
            while (ReadFile(rs->pipe, tmp, sizeof(tmp), &got, NULL) && got > 0)
                rs->out->append(tmp, got);
            return 0;
        }
    };
    HANDLE hRT = CreateThread(NULL, 0, ReadThread::Run, &rs, 0, NULL);
    if (hRT) { WaitForSingleObject(hRT, 15000); CloseHandle(hRT); }

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    EXPECT_HRESULT_SUCCEEDED(hr)
        << "Mhook_Inject (delayed) failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find(expectedMarker) != std::string::npos)
        << "Expected marker '" << expectedMarker << "' not found."
        << " Output: [" << output << "]";

    return created;
}

TEST(MhookInjectTest, DelayedExecutionWithWin32)
{
    // Static builds: companion is mhook_inject_test_companion.dll; the existing
    // ntdll-only Inject_WriteMarkerAndResume function tests the delay mechanism.
    //
    // Dynamic builds: companion is mhook_inject.dll; the target is
    // mhook_inject_win32_test_companion.dll — a regular Win32 DLL that imports
    // kernel32.dll and uses GetStdHandle/WriteFile.  This proves the delayed
    // path can load a standard Win32 DLL.
#ifdef MHOOK_STATIC
    // Static build: companion is mhook_inject_test_companion.dll (ntdll-only).
    // Inject_LoadWin32DllAndResume uses LdrLoadDll + LdrGetProcedureAddress to
    // dynamically load mhook_inject_win32_test_companion.dll at runtime — proving
    // that a static companion with no Win32 imports can still load Win32 DLLs
    // after the delay mechanism fires.
    constexpr const wchar_t *kDll    = L"mhook_inject_test_companion.dll";
    constexpr const char    *kFn     = "Inject_LoadWin32DllAndResume";
    constexpr const char    *kMarker = "MHOOK_INJECT_WIN32_OK";
#else
    constexpr const wchar_t *kDll    = L"mhook_inject_win32_test_companion.dll";
    constexpr const char    *kFn     = "Inject_Win32MarkerAndResume";
    constexpr const char    *kMarker = "MHOOK_INJECT_WIN32_OK";
#endif

    if (!RunDelayedInjectTest(kDll, kFn, kMarker)) {
        GTEST_SKIP() << "Could not create cmd.exe";
    }
}

// ---------------------------------------------------------------------------
// DelayedExecutionWithWin32RunningProcess
//
// Injects into a cmd.exe that is already running and initialized.
// MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT detects that the process is already
// initialized (needDelay = FALSE) and takes the immediate path: no
// entry-point hook is installed; the injection function is called directly
// from the injection thread.
// ---------------------------------------------------------------------------

TEST(MhookInjectTest, DelayedExecutionWithWin32RunningProcess)
{
#ifdef MHOOK_STATIC
    constexpr const wchar_t *kDll    = L"mhook_inject_test_companion.dll";
    constexpr const char    *kFn     = "Inject_LoadWin32DllAndResume";
#else
    constexpr const wchar_t *kDll    = L"mhook_inject_win32_test_companion.dll";
    constexpr const char    *kFn     = "Inject_Win32MarkerAndResume";
#endif
    constexpr const char *kMarker = "MHOOK_INJECT_WIN32_OK";

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    // stdin pipe: hold the write end open so cmd.exe blocks waiting for input
    // rather than exiting before we inject.
    HANDLE hStdinR, hStdinW;
    if (!CreatePipe(&hStdinR, &hStdinW, &sa, 0))
        GTEST_SKIP() << "CreatePipe (stdin) failed: " << GetLastError();

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        CloseHandle(hStdinR); CloseHandle(hStdinW);
        GTEST_SKIP() << "CreatePipe (stdout) failed: " << GetLastError();
    }

    wchar_t cmdLine[] = L"cmd.exe";
    STARTUPINFOW si   = { sizeof(si) };
    si.dwFlags        = STARTF_USESTDHANDLES;
    si.hStdInput      = hStdinR;
    si.hStdOutput     = hWritePipe;
    si.hStdError      = hWritePipe;

    PROCESS_INFORMATION pi = {};
    BOOL created = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hStdinR);
    if (!created) {
        CloseHandle(hStdinW); CloseHandle(hReadPipe); CloseHandle(hWritePipe);
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";
    }

    // Wait for cmd.exe to finish loader initialization so IsProcessInitialized()
    // returns TRUE inside the target, making needDelay = FALSE.
    Sleep(300);

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = kDll;
    params.FunctionName  = kFn;
    params.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;

    HRESULT hr = Mhook_Inject(&params);

    CloseHandle(hWritePipe);
    CloseHandle(hStdinW);   // EOF on stdin → cmd.exe exits naturally

    std::string output;
    struct ReadState { HANDLE pipe; std::string *out; };
    ReadState rs = { hReadPipe, &output };
    struct ReadThread {
        static DWORD WINAPI Run(LPVOID p) {
            ReadState *rs = static_cast<ReadState *>(p);
            char tmp[1024]; DWORD got;
            while (ReadFile(rs->pipe, tmp, sizeof(tmp), &got, NULL) && got > 0)
                rs->out->append(tmp, got);
            return 0;
        }
    };
    HANDLE hRT = CreateThread(NULL, 0, ReadThread::Run, &rs, 0, NULL);
    if (hRT) { WaitForSingleObject(hRT, 15000); CloseHandle(hRT); }

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    EXPECT_HRESULT_SUCCEEDED(hr)
        << "Mhook_Inject (running process) failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find(kMarker) != std::string::npos)
        << "Expected marker '" << kMarker << "' not found."
        << " Output: [" << output << "]";
}
