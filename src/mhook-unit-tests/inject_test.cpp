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
#include <cwchar>
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
// Dynamic builds embed a message-table resource in mhook_inject.dll so the
// MHOOK_INJECT_E_* HRESULTs are retrievable with FormatMessage.  (Static builds
// carry no resource — compiled out below.)
// ---------------------------------------------------------------------------

#ifndef MHOOK_STATIC
TEST(MhookInjectTest, ErrorMessagesAreFormattable)
{
    HMODULE h = GetModuleHandleW(L"mhook_inject.dll");
    ASSERT_NE(h, nullptr) << "mhook_inject.dll not loaded (" << GetLastError() << ")";

    WCHAR buf[256] = {};
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
                             h, (DWORD)MHOOK_INJECT_E_ACCESS, 0, buf, ARRAYSIZE(buf), NULL);
    EXPECT_GT(n, 0u)
        << "FormatMessage(MHOOK_INJECT_E_ACCESS) failed (" << GetLastError() << ")";
    EXPECT_NE(wcsstr(buf, L"PROCESS_ALL_ACCESS"), nullptr)
        << "unexpected message text";
}

// Runtime proof that the inject module's __try/__except actually catches a fault.
// The self-test lives in mhook_inject.dll, so SEH dispatch uses THAT module's
// language handler — on x86 the self-provided _except_handler3 + SafeSEH load
// config (mhook_seh3.lib), on x64 ntdll's __C_specific_handler — not the CRT
// handler of this (normal-CRT) test exe.  This is the end-to-end check that the
// ntdll-only x86 SEH support works, not merely that it links / is SafeSEH-marked.
TEST(MhookInjectTest, InjectModuleSehCatchesFault)
{
    HMODULE h = GetModuleHandleW(L"mhook_inject.dll");
    ASSERT_NE(h, nullptr) << "mhook_inject.dll not loaded (" << GetLastError() << ")";

    typedef int (__cdecl *SehSelfTestFn)(void);
    auto fn = reinterpret_cast<SehSelfTestFn>(GetProcAddress(h, "MhookInjectSehSelfTest"));
    ASSERT_NE(fn, nullptr) << "MhookInjectSehSelfTest not exported (" << GetLastError() << ")";

    EXPECT_EQ(fn(), 1) << "__except did not catch the access violation in mhook_inject.dll";
}
#endif

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

    // Synchronous + DELAY_UNTIL_INIT now BLOCKS until the injection function has
    // returned.  For a suspended target the entry-point hook fires only once the
    // main thread runs, so resume it on a helper thread — after a delay long
    // enough for the injection thread to install the hook first (it parks on the
    // completion event meanwhile).
    struct ResumeCtx { HANDLE th; };
    ResumeCtx rc = { pi.hThread };
    struct Resumer {
        static DWORD WINAPI Run(LPVOID p) {
            Sleep(500);
            ResumeThread(((ResumeCtx *)p)->th);
            return 0;
        }
    };
    HANDLE hResume = CreateThread(NULL, 0, Resumer::Run, &rc, 0, NULL);

    HRESULT hr = Mhook_Inject(&params);

    if (hResume) { WaitForSingleObject(hResume, 5000); CloseHandle(hResume); }
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

// ===========================================================================
// Subtask 1: synchronous DELAY blocking + async completion (Event / IoStatusBlock)
// ===========================================================================

namespace {

// Drain a pipe to EOF (all write ends closed) or until timeoutMs elapses.
std::string DrainPipe(HANDLE hReadPipe, DWORD timeoutMs)
{
    std::string output;
    struct RS { HANDLE pipe; std::string *out; } rs = { hReadPipe, &output };
    struct RT {
        static DWORD WINAPI Run(LPVOID p) {
            RS *rs = (RS *)p; char tmp[1024]; DWORD got;
            while (ReadFile(rs->pipe, tmp, sizeof(tmp), &got, NULL) && got > 0)
                rs->out->append(tmp, got);
            return 0;
        }
    };
    HANDLE h = CreateThread(NULL, 0, RT::Run, &rs, 0, NULL);
    if (h) { WaitForSingleObject(h, timeoutMs); CloseHandle(h); }
    return output;
}

// Create cmd.exe suspended with stdout/stderr redirected to a fresh pipe.
bool CreateSuspendedCmd(PROCESS_INFORMATION *pi, HANDLE *hReadPipe, HANDLE *hWritePipe)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(hReadPipe, hWritePipe, &sa, 0)) return false;

    HANDLE hNullIn = CreateFileW(L"nul", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, NULL);
    wchar_t cmdLine[] = L"cmd.exe";
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = hNullIn;
    si.hStdOutput = *hWritePipe;
    si.hStdError  = *hWritePipe;

    BOOL created = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
                                  CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                  NULL, NULL, &si, pi);
    CloseHandle(hNullIn);
    if (!created) {
        CloseHandle(*hReadPipe); CloseHandle(*hWritePipe);
        *hReadPipe = *hWritePipe = NULL;
        return false;
    }
    return true;
}

// Resume the main thread after a delay long enough for the injection thread to
// install the entry-point hook (the delayed path's hook fires on resume).
DWORD WINAPI DelayedResumeProc(LPVOID p)
{
    Sleep(500);
    ResumeThread((HANDLE)p);
    return 0;
}

} // namespace

// Synchronous + DELAY_UNTIL_INIT must block until the injection function has run.
// Proven by peeking the pipe the instant Mhook_Inject returns: the marker is
// already there (the fn wrote it before completion was signalled).
TEST(MhookInjectTest, SyncDelayBlocksUntilHookFires)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;

    HANDLE hResume = CreateThread(NULL, 0, DelayedResumeProc, pi.hThread, 0, NULL);
    HRESULT hr = Mhook_Inject(&params);
    if (hResume) { WaitForSingleObject(hResume, 5000); CloseHandle(hResume); }

    // The injection fn writes the marker before completion is signalled, so the
    // instant Mhook_Inject returns the marker must already be in the pipe.
    bool markerBeforeDrain = false;
    if (SUCCEEDED(hr)) {
        char peek[256]; DWORD got = 0, avail = 0;
        if (PeekNamedPipe(hRead, peek, sizeof(peek) - 1, &got, &avail, NULL) && got > 0)
            markerBeforeDrain =
                (std::string(peek, got).find("MHOOK_INJECT_OK") != std::string::npos);
    }

    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "sync+delay inject failed: 0x" << std::hex << hr;
    EXPECT_TRUE(markerBeforeDrain)
        << "marker not present when Mhook_Inject returned — it did not block."
        << " Output: [" << output << "]";
}

// A custom (short) TimeoutMs is honoured: sync + DELAY_UNTIL_INIT into a
// suspended cmd.exe that is never resumed.  The bootstrap thread installs the
// entry-point hook and exits, but the hook can never fire (the main thread stays
// suspended), so the completion wait runs out the budget and Mhook_Inject returns
// MHOOK_INJECT_E_TIMEOUT — fast (≈1.5 s), proving the configured value was used
// rather than the 30 s default.
TEST(MhookInjectTest, CustomTimeoutFires)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;
    params.TimeoutMs     = 1500;

    ULONGLONG t0 = GetTickCount64();
    HRESULT hr = Mhook_Inject(&params);          // never resumed → hook never fires
    ULONGLONG elapsed = GetTickCount64() - t0;

    CloseHandle(hWrite);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_EQ(hr, MHOOK_INJECT_E_TIMEOUT)
        << "expected timeout; hr=0x" << std::hex << hr;
    // Comfortably under the 30 s default, and not instant — proves the 1.5 s budget
    // drove it (a kernel-timer wait, so accurate even under heavy parallel load).
    EXPECT_LT(elapsed, 15000u) << "took " << elapsed << " ms (30 s default not honoured?)";
    EXPECT_GE(elapsed, 1000u)  << "returned too soon (" << elapsed << " ms)";
}

// A would-be-negative TimeoutMs (sign bit set, not INFINITE) is rejected up front
// with MHOOK_INJECT_E_PARAMS, before any injection takes place.
TEST(MhookInjectTest, RejectsNegativeTimeout)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    // Full-access handle + valid function selection, so TimeoutMs is the only fault.
    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.TimeoutMs     = 0x80000000u;          // most-negative; not INFINITE

    HRESULT hr = Mhook_Inject(&params);

    CloseHandle(hWrite);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_EQ(hr, MHOOK_INJECT_E_PARAMS)
        << "negative TimeoutMs must be rejected; hr=0x" << std::hex << hr;
}

// TimeoutMs = INFINITE disables the timeout (the wait is passed NULL).  The
// immediate (non-delay) injection still completes normally and writes its marker.
TEST(MhookInjectTest, InfiniteTimeoutDisablesTimeout)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.TimeoutMs     = INFINITE;

    HRESULT hr = Mhook_Inject(&params);          // synchronous; waits with no timeout
    if (SUCCEEDED(hr)) ResumeThread(pi.hThread);

    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "infinite-timeout inject failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not written; Output: [" << output << "]";
}

// ASYNC, all completion outputs NULL: returns immediately; the fn still runs
// (immediate path) on the injection thread and writes the marker.
TEST(MhookInjectTest, AsyncFireAndForget)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.Flags         = MHOOK_INJECT_FLAG_ASYNC;

    HRESULT hr = Mhook_Inject(&params);

    // Fire-and-forget has no completion signal — poll the pipe until the
    // background injection thread has written the marker.  cmd.exe stays
    // suspended (the injection thread writes via its inherited stdout handle),
    // so this does not depend on the target running or exiting.
    bool markerFound = false;
    for (int i = 0; i < 200 && !markerFound; ++i) {
        char peek[512]; DWORD got = 0, avail = 0;
        if (PeekNamedPipe(hRead, peek, sizeof(peek) - 1, &got, &avail, NULL) && got > 0)
            markerFound =
                (std::string(peek, got).find("MHOOK_INJECT_OK") != std::string::npos);
        if (!markerFound) Sleep(50);
    }

    CloseHandle(hWrite);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "async fire-and-forget failed: 0x" << std::hex << hr;
    EXPECT_TRUE(markerFound) << "background injection did not write the marker";
}

// ASYNC + DELAY_UNTIL_INIT + Event: Mhook_Inject returns immediately; the event
// is signalled once the (delayed) injection fn returns.
TEST(MhookInjectTest, AsyncWithEvent)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    HANDLE hEvent = CreateEventW(NULL, FALSE /*auto-reset*/, FALSE, NULL);
    ASSERT_NE(hEvent, (HANDLE)NULL);

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.Flags         = MHOOK_INJECT_FLAG_ASYNC | MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;
    params.Event         = hEvent;

    HANDLE hResume = CreateThread(NULL, 0, DelayedResumeProc, pi.hThread, 0, NULL);
    HRESULT hr = Mhook_Inject(&params);          // returns immediately (async)
    DWORD waited = WaitForSingleObject(hEvent, 15000);

    if (hResume) { WaitForSingleObject(hResume, 5000); CloseHandle(hResume); }
    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead); CloseHandle(hEvent);

    EXPECT_HRESULT_SUCCEEDED(hr) << "async inject failed: 0x" << std::hex << hr;
    EXPECT_EQ(waited, (DWORD)WAIT_OBJECT_0) << "completion event was not signalled";
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// ASYNC + Event + IoStatusBlock (immediate path): the target writes the result
// NTSTATUS back into the caller's IoStatusBlock across the process boundary.
TEST(MhookInjectTest, AsyncIoStatusBlockGetsStatus)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ASSERT_NE(hEvent, (HANDLE)NULL);

    IO_STATUS_BLOCK iosb;
    iosb.Status      = (NTSTATUS)0x7fffffffL;  // sentinel: neither PENDING nor SUCCESS
    iosb.Information = 0;

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.Flags         = MHOOK_INJECT_FLAG_ASYNC;   // immediate path: fn runs on the injection thread
    params.Event         = hEvent;
    params.IoStatusBlock = &iosb;

    HRESULT hr = Mhook_Inject(&params);
    DWORD waited = WaitForSingleObject(hEvent, 15000);
    NTSTATUS finalStatus = iosb.Status;

    ResumeThread(pi.hThread);
    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead); CloseHandle(hEvent);

    EXPECT_HRESULT_SUCCEEDED(hr) << "async inject failed: 0x" << std::hex << hr;
    EXPECT_EQ(waited, (DWORD)WAIT_OBJECT_0) << "completion event was not signalled";
    EXPECT_EQ(finalStatus, (NTSTATUS)0)
        << "IoStatusBlock.Status not updated to STATUS_SUCCESS; got 0x" << std::hex << finalStatus;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// ASYNC + ApcRoutine (+ IoStatusBlock): the target queues a user APC to the
// calling thread.  The APC fires when this thread enters an alertable wait, with
// the caller's ApcContext and the (now-written) IoStatusBlock.
namespace {
volatile LONG    g_apcRan    = 0;
PVOID            g_apcCtx     = nullptr;
PIO_STATUS_BLOCK g_apcIosb    = nullptr;
NTSTATUS         g_apcStatus  = 0;

VOID NTAPI TestApcRoutine(PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    g_apcCtx    = ctx;
    g_apcIosb   = iosb;
    g_apcStatus = iosb ? iosb->Status : (NTSTATUS)0xBADBADL;
    InterlockedExchange(&g_apcRan, 1);
    (void)reserved;
}
} // namespace

TEST(MhookInjectTest, AsyncApcRuns)
{
    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedCmd(&pi, &hRead, &hWrite))
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";

    IO_STATUS_BLOCK iosb;
    iosb.Status = (NTSTATUS)0x7fffffffL;
    iosb.Information = 0;
    g_apcRan = 0; g_apcCtx = nullptr; g_apcIosb = nullptr;
    g_apcStatus = (NTSTATUS)0x7fffffffL;
    void *kCtx = (void *)(ULONG_PTR)0x00C0FFEEu;

    MHOOK_INJECT_PARAMS params = {};
    params.Size          = sizeof(params);
    params.TargetProcess = pi.hProcess;
    params.DllPath       = L"mhook_inject_test_companion.dll";
    params.FunctionName  = "Inject_WriteMarkerAndResume";
    params.Flags         = MHOOK_INJECT_FLAG_ASYNC;   // immediate path: fn runs on the injection thread
    params.ApcRoutine    = TestApcRoutine;
    params.ApcContext    = kCtx;
    params.IoStatusBlock = &iosb;

    HRESULT hr = Mhook_Inject(&params);

    // The APC is queued to THIS (the calling) thread; deliver it via alertable waits.
    for (int i = 0; i < 200 && !g_apcRan; ++i)
        SleepEx(50, TRUE);

    bool             ran       = (g_apcRan != 0);
    PVOID            ctx       = g_apcCtx;
    PIO_STATUS_BLOCK iosbArg   = g_apcIosb;
    NTSTATUS         apcStatus = g_apcStatus;

    CloseHandle(hWrite);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "async inject failed: 0x" << std::hex << hr;
    EXPECT_TRUE(ran) << "APC did not run on the calling thread";
    EXPECT_EQ(ctx, kCtx) << "APC received wrong ApcContext";
    EXPECT_EQ(iosbArg, &iosb) << "APC received wrong IoStatusBlock pointer";
    EXPECT_EQ(apcStatus, (NTSTATUS)0)
        << "APC saw non-success IoStatusBlock.Status: 0x" << std::hex << apcStatus;
}

// ===========================================================================
// Cross-architecture injection (64-bit injector -> 32-bit WOW64 target).
// These run only from the x64 test exe; the 32->64 direction stays E_NOTIMPL.
// ===========================================================================

namespace {
// Directory holding the x86 build artifacts mirroring this x64 test exe.  The
// build copies the x86 companion, mhook.dll and mhook_inject.dll together into
// mhook-unit-tests\Win32\<config>\, so swapping the "\x64\" path component for
// "\Win32\" yields a directory with all three.  "" if not an x64/<config> layout.
std::wstring SiblingX86Dir()
{
    std::wstring dir = GetTestExeDir();              // trailing backslash
    const std::wstring from = L"\\x64\\", to = L"\\Win32\\";
    size_t pos = dir.rfind(from);
    if (pos == std::wstring::npos) return L"";
    dir.replace(pos, from.size(), to);
    return dir;
}

bool FileExists(const std::wstring &p)
{
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// The 32-bit cmd.exe (%WINDIR%\SysWOW64\cmd.exe).  A 64-bit process referencing
// SysWOW64 is NOT file-system-redirected, so this is the real 32-bit binary.
bool Get32BitCmdPath(std::wstring &out)
{
    wchar_t win[MAX_PATH];
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    out = std::wstring(win) + L"\\SysWOW64\\cmd.exe";
    return FileExists(out);
}

// Create a suspended process from an explicit exe path, stdout/stderr -> a pipe.
bool CreateSuspendedExe(const wchar_t *exePath, PROCESS_INFORMATION *pi,
                        HANDLE *hRead, HANDLE *hWrite)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(hRead, hWrite, &sa, 0)) return false;
    HANDLE hNullIn = CreateFileW(L"nul", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, NULL);
    std::wstring cmdline = exePath;                  // mutable buffer for CreateProcessW
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = hNullIn;
    si.hStdOutput = *hWrite;
    si.hStdError  = *hWrite;
    BOOL ok = CreateProcessW(exePath, &cmdline[0], NULL, NULL, TRUE,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, pi);
    CloseHandle(hNullIn);
    if (!ok) {
        CloseHandle(*hRead); CloseHandle(*hWrite);
        *hRead = *hWrite = NULL;
        return false;
    }
    return true;
}
} // namespace

#ifdef _M_X64

// Fill the common cross-arch params (x86 companion + DllPath form).  For dynamic
// builds the x86 mhook.dll is required (the x86 mhook_inject.dll companion ships
// beside it).  Returns false (with a skip reason) if the x86 artifacts are absent.
#ifdef MHOOK_STATIC
#  define CROSS_SET_MHOOK(p, mh)   ((void)0)
#else
#  define CROSS_SET_MHOOK(p, mh)   ((p).MhookDllPath = (mh).c_str())
#endif

// Sync immediate: inject the x86 companion into a suspended 32-bit cmd.exe and
// confirm the injected function writes its marker to the target's stdout.
TEST(MhookInjectTest, CrossArch_InjectsInto32BitTarget)
{
    std::wstring x86dir = SiblingX86Dir();
    if (x86dir.empty()) GTEST_SKIP() << "test exe is not under .../x64/<config>/";
    std::wstring companion = x86dir + L"mhook_inject_test_companion.dll";
    std::wstring mhookdll  = x86dir + L"mhook.dll";
    if (!FileExists(companion)) GTEST_SKIP() << "x86 companion not built";

    std::wstring cmd32;
    if (!Get32BitCmdPath(cmd32)) GTEST_SKIP() << "no SysWOW64\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd32.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 32-bit cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    CROSS_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);
    if (SUCCEEDED(hr)) ResumeThread(pi.hThread);

    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "cross 64->32 inject failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Async + Event: cross-arch completion via a duplicated event (handle-based, so it
// works across the bitness boundary, unlike IoStatusBlock/APC).
TEST(MhookInjectTest, CrossArch_AsyncEventInto32BitTarget)
{
    std::wstring x86dir = SiblingX86Dir();
    if (x86dir.empty()) GTEST_SKIP() << "test exe is not under .../x64/<config>/";
    std::wstring companion = x86dir + L"mhook_inject_test_companion.dll";
    std::wstring mhookdll  = x86dir + L"mhook.dll";
    if (!FileExists(companion)) GTEST_SKIP() << "x86 companion not built";

    std::wstring cmd32;
    if (!Get32BitCmdPath(cmd32)) GTEST_SKIP() << "no SysWOW64\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd32.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 32-bit cmd.exe (" << GetLastError() << ")";

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ASSERT_NE(hEvent, (HANDLE)NULL);

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_ASYNC;
    p.Event         = hEvent;
    CROSS_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);
    DWORD waited = WaitForSingleObject(hEvent, 15000);

    ResumeThread(pi.hThread);
    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead); CloseHandle(hEvent);

    EXPECT_HRESULT_SUCCEEDED(hr) << "cross async inject failed: 0x" << std::hex << hr;
    EXPECT_EQ(waited, (DWORD)WAIT_OBJECT_0) << "completion event was not signalled";
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Sync + DELAY_UNTIL_INIT: the entry-point hook (x86, target-side) fires once the
// 32-bit main thread runs; the caller reads the target's 32-bit PEB init state.
TEST(MhookInjectTest, CrossArch_DelayInto32BitTarget)
{
    std::wstring x86dir = SiblingX86Dir();
    if (x86dir.empty()) GTEST_SKIP() << "test exe is not under .../x64/<config>/";
    std::wstring companion = x86dir + L"mhook_inject_test_companion.dll";
    std::wstring mhookdll  = x86dir + L"mhook.dll";
    if (!FileExists(companion)) GTEST_SKIP() << "x86 companion not built";

    std::wstring cmd32;
    if (!Get32BitCmdPath(cmd32)) GTEST_SKIP() << "no SysWOW64\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd32.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 32-bit cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;
    CROSS_SET_MHOOK(p, mhookdll);

    HANDLE hResume = CreateThread(NULL, 0, DelayedResumeProc, pi.hThread, 0, NULL);
    HRESULT hr = Mhook_Inject(&p);
    if (hResume) { WaitForSingleObject(hResume, 5000); CloseHandle(hResume); }

    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "cross delayed inject failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Cross-arch async + IoStatusBlock: a caller-side watcher thread (the 32-bit target
// can't write the 64-bit caller's IOSB) fills it with the injection NTSTATUS and
// signals the Event.  By the time the Event fires, the IOSB is populated.
TEST(MhookInjectTest, CrossArch_AsyncIoStatusBlockInto32BitTarget)
{
    std::wstring x86dir = SiblingX86Dir();
    if (x86dir.empty()) GTEST_SKIP() << "test exe is not under .../x64/<config>/";
    std::wstring companion = x86dir + L"mhook_inject_test_companion.dll";
    std::wstring mhookdll  = x86dir + L"mhook.dll";
    if (!FileExists(companion)) GTEST_SKIP() << "x86 companion not built";

    std::wstring cmd32;
    if (!Get32BitCmdPath(cmd32)) GTEST_SKIP() << "no SysWOW64\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd32.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 32-bit cmd.exe (" << GetLastError() << ")";

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ASSERT_NE(hEvent, (HANDLE)NULL);
    IO_STATUS_BLOCK iosb;
    iosb.Status = (NTSTATUS)0x7fffffffL; iosb.Information = 0;

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_ASYNC;
    p.Event         = hEvent;
    p.IoStatusBlock = &iosb;
    CROSS_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);
    DWORD waited = WaitForSingleObject(hEvent, 15000);
    NTSTATUS finalStatus = iosb.Status;

    ResumeThread(pi.hThread);
    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead); CloseHandle(hEvent);

    EXPECT_HRESULT_SUCCEEDED(hr) << "cross async inject failed: 0x" << std::hex << hr;
    EXPECT_EQ(waited, (DWORD)WAIT_OBJECT_0) << "completion event was not signalled";
    EXPECT_EQ(finalStatus, (NTSTATUS)0)
        << "IoStatusBlock.Status not updated to STATUS_SUCCESS; got 0x" << std::hex << finalStatus;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Cross-arch async + ApcRoutine: the watcher re-queues the user APC to the original
// calling thread (it runs in the next alertable wait, same as same-arch).
TEST(MhookInjectTest, CrossArch_AsyncApcInto32BitTarget)
{
    std::wstring x86dir = SiblingX86Dir();
    if (x86dir.empty()) GTEST_SKIP() << "test exe is not under .../x64/<config>/";
    std::wstring companion = x86dir + L"mhook_inject_test_companion.dll";
    std::wstring mhookdll  = x86dir + L"mhook.dll";
    if (!FileExists(companion)) GTEST_SKIP() << "x86 companion not built";

    std::wstring cmd32;
    if (!Get32BitCmdPath(cmd32)) GTEST_SKIP() << "no SysWOW64\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd32.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 32-bit cmd.exe (" << GetLastError() << ")";

    IO_STATUS_BLOCK iosb;
    iosb.Status = (NTSTATUS)0x7fffffffL; iosb.Information = 0;
    g_apcRan = 0; g_apcCtx = nullptr; g_apcIosb = nullptr;
    g_apcStatus = (NTSTATUS)0x7fffffffL;
    void *kCtx = (void *)(ULONG_PTR)0x00C0FFEEu;

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_ASYNC;
    p.ApcRoutine    = TestApcRoutine;
    p.ApcContext    = kCtx;
    p.IoStatusBlock = &iosb;
    CROSS_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);

    // The watcher queues the APC to THIS (calling) thread; deliver via alertable waits.
    for (int i = 0; i < 200 && !g_apcRan; ++i)
        SleepEx(50, TRUE);

    bool             ran       = (g_apcRan != 0);
    PVOID            ctx       = g_apcCtx;
    PIO_STATUS_BLOCK iosbArg   = g_apcIosb;
    NTSTATUS         apcStatus = g_apcStatus;

    CloseHandle(hWrite);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "cross async inject failed: 0x" << std::hex << hr;
    EXPECT_TRUE(ran) << "APC did not run on the calling thread";
    EXPECT_EQ(ctx, kCtx) << "APC received wrong ApcContext";
    EXPECT_EQ(iosbArg, &iosb) << "APC received wrong IoStatusBlock pointer";
    EXPECT_EQ(apcStatus, (NTSTATUS)0)
        << "APC saw non-success IoStatusBlock.Status: 0x" << std::hex << apcStatus;
}

// Cross-arch rejects the modes that can't work across the bitness boundary, and a
// wrong-architecture companion, each with MHOOK_INJECT_E_PARAMS.
TEST(MhookInjectTest, CrossArch_RejectsUnsupportedModes)
{
    std::wstring x86dir = SiblingX86Dir();
    if (x86dir.empty()) GTEST_SKIP() << "test exe is not under .../x64/<config>/";
    std::wstring companion = x86dir + L"mhook_inject_test_companion.dll";
    std::wstring mhookdll  = x86dir + L"mhook.dll";
    if (!FileExists(companion)) GTEST_SKIP() << "x86 companion not built";

    std::wstring cmd32;
    if (!Get32BitCmdPath(cmd32)) GTEST_SKIP() << "no SysWOW64\\cmd.exe";

    auto freshTarget = [&](PROCESS_INFORMATION *pi, HANDLE *r, HANDLE *w) -> bool {
        return CreateSuspendedExe(cmd32.c_str(), pi, r, w);
    };
    auto cleanup = [](PROCESS_INFORMATION *pi, HANDLE r, HANDLE w) {
        if (w) CloseHandle(w);
        TerminateProcess(pi->hProcess, 1);
        CloseHandle(pi->hProcess); CloseHandle(pi->hThread); if (r) CloseHandle(r);
    };

    // (a) FunctionPointer form is not allowed cross-arch (must name an x86 file).
    {
        PROCESS_INFORMATION pi = {}; HANDLE r = NULL, w = NULL;
        if (!freshTarget(&pi, &r, &w)) GTEST_SKIP() << "no 32-bit cmd";
        MHOOK_INJECT_PARAMS p = {};
        p.Size = sizeof(p); p.TargetProcess = pi.hProcess;
        p.FunctionPointer = (PVOID)&SiblingX86Dir;   // any VA in this x64 process
        HRESULT hr = Mhook_Inject(&p);
        cleanup(&pi, r, w);
        EXPECT_EQ(hr, MHOOK_INJECT_E_PARAMS) << "FunctionPointer form should be rejected cross-arch";
    }
    // (IoStatusBlock and ApcRoutine ARE supported cross-arch now — see the
    // CrossArch_Async* tests below — so they are no longer rejected here.)
#ifdef MHOOK_STATIC
    // (d) a wrong-architecture (x64) companion against a 32-bit target is rejected.
    // Static only: here DllPath IS the companion whose machine is validated.  In
    // dynamic builds the validated companion is the x86 mhook_inject.dll (derived
    // from MhookDllPath); DllPath is the user DLL, loaded by the target.
    {
        PROCESS_INFORMATION pi = {}; HANDLE r = NULL, w = NULL;
        if (!freshTarget(&pi, &r, &w)) GTEST_SKIP() << "no 32-bit cmd";
        std::wstring x64companion = GetTestExeDir() + L"mhook_inject_test_companion.dll";
        MHOOK_INJECT_PARAMS p = {};
        p.Size = sizeof(p); p.TargetProcess = pi.hProcess;
        p.DllPath = x64companion.c_str(); p.FunctionName = "Inject_WriteMarkerAndResume";
        HRESULT hr = Mhook_Inject(&p);
        cleanup(&pi, r, w);
        EXPECT_EQ(hr, MHOOK_INJECT_E_PARAMS) << "wrong-arch companion should be rejected";
    }
#endif
}

#else  // !_M_X64  — the 32-bit injector

// ===========================================================================
// Cross-architecture injection (32-bit WOW64 injector -> 64-bit target) via the
// native x64 proxy executable (mhook_inject_proxy.exe).
//
// The bundled proxy is self-contained / ntdll-only and uses static-link injection
// semantics, so it needs a STATIC-style x64 companion (one that exports
// _internal_Execute).  Those, plus the proxy itself, exist only in the x64 *static*
// configs (Debug/Release).  So these tests run from the x86 *static* configs reading
// the matching x64 static siblings; in the *Dynamic* x86 configs the proxy isn't
// present and they GTEST_SKIP.  (The no-proxy test runs everywhere.)
//
// Build order matters: the x64 proxy + x64 companion must be built before the x86
// tests run.  The default `.\build.ps1` builds all x64 configs before x86, so this
// is satisfied; a lone `.\build.ps1 -Arch x86` will leave these skipped.
// ===========================================================================

namespace {
// The x64 sibling of this x86 test's output dir (…\mhook-unit-tests\x64\<config>\),
// where the build copies the x64 test companion.  "" if not a Win32/<config> layout.
std::wstring SiblingX64Dir()
{
    std::wstring d = GetTestExeDir();
    size_t pos = d.rfind(L"\\Win32\\");
    if (pos == std::wstring::npos) return L"";
    d.replace(pos, 7, L"\\x64\\");      // "\Win32\" -> "\x64\"
    return d;
}

// The bundled x64 proxy exe in its own artifact tree, same config as this test.
std::wstring ProxyExePath()
{
    std::wstring d = GetTestExeDir();
    const std::wstring from = L"mhook-unit-tests\\Win32\\";
    size_t pos = d.rfind(from);
    if (pos == std::wstring::npos) return L"";
    d.replace(pos, from.size(), L"mhook_inject_proxy\\x64\\");
    return d + L"mhook_inject_proxy.exe";
}

// The native 64-bit cmd.exe via the Sysnative alias (a WOW64 process referencing
// Sysnative is NOT redirected to SysWOW64).
bool Get64BitCmdPath(std::wstring &out)
{
    wchar_t win[MAX_PATH];
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    out = std::wstring(win) + L"\\Sysnative\\cmd.exe";
    return FileExists(out);
}

// Resume the target after a delay sized for the PROXY delayed path: the proxy must
// be launched (RtlCreateUserProcess) + map the section + run its Mhook_Inject to
// install the entry-point hook before the target's main thread reaches the entry.
// That chain is longer than the same-arch case (DelayedResumeProc's 500 ms), so use a
// roomier delay to avoid resuming the suspended cmd before the hook is installed (it
// would otherwise initialise and self-exit on its NUL stdin before injection lands).
DWORD WINAPI DelayedResumeProcProxy(LPVOID p)
{
    Sleep(2000);
    ResumeThread((HANDLE)p);
    return 0;
}

// Common skip preamble: locate the proxy exe bundle + the x64 companion (and, for
// dynamic builds, the x64 mhook.dll for MhookDllPath), or skip with a reason.
bool LocateProxyAssets(std::wstring &proxy, std::wstring &companion,
                       std::wstring &mhookdll, std::string &why)
{
    proxy = ProxyExePath();
    if (proxy.empty() || !FileExists(proxy)) {
        why = "x64 proxy not built for this config (run .\\build.ps1 — x64 builds before x86)";
        return false;
    }
    std::wstring x64dir = SiblingX64Dir();
    if (x64dir.empty()) { why = "test exe is not under .../Win32/<config>/"; return false; }
    companion = x64dir + L"mhook_inject_test_companion.dll";
    if (!FileExists(companion)) { why = "x64 companion not built"; return false; }
    mhookdll = x64dir + L"mhook.dll";   // only needed/used on dynamic builds
    return true;
}
} // namespace

// On dynamic builds the x64 companion is dynamic-style, so the proxy's Mhook_Inject
// needs the x64 mhook.dll via MhookDllPath; static builds use a self-contained
// companion and ignore it.  Mirrors the 64->32 CROSS_SET_MHOOK.
#ifdef MHOOK_STATIC
#  define CROSS32_SET_MHOOK(p, mh)   ((void)0)
#else
#  define CROSS32_SET_MHOOK(p, mh)   ((p).MhookDllPath = (mh).c_str())
#endif

// No proxy deployed -> the expected, distinct MHOOK_INJECT_E_NO_PROXY (not a crash,
// not a generic failure).  Runs in every x86 config.
TEST(MhookInjectTest, CrossArch_32to64_NoProxyReportsNoProxy)
{
    std::wstring cmd64;
    if (!Get64BitCmdPath(cmd64)) GTEST_SKIP() << "no 64-bit cmd.exe via Sysnative (32-bit-only OS?)";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd64.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 64-bit cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = L"some_companion.dll";
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.ProxyPath     = L"this_proxy_does_not_exist_zzz.exe";

    HRESULT hr = Mhook_Inject(&p);

    if (hWrite) CloseHandle(hWrite);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); if (hRead) CloseHandle(hRead);

    EXPECT_EQ(hr, MHOOK_INJECT_E_NO_PROXY)
        << "expected MHOOK_INJECT_E_NO_PROXY; got 0x" << std::hex << hr;
}

// Sync: inject the x64 companion into a suspended 64-bit cmd.exe via the proxy and
// confirm the injected function writes its marker to the target's stdout.
TEST(MhookInjectTest, CrossArch_32to64ViaProxy)
{
    std::wstring proxy, companion, mhookdll; std::string why;
    if (!LocateProxyAssets(proxy, companion, mhookdll, why)) GTEST_SKIP() << why;
    std::wstring cmd64;
    if (!Get64BitCmdPath(cmd64)) GTEST_SKIP() << "no Sysnative\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd64.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 64-bit cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.ProxyPath     = proxy.c_str();
    CROSS32_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);
    if (SUCCEEDED(hr)) ResumeThread(pi.hThread);

    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "32->64 via proxy failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Sync + DELAY_UNTIL_INIT: the proxy defers until the target's loader init; the main
// thread must be allowed to run for the entry-point hook to fire, so resume it on a
// helper thread while Mhook_Inject (and, through it, the proxy) is blocked.
TEST(MhookInjectTest, CrossArch_32to64ViaProxy_Delay)
{
    std::wstring proxy, companion, mhookdll; std::string why;
    if (!LocateProxyAssets(proxy, companion, mhookdll, why)) GTEST_SKIP() << why;
    std::wstring cmd64;
    if (!Get64BitCmdPath(cmd64)) GTEST_SKIP() << "no Sysnative\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd64.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 64-bit cmd.exe (" << GetLastError() << ")";

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;
    p.ProxyPath     = proxy.c_str();
    CROSS32_SET_MHOOK(p, mhookdll);

    HANDLE hResume = CreateThread(NULL, 0, DelayedResumeProcProxy, pi.hThread, 0, NULL);
    HRESULT hr = Mhook_Inject(&p);
    if (hResume) { WaitForSingleObject(hResume, 5000); CloseHandle(hResume); }

    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    EXPECT_HRESULT_SUCCEEDED(hr) << "32->64 delayed via proxy failed: 0x" << std::hex << hr;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Async + Event: completion is delivered by the caller-side proxy watcher signalling
// the user event once the proxy reports done.
TEST(MhookInjectTest, CrossArch_32to64ViaProxy_AsyncEvent)
{
    std::wstring proxy, companion, mhookdll; std::string why;
    if (!LocateProxyAssets(proxy, companion, mhookdll, why)) GTEST_SKIP() << why;
    std::wstring cmd64;
    if (!Get64BitCmdPath(cmd64)) GTEST_SKIP() << "no Sysnative\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd64.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 64-bit cmd.exe (" << GetLastError() << ")";

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ASSERT_NE(hEvent, (HANDLE)NULL);

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_ASYNC;
    p.Event         = hEvent;
    p.ProxyPath     = proxy.c_str();
    CROSS32_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);
    DWORD waited = WaitForSingleObject(hEvent, 15000);

    ResumeThread(pi.hThread);
    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead); CloseHandle(hEvent);

    EXPECT_HRESULT_SUCCEEDED(hr) << "32->64 async via proxy failed: 0x" << std::hex << hr;
    EXPECT_EQ(waited, (DWORD)WAIT_OBJECT_0) << "completion event was not signalled";
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

// Async + IoStatusBlock: the proxy watcher reads the result from the shared section
// and fills the caller's IO_STATUS_BLOCK, then signals the Event.
TEST(MhookInjectTest, CrossArch_32to64ViaProxy_AsyncIoStatusBlock)
{
    std::wstring proxy, companion, mhookdll; std::string why;
    if (!LocateProxyAssets(proxy, companion, mhookdll, why)) GTEST_SKIP() << why;
    std::wstring cmd64;
    if (!Get64BitCmdPath(cmd64)) GTEST_SKIP() << "no Sysnative\\cmd.exe";

    PROCESS_INFORMATION pi = {}; HANDLE hRead = NULL, hWrite = NULL;
    if (!CreateSuspendedExe(cmd64.c_str(), &pi, &hRead, &hWrite))
        GTEST_SKIP() << "could not create 64-bit cmd.exe (" << GetLastError() << ")";

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ASSERT_NE(hEvent, (HANDLE)NULL);
    IO_STATUS_BLOCK iosb;
    iosb.Status = (NTSTATUS)0x7fffffffL; iosb.Information = 0;

    MHOOK_INJECT_PARAMS p = {};
    p.Size          = sizeof(p);
    p.TargetProcess = pi.hProcess;
    p.DllPath       = companion.c_str();
    p.FunctionName  = "Inject_WriteMarkerAndResume";
    p.Flags         = MHOOK_INJECT_FLAG_ASYNC;
    p.Event         = hEvent;
    p.IoStatusBlock = &iosb;
    p.ProxyPath     = proxy.c_str();
    CROSS32_SET_MHOOK(p, mhookdll);

    HRESULT hr = Mhook_Inject(&p);
    DWORD waited = WaitForSingleObject(hEvent, 15000);
    NTSTATUS finalStatus = iosb.Status;

    ResumeThread(pi.hThread);
    CloseHandle(hWrite);
    std::string output = DrainPipe(hRead, 15000);
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead); CloseHandle(hEvent);

    EXPECT_HRESULT_SUCCEEDED(hr) << "32->64 async via proxy failed: 0x" << std::hex << hr;
    EXPECT_EQ(waited, (DWORD)WAIT_OBJECT_0) << "completion event was not signalled";
    EXPECT_EQ(finalStatus, (NTSTATUS)0)
        << "IoStatusBlock.Status not S_OK; got 0x" << std::hex << finalStatus;
    EXPECT_TRUE(output.find("MHOOK_INJECT_OK") != std::string::npos)
        << "marker not found. Output: [" << output << "]";
}

#endif // _M_X64
