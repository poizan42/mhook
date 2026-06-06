// uninit_test.cpp — verifies that mhook can install a hook from a thread that
// runs before the target process's main thread has executed a single instruction.
//
// Test flow:
//   1. Create cmd.exe with CREATE_SUSPENDED and a piped stdout.
//   2. Inject a shellcode blob that loads the companion DLL and calls Execute().
//      The companion DLL installs a hook on NtTerminateProcess and resumes the
//      main thread.
//   3. When cmd.exe exits the hook fires, writing "MHOOK_EARLY_HOOK_OK\n" to
//      the stdout pipe.
//   4. The test reads the pipe and asserts the marker is present.

// nt_defs.h is included first to get NTSTATUS, UNICODE_STRING etc.
// It brings in minwindef.h + winnt.h only (no full Win32 surface), so
// <windows.h> is included afterwards for the Win32 APIs the test needs.
#include "../nt_defs.h"

#include <gtest/gtest.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

// ---------------------------------------------------------------------------
// ShellcodeParams — data block written into the remote process immediately
// after the shellcode bytes.
//
// Path strings are written into the tail of the same allocation so that there
// is no MAX_PATH limitation.  CompanionPath.Buffer and MhookPath.Buffer are
// set to their remote addresses before WriteProcessMemory is called.
//
// Layout (must match the EQU constants in shellcode_x64.asm / shellcode_x86.asm)
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI  *LdrLoadDllFn)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
typedef void     (__cdecl *ExecuteFn)(HANDLE);

#pragma pack(push, 1)
struct ShellcodeParams {
    LdrLoadDllFn    LdrLoadDll;     // fn pointer  8 / 4
    UNICODE_STRING  CompanionPath;  // 16 / 8
    HANDLE          CompanionHandle;// 8 / 4
    ULONG_PTR       ExecuteOffset;  // 8 / 4
    ULONG           IsDynamic;      // 4
    ULONG           _pad;           // 4  (alignment: x64 needs 8-byte align for MhookPath.Buffer)
    UNICODE_STRING  MhookPath;      // 16 / 8
    HANDLE          MhookHandle;    // 8 / 4
};
#pragma pack(pop)

// Compile-time layout assertions — must match the EQU constants in the .asm files.
#ifdef _M_X64
static_assert(offsetof(ShellcodeParams, LdrLoadDll)      ==  0, "layout");
static_assert(offsetof(ShellcodeParams, CompanionPath)   ==  8, "layout");
static_assert(offsetof(ShellcodeParams, CompanionHandle) == 24, "layout");
static_assert(offsetof(ShellcodeParams, ExecuteOffset)   == 32, "layout");
static_assert(offsetof(ShellcodeParams, IsDynamic)       == 40, "layout");
static_assert(offsetof(ShellcodeParams, MhookPath)       == 48, "layout");
static_assert(offsetof(ShellcodeParams, MhookHandle)     == 64, "layout");
static_assert(sizeof(ShellcodeParams)                    == 72, "layout");
#else
static_assert(offsetof(ShellcodeParams, LdrLoadDll)      ==  0, "layout");
static_assert(offsetof(ShellcodeParams, CompanionPath)   ==  4, "layout");
static_assert(offsetof(ShellcodeParams, CompanionHandle) == 12, "layout");
static_assert(offsetof(ShellcodeParams, ExecuteOffset)   == 16, "layout");
static_assert(offsetof(ShellcodeParams, IsDynamic)       == 20, "layout");
static_assert(offsetof(ShellcodeParams, MhookPath)       == 28, "layout");
static_assert(offsetof(ShellcodeParams, MhookHandle)     == 36, "layout");
static_assert(sizeof(ShellcodeParams)                    == 40, "layout");
#endif

// ---------------------------------------------------------------------------
// Shellcode entry point and sentinel label defined in the .asm files.
// ---------------------------------------------------------------------------

extern "C" void ShellcodeEntry();
extern "C" void ShellcodeEnd();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Returns the full path of the running executable without any MAX_PATH limit.
static std::wstring GetExeDir()
{
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(NULL, &buf[0], static_cast<DWORD>(buf.size()));
        if (n == 0) return L"";
        if (n < static_cast<DWORD>(buf.size())) {
            buf.resize(n);
            break;
        }
        buf.resize(buf.size() * 2);
    }
    auto slash = buf.rfind(L'\\');
    return (slash == std::wstring::npos) ? L"" : buf.substr(0, slash + 1);
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

TEST(MhookTest, UninitializedProcess_HookFiresBeforeInit)
{
    std::wstring dir = GetExeDir();
    ASSERT_FALSE(dir.empty()) << "Could not determine exe directory";

    std::wstring companionPath = dir + L"mhook_test_uninitialized_inject.dll";
    std::wstring mhookPath     = dir + L"mhook.dll";

    // --- Compute Execute's offset from the companion DLL base ---
    HMODULE hCompanion = LoadLibraryExW(companionPath.c_str(), NULL,
                                        DONT_RESOLVE_DLL_REFERENCES);
    ASSERT_NE(hCompanion, (HMODULE)NULL)
        << "Cannot load companion DLL: " << GetLastError();
    FARPROC pExecute = GetProcAddress(hCompanion, "Execute");
    ASSERT_NE(pExecute, (FARPROC)NULL) << "Execute not found in companion DLL";
    ULONG_PTR executeOffset = (ULONG_PTR)pExecute - (ULONG_PTR)hCompanion;
    FreeLibrary(hCompanion);

    // --- Resolve LdrLoadDll (same VA in every process on this boot) ---
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    ASSERT_NE(hNtdll, (HMODULE)NULL);
    LdrLoadDllFn pfnLdrLoadDll =
        (LdrLoadDllFn)GetProcAddress(hNtdll, "LdrLoadDll");
    ASSERT_NE(pfnLdrLoadDll, (LdrLoadDllFn)NULL);

    // --- Determine build variant ---
    bool isDynamic = (GetFileAttributesW(mhookPath.c_str()) != INVALID_FILE_ATTRIBUTES);

    // --- Create stdout/stderr pipe ---
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    ASSERT_TRUE(CreatePipe(&hReadPipe, &hWritePipe, &sa, 0));

    // Null stdin so cmd.exe gets EOF and exits on its own.
    HANDLE hNullIn = CreateFileW(L"nul", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, NULL);

    // --- Create cmd.exe suspended ---
    wchar_t cmdLine[] = L"cmd.exe";
    STARTUPINFOW si    = { sizeof(si) };
    si.dwFlags         = STARTF_USESTDHANDLES;
    si.hStdInput       = hNullIn;
    si.hStdOutput      = hWritePipe;
    si.hStdError       = hWritePipe;

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

    // --- Build the remote memory layout ---
    //
    //   [shellcode bytes]                   (codeSize)
    //   [ShellcodeParams]                   (sizeof ShellcodeParams)
    //   [companion DLL path as WCHARs]      (companionBytes)
    //   [mhook DLL path as WCHARs]          (mhookBytes, only if isDynamic)
    //
    SIZE_T codeSize       = (SIZE_T)((BYTE*)ShellcodeEnd - (BYTE*)ShellcodeEntry);
    SIZE_T paramsSize     = sizeof(ShellcodeParams);
    SIZE_T companionBytes = (companionPath.size() + 1) * sizeof(WCHAR);
    SIZE_T mhookBytes     = isDynamic ? (mhookPath.size() + 1) * sizeof(WCHAR) : 0;
    SIZE_T totalSize      = codeSize + paramsSize + companionBytes + mhookBytes;

    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, totalSize,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    ASSERT_NE(remoteBase, (LPVOID)NULL)
        << "VirtualAllocEx failed: " << GetLastError();

    BYTE*  remoteCode         = (BYTE*)remoteBase;
    BYTE*  remoteParamsBytes  = remoteCode + codeSize;
    PWSTR  remoteCompanionBuf = (PWSTR)(remoteParamsBytes + paramsSize);
    PWSTR  remoteMhookBuf     = isDynamic
                                    ? (PWSTR)((BYTE*)remoteCompanionBuf + companionBytes)
                                    : NULL;

    // --- Fill in ShellcodeParams ---
    ShellcodeParams params = {};
    params.LdrLoadDll    = pfnLdrLoadDll;
    params.ExecuteOffset = executeOffset;
    params.IsDynamic     = isDynamic ? 1u : 0u;

    params.CompanionPath.Buffer        = remoteCompanionBuf;
    params.CompanionPath.Length        = (USHORT)(companionPath.size() * sizeof(WCHAR));
    params.CompanionPath.MaximumLength = (USHORT)companionBytes;

    if (isDynamic) {
        params.MhookPath.Buffer        = remoteMhookBuf;
        params.MhookPath.Length        = (USHORT)(mhookPath.size() * sizeof(WCHAR));
        params.MhookPath.MaximumLength = (USHORT)mhookBytes;
    }

    // --- Write everything into the remote process ---
    SIZE_T written;
    ASSERT_TRUE(WriteProcessMemory(pi.hProcess, remoteCode,
                                   (LPCVOID)ShellcodeEntry, codeSize, &written));
    ASSERT_TRUE(WriteProcessMemory(pi.hProcess, remoteParamsBytes,
                                   &params, paramsSize, &written));
    ASSERT_TRUE(WriteProcessMemory(pi.hProcess, remoteCompanionBuf,
                                   companionPath.c_str(), companionBytes, &written));
    if (isDynamic)
        ASSERT_TRUE(WriteProcessMemory(pi.hProcess, remoteMhookBuf,
                                       mhookPath.c_str(), mhookBytes, &written));

    // --- Inject remote thread ---
    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteCode,
        remoteParamsBytes, 0, NULL);
    ASSERT_NE(hRemoteThread, (HANDLE)NULL)
        << "CreateRemoteThread failed: " << GetLastError();
    CloseHandle(hRemoteThread);

    // Close write end of pipe in our process so ReadFile returns at EOF.
    CloseHandle(hWritePipe);

    // --- Read stdout with timeout, look for marker ---
    std::string output;
    struct ReadState { HANDLE pipe; std::string *out; };
    ReadState rs = { hReadPipe, &output };
    HANDLE hReadThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
        ReadState *rs = (ReadState *)p;
        char tmp[1024];
        DWORD got;
        while (ReadFile(rs->pipe, tmp, sizeof(tmp), &got, NULL) && got > 0)
            rs->out->append(tmp, got);
        return 0;
    }, &rs, 0, NULL);

    if (hReadThread) {
        WaitForSingleObject(hReadThread, 15000);
        CloseHandle(hReadThread);
    }

    bool markerFound = (output.find("MHOOK_EARLY_HOOK_OK") != std::string::npos);

    // --- Cleanup ---
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    EXPECT_TRUE(markerFound)
        << "Hook did not fire. Process output: " << output;
}
