// uninit_test.cpp — verifies that mhook can install a hook from a thread that
// runs before the target process's main thread has executed a single instruction.
//
// Test flow:
//   1. Create cmd.exe with CREATE_SUSPENDED and piped stdout.
//   2. Inject a small shellcode blob that loads the companion DLL and calls
//      Execute().  The companion DLL installs a hook on NtTerminateProcess and
//      then resumes the main thread.
//   3. When cmd.exe eventually exits the hook fires, writing "MHOOK_EARLY_HOOK_OK"
//      to the stdout pipe.
//   4. The test reads the pipe and asserts the marker is present.

// nt_defs.h is included first to get NTSTATUS, UNICODE_STRING, and the NT
// function declarations.  It brings in minwindef.h + winnt.h (no full Win32
// surface), so <windows.h> is included afterwards for the Win32 APIs the test
// itself needs (process creation, pipes, etc.).
#include "../nt_defs.h"

#include <gtest/gtest.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------------------
// ShellcodeParams layout  (must match shellcode_x64.asm / shellcode_x86.asm)
// ---------------------------------------------------------------------------

// Function-pointer types for the shellcode data block.
// LdrLoadDll is __stdcall (NTAPI); Execute is __cdecl.
typedef NTSTATUS (NTAPI  *LdrLoadDllFn)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
typedef void     (__cdecl *ExecuteFn)(HANDLE);

#pragma pack(push, 1)   // avoid any implicit padding surprises
struct ShellcodeParams {
    LdrLoadDllFn    LdrLoadDll;         // 8 (x64) / 4 (x86)
    UNICODE_STRING  CompanionPath;      // 16 (x64) / 8 (x86)
    WCHAR           CompanionBuf[MAX_PATH]; // 520
    HANDLE          CompanionHandle;    // 8 / 4
    ULONG_PTR       ExecuteOffset;      // 8 / 4
    ULONG           IsDynamic;          // 4
    ULONG           _pad;               // 4  (x64 alignment; kept on x86 for identical layout)
    UNICODE_STRING  MhookPath;          // 16 / 8
    WCHAR           MhookBuf[MAX_PATH]; // 520
    HANDLE          MhookHandle;        // 8 / 4
};
#pragma pack(pop)

// Compile-time layout assertions — must match the EQU constants in the .asm files.
#ifdef _M_X64
static_assert(offsetof(ShellcodeParams, LdrLoadDll)      ==    0, "layout");
static_assert(offsetof(ShellcodeParams, CompanionPath)   ==    8, "layout");
static_assert(offsetof(ShellcodeParams, CompanionBuf)    ==   24, "layout");
static_assert(offsetof(ShellcodeParams, CompanionHandle) ==  544, "layout");
static_assert(offsetof(ShellcodeParams, ExecuteOffset)   ==  552, "layout");
static_assert(offsetof(ShellcodeParams, IsDynamic)       ==  560, "layout");
static_assert(offsetof(ShellcodeParams, MhookPath)       ==  568, "layout");
static_assert(offsetof(ShellcodeParams, MhookBuf)        ==  584, "layout");
static_assert(offsetof(ShellcodeParams, MhookHandle)     == 1104, "layout");
#else
static_assert(offsetof(ShellcodeParams, LdrLoadDll)      ==    0, "layout");
static_assert(offsetof(ShellcodeParams, CompanionPath)   ==    4, "layout");
static_assert(offsetof(ShellcodeParams, CompanionBuf)    ==   12, "layout");
static_assert(offsetof(ShellcodeParams, CompanionHandle) ==  532, "layout");
static_assert(offsetof(ShellcodeParams, ExecuteOffset)   ==  536, "layout");
static_assert(offsetof(ShellcodeParams, IsDynamic)       ==  540, "layout");
static_assert(offsetof(ShellcodeParams, MhookPath)       ==  548, "layout");
static_assert(offsetof(ShellcodeParams, MhookBuf)        ==  556, "layout");
static_assert(offsetof(ShellcodeParams, MhookHandle)     == 1076, "layout");
#endif

// ---------------------------------------------------------------------------
// Shellcode bytes — defined in shellcode_x64.asm / shellcode_x86.asm.
// Declared as a C symbol so we can get its address and size at runtime.
// ---------------------------------------------------------------------------

extern "C" void ShellcodeEntry();  // entry point defined in the .asm file

// ShellcodeEnd is a sentinel placed immediately after ShellcodeEntry in the
// same object file so that (ShellcodeEnd - ShellcodeEntry) gives the size.
// It is defined as a label in the .asm file.
extern "C" void ShellcodeEnd();    // label at end of shellcode, defined in .asm

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void SetUnicodeString(UNICODE_STRING *us, PWSTR buf, size_t bufCharCap,
                              const wchar_t *path)
{
    size_t len = wcslen(path);
    if (len >= bufCharCap) len = bufCharCap - 1;
    wmemcpy(buf, path, len);
    buf[len] = L'\0';
    us->Buffer        = buf;   // will be fixed up to remote address later
    us->Length        = (USHORT)(len * sizeof(WCHAR));
    us->MaximumLength = (USHORT)(bufCharCap * sizeof(WCHAR));
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

TEST(MhookTest, UninitializedProcess_HookFiresBeforeInit)
{
    // --- Locate companion DLL and test executable directory ---
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t *lastSlash = wcsrchr(exePath, L'\\');
    ASSERT_NE(lastSlash, nullptr);
    wchar_t dir[MAX_PATH];
    size_t dirLen = (size_t)(lastSlash - exePath + 1);
    wmemcpy(dir, exePath, dirLen);
    dir[dirLen] = L'\0';

    wchar_t companionPath[MAX_PATH], mhookPath[MAX_PATH];
    swprintf_s(companionPath, L"%smhook_test_uninitialized_inject.dll", dir);
    swprintf_s(mhookPath,     L"%smhook.dll", dir);

    // --- Compute Execute's offset from the companion DLL base ---
    HMODULE hCompanion = LoadLibraryExW(companionPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    ASSERT_NE(hCompanion, (HMODULE)NULL) << "Cannot load companion DLL: " << GetLastError();
    FARPROC pExecute = GetProcAddress(hCompanion, "Execute");
    ASSERT_NE(pExecute, (FARPROC)NULL) << "Execute not found in companion DLL";
    ULONG_PTR executeOffset = (ULONG_PTR)pExecute - (ULONG_PTR)hCompanion;
    FreeLibrary(hCompanion);

    // --- Resolve LdrLoadDll (same VA in every process on this boot) ---
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    ASSERT_NE(hNtdll, (HMODULE)NULL);
    LdrLoadDllFn pfnLdrLoadDll = (LdrLoadDllFn)GetProcAddress(hNtdll, "LdrLoadDll");
    ASSERT_NE(pfnLdrLoadDll, (LdrLoadDllFn)NULL);

    // --- Determine if this is a dynamic-mhook build ---
    bool isDynamic = (GetFileAttributesW(mhookPath) != INVALID_FILE_ATTRIBUTES);

    // --- Create stdout/stderr pipe ---
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    ASSERT_TRUE(CreatePipe(&hReadPipe, &hWritePipe, &sa, 0));

    // Create a null stdin so cmd.exe gets EOF immediately and exits on its own.
    HANDLE hNullIn = CreateFileW(L"nul", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
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

    // We can close the child-side handles in our process now.
    CloseHandle(hNullIn);

    if (!created) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        GTEST_SKIP() << "Could not create cmd.exe (" << GetLastError() << ")";
    }

    // --- Build ShellcodeParams ---
    ShellcodeParams params;
    memset(&params, 0, sizeof(params));

    params.LdrLoadDll    = pfnLdrLoadDll;
    params.ExecuteOffset = executeOffset;
    params.IsDynamic     = isDynamic ? 1u : 0u;
    params.MhookHandle   = NULL;
    params.CompanionHandle = NULL;

    // We will write the params struct immediately after the shellcode bytes in
    // the remote allocation.  Compute its remote address now.
    SIZE_T codeSize   = (SIZE_T)((BYTE *)ShellcodeEnd - (BYTE *)ShellcodeEntry);
    SIZE_T totalSize  = codeSize + sizeof(ShellcodeParams);

    // Allocate in target process.
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, totalSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(remoteBase, (LPVOID)NULL) << "VirtualAllocEx failed: " << GetLastError();

    BYTE *remoteCode   = (BYTE *)remoteBase;
    BYTE *remoteParams = remoteCode + codeSize;

    // Fix up UNICODE_STRING Buffer pointers to their remote addresses.
    SetUnicodeString(&params.CompanionPath, params.CompanionBuf,
                     ARRAYSIZE(params.CompanionBuf), companionPath);
    params.CompanionPath.Buffer =
        (PWSTR)(remoteParams + offsetof(ShellcodeParams, CompanionBuf));

    if (isDynamic) {
        SetUnicodeString(&params.MhookPath, params.MhookBuf,
                         ARRAYSIZE(params.MhookBuf), mhookPath);
        params.MhookPath.Buffer =
            (PWSTR)(remoteParams + offsetof(ShellcodeParams, MhookBuf));
    }

    // Write shellcode and params into the remote process.
    SIZE_T written;
    ASSERT_TRUE(WriteProcessMemory(pi.hProcess, remoteCode,
                                   (LPCVOID)ShellcodeEntry, codeSize, &written));
    ASSERT_TRUE(WriteProcessMemory(pi.hProcess, remoteParams,
                                   &params, sizeof(params), &written));

    // --- Inject remote thread ---
    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteCode, remoteParams, 0, NULL);
    ASSERT_NE(hRemoteThread, (HANDLE)NULL) << "CreateRemoteThread failed: " << GetLastError();
    CloseHandle(hRemoteThread);

    // Close write end of the pipe in our process so ReadFile returns when
    // the remote process closes its end.
    CloseHandle(hWritePipe);
    hWritePipe = NULL;

    // --- Read stdout with timeout, look for marker ---
    bool markerFound = false;
    char buf[4096];
    std::string output;

    // Use a separate thread to read with timeout.
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

    // Wait up to 15 seconds for the process to exit and the read to complete.
    if (hReadThread) {
        WaitForSingleObject(hReadThread, 15000);
        CloseHandle(hReadThread);
    }

    markerFound = (output.find("MHOOK_EARLY_HOOK_OK") != std::string::npos);

    // --- Cleanup ---
    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    EXPECT_TRUE(markerFound)
        << "Hook did not fire. Process output: " << output;
}
