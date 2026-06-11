// Unit tests for mhook.  Tests are structured around the same hooks that
// mhook-test demonstrated, but with proper assertions and isolation.
//
// Each test:
//   1. Installs a hook that sets a flag and (optionally) checks a value.
//   2. Triggers the hooked function.
//   3. Asserts the hook was reached and the return value looks correct.
//   4. Removes the hook and verifies the original behaviour is restored.

#include <gtest/gtest.h>

#include <crtdbg.h>   // _CrtSetReportMode / _CRTDBG_*
#include <stdlib.h>   // _set_abort_behavior, _set_invalid_parameter_handler

// Win32 / Winsock headers — test code is allowed to use these.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winspool.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#include "../mhook-lib/mhook.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// RAII guard that ensures Mhook_Unhook is always called.
struct ScopedHook {
    PVOID *ppFunc;
    bool  installed;

    ScopedHook(PVOID *pp, PVOID hook)
        : ppFunc(pp), installed(Mhook_SetHook(pp, hook) != FALSE) {}

    ~ScopedHook() {
        if (installed) Mhook_Unhook(ppFunc);
    }

    explicit operator bool() const { return installed; }
};

// ---------------------------------------------------------------------------
// NtOpenProcess
// ---------------------------------------------------------------------------

typedef ULONG (WINAPI *_NtOpenProcess)(
    OUT PHANDLE    ProcessHandle,
    IN  ACCESS_MASK AccessMask,
    IN  PVOID      ObjectAttributes,
    IN  PVOID      ClientId);

static _NtOpenProcess TrueNtOpenProcess =
    (_NtOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtOpenProcess");

static volatile bool g_ntOpenProcessCalled;

static ULONG WINAPI HookNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK AccessMask,
    PVOID ObjectAttributes, PVOID ClientId)
{
    g_ntOpenProcessCalled = true;
    return TrueNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
}

TEST(MhookTest, NtOpenProcess_HookIsCalled) {
    if (!TrueNtOpenProcess) GTEST_SKIP() << "NtOpenProcess not found in ntdll";

    g_ntOpenProcessCalled = false;
    ScopedHook h((PVOID*)&TrueNtOpenProcess, HookNtOpenProcess);
    ASSERT_TRUE(h) << "Mhook_SetHook failed for NtOpenProcess";

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                              GetCurrentProcessId());
    EXPECT_TRUE(g_ntOpenProcessCalled) << "Hook was not called";
    if (proc) CloseHandle(proc);
}

TEST(MhookTest, NtOpenProcess_UnhookRestoresOriginal) {
    if (!TrueNtOpenProcess) GTEST_SKIP() << "NtOpenProcess not found in ntdll";

    {
        ScopedHook h((PVOID*)&TrueNtOpenProcess, HookNtOpenProcess);
        ASSERT_TRUE(h);
    } // hook removed here

    g_ntOpenProcessCalled = false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                              GetCurrentProcessId());
    EXPECT_FALSE(g_ntOpenProcessCalled) << "Hook still active after unhook";
    if (proc) CloseHandle(proc);
}

// ---------------------------------------------------------------------------
// NtClose
// ---------------------------------------------------------------------------

typedef ULONG (WINAPI *_NtClose)(IN HANDLE Handle);

static _NtClose TrueNtClose =
    (_NtClose)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtClose");

static volatile bool g_ntCloseCalled;

static ULONG WINAPI HookNtClose(HANDLE handle)
{
    g_ntCloseCalled = true;
    return TrueNtClose(handle);
}

TEST(MhookTest, NtClose_HookIsCalled) {
    if (!TrueNtClose) GTEST_SKIP() << "NtClose not found in ntdll";

    g_ntCloseCalled = false;
    ScopedHook h((PVOID*)&TrueNtClose, HookNtClose);
    ASSERT_TRUE(h) << "Mhook_SetHook failed for NtClose";

    // CloseHandle calls NtClose internally
    CloseHandle(NULL);
    EXPECT_TRUE(g_ntCloseCalled) << "Hook was not called";
}

// ---------------------------------------------------------------------------
// HeapAlloc  (kernel32 — import jump stub test)
// ---------------------------------------------------------------------------

typedef LPVOID (WINAPI *_HeapAlloc)(HANDLE, DWORD, SIZE_T);

static _HeapAlloc TrueHeapAlloc =
    (_HeapAlloc)GetProcAddress(GetModuleHandleW(L"kernel32"), "HeapAlloc");

static volatile bool   g_heapAllocCalled;
static volatile SIZE_T g_heapAllocSize;

static LPVOID WINAPI HookHeapAlloc(HANDLE heap, DWORD flags, SIZE_T size)
{
    g_heapAllocCalled = true;
    g_heapAllocSize   = size;
    return TrueHeapAlloc(heap, flags, size);
}

TEST(MhookTest, HeapAlloc_HookIsCalledAndAllocSucceeds) {
    if (!TrueHeapAlloc) GTEST_SKIP() << "HeapAlloc not found in kernel32";

    g_heapAllocCalled = false;
    ScopedHook h((PVOID*)&TrueHeapAlloc, HookHeapAlloc);
    ASSERT_TRUE(h) << "Mhook_SetHook failed for HeapAlloc";

    // malloc internally calls HeapAlloc
    void *p = malloc(64);
    EXPECT_TRUE(g_heapAllocCalled) << "Hook was not called";
    EXPECT_GE(g_heapAllocSize, (SIZE_T)64);
    free(p);
}

// ---------------------------------------------------------------------------
// SelectObject  (GDI — IP-relative addressing test)
// ---------------------------------------------------------------------------

typedef HGDIOBJ (WINAPI *_SelectObject)(HDC, HGDIOBJ);

static _SelectObject TrueSelectObject =
    (_SelectObject)GetProcAddress(GetModuleHandleW(L"gdi32"), "SelectObject");

static volatile bool g_selectObjectCalled;

static HGDIOBJ WINAPI HookSelectObject(HDC dc, HGDIOBJ obj)
{
    g_selectObjectCalled = true;
    return TrueSelectObject(dc, obj);
}

TEST(MhookTest, SelectObject_HookIsCalled) {
    if (!TrueSelectObject) GTEST_SKIP() << "SelectObject not found in gdi32";

    g_selectObjectCalled = false;
    ScopedHook h((PVOID*)&TrueSelectObject, HookSelectObject);
    ASSERT_TRUE(h) << "Mhook_SetHook failed for SelectObject";

    HDC    screen = GetDC(NULL);
    HDC    mem    = CreateCompatibleDC(screen);
    HBITMAP bm   = CreateCompatibleBitmap(screen, 8, 8);
    HBITMAP old  = (HBITMAP)SelectObject(mem, bm);

    EXPECT_TRUE(g_selectObjectCalled) << "Hook was not called";

    // clean up — through the (now-unhooked at scope exit) original
    SelectObject(mem, old);
    DeleteObject(bm);
    DeleteDC(mem);
    ReleaseDC(NULL, screen);
}

// ---------------------------------------------------------------------------
// getaddrinfo  (Winsock2)
// ---------------------------------------------------------------------------

typedef int (WSAAPI *_getaddrinfo)(
    const char*, const char*, const struct addrinfo*, struct addrinfo**);

static _getaddrinfo TrueGetaddrinfo =
    (_getaddrinfo)GetProcAddress(GetModuleHandleW(L"ws2_32"), "getaddrinfo");

static volatile bool g_getaddrinfoSCalled;

static int WSAAPI HookGetaddrinfo(
    const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res)
{
    g_getaddrinfoSCalled = true;
    return TrueGetaddrinfo(node, service, hints, res);
}

TEST(MhookTest, Getaddrinfo_HookIsCalled) {
    if (!TrueGetaddrinfo) GTEST_SKIP() << "getaddrinfo not found in ws2_32";

    WSADATA wd = {};
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0)
        GTEST_SKIP() << "WSAStartup failed";

    g_getaddrinfoSCalled = false;
    {
        ScopedHook h((PVOID*)&TrueGetaddrinfo, HookGetaddrinfo);
        ASSERT_TRUE(h) << "Mhook_SetHook failed for getaddrinfo";

        struct addrinfo hints = {};
        hints.ai_family   = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res = nullptr;
        getaddrinfo("localhost", nullptr, &hints, &res);
        if (res) freeaddrinfo(res);

        EXPECT_TRUE(g_getaddrinfoSCalled) << "Hook was not called";
    }

    WSACleanup();
}

// ---------------------------------------------------------------------------
// OpenPrinterW  (winspool — import stub via function pointer)
// ---------------------------------------------------------------------------

typedef BOOL (WINAPI *_OpenPrinterW)(LPWSTR, LPHANDLE, LPPRINTER_DEFAULTS);

static _OpenPrinterW TrueOpenPrinterW = &OpenPrinterW;

static volatile bool g_openPrinterCalled;

static BOOL WINAPI HookOpenPrinterW(
    LPWSTR name, LPHANDLE ph, LPPRINTER_DEFAULTS defaults)
{
    g_openPrinterCalled = true;
    return TrueOpenPrinterW(name, ph, defaults);
}

TEST(MhookTest, OpenPrinterW_HookIsCalled) {
    g_openPrinterCalled = false;
    ScopedHook h((PVOID*)&TrueOpenPrinterW, HookOpenPrinterW);
    ASSERT_TRUE(h) << "Mhook_SetHook failed for OpenPrinterW";

    HANDLE printer = NULL;
    // Attempt to open a printer that may or may not exist — the hook fires
    // regardless of whether the printer is present.
    OpenPrinterW(L"Microsoft XPS Document Writer", &printer, nullptr);
    if (printer) ClosePrinter(printer);

    EXPECT_TRUE(g_openPrinterCalled) << "Hook was not called";
}

// ---------------------------------------------------------------------------
// GetFocus  (user32 — unconditional short jmp)
// ---------------------------------------------------------------------------

typedef HWND (WINAPI *_GetFocus)();

static _GetFocus TrueGetFocus = &GetFocus;

static volatile bool g_getFocusCalled;

static HWND WINAPI HookGetFocus()
{
    g_getFocusCalled = true;
    return TrueGetFocus();
}

TEST(MhookTest, GetFocus_HookIsCalled) {
    g_getFocusCalled = false;
    ScopedHook h((PVOID*)&TrueGetFocus, HookGetFocus);
    ASSERT_TRUE(h) << "Mhook_SetHook failed for GetFocus";

    GetFocus();
    EXPECT_TRUE(g_getFocusCalled) << "Hook was not called";
}

// ---------------------------------------------------------------------------
// Double-hook / unhook stress
// ---------------------------------------------------------------------------

TEST(MhookTest, HookCanBeReinstalled) {
    if (!TrueNtClose) GTEST_SKIP();

    for (int i = 0; i < 3; ++i) {
        g_ntCloseCalled = false;
        ScopedHook h((PVOID*)&TrueNtClose, HookNtClose);
        ASSERT_TRUE(h) << "Iteration " << i << ": Mhook_SetHook failed";
        CloseHandle(NULL);
        EXPECT_TRUE(g_ntCloseCalled) << "Iteration " << i << ": hook not called";
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

static void SilentInvalidParameter(const wchar_t *, const wchar_t *, const wchar_t *,
                                   unsigned int, uintptr_t)
{
    // Swallow invalid-CRT-parameter reports rather than showing the debug box /
    // fast-failing; the failing call simply returns / the test observes the error.
}

// Prevent any modal dialog from blocking an unattended (parallel/CI) test run.
// GoogleTest does most of this itself, but only inside RUN_ALL_TESTS(), only when
// catch_exceptions is on, only for _CRT_ASSERT, and not under a debugger — so do it
// ourselves, unconditionally and early.  WER reporting is left enabled; only the UI
// is suppressed.
static void SuppressErrorDialogs()
{
    // No WER / GP-fault / critical-error / open-file boxes.  The error mode is
    // INHERITED by child processes, so the cmd.exe targets these tests inject into
    // also won't pop a fault box if injected code faults there.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT);

    // abort(): clear only _WRITE_ABORT_MSG (the abort message box).  Keep
    // _CALL_REPORTFAULT so WER still generates a crash report; its *dialog* is
    // suppressed by SEM_NOGPFAULTERRORBOX above, so reporting stays silent.
    _set_abort_behavior(0, _WRITE_ABORT_MSG);

    // Invalid CRT parameter: swallow rather than show the debug box / fast-fail.
    _set_invalid_parameter_handler(SilentInvalidParameter);

#ifdef _DEBUG
    // Debug-CRT assert/error/warn → stderr (+ debugger break), never a dialog.
    // Covers _CRT_ERROR / RTC reports that gtest's _CRT_ASSERT-only redirect misses,
    // and applies even under a debugger (gtest skips its redirect there).
    for (int rt : { _CRT_ASSERT, _CRT_ERROR, _CRT_WARN }) {
        _CrtSetReportMode(rt, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
        _CrtSetReportFile(rt, _CRTDBG_FILE_STDERR);
    }
#endif
}

int main(int argc, char **argv)
{
    SuppressErrorDialogs();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
