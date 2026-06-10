# mhook

A Windows function-hooking library for x86 and x64.  mhook patches target
functions in-place at runtime, using a disassembler to copy the displaced
instructions into a trampoline so the original function can still be called.

The library has been rewritten to depend only on `ntdll.dll` — removing all kernel32, Win32,
and CRT dependencies — so that it can be used during early process
initialisation before those subsystems are available. 

Forked from [original mhook library](https://github.com/martona/mhook)
by Marton Anka (2007–2014); disassembly engine by Matt Conover.

See [COPYING](COPYING) for the MIT licence.

---

## API

```c
#include "mhook-lib/mhook.h"

// Install a hook.
//   ppSystemFunction – address of a function pointer that holds the address
//                      of the function to hook.  On success it is updated to
//                      point at the trampoline so the original can still be
//                      called through it.
//   pHookFunction    – the replacement function.
// Returns TRUE on success.
BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction);

// Remove a previously installed hook.
//   ppHookedFunction – the same pointer that was passed to Mhook_SetHook.
//                      Restored to point at the original function.
// Returns TRUE on success.
BOOL Mhook_Unhook(PVOID *ppHookedFunction);
```

### Example

```c
#include <windows.h>
#include "mhook-lib/mhook.h"

typedef NTSTATUS (NTAPI *NtOpenProcessFn)(PHANDLE, ACCESS_MASK, PVOID, PVOID);

static NtOpenProcessFn TrueNtOpenProcess = NtOpenProcess;

static NTSTATUS NTAPI HookNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK Access,
    PVOID ObjAttrs, PVOID ClientId)
{
    // ... custom logic ...
    return TrueNtOpenProcess(ProcessHandle, Access, ObjAttrs, ClientId);
}

// Install
Mhook_SetHook((PVOID *)&TrueNtOpenProcess, HookNtOpenProcess);

// Remove
Mhook_Unhook((PVOID *)&TrueNtOpenProcess);
```

---

## Injecting into remote processes (`mhook_inject`)

`mhook_inject` is a companion library that injects a user-supplied function
into an arbitrary process — including one that has been created suspended and
has not yet run a single instruction — and delivers `Mhook_SetHook`/`Mhook_Unhook`
pointers to the injected function so hooks can be installed from within the
target.

```c
#include "mhook-inject/mhook_inject.h"
```

### `Mhook_Inject`

```c
HRESULT __cdecl Mhook_Inject(MHOOK_INJECT_PARAMS *params);
```

Allocates a small code + data blob in `TargetProcess` and creates a remote thread
that loads the companion DLL and calls the injection function.  By default the
call is **synchronous** — it blocks until the injection function returns (with
`DELAY_UNTIL_INIT`, until the deferred call fires) and reports the result in the
return value.  With `MHOOK_INJECT_FLAG_ASYNC` it returns `S_OK` as soon as the
remote thread is created and reports completion out-of-band (see [Flags](#flags)).
The remote allocation is freed by the target itself, so an async fire-and-forget
injection needs no further bookkeeping from the caller.  Returns `S_OK` on success
or an `HRESULT` error code.

#### Error codes

The library's own failure codes are declared in `mhook-inject/mhook_inject.h`.
They set the HRESULT **Customer bit** (`0xA00000xx`), so they belong to mhook as a
whole rather than to a Microsoft facility:

| HRESULT | Value | Meaning |
|---|---|---|
| `MHOOK_INJECT_E_PARAMS`   | `0xA0000001` | `params` is NULL, has the wrong `Size`, or specifies neither or both of the `FunctionPointer` / `DllPath`+`FunctionName` forms |
| `MHOOK_INJECT_E_NO_NTDLL` | `0xA0000002` | `ntdll.dll` was not found in the target process |
| `MHOOK_INJECT_E_NO_EXEC`  | `0xA0000003` | `_internal_Execute` was not found in the companion DLL |
| `MHOOK_INJECT_E_TIMEOUT`  | `0xA0000004` | the remote injection thread did not finish within the timeout |
| `MHOOK_INJECT_E_ACCESS`   | `0xA0000005` | `TargetProcess` was not granted `PROCESS_ALL_ACCESS` (see [`TargetProcess`](#mhook_inject_params) below) |

Other failures are propagated as-is — e.g. an underlying `NTSTATUS` mapped into an
`HRESULT` — so test the result with `FAILED(hr)` and only compare against the codes
above when you need to distinguish a specific case.

In **dynamic** builds, `mhook_inject.dll` embeds a message-table resource for the
`MHOOK_INJECT_E_*` codes, so they can be turned into text with `FormatMessage`:

```c
WCHAR buf[256];
FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE,
               GetModuleHandleW(L"mhook_inject.dll"), hr, 0, buf, 256, NULL);
```

(Static builds carry no resource — the consumer's own module would supply one.)

### `MHOOK_INJECT_PARAMS`

```c
typedef struct _MHOOK_INJECT_PARAMS {
    ULONG  Size;           // sizeof(MHOOK_INJECT_PARAMS) — version guard

    HANDLE TargetProcess;  // must be a PROCESS_ALL_ACCESS handle (deliberate
                           // guard; Mhook_Inject refuses anything less)

    // Target function — set EXACTLY ONE of the two forms:

    // Form 1: function pointer in the CALLING process.
    //   Mhook_Inject locates the module that owns the address, derives its
    //   RVA, and loads that module in the target process.
    PVOID  FunctionPointer;

    // Form 2: DLL path + exported function name.
    //   DllPath is relative to the module that contains Mhook_Inject,
    //   or an absolute Win32 path.  NOT limited to MAX_PATH.
    PCWSTR DllPath;
    PCSTR  FunctionName;

    // Path to mhook.dll for the target process architecture.
    //   NULL → look for mhook.dll alongside the companion DLL.
    //   Reserved / always NULL for static builds.
    PCWSTR MhookDllPath;

    // Optional data block copied verbatim into the target process.
    PVOID  UserData;
    SIZE_T UserDataSize;

    // Combination of MHOOK_INJECT_FLAG_* values (see below); 0 = default.
    ULONG  Flags;

    // Async completion — only used when MHOOK_INJECT_FLAG_ASYNC is set; each is
    // optional (NULL = skip).  All NULL = pure fire-and-forget.
    HANDLE           Event;         // signalled when the injection fn returns
    PIO_APC_ROUTINE  ApcRoutine;    // user APC queued to the CALLING thread
    PVOID            ApcContext;    // context passed verbatim to ApcRoutine
    PIO_STATUS_BLOCK IoStatusBlock; // receives the final NTSTATUS (Status field)
} MHOOK_INJECT_PARAMS;
```

(`NTSTATUS`, `IO_STATUS_BLOCK` / `PIO_STATUS_BLOCK`, and `PIO_APC_ROUTINE` are
defined by `mhook_inject.h` itself under include guards, so the header is
self-contained and does not require `<winternl.h>`.)

### Flags

| Flag | Value | Description |
|---|---|---|
| `MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT` | `0x1` | Defer the injection function until the process has completed loader initialisation (`PEB_LDR_DATA.Initialized == TRUE`) so that Win32 APIs are safe to call. |
| `MHOOK_INJECT_FLAG_ASYNC` | `0x2` | Return as soon as the remote thread is created; report completion via the `Event` / `IoStatusBlock` / `ApcRoutine` fields instead of blocking. |

**`MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT`** — when set, `Mhook_Inject` installs a
hook on the process entry point instead of calling the injection function
immediately.  The function is called just before the entry point runs (i.e. after
all DLL `DllMain` handlers have executed but before the process's own startup
code).  For dynamic builds the target DLL is not loaded until that moment either,
so the target DLL may freely import from `kernel32.dll` or any other Win32 DLL.

If the process is already initialised when `Mhook_Inject` injects the thread, the
function is called immediately (fast path, no entry-point hook installed).

```c
// Defer until Win32 is available, then load a normal Win32 DLL
MHOOK_INJECT_PARAMS p = { sizeof(p) };
p.TargetProcess = pi.hProcess;
p.DllPath       = L"my_hooks.dll";    // may freely use kernel32.dll at runtime
p.FunctionName  = "InstallHooks";
p.Flags         = MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT;

HRESULT hr = Mhook_Inject(&p);   // hooks installed before entry point runs
```

**Static builds and `DELAY_UNTIL_INIT`:** the static companion DLL still has an
ntdll-only import table (so it can be loaded before Win32 is available), but the
injection *function itself* can call Win32 APIs at runtime — including
`LdrLoadDll` to load a Win32-dependent DLL and `LdrGetProcedureAddress` to
call into it.

**`MHOOK_INJECT_FLAG_ASYNC`** — by default `Mhook_Inject` is synchronous: it
blocks until the injection function has returned (even with `DELAY_UNTIL_INIT`,
in which case it blocks until the deferred call fires). With `ASYNC` set it
returns `S_OK` once the remote thread is created, and completion is reported
through whichever of these are non-NULL:

- **`Event`** — duplicated into the target and set when the injection function returns.
- **`IoStatusBlock`** — its `Status` is set to `STATUS_PENDING` before the call
  returns and overwritten with the final `NTSTATUS` on completion (the target
  writes it back across the process boundary).
- **`ApcRoutine` / `ApcContext`** — a user APC `(ApcContext, IoStatusBlock, Reserved)`
  queued to the **calling thread**; it runs only while that thread is in an
  alertable wait (e.g. `SleepEx(., TRUE)`), as with `ReadFileEx`.

All four NULL is pure fire-and-forget. Delivering `IoStatusBlock` / `ApcRoutine`
duplicates a handle to the calling process / thread into the target (which already
holds `PROCESS_ALL_ACCESS`).

```c
// Async: return immediately, learn of completion via an event
HANDLE done = CreateEventW(NULL, FALSE, FALSE, NULL);
MHOOK_INJECT_PARAMS p = { sizeof(p) };
p.TargetProcess   = pi.hProcess;
p.FunctionPointer = InstallHooks;
p.Flags           = MHOOK_INJECT_FLAG_ASYNC;
p.Event           = done;

Mhook_Inject(&p);                       // returns S_OK once the thread is created
// ... do other work ...
WaitForSingleObject(done, INFINITE);    // the injection function has now returned
```

> **Caveat (synchronous `DELAY_UNTIL_INIT` on a suspended target):** the deferred
> call fires only when the target's main thread reaches its entry point, so a
> *synchronous* delayed injection into a `CREATE_SUSPENDED` process blocks until
> you let the target run (e.g. resume it from another thread) or the 30 s timeout
> elapses. Resume the target concurrently, or use `ASYNC`.

### `MHOOK_INJECT_CONTEXT` (received by the injected function)

```c
typedef void (__cdecl *MhookInjectedFn)(MHOOK_INJECT_CONTEXT *ctx);

typedef struct _MHOOK_INJECT_CONTEXT {
    ULONG          Size;        // sizeof(MHOOK_INJECT_CONTEXT)
    MhookSetHookFn SetHook;     // Mhook_SetHook for the target process
    MhookUnhookFn  Unhook;      // Mhook_Unhook for the target process
    PVOID          UserData;    // pointer to the UserData copy in the target
    SIZE_T         UserDataSize;
} MHOOK_INJECT_CONTEXT;
```

### Example

```c
// hooks.c  — compiled into hooks.dll (see "Static build" notes below)
#include "mhook-inject/mhook_inject.h"

static NTSTATUS (NTAPI *TrueNtTerminateProcess)(HANDLE, NTSTATUS);

static NTSTATUS NTAPI HookNtTerminateProcess(HANDLE h, NTSTATUS s) {
    // ... custom logic ...
    return TrueNtTerminateProcess(h, s);
}

void __cdecl InstallHooks(MHOOK_INJECT_CONTEXT *ctx) {
    TrueNtTerminateProcess = NtTerminateProcess;
    ctx->SetHook((PVOID *)&TrueNtTerminateProcess, HookNtTerminateProcess);
}
```

```c
// injector.c  — caller that creates the suspended process and injects
#include "mhook-inject/mhook_inject.h"

PROCESS_INFORMATION pi = ...;   // created with CREATE_SUSPENDED

MHOOK_INJECT_PARAMS p = { sizeof(p) };
p.TargetProcess  = pi.hProcess;
p.FunctionPointer = InstallHooks;   // or use DllPath + FunctionName

HRESULT hr = Mhook_Inject(&p);     // returns S_OK when hooks are installed
ResumeThread(pi.hThread);
```

### Static build — what consumers must link and export

When using the **static** `mhook_inject.lib`, the injection function lives in
a DLL that is loaded into the target process.  That DLL must:

1. **Link `mhook_inject.lib`** — provides `Mhook_Inject` (for the calling side)
   and `_internal_Execute` (the remote entry point called by the bootstrap thunk).

2. **Link `mhook.lib`** — provides `Mhook_SetHook`/`Mhook_Unhook`, which
   `_internal_Execute` references directly in static builds.

   **x86 only:** also link **`mhook_seh3.lib`** *unless* your DLL already links a
   CRT / WDK runtime that provides `_except_handler3`.  `_internal_Execute` uses
   `__try`/`__except`, and a CRT-free x86 image has no language SEH handler or
   SafeSEH load-config; `mhook_seh3.lib` supplies a minimal `_except_handler3` (its
   only import is `ntdll!RtlUnwind`) plus the `_load_config_used` that makes the
   image SafeSEH-aware.  Build the file `inject_entry.c` of your own code, if any
   uses `__try`, **without** `/GL` on x86 (under `/GL` the compiler emits
   `_except_handler4`, which `mhook_seh3` does not provide).  x64 needs none of
   this (it uses ntdll's `__C_specific_handler` via `ntdll_extra.lib`).  If your
   DLL uses `__finally` or nested SEH, provide your own full `_except_handler3`
   (or link a CRT) instead — the bundled one is minimal.

3. **Re-export `_internal_Execute`** — the bootstrap thunk locates and calls this
   symbol in the companion DLL.  Add it to the DLL's `.def` file:

   ```
   EXPORTS
       _internal_Execute        ← re-exported from mhook_inject.lib
       InstallHooks             ← your injection function
   ```

   Alternatively pass `/EXPORT:_internal_Execute` to the linker.

The injection DLL's **import table** may only reference `ntdll.dll` if it must
be loaded before Win32 is initialised (i.e. without `MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT`).
With the delay flag set, the companion DLL is still loaded early (import table
must be ntdll-only), but the injection *function* runs after Win32 is available
and can call Win32 APIs or load Win32 DLLs dynamically via `LdrLoadDll`.

### Dynamic build — what consumers must do

When using **`mhook_inject.dll`**, the DLL itself is the companion that runs in
the target process.  The user's injection function lives in a **separate DLL**
that only needs to import from `ntdll.dll`:

- Pass `DllPath` / `FunctionName` (or `FunctionPointer`) in `MHOOK_INJECT_PARAMS`.
- The user's DLL does **not** need to export `_internal_Execute` or link
  `mhook_inject.lib`.
- `mhook_inject.dll` and `mhook.dll` must be present alongside the user's DLL
  (or supply `MhookDllPath`).

---

## Building

### Prerequisites

| Requirement | Notes |
|---|---|
| Visual Studio 2022 | v145 toolset (MSVC 14.3x) |
| Windows SDK 10.0 | Any recent `10.0.x` version |
| PowerShell 7+ | Optional — for build and verify scripts |

### Opening in Visual Studio

Open `libmhook.slnx`.  All eight configurations are available directly in the
IDE.

### Command line

```powershell
# Build a specific configuration
msbuild libmhook.slnx /p:Configuration=Release /p:Platform=x64

# Build all 8 configurations
.\build.ps1

# Build only x64 configurations
.\build.ps1 -Arch x64

# Build only Release configurations (both architectures)
.\build.ps1 -Configuration Release,ReleaseDynamic

# Build exact combinations
.\build.ps1 -Target x64/Release,x86/Release
```

### Configurations

| Configuration | Type | Description |
|---|---|---|
| `Debug\|x64` | Static library | Full debug info, no optimisations, no CRT |
| `Release\|x64` | Static library | Optimised, LTCG/WPO, no CRT |
| `DebugDynamic\|x64` | DLL | Debug `mhook.dll` + import library |
| `ReleaseDynamic\|x64` | DLL | Optimised `mhook.dll` + import library |
| _(same four for Win32 / x86)_ | | |

All configurations import exclusively from `ntdll.dll`.

### Build outputs

```
build/artifacts/
  libmhook/<platform>/<configuration>/
    mhook.lib              ← link this (static: self-contained; dynamic: import lib)
    mhook_internal.lib     ← intermediate archive (static builds only)
    mhook.dll              ← DLL (dynamic builds only)
    mhook.pdb
  mhook_inject/<platform>/<configuration>/
    mhook_inject.lib       ← link this (static: self-contained; dynamic: import lib)
    mhook_inject_internal.lib  ← intermediate archive (static builds only)
    mhook_inject.dll       ← DLL (dynamic builds only)
    mhook_inject.pdb
  mhook-unit-tests/<platform>/<configuration>/
    mhook-unit-tests.exe
  ntdll_extra_stub/<platform>/<configuration>/
    ntdll_extra.lib        ← already bundled into static mhook.lib and mhook_inject.lib
  mhook_test_uninitialized_inject/<platform>/<configuration>/
    mhook_test_uninitialized_inject.dll
  mhook_inject_test_companion/<platform>/<configuration>/
    mhook_inject_test_companion.dll
```

**Static `mhook.lib` consumers** link only `mhook.lib`.  The `ntdll_extra.lib`
import stubs (for ntdll symbols absent from the SDK's `ntdll.lib`) are bundled
into `mhook.lib` at build time.

**Static `mhook_inject.lib` consumers** link `mhook_inject.lib` + `mhook.lib`
and must re-export `_internal_Execute` from their companion DLL (see
[Static build notes](#static-build--what-consumers-must-link-and-export) above).

**DLL consumers** link the respective import library and distribute the DLL.

---

## Testing

Unit tests use [Google Test](https://github.com/google/googletest) (v1.17.0,
included as a git submodule under `third_party/googletest`).

```powershell
# Build and run all 8 configurations (default behaviour)
.\run-tests.ps1

# Run tests without rebuilding
.\run-tests.ps1 -NoBuild

# Run tests for a subset of configurations
.\run-tests.ps1 -NoBuild -Arch x64
.\run-tests.ps1 -NoBuild -Configuration Release,ReleaseDynamic
.\run-tests.ps1 -NoBuild -Target x64/Release,x86/Debug

# Filter to specific test cases
.\run-tests.ps1 -NoBuild -Filter "InjectTest*"

# Override the per-configuration timeout (default: 10 s)
.\run-tests.ps1 -NoBuild -TimeoutSeconds 60

# Run each configuration N times to surface flaky tests (failed iterations keep their artifacts)
.\run-tests.ps1 -NoBuild -Repeat 10

# Capture Time Travel Debugging traces alongside test logs (requires an elevated session)
.\run-tests.ps1 -NoBuild -Trace -KeepResults

# Stop as soon as one iteration fails (combine with -Repeat and -Trace to capture a trace of the first failure)
.\run-tests.ps1 -NoBuild -Repeat 100 -Trace -StopOnFailure

# Run a single configuration's test binary directly
.\build\artifacts\mhook-unit-tests\x64\Release\mhook-unit-tests.exe

# Verify all outputs import only from ntdll.dll
.\verify-ntdll-only.ps1
```

The test suite covers:

- Basic hooks on a range of Windows API functions (`NtOpenProcess`,
  `MessageBoxW`, `GetPrinter`, `getaddrinfo`, etc.)
- Hook install/uninstall round-trips
- **`UninitializedProcess_HookFiresBeforeInit`** — injects a thread into a
  freshly-created, still-suspended `cmd.exe` before its main thread has
  executed a single instruction, installs a hook on `NtTerminateProcess`, and
  asserts the hook fires when the process eventually exits.
- **`MhookInjectTest.ExecutesInUninitializedProcess`** — exercises `Mhook_Inject`
  end-to-end: injects a function into a suspended `cmd.exe` that writes a known
  marker to stdout, and asserts the marker is received.

---

## Design notes

### ntdll-only dependency

Every code path in `mhook.cpp` uses NT native APIs directly:

| Purpose | API used |
|---|---|
| Memory allocation | `RtlAllocateHeap` / `RtlFreeHeap` (via `RtlProcessHeap()` PEB macro) |
| Virtual memory | `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory` |
| Thread suspension | `NtGetNextThread`, `NtSuspendThread`, `NtResumeThread` |
| Thread context | `NtGetContextThread`, `NtSetContextThread` |
| Synchronisation | `RtlInitializeCriticalSection`, `RtlEnterCriticalSection`, `RtlLeaveCriticalSection` |
| Debug output (debug builds) | `vDbgPrintEx` |

Type definitions (`NTSTATUS`, `UNICODE_STRING`, `CLIENT_ID`, etc.) and all
ntdll declarations live in `src/nt_defs.h`.  `<windows.h>` is never included
by the library itself; this keeps IDE IntelliSense free of inaccessible Win32
APIs when working on the library code.

### ntdll_extra_stub

Several ntdll exports are absent from the Windows SDK's `ntdll.lib`
(`NtGetNextThread`, `LdrLoadDll`, `LdrGetProcedureAddress`, `_snprintf`,
`_vsnprintf`, `memset`, `memcpy`, `memmove`, `memcmp`).  The
`ntdll_extra_stub` project provides a stub DLL whose `.def` file carries
`LIBRARY ntdll.dll`, causing the linker to generate import stubs that resolve
to the real system DLL at runtime.  These stubs are bundled into the static
`mhook.lib` at build time.

### Disassembler

Instruction length decoding for x86 and x64 is handled by the embedded
`disasm-lib` (originally by Matt Conover).  It is used to find safe
instruction boundaries when building the trampoline for each hook.

---

## Repository layout

```
libmhook.slnx               Visual Studio 2022 solution
build.ps1                   Build all 8 configs (or a filtered subset via -Arch/-Configuration/-Target)
run-tests.ps1               Build then run tests; -NoBuild skips the build step
verify-ntdll-only.ps1       Check that all outputs only import from ntdll.dll
src/
  nt_defs.h                 NT native API types and declarations
  exports.def               DLL export list (dynamic configs)
  mhook-lib/
    mhook.h                 Public API header
    mhook.cpp               Hook engine
  disasm-lib/               Instruction-length disassembler
  ntdll_extra_stub/         Stub DLL for ntdll symbols absent from SDK ntdll.lib
  mhook-inject/
    mhook_inject.h          Public API header
    mhook_inject.cpp        Mhook_Inject implementation (calling-process side)
    inject_entry.c          _internal_Execute (runs in target process)
    inject_bootstrap_thunk_x64/x86.asm  Bootstrap-thunk stubs
  mhook-unit-tests/         Google Test test runner
  mhook_test_uninitialized_inject/  Companion DLL for the pre-init hook test (manual)
  mhook_inject_test_companion/      Companion DLL for the Mhook_Inject test
third_party/
  googletest/               Google Test v1.17.0 (git submodule)
```
