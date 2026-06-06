# mhook

A Windows function-hooking library for x86 and x64.  mhook patches target
functions in-place at runtime, using a disassembler to copy the displaced
instructions into a trampoline so the original function can still be called.

**Key property:** the library depends only on `ntdll.dll` — no kernel32, no
Win32 subsystem, no CRT.  This means hooks can be installed before the process
is fully initialised, including from a thread injected into a still-suspended
process.

Original library by Marton Anka (2007–2014); disassembly engine by Matt
Conover.  See [COPYING](COPYING) for the MIT licence.

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

# Build and test all 8 configurations
.\build-and-test.ps1
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
    mhook.lib            ← link this (static builds: self-contained)
    mhook_internal.lib   ← intermediate archive (static builds only)
    mhook.dll            ← DLL (dynamic builds only)
    mhook.pdb
  mhook-unit-tests/<platform>/<configuration>/
    mhook-unit-tests.exe
  ntdll_extra_stub/<platform>/<configuration>/
    ntdll_extra.lib      ← already bundled into static mhook.lib
  mhook_test_uninitialized_inject/<platform>/<configuration>/
    mhook_test_uninitialized_inject.dll
```

**Static library consumers** link only `mhook.lib`.  The `ntdll_extra.lib`
import stubs (for ntdll symbols absent from the SDK's `ntdll.lib`) are bundled
into `mhook.lib` at build time and do not need to be specified separately.

**DLL consumers** link `mhook.lib` (the import library) and distribute
`mhook.dll`.

---

## Testing

Unit tests use [Google Test](https://github.com/google/googletest) (v1.17.0,
included as a git submodule under `third_party/googletest`).

```powershell
# Run all tests for one configuration
.\build\artifacts\mhook-unit-tests\x64\Release\mhook-unit-tests.exe

# Build and run all 8 configurations
.\build-and-test.ps1

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

---

## Design notes

### ntdll-only dependency

Every code path in `mhook.cpp` uses NT native APIs directly:

| Purpose | API used |
|---|---|
| Memory allocation | `RtlAllocateHeap` / `RtlFreeHeap` (via `RtlProcessHeap()` PEB macro) |
| Virtual memory | `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory` |
| Instruction cache flush | `NtFlushInstructionCache` |
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
build-and-test.ps1          Build all 8 configs and run tests
verify-ntdll-only.ps1       Check that all outputs only import from ntdll.dll
src/
  nt_defs.h                 NT native API types and declarations
  exports.def               DLL export list (dynamic configs)
  mhook-lib/
    mhook.h                 Public API header
    mhook.cpp               Hook engine
  disasm-lib/               Instruction-length disassembler
  ntdll_extra_stub/         Stub DLL for ntdll symbols absent from SDK ntdll.lib
  mhook-unit-tests/         Google Test test runner
  mhook_test_uninitialized_inject/  Companion DLL for the pre-init hook test
third_party/
  googletest/               Google Test v1.17.0 (git submodule)
```
