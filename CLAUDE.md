# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

mhook is a Windows function-hooking library (x86 + x64) that patches target functions in-place at runtime, using a disassembler to build a trampoline so the original function can still be called. The entire library depends only on `ntdll.dll` — no kernel32, Win32, or CRT — enabling use during early process initialisation before those subsystems exist.

## Build

**Prerequisites:** Visual Studio 2022 (v145 toolset), Windows SDK 10.0, PowerShell 7+. Google Test is a git submodule under `third_party/googletest`; on a fresh clone run `git submodule update --init` before building or the test project won't compile.

```powershell
# All 8 configurations
.\build.ps1

# Filtered subsets
.\build.ps1 -Arch x64
.\build.ps1 -Configuration Release,ReleaseDynamic
.\build.ps1 -Target x64/Release,x86/Debug

# Single configuration via MSBuild directly
msbuild libmhook.slnx /p:Configuration=Release /p:Platform=x64
```

**Configurations:** 2 architectures (`x64`, `x86`) × 4 variants (`Debug`, `DebugDynamic`, `Release`, `ReleaseDynamic`).  Static builds produce `.lib`; Dynamic builds produce `.dll` + import `.lib`.

Build artifacts land in `build/artifacts/`.

## Testing

```powershell
# Build then run all 8 configurations
.\run-tests.ps1

# Skip rebuild
.\run-tests.ps1 -NoBuild

# Subset of configurations
.\run-tests.ps1 -NoBuild -Target x64/Debug
.\run-tests.ps1 -NoBuild -Arch x64 -Configuration Release,ReleaseDynamic

# Filter to specific test cases (Google Test filter syntax)
.\run-tests.ps1 -NoBuild -Filter "MhookInjectTest*"

# Run a test binary directly
.\build\artifacts\mhook-unit-tests\x64\Release\mhook-unit-tests.exe --gtest_filter="*NtOpenProcess*"

# Stress for flakiness
.\run-tests.ps1 -NoBuild -Repeat 10 -StopOnFailure

# TTD traces (requires elevation)
.\run-tests.ps1 -NoBuild -Trace -KeepResults

# CDB post-mortem script (no elevation needed)
.\run-tests.ps1 -NoBuild -Cdb my_script.cdb

# Verify all outputs only import from ntdll.dll
.\verify-ntdll-only.ps1
```

## Architecture

### Core hook engine (`src/mhook-lib/`)

`mhook.cpp` implements `Mhook_SetHook` / `Mhook_Unhook`.  The central data structure is `MHOOKS_TRAMPOLINE`, which stores:
- a copy of the overwritten bytes from the target function (`codeTrampoline`)
- a jump stub pointing at the hook function (`codeJumpToHookFunction`)
- the unmodified original bytes for reference (`codeUntouched`)

On `SetHook`, the library: suspends all other threads (via `NtGetNextThread` + `NtSuspendThread`), uses `disasm-lib` to find a safe instruction boundary, allocates a trampoline near the target (within ±2 GB for x64 relative jumps), copies + patches displaced instructions (fixing RIP-relative addresses), writes a jump at the start of the target, then resumes threads.

### Remote injection (`src/mhook-inject/`)

`mhook_inject.cpp` implements `Mhook_Inject` (calling-process side): allocates a code+data blob in the target process, writes the `MhookInjectRemoteParams` struct, creates a remote thread running the shellcode stub, and waits for completion.

`inject_entry.c` is the code that runs inside the target process (`_internal_Execute`): loads the companion DLL via `LdrLoadDll`, resolves the user function, builds a `MHOOK_INJECT_CONTEXT`, and calls the function.

`inject_entry_thunk_x64/x86.asm` are MASM thunks that call `DoDelayedEntry` then JMP (not CALL) to the returned address so no hook frame remains on the stack when `DELAY_UNTIL_INIT` is used.

`inject_shellcode_x86.asm` / `inject_entry_thunk_x64.asm` are the shellcode stubs written into the remote process.

**`DELAY_UNTIL_INIT` flow:** when set, `Mhook_Inject` hooks the process entry point instead of calling the injection function immediately. `inject_entry.c` polls `PEB_LDR_DATA.Initialized` — once true (all `DllMain` handlers have run), it calls the user function before the entry point executes.

**Static vs Dynamic builds:**
- Static (`mhook.lib` + `mhook_inject.lib`): the companion DLL must re-export `_internal_Execute` and link both libs.
- Dynamic (`mhook.dll` + `mhook_inject.dll`): `mhook_inject.dll` is the companion; the user's DLL only needs to export the injection function and import from ntdll.

### `MhookInjectRemoteParams` struct (`src/mhook-inject/inject_params.h`)

This `#pragma pack(1)` struct is written into the remote process immediately after the shellcode. Its layout is fixed and verified with `static_assert` offset checks for both x64 (180 bytes) and x86 (80 bytes). Any change to field order must keep all offset assertions passing.

### `ntdll_extra_stub` (`src/ntdll_extra_stub/`)

Several ntdll exports are absent from the Windows SDK's `ntdll.lib` (`NtGetNextThread`, `LdrLoadDll`, `LdrGetProcedureAddress`, `_snprintf`, `_vsnprintf`, `memset`, `memcpy`, `memmove`, `memcmp`). This stub DLL's `.def` carries `LIBRARY ntdll.dll`, making the linker generate import stubs that resolve to the real system DLL. These stubs are bundled into the static `mhook.lib` at build time.

### `src/nt_defs.h`

Replaces `<windows.h>` throughout the library. Includes only `<minwindef.h>` and `<winnt.h>` (no kernel32/user32 surface). All NT native type definitions (`NTSTATUS`, `UNICODE_STRING`, `NT_PEB`, `PEB_LDR_DATA_MIN`, etc.) and `ntdll` function declarations live here.

**Hard rule:** never include `<windows.h>` in library code (`mhook.cpp`, `inject_entry.c`, `mhook_inject.cpp`, or any header they include). Test code (`tests.cpp`) is exempt.

### `disasm-lib` (`src/disasm-lib/`)

Instruction-length decoder (originally by Matt Conover) for x86 and x64. Used by the hook engine to find safe instruction boundaries when building the trampoline — copies whole instructions, never splits one mid-byte.

### Test companion DLLs

- `mhook_inject_test_companion/` — companion DLL used by `MhookInjectTest` (exercises `Mhook_Inject` end-to-end).
- `mhook_test_uninitialized_inject/` — companion for the `UninitializedProcess_HookFiresBeforeInit` test, which injects into a still-suspended `cmd.exe` before its main thread runs a single instruction.
- `mhook_inject_win32_test_companion/` — Win32-linked companion for testing the `DELAY_UNTIL_INIT` path. This should behave like what a consumer would normally generate for a dll - i.e. debug builds links dynamic debug crt, has security features enabled etc.
