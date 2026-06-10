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

`mhook_inject.cpp` implements `Mhook_Inject` (calling-process side): allocates a code+data blob in the target process, writes the `MhookInjectRemoteParams` struct, creates a remote thread running the bootstrap-thunk stub, and waits for completion.

`inject_entry.c` is the code that runs inside the target process (`_internal_Execute`): loads the companion DLL via `LdrLoadDll`, resolves the user function, builds a `MHOOK_INJECT_CONTEXT`, and calls the function.

`inject_delayed_entry_thunk_x64/x86.asm` are MASM thunks that call `DoDelayedEntry` then JMP (not CALL) to the returned address so no hook frame remains on the stack when `DELAY_UNTIL_INIT` is used.

`inject_bootstrap_thunk_x64.asm` / `inject_bootstrap_thunk_x86.asm` are the bootstrap-thunk stubs written into the remote process (the position-independent code that `LdrLoadDll`s the companion DLL and calls `_internal_Execute`).

**`DELAY_UNTIL_INIT` flow:** when set, the injection function is deferred until the target has finished loader initialisation, by hooking the process **entry point** so the user function runs on the target's *main* thread (with Win32 available) just before the entry point executes. The delayed-vs-immediate decision is **caller-authoritative**: `Mhook_Inject` reads the target's `PEB_LDR_DATA.Initialized` *before* creating the injection thread and passes `MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED` in the remote params; `_internal_Execute` trusts that bit (falling back to its own `IsProcessInitialized()` only if the caller couldn't read the state). This indirection exists because **creating the injection thread itself runs loader init in the target** (see Invariants), so an in-target `IsProcessInitialized()` check at `_internal_Execute` time is unreliable.

**Static vs Dynamic builds:**
- Static (`mhook.lib` + `mhook_inject.lib`): the companion DLL must re-export `_internal_Execute` and link both libs.
- Dynamic (`mhook.dll` + `mhook_inject.dll`): `mhook_inject.dll` is the companion; the user's DLL only needs to export the injection function and import from ntdll.

**Access guard & error codes:** `Mhook_Inject` deliberately requires a `PROCESS_ALL_ACCESS` target handle (a basic anti-exploitation guard — it reads the handle's *granted* access via `NtQueryObject`; a `static_assert` pins `PROCESS_ALL_ACCESS == 0x1FFFFF` so a future SDK change forces a manual decision). It returns the public `MHOOK_INJECT_E_*` HRESULTs (declared in `mhook_inject.h`), which use the Customer bit (`0xA00000xx`). Dynamic builds also embed a message-table resource so those codes are `FormatMessage`-able from `mhook_inject.dll` (see Invariants).

### `MhookInjectRemoteParams` struct (`src/mhook-inject/inject_params.h`)

This `#pragma pack(1)` struct is written into the remote process immediately after the bootstrap thunk. Its layout is fixed and verified with `static_assert` offset checks for both x64 (180 bytes) and x86 (80 bytes). Any change to field order must keep all offset assertions passing.

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

## Invariants & gotchas (non-obvious, easy to break)

### x64 bootstrap-thunk stack alignment
The remote-thread bootstrap thunks (`src/mhook-inject/inject_bootstrap_thunk_x64.asm` and `src/mhook-unit-tests/uninit_test_bootstrap_thunk_x64.asm`) **must keep RSP 16-byte aligned at every `call`**. Per the x64 ABI, RSP ≡ 8 (mod 16) at `PROC` entry; after `push rbx` it is ≡ 0, so the prologue's `sub rsp, N` must use **N ≡ 0 (mod 16)** — use `0x20` (the 32-byte shadow space), not `0x28`. A misaligned stack makes any 16-byte-aligned local in a callee (notably the `CONTEXT` used by `NtGetContextThread` in `SuspendOneThread`) fault with `STATUS_DATATYPE_MISALIGNMENT`, with confusing downstream symptoms. Three things must stay in sync: the prologue `sub rsp`, the matching epilogue `add rsp`, and — for `inject_bootstrap_thunk_x64.asm` — the hand-encoded `UNWIND_INFO` (`rp.BootstrapThunkUI[...]` / `UWOP_ALLOC_SMALL`) in `mhook_inject.cpp`.

### Injecting a runnable thread initialises the target process
Creating a thread with `NtCreateThreadEx` in a still-suspended target runs `ntdll!LdrInitializeThunk → LdrpInitializeProcess` as a side effect (whichever thread runs user code first wins the loader-init CAS), flipping `PEB_LDR_DATA.Initialized` to TRUE before `_internal_Execute` runs. This is why the `DELAY_UNTIL_INIT` decision is made caller-side (above). Background on the loader/thread mechanics is captured in `G:\projects-ext\claude-notes\ntapi\` (`process-initialization.md`, `NtCreateThreadEx.md`).

### Thread suspend/resume contract (`mhook.cpp`)
- `SuspendOtherThreads` walks threads with `NtGetNextThread`; the enumeration cursor must **never** be reset to `NULL` mid-walk (passing `NULL` restarts from the first thread → infinite re-suspension). Keep the last-returned handle as the cursor.
- `SuspendOneThread` must **resume on every failure path** (it suspends first, then checks the IP) — never return failure with the thread left suspended, or the target's main thread can be stranded.

### Debugging the injected path
Attaching a user-mode debugger to the target sets `PEB.BeingDebugged`, which switches ntdll to the debug heap and serialises the loader differently — this can mask timing-dependent injection bugs (heisenbugs). For debugger-free diagnostics from inside the target, write to the target's stdout via `RtlCurrentPeb()->ProcessParameters->StandardOutput` (the inject tests capture it and print it in the assertion's `Output: [...]`). `ODPRINTF` (debug builds) routes to `vDbgPrintEx` and only shows under a debugger.

### Error-message resource must stay in sync (`mhook_inject_messages.mc`)
The `MHOOK_INJECT_E_*` strings are an `RT_MESSAGETABLE` compiled from `mhook_inject_messages.mc` and linked into `mhook_inject.dll` (dynamic configs only, via a `<CustomBuild>` + `<ResourceCompile>` in `mhook_inject.vcxproj`; static `.lib` configs carry no resource). It **must** be compiled with `mc -c` — that Customer-bit flag is what makes the generated message IDs equal the `0xA00000xx` HRESULTs (mc's docs call it "bit 28", but it actually sets bit 29). The `.mc`'s `MessageId` values (`0x1..0x5`) and the `MHOOK_INJECT_E_*` defines in `mhook_inject.h` are hand-maintained and must stay in lockstep; the `mc`-generated header is intentionally not `#include`d anywhere (`mhook_inject.h` is the single source of truth).
