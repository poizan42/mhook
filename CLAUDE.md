# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

mhook is a Windows function-hooking library (x86 + x64) that patches target functions in-place at runtime, using a disassembler to build a trampoline so the original function can still be called. The entire library depends only on `ntdll.dll` — no kernel32, Win32, or CRT — enabling use during early process initialisation before those subsystems exist.

It ships in two halves: the **hook engine** (`Mhook_SetHook`/`Mhook_Unhook`, `src/mhook-lib/`) and a **remote-injection** component (`Mhook_Inject`, `src/mhook-inject/`) that loads a companion DLL into another process and runs a user function there — optionally deferred until the target finishes loader initialisation. Both are equally constrained to ntdll-only.

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

# Stress for flakiness (-Parallel N runs the repeat/config work N-wide; raise
# -TimeoutSeconds since the box is loaded)
.\run-tests.ps1 -NoBuild -Repeat 10 -StopOnFailure
.\run-tests.ps1 -NoBuild -Arch x86 -Filter "MhookInjectTest.*Delay*" -Repeat 40 -Parallel 8 -TimeoutSeconds 120

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

`mhook_inject.cpp` implements `Mhook_Inject` (calling-process side): allocates a code+data blob in the target process, writes the `MhookInjectRemoteParams` struct, and creates a remote thread running the bootstrap-thunk stub. In synchronous mode it then waits for the injection to finish; in async mode (`MHOOK_INJECT_FLAG_ASYNC`) it returns as soon as the thread is created and completion is reported out-of-band (see *Synchronous vs async completion* below).

`inject_entry.c` is the code that runs inside the target process (`_internal_Execute`): loads the companion DLL via `LdrLoadDll`, resolves the user function, builds a `MHOOK_INJECT_CONTEXT`, and calls the function.

`inject_delayed_entry_thunk_x64/x86.asm` are MASM thunks that call `DoDelayedEntry` then JMP (not CALL) to the returned address so no hook frame remains on the stack when `DELAY_UNTIL_INIT` is used.

`inject_bootstrap_thunk_x64.asm` / `inject_bootstrap_thunk_x86.asm` are the bootstrap-thunk stubs written into the remote process (the position-independent code that `LdrLoadDll`s the companion DLL and calls `_internal_Execute`).

**`DELAY_UNTIL_INIT` flow:** when set, the injection function is deferred until the target has finished loader initialisation, by hooking the process **entry point** so the user function runs on the target's *main* thread (with Win32 available) just before the entry point executes. The delayed-vs-immediate decision is **caller-authoritative**: `Mhook_Inject` reads the target's `PEB_LDR_DATA.Initialized` *before* creating the injection thread and passes `MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED` in the remote params; `_internal_Execute` trusts that bit (falling back to its own `IsProcessInitialized()` only if the caller couldn't read the state). This indirection exists because **creating the injection thread itself runs loader init in the target** (see Invariants), so an in-target `IsProcessInitialized()` check at `_internal_Execute` time is unreliable.

**Synchronous vs async completion:** the public flag `MHOOK_INJECT_FLAG_ASYNC` and the `Event` / `IoStatusBlock` / `ApcRoutine`+`ApcContext` fields of `MHOOK_INJECT_PARAMS` select how completion is reported:
- *sync, no delay* — blocks until the injection fn returns; result is the thread exit status (read via `NtQueryInformationThread`).
- *sync + `DELAY_UNTIL_INIT`* — blocks until the entry-point hook fires **and** the fn returns, via an internal auto-reset event signalled by `_internal_Execute`/`DoDelayedEntry`. **Caveat:** for a *suspended* target the hook can only fire once the main thread runs, so the caller must let it run (e.g. resume it on another thread) or the call waits out the timeout.
- *async* — returns `S_OK` once the thread is created; completion is delivered to the caller-provided `Event` (duplicated into the target and signalled), `IoStatusBlock` (the target writes the final `NTSTATUS` across the process boundary via a duplicated caller-process handle), and/or a user APC (`NtQueueApcThread` to the calling thread — fires only when that thread is in an alertable wait). Delivering `IoStatusBlock`/APC duplicates handles to the calling process/thread into the target; acceptable under the `PROCESS_ALL_ACCESS` trust model (below).

The synchronous-wait timeout is configurable via `MHOOK_INJECT_PARAMS.TimeoutMs` (a DWORD ms count; `0` = default **30 s**, `INFINITE` = no timeout, would-be-negative values rejected with `MHOOK_INJECT_E_PARAMS`). It is the **total** budget across both sync wait phases (bootstrap thread, then the delay hook), and is measured with `RtlQueryUnbiasedInterruptTime` + **relative** `NtWaitForSingleObject` timeouts — both run off monotonic interrupt time, so the budget is immune to wall-clock changes and excludes system sleep. (`async` mode never waits, so `TimeoutMs` is ignored.)

**Static vs Dynamic builds:**
- Static (`mhook.lib` + `mhook_inject.lib`): the companion DLL must re-export `_internal_Execute` and link both libs.
- Dynamic (`mhook.dll` + `mhook_inject.dll`): `mhook_inject.dll` is the companion; the user's DLL only needs to export the injection function and import from ntdll.

**Cross-architecture (64-bit injector → 32-bit WOW64 target):** an x64 `mhook_inject` can inject an **x86** companion into a WOW64 target; the reverse (32→64) is `E_NOTIMPL` (no clean way to spawn a 64-bit thread from WOW64 — deferred). The whole payload is target-arch: the x86 bootstrap thunk is generated into the x64 build at build time (ml64 can't assemble x86 — see the thunk-generation invariant below), and the remote params use the explicit fixed-width `MHOOK_INJECT_REMOTE_PARAMS_X86` (108 bytes, no x64 unwind tail). `LdrLoadDll` is resolved from the target's **32-bit** ntdll (the WOW64 target maps both; `FindDllBaseInProcess` selects the one whose path contains `SysWOW64`, and the file parsed for the RVA is the injector's own ntdll path with `System32`→`SysWOW64`). The `DELAY_UNTIL_INIT` init check reads the target's **32-bit PEB** (the `ProcessWow64Information` pointer; `Ldr` @ +0x0C, `Initialized` @ +0x04). Constraints (all `MHOOK_INJECT_E_PARAMS`): DllPath+FunctionName form only (no FunctionPointer); companion PE machine must match the target. Dynamic cross-arch requires `MhookDllPath` (the x86 `mhook.dll`); the x86 `mhook_inject.dll` companion is taken from the same directory. **All completion modes work cross-arch** (sync, Event, IoStatusBlock, ApcRoutine): because a 32-bit target can't write back into the 64-bit caller, async `IoStatusBlock`/`ApcRoutine` are delivered by a **caller-side watcher thread** (`InjectWatcherProc` in `mhook_inject.cpp`) — the target signals an internal completion event and stashes its `NTSTATUS` in a small caller-owned slot (`MHOOK_INJECT_REMOTE_PARAMS.StatusSlot`); the watcher reads it (`NtReadVirtualMemory`) and does the IOSB write / Event signal / APC re-queue in-process. The watcher is bounded by `TimeoutMs` (target-death surfaces as `STATUS_IO_TIMEOUT`); a thread-per-injection for now (pooling is a future optimization).

**Access guard & error codes:** `Mhook_Inject` deliberately requires a `PROCESS_ALL_ACCESS` target handle (a basic anti-exploitation guard — it reads the handle's *granted* access via `NtQueryObject`; a `static_assert` pins `PROCESS_ALL_ACCESS == 0x1FFFFF` so a future SDK change forces a manual decision). It returns the public `MHOOK_INJECT_E_*` HRESULTs (declared in `mhook_inject.h`), which use the Customer bit (`0xA00000xx`). Dynamic builds also embed a message-table resource so those codes are `FormatMessage`-able from `mhook_inject.dll` (see Invariants).

### `MhookInjectRemoteParams` struct (`src/mhook-inject/inject_params.h`)

This `#pragma pack(1)` struct is written into the remote process immediately after the bootstrap thunk. Its layout is fixed and verified with `static_assert` offset checks for both x64 (236 bytes) and x86 (108 bytes). Any change to field order must keep all offset assertions passing. The x64-only tail (`RtlAddFunctionTable` … `BootstrapThunkUC`) carries the dynamic-unwind registration; the common completion tail (`CompletionEvent`, `CallerProcess`, `CallerThread`, `ApcRoutine`, `ApcContext`, `IoStatusBlock`, and `StatusSlot`) carries the async/sync-event plumbing — `StatusSlot` is the cross-arch caller-owned NTSTATUS slot the target writes for the watcher thread (above). A second, explicit fixed-width struct `MHOOK_INJECT_REMOTE_PARAMS_X86` (same file) mirrors the x86 layout with `UINT32`/8-byte-string fields and **no** unwind tail; its asserts compile in **both** builds so an x64 injector can construct the 32-bit layout for cross-arch injection. Keep the two in lockstep.

### `ntdll_extra_stub` (`src/ntdll_extra_stub/`)

Several ntdll exports the library uses are absent from the Windows SDK's `ntdll.lib` — loader/thread/memory primitives (`NtGetNextThread`, `LdrLoadDll`, `LdrGetProcedureAddress`, `_snprintf`/`_vsnprintf`, `memset`/`memcpy`/`memmove`/`memcmp`) plus the object/event primitives the async-injection path needs (`NtCreateEvent`, `NtSetEvent`, `NtDuplicateObject`, `NtQueueApcThread`, `NtTerminateThread`, `NtQueryObject`). This stub project's `.def` carries `LIBRARY ntdll.dll`, so the linker generates import stubs that resolve to the real system DLL. The def is **per-arch**: `ntdll_extra_stub_x64.def` additionally exports **`__C_specific_handler`** — the x64 SEH language handler that x64 ntdll exports but the SDK lib omits (its x86 analogue can't come from ntdll and is hand-written in `mhook_seh3`). The stub's import lib (`ntdll_extra.lib`) is merged into the static `mhook.lib` *and* `mhook_inject.lib` at build time via each project's `CombineWithNtdllExtra` `Lib` step.

### `src/nt_defs.h`

Replaces `<windows.h>` throughout the library. Includes only `<minwindef.h>` and `<winnt.h>` (no kernel32/user32 surface). All NT native type definitions (`NTSTATUS`, `UNICODE_STRING`, `NT_PEB`, `PEB_LDR_DATA_MIN`, etc.) and `ntdll` function declarations live here. It also defines the x64 unwind types `UNWIND_INFO` / `UNWIND_CODE` / the `UWOP_*` opcodes (guarded by `#ifdef _M_X64`), which `winnt.h` does **not** provide — but `RUNTIME_FUNCTION` **is** in `winnt.h`, so do not redefine it (a second definition would clash).

**Hard rule:** never include `<windows.h>` in library code (`mhook.cpp`, `inject_entry.c`, `mhook_inject.cpp`, or any header they include). Test code under `src/mhook-unit-tests/` (`tests.cpp`, `inject_test.cpp`, `uninit_test.cpp`) is exempt and uses `<windows.h>` freely. **Gotcha:** a test TU that needs *both* `nt_defs.h` (for NT types like `NTSTATUS`/`UNICODE_STRING`, which the lean Win32 surface doesn't provide) and `<windows.h>` must include `<windows.h>` **first** — `nt_defs.h`'s windows-free fallback macros (the `#ifndef S_OK` HRESULT block, `THREAD_PRIORITY_TIME_CRITICAL`, etc.) are `#ifndef`-guarded and self-skip once the SDK headers have defined them, so this avoids C4005 macro-redefinition warnings (see `uninit_test.cpp`).

### `disasm-lib` (`src/disasm-lib/`)

Instruction-length decoder (originally by Matt Conover) for x86 and x64. Used by the hook engine to find safe instruction boundaries when building the trampoline — copies whole instructions, never splits one mid-byte.

### `mhook_seh3` (`src/mhook_seh3/`) — x86 SEH support

x86 frame-based `__try`/`__except` needs a language handler (`_except_handler3` under `/GS-`) plus a `_load_config_used` for the SafeSEH handler table — both normally supplied by the CRT, so an ntdll-only x86 binary lacks them. This static lib provides them: a hand-written `_except_handler3` (`except_handler3_x86.asm`, its only dependency is `ntdll!RtlUnwind`) and a `_load_config_used` (`seh3_loadcfg_x86.c`) whose `SEHandlerTable`/`SEHandlerCount` point at the linker's `__safe_se_handler_table`/`__safe_se_handler_count`. It is x86-only (the `.asm` is `Win32`-only; the `.c` body is `#if defined(_M_IX86)`, so the x64 lib is empty — x64 uses ntdll's `__C_specific_handler` via `ntdll_extra_stub`). The lib is referenced by `mhook_inject` and `mhook_inject_test_companion` (Win32 only); it auto-links into the **dynamic** `mhook_inject.dll`, and ntdll-only static consumers link it explicitly. It is deliberately **not** merged into `mhook_inject.lib` (see the invariant below).

### Test companion DLLs

- `mhook_inject_test_companion/` — companion DLL used by `MhookInjectTest` (exercises `Mhook_Inject` end-to-end).
- `mhook_test_uninitialized_inject/` — companion for the `UninitializedProcess_HookFiresBeforeInit` test, which injects into a still-suspended `cmd.exe` before its main thread runs a single instruction.
- `mhook_inject_win32_test_companion/` — Win32-linked companion for testing the `DELAY_UNTIL_INIT` path. This should behave like what a consumer would normally generate for a dll - i.e. debug builds links dynamic debug crt, has security features enabled etc.

## Invariants & gotchas (non-obvious, easy to break)

### x64 bootstrap-thunk stack alignment
The remote-thread bootstrap thunks (`src/mhook-inject/inject_bootstrap_thunk_x64.asm` and `src/mhook-unit-tests/uninit_test_bootstrap_thunk_x64.asm`) **must keep RSP 16-byte aligned at every `call`**. Per the x64 ABI, RSP ≡ 8 (mod 16) at `PROC` entry; after `push rbx` it is ≡ 0, so the prologue's `sub rsp, N` must use **N ≡ 0 (mod 16)** — use `0x20` (the 32-byte shadow space), not `0x28`. A misaligned stack makes any 16-byte-aligned local in a callee (notably the `CONTEXT` used by `NtGetContextThread` in `SuspendOneThread`) fault with `STATUS_DATATYPE_MISALIGNMENT`, with confusing downstream symptoms. Three things must stay in sync: the prologue `sub rsp`, the matching epilogue `add rsp`, and — for `inject_bootstrap_thunk_x64.asm` — the `UNWIND_INFO` describing that prolog, filled field-by-field in `mhook_inject.cpp` (`rp.BootstrapThunkUI` + the trailing `rp.BootstrapThunkUC`; the `sub rsp,0x20` is the `UWOP_ALLOC_SMALL` code with `OpInfo = (0x20-8)/8`).

### Injecting a runnable thread initialises the target process
Creating a thread with `NtCreateThreadEx` in a still-suspended target runs `ntdll!LdrInitializeThunk → LdrpInitializeProcess` as a side effect (whichever thread runs user code first wins the loader-init CAS), flipping `PEB_LDR_DATA.Initialized` to TRUE before `_internal_Execute` runs. This is why the `DELAY_UNTIL_INIT` decision is made caller-side (above). Background on the loader/thread mechanics is captured in `G:\projects-ext\claude-notes\ntapi\` (`process-initialization.md`, `NtCreateThreadEx.md`).

### Remote-allocation cleanup is target-owned
Once the remote thread is created, `_internal_Execute` frees the remote allocation itself via `FreeAllocationAndExitThread` (`NtFreeVirtualMemory` + `NtTerminateThread`) on **every** exit path, in both sync and async modes; the caller frees `remoteBase` only when `NtCreateThreadEx` *failed* (gated by `remoteBaseOwned`), to avoid a double-free. Because `NtTerminateThread` bypasses the bootstrap thunk's epilog (which would otherwise call `RtlDeleteFunctionTable`), on x64 `FreeAllocationAndExitThread` must deregister the unwind entry (`RtlDeleteFunctionTable(&pParams->BootstrapThunkRF)`) **before** freeing — otherwise a dynamic-function-table entry dangles into freed memory and corrupts later exception dispatch in the target.

### x86 `__try` needs `mhook_seh3` — and a non-LTCG object
`inject_entry.c`'s hook-install `__try`/`__except` compiles on x86 only because `mhook_seh3.lib` supplies `_except_handler3` + the SafeSEH `_load_config_used` (above). Two non-obvious constraints:
- **`/GL` (Release `WholeProgramOptimization`) makes the x86 compiler emit `_except_handler4`, not `_except_handler3`, even under `/GS-`.** `_except_handler4` would need the full GS-cookie SEH machinery, which we don't provide. So `inject_entry.c` carries a per-file `<WholeProgramOptimization Condition="'$(Platform)'=='Win32'">false</WholeProgramOptimization>` in `mhook_inject.vcxproj` to force a non-LTCG object (→ `_except_handler3`). x64 is unaffected.
- **Do not merge `mhook_seh3` into `mhook_inject.lib`.** Our `_except_handler3` is minimal (single try-level, no `__finally`). If bundled into the static lib, a consumer linking it would have *their own* `__try` resolve to our minimal handler (one definition per image) — silently breaking their `__finally`/nested SEH. Keeping it a separate opt-in lib means consumers with a CRT/WDK runtime use their own full handler, and only no-runtime consumers link ours. (Linking it would not cause `LNK2005` — the WDK's copies are library members and lose the first-pull — but the override is a semantic footgun. The `CombineWithNtdllExtra` `Lib` step merges only `ntdll_extra.lib`.)

### Cross-arch x86 thunk is generated into the x64 build (no checked-in blob)
ml64 can't assemble x86, so the **x64** build can't directly assemble the x86 bootstrap thunk. Instead the x64 `mhook_inject` build (x64-only `<CustomBuild>` in `mhook_inject.vcxproj`) runs `utils/Asm-To-MasmDataBlob.ps1`, which: assembles `inject_bootstrap_thunk_x86.asm` with the 32-bit `ml.exe` (`$(VC_ExecutablePath_x64_x86)`), reads the `InjectBootstrapThunkEnd` offset (= code size) and the `.text$mn` bytes via `dumpbin` (`$(VC_ExecutablePath_x64_x64)`), and emits `$(IntDir)inject_bootstrap_thunk_x86_data.asm` — a native-MASM `.const` `DB` blob bracketed by `PUBLIC InjectBootstrapThunkX86Begin`/`End`. A second x64-only `<MASM>` item assembles that generated `.asm` with ml64 (auto-added to both the static `Lib` and dynamic `Link`, like any MASM item), and `mhook_inject.cpp` consumes the linked `InjectBootstrapThunkX86Begin`/`End` symbols in the `crossTo32` path (`#ifdef _M_X64`). So **`inject_bootstrap_thunk_x86.asm` is the single source of truth** — edit it and rebuild; nothing is checked in or hand-maintained. The thunk must remain position-independent with **no relocations** (all calls go indirectly through the params block) for the raw byte copy to be valid. `Asm-To-MasmDataBlob.ps1` is a generic utility (label names are parameters), reusable for any "embed a foreign-arch assembled blob as native data" need.

### Thread suspend/resume contract (`mhook.cpp`)
- `SuspendOtherThreads` walks threads with `NtGetNextThread`; the enumeration cursor must **never** be reset to `NULL` mid-walk (passing `NULL` restarts from the first thread → infinite re-suspension). Keep the last-returned handle as the cursor.
- `SuspendOneThread` must **resume on every failure path** (it suspends first, then checks the IP) — never return failure with the thread left suspended, or the target's main thread can be stranded.

### Debugging the injected path
Attaching a user-mode debugger to the target sets `PEB.BeingDebugged`, which switches ntdll to the debug heap and serialises the loader differently — this can mask timing-dependent injection bugs (heisenbugs). For debugger-free diagnostics from inside the target, write to the target's stdout via `RtlCurrentPeb()->ProcessParameters->StandardOutput` (the inject tests capture it and print it in the assertion's `Output: [...]`). `ODPRINTF` (debug builds) routes to `vDbgPrintEx` and only shows under a debugger.

### Error-message resource must stay in sync (`mhook_inject_messages.mc`)
The `MHOOK_INJECT_E_*` strings are an `RT_MESSAGETABLE` compiled from `mhook_inject_messages.mc` and linked into `mhook_inject.dll` (dynamic configs only, via a `<CustomBuild>` + `<ResourceCompile>` in `mhook_inject.vcxproj`; static `.lib` configs carry no resource). It **must** be compiled with `mc -c` — that Customer-bit flag is what makes the generated message IDs equal the `0xA00000xx` HRESULTs (mc's docs call it "bit 28", but it actually sets bit 29). The `.mc`'s `MessageId` values (`0x1..0x5`) and the `MHOOK_INJECT_E_*` defines in `mhook_inject.h` are hand-maintained and must stay in lockstep; the `mc`-generated header is intentionally not `#include`d anywhere (`mhook_inject.h` is the single source of truth).
