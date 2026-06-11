// mhook_inject.cpp — calling-process side of mhook_inject.
//
// Implements Mhook_Inject.  All system calls go through ntdll so the library
// can be used before the Win32 subsystem is initialised.
//
// IMPORTANT: this code is also compiled into the DLL configurations
// (IgnoreAllDefaultLibraries=true, NoEntryPoint=true).  Avoid large stack
// frames — the CRT-provided __chkstk is not available.  All path buffers
// are heap-allocated via RtlAllocateHeap.

#include "../nt_defs.h"
#include "inject_params.h"
#include "inject_bootstrap_thunk_x86_blob.h"  // kInjectBootstrapThunkX86 (cross-arch payload)

// The library never includes <windows.h>; define the timeout sentinel locally.
#ifndef INFINITE
#define INFINITE 0xFFFFFFFFu
#endif

// Unsigned 32x32->64 multiply as a single `mul` (compiler intrinsic, inlined in
// every config) — used for ms->100ns timeout math without pulling the CRT __allmul
// helper that a generic 64x64 multiply emits on x86 (we are ntdll-only).
extern "C" unsigned __int64 __emulu(unsigned int, unsigned int);
#pragma intrinsic(__emulu)

// ---------------------------------------------------------------------------
// Bootstrap-thunk blobs — assembled by MASM, linked as object code
// ---------------------------------------------------------------------------

// Declared as char[] (data symbol) rather than void() (function symbol) so
// that the MSVC incremental linker does NOT create ILT thunks for them in
// Debug builds.  ILT thunks are created for PROC symbols; a plain label like
// InjectBootstrapThunkEnd:: gets the actual address, but InjectBootstrapThunkEntry PROC
// would get its thunk address, making (End - Entry) produce the wrong size.
extern "C" char InjectBootstrapThunkEntry[];
extern "C" char InjectBootstrapThunkEnd[];

// ---------------------------------------------------------------------------
// HRESULT helpers
//
// The MHOOK_INJECT_E_* failure codes are public (declared in mhook_inject.h).
// ---------------------------------------------------------------------------

static HRESULT HrFromNt(NTSTATUS s)
{
    if (NT_SUCCESS(s)) return S_OK;
    return (HRESULT)(s | 0x10000000L);
}

// ---------------------------------------------------------------------------
// Heap helpers (for path strings; avoids large stack frames in DLL builds)
// ---------------------------------------------------------------------------

static WCHAR *HeapAllocPath(SIZE_T nchars)
{
    return (WCHAR *)RtlAllocateHeap(RtlProcessHeap(), 0, nchars * sizeof(WCHAR));
}

static void HeapFreePath(WCHAR *p)
{
    if (p) RtlFreeHeap(RtlProcessHeap(), 0, p);
}

// Duplicate a null-terminated WCHAR string onto the heap
static WCHAR *HeapDupWStr(const WCHAR *s)
{
    if (!s) return NULL;
    SIZE_T n = 0; while (s[n]) ++n;
    WCHAR *r = HeapAllocPath(n + 1);
    if (r) { for (SIZE_T i = 0; i <= n; ++i) r[i] = s[i]; }
    return r;
}

// ---------------------------------------------------------------------------
// FindDllBaseInProcess — walk the remote VA space to find a DLL by filename
// ---------------------------------------------------------------------------

// Case-insensitive: does the wide string [s, s+slen) contain `needle`?
static BOOLEAN WStrContainsCI(const WCHAR *s, USHORT slen, const WCHAR *needle)
{
    USHORT nlen = 0; while (needle[nlen]) ++nlen;
    if (nlen == 0) return TRUE;
    if (slen < nlen) return FALSE;
    auto lc = [](WCHAR c) -> WCHAR { return (c >= L'A' && c <= L'Z') ? (WCHAR)(c + (L'a' - L'A')) : c; };
    for (USHORT i = 0; i + nlen <= slen; ++i) {
        USHORT k = 0;
        for (; k < nlen; ++k)
            if (lc(s[i + k]) != lc(needle[k])) break;
        if (k == nlen) return TRUE;
    }
    return FALSE;
}

// Find a loaded module's base by file name.  `requirePathSubstr` (optional) further
// requires the mapped file's full path to contain that substring (case-insensitive) —
// used to pick the 32-bit ntdll (path under "SysWOW64") in a WOW64 target, which also
// maps the 64-bit ntdll of the same base name.
static ULONG_PTR FindDllBaseInProcess(HANDLE hProcess, const WCHAR *targetName,
                                      const WCHAR *requirePathSubstr = NULL)
{
    // Allocate MemoryMappedFileInformation buffer on heap to avoid large frame
    const SIZE_T kBufSize = sizeof(UNICODE_STRING) + 2048 * sizeof(WCHAR);
    BYTE *infoBuf = (BYTE *)RtlAllocateHeap(RtlProcessHeap(), 0, kBufSize);
    if (!infoBuf) return 0;

    ULONG_PTR result = 0;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;

    while (NT_SUCCESS(NtQueryVirtualMemory(hProcess, (PVOID)addr,
                                           MemoryBasicInformation,
                                           &mbi, sizeof(mbi), NULL)))
    {
        if ((ULONG_PTR)mbi.BaseAddress <= addr &&
            mbi.Type == MEM_IMAGE &&
            (ULONG_PTR)mbi.BaseAddress == (ULONG_PTR)mbi.AllocationBase)
        {
            UNICODE_STRING *us = (UNICODE_STRING *)infoBuf;
            if (NT_SUCCESS(NtQueryVirtualMemory(hProcess, (PVOID)addr,
                                                MemoryMappedFileInformation,
                                                infoBuf, kBufSize, NULL)))
            {
                WCHAR *p   = us->Buffer;
                USHORT len = us->Length / sizeof(WCHAR);
                WCHAR *last = p;
                for (USHORT i = 0; i < len; ++i)
                    if (p[i] == L'\\') last = p + i + 1;

                USHORT tlen = 0;
                while (targetName[tlen]) ++tlen;
                USHORT slen = (USHORT)(len - (USHORT)(last - p));

                if (slen == tlen) {
                    BOOLEAN match = TRUE;
                    for (USHORT i = 0; i < tlen; ++i) {
                        WCHAR a = last[i], b = targetName[i];
                        if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                        if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                        if (a != b) { match = FALSE; break; }
                    }
                    if (match && requirePathSubstr &&
                        !WStrContainsCI(p, len, requirePathSubstr))
                        match = FALSE;
                    if (match) {
                        result = (ULONG_PTR)mbi.AllocationBase;
                        break;
                    }
                }
            }
        }

        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    RtlFreeHeap(RtlProcessHeap(), 0, infoBuf);
    return result;
}

// ---------------------------------------------------------------------------
// FindModuleEntryByBaseName — locate the LDR entry whose BaseDllName matches
// ---------------------------------------------------------------------------

static LDR_DATA_TABLE_ENTRY_MIN *FindModuleEntryByBaseName(const WCHAR *name)
{
    NT_PEB *peb = RtlCurrentPeb();
    if (!peb || !peb->Ldr) return NULL;

    PEB_LDR_DATA_MIN *ldr = (PEB_LDR_DATA_MIN *)peb->Ldr;
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;

    USHORT targetLen = 0;
    while (name[targetLen]) ++targetLen;

    while (cur != head) {
        LDR_DATA_TABLE_ENTRY_MIN *entry =
            CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_MIN, InMemoryOrderLinks);

        USHORT nchars = entry->BaseDllName.Length / sizeof(WCHAR);
        if (nchars == targetLen) {
            BOOLEAN match = TRUE;
            for (USHORT i = 0; i < targetLen; ++i) {
                WCHAR a = entry->BaseDllName.Buffer[i], b = name[i];
                if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                if (a != b) { match = FALSE; break; }
            }
            if (match) return entry;
        }
        cur = cur->Flink;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// FindModuleEntryForAddress — locate the LDR entry that contains `addr`
// ---------------------------------------------------------------------------

static LDR_DATA_TABLE_ENTRY_MIN *FindModuleEntryForAddress(PVOID addr)
{
    NT_PEB *peb = RtlCurrentPeb();
    if (!peb || !peb->Ldr) return NULL;

    PEB_LDR_DATA_MIN *ldr = (PEB_LDR_DATA_MIN *)peb->Ldr;
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        LDR_DATA_TABLE_ENTRY_MIN *entry =
            CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_MIN, InMemoryOrderLinks);

        ULONG_PTR base = (ULONG_PTR)entry->DllBase;
        ULONG_PTR end  = base + entry->SizeOfImage;
        if ((ULONG_PTR)addr >= base && (ULONG_PTR)addr < end)
            return entry;

        cur = cur->Flink;
    }
    return NULL;
}

// Return a heap-allocated copy of the module's Win32 full path (FullDllName),
// null-terminated.  Caller must HeapFreePath.
static WCHAR *GetModuleFullPath(PVOID addr)
{
    LDR_DATA_TABLE_ENTRY_MIN *entry = FindModuleEntryForAddress(addr);
    if (!entry) return NULL;

    USHORT nchars = entry->FullDllName.Length / sizeof(WCHAR);
    WCHAR *r = HeapAllocPath((SIZE_T)nchars + 1);
    if (r) {
        for (USHORT i = 0; i < nchars; ++i) r[i] = entry->FullDllName.Buffer[i];
        r[nchars] = L'\0';
    }
    return r;
}

// Return the module base for the module containing addr
static PVOID GetModuleBase(PVOID addr)
{
    LDR_DATA_TABLE_ENTRY_MIN *entry = FindModuleEntryForAddress(addr);
    return entry ? entry->DllBase : NULL;
}

// ---------------------------------------------------------------------------
// GetDirectoryFromPath — heap-allocate a copy of the directory component
// ---------------------------------------------------------------------------

static WCHAR *GetDirectoryFromPath(const WCHAR *fullPath)
{
    SIZE_T len = 0;
    while (fullPath[len]) ++len;

    SIZE_T lastSlash = (SIZE_T)-1;
    for (SIZE_T i = 0; i < len; ++i)
        if (fullPath[i] == L'\\') lastSlash = i;

    if (lastSlash == (SIZE_T)-1) return NULL;

    WCHAR *dir = HeapAllocPath(lastSlash + 2);
    if (dir) {
        for (SIZE_T i = 0; i <= lastSlash; ++i) dir[i] = fullPath[i];
        dir[lastSlash + 1] = L'\0';
    }
    return dir;
}

// PROCESS_ALL_ACCESS is STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF, i.e.
// 0x1FFFFF on current Windows (NTDDI >= Vista).  Pin the value: if a future SDK
// or OS adds process-specific access bits, this fails to compile and forces a
// deliberate decision about whether the all-access guard below should require
// the new bits too (rather than silently accepting handles that lack them).
static_assert(PROCESS_ALL_ACCESS == 0x1FFFFF,
              "PROCESS_ALL_ACCESS changed — re-evaluate the Mhook_Inject access guard");

// ---------------------------------------------------------------------------
// TargetHasAllAccess — TRUE only if the handle was granted PROCESS_ALL_ACCESS.
//
// Deliberate guard so the library isn't a convenient privilege-escalation /
// exploitation primitive: we refuse to operate through a deliberately minimal
// handle.  A determined caller can still open a full-access handle (or patch
// this out) — that is on them; we just won't help.  We read the handle's GRANTED
// access via NtQueryObject (not what the caller claims), and fail closed if the
// query fails.
// ---------------------------------------------------------------------------

static BOOLEAN TargetHasAllAccess(HANDLE hProcess)
{
    OBJECT_BASIC_INFORMATION obi;
    RtlZeroMemory(&obi, sizeof(obi));
    if (!NT_SUCCESS(NtQueryObject(hProcess, ObjectBasicInformation,
                                  &obi, sizeof(obi), NULL)))
        return FALSE;
    return (obi.GrantedAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS;
}

// ---------------------------------------------------------------------------
// TargetIsUninitialized — TRUE only when the target is POSITIVELY observed to be
// not-yet-initialized by the loader (PEB.Ldr not built, or Initialized == FALSE).
//
// Must be called BEFORE creating the injection thread: that thread runs
// LdrpInitializeProcess as a side effect of loading the companion DLL, which
// flips PEB_LDR_DATA.Initialized to TRUE.  Reading here captures the pre-injection
// truth so the delayed-vs-immediate decision is authoritative.
//
// Returns FALSE on initialized OR on any read failure — the injected code then
// falls back to its own IsProcessInitialized() check (prior behavior).
// ---------------------------------------------------------------------------

static BOOLEAN TargetIsUninitialized(HANDLE hProcess, PVOID wow64Peb = NULL)
{
    if (wow64Peb) {
        // Cross-arch (WOW64 target): read the 32-bit PEB.  Its address is exactly
        // the pointer ProcessWow64Information returns.  32-bit layout: PEB.Ldr is at
        // +0x0C; PEB_LDR_DATA.Initialized (a BOOLEAN after the ULONG Length) at +0x04.
        ULONG ldr32 = 0;
        if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, (PVOID)((ULONG_PTR)wow64Peb + 0x0C),
                                            &ldr32, sizeof(ldr32), NULL)))
            return FALSE;
        if (!ldr32)
            return TRUE;   // loader data not built yet
        BYTE initialized = 0;
        if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, (PVOID)((ULONG_PTR)ldr32 + 0x04),
                                            &initialized, sizeof(initialized), NULL)))
            return FALSE;
        return !initialized;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                              &pbi, sizeof(pbi), NULL)) ||
        !pbi.PebBaseAddress)
        return FALSE;

    NT_PEB peb = {};
    if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, pbi.PebBaseAddress,
                                        &peb, sizeof(peb), NULL)))
        return FALSE;

    if (!peb.Ldr)
        return TRUE;   // loader data not built yet → definitely uninitialized

    PEB_LDR_DATA_MIN ldr = {};
    if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, peb.Ldr,
                                        &ldr, sizeof(ldr), NULL)))
        return FALSE;

    return !ldr.Initialized;
}

// ---------------------------------------------------------------------------
// ResolveFullPath — heap-allocate the resolved absolute path.
// If relOrAbs starts with a drive letter or \\ it is used as-is;
// otherwise it is appended to baseDir.
// ---------------------------------------------------------------------------

static WCHAR *ResolveFullPath(const WCHAR *baseDir, const WCHAR *relOrAbs)
{
    if (!relOrAbs) return NULL;
    BOOLEAN isAbs = (relOrAbs[0] != L'\0' && relOrAbs[1] == L':') ||
                    (relOrAbs[0] == L'\\' && relOrAbs[1] == L'\\');

    SIZE_T baselen = 0;
    if (!isAbs && baseDir)
        while (baseDir[baselen]) ++baselen;

    SIZE_T rellen = 0;
    while (relOrAbs[rellen]) ++rellen;

    SIZE_T total = baselen + rellen + 1;
    WCHAR *r = HeapAllocPath(total);
    if (!r) return NULL;

    if (!isAbs && baselen)
        for (SIZE_T i = 0; i < baselen; ++i) r[i] = baseDir[i];
    for (SIZE_T i = 0; i <= rellen; ++i) r[baselen + i] = relOrAbs[i];
    return r;
}

// ---------------------------------------------------------------------------
// AppendPathComponent — heap-allocate "dir\filename"
// ---------------------------------------------------------------------------

static WCHAR *AppendPathComponent(const WCHAR *dir, const WCHAR *filename)
{
    SIZE_T dlen = 0; while (dir[dlen]) ++dlen;
    SIZE_T flen = 0; while (filename[flen]) ++flen;
    BOOLEAN needSlash = (dlen > 0 && dir[dlen - 1] != L'\\');
    SIZE_T total = dlen + (needSlash ? 1 : 0) + flen + 1;
    WCHAR *r = HeapAllocPath(total);
    if (!r) return NULL;
    SIZE_T pos = 0;
    for (SIZE_T i = 0; i < dlen; ++i) r[pos++] = dir[i];
    if (needSlash) r[pos++] = L'\\';
    for (SIZE_T i = 0; i <= flen; ++i) r[pos++] = filename[i];
    return r;
}

// ---------------------------------------------------------------------------
// GetExportRvaFromFile — parse the PE export directory of a DLL on disk and
// return the RVA of a named export.  Works for both 32-bit and 64-bit PEs.
// Heap-allocates a temporary NT path string internally.
// ---------------------------------------------------------------------------

static NTSTATUS ReadFileAt(HANDLE hFile, PVOID buf, ULONG len, ULONG offset)
{
    LARGE_INTEGER pos;
    pos.QuadPart = offset;
    IO_STATUS_BLOCK iosb;
    return NtReadFile(hFile, NULL, NULL, NULL, &iosb, buf, len, &pos, NULL);
}

static NTSTATUS GetExportRvaFromFile(const WCHAR *dllPath,
                                     const CHAR  *exportName,
                                     ULONG       *outRva,
                                     USHORT      *outMachine = NULL)
{
    if (outMachine) *outMachine = 0;
    // Build \??\<dllPath>  NT object path
    const WCHAR prefix[] = { L'\\', L'?', L'?', L'\\', L'\0' };
    const SIZE_T pfxLen = 4;
    SIZE_T pathLen = 0;
    while (dllPath[pathLen]) ++pathLen;
    SIZE_T ntLen = pfxLen + pathLen;

    WCHAR *ntBuf = HeapAllocPath(ntLen + 1);
    if (!ntBuf) return STATUS_NO_MEMORY;
    for (SIZE_T i = 0; i < pfxLen;   ++i) ntBuf[i]         = prefix[i];
    for (SIZE_T i = 0; i <= pathLen; ++i) ntBuf[pfxLen + i] = dllPath[i];

    UNICODE_STRING ntPath;
    ntPath.Buffer        = ntBuf;
    ntPath.Length        = (USHORT)(ntLen * sizeof(WCHAR));
    ntPath.MaximumLength = ntPath.Length + (USHORT)sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS st = NtOpenFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb,
                              FILE_SHARE_READ,
                              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    HeapFreePath(ntBuf);
    if (!NT_SUCCESS(st)) return st;

    st = STATUS_INVALID_IMAGE_FORMAT;
    *outRva = 0;

    IMAGE_DOS_HEADER dos;
    if (!NT_SUCCESS(ReadFileAt(hFile, &dos, sizeof(dos), 0))) goto out;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) goto out;

    DWORD peSig;
    if (!NT_SUCCESS(ReadFileAt(hFile, &peSig, 4, dos.e_lfanew))) goto out;
    if (peSig != IMAGE_NT_SIGNATURE) goto out;

    IMAGE_FILE_HEADER fhdr;
    ULONG fhdrOff = dos.e_lfanew + 4;
    if (!NT_SUCCESS(ReadFileAt(hFile, &fhdr, sizeof(fhdr), fhdrOff))) goto out;
    if (outMachine) *outMachine = fhdr.Machine;

    WORD optMagic;
    ULONG optOffset = fhdrOff + sizeof(IMAGE_FILE_HEADER);
    if (!NT_SUCCESS(ReadFileAt(hFile, &optMagic, sizeof(optMagic), optOffset))) goto out;

    ULONG exportDirRva = 0, exportDirSize = 0, sectionOffset = 0;
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt;
        if (!NT_SUCCESS(ReadFileAt(hFile, &opt, sizeof(opt), optOffset))) goto out;
        exportDirRva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        sectionOffset = optOffset + sizeof(opt);
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt;
        if (!NT_SUCCESS(ReadFileAt(hFile, &opt, sizeof(opt), optOffset))) goto out;
        exportDirRva  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        sectionOffset = optOffset + sizeof(opt);
    } else goto out;

    if (!exportDirRva || !exportDirSize) { st = STATUS_NOT_FOUND; goto out; }

    {
        ULONG exportFileOff = 0, exportSecBase = 0;
        for (WORD i = 0; i < fhdr.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sec;
            ULONG secOff = sectionOffset + i * sizeof(IMAGE_SECTION_HEADER);
            if (!NT_SUCCESS(ReadFileAt(hFile, &sec, sizeof(sec), secOff))) goto out;
            if (exportDirRva >= sec.VirtualAddress &&
                exportDirRva <  sec.VirtualAddress + sec.Misc.VirtualSize)
            {
                exportFileOff = sec.PointerToRawData + (exportDirRva - sec.VirtualAddress);
                exportSecBase = sec.VirtualAddress   - sec.PointerToRawData;
                break;
            }
        }
        if (!exportFileOff) { st = STATUS_NOT_FOUND; goto out; }

        IMAGE_EXPORT_DIRECTORY expDir;
        if (!NT_SUCCESS(ReadFileAt(hFile, &expDir, sizeof(expDir), exportFileOff))) goto out;
        if (!expDir.NumberOfNames) { st = STATUS_NOT_FOUND; goto out; }

        ULONG nameTableFileOff    = expDir.AddressOfNames        - exportSecBase;
        ULONG ordinalTableFileOff = expDir.AddressOfNameOrdinals - exportSecBase;
        ULONG funcTableFileOff    = expDir.AddressOfFunctions    - exportSecBase;

        SIZE_T targetLen = 0;
        while (exportName[targetLen]) ++targetLen;

        for (ULONG n = 0; n < expDir.NumberOfNames; ++n) {
            DWORD nameRva;
            if (!NT_SUCCESS(ReadFileAt(hFile, &nameRva, 4, nameTableFileOff + n * 4))) goto out;

            CHAR nameStr[256];
            ReadFileAt(hFile, nameStr, sizeof(nameStr) - 1, nameRva - exportSecBase);
            nameStr[sizeof(nameStr) - 1] = '\0';

            SIZE_T nlen = 0; while (nameStr[nlen]) ++nlen;
            if (nlen != targetLen) continue;
            BOOLEAN match = TRUE;
            for (SIZE_T k = 0; k < targetLen; ++k)
                if (nameStr[k] != exportName[k]) { match = FALSE; break; }
            if (!match) continue;

            WORD ordinalIdx;
            if (!NT_SUCCESS(ReadFileAt(hFile, &ordinalIdx, 2,
                                       ordinalTableFileOff + n * 2))) goto out;
            DWORD funcRva;
            if (!NT_SUCCESS(ReadFileAt(hFile, &funcRva, 4,
                                       funcTableFileOff + ordinalIdx * 4))) goto out;
            *outRva = funcRva;
            st = STATUS_SUCCESS;
            goto out;
        }
        st = STATUS_NOT_FOUND;
    }

out:
    NtClose(hFile);
    return st;
}

// Given the injector's native ntdll path (...\System32\ntdll.dll) produce the
// 32-bit WOW64 ntdll path (...\SysWOW64\ntdll.dll) — both components are 8 chars,
// so the last case-insensitive "System32" is overwritten in place.  Returns a
// heap copy (caller frees); on no match the path is returned unchanged.
static WCHAR *DeriveSysWow64Path(const WCHAR *nativePath)
{
    WCHAR *r = HeapDupWStr(nativePath);
    if (!r) return NULL;
    const WCHAR want[8] = { L's', L'y', L's', L't', L'e', L'm', L'3', L'2' };
    const WCHAR repl[8] = { L'S', L'y', L's', L'W', L'O', L'W', L'6', L'4' };
    auto lc = [](WCHAR c) -> WCHAR { return (c >= L'A' && c <= L'Z') ? (WCHAR)(c + (L'a' - L'A')) : c; };
    SIZE_T n = 0; while (r[n]) ++n;
    if (n >= 8) {
        for (SIZE_T i = n - 8 + 1; i-- > 0; ) {
            SIZE_T k = 0;
            for (; k < 8; ++k) if (lc(r[i + k]) != want[k]) break;
            if (k == 8) { for (k = 0; k < 8; ++k) r[i + k] = repl[k]; break; }
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// Cross-arch (64->32) async completion watcher
//
// A 32-bit target can't write the 64-bit caller's IO_STATUS_BLOCK nor queue a
// 64-bit APC, so for cross-arch async injections that request either, the target
// only signals a completion event and stashes its NTSTATUS in a caller-owned slot
// (see MHOOK_INJECT_REMOTE_PARAMS.StatusSlot).  This thread runs in the CALLING
// process: it waits for completion, reads the status, and performs the IoStatusBlock
// write / Event signal / APC queue itself — all trivial in-process for a 64-bit
// caller.  It owns (and frees) the slot, the completion event, and the duplicated
// handles below.
// ---------------------------------------------------------------------------

typedef struct _MHOOK_INJECT_WATCHER {
    HANDLE  TargetProcess;     // dup (PROCESS_VM_READ | PROCESS_VM_OPERATION)
    PVOID   StatusSlot;        // target VA of the caller-owned NTSTATUS slot
    HANDLE  CompletionEvent;   // calling-side event the target signals
    PVOID   IoStatusBlock;     // caller VA (NULL if unused)
    HANDLE  CallerThread;      // dup (THREAD_SET_CONTEXT); for the APC (NULL if unused)
    PVOID   ApcRoutine;        // caller VA (NULL if unused)
    PVOID   ApcContext;
    HANDLE  UserEvent;         // caller's Event (NULL if unused)
    ULONG   TimeoutMs;
} MHOOK_INJECT_WATCHER;

static VOID NTAPI InjectWatcherProc(PVOID arg)
{
    MHOOK_INJECT_WATCHER *w = (MHOOK_INJECT_WATCHER *)arg;

    // Wait for completion, bounded by TimeoutMs (0 => 30 s, INFINITE => no timeout).
    NTSTATUS waitSt;
    if (w->TimeoutMs == INFINITE) {
        waitSt = NtWaitForSingleObject(w->CompletionEvent, FALSE, NULL);
    } else {
        ULONG ms = w->TimeoutMs ? w->TimeoutMs : 30000u;
        LARGE_INTEGER rel; rel.QuadPart = -(LONGLONG)__emulu(ms, 10000u);  // ms -> 100ns, relative
        waitSt = NtWaitForSingleObject(w->CompletionEvent, FALSE, &rel);
    }

    NTSTATUS status = (NTSTATUS)0xC00000B5L;  // STATUS_IO_TIMEOUT (also the death/timeout case)
    if (waitSt != STATUS_TIMEOUT)
        NtReadVirtualMemory(w->TargetProcess, w->StatusSlot, &status, sizeof(status), NULL);

    // Deliver caller-side, in NT order: IoStatusBlock, then Event, then APC.
    if (w->IoStatusBlock) {
        IO_STATUS_BLOCK *iosb = (IO_STATUS_BLOCK *)w->IoStatusBlock;
        iosb->Status      = status;
        iosb->Information = 0;
    }
    if (w->UserEvent)
        NtSetEvent(w->UserEvent, NULL);
    if (w->ApcRoutine && w->CallerThread)
        NtQueueApcThread(w->CallerThread, (PPS_APC_ROUTINE)w->ApcRoutine,
                         w->ApcContext, w->IoStatusBlock, NULL);

    // Cleanup — the watcher owns all of these.
    if (w->StatusSlot) {
        PVOID base = w->StatusSlot; SIZE_T zero = 0;
        NtFreeVirtualMemory(w->TargetProcess, &base, &zero, MEM_RELEASE);
    }
    if (w->TargetProcess)   NtClose(w->TargetProcess);
    if (w->CallerThread)    NtClose(w->CallerThread);
    if (w->CompletionEvent) NtClose(w->CompletionEvent);
    RtlFreeHeap(RtlProcessHeap(), 0, w);
}

// ---------------------------------------------------------------------------
// Mhook_Inject
// ---------------------------------------------------------------------------

HRESULT __cdecl Mhook_Inject(MHOOK_INJECT_PARAMS *params)
{
    if (!params || params->Size != sizeof(MHOOK_INJECT_PARAMS))
        return MHOOK_INJECT_E_PARAMS;
    if (!params->TargetProcess)
        return MHOOK_INJECT_E_PARAMS;

    // Deliberate guard: require a full-access target handle (see TargetHasAllAccess).
    if (!TargetHasAllAccess(params->TargetProcess))
        return MHOOK_INJECT_E_ACCESS;

    BOOLEAN useFnPtr = (params->FunctionPointer != NULL);
    BOOLEAN useName  = (params->DllPath != NULL && params->FunctionName != NULL);
    if (useFnPtr == useName)
        return MHOOK_INJECT_E_PARAMS;

    // Reject would-be-negative timeouts; INFINITE (all-ones) is the only allowed
    // sign-bit-set value (means "no timeout").  0 means "use the default".
    if (params->TimeoutMs >= 0x80000000u && params->TimeoutMs != INFINITE)
        return MHOOK_INJECT_E_PARAMS;

    // Determine the target architecture (x86/x64).  A non-NULL ProcessWow64Information
    // pointer means the target is a 32-bit (WOW64) process; it is also the target's
    // 32-bit PEB address (used for the cross-arch DELAY init check).
    PVOID   wow64Peb   = NULL;
    NtQueryInformationProcess(params->TargetProcess, ProcessWow64Information,
                              &wow64Peb, sizeof(wow64Peb), NULL);
    BOOLEAN targetIs32 = (wow64Peb != NULL);
    BOOLEAN crossTo32  = FALSE;
#ifdef _M_X64
    crossTo32 = targetIs32;                 // 64-bit injector + WOW64 target = cross 64->32
#else
    if (!targetIs32) return E_NOTIMPL;      // 32-bit injector + 64-bit target: deferred
#endif

    if (crossTo32) {
        // Cross-arch constraint: the injection module must be named as an x86 file
        // on disk, so the FunctionPointer form (a VA in the x64 caller) is not
        // allowed.  IoStatusBlock/APC completion IS supported (delivered by a
        // caller-side watcher thread — see InjectWatcherProc / needWatcher below).
        if (useFnPtr)
            return MHOOK_INJECT_E_PARAMS;
    }

    BOOLEAN isAsync = (params->Flags & MHOOK_INJECT_FLAG_ASYNC) != 0;
    // Synchronous + delay needs an internal kernel event: after the bootstrap
    // thread exits (hook installed), we wait on it until the entry-point hook
    // fires and the injection function returns.
    BOOLEAN needsSyncEvent = !isAsync
                             && (params->Flags & MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT) != 0;

    // Cross-arch async with IoStatusBlock/APC: the 32-bit target can't write back
    // into the 64-bit caller, so a caller-side watcher thread delivers them.
    BOOLEAN needWatcher = crossTo32 && isAsync
                          && (params->IoStatusBlock || params->ApcRoutine);

    HRESULT hr = E_FAIL;
    NTSTATUS st;
    PVOID   remoteBase      = NULL;
    BOOLEAN remoteBaseOwned = FALSE;  // TRUE once the remote thread owns the free
    HANDLE  hThread         = NULL;
    HANDLE  hSyncEvent      = NULL;   // calling-side handle (sync+delay internal event,
                                      // or cross-arch async watcher completion event)
    PVOID   watcherSlot     = NULL;   // cross-arch async: caller-owned status slot (target VA)
    BOOLEAN watcherSpawned  = FALSE;  // TRUE once the watcher owns hSyncEvent + watcherSlot

    // All path strings are heap-allocated; freed in cleanup.
    WCHAR *selfPath      = NULL;  // full path of module containing Mhook_Inject
    WCHAR *selfDir       = NULL;  // directory of selfPath
    WCHAR *companionPath = NULL;  // companion DLL to load in target
    WCHAR *mhookPath     = NULL;  // mhook.dll for target
    WCHAR *targetDllPath = NULL;  // user's DLL (dynamic: separate; static: same as companion)
    WCHAR *cmpDir        = NULL;  // directory of companionPath

    // -----------------------------------------------------------------------
    // Step 1: Find our own module path
    // -----------------------------------------------------------------------
    selfPath = GetModuleFullPath((PVOID)&Mhook_Inject);
    if (!selfPath) { hr = E_FAIL; goto cleanup; }

    selfDir = GetDirectoryFromPath(selfPath);
    if (!selfDir) { hr = E_FAIL; goto cleanup; }

    // -----------------------------------------------------------------------
    // Step 2: Resolve companion DLL, target DLL, and function RVA
    // -----------------------------------------------------------------------
    ULONG functionRva;
    functionRva = 0;
    BOOLEAN isDynamic;

#ifdef MHOOK_INJECT_DYNAMIC
    isDynamic = TRUE;

    if (crossTo32) {
        // The companion (which exports _internal_Execute and is loaded into the
        // target) must be the TARGET-architecture mhook_inject.dll — not this x64
        // one.  It ships next to the matching mhook.dll, so derive it from
        // MhookDllPath (required for cross-arch dynamic).  mhookPath is resolved
        // here too; Step 4 then skips its own resolution.
        if (!params->MhookDllPath) { hr = MHOOK_INJECT_E_PARAMS; goto cleanup; }
        mhookPath = ResolveFullPath(selfDir, params->MhookDllPath);
        if (!mhookPath) { hr = E_FAIL; goto cleanup; }
        cmpDir = GetDirectoryFromPath(mhookPath);
        if (!cmpDir) { hr = E_FAIL; goto cleanup; }
        companionPath = AppendPathComponent(cmpDir, L"mhook_inject.dll");
        targetDllPath = ResolveFullPath(selfDir, params->DllPath);  // user's x86 DLL
    } else {
        companionPath = HeapDupWStr(selfPath);  // companion = this mhook_inject.dll

        if (useFnPtr) {
            PVOID fnBase = GetModuleBase(params->FunctionPointer);
            if (!fnBase) { hr = E_FAIL; goto cleanup; }
            functionRva = (ULONG)((ULONG_PTR)params->FunctionPointer - (ULONG_PTR)fnBase);
            targetDllPath = GetModuleFullPath(params->FunctionPointer);
        } else {
            targetDllPath = ResolveFullPath(selfDir, params->DllPath);
        }
    }
#else
    isDynamic = FALSE;

    if (useFnPtr) {
        PVOID fnBase = GetModuleBase(params->FunctionPointer);
        if (!fnBase) { hr = E_FAIL; goto cleanup; }
        functionRva = (ULONG)((ULONG_PTR)params->FunctionPointer - (ULONG_PTR)fnBase);
        companionPath = GetModuleFullPath(params->FunctionPointer);
    } else {
        companionPath = ResolveFullPath(selfDir, params->DllPath);
    }
    // targetDllPath stays NULL: function is inside the companion
#endif

    if (!companionPath) { hr = E_FAIL; goto cleanup; }

    // -----------------------------------------------------------------------
    // Step 3: Get _internal_Execute RVA from companion DLL on disk
    // -----------------------------------------------------------------------
    ULONG executeRva;
    executeRva = 0;
    USHORT companionMachine;
    companionMachine = 0;
    st = GetExportRvaFromFile(companionPath, "_internal_Execute", &executeRva, &companionMachine);
    if (!NT_SUCCESS(st)) { hr = MHOOK_INJECT_E_NO_EXEC; goto cleanup; }

    // The companion must match the TARGET architecture (an x86 companion for a
    // WOW64 target, x64 for a native x64 target) — catch a wrong-arch DLL up front
    // instead of failing obscurely in the remote thread.
    {
#ifdef _M_X64
        USHORT nativeMachine = IMAGE_FILE_MACHINE_AMD64;
#else
        USHORT nativeMachine = IMAGE_FILE_MACHINE_I386;
#endif
        USHORT wantMachine = crossTo32 ? IMAGE_FILE_MACHINE_I386 : nativeMachine;
        if (companionMachine != wantMachine) { hr = MHOOK_INJECT_E_PARAMS; goto cleanup; }
    }

    // -----------------------------------------------------------------------
    // Step 4: Resolve mhook.dll path (dynamic builds only; cross-arch already did)
    // -----------------------------------------------------------------------
    if (isDynamic && !mhookPath) {
        cmpDir = GetDirectoryFromPath(companionPath);
        if (!cmpDir) { hr = E_FAIL; goto cleanup; }

        if (params->MhookDllPath) {
            mhookPath = ResolveFullPath(cmpDir, params->MhookDllPath);
        } else {
            mhookPath = AppendPathComponent(cmpDir, L"mhook.dll");
        }
        if (!mhookPath) { hr = E_FAIL; goto cleanup; }
    }

    // -----------------------------------------------------------------------
    // Step 5: (target architecture already determined above as crossTo32)
    // -----------------------------------------------------------------------
    {
    // -----------------------------------------------------------------------
    // Step 6: Find LdrLoadDll in the target's ntdll
    // -----------------------------------------------------------------------
    // Same-arch: resolve from the injector's own ntdll (same RVAs as the target's,
    // shared base).  Cross 64->32: resolve from the target's 32-bit ntdll
    // (SysWOW64) — a WOW64 target maps both the 64-bit and the 32-bit ntdll under
    // the same base name, so select by path, and parse the 32-bit file on disk
    // (derived from the injector's own System32 ntdll path).
    ULONG_PTR remoteNtdllBase = 0;
    WCHAR    *ntdllFilePath   = NULL;   // file parsed for export RVAs
    {
        LDR_DATA_TABLE_ENTRY_MIN *ntdllEntry = FindModuleEntryByBaseName(L"ntdll.dll");
        if (!ntdllEntry) { hr = E_FAIL; goto cleanup; }
        WCHAR *localNtdllPath = GetModuleFullPath(ntdllEntry->DllBase);
        if (!localNtdllPath) { hr = E_FAIL; goto cleanup; }

        if (crossTo32) {
            remoteNtdllBase = FindDllBaseInProcess(params->TargetProcess, L"ntdll.dll", L"SysWOW64");
            ntdllFilePath   = DeriveSysWow64Path(localNtdllPath);
            HeapFreePath(localNtdllPath);
        } else {
            remoteNtdllBase = FindDllBaseInProcess(params->TargetProcess, L"ntdll.dll");
            ntdllFilePath   = localNtdllPath;   // ownership transferred
        }
        if (!remoteNtdllBase) { HeapFreePath(ntdllFilePath); hr = MHOOK_INJECT_E_NO_NTDLL; goto cleanup; }
        if (!ntdllFilePath)   { hr = E_FAIL; goto cleanup; }
    }

    ULONG ldrRva = 0;
    st = GetExportRvaFromFile(ntdllFilePath, "LdrLoadDll", &ldrRva);
    if (!NT_SUCCESS(st)) { HeapFreePath(ntdllFilePath); hr = E_FAIL; goto cleanup; }

#ifdef _M_X64
    // x64 same-arch only: look up RtlAddFunctionTable / RtlDeleteFunctionTable so
    // the bootstrap thunk can register/remove dynamic unwind info for its own
    // frame.  A 32-bit (cross) target has no SEH unwind table, so skip it.
    ULONG rtlAddFuncRva = 0, rtlDelFuncRva = 0;
    if (!crossTo32) {
        GetExportRvaFromFile(ntdllFilePath, "RtlAddFunctionTable",    &rtlAddFuncRva);
        GetExportRvaFromFile(ntdllFilePath, "RtlDeleteFunctionTable", &rtlDelFuncRva);
    }
#endif

    HeapFreePath(ntdllFilePath);
    ntdllFilePath = NULL;

    LdrLoadDllFn remoteLdrLoadDll =
        (LdrLoadDllFn)(remoteNtdllBase + ldrRva);

    // -----------------------------------------------------------------------
    // Step 7: Calculate remote memory layout
    // -----------------------------------------------------------------------
    // Cross 64->32 embeds the x86 thunk blob + the fixed-width x86 params layout;
    // same-arch uses the linked native thunk + native params.
    const void *thunkSrc;
    SIZE_T codeSize, paramsSize;
    if (crossTo32) {
        thunkSrc   = kInjectBootstrapThunkX86;
        codeSize   = sizeof(kInjectBootstrapThunkX86);
        paramsSize = sizeof(MHOOK_INJECT_REMOTE_PARAMS_X86);
    } else {
        thunkSrc   = InjectBootstrapThunkEntry;
        codeSize   = (SIZE_T)((BYTE*)InjectBootstrapThunkEnd - (BYTE*)InjectBootstrapThunkEntry);
        paramsSize = sizeof(MHOOK_INJECT_REMOTE_PARAMS);
    }

    auto WStrBytes = [](const WCHAR *s) -> SIZE_T {
        if (!s || !s[0]) return 0;
        SIZE_T n = 0; while (s[n]) ++n; return (n + 1) * sizeof(WCHAR);
    };
    auto AStrBytes = [](const CHAR *s) -> SIZE_T {
        if (!s || !s[0]) return 0;
        SIZE_T n = 0; while (s[n]) ++n; return n + 1;
    };

    SIZE_T companionBytes  = WStrBytes(companionPath);
    SIZE_T mhookBytes      = isDynamic ? WStrBytes(mhookPath) : 0;
    SIZE_T targetDllBytes  = WStrBytes(targetDllPath);
    SIZE_T funcNameBytes   = useName ? AStrBytes(params->FunctionName) : 0;
    SIZE_T userDataBytes   = params->UserDataSize;

    SIZE_T strOffset  = (codeSize + paramsSize + 7) & ~(SIZE_T)7;
    SIZE_T strRegion  = companionBytes + mhookBytes + targetDllBytes + funcNameBytes;
    SIZE_T udOffset   = (strOffset + strRegion + 7) & ~(SIZE_T)7;
    SIZE_T totalSize  = udOffset + userDataBytes;

    // -----------------------------------------------------------------------
    // Step 8: Allocate remote memory and write contents
    // -----------------------------------------------------------------------
    st = NtAllocateVirtualMemory(params->TargetProcess, &remoteBase, 0,
                                  &totalSize, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }

    BYTE *rCode   = (BYTE *)remoteBase;
    BYTE *rCur    = rCode + strOffset;

    BYTE *rCompanion  = rCur; rCur += companionBytes;
    BYTE *rMhook      = isDynamic && mhookBytes   ? rCur : NULL; if (isDynamic && mhookBytes)   rCur += mhookBytes;
    BYTE *rTargetDll  = targetDllBytes ? rCur : NULL; if (targetDllBytes)  rCur += targetDllBytes;
    BYTE *rFuncName   = funcNameBytes  ? rCur : NULL; if (funcNameBytes)   rCur += funcNameBytes;
    BYTE *rUserData   = userDataBytes  ? rCode + udOffset : NULL;

    MHOOK_INJECT_REMOTE_PARAMS rp = {};
    rp.LdrLoadDll     = remoteLdrLoadDll;
    rp.ExecuteOffset  = executeRva;
    rp.IsDynamic      = isDynamic ? 1u : 0u;
    rp.RemoteFlags    = 0u;
    if (params->Flags & MHOOK_INJECT_FLAG_DELAY_UNTIL_INIT) {
        rp.RemoteFlags |= MHOOK_REMOTE_FLAG_DELAY_UNTIL_INIT;
        // Read the target's loader-init state NOW, before the injection thread
        // perturbs it, so the delayed-vs-immediate decision is authoritative.
        if (TargetIsUninitialized(params->TargetProcess, crossTo32 ? wow64Peb : NULL))
            rp.RemoteFlags |= MHOOK_REMOTE_FLAG_TARGET_UNINITIALIZED;
    }
    rp.FunctionRva    = functionRva;
    rp.UserData       = rUserData;
    rp.UserDataSize   = userDataBytes;

#ifdef _M_X64
    // Bootstrap-thunk-frame unwind registration + deregistration.
    // BootstrapThunkRF (a RUNTIME_FUNCTION, offsets relative to BootstrapThunkBase
    // = rCode) describes the thunk's extent and points at BootstrapThunkUI, the
    // UNWIND_INFO for InjectBootstrapThunkEntry's prolog: push rbx (1 byte) +
    // sub rsp,20h (4 bytes).  UNWIND_INFO carries UnwindCode[0] inline; the second
    // code lives in the contiguous BootstrapThunkUC field.
    enum { UNWIND_REG_RBX = 3 };                     // OpInfo register code for RBX
    if (!crossTo32 && rtlAddFuncRva) {               // x86 (cross) target: no unwind table
        rp.RtlAddFunctionTable    = (PVOID)(remoteNtdllBase + rtlAddFuncRva);
        rp.RtlDeleteFunctionTable = rtlDelFuncRva
                                    ? (PVOID)(remoteNtdllBase + rtlDelFuncRva)
                                    : NULL;
        rp.BootstrapThunkBase = (ULONG64)rCode;

        rp.BootstrapThunkRF.BeginAddress = 0;               // start of bootstrap thunk
        rp.BootstrapThunkRF.EndAddress   = (ULONG)codeSize; // exclusive end
        rp.BootstrapThunkRF.UnwindData   = (ULONG)(codeSize +
                             offsetof(MHOOK_INJECT_REMOTE_PARAMS, BootstrapThunkUI));

        // UNWIND_INFO describing: push rbx (CodeOffset=1) + sub rsp,20h (CodeOffset=5).
        rp.BootstrapThunkUI.Version       = 1;
        rp.BootstrapThunkUI.Flags         = 0;   // no exception handler
        rp.BootstrapThunkUI.SizeOfProlog  = 5;   // bytes covered: push(1) + sub(4)
        rp.BootstrapThunkUI.CountOfCodes  = 2;
        rp.BootstrapThunkUI.FrameRegister = 0;   // no frame pointer
        rp.BootstrapThunkUI.FrameOffset   = 0;
        // Codes are ordered last-prolog-op first.
        // sub rsp,20h: for UWOP_ALLOC_SMALL, OpInfo = (alloc size - 8) / 8.
        rp.BootstrapThunkUI.UnwindCode[0].CodeOffset = 5;
        rp.BootstrapThunkUI.UnwindCode[0].UnwindOp   = UWOP_ALLOC_SMALL;
        rp.BootstrapThunkUI.UnwindCode[0].OpInfo     = (0x20 - 8) / 8;
        // push rbx: for UWOP_PUSH_NONVOL, OpInfo is the register code.
        rp.BootstrapThunkUC.CodeOffset = 1;
        rp.BootstrapThunkUC.UnwindOp   = UWOP_PUSH_NONVOL;
        rp.BootstrapThunkUC.OpInfo     = UNWIND_REG_RBX;
    }
#endif

    rp.CompanionPath.Buffer        = (PWSTR)rCompanion;
    rp.CompanionPath.Length        = (USHORT)(companionBytes > 0 ? companionBytes - sizeof(WCHAR) : 0);
    rp.CompanionPath.MaximumLength = (USHORT)companionBytes;

    if (isDynamic && rMhook) {
        rp.MhookPath.Buffer        = (PWSTR)rMhook;
        rp.MhookPath.Length        = (USHORT)(mhookBytes - sizeof(WCHAR));
        rp.MhookPath.MaximumLength = (USHORT)mhookBytes;
    }
    if (rTargetDll) {
        rp.TargetDllPath.Buffer        = (PWSTR)rTargetDll;
        rp.TargetDllPath.Length        = (USHORT)(targetDllBytes - sizeof(WCHAR));
        rp.TargetDllPath.MaximumLength = (USHORT)targetDllBytes;
    }
    if (rFuncName) {
        rp.FunctionName.Buffer        = (PCHAR)rFuncName;
        rp.FunctionName.Length        = (USHORT)(funcNameBytes - 1);
        rp.FunctionName.MaximumLength = (USHORT)funcNameBytes;
    }

    // -----------------------------------------------------------------------
    // Completion plumbing — set the rp fields before the params block is written.
    //   sync + delay : internal auto-reset event, signalled when the hook fires.
    //   async        : the user's Event (duplicated in) and/or an IoStatusBlock
    //                  written across the process boundary on completion.
    // (APC delivery — CallerThread/ApcRoutine/ApcContext — arrives in subtask 2.)
    // -----------------------------------------------------------------------
    if (needsSyncEvent) {
        HANDLE hRemoteEvent = NULL;
        st = NtCreateEvent(&hSyncEvent, EVENT_ALL_ACCESS, NULL,
                           SynchronizationEvent, FALSE);
        if (NT_SUCCESS(st))
            st = NtDuplicateObject(NtCurrentProcess(), hSyncEvent,
                                   params->TargetProcess, &hRemoteEvent,
                                   EVENT_ALL_ACCESS, 0, 0);
        if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }
        rp.CompletionEvent = hRemoteEvent;
    } else if (needWatcher) {
        // Cross-arch async + IoStatusBlock/APC: the target only signals an internal
        // completion event and writes its NTSTATUS into a caller-owned slot; the
        // caller-side watcher thread (spawned after thread creation) reads the slot
        // and performs the IoStatusBlock/Event/APC delivery.
        HANDLE hRemoteEvent = NULL;
        st = NtCreateEvent(&hSyncEvent, EVENT_ALL_ACCESS, NULL,
                           SynchronizationEvent, FALSE);
        if (NT_SUCCESS(st))
            st = NtDuplicateObject(NtCurrentProcess(), hSyncEvent,
                                   params->TargetProcess, &hRemoteEvent,
                                   EVENT_ALL_ACCESS, 0, 0);
        if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }
        rp.CompletionEvent = hRemoteEvent;

        SIZE_T slotSize = sizeof(NTSTATUS);
        st = NtAllocateVirtualMemory(params->TargetProcess, &watcherSlot, 0,
                                     &slotSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) { watcherSlot = NULL; hr = HrFromNt(st); goto cleanup; }
        rp.StatusSlot = watcherSlot;

        if (params->IoStatusBlock) {
            params->IoStatusBlock->Status      = (NTSTATUS)0x00000103L; // STATUS_PENDING
            params->IoStatusBlock->Information  = 0;
        }
        // rp.CallerProcess/CallerThread/ApcRoutine/IoStatusBlock stay 0: the 32-bit
        // target can't use them; the watcher does the caller-side delivery.
    } else if (isAsync) {
        if (params->Event) {
            HANDLE hRemoteEvent = NULL;
            st = NtDuplicateObject(NtCurrentProcess(), params->Event,
                                   params->TargetProcess, &hRemoteEvent,
                                   EVENT_ALL_ACCESS, 0, 0);
            if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }
            rp.CompletionEvent = hRemoteEvent;
        }
        if (params->IoStatusBlock) {
            // The target writes the final status across the boundary, so give it
            // a handle to THIS process with write access.
            HANDLE hRemoteSelf = NULL;
            st = NtDuplicateObject(NtCurrentProcess(), NtCurrentProcess(),
                                   params->TargetProcess, &hRemoteSelf,
                                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, 0);
            if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }
            rp.CallerProcess = hRemoteSelf;
            rp.IoStatusBlock = params->IoStatusBlock;
            // NT idiom: pending until the target overwrites it on completion.
            params->IoStatusBlock->Status      = (NTSTATUS)0x00000103L; // STATUS_PENDING
            params->IoStatusBlock->Information  = 0;
        }
        if (params->ApcRoutine) {
            // The target queues a user APC to the calling thread, so give it a
            // handle to that thread.  ApcRoutine/ApcContext are caller-side VAs
            // delivered verbatim (the APC runs in the caller's address space).
            HANDLE hRemoteThread = NULL;
            st = NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(),
                                   params->TargetProcess, &hRemoteThread,
                                   THREAD_SET_CONTEXT, 0, 0);
            if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }
            rp.CallerThread = hRemoteThread;
            rp.ApcRoutine   = (PVOID)params->ApcRoutine;
            rp.ApcContext   = params->ApcContext;
        }
    }

    // Cross 64->32: serialize the params into the fixed-width x86 layout (every
    // pointer/handle is a remote <4 GB address that fits a ULONG).  All field
    // VALUES were computed into `rp` above; truncate them into `rp86`.
    MHOOK_INJECT_REMOTE_PARAMS_X86 rp86;
    const void *paramsSrc = &rp;
    if (crossTo32) {
        RtlZeroMemory(&rp86, sizeof(rp86));
        auto toU32 = [](void *p) -> ULONG { return (ULONG)(ULONG_PTR)p; };
        rp86.LdrLoadDll                   = toU32((void*)rp.LdrLoadDll);
        rp86.CompanionPath.Length         = rp.CompanionPath.Length;
        rp86.CompanionPath.MaximumLength  = rp.CompanionPath.MaximumLength;
        rp86.CompanionPath.Buffer         = toU32(rp.CompanionPath.Buffer);
        rp86.ExecuteOffset                = (ULONG)rp.ExecuteOffset;
        rp86.IsDynamic                    = rp.IsDynamic;
        rp86.RemoteFlags                  = rp.RemoteFlags;
        rp86.MhookPath.Length             = rp.MhookPath.Length;
        rp86.MhookPath.MaximumLength      = rp.MhookPath.MaximumLength;
        rp86.MhookPath.Buffer             = toU32(rp.MhookPath.Buffer);
        rp86.TargetDllPath.Length         = rp.TargetDllPath.Length;
        rp86.TargetDllPath.MaximumLength  = rp.TargetDllPath.MaximumLength;
        rp86.TargetDllPath.Buffer         = toU32(rp.TargetDllPath.Buffer);
        rp86.FunctionName.Length          = rp.FunctionName.Length;
        rp86.FunctionName.MaximumLength   = rp.FunctionName.MaximumLength;
        rp86.FunctionName.Buffer          = toU32(rp.FunctionName.Buffer);
        rp86.FunctionRva                  = rp.FunctionRva;
        rp86.UserData                     = toU32(rp.UserData);
        rp86.UserDataSize                 = (ULONG)rp.UserDataSize;
        rp86.CompletionEvent              = toU32(rp.CompletionEvent);
        rp86.StatusSlot                   = toU32(rp.StatusSlot);
        // CallerProcess/Thread/Apc/IoStatusBlock stay 0: delivered caller-side by the
        // watcher thread (see needWatcher), so the 32-bit target never touches them.
        paramsSrc = &rp86;
    }

#define WRITE(dst, src, len) \
    do { st = NtWriteVirtualMemory(params->TargetProcess, dst, (PVOID)(src), len, NULL); \
         if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; } } while(0)

    WRITE(rCode,              thunkSrc,       codeSize);
    WRITE(rCode + codeSize,   paramsSrc,      paramsSize);
    WRITE(rCompanion,         companionPath,  companionBytes);
    if (isDynamic && mhookPath && mhookBytes)
        WRITE(rMhook,         mhookPath,      mhookBytes);
    if (rTargetDll && targetDllBytes)
        WRITE(rTargetDll,     targetDllPath,  targetDllBytes);
    if (rFuncName && funcNameBytes)
        WRITE(rFuncName,      params->FunctionName, funcNameBytes);
    if (rUserData && userDataBytes)
        WRITE(rUserData,      params->UserData,     userDataBytes);
#undef WRITE

    // -----------------------------------------------------------------------
    // Step 9: Create remote thread
    // -----------------------------------------------------------------------
    st = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                           params->TargetProcess,
                           rCode,              // start = bootstrap thunk
                           rCode + codeSize,   // arg   = params block
                           0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }

    // The remote thread now owns the allocation: _internal_Execute releases it
    // via FreeAllocationAndExitThread before terminating.  The caller must not
    // free remoteBase (doing so would race the running bootstrap thunk).
    remoteBaseOwned = TRUE;

    if (needWatcher) {
        // Hand the completion event + caller-owned status slot to a watcher thread
        // in THIS process; it delivers IoStatusBlock/Event/APC once the target
        // signals.  After it starts, the watcher owns hSyncEvent + watcherSlot.
        MHOOK_INJECT_WATCHER *w = (MHOOK_INJECT_WATCHER *)RtlAllocateHeap(
            RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MHOOK_INJECT_WATCHER));
        HANDLE wTarget = NULL, wThread = NULL, hWatcher = NULL;
        st = w ? STATUS_SUCCESS : STATUS_NO_MEMORY;
        if (NT_SUCCESS(st))
            st = NtDuplicateObject(NtCurrentProcess(), params->TargetProcess,
                                   NtCurrentProcess(), &wTarget,
                                   PROCESS_VM_READ | PROCESS_VM_OPERATION, 0, 0);
        if (NT_SUCCESS(st) && params->ApcRoutine)
            st = NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(),
                                   NtCurrentProcess(), &wThread,
                                   THREAD_SET_CONTEXT, 0, 0);
        if (NT_SUCCESS(st)) {
            w->TargetProcess   = wTarget;
            w->StatusSlot      = watcherSlot;
            w->CompletionEvent = hSyncEvent;
            w->IoStatusBlock   = params->IoStatusBlock;
            w->CallerThread    = wThread;
            w->ApcRoutine      = (PVOID)params->ApcRoutine;
            w->ApcContext      = params->ApcContext;
            w->UserEvent       = params->Event;
            w->TimeoutMs       = params->TimeoutMs;
            st = NtCreateThreadEx(&hWatcher, THREAD_ALL_ACCESS, NULL,
                                  NtCurrentProcess(), (PVOID)InjectWatcherProc, w,
                                  0, 0, 0, 0, NULL);
        }
        if (!NT_SUCCESS(st)) {
            // Couldn't start the watcher.  The remote thread still runs and frees
            // its own allocation; we just drop the (now-orphaned) completion event
            // + slot via cleanup (watcherSpawned stays FALSE).
            if (wTarget) NtClose(wTarget);
            if (wThread) NtClose(wThread);
            if (w) RtlFreeHeap(RtlProcessHeap(), 0, w);
            hr = HrFromNt(st);
            goto cleanup;
        }
        NtClose(hWatcher);        // detached
        watcherSpawned = TRUE;    // watcher now owns hSyncEvent + watcherSlot
        hSyncEvent     = NULL;    // so cleanup doesn't close it
    }

    if (isAsync) {
        // Return immediately; completion is delivered to the target-bound Event
        // and/or IoStatusBlock when the injection function returns (or, cross-arch,
        // by the watcher thread spawned above).
        hr = S_OK;
        goto cleanup;
    }

    // -----------------------------------------------------------------------
    // Step 10: Wait for completion (synchronous modes)
    // -----------------------------------------------------------------------
    {
        // TimeoutMs is the TOTAL budget across both waits below.  Measure elapsed
        // with the monotonic unbiased interrupt time and pass a RELATIVE timeout
        // (negative) to NtWaitForSingleObject — relative waits are scheduled off
        // interrupt time, not the wall clock, so the budget is immune to clock
        // changes and ignores time the system spent asleep.  INFINITE => NULL
        // (wait forever).
        BOOLEAN   infinite = (params->TimeoutMs == INFINITE);
        LONGLONG  budget   = infinite ? 0
                           : (LONGLONG)(params->TimeoutMs ? params->TimeoutMs : 30000u) * 10000LL;
        ULONGLONG t0 = 0;
        if (!infinite) RtlQueryUnbiasedInterruptTime(&t0);

        LARGE_INTEGER  rel;
        PLARGE_INTEGER pTimeout = NULL;  // NULL => wait forever
        if (!infinite) { rel.QuadPart = -budget; pTimeout = &rel; }

        // Wait for the bootstrap thread.  Its exit status is the NTSTATUS set by
        // FreeAllocationAndExitThread (kept alive by the kernel thread object
        // while hThread is open, even if the target has since exited).
        st = NtWaitForSingleObject(hThread, FALSE, pTimeout);
        if (st == STATUS_TIMEOUT) { hr = MHOOK_INJECT_E_TIMEOUT; goto cleanup; }

        THREAD_BASIC_INFORMATION tbi = {};
        NTSTATUS injectStatus = STATUS_UNSUCCESSFUL;
        if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation,
                                                &tbi, sizeof(tbi), NULL)))
            injectStatus = tbi.ExitStatus;
        if (!NT_SUCCESS(injectStatus)) { hr = HrFromNt(injectStatus); goto cleanup; }

        if (needsSyncEvent) {
            // Delay path: the bootstrap thread installed the entry-point hook and
            // exited; now wait for the hook to fire and the injection fn to return,
            // charged against whatever remains of the total budget.
            if (!infinite) {
                ULONGLONG now; RtlQueryUnbiasedInterruptTime(&now);
                LONGLONG remaining = budget - (LONGLONG)(now - t0);
                if (remaining < 0) remaining = 0;  // budget already spent
                rel.QuadPart = -remaining;         // 0 => time out immediately
            }
            st = NtWaitForSingleObject(hSyncEvent, FALSE, pTimeout);
            hr = (st == STATUS_TIMEOUT) ? MHOOK_INJECT_E_TIMEOUT : S_OK;
        } else {
            hr = S_OK;
        }
    }
    } // end architecture block

cleanup:
    if (hThread)    NtClose(hThread);
    if (hSyncEvent) NtClose(hSyncEvent);
    // remoteBase is freed by the remote thread once created; free here only if
    // thread creation failed (remoteBaseOwned == FALSE) to avoid a double-free.
    if (!remoteBaseOwned && remoteBase) {
        SIZE_T zero = 0;
        NtFreeVirtualMemory(params->TargetProcess, &remoteBase, &zero, MEM_RELEASE);
    }
    // Cross-arch watcher status slot: the watcher frees it once spawned; otherwise
    // (allocated but watcher never started) free it here.
    if (!watcherSpawned && watcherSlot) {
        SIZE_T zero = 0;
        NtFreeVirtualMemory(params->TargetProcess, &watcherSlot, &zero, MEM_RELEASE);
    }
    HeapFreePath(selfPath);
    HeapFreePath(selfDir);
    HeapFreePath(companionPath);
    HeapFreePath(mhookPath);
    HeapFreePath(targetDllPath);
    HeapFreePath(cmpDir);
    return hr;
}
