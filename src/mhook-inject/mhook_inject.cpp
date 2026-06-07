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

// ---------------------------------------------------------------------------
// Shellcode blobs — assembled by MASM, linked as object code
// ---------------------------------------------------------------------------

extern "C" void InjectShellcodeEntry();
extern "C" void InjectShellcodeEnd();

// ---------------------------------------------------------------------------
// HRESULT helpers
// ---------------------------------------------------------------------------

#define MHOOK_INJECT_E_PARAMS    ((HRESULT)0x80040001L)  // bad/incompatible params
#define MHOOK_INJECT_E_NO_NTDLL  ((HRESULT)0x80040002L)  // ntdll not found in target
#define MHOOK_INJECT_E_NO_EXEC   ((HRESULT)0x80040003L)  // _internal_Execute not in DLL
#define MHOOK_INJECT_E_TIMEOUT   ((HRESULT)0x80040004L)  // remote thread timed out

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

static ULONG_PTR FindDllBaseInProcess(HANDLE hProcess, const WCHAR *targetName)
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

// ---------------------------------------------------------------------------
// IsTargetWow64 — TRUE if target process is a WOW64 (32-bit) process
// ---------------------------------------------------------------------------

static BOOLEAN IsTargetWow64(HANDLE hProcess)
{
    PVOID wow64Info = NULL;
    NTSTATUS st = NtQueryInformationProcess(hProcess, ProcessWow64Information,
                                            &wow64Info, sizeof(wow64Info), NULL);
    return NT_SUCCESS(st) && wow64Info != NULL;
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
                                     ULONG       *outRva)
{
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

// ---------------------------------------------------------------------------
// Mhook_Inject
// ---------------------------------------------------------------------------

HRESULT __cdecl Mhook_Inject(MHOOK_INJECT_PARAMS *params)
{
    if (!params || params->Size != sizeof(MHOOK_INJECT_PARAMS))
        return MHOOK_INJECT_E_PARAMS;
    if (!params->TargetProcess)
        return MHOOK_INJECT_E_PARAMS;

    BOOLEAN useFnPtr = (params->FunctionPointer != NULL);
    BOOLEAN useName  = (params->DllPath != NULL && params->FunctionName != NULL);
    if (useFnPtr == useName)
        return MHOOK_INJECT_E_PARAMS;

    HRESULT hr = E_FAIL;
    NTSTATUS st;
    PVOID  remoteBase = NULL;
    HANDLE hThread    = NULL;

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
    companionPath = HeapDupWStr(selfPath);  // companion = mhook_inject.dll

    if (useFnPtr) {
        PVOID fnBase = GetModuleBase(params->FunctionPointer);
        if (!fnBase) { hr = E_FAIL; goto cleanup; }
        functionRva = (ULONG)((ULONG_PTR)params->FunctionPointer - (ULONG_PTR)fnBase);
        targetDllPath = GetModuleFullPath(params->FunctionPointer);
    } else {
        targetDllPath = ResolveFullPath(selfDir, params->DllPath);
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
    st = GetExportRvaFromFile(companionPath, "_internal_Execute", &executeRva);
    if (!NT_SUCCESS(st)) { hr = MHOOK_INJECT_E_NO_EXEC; goto cleanup; }

    // -----------------------------------------------------------------------
    // Step 4: Resolve mhook.dll path (dynamic builds only)
    // -----------------------------------------------------------------------
    if (isDynamic) {
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
    // Step 5: Determine target architecture; select shellcode
    // -----------------------------------------------------------------------
    {
    BOOLEAN targetIs32 = IsTargetWow64(params->TargetProcess);
#ifdef _M_X64
    if (targetIs32) { hr = E_NOTIMPL; goto cleanup; }
#else
    if (!targetIs32) { hr = E_NOTIMPL; goto cleanup; }
#endif

    // -----------------------------------------------------------------------
    // Step 6: Find LdrLoadDll in target process
    // -----------------------------------------------------------------------
    ULONG_PTR remoteNtdllBase = FindDllBaseInProcess(params->TargetProcess, L"ntdll.dll");
    if (!remoteNtdllBase) { hr = MHOOK_INJECT_E_NO_NTDLL; goto cleanup; }

    // Compute LdrLoadDll RVA from the local ntdll and apply to remote base.
    // Look up ntdll by BaseDllName in the LDR — using &LdrLoadDll would give
    // the address of the import thunk in the calling module, not ntdll itself.
    LDR_DATA_TABLE_ENTRY_MIN *ntdllEntry = FindModuleEntryByBaseName(L"ntdll.dll");
    if (!ntdllEntry) { hr = E_FAIL; goto cleanup; }

    WCHAR *localNtdllPath = GetModuleFullPath(ntdllEntry->DllBase);
    if (!localNtdllPath) { hr = E_FAIL; goto cleanup; }

    ULONG ldrRva = 0;
    st = GetExportRvaFromFile(localNtdllPath, "LdrLoadDll", &ldrRva);
    HeapFreePath(localNtdllPath);
    if (!NT_SUCCESS(st)) { hr = E_FAIL; goto cleanup; }

    LdrLoadDllFn remoteLdrLoadDll =
        (LdrLoadDllFn)(remoteNtdllBase + ldrRva);

    // -----------------------------------------------------------------------
    // Step 7: Calculate remote memory layout
    // -----------------------------------------------------------------------
    SIZE_T codeSize   = (SIZE_T)((BYTE*)InjectShellcodeEnd - (BYTE*)InjectShellcodeEntry);
    SIZE_T paramsSize = sizeof(MHOOK_INJECT_REMOTE_PARAMS);

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
    rp.FunctionRva    = functionRva;
    rp.UserData       = rUserData;
    rp.UserDataSize   = userDataBytes;

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

#define WRITE(dst, src, len) \
    do { st = NtWriteVirtualMemory(params->TargetProcess, dst, (PVOID)(src), len, NULL); \
         if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; } } while(0)

    WRITE(rCode,              InjectShellcodeEntry, codeSize);
    WRITE(rCode + codeSize,   &rp,            paramsSize);
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
    // Step 9: Create remote thread and wait
    // -----------------------------------------------------------------------
    st = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                           params->TargetProcess,
                           rCode,              // start = shellcode
                           rCode + codeSize,   // arg   = params block
                           0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(st)) { hr = HrFromNt(st); goto cleanup; }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL;  // 30 s in 100-ns units
    st = NtWaitForSingleObject(hThread, FALSE, &timeout);
    if (st == STATUS_TIMEOUT) { hr = MHOOK_INJECT_E_TIMEOUT; goto cleanup; }
    // The remote thread has finished (_internal_Execute ran + ResumeOtherThreads).
    // Reading InjectStatus back from remote memory is unreliable: the target process
    // may have already exited (and its address space freed) by the time we get here,
    // because _internal_Execute calls ResumeOtherThreads() before returning.
    // Treat a completed-without-timeout thread as success; the caller's own
    // logic (e.g. reading a marker from a pipe) verifies the injection outcome.
    hr = NT_SUCCESS(st) ? S_OK : HrFromNt(st);
    } // end architecture block

cleanup:
    if (hThread)    NtClose(hThread);
    if (remoteBase) {
        SIZE_T zero = 0;
        NtFreeVirtualMemory(params->TargetProcess, &remoteBase, &zero, MEM_RELEASE);
    }
    HeapFreePath(selfPath);
    HeapFreePath(selfDir);
    HeapFreePath(companionPath);
    HeapFreePath(mhookPath);
    HeapFreePath(targetDllPath);
    HeapFreePath(cmpDir);
    return hr;
}
