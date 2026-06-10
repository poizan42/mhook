// seh3_loadcfg_x86.c — self-provided load-config directory for a CRT-free,
// SafeSEH-aware x86 image.
//
// When an x86 image contains SafeSEH-registered handlers (.sxdata), the linker
// references __load_config_used to emit the IMAGE_LOAD_CONFIG_DIRECTORY that
// holds the Safe Exception Handler table.  In an ntdll-only (no-CRT) binary
// nothing provides that symbol, so the link fails with
//   LNK2001: unresolved external symbol __load_config_used
// We provide it here.
//
// CRITICAL: the SEHandlerTable / SEHandlerCount fields must REFERENCE the
// linker-synthesised symbols __safe_se_handler_table / __safe_se_handler_count
// (COFF: ___safe_se_handler_table / ___safe_se_handler_count).  The linker
// defines those and points them at the table it builds from the .sxdata-
// registered handlers.  If these fields are left NULL, the linker emits LNK4239
// ("invalid load config struct for SAFESEH image") and silently downgrades the
// image to non-SafeSEH.  Everything else can be zero (no /GS cookie, no CFG).
//
// x86-only: on x64 SEH is table-based (.pdata) and needs no load config, so this
// translation unit is empty there (and must NOT define _load_config_used, which
// would clash with the x64 image's own load config).

#if defined(_M_IX86)

typedef unsigned long  DWORD;
typedef unsigned short WORD;

// Linker-provided (declared, never defined here).
extern void *__safe_se_handler_table;   // COFF ___safe_se_handler_table
extern char  __safe_se_handler_count;    // COFF ___safe_se_handler_count
                                         // (its ADDRESS is the count value)

typedef struct {
    DWORD Size;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    DWORD DeCommitFreeBlockThreshold;
    DWORD DeCommitTotalFreeThreshold;
    DWORD LockPrefixTable;
    DWORD MaximumAllocationSize;
    DWORD VirtualMemoryThreshold;
    DWORD ProcessHeapFlags;
    DWORD ProcessAffinityMask;
    WORD  CSDVersion;
    WORD  DependentLoadFlags;
    DWORD EditList;
    DWORD SecurityCookie;     // 0 under /GS-
    DWORD SEHandlerTable;     // must reference the linker symbol
    DWORD SEHandlerCount;     // must reference the linker symbol
} MHOOK_LOADCFG_SEH;

const MHOOK_LOADCFG_SEH _load_config_used = {
    sizeof(MHOOK_LOADCFG_SEH),                          // Size
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,                                                  // SecurityCookie
    (DWORD)(unsigned long)&__safe_se_handler_table,     // SEHandlerTable
    (DWORD)(unsigned long)&__safe_se_handler_count,     // SEHandlerCount
};

#endif // _M_IX86
