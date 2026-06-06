; shellcode_x64.asm — remote-thread entry point for x64 injection.
;
; Called as:  DWORD WINAPI ShellcodeEntry(LPVOID lpParam)
;   RCX = pointer to ShellcodeParams (see uninit_test.cpp)
;
; The function loads the companion DLL (and optionally mhook.dll) via
; LdrLoadDll, then calls Execute(hMhook).
;
; ShellcodeParams field offsets (x64) — must match the C struct in uninit_test.cpp.
; UNICODE_STRING is 16 bytes on x64 (2+2+4pad+8).  WCHAR[MAX_PATH]=520 bytes.
;
PARAM_LdrLoadDll        EQU 0           ; ULONG_PTR (8)
PARAM_CompanionPath     EQU 8           ; UNICODE_STRING (16)
PARAM_CompanionBuf      EQU 24          ; WCHAR[260] (520)  offset = 8+16
PARAM_CompanionHandle   EQU 544         ; HANDLE (8)        offset = 24+520
PARAM_ExecuteOffset     EQU 552         ; ULONG_PTR (8)
PARAM_IsDynamic         EQU 560         ; ULONG (4)
PARAM_MhookPath         EQU 568         ; UNICODE_STRING (16)  offset = 560+4pad+4
PARAM_MhookBuf          EQU 584         ; WCHAR[260] (520)  offset = 568+16
PARAM_MhookHandle       EQU 1104        ; HANDLE (8)        offset = 584+520

.code

; ---------------------------------------------------------------------------
ShellcodeEntry PROC
        ; Standard x64 prolog: preserve RBX (non-volatile), allocate shadow space.
        push    rbx
        sub     rsp, 28h            ; 32-byte shadow space + 8 for alignment

        mov     rbx, rcx            ; save ShellcodeParams* across calls

        ; --- Load companion DLL ---
        ; LdrLoadDll(SearchPath=NULL, Characteristics=NULL,
        ;            DllName=&params.CompanionPath, DllHandle=&params.CompanionHandle)
        xor     ecx, ecx
        xor     edx, edx
        lea     r8,  [rbx + PARAM_CompanionPath]
        lea     r9,  [rbx + PARAM_CompanionHandle]
        call    qword ptr [rbx + PARAM_LdrLoadDll]

        ; --- Optionally load mhook.dll (dynamic builds) ---
        mov     eax, dword ptr [rbx + PARAM_IsDynamic]
        test    eax, eax
        jz      CallExecute

        xor     ecx, ecx
        xor     edx, edx
        lea     r8,  [rbx + PARAM_MhookPath]
        lea     r9,  [rbx + PARAM_MhookHandle]
        call    qword ptr [rbx + PARAM_LdrLoadDll]

CallExecute:
        ; --- Call Execute(hMhook) ---
        ; Execute address = CompanionHandle + ExecuteOffset
        mov     rax, qword ptr [rbx + PARAM_CompanionHandle]
        add     rax, qword ptr [rbx + PARAM_ExecuteOffset]
        mov     rcx, qword ptr [rbx + PARAM_MhookHandle]   ; NULL for static builds
        call    rax

        xor     eax, eax
        add     rsp, 28h
        pop     rbx
        ret
ShellcodeEntry ENDP

; Sentinel label immediately after ShellcodeEntry.
; Used by the test to compute sizeof(shellcode) = ShellcodeEnd - ShellcodeEntry.
ShellcodeEnd PROC
ShellcodeEnd ENDP

END
