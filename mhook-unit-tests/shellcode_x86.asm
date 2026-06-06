; shellcode_x86.asm — remote-thread entry point for x86 injection.
;
; Called as:  DWORD WINAPI ShellcodeEntry(LPVOID lpParam)  (__stdcall)
;   [EBP+8] = pointer to ShellcodeParams (see uninit_test.cpp)
;
; .model flat, C causes MASM to prepend '_' to all PROC names so the symbols
; match the names expected by extern "C" declarations in C/C++ source.
; Calling convention is handled manually: we use "ret 4" to clean lpParam
; (4 bytes) from the stack as required by __stdcall.
;
; ShellcodeParams field offsets (x86) — must match the C struct in uninit_test.cpp.
; UNICODE_STRING is 8 bytes on x86 (2+2+4).  WCHAR[MAX_PATH]=520 bytes.
; ULONG_PTR / HANDLE = 4 bytes on x86.
;
PARAM_LdrLoadDll        EQU 0           ; ULONG_PTR (4)
PARAM_CompanionPath     EQU 4           ; UNICODE_STRING (8)
PARAM_CompanionBuf      EQU 12          ; WCHAR[260] (520)  offset = 4+8
PARAM_CompanionHandle   EQU 532         ; HANDLE (4)        offset = 12+520
PARAM_ExecuteOffset     EQU 536         ; ULONG_PTR (4)
PARAM_IsDynamic         EQU 540         ; ULONG (4)
PARAM__pad              EQU 544         ; ULONG (4, alignment pad)
PARAM_MhookPath         EQU 548         ; UNICODE_STRING (8)
PARAM_MhookBuf          EQU 556         ; WCHAR[260] (520)  offset = 548+8
PARAM_MhookHandle       EQU 1076        ; HANDLE (4)        offset = 556+520

.686
.model flat, C      ; 'C' language: MASM adds '_' prefix to all PROC names

.code

; ---------------------------------------------------------------------------
ShellcodeEntry PROC
        push    ebp
        mov     ebp, esp
        push    ebx

        mov     ebx, dword ptr [ebp+8]  ; ShellcodeParams*

        ; --- Load companion DLL ---
        lea     eax, [ebx + PARAM_CompanionHandle]
        push    eax                     ; DllHandle  (arg4)
        lea     eax, [ebx + PARAM_CompanionPath]
        push    eax                     ; DllName    (arg3)
        push    0                       ; Characteristics (arg2)
        push    0                       ; SearchPath (arg1)
        call    dword ptr [ebx + PARAM_LdrLoadDll]

        ; --- Optionally load mhook.dll ---
        mov     eax, dword ptr [ebx + PARAM_IsDynamic]
        test    eax, eax
        jz      CallExecute

        lea     eax, [ebx + PARAM_MhookHandle]
        push    eax
        lea     eax, [ebx + PARAM_MhookPath]
        push    eax
        push    0
        push    0
        call    dword ptr [ebx + PARAM_LdrLoadDll]

CallExecute:
        ; --- Call Execute(hMhook) ---
        ; Execute is __cdecl so caller cleans its one DWORD argument.
        ; Execute address = CompanionHandle + ExecuteOffset
        mov     eax, dword ptr [ebx + PARAM_CompanionHandle]
        add     eax, dword ptr [ebx + PARAM_ExecuteOffset]
        push    dword ptr [ebx + PARAM_MhookHandle]     ; hMhook
        call    eax
        add     esp, 4                  ; __cdecl caller-clean

        xor     eax, eax
        pop     ebx
        pop     ebp
        ret     4                       ; __stdcall: clean lpParam (4 bytes)
ShellcodeEntry ENDP

; Sentinel: immediately follows ShellcodeEntry so that
; (ShellcodeEnd - ShellcodeEntry) gives the code size.
ShellcodeEnd PROC
ShellcodeEnd ENDP

END
