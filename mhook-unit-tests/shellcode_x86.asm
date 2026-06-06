; shellcode_x86.asm — remote-thread entry point for x86 injection.
;
; Called as:  DWORD WINAPI ShellcodeEntry(LPVOID lpParam)  (__stdcall)
;   [EBP+8] = pointer to ShellcodeParams (see uninit_test.cpp)
;
; ShellcodeParams field offsets (x86) — must match the C struct in uninit_test.cpp.
; Path strings are written AFTER the struct in the same remote allocation;
; UNICODE_STRING.Buffer pointers are set by the test to those remote addresses.
; UNICODE_STRING is 8 bytes on x86 (2+2+4).  ULONG_PTR / HANDLE = 4 bytes.
;
PARAM_LdrLoadDll        EQU 0           ; ULONG_PTR (4)
PARAM_CompanionPath     EQU 4           ; UNICODE_STRING (8)
PARAM_CompanionHandle   EQU 12          ; HANDLE (4)     = 4+8
PARAM_ExecuteOffset     EQU 16          ; ULONG_PTR (4)
PARAM_IsDynamic         EQU 20          ; ULONG (4)
PARAM__pad              EQU 24          ; ULONG (4, alignment pad)
PARAM_MhookPath         EQU 28          ; UNICODE_STRING (8)
PARAM_MhookHandle       EQU 36          ; HANDLE (4)     = 28+8

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
