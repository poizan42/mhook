; shellcode_x64.asm — remote-thread entry point for x64 injection.
;
; Called as:  DWORD WINAPI ShellcodeEntry(LPVOID lpParam)
;   RCX = pointer to ShellcodeParams (see uninit_test.cpp)
;
; ShellcodeParams field offsets (x64) — must match the C struct in uninit_test.cpp.
; Path strings are written AFTER the struct in the same remote allocation;
; UNICODE_STRING.Buffer pointers are set by the test to those remote addresses.
; UNICODE_STRING is 16 bytes on x64 (2+2+4pad+8).
;
PARAM_LdrLoadDll        EQU 0           ; ULONG_PTR (8)
PARAM_CompanionPath     EQU 8           ; UNICODE_STRING (16)
PARAM_CompanionHandle   EQU 24          ; HANDLE (8)     = 8+16
PARAM_ExecuteOffset     EQU 32          ; ULONG_PTR (8)
PARAM_IsDynamic         EQU 40          ; ULONG (4)
PARAM__pad              EQU 44          ; ULONG (4, alignment)
PARAM_MhookPath         EQU 48          ; UNICODE_STRING (16)
PARAM_MhookHandle       EQU 64          ; HANDLE (8)     = 48+16

.code

; ---------------------------------------------------------------------------
ShellcodeEntry PROC
        push    rbx
        sub     rsp, 28h            ; shadow space + alignment

        mov     rbx, rcx            ; save ShellcodeParams*

        ; --- Load companion DLL ---
        ; LdrLoadDll(NULL, NULL, &CompanionPath, &CompanionHandle)
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

; Sentinel: immediately follows ShellcodeEntry so that
; (ShellcodeEnd - ShellcodeEntry) gives the code size.
ShellcodeEnd PROC
ShellcodeEnd ENDP

END
