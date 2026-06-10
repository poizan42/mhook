; uninit_test_shellcode_x64.asm — remote-thread entry point for x64 injection.
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
PARAM_MhookHandle           EQU 64          ; HANDLE (8)     = 48+16
PARAM_LdrCompanionStatus    EQU 72          ; NTSTATUS (4) diagnostic — sizeof(ShellcodeParams) without this = 72

        PUBLIC ShellcodeEnd

.code

; ---------------------------------------------------------------------------
ShellcodeEntry PROC
        push    rbx
        ; x64 ABI: RSP is 8 (mod 16) at entry; "push rbx" makes it 0 (mod 16), so
        ; the allocation must be a multiple of 16 to keep RSP 16-aligned at the
        ; inner CALLs.  0x28 left it misaligned by 8, which makes callees that use
        ; 16-byte-aligned locals (e.g. CONTEXT in NtGetContextThread) fail.
        sub     rsp, 20h            ; 32-byte shadow space, keeps RSP 16-aligned

        mov     rbx, rcx            ; save ShellcodeParams*

        ; --- Load companion DLL ---
        ; LdrLoadDll(NULL, NULL, &CompanionPath, &CompanionHandle)
        xor     ecx, ecx
        xor     edx, edx
        lea     r8,  [rbx + PARAM_CompanionPath]
        lea     r9,  [rbx + PARAM_CompanionHandle]
        call    qword ptr [rbx + PARAM_LdrLoadDll]
        ; Save NTSTATUS from LdrLoadDll for companion DLL (diagnostic)
        mov     dword ptr [rbx + PARAM_LdrCompanionStatus], eax

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
        add     rsp, 20h            ; must match the prolog's "sub rsp, 20h"
        pop     rbx
        ret

; Sentinel: immediately follows ShellcodeEntry so that
; (ShellcodeEnd - ShellcodeEntry) gives the code size.
ShellcodeEnd::
        nop
ShellcodeEntry ENDP

END
