; inject_shellcode_x64.asm — remote-thread entry point for x64 injection.
;
; Called as:  DWORD WINAPI InjectShellcodeEntry(LPVOID lpParam)
;   RCX = pointer to MHOOK_INJECT_REMOTE_PARAMS (see inject_params.h)
;
; MHOOK_INJECT_REMOTE_PARAMS field offsets (x64) — must match inject_params.h.
;
PARAM_LdrLoadDll            EQU 0           ; ULONG_PTR (8)
PARAM_CompanionPath         EQU 8           ; UNICODE_STRING (16)
PARAM_CompanionHandle       EQU 24          ; HANDLE (8)
PARAM_ExecuteOffset         EQU 32          ; ULONG_PTR (8)
PARAM_IsDynamic             EQU 40          ; ULONG (4)
PARAM__pad                  EQU 44          ; ULONG (4)
PARAM_MhookPath             EQU 48          ; UNICODE_STRING (16)
PARAM_MhookHandle           EQU 64          ; HANDLE (8)
PARAM_TargetDllPath         EQU 72          ; UNICODE_STRING (16)
PARAM_FunctionName          EQU 88          ; ANSI_STRING (16)
PARAM_FunctionRva           EQU 104         ; ULONG (4)
PARAM__rvapad               EQU 108         ; ULONG (4)
PARAM_UserData              EQU 112         ; PVOID (8)
PARAM_UserDataSize          EQU 120         ; SIZE_T (8)
PARAM_InjectStatus          EQU 128         ; NTSTATUS (4)
PARAM_LdrCompanionStatus    EQU 132         ; NTSTATUS (4)

        PUBLIC InjectShellcodeEnd

.code

; ---------------------------------------------------------------------------
InjectShellcodeEntry PROC
        push    rbx
        sub     rsp, 28h            ; shadow space + stack alignment

        mov     rbx, rcx            ; save MHOOK_INJECT_REMOTE_PARAMS*

        ; --- Load companion DLL ---
        ; LdrLoadDll(NULL, NULL, &CompanionPath, &CompanionHandle)
        xor     ecx, ecx
        xor     edx, edx
        lea     r8,  [rbx + PARAM_CompanionPath]
        lea     r9,  [rbx + PARAM_CompanionHandle]
        call    qword ptr [rbx + PARAM_LdrLoadDll]
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
        ; --- Call _internal_Execute(pParams) ---
        ; Execute address = CompanionHandle + ExecuteOffset
        mov     rax, qword ptr [rbx + PARAM_CompanionHandle]
        add     rax, qword ptr [rbx + PARAM_ExecuteOffset]
        mov     rcx, rbx            ; _internal_Execute(MHOOK_INJECT_REMOTE_PARAMS*)
        call    rax

        xor     eax, eax
        add     rsp, 28h
        pop     rbx
        ret

; Sentinel: immediately follows InjectShellcodeEntry so that
; (InjectShellcodeEnd - InjectShellcodeEntry) gives the code size.
InjectShellcodeEnd::
        nop
InjectShellcodeEntry ENDP

END
