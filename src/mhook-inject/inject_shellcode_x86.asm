; inject_shellcode_x86.asm — remote-thread entry point for x86 injection.
;
; Called as:  DWORD WINAPI InjectShellcodeEntry(LPVOID lpParam)  (__stdcall)
;   [EBP+8] = pointer to MHOOK_INJECT_REMOTE_PARAMS (see inject_params.h)
;
; MHOOK_INJECT_REMOTE_PARAMS field offsets (x86) — must match inject_params.h.
;
PARAM_LdrLoadDll            EQU 0           ; ULONG_PTR (4)
PARAM_CompanionPath         EQU 4           ; UNICODE_STRING (8)
PARAM_CompanionHandle       EQU 12          ; HANDLE (4)
PARAM_ExecuteOffset         EQU 16          ; ULONG_PTR (4)
PARAM_IsDynamic             EQU 20          ; ULONG (4)
PARAM_RemoteFlags           EQU 24          ; ULONG (4) MHOOK_REMOTE_FLAG_*
PARAM_MhookPath             EQU 28          ; UNICODE_STRING (8)
PARAM_MhookHandle           EQU 36          ; HANDLE (4)
PARAM_TargetDllPath         EQU 40          ; UNICODE_STRING (8)
PARAM_FunctionName          EQU 48          ; ANSI_STRING (8)
PARAM_FunctionRva           EQU 56          ; ULONG (4)
PARAM__rvapad               EQU 60          ; ULONG (4)
PARAM_UserData              EQU 64          ; PVOID (4)
PARAM_UserDataSize          EQU 68          ; SIZE_T (4)
PARAM_InjectStatus          EQU 72          ; NTSTATUS (4)
PARAM_LdrCompanionStatus    EQU 76          ; NTSTATUS (4)

        PUBLIC InjectShellcodeEnd

.686
.model flat, C      ; 'C' language: MASM adds '_' prefix to all PROC names

.code

; ---------------------------------------------------------------------------
InjectShellcodeEntry PROC
        push    ebp
        mov     ebp, esp
        push    ebx

        mov     ebx, dword ptr [ebp+8]      ; MHOOK_INJECT_REMOTE_PARAMS*

        ; --- Load companion DLL ---
        ; LdrLoadDll(NULL, NULL, &CompanionPath, &CompanionHandle)
        lea     eax, [ebx + PARAM_CompanionHandle]
        push    eax                     ; DllHandle  (arg4)
        lea     eax, [ebx + PARAM_CompanionPath]
        push    eax                     ; DllName    (arg3)
        push    0                       ; Characteristics (arg2)
        push    0                       ; SearchPath (arg1)
        call    dword ptr [ebx + PARAM_LdrLoadDll]
        mov     dword ptr [ebx + PARAM_LdrCompanionStatus], eax

        ; --- Optionally load mhook.dll (dynamic builds) ---
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
        ; --- Call _internal_Execute(pParams) ---
        ; _internal_Execute is __cdecl so caller cleans the one DWORD argument.
        ; Execute address = CompanionHandle + ExecuteOffset
        mov     eax, dword ptr [ebx + PARAM_CompanionHandle]
        add     eax, dword ptr [ebx + PARAM_ExecuteOffset]
        push    ebx                     ; pParams (_internal_Execute's only arg)
        call    eax
        add     esp, 4                  ; __cdecl caller-clean

        ; eax holds the NTSTATUS returned by _internal_Execute; propagate it
        ; as the thread exit code (same mechanism as x64).
        pop     ebx
        pop     ebp
        ret     4                       ; __stdcall: clean lpParam (4 bytes)

; Sentinel: immediately follows InjectShellcodeEntry so that
; (InjectShellcodeEnd - InjectShellcodeEntry) gives the code size.
InjectShellcodeEnd::
        nop
InjectShellcodeEntry ENDP

END
