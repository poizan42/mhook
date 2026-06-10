; inject_bootstrap_thunk_x64.asm — remote-thread entry point for x64 injection.
;
; Called as:  DWORD WINAPI InjectBootstrapThunkEntry(LPVOID lpParam)
;   RCX = pointer to MHOOK_INJECT_REMOTE_PARAMS (see inject_params.h)
;
; MHOOK_INJECT_REMOTE_PARAMS field offsets (x64) — must match inject_params.h.
;
PARAM_LdrLoadDll            EQU 0           ; ULONG_PTR (8)
PARAM_CompanionPath         EQU 8           ; UNICODE_STRING (16)
PARAM_CompanionHandle       EQU 24          ; HANDLE (8)
PARAM_ExecuteOffset         EQU 32          ; ULONG_PTR (8)
PARAM_IsDynamic             EQU 40          ; ULONG (4)
PARAM_RemoteFlags           EQU 44          ; ULONG (4) MHOOK_REMOTE_FLAG_*
PARAM_MhookPath             EQU 48          ; UNICODE_STRING (16)
PARAM_MhookHandle           EQU 64          ; HANDLE (8)
PARAM_TargetDllPath         EQU 72          ; UNICODE_STRING (16)
PARAM_FunctionName          EQU 88          ; ANSI_STRING (16)
PARAM_FunctionRva           EQU 104         ; ULONG (4)
PARAM__rvapad               EQU 108         ; ULONG (4)
PARAM_UserData              EQU 112         ; PVOID (8)
PARAM_UserDataSize          EQU 120         ; SIZE_T (8)
PARAM_InjectStatus           EQU 128         ; NTSTATUS (4)
PARAM_LdrCompanionStatus     EQU 132         ; NTSTATUS (4)
PARAM_RtlAddFunctionTable    EQU 136         ; PVOID (8)
PARAM_RtlDeleteFunctionTable EQU 144         ; PVOID (8)
PARAM_BootstrapThunkBase          EQU 152         ; ULONG64 (8)
PARAM_BootstrapThunkRF            EQU 160         ; RUNTIME_FUNCTION [3 DWORDs = 12 bytes]

        PUBLIC InjectBootstrapThunkEnd

.code

; ---------------------------------------------------------------------------
InjectBootstrapThunkEntry PROC
        push    rbx
        ; x64 ABI: RSP is 8 (mod 16) at entry; after "push rbx" it is 0 (mod 16),
        ; so the allocation MUST be a multiple of 16 to keep RSP 16-aligned at the
        ; inner CALLs.  0x20 = the 32-byte shadow space.  (Using 0x28 here left the
        ; stack misaligned by 8, which made NtGetContextThread in callees fail with
        ; STATUS_DATATYPE_MISALIGNMENT — CONTEXT requires 16-byte alignment.)
        sub     rsp, 20h            ; 32-byte shadow space, keeps RSP 16-aligned

        mov     rbx, rcx            ; save MHOOK_INJECT_REMOTE_PARAMS*

        ; --- Register unwind info for this frame so that x64 exception
        ;     dispatch and WER can unwind through the bootstrap-thunk frame. ---
        ; RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
        mov     rax, qword ptr [rbx + PARAM_RtlAddFunctionTable]
        test    rax, rax
        jz      LoadCompanion
        lea     rcx, [rbx + PARAM_BootstrapThunkRF]              ; FunctionTable
        mov     edx, 1                                       ; EntryCount
        mov     r8,  qword ptr [rbx + PARAM_BootstrapThunkBase]  ; BaseAddress
        call    rax
        ; ignore BOOLEAN return value in rax

LoadCompanion:
        ; --- Load companion DLL ---
        ; LdrLoadDll(NULL, NULL, &CompanionPath, &CompanionHandle)
        xor     ecx, ecx
        xor     edx, edx
        lea     r8,  [rbx + PARAM_CompanionPath]
        lea     r9,  [rbx + PARAM_CompanionHandle]
        call    qword ptr [rbx + PARAM_LdrLoadDll]
        mov     dword ptr [rbx + PARAM_LdrCompanionStatus], eax

        ; --- Guard: if LdrLoadDll failed CompanionHandle is still NULL.
        ;     Return LdrCompanionStatus directly instead of crashing through
        ;     a zero handle. ---
        cmp     qword ptr [rbx + PARAM_CompanionHandle], 0
        jne     CallMhook
        movsxd  rax, dword ptr [rbx + PARAM_LdrCompanionStatus]
        jmp     Epilog

CallMhook:
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
        ; rax = NTSTATUS from _internal_Execute; fall through to Epilog

Epilog:
        ; --- Deregister the bootstrap-thunk unwind info before the host frees the
        ;     allocation.  Safe no-op if RtlAddFunctionTable was skipped or
        ;     returned FALSE. ---
        ;
        ; We must NOT use push rax / pop rax to preserve the return value
        ; across the call: RtlDeleteFunctionTable homes rcx at [RSP+8], which
        ; is exactly where push would have stored rax.  Instead, spill eax into
        ; the InjectStatus field of the params block (in remote heap, not the
        ; stack), then reload it after the call.
        ;
        ; RtlDeleteFunctionTable(FunctionTable)
        mov     dword ptr [rbx + PARAM_InjectStatus], eax   ; spill NTSTATUS
        mov     rax, qword ptr [rbx + PARAM_RtlDeleteFunctionTable]
        test    rax, rax
        jz      EpilogDone
        lea     rcx, [rbx + PARAM_BootstrapThunkRF]              ; same ptr as Add
        call    rax
EpilogDone:
        movsxd  rax, dword ptr [rbx + PARAM_InjectStatus]   ; reload NTSTATUS
        add     rsp, 20h            ; must match the prolog's "sub rsp, 20h"
        pop     rbx
        ret

; Sentinel: immediately follows InjectBootstrapThunkEntry so that
; (InjectBootstrapThunkEnd - InjectBootstrapThunkEntry) gives the code size.
InjectBootstrapThunkEnd::
        nop
InjectBootstrapThunkEntry ENDP

END
