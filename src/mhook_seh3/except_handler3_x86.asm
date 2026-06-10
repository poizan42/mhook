; except_handler3_x86.asm — self-provided _except_handler3 for x86 MSVC
; __try/__except in ntdll-only (no-CRT) binaries.
;
; Background
; ---------
; On x86 the C/C++ compiler implements __try/__except with frame-based SEH: the
; prologue pushes a VC_EXCEPTION_REGISTRATION onto the stack, chains it through
; fs:[0], and points its Handler field at _except_handler3.  Under /GS- (which
; this project uses everywhere) the compiler emits _except_handler3 — NOT the
; cookie-checking _except_handler4 — so the only thing missing from an ntdll-only
; image is _except_handler3 itself (normally supplied by the CRT).  x86 ntdll.dll
; does not export it, so we provide it here.  Its sole external dependency is
; ntdll!RtlUnwind, which is already present in the SDK x86 ntdll.lib.
;
; This is a fresh implementation written from the published contract:
;   - Matt Pietrek, "A Crash Course on the Depths of Win32 Structured Exception
;     Handling", MSJ Jan 1997.
;   - The MSVC EH3 per-function scope-table layout (exsup.inc), /GS- variant.
; It is NOT copied from ReactOS / Wine.
;
; Scope: sufficient for mhook's use — single try level, __except with an
; EXCEPTION_EXECUTE_HANDLER / CONTINUE_SEARCH / CONTINUE_EXECUTION filter, and no
; __finally blocks.  __finally (local unwind) is intentionally not implemented;
; do not rely on __finally in a binary that gets its _except_handler3 from here.
;
; The frame layouts:
;
;   EXCEPTION_REGISTRATION_RECORD (OS-visible):
;       +0  Next
;       +4  Handler            (== _except_handler3)
;
;   VC_EXCEPTION_REGISTRATION (what MSVC actually pushes):
;       +0   Next
;       +4   Handler
;       +8   ScopeTable
;       +0Ch TryLevel
;       +10h _ebp              (EBP captured at __try entry)
;
;   SCOPETABLE_ENTRY (EH3):
;       +0  EnclosingLevel
;       +4  FilterFunc
;       +8  HandlerFunc

.386
.model flat

EXCEPTION_DISPOSITION   TYPEDEF SDWORD
ExceptionContinueExecution  EQU 0
ExceptionContinueSearch     EQU 1

EH_UNWINDING        EQU 2
EH_EXIT_UNWIND      EQU 4

; Filter return codes (the value an __except(expr) expression yields):
EXCEPTION_CONTINUE_SEARCH       EQU 0
EXCEPTION_EXECUTE_HANDLER       EQU 1
EXCEPTION_CONTINUE_EXECUTION    EQU -1

; void __stdcall RtlUnwind(void* TargetFrame, void* TargetIp,
;                          PEXCEPTION_RECORD ExceptionRecord, void* ReturnValue);
; Present in the SDK x86 ntdll.lib; resolved at the consumer link.
EXTERN _RtlUnwind@16 : PROC

.code

; -----------------------------------------------------------------------------
; transfer_to_handler(frame, handlerAddr, newTryLevel) — never returns.
; Sets frame->TryLevel, restores the function's EBP (= &registration + 0x10,
; computed with lea, NOT dereferenced), and JMPs into the __except block.
; -----------------------------------------------------------------------------
PUBLIC ___mhook_transfer_to_handler
___mhook_transfer_to_handler PROC
    mov     ecx, [esp+4]            ; ecx = registration frame (== fs:[0] value)
    mov     eax, [esp+8]            ; eax = handler address
    mov     edx, [esp+0Ch]          ; edx = new (enclosing) try level
    mov     [ecx+0Ch], edx          ; frame->TryLevel = newTryLevel
    lea     ebp, [ecx+10h]          ; ebp = &registration + 0x10  (function EBP)
    jmp     eax                     ; transfer to __except block (no return)
___mhook_transfer_to_handler ENDP

; -----------------------------------------------------------------------------
; EXCEPTION_DISPOSITION __cdecl _except_handler3(
;       PEXCEPTION_RECORD pRec,       [ebp+8]
;       VCREG*            pFrame,     [ebp+0Ch]
;       PCONTEXT          pCtx,       [ebp+10h]
;       PVOID             pDispatch)  [ebp+14h]
; -----------------------------------------------------------------------------
PUBLIC __except_handler3
__except_handler3 PROC
    ; Real EBP frame so pRec/pFrame survive the RtlUnwind call (which clobbers
    ; EBX/ESI/EDI). [ebp-8..ebp-4] = EXCEPTION_POINTERS{ExceptionRecord,ContextRecord}.
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    push    ebx
    push    esi
    push    edi

    mov     ebx, [ebp+0Ch]          ; ebx = pFrame (VC registration)
    mov     esi, [ebp+8]            ; esi = pRec

    ; Publish GetExceptionInformation() data: MSVC filter/handler code reads an
    ; EXCEPTION_POINTERS* from [EstablisherFrame-4]; _exception_code() then does
    ; ptr->ExceptionRecord->ExceptionCode.  Build it and store the pointer.
    mov     eax, [ebp+10h]          ; pCtx
    mov     [ebp-8], esi            ; EXCEPTION_POINTERS.ExceptionRecord = pRec
    mov     [ebp-4], eax            ; EXCEPTION_POINTERS.ContextRecord  = pCtx
    lea     eax, [ebp-8]
    mov     [ebx-4], eax            ; [pFrame-4] = EXCEPTION_POINTERS*

    ; Unwinding pass?  EXCEPTION_RECORD.ExceptionFlags is at +4.
    mov     eax, [esi+4]
    test    eax, (EH_UNWINDING OR EH_EXIT_UNWIND)
    jnz     do_unwind

    ; ---- SEARCH PASS: evaluate filters from current TryLevel outward ----
    mov     edx, [ebx+0Ch]          ; edx = current TryLevel
search_loop:
    cmp     edx, -1                 ; TRYLEVEL_NONE — no more scopes
    je      continue_search
    mov     ecx, [ebx+8]            ; ScopeTable base
    mov     eax, edx
    imul    eax, eax, 12            ; sizeof SCOPETABLE_ENTRY == 12
    lea     ecx, [ecx+eax]          ; ecx -> scope entry[edx]
    mov     eax, [ecx+4]            ; FilterFunc
    test    eax, eax
    jz      next_scope              ; no filter (a __finally) -> skip

    push    edx                     ; save level
    push    ecx                     ; save entry ptr
    push    ebp                     ; save OUR frame pointer
    lea     ebp, [ebx+10h]          ; EBP = function EBP for the filter
    call    eax                     ; eax = filter result
    pop     ebp
    pop     ecx
    pop     edx

    cmp     eax, EXCEPTION_CONTINUE_EXECUTION
    je      continue_execution
    cmp     eax, EXCEPTION_EXECUTE_HANDLER
    je      execute_handler
next_scope:
    mov     ecx, [ebx+8]
    mov     eax, edx
    imul    eax, eax, 12
    mov     edx, [ecx+eax]          ; edx = entry.EnclosingLevel
    jmp     search_loop

continue_search:
    mov     eax, ExceptionContinueSearch
    jmp     epilogue

continue_execution:
    mov     eax, ExceptionContinueExecution
    jmp     epilogue

    ; ---- ACCEPT: local-unwind to this scope, then jump to the handler block ----
execute_handler:
    push    dword ptr [ecx]         ; save entry.EnclosingLevel
    push    dword ptr [ecx+8]       ; save HandlerFunc

    ; RtlUnwind(pFrame, after_unwind, pRec, 0) — __stdcall (cleans its 16 bytes).
    push    0
    push    esi                     ; pRec
    push    offset after_unwind
    push    ebx                     ; pFrame (target)
    call    _RtlUnwind@16
after_unwind:
    ; RtlUnwind clobbered ebx/esi/edi; our EBP frame is intact.  HandlerFunc and
    ; enclosing level are still on our stack (pushed before the cleaned args).
    pop     eax                     ; HandlerFunc
    pop     edx                     ; enclosing level
    mov     ecx, [ebp+0Ch]          ; pFrame (reloaded)

    push    edx
    push    eax
    push    ecx
    call    ___mhook_transfer_to_handler
    int     3                       ; not reached

    ; ---- UNWIND PASS: mhook generates no __finally, so nothing to run ----
do_unwind:
    mov     eax, ExceptionContinueSearch

epilogue:
    pop     edi
    pop     esi
    pop     ebx
    mov     esp, ebp
    pop     ebp
    ret
__except_handler3 ENDP

; Register our handler in this object's .sxdata so the linker places it in the
; image SEHandlerTable (requires assembling with ml /safeseh — set via the
; project's <UseSafeExceptionHandlers>true</UseSafeExceptionHandlers> on this item).
.safeseh __except_handler3

END
