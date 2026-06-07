; inject_entry_thunk_x86.asm — entry-point hook trampoline for x86.
;
; Same role as inject_entry_thunk_x64.asm but for 32-bit targets.
; DoDelayedEntry is __cdecl (no stack arguments, returns PVOID in EAX).
;
; After the call returns, EAX = original entry point; JMP there so this
; frame is NOT on the stack.

.686
.model flat, C      ; 'C' language: MASM auto-adds '_' prefix to PROC names

        EXTERN DoDelayedEntry:PROC

        PUBLIC DelayedEntryThunk

.code

; ---------------------------------------------------------------------------
DelayedEntryThunk PROC
        call    DoDelayedEntry      ; eax = original entry point address
        jmp     eax                 ; tail-jump — no hook frame left on stack
DelayedEntryThunk ENDP

END
