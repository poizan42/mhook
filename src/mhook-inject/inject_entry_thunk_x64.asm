; inject_entry_thunk_x64.asm — entry-point hook trampoline for x64.
;
; DelayedEntryThunk is installed as a hook on the process entry point when
; MHOOK_REMOTE_FLAG_DELAY_UNTIL_INIT is set and the process is not yet
; initialised.  When the loader calls the entry point, the hook fires here:
;
;   1. Call DoDelayedEntry() — runs the user's injection function (if not
;      already called by the race-check), unhooks the entry point, and
;      returns the restored original entry-point address in RAX.
;   2. JMP to that address — tail-jump so this frame is NOT on the stack
;      when the original entry point runs.
;
; The stack is in the same state as if the loader had called the entry point
; directly (return address to the loader is at [RSP] after the JMP).

        EXTERN DoDelayedEntry:PROC

        PUBLIC DelayedEntryThunk

.code

; ---------------------------------------------------------------------------
DelayedEntryThunk PROC
        sub     rsp, 28h            ; shadow space + 16-byte stack alignment
        call    DoDelayedEntry      ; rax = original entry point address
        add     rsp, 28h
        jmp     rax                 ; tail-jump — no hook frame left on stack
DelayedEntryThunk ENDP

END
