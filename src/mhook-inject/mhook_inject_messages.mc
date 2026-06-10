;// mhook_inject_messages.mc - message-table resource for the MHOOK_INJECT_E_* HRESULTs.
;//
;// Compiled with "mc -c", which sets the Customer bit (0x20000000) in every message ID,
;// so the generated IDs equal the public HRESULTs in mhook_inject.h
;// (0xA0000001..0xA0000005).  Severity "Failure" is value 0x2 (-> bit 31); a non-built-in
;// name is used so mc does not warn "Redefining value of Error".
;//
;// This resource is embedded only in mhook_inject.dll (dynamic builds); consumers look up
;// the strings with FormatMessage(FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle(
;// L"mhook_inject.dll"), hr, ...).
;//
;// IMPORTANT: keep MessageId 0x1..0x5 in sync with the MHOOK_INJECT_E_* defines in
;// mhook_inject.h.  The generated header is NOT included anywhere - mhook_inject.h remains
;// the single source of truth for the public constants.

MessageIdTypedef=HRESULT

SeverityNames=(Failure=0x2:MHOOK_SEV_FAILURE)

FacilityNames=(Inject=0x0:MHOOK_FACILITY_INJECT)

LanguageNames=(English=0x409:MSG00409)

MessageId=0x1
Severity=Failure
Facility=Inject
SymbolicName=MHOOK_INJECT_E_PARAMS_MSG
Language=English
Invalid or incompatible MHOOK_INJECT_PARAMS passed to Mhook_Inject.
.

MessageId=0x2
Severity=Failure
Facility=Inject
SymbolicName=MHOOK_INJECT_E_NO_NTDLL_MSG
Language=English
ntdll.dll was not found in the target process.
.

MessageId=0x3
Severity=Failure
Facility=Inject
SymbolicName=MHOOK_INJECT_E_NO_EXEC_MSG
Language=English
The injection entry point (_internal_Execute) was not found in the companion DLL.
.

MessageId=0x4
Severity=Failure
Facility=Inject
SymbolicName=MHOOK_INJECT_E_TIMEOUT_MSG
Language=English
Timed out waiting for the remote injection thread to complete.
.

MessageId=0x5
Severity=Failure
Facility=Inject
SymbolicName=MHOOK_INJECT_E_ACCESS_MSG
Language=English
The target process handle was not granted PROCESS_ALL_ACCESS.
.
