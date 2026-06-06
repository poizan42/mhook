// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
#undef NDEBUG
#include "disasm.h"

#ifdef NO_SANITY_CHECKS
#define NDEBUG
#undef MHOOK_ASSERT
#define MHOOK_ASSERT(x)
#endif

//////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////

ARCHITECTURE_FORMAT SupportedArchitectures[] =
{
	{ ARCH_X86,	&X86 },
	{ ARCH_X86_16, &X86 },
	{ ARCH_X64,	&X86 },
	{ ARCH_UNKNOWN, NULL }
};

typedef struct _DISASM_ARG_INFO
{
	INSTRUCTION *MatchedInstruction;
	BOOL MatchPrefix;
	U8 *Opcode;
	U32 OpcodeLength;
	INSTRUCTION_TYPE InstructionType;
	U32 Count;
} DISASM_ARG_INFO;

//////////////////////////////////////////////////////////////////////
// Function prototypes
//////////////////////////////////////////////////////////////////////

BOOL InitInstruction(INSTRUCTION *Instruction, DISASSEMBLER *Disassembler);
struct _ARCHITECTURE_FORMAT *GetArchitectureFormat(ARCHITECTURE_TYPE Type);

//////////////////////////////////////////////////////////////////////
// Error handling
//////////////////////////////////////////////////////////////////////

static void DefaultErrorHandler(ULONG64 virtualAddress, BOOL isError, LPCWSTR fmt, ...)
{
	(void)fmt;
	DbgPrint(isError ? "[0x%08I64X] DISASM ERROR\n"
	                 : "[0x%08I64X] DISASM ANOMALY\n",
	         virtualAddress);
}

tDisasmErrorProc tDisasmErrorHandler = DefaultErrorHandler;

//////////////////////////////////////////////////////////////////////
// Disassembler setup
//////////////////////////////////////////////////////////////////////

BOOL InitDisassembler(DISASSEMBLER *Disassembler, ARCHITECTURE_TYPE Architecture)
{
	ARCHITECTURE_FORMAT *ArchFormat;

	memset(Disassembler, 0, sizeof(DISASSEMBLER));
	Disassembler->Initialized = DISASSEMBLER_INITIALIZED;
	
	ArchFormat = GetArchitectureFormat(Architecture);
	if (!ArchFormat) { MHOOK_ASSERT(0); return FALSE; }
	Disassembler->ArchType = ArchFormat->Type;
	Disassembler->Functions = ArchFormat->Functions;
	return TRUE;
}

void CloseDisassembler(DISASSEMBLER *Disassembler)
{
	memset(Disassembler, 0, sizeof(DISASSEMBLER));
}

//////////////////////////////////////////////////////////////////////
// Instruction setup
//////////////////////////////////////////////////////////////////////

BOOL InitInstruction(INSTRUCTION *Instruction, DISASSEMBLER *Disassembler)
{
	memset(Instruction, 0, sizeof(INSTRUCTION));
	Instruction->Initialized = INSTRUCTION_INITIALIZED;
	Instruction->Disassembler = Disassembler;
	memset(Instruction->String, ' ', MAX_OPCODE_DESCRIPTION-1);
	Instruction->String[MAX_OPCODE_DESCRIPTION-1] = '\0';
	return TRUE;
}

// If Decode = FALSE, only the following fields are valid:
// Instruction->Length, Instruction->Address, Instruction->Prefixes, Instruction->PrefixCount,
// Instruction->OpcodeBytes, Instruction->Instruction->OpcodeLength, Instruction->Groups,
// Instruction->Type, Instruction->OperandCount
//
// If Disassemble = TRUE, then Instruction->String is valid (also requires Decode = TRUE)
//
// WARNING: This will overwrite the previously obtained instruction
INSTRUCTION *GetInstruction(DISASSEMBLER *Disassembler, U64 VirtualAddress, U8 *Address, U32 Flags)
{
	if (Disassembler->Initialized != DISASSEMBLER_INITIALIZED) { MHOOK_ASSERT(0); return NULL; }
	MHOOK_ASSERT(Address);
	InitInstruction(&Disassembler->Instruction, Disassembler);
	Disassembler->Instruction.Address = Address;	
	Disassembler->Instruction.VirtualAddressDelta = VirtualAddress - (U64)Address;
	if (!Disassembler->Functions->GetInstruction(&Disassembler->Instruction, Address, Flags))
	{
		MHOOK_ASSERT(Disassembler->Instruction.Address == Address);
		MHOOK_ASSERT(Disassembler->Instruction.Length < MAX_INSTRUCTION_LENGTH);

		// Save the address that failed, in case the lower-level disassembler didn't
		Disassembler->Instruction.Address = Address;
		Disassembler->Instruction.ErrorOccurred = TRUE;
		return NULL;
	}
	return &Disassembler->Instruction;
}

///////////////////////////////////////////////////////////////////////////
// Miscellaneous
///////////////////////////////////////////////////////////////////////////

static ARCHITECTURE_FORMAT *GetArchitectureFormat(ARCHITECTURE_TYPE Type)
{
	ARCHITECTURE_FORMAT *Format;
	for (Format = SupportedArchitectures; Format->Type != ARCH_UNKNOWN; Format++)
	{
		if (Format->Type == Type) return Format;
	}

	MHOOK_ASSERT(0);
	return NULL;
}

