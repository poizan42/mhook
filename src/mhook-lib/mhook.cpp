//Copyright (c) 2007-2008, Marton Anka
//
//Permission is hereby granted, free of charge, to any person obtaining a
//copy of this software and associated documentation files (the "Software"),
//to deal in the Software without restriction, including without limitation
//the rights to use, copy, modify, merge, publish, distribute, sublicense,
//and/or sell copies of the Software, and to permit persons to whom the
//Software is furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included
//in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//IN THE SOFTWARE.

#include "../nt_defs.h"
#include "mhook.h"
#include "../disasm-lib/disasm.h"

//=========================================================================
#ifndef cntof
#define cntof(a) (sizeof(a)/sizeof(a[0]))
#endif

//=========================================================================
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a != INVALID_HANDLE_VALUE) && (a != NULL))
#endif

//=========================================================================
#ifndef ODPRINTF

#ifdef _DEBUG
#define ODPRINTF(a) odprintf a
#else
#define ODPRINTF(a)
#endif

inline void __cdecl odprintf(PCSTR format, ...) {
	va_list args;
	va_start(args, format);
	vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, format, args);
	va_end(args);
}

#endif //#ifndef ODPRINTF

//=========================================================================
// Heap helpers — all allocation goes through the process heap via ntdll.
#define mhook_alloc(sz)     RtlAllocateHeap(RtlProcessHeap(), 0, (sz))
#define mhook_zalloc(sz)    RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define mhook_free(p)       RtlFreeHeap(RtlProcessHeap(), 0, (p))

//=========================================================================
#define MHOOKS_MAX_CODE_BYTES	32
#define MHOOKS_MAX_RIPS			 4

//=========================================================================
// The trampoline structure - stores every bit of info about a hook
struct MHOOKS_TRAMPOLINE {
	PBYTE	pSystemFunction;								// the original system function
	DWORD	cbOverwrittenCode;								// number of bytes overwritten by the jump
	PBYTE	pHookFunction;									// the hook function that we provide
	BYTE	codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES];	// placeholder for code that jumps to the hook function
	BYTE	codeTrampoline[MHOOKS_MAX_CODE_BYTES];			// placeholder for code that holds the first few
															//   bytes from the system function and a jump to the remainder
															//   in the original location
	BYTE	codeUntouched[MHOOKS_MAX_CODE_BYTES];			// placeholder for unmodified original code
															//   (we patch IP-relative addressing)
	MHOOKS_TRAMPOLINE* pPrevTrampoline;						// When in the free list, these are pointers to the prev and next entry.
	MHOOKS_TRAMPOLINE* pNextTrampoline;						// When not in the free list, this is a pointer to the prev and next trampoline in use.
};

//=========================================================================
// The patch data structures - store info about rip-relative instructions
// during hook placement
struct MHOOKS_RIPINFO
{
	DWORD	dwOffset;
	S64		nDisplacement;

	// new instruction
	DWORD   dwInstructionOffset;
	BYTE    pbInstruction[64];
	DWORD   dwInstructionLength;

	// old instruction
	DWORD   dwOldInstructionOffset;
	DWORD   dwOldInstructionLength;
};

struct MHOOKS_PATCHDATA
{
	S64				nLimitUp;
	S64				nLimitDown;
	DWORD			nRipCnt;
	MHOOKS_RIPINFO	rips[MHOOKS_MAX_RIPS];
};

//=========================================================================
// Global vars
static BOOL g_bVarsInitialized = FALSE;
static RTL_CRITICAL_SECTION g_cs;
static MHOOKS_TRAMPOLINE* g_pHooks = NULL;
static MHOOKS_TRAMPOLINE* g_pFreeList = NULL;
static DWORD g_nHooksInUse = 0;
static HANDLE* g_hThreadHandles = NULL;
static DWORD g_nThreadHandles = 0;
#define MHOOK_JMPSIZE 5
#define MHOOK_MINALLOCSIZE 4096

//=========================================================================
// Internal function:
//
// Remove the trampoline from the specified list, updating the head pointer
// if necessary.
//=========================================================================
static VOID ListRemove(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode) {
	if (pNode->pPrevTrampoline) {
		pNode->pPrevTrampoline->pNextTrampoline = pNode->pNextTrampoline;
	}

	if (pNode->pNextTrampoline) {
		pNode->pNextTrampoline->pPrevTrampoline = pNode->pPrevTrampoline;
	}

	if ((*pListHead) == pNode) {
		(*pListHead) = pNode->pNextTrampoline;
		if (*pListHead != NULL) {
			MHOOK_ASSERT((*pListHead)->pPrevTrampoline == NULL);
		}
	}

	pNode->pPrevTrampoline = NULL;
	pNode->pNextTrampoline = NULL;
}

//=========================================================================
// Internal function:
//
// Prepend the trampoline from the specified list and update the head pointer.
//=========================================================================
static VOID ListPrepend(MHOOKS_TRAMPOLINE** pListHead, MHOOKS_TRAMPOLINE* pNode) {
	pNode->pPrevTrampoline = NULL;
	pNode->pNextTrampoline = (*pListHead);
	if ((*pListHead)) {
		(*pListHead)->pPrevTrampoline = pNode;
	}
	(*pListHead) = pNode;
}

//=========================================================================
static VOID EnterCritSec() {
	if (!g_bVarsInitialized) {
		RtlInitializeCriticalSection(&g_cs);
		g_bVarsInitialized = TRUE;
	}
	RtlEnterCriticalSection(&g_cs);
}

//=========================================================================
static VOID LeaveCritSec() {
	RtlLeaveCriticalSection(&g_cs);
}

//=========================================================================
// Internal function:
//
// Skip over jumps that lead to the real function. Gets around import
// jump tables, etc.
//=========================================================================
static PBYTE SkipJumps(PBYTE pbCode) {
	PBYTE pbOrgCode = pbCode;
#ifdef _M_IX86_X64
#ifdef _M_IX86
	//mov edi,edi: hot patch point
	if (pbCode[0] == 0x8b && pbCode[1] == 0xff)
		pbCode += 2;
	// push ebp; mov ebp, esp; pop ebp;
	// "collapsed" stackframe generated by MSVC
	if (pbCode[0] == 0x55 && pbCode[1] == 0x8b && pbCode[2] == 0xec && pbCode[3] == 0x5d)
		pbCode += 4;
#endif
	if (pbCode[0] == 0xff && pbCode[1] == 0x25) {
#ifdef _M_IX86
		// on x86 we have an absolute pointer...
		PBYTE pbTarget = *(PBYTE *)&pbCode[2];
		// ... that shows us an absolute pointer.
		return SkipJumps(*(PBYTE *)pbTarget);
#elif defined _M_X64
		// on x64 we have a 32-bit offset...
		INT32 lOffset = *(INT32 *)&pbCode[2];
		// ... that shows us an absolute pointer
		return SkipJumps(*(PBYTE*)(pbCode + 6 + lOffset));
	} else if (pbCode[0] == 0x48 && pbCode[1] == 0xff && pbCode[2] == 0x25) {
		// or we can have the same with a REX prefix
		INT32 lOffset = *(INT32 *)&pbCode[3];
		// ... that shows us an absolute pointer
		return SkipJumps(*(PBYTE*)(pbCode + 7 + lOffset));
#endif
	} else if (pbCode[0] == 0xe9) {
		// here the behavior is identical, we have...
		// ...a 32-bit offset to the destination.
		return SkipJumps(pbCode + 5 + *(INT32 *)&pbCode[1]);
	} else if (pbCode[0] == 0xeb) {
		// and finally an 8-bit offset to the destination
		return SkipJumps(pbCode + 2 + *(CHAR *)&pbCode[1]);
	}
#else
#error unsupported platform
#endif
	return pbOrgCode;
}

//=========================================================================
// Internal function:
//
// Writes code at pbCode that jumps to pbJumpTo. Will attempt to do this
// in as few bytes as possible. Important on x64 where the long jump
// (0xff 0x25 ....) can take up 14 bytes.
//=========================================================================
static PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo) {
#ifdef _M_IX86_X64
	PBYTE pbJumpFrom = pbCode + 5;
	SIZE_T cbDiff = pbJumpFrom > pbJumpTo ? pbJumpFrom - pbJumpTo : pbJumpTo - pbJumpFrom;
	ODPRINTF(("mhooks: EmitJump: Jumping from %p to %p, diff is %p", pbJumpFrom, pbJumpTo, cbDiff));
	if (cbDiff <= 0x7fff0000) {
		pbCode[0] = 0xe9;
		pbCode += 1;
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbJumpTo - pbJumpFrom);
		pbCode += sizeof(DWORD);
	} else {
		pbCode[0] = 0xff;
		pbCode[1] = 0x25;
		pbCode += 2;
#ifdef _M_IX86
		// on x86 we write an absolute address (just behind the instruction)
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbCode + sizeof(DWORD));
#elif defined _M_X64
		// on x64 we write the relative address of the same location
		*((PDWORD)pbCode) = (DWORD)0;
#endif
		pbCode += sizeof(DWORD);
		*((PDWORD_PTR)pbCode) = (DWORD_PTR)(pbJumpTo);
		pbCode += sizeof(DWORD_PTR);
	}
#else
#error unsupported platform
#endif
	return pbCode;
}


//=========================================================================
// Internal function:
//
// Round down to the next multiple of rndDown
//=========================================================================
static size_t RoundDown(size_t addr, size_t rndDown)
{
	return (addr / rndDown) * rndDown;
}

//=========================================================================
// Internal function:
//
// Initalize the block as a doubly linked list.
//=========================================================================
static void InitBlock(MHOOKS_TRAMPOLINE* pBlock, const ptrdiff_t cAllocSize){
	size_t trampolineCount = cAllocSize / sizeof(MHOOKS_TRAMPOLINE);
	ODPRINTF(("mhooks: BlockAlloc: Allocated block at %p as %d trampolines", pBlock, trampolineCount));

	pBlock[0].pPrevTrampoline = NULL;
	pBlock[0].pNextTrampoline = &pBlock[1];

	// prepare them by having them point down the line at the next entry.
	for (size_t s = 1; s < trampolineCount; ++s) {
		pBlock[s].pPrevTrampoline = &pBlock[s - 1];
		pBlock[s].pNextTrampoline = &pBlock[s + 1];
	}

	// last entry points to the current head of the free list
	pBlock[trampolineCount - 1].pNextTrampoline = g_pFreeList;

	if (g_pFreeList) {
		g_pFreeList->pPrevTrampoline = &pBlock[trampolineCount - 1];
	}
}


//=========================================================================
// Internal function:
//
// Will attempt allocate a block of memory within the specified range, as
// near as possible to the specified function.
//=========================================================================
static MHOOKS_TRAMPOLINE* BlockAlloc(PBYTE pSystemFunction, PBYTE pbLower, PBYTE pbUpper) {
	static DWORD gs_dwAllocGran = 0;

	if (gs_dwAllocGran == 0) {
		SYSTEM_BASIC_INFORMATION sbi;
		RtlZeroMemory(&sbi, sizeof(sbi));
		NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), NULL);
		gs_dwAllocGran = sbi.AllocationGranularity;
	}

	// Always allocate in bulk, in case the system actually has a smaller allocation granularity than MINALLOCSIZE.
	const ptrdiff_t cAllocSize = max(gs_dwAllocGran, MHOOK_MINALLOCSIZE);

	MHOOKS_TRAMPOLINE* pRetVal = NULL;

	// Try to allocate directly, If target function is in 0x10000~0x80000000.
	if ( (ptrdiff_t)pbLower < 0x10000 ){
		PVOID base = NULL;
		SIZE_T sz = (SIZE_T)cAllocSize;
		NTSTATUS st = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &sz,
		                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(st)) {
			pRetVal = (MHOOKS_TRAMPOLINE*)base;
			if (pbLower < (PBYTE)pRetVal && (PBYTE)pRetVal < pbUpper) {
				InitBlock(pRetVal, cAllocSize);
				return pRetVal;
			}
			PVOID freeBase = pRetVal;
			SIZE_T freeSz = 0;
			NtFreeVirtualMemory(NtCurrentProcess(), &freeBase, &freeSz, MEM_RELEASE);
		}
	}

	pRetVal = NULL;

	PBYTE pModuleGuess = (PBYTE) RoundDown((size_t)pSystemFunction, cAllocSize);
	int loopCount = 0;

	ptrdiff_t spiral = 1;
	bool bSpiral = true;
	for (PBYTE pbAlloc = pModuleGuess;; ++loopCount) {

		if (pbLower < pbAlloc && pbAlloc < pbUpper) {
			// determine current state
			MEMORY_BASIC_INFORMATION mbi;
			ODPRINTF(("mhooks: BlockAlloc: Looking at address %p", pbAlloc));
			SIZE_T retLen = 0;
			if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), pbAlloc,
			        MemoryBasicInformation, &mbi, sizeof(mbi), &retLen)))
				break;
			// free & large enough?
			if (mbi.State == MEM_FREE && mbi.RegionSize >= (unsigned)cAllocSize) {
				// and then try to allocate it
				PVOID base = pbAlloc;
				SIZE_T sz = (SIZE_T)cAllocSize;
				NTSTATUS st = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &sz,
				                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (NT_SUCCESS(st)) {
					pRetVal = (MHOOKS_TRAMPOLINE*)base;
					InitBlock(pRetVal, cAllocSize);
					break;
				}
			}
		}
		else if (!bSpiral)
			break;

		ptrdiff_t bytesToOffset = cAllocSize;
		if (bSpiral) {
			if (pbLower < pbAlloc && pbAlloc < pbUpper){
				// This is a spiral, should be -1, 2, -3, 4, etc. (* cAllocSize)
				// -1 or 1
				spiral = ((loopCount % 2 == 0) ? -1 : 1);
			}
			else if ( pbLower < pbAlloc){
				bSpiral = false;
				spiral = -1;
			}
			else if ( pbAlloc < pbUpper){
				bSpiral = false;
				spiral = 1;
			}
			// 1, 2, 3, 4, etc. (* cAllocSize)
			bytesToOffset = (cAllocSize * (loopCount+1));
		}
		// maybe a spiral, -1, 2, -3, 4, etc. (* cAllocSize) or just right or left
		pbAlloc = pbAlloc + bytesToOffset * spiral;
	}

	return pRetVal;
}

//=========================================================================
// Internal function:
//
// Will try to find a trampoline entry from free list inside the required range.
//=========================================================================
static MHOOKS_TRAMPOLINE* FindTrampolineInRange(PBYTE pLower, PBYTE pUpper) {
	if (!g_pFreeList) {
		return NULL;
	}

	// This is a standard free list, except we're doubly linked to deal with some return shenanigans.
	MHOOKS_TRAMPOLINE* curEntry = g_pFreeList;
	while (curEntry) {
		if ((MHOOKS_TRAMPOLINE*) pLower < curEntry && curEntry < (MHOOKS_TRAMPOLINE*) pUpper) {
			ListRemove(&g_pFreeList, curEntry);

			return curEntry;
		}

		curEntry = curEntry->pNextTrampoline;
	}

	return NULL;
}

//=========================================================================
// Internal function:
//
// Will try to allocate the trampoline structure within 2 gigabytes of
// the target function.
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineAlloc(PBYTE pSystemFunction, S64 nLimitUp, S64 nLimitDown) {

	MHOOKS_TRAMPOLINE* pTrampoline = NULL;

	// determine lower and upper bounds for the allocation locations.
	// in the basic scenario this is +/- 2GB but IP-relative instructions
	// found in the original code may require a smaller window.
	PBYTE pLower = pSystemFunction + nLimitUp;
	pLower = pLower < (PBYTE)(DWORD_PTR)0x0000000080000000 ?
						(PBYTE)(0x1) : (PBYTE)(pLower - (PBYTE)0x7fff0000);
	PBYTE pUpper = pSystemFunction + nLimitDown;
	pUpper = pUpper < (PBYTE)(DWORD_PTR)0xffffffff80000000 ?
		(PBYTE)(pUpper + (DWORD_PTR)0x7ff80000) : (PBYTE)(DWORD_PTR)0xfffffffffff80000;
	ODPRINTF(("mhooks: TrampolineAlloc: Allocating for %p between %p and %p", pSystemFunction, pLower, pUpper));

	// try to find a trampoline in the specified range
	pTrampoline = FindTrampolineInRange(pLower, pUpper);
	if (!pTrampoline) {
		// if it we can't find it, then we need to allocate a new block and
		// try again. Just fail if that doesn't work
		g_pFreeList = BlockAlloc(pSystemFunction, pLower, pUpper);
		pTrampoline = FindTrampolineInRange(pLower, pUpper);
	}

	// found and allocated a trampoline?
	if (pTrampoline) {
		ListPrepend(&g_pHooks, pTrampoline);
	}

	return pTrampoline;
}

//=========================================================================
// Internal function:
//
// Return the internal trampoline structure that belongs to a hooked function.
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineGet(PBYTE pHookedFunction) {
	MHOOKS_TRAMPOLINE* pCurrent = g_pHooks;

	while (pCurrent) {
		if ((PBYTE)&(pCurrent->codeTrampoline) == pHookedFunction) {
			return pCurrent;
		}

		pCurrent = pCurrent->pNextTrampoline;
	}

	return NULL;
}

//=========================================================================
// Internal function:
//
// Free a trampoline structure.
//=========================================================================
static VOID TrampolineFree(MHOOKS_TRAMPOLINE* pTrampoline, BOOL bNeverUsed) {
	ListRemove(&g_pHooks, pTrampoline);
	g_nHooksInUse--;

	// If a thread could feasibly have some of our trampoline code
	// on its stack and we yank the region from underneath it then it will
	// surely crash upon returning. So instead of freeing the
	// memory we just let it leak. Ugly, but safe.
	if (bNeverUsed) {
		//VirtualFree(pTrampoline, 0, MEM_RELEASE);
		return;
	}

	ListPrepend(&g_pFreeList, pTrampoline);
}

//=========================================================================
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.  Takes ownership of hThread on
// success; closes it and returns FALSE on failure.
//=========================================================================
static BOOL SuspendOneThread(HANDLE hThread, PBYTE pbCode, DWORD cbBytes) {
	ULONG dwSuspendCount = 0;
	NTSTATUS st = NtSuspendThread(hThread, &dwSuspendCount);
	if (NT_SUCCESS(st)) {
		// see where the IP is
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		int nTries = 0;
		while (NT_SUCCESS(NtGetContextThread(hThread, &ctx))) {
#ifdef _M_IX86
			PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
			PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
			if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
				if (nTries < 3) {
					// oops - we should try to get the instruction pointer out of here.
					ODPRINTF(("mhooks: SuspendOneThread: suspended thread - IP is colliding with code, retrying"));
					NtResumeThread(hThread, &dwSuspendCount);
					// brief delay before re-suspending
					LARGE_INTEGER delay;
					delay.QuadPart = -1000000LL; // 100 ms
					NtDelayExecution(FALSE, &delay);
					NtSuspendThread(hThread, &dwSuspendCount);
					nTries++;
				} else {
					// gave it all we could
					ODPRINTF(("mhooks: SuspendOneThread: IP collision unresolvable, giving up on this thread"));
					NtResumeThread(hThread, &dwSuspendCount);
					NtClose(hThread);
					return FALSE;
				}
			} else {
				// success, the IP is not conflicting
				ODPRINTF(("mhooks: SuspendOneThread: successfully suspended thread, IP at %p", pIp));
				return TRUE;
			}
		}
	}
	// couldn't suspend
	NtClose(hThread);
	return FALSE;
}

//=========================================================================
// Internal function:
//
// Resumes all previously suspended threads in the current process.
//=========================================================================
static VOID ResumeOtherThreads() {
	// make sure things go as fast as possible
	THREAD_BASIC_INFORMATION tbi;
	RtlZeroMemory(&tbi, sizeof(tbi));
	NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
	KPRIORITY origPriority = tbi.Priority;
	KPRIORITY hiPri = (KPRIORITY)THREAD_PRIORITY_TIME_CRITICAL;
	NtSetInformationThread(NtCurrentThread(), ThreadBasePriority, &hiPri, sizeof(hiPri));
	// go through our list
	for (DWORD i = 0; i < g_nThreadHandles; i++) {
		// resume & close thread handles
		ULONG prevCount = 0;
		NtResumeThread(g_hThreadHandles[i], &prevCount);
		NtClose(g_hThreadHandles[i]);
	}
	// clean up
	mhook_free(g_hThreadHandles);
	g_hThreadHandles = NULL;
	g_nThreadHandles = 0;
	NtSetInformationThread(NtCurrentThread(), ThreadBasePriority, &origPriority, sizeof(origPriority));
}

//=========================================================================
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their
// instruction pointer is not in the given range.
//=========================================================================
static BOOL SuspendOtherThreads(PBYTE pbCode, DWORD cbBytes) {
	BOOL bRet = FALSE;

	// make sure we're the most important thread in the process
	THREAD_BASIC_INFORMATION tbi;
	RtlZeroMemory(&tbi, sizeof(tbi));
	NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
	KPRIORITY origPriority = tbi.Priority;
	KPRIORITY hiPri = (KPRIORITY)THREAD_PRIORITY_TIME_CRITICAL;
	NtSetInformationThread(NtCurrentThread(), ThreadBasePriority, &hiPri, sizeof(hiPri));

	// Walk all threads in this process using NtGetNextThread.
	// NtGetNextThread returns a new handle to the next thread; we close the
	// previous handle after each successful call.
	HANDLE hCur = NULL;
	HANDLE hNext = NULL;
	ULONG nAllocated = 0;
	BOOL bFailed = FALSE;

	while (NT_SUCCESS(NtGetNextThread(NtCurrentProcess(), hCur,
	        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
	        THREAD_SET_CONTEXT   | THREAD_QUERY_INFORMATION,
	        0, 0, &hNext)))
	{
		// close the handle from the previous iteration (not needed after getting hNext)
		if (hCur != NULL)
			NtClose(hCur);
		hCur = hNext;

		// skip ourselves
		RtlZeroMemory(&tbi, sizeof(tbi));
		NtQueryInformationThread(hCur, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
		if (tbi.ClientId.UniqueThread == NtCurrentClientId().UniqueThread)
			continue;

		// grow the handle array if needed
		if (g_nThreadHandles >= nAllocated) {
			ULONG nNew = nAllocated ? nAllocated * 2 : 8;
			HANDLE* pNew = (HANDLE*)RtlReAllocateHeap(RtlProcessHeap(), 0,
			                   g_hThreadHandles, nNew * sizeof(HANDLE));
			if (!pNew) {
				ODPRINTF(("mhooks: SuspendOtherThreads: allocation failure"));
				bFailed = TRUE;
				break;
			}
			g_hThreadHandles = pNew;
			nAllocated = nNew;
		}

		// attempt to suspend; SuspendOneThread takes ownership of hCur on success
		if (SuspendOneThread(hCur, pbCode, cbBytes)) {
			ODPRINTF(("mhooks: SuspendOtherThreads: suspended thread %p", tbi.ClientId.UniqueThread));
			g_hThreadHandles[g_nThreadHandles++] = hCur;
			hCur = NULL; // ownership transferred; don't close on next iteration
		} else {
			ODPRINTF(("mhooks: SuspendOtherThreads: failed to suspend thread %p", tbi.ClientId.UniqueThread));
			// SuspendOneThread already closed hCur on failure
			hCur = NULL;
		}
	}

	// close the last handle if it wasn't transferred or wasn't NULL
	if (hCur != NULL)
		NtClose(hCur);

	bRet = !bFailed;

	NtSetInformationThread(NtCurrentThread(), ThreadBasePriority, &origPriority, sizeof(origPriority));

	if (!bRet) {
		ODPRINTF(("mhooks: SuspendOtherThreads: problem suspending threads, resuming all."));
		ResumeOtherThreads();
	}
	return bRet;
}

//=========================================================================
// if IP-relative addressing has been detected, fix up the code so the
// offset points to the original location
// return a extended code length after fixup
static DWORD FixupIPRelativeAddressing(PBYTE pbNew, PBYTE pbOriginal, MHOOKS_PATCHDATA* pdata)
{
	DWORD dwRet = 0;

	S64 diff = pbNew - pbOriginal;
	for (DWORD i = 0; i < pdata->nRipCnt; i++) {
		MHOOKS_RIPINFO rip = pdata->rips[i];

		DWORD dwNewDisplacement = (DWORD)(rip.nDisplacement - diff);

		if (rip.dwInstructionLength > rip.dwOldInstructionLength){

			DWORD dwExtend = rip.dwInstructionOffset + rip.dwInstructionLength - rip.dwOldInstructionOffset - rip.dwOldInstructionLength;

			// move other instructions backward
			for (int j = MHOOKS_MAX_CODE_BYTES - 1; j >= rip.dwInstructionOffset + rip.dwOldInstructionLength + dwExtend; j--){
				pbNew[j] = pbNew[j - dwExtend];
			}
			// fixing up instruction
			for (int p = 0; p < rip.dwInstructionLength; p++){
				*PBYTE(pbNew+rip.dwInstructionOffset+p) = rip.pbInstruction[p];
			}

			// fixing up RIP instruction operand
			dwNewDisplacement -= dwExtend;

			dwRet += rip.dwInstructionLength - rip.dwOldInstructionLength;
		}

		ODPRINTF(("mhooks: fixing up RIP instruction operand for code at %p: "
			"old displacement: 0x%8.8x, new displacement: 0x%8.8x",
			pbNew + rip.dwInstructionOffset + rip.dwOffset,
			(DWORD)rip.nDisplacement,
			dwNewDisplacement));

		*(PDWORD)(pbNew + rip.dwInstructionOffset + rip.dwOffset) = dwNewDisplacement;
	}

	return dwRet;
}

//=========================================================================
// Examine the machine code at the target function's entry point, and
// skip bytes in a way that we'll always end on an instruction boundary.
// We also detect branches and subroutine calls (as well as returns)
// at which point disassembly must stop.
// Finally, detect and collect information on IP-relative instructions
// that we can patch.
static DWORD DisassembleAndSkip(PVOID pFunction, DWORD dwMinLen, MHOOKS_PATCHDATA* pdata) {
	DWORD dwRet = 0;
	DWORD dwInsLength = 0;

	pdata->nLimitDown = 0;
	pdata->nLimitUp = 0;
	pdata->nRipCnt = 0;
#ifdef _M_IX86
	ARCHITECTURE_TYPE arch = ARCH_X86;
#elif defined _M_X64
	ARCHITECTURE_TYPE arch = ARCH_X64;
#else
	#error unsupported platform
#endif
	DISASSEMBLER dis;
	if (InitDisassembler(&dis, arch)) {
		INSTRUCTION* pins = NULL;
		U8* pLoc = (U8*)pFunction;
		DWORD dwFlags = DISASM_DECODE | DISASM_DISASSEMBLE | DISASM_ALIGNOUTPUT;

		ODPRINTF(("mhooks: DisassembleAndSkip: Disassembling %p", pLoc));
		while ( (dwRet < dwMinLen) && (pins = GetInstruction(&dis, (ULONG_PTR)pLoc, pLoc, dwFlags)) ) {
			ODPRINTF(("mhooks: DisassembleAndSkip: %p:(0x%2.2x) %s", pLoc, pins->Length, pins->String));
			if (pins->Type == ITYPE_RET		) break;
			if (pins->Type == ITYPE_CALLCC	) break;

			BOOL bProcessRip = FALSE;
			// call to rip+imm32 or eip+imm32
			if ((pins->Type == ITYPE_CALL) && (pins->X86.Relative) &&
				(pins->OperandCount == 1) && (pins->Operands[0].Flags & OP_IPREL) &&
				((pins->Operands[0].Register == AMD64_REG_RIP) || (pins->Operands[0].Register == X86_REG_EIP)))
			{
				// rip-addressing "call [rip+imm32]"
				bProcessRip = TRUE;
			}
			// jmp to rip+imm32 or eip+imm32
			else if ((pins->Type == ITYPE_BRANCH) && (pins->X86.Relative) &&
				(pins->OperandCount == 1) && (pins->Operands[0].Flags & OP_IPREL) &&
				((pins->Operands[0].Register == AMD64_REG_RIP) || (pins->Operands[0].Register == X86_REG_EIP)))
			{
				// rip-addressing  "jmp [rip+imm32]"
				bProcessRip = TRUE;
			}
			else if ((pins->Type == ITYPE_BRANCHCC) && (pins->X86.Relative) &&
				(pins->OperandCount == 1) && (pins->Operands[0].Flags & OP_IPREL) &&
				((pins->Operands[0].Register == AMD64_REG_RIP) || (pins->Operands[0].Register == X86_REG_EIP)))
			{
				bProcessRip = TRUE;
			}
#if defined _M_X64
			// mov or lea to register from rip+imm32
			else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) &&
				(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
				(pins->Operands[1].Flags & OP_IPREL) && (pins->Operands[1].Register == AMD64_REG_RIP))
			{
				// rip-addressing "mov reg, [rip+imm32]"
				bProcessRip = TRUE;
			}
			// mov or lea to rip+imm32 from register
			else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) &&
				(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
				(pins->Operands[0].Flags & OP_IPREL) && (pins->Operands[0].Register == AMD64_REG_RIP))
			{
				// rip-addressing "mov [rip+imm32], reg"
				bProcessRip = TRUE;
			}
#endif
			else if ( (pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL) )
			{
				// unsupported rip-addressing
				ODPRINTF(("mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 0));
				for (DWORD i=0; i<pins->Length; i++) {
					ODPRINTF(("mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]));
				}
				break;
			}
			else if ( (pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL) )
			{
				// unsupported rip-addressing
				ODPRINTF(("mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 1));
				for (DWORD i=0; i<pins->Length; i++) {
					ODPRINTF(("mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]));
				}
				break;
			}
			else if ( (pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL) )
			{
				// unsupported rip-addressing
				ODPRINTF(("mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 2));
				for (DWORD i=0; i<pins->Length; i++) {
					ODPRINTF(("mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]));
				}
				break;
			}

			DWORD dwInstructionLength = pins->Length;
			// follow through with RIP-processing if needed
			if (bProcessRip) {
				// calculate displacement relative to this instruction start
				int nDisplacementPos = pins->PrefixCount + pins->OpcodeLength + pins->X86.HasModRM + (pins->X86.sib_b == 0?0:1);
				ODPRINTF(("mhooks: DisassembleAndSkip: found OP_IPREL with displacement 0x%x (in memory: 0x%x)", pins->X86.Displacement, *(PDWORD)(pLoc + nDisplacementPos)));
				// calculate displacement relative to function start
				S64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
				// store displacement values furthest from zero (both positive and negative)
				if (nAdjustedDisplacement < pdata->nLimitDown)
					pdata->nLimitDown = nAdjustedDisplacement;
				if (nAdjustedDisplacement > pdata->nLimitUp)
					pdata->nLimitUp = nAdjustedDisplacement;
				// store patch info
				if (pdata->nRipCnt < MHOOKS_MAX_RIPS) {

					pdata->rips[pdata->nRipCnt].dwOffset = nDisplacementPos;
					pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;

					pdata->rips[pdata->nRipCnt].dwOldInstructionOffset = dwRet;
					pdata->rips[pdata->nRipCnt].dwOldInstructionLength = pins->Length;

					pdata->rips[pdata->nRipCnt].dwInstructionOffset = dwInsLength;
					pdata->rips[pdata->nRipCnt].dwInstructionLength = pins->Length;

					// short condition jmp
					if (pins->Type == ITYPE_BRANCHCC && pins->Length == 2){
						// jne jnz
						if ( pins->OpcodeAddress[0] == 0x75 ){
							// store a new instruction to replace the old one
							pdata->rips[pdata->nRipCnt].dwInstructionLength = 6;
							// a new Displacement offset in new instruction
							pdata->rips[pdata->nRipCnt].dwOffset = 2;
							BYTE tmp[6] = {0x0F, 0x85, 0};
							for(int i=0; i < MAX_OPCODE_LENGTH; i++){
								pdata->rips[pdata->nRipCnt].pbInstruction[i] = tmp[i];
							}
						}
						else
							// todo unsupport short condition jmp for now
							break;
					}
					// short uncondition jmp
					else if (pins->Type == ITYPE_BRANCH && pins->Length == 2){
						// jmp
						if (pins->OpcodeAddress[0] == 0xEB){
							// store a new instruction to replace the old one
							pdata->rips[pdata->nRipCnt].dwInstructionLength = 5;
							// a new Displacement offset in new instruction
							pdata->rips[pdata->nRipCnt].dwOffset = 1;
							BYTE tmp[5] = {0xE9, 0};
							for(int i=0; i < MAX_OPCODE_LENGTH; i++){
								pdata->rips[pdata->nRipCnt].pbInstruction[i] = tmp[i];
							}
						}
						else
							// todo unsupport short uncondition jmp for now
							break;
					}

					dwInstructionLength = pdata->rips[pdata->nRipCnt].dwInstructionLength;

					pdata->nRipCnt++;
				}
				else {
					// no room for patch info, stop disassembly
					break;
				}
			}

			dwInsLength += dwInstructionLength;

			dwRet += pins->Length;
			pLoc  += pins->Length;
		}

		CloseDisassembler(&dis);
	}

	return dwRet;
}

//=========================================================================
extern "C" BOOL Mhook_SetHook(PVOID *ppSystemFunction, PVOID pHookFunction) {
	MHOOKS_TRAMPOLINE* pTrampoline = NULL;
	PVOID pSystemFunction = *ppSystemFunction;
	// ensure thread-safety
	EnterCritSec();
	ODPRINTF(("mhooks: Mhook_SetHook: Started on the job: %p / %p", pSystemFunction, pHookFunction));
	// find the real functions (jump over jump tables, if any)
	pSystemFunction = SkipJumps((PBYTE)pSystemFunction);
	pHookFunction   = SkipJumps((PBYTE)pHookFunction);
	ODPRINTF(("mhooks: Mhook_SetHook: After SkipJumps: %p / %p", pSystemFunction, pHookFunction));
	// figure out the length of the overwrite zone
	MHOOKS_PATCHDATA patchdata = {0};
	DWORD dwInstructionLength = DisassembleAndSkip(pSystemFunction, MHOOK_JMPSIZE, &patchdata);
	if (dwInstructionLength >= MHOOK_JMPSIZE) {
		ODPRINTF(("mhooks: Mhook_SetHook: disassembly signals %d bytes", dwInstructionLength));
		// suspend every other thread in this process, and make sure their IP
		// is not in the code we're about to overwrite.
		SuspendOtherThreads((PBYTE)pSystemFunction, dwInstructionLength);
		// allocate a trampoline structure
		pTrampoline = TrampolineAlloc((PBYTE)pSystemFunction, patchdata.nLimitUp, patchdata.nLimitDown);
		if (pTrampoline) {
			ODPRINTF(("mhooks: Mhook_SetHook: allocated structure at %p", pTrampoline));
			ULONG dwOldProtectSystemFunction = 0;
			ULONG dwOldProtectTrampolineFunction = 0;
			// set the system function to PAGE_EXECUTE_READWRITE
			PVOID sysBase = pSystemFunction; SIZE_T sysSz = dwInstructionLength;
			if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &sysBase, &sysSz,
			        PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction))) {
				ODPRINTF(("mhooks: Mhook_SetHook: readwrite set on system function"));
				// mark our trampoline buffer to PAGE_EXECUTE_READWRITE
				PVOID tramBase = pTrampoline; SIZE_T tramSz = sizeof(MHOOKS_TRAMPOLINE);
				if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &tramBase, &tramSz,
				        PAGE_EXECUTE_READWRITE, &dwOldProtectTrampolineFunction))) {
					ODPRINTF(("mhooks: Mhook_SetHook: readwrite set on trampoline structure"));

					// create our trampoline function
					PBYTE pbCode = pTrampoline->codeTrampoline;
					// save original code..
					for (DWORD i = 0; i<dwInstructionLength; i++) {
						pTrampoline->codeUntouched[i] = pbCode[i] = ((PBYTE)pSystemFunction)[i];
					}

					pbCode += dwInstructionLength;
					// fix up any IP-relative addressing in the code
					pbCode += FixupIPRelativeAddressing(pTrampoline->codeTrampoline, (PBYTE)pSystemFunction, &patchdata);

					// plus a jump to the continuation in the original location
					pbCode = EmitJump(pbCode, ((PBYTE)pSystemFunction) + dwInstructionLength);
					ODPRINTF(("mhooks: Mhook_SetHook: updated the trampoline"));

					DWORD_PTR dwDistance = (PBYTE)pHookFunction < (PBYTE)pSystemFunction ?
						(PBYTE)pSystemFunction - (PBYTE)pHookFunction : (PBYTE)pHookFunction - (PBYTE)pSystemFunction;
					if (dwDistance > 0x7fff0000) {
						// create a stub that jumps to the replacement function.
						pbCode = pTrampoline->codeJumpToHookFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
						ODPRINTF(("mhooks: Mhook_SetHook: created reverse trampoline"));
						NtFlushInstructionCache(NtCurrentProcess(), pTrampoline->codeJumpToHookFunction,
							pbCode - pTrampoline->codeJumpToHookFunction);

						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, pTrampoline->codeJumpToHookFunction);
					} else {
						// the jump will be at most 5 bytes so we can do it directly
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
					}

					// update data members
					pTrampoline->cbOverwrittenCode = dwInstructionLength;
					pTrampoline->pSystemFunction = (PBYTE)pSystemFunction;
					pTrampoline->pHookFunction = (PBYTE)pHookFunction;

					// flush instruction cache and restore original protection
					NtFlushInstructionCache(NtCurrentProcess(), pTrampoline->codeTrampoline, dwInstructionLength);
					tramBase = pTrampoline; tramSz = sizeof(MHOOKS_TRAMPOLINE);
					NtProtectVirtualMemory(NtCurrentProcess(), &tramBase, &tramSz,
					    dwOldProtectTrampolineFunction, &dwOldProtectTrampolineFunction);
				} else {
					ODPRINTF(("mhooks: Mhook_SetHook: failed NtProtectVirtualMemory on trampoline"));
				}
				// flush instruction cache and restore original protection
				NtFlushInstructionCache(NtCurrentProcess(), pSystemFunction, dwInstructionLength);
				sysBase = pSystemFunction; sysSz = dwInstructionLength;
				NtProtectVirtualMemory(NtCurrentProcess(), &sysBase, &sysSz,
				    dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			} else {
				ODPRINTF(("mhooks: Mhook_SetHook: failed NtProtectVirtualMemory on system function"));
			}
			if (pTrampoline->pSystemFunction) {
				// this is what the application will use as the entry point
				// to the "original" unhooked function.
				*ppSystemFunction = pTrampoline->codeTrampoline;
				ODPRINTF(("mhooks: Mhook_SetHook: Hooked the function!"));
			} else {
				// if we failed discard the trampoline (forcing VirtualFree)
				TrampolineFree(pTrampoline, TRUE);
				pTrampoline = NULL;
			}
		}
		// resume everybody else
		ResumeOtherThreads();
	} else {
		ODPRINTF(("mhooks: disassembly signals %d bytes (unacceptable)", dwInstructionLength));
	}
	LeaveCritSec();
	return (pTrampoline != NULL);
}

//=========================================================================
extern "C" BOOL Mhook_Unhook(PVOID *ppHookedFunction) {
	ODPRINTF(("mhooks: Mhook_Unhook: %p", *ppHookedFunction));
	BOOL bRet = FALSE;
	EnterCritSec();
	// get the trampoline structure that corresponds to our function
	MHOOKS_TRAMPOLINE* pTrampoline = TrampolineGet((PBYTE)*ppHookedFunction);
	if (pTrampoline) {
		// make sure nobody's executing code where we're about to overwrite a few bytes
		SuspendOtherThreads(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
		ODPRINTF(("mhooks: Mhook_Unhook: found struct at %p", pTrampoline));
		ULONG dwOldProtectSystemFunction = 0;
		// make memory writable
		PVOID sysBase = pTrampoline->pSystemFunction; SIZE_T sysSz = pTrampoline->cbOverwrittenCode;
		if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &sysBase, &sysSz,
		        PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction))) {
			ODPRINTF(("mhooks: Mhook_Unhook: readwrite set on system function"));
			PBYTE pbCode = (PBYTE)pTrampoline->pSystemFunction;
			for (DWORD i = 0; i<pTrampoline->cbOverwrittenCode; i++) {
				pbCode[i] = pTrampoline->codeUntouched[i];
			}
			// flush instruction cache and make memory unwritable
			NtFlushInstructionCache(NtCurrentProcess(), pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
			sysBase = pTrampoline->pSystemFunction; sysSz = pTrampoline->cbOverwrittenCode;
			NtProtectVirtualMemory(NtCurrentProcess(), &sysBase, &sysSz,
			    dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			// return the original function pointer
			*ppHookedFunction = pTrampoline->pSystemFunction;
			bRet = TRUE;
			ODPRINTF(("mhooks: Mhook_Unhook: sysfunc: %p", *ppHookedFunction));
			// free the trampoline while not really discarding it from memory
			TrampolineFree(pTrampoline, FALSE);
			ODPRINTF(("mhooks: Mhook_Unhook: unhook successful"));
		} else {
			ODPRINTF(("mhooks: Mhook_Unhook: failed NtProtectVirtualMemory"));
		}
		// make the other guys runnable
		ResumeOtherThreads();
	}
	LeaveCritSec();
	return bRet;
}

//=========================================================================
