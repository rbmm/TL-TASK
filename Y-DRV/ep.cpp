#include "stdafx.h"

//NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ ULONG_PTR Size, _Out_opt_ void** ppv);
extern const UCHAR SC_begin[], SC_end[], DLL_begin[], DLL_end[];

#ifdef _WIN64
extern const UCHAR SCx86_begin[], SCx86_end[], DLLx86_begin[], DLLx86_end[];
#endif // _WIN64


_NT_BEGIN

#include "api.h"

EXTERN_C { PDRIVER_OBJECT _G_DriverObject; }

// #define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

VOID CALLBACK RundownRoutine(PKAPC)ASM_FUNCTION;
VOID CALLBACK KernelRoutine(PKAPC, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*)ASM_FUNCTION;
VOID CALLBACK NormalRoutine(PVOID, PVOID, PVOID)ASM_FUNCTION;

VOID CALLBACK _RundownRoutine(PKAPC Apc)
{
	CPP_FUNCTION;

	DbgPrint("--Apc<%p>\n", Apc);
	delete Apc;
}

VOID CALLBACK _KernelRoutine(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	CPP_FUNCTION;

	struct BR {
		PVOID BaseAddress;
		SIZE_T RegionSize;
	};

	PVOID BaseAddress = *NormalContext;
	NTSTATUS status;

	DbgPrint("KernelRoutine<%p>(%x %p)\n", Apc, Apc->ApcMode, BaseAddress);

	if (KernelMode == Apc->ApcMode)
	{
		ObfReferenceObject(_G_DriverObject);//NormalRoutine will be called
		return;
	}

	*NormalRoutine = 0;
	*NormalContext = 0;

	if (_TEB* teb = (_TEB*)PsGetCurrentThreadTeb())
	{
		union {
			PWSTR buf;
			BR* pup;
		};

		buf = teb->StaticUnicodeBuffer;
		pup->BaseAddress = BaseAddress;

		struct GR 
		{
			BOOL _M_bApc = APC_LEVEL == KeGetCurrentIrql();

			GR()
			{
				if (_M_bApc)
				{
					KeEnterCriticalRegion();
					KeEnterGuardedRegion();
					KeLowerIrql(PASSIVE_LEVEL);
					DbgPrint("%s\n", __FUNCTION__);
				}
			}

			~GR()
			{
				if (_M_bApc)
				{
					DbgPrint("%s\n", __FUNCTION__);
					KfRaiseIrql(APC_LEVEL);
					KeLeaveGuardedRegion();
					KeLeaveCriticalRegion();
				}
			}
		} _;

		if (BaseAddress)
		{
			pup->RegionSize = 0;
			status = NtFreeVirtualMemory(NtCurrentProcess(), &pup->BaseAddress, &pup->RegionSize, MEM_RELEASE);
			DbgPrint("Free(%p)=%x\n", BaseAddress, status);
		}
		else
		{
			const void* pv = 0;
			SIZE_T cb = 0, ep = 0, s = 0;

#ifdef _WIN64

			BOOL bWow = FALSE;
			PEPROCESS Process = IoGetCurrentProcess();

			if (PsGetProcessWow64Process(Process))
			{
				DbgPrint("wow: %x\n", PsWow64GetProcessMachine(Process));

				if (IMAGE_FILE_MACHINE_I386 == PsWow64GetProcessMachine(Process))
				{
					pv = DLLx86_begin;
					cb = SCx86_end - DLLx86_begin, ep = SCx86_begin - DLLx86_begin, s = DLLx86_end - DLLx86_begin;
					bWow = TRUE;
				}
			}
			else
#endif // _WIN64
			{
				pv = DLL_begin;
				cb = SC_end - DLL_begin, ep = SC_begin - DLL_begin, s = DLL_end - DLL_begin;
			}

			if (pv)
			{
				pup->RegionSize = cb;

				if (0 <= (status = NtAllocateVirtualMemory(NtCurrentProcess(),
					&pup->BaseAddress, 0, &pup->RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
				{
					__try
					{
						memcpy(BaseAddress = pup->BaseAddress, pv, cb);
						*NormalRoutine = (PKNORMAL_ROUTINE)RtlOffsetToPointer(BaseAddress, ep);
						*NormalContext = BaseAddress;
						*SystemArgument1 = (PVOID)s;
						*SystemArgument2 = 0;
						DbgPrint("<%p>:Routine(%p, %p)\n", Apc, BaseAddress, *NormalRoutine);

#ifdef _WIN64
						if (bWow) PsWrapApcWow64Thread(NormalContext, (void**)NormalRoutine);
#endif // _WIN64

						KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment,
							KernelRoutine, RundownRoutine, NT::NormalRoutine, UserMode, BaseAddress);

						ObfReferenceObject(_G_DriverObject);

						if (KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT))
						{
							return;
						}

						ObfDereferenceObject(_G_DriverObject);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						NtFreeVirtualMemory(NtCurrentProcess(), &pup->BaseAddress, &pup->RegionSize, MEM_RELEASE);
					}
				}
			}
		}
	}

	_RundownRoutine(Apc);
}

VOID CALLBACK _NormalRoutine(PKAPC Apc, PVOID , BOOL )
{
	CPP_FUNCTION;

	DbgPrint("NormalRoutine(%p)\n", Apc);

	BOOL bLast;
	if (0 <= ZwQueryInformationThread(NtCurrentThread(), ThreadAmILastThread, &bLast, sizeof(bLast), 0) && bLast)
	{
		DbgPrint("++Process(%p)\n", PsGetCurrentProcessId());

		KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment,
			KernelRoutine, RundownRoutine, NormalRoutine, UserMode, 0);

		ObfReferenceObject(_G_DriverObject);

		if (KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT))
		{
			return;
		}

		ObfDereferenceObject(_G_DriverObject);

	}
	// delete Apc; 
	_RundownRoutine(Apc);
}

BOOLEAN IsTargetProcess(PEPROCESS Process)
{
	return PsIsProcessBeingDebugged(Process) || !_stricmp("notepad.exe", PsGetProcessImageFileName(Process));
}

VOID NTAPI CreateThreadNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	)
{
	if (Create)
	{
		//DbgPrint("CreateThreadNotifyRoutine(%p, %p)\n", ProcessId, ThreadId);

		CLIENT_ID cid = { ProcessId, ThreadId };
		PEPROCESS Process;
		PETHREAD Thread;
		if (0 <= PsLookupProcessThreadByCid(&cid, &Process, &Thread))
		{
			if (IsTargetProcess(Process))
			{
				if (PKAPC Apc = new(NonPagedPool) KAPC)
				{
					KeInitializeApc(Apc, Thread, OriginalApcEnvironment,
						KernelRoutine, RundownRoutine, NormalRoutine, KernelMode, Apc);

					DbgPrint("++Apc<%p> \n", Apc);

					ObfReferenceObject(_G_DriverObject);

					if (!KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT))
					{
						RundownRoutine(Apc);
					}
				}
			}
			ObfDereferenceObject(Thread);
			ObfDereferenceObject(Process);
		}
	}
}

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);

	DbgPrint("DriverUnload(%p)\n", DriverObject);
}

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("DriverLoad(%p, %wZ)\n", DriverObject, RegistryPath);

#if 0
	HANDLE hKey;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, RegistryPath, OBJ_CASE_INSENSITIVE };
	if (0 <= ZwOpenKey(&hKey, KEY_WRITE, &oa))
	{
		STATIC_UNICODE_STRING_(Start);
		ULONG s = 3;
		ZwSetValueKey(hKey, &Start, 0, REG_DWORD, &s, sizeof(s));
		NtClose(hKey);
	}
#endif

	_G_DriverObject = DriverObject;

	DriverObject->DriverUnload = DriverUnload;

	return PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
}

_NT_END