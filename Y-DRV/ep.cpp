#include "stdafx.h"

//NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ ULONG_PTR Size, _Out_opt_ void** ppv);
extern const UCHAR SC_begin[], SC_end[], DLL_begin[], DLL_end[];
extern const UCHAR SCx86_begin[], SCx86_end[], DLLx86_begin[], DLLx86_end[];

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

	PVOID BaseAddress = *NormalContext;
	SIZE_T RegionSize = 0;
	NTSTATUS status;

	DbgPrint("Apc<%p>(%p)\n", Apc, BaseAddress);

	*NormalRoutine = 0;
	*NormalContext = 0;

	if (BaseAddress)
	{
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
		DbgPrint("Free(%p)=%x\n", BaseAddress, status);
	}
	else
	{
		const void* pv = 0;
		SIZE_T cb = 0, ep = 0, s = 0;

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
		{
			pv = DLL_begin;
			cb = SC_end - DLL_begin, ep = SC_begin - DLL_begin, s = DLL_end - DLL_begin;
		}

		if (pv)
		{
			if (0 <= (status = ZwAllocateVirtualMemory(NtCurrentProcess(), 
				&(BaseAddress = 0), 0, &(RegionSize = cb), MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			{
				__try
				{
					memcpy(BaseAddress, pv, cb);
					*NormalRoutine = (PKNORMAL_ROUTINE)RtlOffsetToPointer(BaseAddress, ep);
					*NormalContext = BaseAddress;
					*SystemArgument1 = (PVOID)s;
					*SystemArgument2 = 0;
					DbgPrint("<%p>:Routine(%p, %p)\n", Apc, BaseAddress, *NormalRoutine);

					if (bWow) PsWrapApcWow64Thread(NormalContext, (void**)NormalRoutine);

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
					ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
				}
			}
		}
	}

	_RundownRoutine(Apc);
}

VOID CALLBACK _NormalRoutine(PKAPC Apc, PVOID Section, BOOL bWow)
{
	CPP_FUNCTION;

	DbgPrint("NormalRoutine(%p, %p, %p)\n", Apc, Section, bWow);

	// delete Apc; 
	_RundownRoutine(Apc);
}

BOOLEAN SuffixUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName)
{
	if (ShortName->Length < FullName->Length)
	{
		UNICODE_STRING us = {
			ShortName->Length, us.Length,
			(PWSTR)RtlOffsetToPointer(FullName->Buffer, FullName->Length - us.Length)
		};

		return RtlEqualUnicodeString(&us, ShortName, TRUE);
	}

	return FALSE;
}

BOOLEAN IsTargetProcess(PEPROCESS Process)
{
	return PsIsProcessBeingDebugged(Process) || !_stricmp("notepad.exe", PsGetProcessImageFileName(Process));
}

VOID NTAPI CreateProcessNotifyEx(_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo && CreateInfo->FileOpenNameAvailable)
	{
		DbgPrint("%hs (%p<%p [%p:%p] \"%wZ\" \"%wZ\")\n", __FUNCTION__,
			ProcessId,
			CreateInfo->ParentProcessId,
			CreateInfo->CreatingThreadId.UniqueProcess, CreateInfo->CreatingThreadId.UniqueThread,
			CreateInfo->ImageFileName,
			CreateInfo->CommandLine);

		if (IsTargetProcess(Process))
		{
			HANDLE hThread, hProcess;
			CLIENT_ID cid = { ProcessId };
			OBJECT_ATTRIBUTES oa = { sizeof(oa) };
			NTSTATUS status;
			if (0 <= (status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid)))
			{
				status = ZwGetNextThread(hProcess, 0, THREAD_SET_CONTEXT, 0, 0, &hThread);
				NtClose(hProcess);
				if (0 <= status)
				{
					PKTHREAD Thread;
					status = ObReferenceObjectByHandle(hThread, 0, *PsThreadType, KernelMode, (void**)&Thread, 0);
					NtClose(hThread);
					if (0 <= status)
					{
						if (PKAPC Apc = new(NonPagedPool) KAPC)
						{
							KeInitializeApc(Apc, Thread, OriginalApcEnvironment,
								KernelRoutine, RundownRoutine, NormalRoutine, UserMode, 0);

							DbgPrint("++Apc<%p> \n", Apc);

							ObfReferenceObject(_G_DriverObject);

							if (!KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT))
							{
								RundownRoutine(Apc);
							}
						}

						ObfDereferenceObject(Thread);
					}
				}
			}
		}
	}
}

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);

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

	return PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
}

_NT_END