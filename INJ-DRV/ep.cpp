#include "stdafx.h"

_NT_BEGIN

#include "api.h"

EXTERN_C { PDRIVER_OBJECT _G_DriverObject; }

RTL_RUN_ONCE
#ifdef _WIN64
_G_RunOncex86{}, 
#endif // _WIN64
_G_RunOncex64{};

ULONG
#ifdef _WIN64
_G_rvax86, 
#endif // _WIN64
_G_rvax64;


/*++

if DLL section mapped not at preferred base (STATUS_IMAGE_NOT_AT_BASE, STATUS_IMAGE_AT_DIFFERENT_BASE):

1.) system need relocate image to new base, as result modify it pages
(allocate new private physical pages for modification), after this pages already not shared

2.) win10 1703+: system by unknown reason unload it, insert task to LdrpRetryQueue and return STATUS_RETRY
and then tryed load it again (by using full path (!!) instead known section handle).

so mapping DLL not at preferred base have serious penalty

for avoid this - map our shellcode at different base - for not occupying preferred base

note that because our shellcode is based-independent - any base (STATUS_IMAGE_NOT_AT_BASE) is ok for us.
we not need relocated this mapping

for force shellcode not occupy preferred base:
1.) before map section - reserve preffered memory range with ZwAllocateVirtualMemory (MEM_RESERVE, PAGE_NOACCESS)
2.) map section (waited return status - STATUS_IMAGE_NOT_AT_BASE)
3.) free reserved range

however if load native 64-bit dll in wow64 process - preferred DLL base almost certainly will be in wow reserved memory range

-------------------------------------------------------------------------------
difference between STATUS_IMAGE_NOT_AT_BASE and STATUS_IMAGE_AT_DIFFERENT_BASE:
if section can not be mapped at  base:

when in ZwMapViewOfSection:
AllocationType containing MEM_DIFFERENT_IMAGE_BASE_OK flag(used inside LdrLoadDll) -
section RELOCATED and returned STATUS_IMAGE_AT_DIFFERENT_BASE
otherwise - section NOT relocated and STATUS_IMAGE_NOT_AT_BASE returned.

when STATUS_IMAGE_NOT_AT_BASE returned need process relocs
when STATUS_IMAGE_AT_DIFFERENT_BASE relocs already applied (in kernel) - not need relocate

we use base-independed code in section, we not need relocation

so better not use MEM_DIFFERENT_IMAGE_BASE_OK and got unrelocated view

--*/

NTSTATUS MapSection(_In_ PVOID Section, _Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize)
{
	PVOID PreferredAddress = 0;
	LARGE_INTEGER ZeroOffset = {};

	NTSTATUS status;

	if (0 <= (status = MmMapViewOfSection(Section, IoGetCurrentProcess(),
		&PreferredAddress, 0, 0, &ZeroOffset, ViewSize, ViewUnmap, 0, PAGE_EXECUTE)))
	{
		if (STATUS_SUCCESS == status)
		{
			status = MmMapViewOfSection(Section, IoGetCurrentProcess(),
				BaseAddress, 0, 0, &ZeroOffset, ViewSize, ViewUnmap, 0, PAGE_EXECUTE);
		}
		else
		{
			status = STATUS_CONFLICTING_ADDRESSES;
		}

		MmUnmapViewOfSection(IoGetCurrentProcess(), PreferredAddress);
	}

	return status;
}

BOOL InRange(PVOID BaseAddress, SIZE_T ViewSize, PVOID pv, ULONG cb)
{
	SIZE_T o = (SIZE_T)pv - (SIZE_T)BaseAddress;
	return o < ViewSize && cb <= ViewSize - o;
}

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
	PKNORMAL_ROUTINE* /*NormalRoutine*/,
	PVOID* /*NormalContext*/,
	PVOID* /*SystemArgument1*/,
	PVOID* /*SystemArgument2*/
)
{
	CPP_FUNCTION;

	DbgPrint("_KernelRoutine(%p, %x)\n", Apc, Apc->ApcMode);

	if (Apc->ApcMode == KernelMode)
	{
		// stage #1 - kernel mode apc
		ObfReferenceObject(_G_DriverObject);//NormalRoutine will be called

		return;
	}

	// stage #2 - user mode apc, free Apc object
	_RundownRoutine(Apc);
}

VOID CALLBACK _NormalRoutine(PKAPC Apc, PVOID Section, BOOL bWow)
{
	CPP_FUNCTION;

	DbgPrint("NormalRoutine(%p, %p, %p)\n", Apc, Section, bWow);

	SIZE_T ViewSize = 0;
	PVOID BaseAddress = 0;

	NTSTATUS status = MapSection(Section, &BaseAddress, &ViewSize);

	ObfDereferenceObject(Section);

	DbgPrint("MapSection = %x, %p [%x]\n", status, BaseAddress, ViewSize);
	//ASSERT (status == STATUS_IMAGE_NOT_AT_BASE);

	if (0 <= status)
	{
		ULONG* prva = 
#ifdef _WIN64
			bWow ? &_G_rvax86 : 
#endif
			&_G_rvax64, rva = *prva;

		if (!rva)
		{
			PIMAGE_NT_HEADERS pinth;
			if (0 <= RtlImageNtHeaderEx(0, BaseAddress, ViewSize, &pinth))
			{
				ULONG size, Ordinal = 1;
				PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)
					RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

				if (pied && size >= sizeof(IMAGE_EXPORT_DIRECTORY) &&
					InRange(BaseAddress, ViewSize, pied, size) &&
					(Ordinal -= pied->Base) < pied->NumberOfFunctions)
				{
					if (PULONG AddressOfFunctions = (PULONG)RtlOffsetToPointer(BaseAddress, pied->AddressOfFunctions))
					{
						if (InRange(BaseAddress, ViewSize, AddressOfFunctions, pied->NumberOfFunctions * sizeof(ULONG)))
						{
							*prva = rva = AddressOfFunctions[Ordinal];
						}
					}
				}
			}
		}

		if (rva)
		{
			union {
				PVOID pvNormalRoutine;
				PKNORMAL_ROUTINE NormalRoutine;
			};

			PVOID NormalContext = BaseAddress;
			pvNormalRoutine = (PBYTE)BaseAddress + rva;

			// pvNormalRoutine is valid for CFG because this is exported address from image, 
			// which have IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT and 
			// pvNormalRoutine was in GuardCFFunctionTable (__guard_fids_table)

#ifdef _WIN64
			if (bWow) PsWrapApcWow64Thread(&NormalContext, &pvNormalRoutine);
#endif

			KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment,
				KernelRoutine, RundownRoutine, NormalRoutine, UserMode, NormalContext);

			ObfReferenceObject(_G_DriverObject);

			if (KeInsertQueueApc(Apc, 
#ifdef _WIN64
#pragma warning (suppress : 4310)
				bWow ? (PVOID)(ULONG_PTR)(ULONG)(ULONG_PTR)NtCurrentProcess() : 
#endif
				NtCurrentProcess(),
				BaseAddress, IO_NO_INCREMENT))
			{
				DbgPrint("InsertQueueApc(%p, %p, %p)\n", BaseAddress, NormalContext, NormalRoutine);

				// force call user mode apc
				KeTestAlertThread(UserMode);

				return;
			}

			ObfDereferenceObject(_G_DriverObject);
		}

		MmUnmapViewOfSection(IoGetCurrentProcess(), BaseAddress);
	}

	DbgPrint("!!!!!!!!!!!!!!!!!!! _NormalRoutine\n");

	// delete Apc; 
	_RundownRoutine(Apc);
}

NTSTATUS CreateKnownSection(_Out_ void** section, _In_ HANDLE hFile, _In_ PCOBJECT_ATTRIBUTES poaNt, _In_ PCUNICODE_STRING My)
{
	ULONG cb = 0, rcb = 256;

	static volatile const UCHAR guz = 0;

	PVOID stack = alloca(guz);

	HANDLE hSection;

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(My), OBJ_CASE_INSENSITIVE | OBJ_PERMANENT };

	// look for system (smss.exe) assigned SD for known dlls

	NTSTATUS status = ZwOpenSection(&hSection, READ_CONTROL, const_cast<POBJECT_ATTRIBUTES>(poaNt));

	if (0 <= status)
	{
		do
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(oa.SecurityDescriptor = alloca(rcb - cb), stack);
			}

			status = ZwQuerySecurityObject(hSection,
				PROCESS_TRUST_LABEL_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
				oa.SecurityDescriptor, cb, &rcb);

		} while (status == STATUS_BUFFER_TOO_SMALL);

		ZwClose(hSection);

		if (0 <= status)
		{
			if (0 <= (status = ZwCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_QUERY, &oa, 0, PAGE_EXECUTE, SEC_IMAGE, hFile)))
			{
				status = ObReferenceObjectByHandle(hSection, 0, 0, KernelMode, section, 0);
				ZwClose(hSection);
			}
		}
	}

	return status;
}

NTSTATUS CreateKnownSection(_Out_ void** section, _In_ PCWSTR pcszFile, _In_ PCWSTR pcszNt, _In_ PCWSTR My)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName, usMy;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE };

	RtlInitUnicodeString(&ObjectName, pcszFile);

	NTSTATUS status = ZwOpenFile(&hFile, FILE_GENERIC_READ | FILE_EXECUTE,
		&oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	DbgPrint("OpenFile(%ws)=%x\n", pcszFile, status);

	if (0 <= status)
	{
		RtlInitUnicodeString(&ObjectName, pcszNt);
		RtlInitUnicodeString(&usMy, My);

		KAPC_STATE ApcState;
		KeStackAttachProcess(PsInitialSystemProcess, &ApcState);
		status = CreateKnownSection(section, hFile, &oa, &usMy);
		KeUnstackDetachProcess(&ApcState);

		ZwClose(hFile);
		DbgPrint("CreateKnownSection=%x [%p]\n", status, *section);
	}

	return status;
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

LONG OnException(PCSTR file, ULONG line, PEXCEPTION_RECORD ExceptionRecord)
{
	ULONG NumberParameters = ExceptionRecord->NumberParameters;
	DbgPrint("%hs(%u): %x at %p [%x]\n", file, line, ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress, NumberParameters);
	if (NumberParameters)
	{
		PULONG_PTR ExceptionInformation = ExceptionRecord->ExceptionInformation;
		char buf[0x100], * psz = buf;
		ULONG cch = _countof(buf);
		do
		{
			int len = sprintf_s(psz, cch, "%p, ", (void*)*ExceptionInformation++);
			if (0 >= len)
			{
				break;
			}
			psz += len, cch -= len;
		} while (--NumberParameters);

		sprintf_s(psz, cch, "\n");
		DbgPrint(buf);
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

#define ONEXCEPTION OnException(__FILE__, __LINE__, GetExceptionInformation()->ExceptionRecord)

NTSTATUS GetSection(void** section, PRTL_RUN_ONCE RunOnce, PCWSTR pcszMyDllPath, PCWSTR pcszKnownNt, PCWSTR pcszKnownMy)
{
	NTSTATUS status;
	if (STATUS_PENDING == (status = RtlRunOnceBeginInitialize(RunOnce, 0, section)))
	{
		PVOID Section = 0;
		if (0 > (status = CreateKnownSection(&Section, pcszMyDllPath, pcszKnownNt, pcszKnownMy)))
		{
			RtlRunOnceComplete(RunOnce, RTL_RUN_ONCE_INIT_FAILED, 0);
		}
		else
		{
			status = RtlRunOnceComplete(RunOnce, 0, Section);
			*section = Section;
		}
	}

	return status;
}

/*++
	we called because somebody call ZwMapViewOfSection with SEC_IMAGE
	but this can be not true load library: (ArbitraryUserPointer -> L"*\\kernel32.dll" in true load lib)
	smss.exe map kernel32.dll during create \\KnownDlls (ArbitraryUserPointer == 0 in this case)
	wow64 process several time map kernel32.dll (32 and 64 bit) with WOW64_IMAGE_SECTION or NOT_AN_IMAGE
--*/

BOOLEAN IsByLdrLoadDll(PCUNICODE_STRING ShortName)
{
	UNICODE_STRING Name;

	__try
	{
		PNT_TIB Teb = (PNT_TIB)PsGetCurrentThreadTeb();

		if (!Teb || !(Name.Buffer = (PWSTR)Teb->ArbitraryUserPointer))
		{
			return FALSE;
		}

		ProbeForRead(Name.Buffer, sizeof(WCHAR), __alignof(WCHAR));

		Name.Length = (USHORT)wcsnlen(Name.Buffer, MAXSHORT);

		if (Name.Length == MAXSHORT)
		{
			return FALSE;
		}

		Name.MaximumLength = Name.Length <<= 1;

		DbgPrint("ArbitraryUserPointer= \"%wZ\"\n", &Name);

		return SuffixUnicodeString(&Name, ShortName);

	}
	__except (ONEXCEPTION)
	{
	}

	return FALSE;
}

BOOLEAN IsTargetProcess()
{
	PEPROCESS Process = IoGetCurrentProcess();
	PCSTR name = PsGetProcessImageFileName(Process);
	return PsIsProcessBeingDebugged(Process) || !_stricmp("notepad.exe", name);
}

void SetProtectedBit(PEPROCESS Process, BOOL IsProtectedProcess)
{
	if (PsIsProtectedProcess(Process))
	{
		_PEB* peb;// IsProtectedProcess at the same place in 32/64 bit PEB (+3 bytes offset) 
		if (
#ifdef _WIN64
			(peb = (_PEB*)PsGetProcessWow64Process(Process)) ||
#endif
			(peb = PsGetProcessPeb(Process)))
		{
			peb->IsProtectedProcess = IsProtectedProcess;
			DbgPrint("IsProtectedProcess<%p> = %x \"%hs\"\n", peb, IsProtectedProcess, PsGetProcessImageFileName(Process));
		}
	}
}

VOID CALLBACK OnLoadImage(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId, // where image is mapped
	IN PIMAGE_INFO ImageInfo
)
{
	STATIC_UNICODE_STRING(ntdll, "\\ntdll.dll");
	STATIC_UNICODE_STRING(kernel32, "\\kernel32.dll");

	if (
		!ImageInfo->SystemModeImage &&
		ProcessId == PsGetCurrentProcessId() // section can be "remote" mapped from another process
		)
	{
		PEPROCESS Process = IoGetCurrentProcess();

		if (SuffixUnicodeString(FullImageName, &ntdll))
		{
			if (PsGetProcessId(PsInitialSystemProcess) != PsGetProcessInheritedFromUniqueProcessId(Process))
			{
				SetProtectedBit(Process, FALSE);
			}
		}
		else if (SuffixUnicodeString(FullImageName, &kernel32) && IsByLdrLoadDll(&kernel32) /* && IsTargetProcess()*/)
		{
			SetProtectedBit(Process, TRUE);

			DbgPrint("%p %x \"%wZ\" \"%hs\"\n", ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, PsGetProcessImageFileName(Process));
			PRTL_RUN_ONCE RunOnce = 0;
			PCWSTR pcszMyDllPath = 0, pcszKnownNt = 0, pcszKnownMy = 0;
			BOOL wow;

#ifdef _WIN64
			if (PsGetProcessWow64Process(Process))
			{
				RunOnce = &_G_RunOncex86;
				pcszMyDllPath = L"\\systemroot\\syswow64\\]]rbmm[[.dll";
				pcszKnownNt = L"\\KnownDlls32\\ntdll.dll";
				pcszKnownMy = L"\\KnownDlls32\\{EBB50DDB-F6AA-492d-94E3-1D51B299F627}.dll";
				wow = true;
			}
			else
#endif
			{
				RunOnce = &_G_RunOncex64;
				pcszMyDllPath = L"\\systemroot\\system32\\]]rbmm[[.dll";
				pcszKnownNt = L"\\KnownDlls\\ntdll.dll";
				pcszKnownMy = L"\\KnownDlls\\{EBB50DDB-F6AA-492d-94E3-1D51B299F627}.dll";
				wow = false;
			}

			PVOID section;
			if (0 <= GetSection(&section, RunOnce, pcszMyDllPath, pcszKnownNt, pcszKnownMy))
			{
				// for do main job out of critical region
				if (PKAPC Apc = new(NonPagedPool) KAPC)
				{
					KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment,
						KernelRoutine, RundownRoutine, NormalRoutine, KernelMode, Apc);

					DbgPrint("++Apc<%p> \n", Apc);

					ObfReferenceObject(_G_DriverObject);

					ObfReferenceObject(section);

					if (!KeInsertQueueApc(Apc, section, (PVOID)wow, IO_NO_INCREMENT))
					{
						ObfDereferenceObject(section);
						RundownRoutine(Apc);
					}
				}
			}
		}
	}
}

void CloseSection(PRTL_RUN_ONCE RunOnce)
{
	PVOID section;
	if (STATUS_SUCCESS == RtlRunOnceBeginInitialize(RunOnce, RTL_RUN_ONCE_CHECK_ONLY, &section))
	{
		ObMakeTemporaryObject(section);
		ObfDereferenceObject(section);
		DbgPrint("delete section %p\n", section);
	}
}

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	PsRemoveLoadImageNotifyRoutine(OnLoadImage);

#ifdef _WIN64
	CloseSection(&_G_RunOncex86);
#endif
	CloseSection(&_G_RunOncex64);

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

	return PsSetLoadImageNotifyRoutine(OnLoadImage);
}

_NT_END