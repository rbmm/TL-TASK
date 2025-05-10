#include "stdafx.h"

_NT_BEGIN

#include "api.h"

RTL_RUN_ONCE _G_RunOncex64 {}, _G_RunOncex86 {};
ULONG _G_rvax64, _G_rvax86;

NTSTATUS CreateKnownSection(_Out_ PHANDLE SectionHandle,
							_In_ HANDLE hFile, 
							_In_ PCOBJECT_ATTRIBUTES poaNt, 
							_In_ PCUNICODE_STRING My)
{
	ULONG cb = 0, rcb = 256;

	static volatile const UCHAR guz = 0;

	PVOID stack = alloca(guz);

	HANDLE hSection;

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(My), OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE };

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
				PROCESS_TRUST_LABEL_SECURITY_INFORMATION|
				DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION, 
				oa.SecurityDescriptor, cb, &rcb);

		} while (status == STATUS_BUFFER_TOO_SMALL);

		ZwClose(hSection);

		if (0 <= status)
		{
			status = ZwCreateSection(SectionHandle, SECTION_MAP_EXECUTE|SECTION_QUERY, &oa, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);
		}
	}

	return status;
}

NTSTATUS CreateKnownSection(_Out_ PHANDLE SectionHandle,
							PCWSTR pcszFile, 
							PCWSTR pcszNt, 
							PCWSTR My)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName, usMy;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE };

	RtlInitUnicodeString(&ObjectName, pcszFile);


	NTSTATUS status = ZwOpenFile(&hFile, FILE_GENERIC_READ|FILE_EXECUTE, 
		&oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	DbgPrint("OpenFile(%ws)=%x\n", pcszFile, status);

	if (0 <= status)
	{
		RtlInitUnicodeString(&ObjectName, pcszNt);
		RtlInitUnicodeString(&usMy, My);

		KAPC_STATE ApcState;
		KeStackAttachProcess(PsInitialSystemProcess, &ApcState);
		status = CreateKnownSection(SectionHandle, hFile, &oa, &usMy);
		KeUnstackDetachProcess(&ApcState);

		ZwClose(hFile);
		DbgPrint("CreateKnownSection=%x\n", status);
	}

	return status;
}

ULONG GetSectionSize(PIMAGE_SECTION_HEADER pish)
{
	if ((pish->Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE)) == IMAGE_SCN_MEM_READ)
	{
		ULONG VirtualSize = pish->Misc.VirtualSize, SizeOfRawData = pish->SizeOfRawData;

		return SizeOfRawData < VirtualSize ? SizeOfRawData : VirtualSize;
	}

	return 0;
}

PVOID FindLdrpKernel32DllName(PVOID hmod, 
							  PIMAGE_NT_HEADERS pinth, 
							  ULONG algn,
							  ULONG n,
							  PULONG prva)
{
	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PVOID pstr = 0;

		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);
		do 
		{
			ULONG VirtualSize = GetSectionSize(pish);

			if (VirtualSize > n)
			{
				n = 1 + (VirtualSize - n) / algn;

				union {
					PVOID pv;
					PUNICODE_STRING str;
					PUNICODE_STRING64 str64;
					PUNICODE_STRING32 str32;
					ULONG_PTR up;
				};

				PVOID VirtualAddress = RtlOffsetToPointer(hmod, pish->VirtualAddress);
				pv = VirtualAddress;

				STATIC_UNICODE_STRING(kernel32, "kernel32.dll");
				do 
				{
					if (str->Length == kernel32.Length &&str->MaximumLength == kernel32.MaximumLength)
					{
						ULONG_PTR Buffer = algn == __alignof(UNICODE_STRING) ? str64->Buffer : str32->Buffer;

						if (!(Buffer & (__alignof(WCHAR) - 1)))
						{
							if (Buffer - (ULONG_PTR)VirtualAddress < VirtualSize)
							{
								if (!_wcsicmp((PWSTR)Buffer, kernel32.Buffer))
								{
									if (pstr)
									{
										return 0;
									}

									pstr = pv, *prva = RtlPointerToOffset(hmod, Buffer);
								}
							}
						}
					}
				} while (up += algn, --n);
			}

		} while (pish++, --NumberOfSections);

		return pstr;
	}

	return 0;
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
		char buf[0x100], *psz = buf;
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

void FindLdrpKernel32(_In_ PVOID hmod, _In_ ULONG64 Size)
{
	union {
		PIMAGE_NT_HEADERS pinth;
		PIMAGE_NT_HEADERS32 pinth32;
		PIMAGE_NT_HEADERS64 pinth64;
	};

	PRTL_RUN_ONCE RunOnce = 0;
	ULONG *prva, rva = 0;
	PCWSTR pcszMyDllPath = 0, pcszKnownNt = 0, pcszKnownMy = 0;

	__try
	{
		if (0 > RtlImageNtHeaderEx(0, hmod, Size, &pinth))
		{
			return ;
		}

		ULONG algn, n;
		ULONG_PTR ImageBase;

		WORD Machine = pinth->FileHeader.Machine;

		switch (pinth->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			ImageBase = pinth32->OptionalHeader.ImageBase;
			algn = __alignof(UNICODE_STRING32);
			n = sizeof(UNICODE_STRING64);
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			ImageBase = pinth64->OptionalHeader.ImageBase;
			algn = __alignof(UNICODE_STRING64);
			n = sizeof(UNICODE_STRING64);
			break;
		default: return ;
		}

		if ((PVOID)ImageBase != hmod)
		{
			return ;
		}

		switch (Machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			RunOnce = &_G_RunOncex86;
			prva = &_G_rvax86;
			pcszMyDllPath = L"\\systemroot\\syswow64\\LdrpKernel32.dll"; 
			pcszKnownNt = L"\\KnownDlls32\\ntdll.dll"; 
			pcszKnownMy = L"\\KnownDlls32\\[[rbmm]].dll";
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			RunOnce = &_G_RunOncex64;
			prva = &_G_rvax64;
			pcszMyDllPath = L"\\systemroot\\system32\\LdrpKernel32.dll"; 
			pcszKnownNt = L"\\KnownDlls\\ntdll.dll"; 
			pcszKnownMy = L"\\KnownDlls\\[[rbmm]].dll";
			break;
		default:
			return ;
		}

		if (!(rva = *prva))
		{
			if (!FindLdrpKernel32DllName(hmod, pinth, algn, n, &rva))
			{
				return ;
			}

			*prva = rva;

			DbgPrint("kernel32[%x]: %x\n", Machine, rva);
		}
	}
	__except(ONEXCEPTION)
	{
	}

	NTSTATUS status;
	HANDLE hSection = 0;
	if (STATUS_PENDING == (status = RtlRunOnceBeginInitialize(RunOnce, 0, &hSection)))
	{
		if (0 > (status = CreateKnownSection(&hSection, pcszMyDllPath, pcszKnownNt, pcszKnownMy)))
		{
			RtlRunOnceComplete(RunOnce, RTL_RUN_ONCE_INIT_FAILED, 0);
		}
		else
		{
			status = RtlRunOnceComplete(RunOnce, 0, hSection);
		}
	}

	DbgPrint("KS: %p %x\n", hSection, status);

	if (STATUS_SUCCESS == status)
	{
		PWSTR pszDllName = (PWSTR)RtlOffsetToPointer(hmod, rva);

		PEPROCESS Process = IoGetCurrentProcess();

		DbgPrint("++OverWrite: %p \"%hs\"\n", pszDllName, PsGetProcessImageFileName(Process));

		SIZE_T s = sizeof(L"[[rbmm]].dll");
		ULONG op;
		PVOID pv = pszDllName;

		if (0 <= (status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &s, PAGE_READWRITE, &op)))
		{
			__try
			{
				wcscpy(pszDllName, L"\\KnownDlls\\[[rbmm]].dll" + _countof("\\KnownDlls"));

				if (PsIsProtectedProcess(Process))
				{
					_PEB* peb;// IsProtectedProcess at the same place in 32/64 bit PEB (+3 bytes offset) 
					if ((peb = (_PEB*)PsGetProcessWow64Process(Process)) || 
						(peb = PsGetProcessPeb(Process)))
					{
						peb->IsProtectedProcess = FALSE;
						DbgPrint("PP: %p\n", peb);
					}
				}
			}
			__except(ONEXCEPTION)
			{
				status = GetExceptionCode();
			}

			ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &s, op, &op);
		}
		DbgPrint("--OverWrite: %p \"%hs\" = %x\n", pszDllName, PsGetProcessImageFileName(Process), status);
	}
}

VOID CALLBACK OnLoadImage(
						  IN PUNICODE_STRING FullImageName,
						  IN HANDLE ProcessId, // where image is mapped
						  IN PIMAGE_INFO ImageInfo
						  )
{
	STATIC_UNICODE_STRING(ntdll, "\\ntdll.dll");

	if (
		!ImageInfo->SystemModeImage && 
		ProcessId == PsGetCurrentProcessId() && // section can be "remote" mapped from another process
		SuffixUnicodeString(FullImageName, &ntdll)
		)
	{
		DbgPrint("%p %x \"%wZ\"\n", ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName);
		FindLdrpKernel32(ImageInfo->ImageBase, ImageInfo->ImageSize);
	}
}

void CloseSection(PRTL_RUN_ONCE RunOnce)
{
	HANDLE hSection;
	if (STATUS_SUCCESS == RtlRunOnceBeginInitialize(RunOnce, RTL_RUN_ONCE_CHECK_ONLY, &hSection))
	{
		NTSTATUS status = NtClose(hSection);

		DbgPrint("close(%p)=%x\n", hSection, status);
	}
}

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{	
	PsRemoveLoadImageNotifyRoutine(OnLoadImage);

	CloseSection(&_G_RunOncex86);
	CloseSection(&_G_RunOncex64);

	DbgPrint("DriverUnload(%p)\n", DriverObject);
}

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("DriverLoad(%p, %wZ)\n", DriverObject, RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	return PsSetLoadImageNotifyRoutine(OnLoadImage);
}

_NT_END