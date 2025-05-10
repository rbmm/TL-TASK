#include "stdafx.h"

_NT_BEGIN

#include "log.h"

EXTERN_C
WINBASEAPI
NTSTATUS
FASTCALL
K32BaseThreadInitThunk(
					   BOOL bInitializeTermsrv, 
					   LPTHREAD_START_ROUTINE lpStartAddress, 
					   PVOID lpParameter
					   );

#ifdef _M_IX86
#pragma warning(disable: 4483) // Allow use of __identifier
#define __imp_K32BaseThreadInitThunk __identifier("_imp_@K32BaseThreadInitThunk@12")
#endif

EXTERN_C { PVOID __imp_K32BaseThreadInitThunk = 0; }

void TermsrvGetWindowsDirectoryW()
{
	__debugbreak();
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

PVOID FindLdrpKernel32DllName(_In_ PVOID hmod, _Out_ PWSTR* pBuffer)
{
	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hmod))
	{
		if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
		{
			PUNICODE_STRING pstr = 0;

			PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);
			do 
			{
				ULONG VirtualSize = GetSectionSize(pish);

				if (VirtualSize > sizeof(UNICODE_STRING))
				{
					ULONG n = 1 + (VirtualSize - sizeof(UNICODE_STRING)) / __alignof(UNICODE_STRING);

					union {
						PVOID pv;
						PUNICODE_STRING str;
						ULONG_PTR up;
					};

					PVOID VirtualAddress = RtlOffsetToPointer(hmod, pish->VirtualAddress);
					pv = VirtualAddress;

					STATIC_UNICODE_STRING(kernel32, "[[rbmm]].dll");
					do 
					{
						if (str->Length == kernel32.Length && str->MaximumLength == kernel32.MaximumLength)
						{
							PWSTR Buffer = str->Buffer;

							if (!((ULONG_PTR)Buffer & (__alignof(WCHAR) - 1)))
							{
								if ((ULONG_PTR)Buffer - (ULONG_PTR)VirtualAddress < VirtualSize)
								{
									if (!_wcsicmp(Buffer, kernel32.Buffer))
									{
										if (pstr)
										{
											return 0;
										}

										pstr = str, *pBuffer = Buffer;
									}
								}
							}
						}
					} while (up += __alignof(UNICODE_STRING), --n);
				}

			} while (pish++, --NumberOfSections);

			return pstr;
		}
	}

	return 0;
}

NTSTATUS 
FASTCALL 
BaseThreadInitThunk(
					BOOL bInitializeTermsrv, 
					LPTHREAD_START_ROUTINE lpStartAddress, 
					PVOID lpParameter
					)
{
	union {
		PVOID func;
		HMODULE hmod;
	};

	UNICODE_STRING DllName;
	static const WCHAR kernel32[] = L"kernel32.dll";

	if (!__imp_K32BaseThreadInitThunk)
	{
		static HMODULE shmod = 0;
		
		NTSTATUS status;

		if (!shmod)
		{
			RtlInitUnicodeString(&DllName, kernel32);
			if (0 > (status = LdrGetDllHandle(0, 0, &DllName, &hmod)))
			{
				return status;
			}
			shmod = hmod;
		}

		STATIC_ANSI_STRING(aBaseThreadInitThunk, "BaseThreadInitThunk");

		if (0 > (status = LdrGetProcedureAddress(shmod, &aBaseThreadInitThunk, 0, &func)))
		{
			return status;
		}

		__imp_K32BaseThreadInitThunk = func;
	}

	if (bInitializeTermsrv)
	{
		RtlInitUnicodeString(&DllName, L"ntdll.dll");

		if (0 <= LdrGetDllHandle(0, 0, &DllName, &hmod))
		{
			PWSTR Buffer;
			if (PVOID pv = FindLdrpKernel32DllName(hmod, &Buffer))
			{
				SIZE_T s = sizeof(kernel32);
				ULONG op;
				if (0 <= ZwProtectVirtualMemory(NtCurrentProcess(), &(pv = Buffer), &s, PAGE_READWRITE, &op))
				{
					wcscpy(Buffer, kernel32);
					ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &s, op, &op);
				}
			}
		}

		PS_PROTECTION pp;
		if (0 <= NtQueryInformationProcess(NtCurrentProcess(), ProcessProtectionInformation, &pp, sizeof(pp), 0))
		{
			if (pp.Type)
			{
				RtlGetCurrentPeb()->IsProtectedProcess = TRUE;
			}
		}
	}

	return K32BaseThreadInitThunk(bInitializeTermsrv, lpStartAddress, lpParameter);
}

_NT_END