#include "stdafx.h"
#include "zip.h"

extern const UCHAR codesec_exe_begin[], codesec_exe_end[];

_NT_BEGIN

static const WCHAR DriverFileName[] = L"\\systemroot\\system32\\drivers\\D8F86BDE6363440e821FB5F0B9C9FF4F.sys";
static const WCHAR DriverServiceName[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\D8F86BDE6363440e821FB5F0B9C9FF4F";

NTSTATUS DropDriver()
{
	PVOID pv;
	LARGE_INTEGER as {};

	HRESULT hr = Unzip(codesec_exe_begin, RtlPointerToOffset(codesec_exe_begin, codesec_exe_end), &pv, &as.LowPart);
	if (S_OK == hr)
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;

		RtlInitUnicodeString(&ObjectName, DriverFileName);

		if (0 <= (hr = NtCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &iosb, &as, 
			FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, 0, FILE_OVERWRITE_IF, 
			FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT, 0, 0)))
		{
			hr = NtWriteFile(hFile, 0, 0, 0, &iosb, pv, as.LowPart, 0, 0);
			NtClose(hFile);
		}
		LocalFree(pv);
	}

	return hr;
}

NTSTATUS DeleteDriver()
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, DriverFileName);
	return ZwDeleteFile(&oa);
}

NTSTATUS LoadDriver()
{
	UNICODE_STRING ObjectName;
	RtlInitUnicodeString(&ObjectName, DriverServiceName);
	return ZwLoadDriver(&ObjectName);
}

NTSTATUS UnloadDriver()
{
	UNICODE_STRING ObjectName;
	RtlInitUnicodeString(&ObjectName, DriverServiceName);
	return ZwUnloadDriver(&ObjectName);
}

NTSTATUS SetValueKey( _In_ HANDLE hKey, _In_ PCWSTR ValueName, _In_ ULONG Type, _In_ const void* Data, _In_ ULONG DataSize )
{
	UNICODE_STRING ObjectName;
	RtlInitUnicodeString(&ObjectName, ValueName);
	return ZwSetValueKey(hKey, &ObjectName, 0, Type, const_cast<void*>(Data), DataSize);
}

NTSTATUS SetValueKey( _In_ HANDLE hKey, _In_ PCWSTR ValueName, _In_ ULONG Value )
{
	return SetValueKey(hKey, ValueName, REG_DWORD, &Value, sizeof(Value));
}

NTSTATUS RegisterDriver()
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, DriverServiceName);
	HANDLE hKey;
	NTSTATUS status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, 0, 0, 0);

	if (0 <= status)
	{
		if (0 > (status = SetValueKey(hKey, L"ImagePath", REG_SZ, DriverFileName, sizeof(DriverFileName))) || 
			0 > (status = SetValueKey(hKey, L"Start", SERVICE_DEMAND_START)) || 
			0 > (status = SetValueKey(hKey, L"Type", SERVICE_KERNEL_DRIVER)) || 
			0 > (status = SetValueKey(hKey, L"ErrorControl", SERVICE_ERROR_IGNORE)) ||
			0 > (status = DropDriver()))
		{
			ZwDeleteKey(hKey);
		}

		NtClose(hKey);
	}

	return status;
}

NTSTATUS UnregisterDriver()
{
	DeleteDriver();

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, DriverServiceName);
	HANDLE hKey;
	NTSTATUS status = ZwOpenKey(&hKey, DELETE, &oa);

	if (0 <= status)
	{
		status = ZwDeleteKey(hKey);
	}

	return status;
}

_NT_END