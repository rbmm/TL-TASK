#include "stdafx.h"

_NT_BEGIN

EXTERN_C
NTSYSAPI
DECLSPEC_NORETURN
VOID
NTAPI
RtlExitUserProcess(
    _In_ NTSTATUS uExitCode
);

HANDLE _G_hLog;

NTSTATUS lInit()
{
	UNICODE_STRING ObjectName;
	RtlInitUnicodeString(&ObjectName, L"\\systemroot\\temp\\TLT.log");
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
	IO_STATUS_BLOCK iosb;

	return NtCreateFile(&_G_hLog, FILE_APPEND_DATA | SYNCHRONIZE,
		&oa, &iosb, 0, 0, FILE_SHARE_READ, FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
}

void lprintf(PCSTR format, ...)
{
	if (_G_hLog)
	{
		va_list args;
		va_start(args, format);
		char buf[0x800];
		int len = _vsnprintf_s(buf, RTL_NUMBER_OF(buf), _TRUNCATE, format, args);
		if (0 < len)
		{
			IO_STATUS_BLOCK iosb;
			NtWriteFile(_G_hLog, 0, 0, 0, &iosb, buf, len, 0, 0);
		}
	}
}

void lclose()
{
	if (_G_hLog)
	{
		NtClose(_G_hLog);
	}
}

#define DbgPrint lprintf

#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())

extern volatile const UCHAR guz = 0;

void NTAPI ep(void* /* peb */)
{
	if (0 <= lInit())
	{
		PVOID stack = alloca(guz);

		union {
			PVOID buf;
			PTOKEN_SID_INFORMATION ptsi;
		};

		ULONG cb = 0, rcb = sizeof(TOKEN_SID_INFORMATION) + SECURITY_SID_SIZE(SECURITY_PROCESS_TRUST_AUTHORITY_RID_COUNT);

		NTSTATUS status;
		do
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			if (0 <= (status = NtQueryInformationToken(NtCurrentProcessToken(), TokenProcessTrustLevel, buf, cb, &rcb)))
			{
				if (ptsi->Sid)
				{
					UNICODE_STRING szSid;
					if (0 <= RtlConvertSidToUnicodeString(&szSid, ptsi->Sid, TRUE))
					{
						DbgPrint("TrustLevel=%wZ\r\n", &szSid);
						RtlFreeUnicodeString(&szSid);
					}
				}
				else
				{
					DbgPrint("TrustLevel=0\r\n");
				}
				break;
			}
		} while (STATUS_BUFFER_TOO_SMALL == status);

		DbgPrint("status=%x\r\n", status);

		lclose();
	}

	RtlExitUserProcess(0);
}

_NT_END