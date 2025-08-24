#include "stdafx.h"

_NT_BEGIN

#include "print.h"

DWORD HashString(PCWSTR lpsz, DWORD hash = 0)
{
	while (WCHAR c = *lpsz++) hash = hash * 33 ^ c;
	return hash;
}

BEGIN_PRIVILEGES(tp_backup_restore_security, 3)
	LAA(SE_BACKUP_PRIVILEGE),
	LAA(SE_RESTORE_PRIVILEGE),
	LAA(SE_SECURITY_PRIVILEGE),
END_PRIVILEGES

BEGIN_PRIVILEGES(tp_load, 1)
	LAA(SE_LOAD_DRIVER_PRIVILEGE),
END_PRIVILEGES

NTSTATUS AdjustPrivileges(const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)))
	{
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0);

		NtClose(hToken);
	}

	return status;
}

NTSTATUS RegisterDriver();
NTSTATUS UnregisterDriver();
NTSTATUS LoadDriver();
NTSTATUS UnloadDriver();
NTSTATUS robocopy(PWSTR pszFrom, PWSTR pszTo);

//#define _HELP_PRINT_

#ifdef _HELP_PRINT_

void HashCmd(PCWSTR cmd)
{
	DbgPrint("case 0x%08X: // %ws\n\tbreak;\r\n", HashString(cmd), cmd);
}

#endif

NTSTATUS run()
{
	PrintInfo pi;
	InitPrintf();

#ifdef _HELP_PRINT_
	HashCmd(L"copy");
	HashCmd(L"install");
	HashCmd(L"uninstall");
	HashCmd(L"load");
	HashCmd(L"unload");
#endif

	PWSTR psz = GetCommandLineW();
	PWSTR pc = psz + wcslen(psz);
	while (' ' == *--pc) *pc = 0;

	DbgPrint("cmd: \"%ws\"\r\n", psz);

	NTSTATUS status = STATUS_INVALID_PARAMETER;

	if (psz = wcschr(psz, '*'))
	{
		PWSTR cmd = psz + 1;

		if (psz = wcschr(cmd, '*'))
		{
			*psz++ = 0;

			switch(HashString(cmd))
			{
			case 0x6C9612A1: // install
				status = RegisterDriver();
				break;

			case 0x483FA87A: // uninstall
				status = UnregisterDriver();
				break;

			case 0x00396DA6: // load
				if (STATUS_SUCCESS == (status = AdjustPrivileges(&tp_load)))
				{
					status = LoadDriver();
				}

				break;

			case 0x180F27DD: // unload
				if (STATUS_SUCCESS == (status = AdjustPrivileges(&tp_load)))
				{
					status = UnloadDriver();
				}
				break;

			case 0x0035EDA5: // copy

				status = STATUS_INVALID_PARAMETER_MIX;

				if (cmd = wcschr(psz, '*'))
				{
					*cmd = 0;

					if (STATUS_SUCCESS == (status = AdjustPrivileges(&tp_backup_restore_security)))
					{
						status = robocopy(psz, cmd + 1);
					}
				}

				break;
			}
		}
	}

	return PrintError(status);
}

void WINAPI ep(_PEB* /*peb*/)
{
	//while (!IsDebuggerPresent()) Sleep(1000); __debugbreak();

	ExitProcess(run());
}

_NT_END