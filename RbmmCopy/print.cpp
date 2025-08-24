#include "stdafx.h"

_NT_BEGIN

#include "print.h"

void PutChars(PWSTR pwz, ULONG cch)
{
	enum { len_cc = 0x40 };

	if ((2 * len_cc + 3) < cch)
	{
		pwz[len_cc]     = ' ';
		pwz[len_cc + 1] = '*';
		pwz[len_cc + 2] = ' ';
		memcpy(pwz + len_cc + 3, pwz + cch - (len_cc + 1), (1 + len_cc) * sizeof(WCHAR));
		cch = 2 * len_cc + 3;
	}

	if (PrintInfo* ppi = PrintInfo::get())
	{
		PSTR buf = 0;
		ULONG len = 0;
		while (len = WideCharToMultiByte(ppi->_G_CodePage, 0, pwz, cch, buf, len, 0, 0))
		{
			if (buf)
			{
				break;
			}

			if (!(buf = (PSTR)_malloca(len)))
			{
				break;
			}
		}

		if (IsDebuggerPresent())
		{
			ULONG_PTR params[] = { cch, (ULONG_PTR)pwz, len, (ULONG_PTR)buf };
			RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, _countof(params), params);
		}

		if (ppi->_G_hFile)
		{
			if (ppi->_G_bConsole)
			{
				WriteConsoleW(ppi->_G_hFile, pwz, cch, &cch, 0);
			}
			else
			{
				WriteFile(ppi->_G_hFile, buf, len, &len, 0);

			}
		}

		if (buf)
		{
			_freea(buf);
		}
	}
}

void PrintWA_v(PCWSTR format, ...)
{
	va_list ap;
	va_start(ap, format);

	PWSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnwprintf(buf, len, format, ap)))
	{
		if (buf)
		{
			PutChars(buf, len);
			break;
		}

		++len;
		if (!(buf = (PWSTR)_malloca(len * sizeof(WCHAR))))
		{
			break;
		}
	}

	if (buf)
	{
		_freea(buf);
	}

	va_end(ap);
}

HRESULT PrintError(HRESULT dwError)
{
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		lpSource = GetModuleHandle(L"ntdll");
	}

	PWSTR lpText;
	if (ULONG cch = FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		PutChars(lpText, cch);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return dwError;
}

void InitPrintf()
{
	if (PrintInfo* ppi = PrintInfo::get())
	{
		ppi->_G_CodePage = GetConsoleOutputCP();
		ppi->_G_hFile = 0;

		if (HANDLE hFile = GetStdHandle(STD_OUTPUT_HANDLE))
		{
			ppi->_G_hFile = hFile;
			FILE_FS_DEVICE_INFORMATION ffdi;
			IO_STATUS_BLOCK iosb;
			if (0 <= NtQueryVolumeInformationFile(hFile, &iosb, &ffdi, sizeof(ffdi), FileFsDeviceInformation))
			{
				switch (ffdi.DeviceType)
				{
				case FILE_DEVICE_CONSOLE:
					ppi->_G_bConsole = TRUE;
					break;
				}
			}
		}
	}
}

_NT_END