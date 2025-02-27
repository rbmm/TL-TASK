#include "stdafx.h"

_NT_BEGIN

#include "log.h"

HRESULT GetLastErrorEx(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

extern const WCHAR ServiceName[] = L"RbmmTL";

void NTAPI ServiceMain(DWORD argc, PWSTR argv[]);

HRESULT WINAPI DllInstall(BOOL bInstall, _In_opt_ PCWSTR pszCmdLine)
{
	if (bInstall && pszCmdLine && '\n' == *pszCmdLine)
	{
		const static SERVICE_TABLE_ENTRY ste[] = { { const_cast<PWSTR>(ServiceName), ServiceMain }, {} };
		if (StartServiceCtrlDispatcher(ste))
		{
			return S_OK;
		}

		return GetLastHr();
	}

	return E_INVALIDARG;
}

struct ServiceData : SERVICE_NOTIFY
{
	ServiceData() { 
		RtlZeroMemory(this, sizeof(ServiceData)); 
		dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
		pfnNotifyCallback = ScNotifyCallback;
		pContext = this;
	}

	void OnScNotify()
	{
		DbgPrint("ScNotifyCallback(%u %08x %x %x pid=%x)\r\n", 
			dwNotificationStatus, dwNotificationTriggered, 
			ServiceStatus.dwCurrentState, ServiceStatus.dwCheckPoint, ServiceStatus.dwProcessId );
	}

	static VOID CALLBACK ScNotifyCallback (_In_ PVOID pParameter)
	{
		reinterpret_cast<ServiceData*>(pParameter)->OnScNotify();
	}
};

HRESULT WINAPI DllUnregisterServer()
{
	LOG(Init());

	HRESULT hr;

	if (SC_HANDLE hSCManager = HR(hr, OpenSCManagerW(NULL, NULL, 0 )))
	{
		SC_HANDLE hService = HR(hr, OpenServiceW(hSCManager, ServiceName, DELETE|SERVICE_STOP|SERVICE_QUERY_STATUS));
		
		CloseServiceHandle(hSCManager);
		
		if (hService)
		{
			ServiceData sd;

			if (HR(hr, ControlService(hService, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&sd.ServiceStatus)))
			{
				ULONG64 t_end = GetTickCount64() + 4000, t;

				DbgPrint("dwCurrentState=%x\r\n", sd.ServiceStatus.dwCurrentState);

				while (sd.ServiceStatus.dwCurrentState != SERVICE_STOPPED)
				{
					if (sd.dwNotificationStatus = NotifyServiceStatusChangeW(hService, 
						SERVICE_NOTIFY_CONTINUE_PENDING|
						SERVICE_NOTIFY_DELETE_PENDING|
						SERVICE_NOTIFY_PAUSE_PENDING|
						SERVICE_NOTIFY_PAUSED|
						SERVICE_NOTIFY_RUNNING|
						SERVICE_NOTIFY_START_PENDING|
						SERVICE_NOTIFY_STOP_PENDING|
						SERVICE_NOTIFY_STOPPED, &sd))
					{
						hr = sd.dwNotificationStatus;
						DbgPrint("SERVICE_CONTROL_STOP=%u\r\n", hr);
						break;
					}

					sd.dwNotificationStatus = ERROR_TIMEOUT;

					if ((t = GetTickCount64()) >= t_end ||
						WAIT_IO_COMPLETION != SleepEx((ULONG)(t_end - t), TRUE) ||
						NOERROR != sd.dwNotificationStatus)
					{
						break;
					}
				}

				if (sd.ServiceStatus.dwCurrentState != SERVICE_STOPPED)
				{
					hr = sd.dwNotificationStatus;
					DbgPrint("SERVICE_CONTROL_STOP=%u\r\n", hr);
				}
				else if (NOERROR == sd.dwNotificationStatus && sd.ServiceStatus.dwProcessId)
				{
					if (HANDLE hProcess = OpenProcess(SYNCHRONIZE, 0, sd.ServiceStatus.dwProcessId))
					{
						hr = WaitForSingleObject(hProcess, 1000);
						NtClose(hProcess);

						DbgPrint("WaitForSingleObject=%x\r\n", hr);
					}
				}
			}

			if (!HR(hr, DeleteService(hService)))
			{
				DbgPrint("DeleteService=%u\r\n", hr);
			}
			
			CloseServiceHandle(hService);
			ZwTestAlert();
		}
	}

	DbgPrint("%s=%x\r\n", __FUNCTION__, hr);

	LOG(Destroy());
	return hr;
}

HRESULT WINAPI DllRegisterServer()
{
	LOG(Init());

	HRESULT hr = STATUS_NO_MEMORY;

	if (PWSTR lpBinaryPathName = new WCHAR[MINSHORT])
	{
		STATIC_WSTRING(cmd, "\" /s /n /i:\"\n\" \"");
		if (ULONG cch = HR(hr, SearchPathW(0, L"regsvr32.exe", 0, MINSHORT - _countof(cmd), lpBinaryPathName + 1, 0)))
		{
			*lpBinaryPathName = '\"';
			PWSTR psz = lpBinaryPathName + cch + 1;
			ULONG len = MINSHORT - cch - 1;

			wcscpy_s(psz, len, cmd);

			if (ULONG s = HR(hr, GetModuleFileNameW((HMODULE)&__ImageBase, psz + _countof(cmd) - 1, len - _countof(cmd))))
			{
				psz[s + _countof(cmd) - 1] = '\"';
				psz[s + _countof(cmd)] = 0;

				if (SC_HANDLE hSCManager = HR(hr, OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE )))
				{
					if (SC_HANDLE hService = HR(hr, CreateServiceW(hSCManager, ServiceName, L"Rbmm TL Service", 
						SERVICE_START, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
						lpBinaryPathName, NULL, NULL, NULL, 0, NULL)))
					{
__ok:
						HR(hr, StartServiceW(hService, 0, 0));
						CloseServiceHandle(hService);

						if (HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING) == hr)
						{
							hr = S_OK;
						}
					}
					else if (HRESULT_FROM_WIN32(ERROR_SERVICE_EXISTS) == hr)
					{
						if (hService = HR(hr, OpenServiceW(hSCManager, ServiceName, SERVICE_START)))
						{
							goto __ok;
						}
					}

					CloseServiceHandle(hSCManager);
				}
			}
		}

		delete [] lpBinaryPathName;
	}
	
	DbgPrint("%s=%x\r\n", __FUNCTION__,hr);

	LOG(Destroy());

	return hr;
}

_NT_END