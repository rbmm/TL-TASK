#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "SvcBase.h"

class ClientPort
{
public:
	HANDLE _M_hPort = 0;

	~ClientPort()
	{
		if (_M_hPort)
		{
			NtClose(_M_hPort);
		}
		DbgPrint("%hs<%p>(%p)\r\n", __FUNCTION__, this, _M_hPort);
	}
};

typedef struct PS_CREATE_NOTIFY_INFO_U {
	_Inout_ NTSTATUS CreationStatus;
	union {
		_In_ ULONG Flags;
		struct {
			_In_ ULONG FileOpenNameAvailable : 1;
			_In_ ULONG IsSubsystemProcess : 1;
			_In_ ULONG LocalBuffer : 1;
			_In_ ULONG Reserved : 29;
		};
	};
	_In_ HANDLE ProcessId;
	_In_ HANDLE ParentProcessId;
	_In_ CLIENT_ID CreatingThreadId;
	_In_ PCWSTR ImageFileName;
	_In_ PCWSTR CommandLine;
} *PPS_CREATE_NOTIFY_INFO_U;

struct STR_PORT_MESSAGE : public PORT_MESSAGE 
{
	PS_CREATE_NOTIFY_INFO_U CreateInfo;
};

typedef struct SYSTEM_PROCESS_ID_INFORMATION
{
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} *PSYSTEM_PROCESS_ID_INFORMATION;

void PrintProcessName(HANDLE ProcessId)
{
	SYSTEM_PROCESS_ID_INFORMATION spii = { ProcessId, {0, 0x8000, new WCHAR[0x8000] }};
	if (spii.ImageName.Buffer)
	{
		if (0 <= NtQuerySystemInformation(SystemProcessIdInformation, &spii, sizeof(spii), 0))
		{
			DbgPrint("\t%x = \"%wZ\"\r\n", ProcessId, &spii.ImageName);
		}
		delete [] spii.ImageName.Buffer;
	}
}

void LpcServer(HANDLE PortHandle, PULONG pdwThread)
{
	union {
		ClientPort* pPort;
		void* PortCtx;
	};

	PPORT_MESSAGE ReplyMessage = 0;

	union {
		PORT_MESSAGE ReceiveMessage;
		STR_PORT_MESSAGE msg;
	};

	while (0 <= ZwReplyWaitReceivePort(PortHandle, &PortCtx, ReplyMessage, &ReceiveMessage))
	{
		ReplyMessage = 0;

		switch ((UCHAR)ReceiveMessage.u2.s2.Type)
		{
		case LPC_CONNECTION_REQUEST:
			DbgPrint("CONNECTION_REQUEST:%x,%x\r\n", (ULONG)(ULONG_PTR)ReceiveMessage.ClientId.UniqueThread, *pdwThread);
			if (ReceiveMessage.ClientId.UniqueThread == (HANDLE)(ULONG_PTR)*pdwThread && (pPort = new ClientPort))
			{
				msg.u1.s1.DataLength = sizeof(ULONG);
				msg.CreateInfo.CreationStatus = GetCurrentProcessId();

				if (0 <= NtAcceptConnectPort(&pPort->_M_hPort, PortCtx, &ReceiveMessage, TRUE, 0, 0))
				{
					NtCompleteConnectPort(pPort->_M_hPort);

					continue;
				}

				delete pPort;
			}
			else
			{
				HANDLE hPort;
				NtAcceptConnectPort(&hPort, 0, &ReceiveMessage, FALSE, 0, 0);
			}
			break;

		case LPC_PORT_CLOSED:
			if (pPort)
			{
				delete pPort;
			}
			break;

		case LPC_REQUEST:
			ReplyMessage = &ReceiveMessage;

			if (pPort)
			{
				if (sizeof(PS_CREATE_NOTIFY_INFO_U) == msg.u1.s1.DataLength)
				{
					DbgPrint("%x: %x(%x)-> %x <%ws> <%ws>\r\n", GetCurrentThreadId(), 
						(ULONG)(ULONG_PTR)msg.CreateInfo.CreatingThreadId.UniqueProcess,
						(ULONG)(ULONG_PTR)msg.CreateInfo.ParentProcessId,
						(ULONG)(ULONG_PTR)msg.CreateInfo.ProcessId,
						msg.CreateInfo.ImageFileName, msg.CreateInfo.CommandLine);

					msg.u1.s1.DataLength = 0;

					PrintProcessName(msg.CreateInfo.CreatingThreadId.UniqueProcess);

					if (msg.CreateInfo.CreatingThreadId.UniqueProcess != msg.CreateInfo.ParentProcessId)
					{
						PrintProcessName(msg.CreateInfo.ParentProcessId);
					}

					if (PWSTR pc = wcsrchr(msg.CreateInfo.ImageFileName, L'\\'))
					{
						if (!_wcsicmp(pc + 1, L"Firefox.exe"))
						{
							msg.u1.s1.DataLength = sizeof(NTSTATUS);
							msg.CreateInfo.CreationStatus = STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT;
						}
					}
				}
			}
			break;

		case LPC_DATAGRAM:
			DbgPrint("DATAGRAM:%x,%x\r\n", (ULONG)(ULONG_PTR)ReceiveMessage.ClientId.UniqueThread, *pdwThread);
			if (ReceiveMessage.ClientId.UniqueThread == (HANDLE)(ULONG_PTR)*pdwThread)
			{
				return ;
			}
			break;

		default: __debugbreak();
		}
	}
}

class CService : public CSvcBase
{
	HANDLE _M_hPort = 0;
	HANDLE _M_hFile = 0;
	HANDLE _M_hEvent = CreateEventW(0, TRUE, FALSE, 0);
	ULONG _M_random = ~GetTickCount();
	ULONG _M_dwThreadId = 0;
	LONG _M_dwRefCount = 1;
	LONG _M_dwWorkers = 1;

	void BeginWorker()
	{
		InterlockedIncrementNoFence(&_M_dwWorkers);
	}

	void EndWorker()
	{
		if (!InterlockedDecrement(&_M_dwWorkers))
		{
			SetEvent(_M_hEvent);
		}
	}

	virtual HRESULT Run();

	virtual DWORD Handler(
		DWORD    dwControl,
		DWORD    dwEventType,
		PVOID   lpEventData
		);

	static PCWSTR GetFmt()
	{
		return L"\\Device\\D8F86BDE6363440e821FB5F0B9C9FF4F\\RPC Control\\>%08x<";
	}

	NTSTATUS Create()
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		WCHAR buf[0x80];
		swprintf_s(buf, _countof(buf), _countof(L"Device\\D8F86BDE6363440e821FB5F0B9C9FF4F") + GetFmt(), _M_random);

		RtlInitUnicodeString(&ObjectName, buf);

		return NtCreatePort(&_M_hPort, &oa, LPC_MAX_CONNECTION_INFO_SIZE, sizeof(STR_PORT_MESSAGE), 0);
	}

	NTSTATUS DrvConnect()
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		WCHAR buf[0x80];
		swprintf_s(buf, _countof(buf), GetFmt(), _M_random);
		RtlInitUnicodeString(&ObjectName, buf);
		_M_dwThreadId = GetCurrentThreadId();
		IO_STATUS_BLOCK iosb;
		HANDLE hFile;
		NTSTATUS status = NtOpenFile(&hFile, WRITE_OWNER, &oa, &iosb, 0, 0);
		DbgPrint("%x> open=%x, heap at %p\r\n", GetCurrentThreadId(), status, iosb.Information);
		if (0 <= status)
		{
			if (hFile = InterlockedExchangePointer(&_M_hFile, hFile))
			{
				NtClose(hFile);
			}
		}
		return status;
	}

	void Stop(ULONG n = 4)
	{
		DbgPrint("%x> DrvDisconnect..\r\n", GetCurrentThreadId());

		_M_dwThreadId = GetCurrentThreadId();
		STR_PORT_MESSAGE msg {};
		msg.u1.s1.TotalLength = sizeof(STR_PORT_MESSAGE);
		do 
		{
			NtRequestPort(_M_hPort, &msg);
		} while (--n);
	}

	static ULONG WINAPI _S_LpcServer(void* param)
	{
		DbgPrint("%x> ++LpcServer\r\n", GetCurrentThreadId());
		LpcServer(reinterpret_cast<CService*>(param)->_M_hPort, &reinterpret_cast<CService*>(param)->_M_dwThreadId);
		DbgPrint("%x> --LpcServer\r\n", GetCurrentThreadId());

		reinterpret_cast<CService*>(param)->EndWorker();
		reinterpret_cast<CService*>(param)->Release();
		FreeLibraryAndExitThread((HMODULE)&__ImageBase, 0);
	}

	ULONG Start(ULONG n)
	{
		ULONG m = 0;
		do 
		{
			HMODULE hmod;
			if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCWSTR)&__ImageBase, &hmod))
			{
				AddRef();
				BeginWorker();
				if (HANDLE hThread = CreateThread(0, 0, _S_LpcServer, this, 0, 0))
				{
					NtClose(hThread);
					m++;
					continue;
				}
				EndWorker();
				Release();
				FreeLibrary(hmod);
			}
		} while (--n);

		return m;
	}

	~CService()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);

		if (_M_hEvent)
		{
			NtClose(_M_hEvent);
		}
	}
public:

	CService() 
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}

	void AddRef()
	{
		InterlockedIncrementNoFence(&_M_dwRefCount);
	}

	void Release()
	{
		if (!InterlockedDecrement(&_M_dwRefCount))
		{
			delete this;
		}
	}

	void Close()
	{
		if (HANDLE h = InterlockedExchangePointer(&_M_hFile, 0))
		{
			NtClose(h);
		}
	}
};

HRESULT CService::Run()
{
	HRESULT hr = SetState(0);

	if (NOERROR == hr)
	{
		BOOLEAN bEnabled;
		RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &bEnabled);
		UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TL-DRV");

		switch (NTSTATUS status = ZwLoadDriver(&Name))
		{
		case STATUS_SUCCESS:
		case STATUS_IMAGE_ALREADY_LOADED:
			if (0 <= (status = Create()))
			{
				if (Start(4))
				{
					if (0 <= DrvConnect())
					{
						SetState(SERVICE_RUNNING, SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_PAUSE_CONTINUE);
						EndWorker();
						WaitForSingleObject(_M_hEvent, INFINITE);
					}
					Stop();
				}
			}
			else
			{
				DbgPrint("create=%x\r\n", status);
			}
			ZwUnloadDriver(&Name);
			break;
		default:
			DbgPrint("LoadDriver=%x\r\n", status);
		}
	}

	return hr;
}

DWORD CService::Handler( DWORD dwControl, DWORD , PVOID  )
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_STOP:
		Close();
		Stop();
		return NOERROR;

	case SERVICE_CONTROL_PAUSE:
		Close();
		SetState(SERVICE_PAUSED, SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_PAUSE_CONTINUE);
		return NOERROR;

	case SERVICE_CONTROL_CONTINUE:
		SetState(0 > DrvConnect() ? SERVICE_PAUSED : SERVICE_RUNNING, SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_PAUSE_CONTINUE);
		return NOERROR;
	}
	return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
}

void NTAPI ServiceMain(DWORD argc, PWSTR argv[])
{
	LOG(Init());

	if (argc)
	{
		if (CService* p = new CService)
		{
			DbgPrint("++ ServiceMain\r\n");
			p->ServiceMain(argv[0]);
			DbgPrint("-- ServiceMain\r\n");
			p->Close();
			p->Release();
		}
	}

	LOG(Destroy());
}

_NT_END