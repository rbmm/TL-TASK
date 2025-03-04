#include "stdafx.h"

_NT_BEGIN

PVOID _G_Port;
PEPROCESS _G_Process;
PVOID _G_pvUser, _G_heap, _G_hHeap;
ULONG_PTR _G_Delta;
EX_RUNDOWN_REF _G_RunRef;
EX_PUSH_LOCK _G_PushLock;
ERESOURCE _G_Lock;

EXTERN_C __declspec(dllimport) POBJECT_TYPE* LpcPortObjectType;

typedef struct PS_CREATE_NOTIFY_INFO_U {
	_Inout_ NTSTATUS CreationStatus;
	union {
		_In_ ULONG Flags;
		struct {
			_In_ ULONG FileOpenNameAvailable : 1;
			_In_ ULONG IsSubsystemProcess : 1;
			_In_ ULONG Reserved : 30;
		};
	};
	_In_ HANDLE ProcessId;
	_In_ HANDLE ParentProcessId;
	_In_ CLIENT_ID CreatingThreadId;
	_In_ ULONG_PTR ImageFileName;
	_In_ ULONG_PTR CommandLine;
} *PPS_CREATE_NOTIFY_INFO_U;

#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2 // 
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000 // dbg
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000 // dbg
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000 // dbg

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
LpcSendWaitReceivePort(_In_ PVOID Port,
	_In_ ULONG Flags,
	_In_ PPORT_MESSAGE SendMessage,
	_Out_ PPORT_MESSAGE ReceiveMessage,
	_Inout_opt_ PSIZE_T BufferLength,
	_In_opt_ PLARGE_INTEGER Timeout);

struct STR_PORT_MESSAGE : public PORT_MESSAGE
{
	PS_CREATE_NOTIFY_INFO_U CreateInfo;
};

VOID NTAPI CreateProcessNotifyEx(_Inout_ PEPROCESS /*Process*/,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo)
	{
		DbgPrint("%hs (%p %p %p.%p %p \"%wZ\" %p \"%wZ\")\n", __FUNCTION__,
			ProcessId,
			CreateInfo->ParentProcessId,
			CreateInfo->CreatingThreadId.UniqueProcess, CreateInfo->CreatingThreadId.UniqueThread,
			CreateInfo->ImageFileName->Buffer, CreateInfo->FileOpenNameAvailable ? CreateInfo->ImageFileName : 0,
			CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine);

		if (ExAcquireRundownProtection(&_G_RunRef))
		{
			STR_PORT_MESSAGE msg{};

			union {
				PVOID BaseAddress = 0;
				PWSTR buf;
			};

			int len = 0;
			NTSTATUS status = 0;

			__try
			{
				while (0 < (len = _snwprintf(buf, len, L"%wZ%c%wZ", CreateInfo->ImageFileName, 0, CreateInfo->CommandLine)))
				{
					if (buf)
					{

						msg.u1.s1.DataLength = sizeof(PS_CREATE_NOTIFY_INFO_U);
						msg.u1.s1.TotalLength = sizeof(STR_PORT_MESSAGE);

						PPS_CREATE_NOTIFY_INFO_U pCreateInfo = &msg.CreateInfo;

						pCreateInfo->CreatingThreadId = CreateInfo->CreatingThreadId;
						pCreateInfo->CreationStatus = CreateInfo->CreationStatus;
						pCreateInfo->Flags = pCreateInfo->Flags;
						pCreateInfo->ParentProcessId = CreateInfo->ParentProcessId;
						pCreateInfo->ProcessId = ProcessId;

						pCreateInfo->ImageFileName = (ULONG_PTR)buf - _G_Delta;
						pCreateInfo->CommandLine = (ULONG_PTR)(buf + wcslen(buf) + 1) - _G_Delta;

						if (STATUS_NOT_SUPPORTED == (status = LpcRequestWaitReplyPort(_G_Port, &msg, &msg)))
						{
							SIZE_T s = sizeof(msg);
							status = LpcSendWaitReceivePort(_G_Port, ALPC_MSGFLG_SYNC_REQUEST, &msg, &msg, &s, 0);
						}

						if (0 <= status)
						{
							CreateInfo->CreationStatus = msg.CreateInfo.CreationStatus;
						}

						break;
					}

					if (BaseAddress = RtlAllocateHeap(_G_hHeap, 0, ++len * sizeof(WCHAR)))
					{
						//DbgPrint("++ %p\n", BaseAddress);
					}
					else
					{
						break;
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}

			if (BaseAddress)
			{
				RtlFreeHeap(_G_hHeap, 0, BaseAddress);
				//DbgPrint("-- %p\n", BaseAddress);
			}

			ExReleaseRundownProtection(&_G_RunRef);

			DbgPrint("status = %x(%x)\n", status, CreateInfo->CreationStatus);
		}
	}
}

PDEVICE_OBJECT _G_DeviceObject;

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("%hs (%p)\n", __FUNCTION__, DriverObject);

	if (_G_DeviceObject)
	{
		IoDeleteDevice(_G_DeviceObject);
	}

	ExDeleteResourceLite(&_G_Lock);
}

NTSTATUS NTAPI CommitRoutine(IN PVOID Base,
	IN OUT PVOID* CommitAddress,
	IN OUT PSIZE_T CommitSize
)
{
	DbgPrint("CommitRoutine(%p %p %x)\n", Base, *CommitAddress, CommitSize);
	return 0;
}

#define SEC_NO_CHANGE 0x00400000

NTSTATUS NTAPI OnCreate(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
{
	PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

	DbgPrint("%hs(%p, \"%wZ\")\n", __FUNCTION__, FileObject, &FileObject->FileName);

	Irp->IoStatus.Information = 0;
	ULONG dwProcessId = 0;
	ULONG BufferLength = sizeof(dwProcessId);
	ULONG MaxMessageLength;

	static const SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };

	HANDLE PortHandle;
	PVOID Port;
	STR_PORT_MESSAGE msg{};

	NTSTATUS status = ZwConnectPort(&PortHandle, &FileObject->FileName,
		const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos), 0, 0, &MaxMessageLength, &dwProcessId, &BufferLength);

	DbgPrint("ConnectPort=%x\n", status);

	if (0 <= status)
	{
		status = ObReferenceObjectByHandle(PortHandle, 0, *LpcPortObjectType, KernelMode, &Port, 0);

		NtClose(PortHandle);

		DbgPrint("Port=%p, %x\n", Port, status);

		if (0 <= status)
		{
			HANDLE hSection;
			enum { cbSection = 0x40000 }; // 256Kb
			LARGE_INTEGER li = { cbSection };

			if (0 <= (status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, 
				0, &li, PAGE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, 0)))
			{
				PVOID Section;
				
				status = ObReferenceObjectByHandle(hSection, 0, 0, KernelMode, &Section, 0);
				
				NtClose(hSection);

				if (0 <= status)
				{
					PVOID BaseAddress = 0;
					SIZE_T ViewSize = 0;

					PEPROCESS Process = PsGetCurrentProcess();
					LARGE_INTEGER offset = {};

					if (0 <= (status = MmMapViewOfSection(Section, Process, &BaseAddress,
						0, 0, &offset, &ViewSize, ViewUnmap, MEM_TOP_DOWN, PAGE_READONLY)))
					{
						DbgPrint("MmMapViewOfSection=%p", BaseAddress);

						PVOID MappedBase = 0;

						if (0 <= (status = MmMapViewInSystemSpace(Section, &MappedBase, &(ViewSize = 0))))
						{
							DbgPrint("MmMapViewInSystemSpace=%p", MappedBase);

							RTL_HEAP_PARAMETERS hp = { sizeof(hp), 0, 0, 0, 0, 0, 0, cbSection, cbSection, CommitRoutine };

							if (PVOID hHeap = RtlCreateHeap(0, MappedBase, 0, cbSection, &_G_Lock, &hp))
							{
								DbgPrint("RtlCreateHeap=%p\n", hHeap);

								KeEnterCriticalRegion();
								ExfAcquirePushLockExclusive(&_G_PushLock);

								if (_G_Port)
								{
									status = STATUS_PORT_ALREADY_SET;
								}
								else
								{
									FileObject->FsContext = Port;

									_G_Port = Port, Port = 0;
									ObfReferenceObject(_G_Process = Process);

									Irp->IoStatus.Information = (ULONG_PTR)BaseAddress;

									_G_pvUser = BaseAddress;
									_G_heap = MappedBase;
									_G_hHeap = hHeap;
									_G_Delta = (ULONG_PTR)MappedBase - (ULONG_PTR)BaseAddress;

									ExReInitializeRundownProtection(&_G_RunRef);

									status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);

									DbgPrint("Port Set = %x (%p) !!\n", status, _G_Delta);
								}

								ExfReleasePushLockExclusive(&_G_PushLock);
								KeLeaveCriticalRegion();

								if (0 <= status)
								{
									goto __exit;
								}

								RtlDestroyHeap(hHeap);
							}

							MmUnmapViewInSystemSpace(MappedBase);
						}
					}

					MmUnmapViewOfSection(Process, BaseAddress);
				}
			}

			ObfDereferenceObject(Port);
		}
	}

__exit:
	Irp->IoStatus.Status = status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnCleanup(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
{
	PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

	DbgPrint("%hs(%p, %p)\n", __FUNCTION__, FileObject, FileObject->FsContext);

	KeEnterCriticalRegion();
	ExfAcquirePushLockExclusive(&_G_PushLock);

	PVOID Port = 0;
	PEPROCESS Process = 0;
	PVOID pvUser = 0, heap = 0, hHeap = 0;

	if (_G_Port && _G_Port == FileObject->FsContext)
	{
		PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
		ExWaitForRundownProtectionRelease(&_G_RunRef);

		Port = _G_Port, _G_Port = 0;
		Process = _G_Process, _G_Process = 0;
		FileObject->FsContext = 0;

		heap = _G_heap, _G_heap = 0;
		hHeap = _G_hHeap, _G_hHeap = 0;
		pvUser = _G_pvUser, _G_pvUser = 0;
	}

	ExfReleasePushLockExclusive(&_G_PushLock);
	KeLeaveCriticalRegion();

	if (Port)
	{
		RtlDestroyHeap(hHeap);
		MmUnmapViewInSystemSpace(heap);
		MmUnmapViewOfSection(Process, pvUser);

		ObfDereferenceObject(Process);
		ObfDereferenceObject(Port);

		DbgPrint("Port removed %p %p %p !!\n", Port, pvUser, heap);
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnClose(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
{
	DbgPrint("%hs\n", __FUNCTION__);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

EXTERN_C
NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreate;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = OnCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnClose;

	ExRundownCompleted(&_G_RunRef);

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\D8F86BDE6363440e821FB5F0B9C9FF4F");

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &_G_DeviceObject);

	if (0 <= status)
	{
		_G_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	ExInitializeResourceLite(&_G_Lock);

	DbgPrint("%hs(%p, %p, %wZ)=%x\n", __FUNCTION__, DriverObject, _G_DeviceObject, RegistryPath, status);

	return status;
}

_NT_END