#include "stdafx.h"

_NT_BEGIN

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
ObDuplicateObject(
	_In_ PEPROCESS SourceProcess,
	_In_ HANDLE SourceHandle,
	_In_opt_ PEPROCESS TargetProcess,
	_Out_opt_ PHANDLE TargetHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Options,
	_In_ KPROCESSOR_MODE PreviousMode
);

PDEVICE_OBJECT _G_DeviceObject;

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("%hs (%p)\n", __FUNCTION__, DriverObject);

	if (_G_DeviceObject)
	{
		IoDeleteDevice(_G_DeviceObject);
	}
}

NTSTATUS NTAPI OnCreate(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	Irp->IoStatus.Information = 0;

	OBJECT_ATTRIBUTES oa = {
		sizeof(oa), 0, &FileObject->FileName, OBJ_KERNEL_HANDLE,
		IrpSp->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor
	};

	NTSTATUS status = STATUS_INVALID_PARAMETER;
	HANDLE hFile = 0;

	ACCESS_MASK DesiredAccess = IrpSp->Parameters.Create.SecurityContext->DesiredAccess;

	status = STATUS_ACCESS_DENIED;

	if ((FILE_WRITE_DATA & DesiredAccess) && (KernelMode != ExGetPreviousMode()))
	{
		IO_STATUS_BLOCK iosb;
		ULONG Options = IrpSp->Parameters.Create.Options;
		KAPC_STATE ApcState;
		KeStackAttachProcess(PsInitialSystemProcess, &ApcState);

		status = ZwCreateFile(&hFile, DesiredAccess,
			&oa, &iosb, &Irp->Overlay.AllocationSize, IrpSp->Parameters.Create.FileAttributes,
			IrpSp->Parameters.Create.ShareAccess, Options >> 24, Options & 0x00FFFFFF,
			Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.Create.EaLength);

		KeUnstackDetachProcess(&ApcState);

		if (0 <= status)
		{
			//DbgPrint("h=%p\n", hFile);
			status = ObDuplicateObject(IoGetCurrentProcess(), hFile, IoGetCurrentProcess(),
				(PHANDLE)&Irp->IoStatus.Information, 0, 0, DUPLICATE_SAME_ACCESS, KernelMode);
			if (0 > ZwClose(hFile)) KeBugCheckEx(BAD_EXHANDLE, (ULONG_PTR)hFile, 0, 0, 0);
		}
	}

	DbgPrint("%hs(\"%wZ\")=%x\n", __FUNCTION__, &FileObject->FileName, status);

	if (0 <= status)
	{
		status = STATUS_SINGLE_STEP;
	}

	Irp->IoStatus.Status = status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnCloseCleanup(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
{
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
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = OnCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCloseCleanup;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\D8F86BDE6363440e821FB5F0B9C9FF4F");

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &DeviceName, 
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &_G_DeviceObject);

	if (0 <= status)
	{
		_G_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	DbgPrint("%hs(%p, %p, %wZ)=%x [" __DATE__ " " __TIME__ "]\n",
		__FUNCTION__, DriverObject, _G_DeviceObject, RegistryPath, status);

	return status;
}

_NT_END