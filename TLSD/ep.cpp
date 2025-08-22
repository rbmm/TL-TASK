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

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
RtlGetControlSecurityDescriptor(
	_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
	_Out_ PSECURITY_DESCRIPTOR_CONTROL pControl,
	_Out_ PULONG lpdwRevision
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

BOOL IsTrustedSD(PSECURITY_DESCRIPTOR SecurityDescriptor)
{
	PACL Acl;
	BOOLEAN bPresent, bDefault;
	if (SecurityDescriptor && 
		0 <= RtlGetSaclSecurityDescriptor(SecurityDescriptor, &bPresent, &Acl, &bDefault) && 
		bPresent && Acl)
	{
		if (ULONG AceCount = Acl->AceCount)
		{
			union {
				PVOID pv;
				PBYTE pb;
				PACE_HEADER ph;
				PACCESS_ALLOWED_ACE pah;
			};

			pv = Acl + 1;

			do
			{
				switch (ph->AceType)
				{
				case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
					PSID Sid = &pah->SidStart;
					static const SID_IDENTIFIER_AUTHORITY pta = SECURITY_PROCESS_TRUST_AUTHORITY;
					if (SECURITY_PROCESS_TRUST_AUTHORITY_RID_COUNT == *RtlSubAuthorityCountSid(Sid) &&
						!memcmp(&pta, RtlIdentifierAuthoritySid(Sid), sizeof(pta)))
					{
						if (*RtlSubAuthoritySid(Sid, 0) || *RtlSubAuthoritySid(Sid, 1))
						{
							return TRUE;
						}
					}
				}
			} while (pb += ph->AceSize, --AceCount);
		}
	}

	return FALSE;
}

NTSTATUS NTAPI OnCreate(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	Irp->IoStatus.Information = 0;

	OBJECT_ATTRIBUTES oa = {
		sizeof(oa), 0, &FileObject->FileName, 0,
		IrpSp->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor
	};

	NTSTATUS status = STATUS_INVALID_PARAMETER;
	HANDLE hFile = 0;

	if (IsTrustedSD(oa.SecurityDescriptor))
	{
		ACCESS_MASK DesiredAccess = IrpSp->Parameters.Create.SecurityContext->DesiredAccess;

		status = STATUS_ACCESS_DENIED;

		if (FILE_WRITE_DATA & DesiredAccess)
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
				DbgPrint("hfile=[%p]\n", hFile);

				status = ObDuplicateObject(PsInitialSystemProcess, hFile, IoGetCurrentProcess(),
					&hFile, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE, KernelMode);

				DbgPrint("ObDuplicateObject=%x [%p]\n", status, hFile);
			}
		}
	}

	DbgPrint("%hs(\"%wZ\")=%x\n", __FUNCTION__, &FileObject->FileName, status);

	if (0 <= status)
	{
		status = STATUS_SINGLE_STEP;
		Irp->IoStatus.Information = (ULONG_PTR)hFile;
	}

	Irp->IoStatus.Status = status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI OnCloseCleanup(_In_ PDEVICE_OBJECT /*DeviceObject*/, _Inout_ PIRP Irp)
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
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = OnCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCloseCleanup;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\D8F86BDE6363440e821FB5F0B9C9FF4F");

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &DeviceName, 
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &_G_DeviceObject);

	if (0 <= status)
	{
		_G_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	DbgPrint("%hs(%p, %p, %wZ)=%x\n", __FUNCTION__, DriverObject, _G_DeviceObject, RegistryPath, status);

	return status;
}

_NT_END