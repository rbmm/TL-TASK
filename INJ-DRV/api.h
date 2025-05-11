#pragma once

enum SYSTEM_DLL_TYPE {
	PsNativeSystemDll,
	PsWowX86SystemDll,
	PsWowArm32SystemDll,
	PsWowAmd64SystemDll,
	PsWowChpeX86SystemDll,
	PsVsmEnclaveRuntimeDll,
	PsSystemDllTotalTypes
};

struct EWOW64PROCESS {
	/*0000*/ void* Peb;
	/*0008*/ USHORT Machine;
	/*000c*/ SYSTEM_DLL_TYPE NtdllType;
	/*0010*/
};

EXTERN_C_START

NTSYSAPI
NTSTATUS
NTAPI
RtlImageNtHeaderEx(_In_ ULONG Flags, _In_ PVOID BaseOfImage, _In_ ULONG64 Size, _Out_ PIMAGE_NT_HEADERS* OutHeaders);

NTKERNELAPI
PVOID // Peb
NTAPI
PsGetProcessWow64Process(_In_ PEPROCESS Process);

NTKERNELAPI
USHORT
NTAPI
PsWow64GetProcessMachine(_In_ PEPROCESS Process);

NTSYSAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(_In_ PEPROCESS Process);

NTSYSAPI
BOOLEAN 
NTAPI 
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

EXTERN_C_END
