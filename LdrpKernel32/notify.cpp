#include "StdAfx.h"

_NT_BEGIN

#include "log.h"

VOID CALLBACK LdrDllNotification(
								 _In_     LDR_DLL_NOTIFICATION_REASON NotificationReason,
								 _In_     PCLDR_DLL_NOTIFICATION_DATA NotificationData,
								 _In_opt_ PVOID                       /*Context*/
								 )
{
	DbgPrint("%x %p %wZ\r\n", NotificationReason, NotificationData->DllBase, NotificationData->FullDllName);
}

#ifdef _M_IX86
#pragma warning(disable: 4483) // Allow use of __identifier
#define __imp_LdrRegisterDllNotification __identifier("_imp__LdrRegisterDllNotification@16")
#define __imp_LdrUnregisterDllNotification __identifier("_imp__LdrUnregisterDllNotification@4")
#endif

EXTERN_C_START

PVOID __imp_LdrRegisterDllNotification, __imp_LdrUnregisterDllNotification;

EXTERN_C_END

BOOL LdrR()
{
	union {
		ANSI_STRING as;
		UNICODE_STRING DllName;
	};

	RtlInitUnicodeString(&DllName, L"ntdll.dll");

	HMODULE hmod;
	if (0 <= LdrGetDllHandle(0, 0, &DllName, &hmod))
	{
		RtlInitString(&as, "LdrRegisterDllNotification");
		if (0 <= LdrGetProcedureAddress(hmod, &as, 0, &__imp_LdrRegisterDllNotification))
		{
			RtlInitString(&as, "LdrUnregisterDllNotification");
			if (0 <= LdrGetProcedureAddress(hmod, &as, 0, &__imp_LdrUnregisterDllNotification))
			{
				return TRUE;
			}
			
		}
	}
	return FALSE;
}

BOOLEAN WINAPI DllMain( HMODULE hmod, DWORD ul_reason_for_call, PVOID)
{
	static PVOID gCookie;

	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH:
		if (!LdrR())
		{
			return FALSE;
		}
		LdrDisableThreadCalloutsForDll(hmod);
		Log::Init();
		DbgPrint("ATTACH:\r\n");
		LdrRegisterDllNotification(0, LdrDllNotification, 0, &gCookie);
		break;

	case DLL_PROCESS_DETACH:
		if (gCookie) LdrUnregisterDllNotification(gCookie);
		DbgPrint("DETACH:\r\n");
		Log::Close();
		break;
	}

	return TRUE;
}

_NT_END