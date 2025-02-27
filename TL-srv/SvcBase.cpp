#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "SvcBase.h"

CSvcBase::CSvcBase()
{
	InitializeSRWLock(&m_SRWLock);
}

CSvcBase::~CSvcBase()
{
}

ULONG WINAPI CSvcBase::HandlerEx(
								 ULONG dwControl,
								 ULONG dwEventType,
								 PVOID lpEventData,
								 PVOID lpContext
								 )
{
	DbgPrint("HandlerEx<%p>(%x %x %p)\n", lpContext, dwControl, dwEventType, lpEventData);
	return static_cast<CSvcBase*>(lpContext)->PreHandler(dwControl, dwEventType, lpEventData);
}

ULONG CSvcBase::PreHandler(ULONG dwControl)
{
	switch(dwControl)
	{
	case SERVICE_CONTROL_CONTINUE:

		if (SERVICE_PAUSED != dwCurrentState || 
			!BeginChangeState(SERVICE_ACCEPT_PAUSE_CONTINUE, SERVICE_CONTINUE_PENDING, SERVICE_RUNNING))
		{
			return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
		}
		break;

	case SERVICE_CONTROL_PAUSE:

		if (SERVICE_RUNNING != dwCurrentState ||
			!BeginChangeState(SERVICE_ACCEPT_PAUSE_CONTINUE, SERVICE_PAUSE_PENDING, SERVICE_PAUSED))
		{
			return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
		}
		break;

	case SERVICE_CONTROL_STOP:

		if (!BeginChangeState(SERVICE_ACCEPT_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED))
		{
			return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
		}
		break;
	}

	return SetServiceStatus(m_statusHandle, this) ? NOERROR : GetLastError();
}

ULONG CSvcBase::PreHandler(ULONG dwControl, ULONG dwEventType, PVOID lpEventData)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_INTERROGATE:
	case SERVICE_CONTROL_SESSIONCHANGE:
	case SERVICE_CONTROL_DEVICEEVENT:
		return NOERROR;

	case SERVICE_CONTROL_CONTINUE:
	case SERVICE_CONTROL_PAUSE:
	case SERVICE_CONTROL_STOP:
		LockState();
		ULONG err = PreHandler(dwControl);
		UnlockState();
		if (err)
		{
			return err;
		}
	}

	return Handler(dwControl, dwEventType, lpEventData);
}

ULONG CSvcBase::SetState(ULONG WaitHint)
{
	if (!WaitHint) WaitHint = GetWaitHint();

	ULONG err = ERROR_INVALID_STATE;

	LockState();

	if (dwCheckPoint)
	{
		dwCheckPoint++;
		dwWaitHint = WaitHint;
		err = SetServiceStatus(m_statusHandle, this) ? NOERROR : GetLastError();
	}

	UnlockState();

	return err;
}

ULONG CSvcBase::SetState(ULONG NewState, ULONG ControlsAccepted, ULONG Win32ExitCode)
{
	LockState();

	if (dwCurrentState != NewState)
	{
		dwCurrentState = NewState;
		dwControlsAccepted = ControlsAccepted;
		if (Win32ExitCode & FACILITY_NT_BIT)
		{
			Win32ExitCode = (dwServiceSpecificExitCode = Win32ExitCode & ~FACILITY_NT_BIT) ? ERROR_SERVICE_SPECIFIC_ERROR : NOERROR;
		}
		dwWin32ExitCode = Win32ExitCode;
		dwCheckPoint = 0;
		dwWaitHint = 0;

		Win32ExitCode = SetServiceStatus(m_statusHandle, this) ? NOERROR : GetLastError();
	}

	UnlockState();

	return Win32ExitCode;
}

BOOL CSvcBase::BeginChangeState(ULONG MustAccept, ULONG dwNewState, ULONG dwTargetState)
{
	if (dwCheckPoint || !(dwControlsAccepted & MustAccept)) return FALSE;

	dwCurrentState = dwNewState;
	dwCheckPoint = 1;
	dwWaitHint = GetWaitHint();
	dwControlsAccepted &= ~(SERVICE_CONTROL_CONTINUE|SERVICE_CONTROL_PAUSE|SERVICE_CONTROL_STOP);

	m_dwTargetState = dwTargetState;

	return TRUE;
}

HRESULT CSvcBase::ServiceMain(PCWSTR ServiceName)
{
	m_dwTargetState = SERVICE_RUNNING;

	dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
	dwCurrentState = SERVICE_START_PENDING;
	dwControlsAccepted = 0;
	dwWin32ExitCode = NOERROR;
	dwServiceSpecificExitCode = 0;
	dwCheckPoint = 1;
	dwWaitHint = GetWaitHint();

	if (m_statusHandle = RegisterServiceCtrlHandlerEx(ServiceName, HandlerEx, this))
	{
		SetState(SERVICE_STOPPED, 0, Run());

		return dwWin32ExitCode;
	}

	return HRESULT_FROM_WIN32(GetLastError());
}

_NT_END