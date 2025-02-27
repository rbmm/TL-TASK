#pragma once

struct DECLSPEC_NOVTABLE CSvcBase : protected SERVICE_STATUS 
{
	BOOL BeginChangeState(ULONG MustAccept, ULONG dwNewState, ULONG dwTargetState);

protected:

	static ULONG WINAPI HandlerEx(
		ULONG    dwControl,
		ULONG    dwEventType,
		PVOID   lpEventData,
		PVOID   lpContext
		);

	ULONG PreHandler(ULONG dwControl);

	ULONG PreHandler(ULONG dwControl, ULONG dwEventType, PVOID lpEventData);

	SRWLOCK m_SRWLock;
	SERVICE_STATUS_HANDLE m_statusHandle;
	ULONG m_dwTargetState;

	virtual ULONG GetWaitHint()
	{
		return 2000;
	}

	ULONG IsTransitiveState()
	{
		return dwCheckPoint;
	}

	virtual HRESULT Run() = 0;

	virtual ULONG Handler(
		ULONG    dwControl,
		ULONG    dwEventType,
		PVOID   lpEventData
		) = 0;

	ULONG SetState(ULONG NewState, ULONG ControlsAccepted, ULONG Win32ExitCode = NOERROR);

	ULONG SetState(ULONG WaitHint = 0);

	ULONG GetState() { return dwCurrentState; }

	void LockState()
	{
		AcquireSRWLockExclusive(&m_SRWLock);
	}

	void UnlockState()
	{
		ReleaseSRWLockExclusive(&m_SRWLock);
	}

public:

	HRESULT ServiceMain(PCWSTR ServiceName);

	CSvcBase();

	virtual ~CSvcBase();
};
