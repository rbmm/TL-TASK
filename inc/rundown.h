#pragma once

#include "mini_yvals.h"

class RundownProtection
{
	LONG _Value;

public:

	enum {
		v_complete = 0, v_init = 1 << 31
	};

	BOOL IsRundownCompleted()
	{
		return v_complete == _Value;
	}

	_NODISCARD BOOL IsRundownBegin()
	{
		return 0 <= _Value;
	}

	_NODISCARD BOOL Acquire()
	{
		LONG Value, NewValue;

		if (0 > (Value = _Value))
		{
			do 
			{
				NewValue = InterlockedCompareExchangeNoFence(&_Value, Value + 1, Value);

				if (NewValue == Value) return TRUE;

			} while (0 > (Value = NewValue));
		}

		return FALSE;
	}

	_NODISCARD BOOL Release()
	{
		return InterlockedDecrement(&_Value) == v_complete;
	}

	// if (Acquire()) { Rundown_l(); Release(); }
	void Rundown_l()
	{
		InterlockedBitTestAndReset(&_Value, 31);
	}

	RundownProtection(LONG Value = v_complete) : _Value(Value)
	{
	}

	BOOL Init()
	{
		return InterlockedCompareExchange(&_Value, v_init, v_complete) == v_complete;
	}
};

class __declspec(novtable) RUNDOWN_REF : public RundownProtection
{
protected:

	virtual void RundownCompleted() = 0;

public:

	void BeginRundown()
	{
		if (Acquire())
		{
			Rundown_l();
			Release();
		}
	}

	void Release()
	{
		if (RundownProtection::Release())
		{
			RundownCompleted();
		}
	}

	RUNDOWN_REF(LONG Value = RundownProtection::v_init) : RundownProtection(Value) {}
};

//  */<memory>*/ bool _Ref_count_base::_Incref_nz()
// increment (*pLock) if not zero, return true if successful
inline _NODISCARD BOOL ObpLock(PLONG pLock)
{
	LONG Value, NewValue;

	if (Value = *pLock)
	{
		do 
		{
			NewValue = InterlockedCompareExchangeNoFence(pLock, Value + 1, Value);

			if (NewValue == Value) return TRUE;

		} while (Value = NewValue);
	}

	return FALSE;
}

struct UYRundown 
{
	ULONG _dwThreadId = GetCurrentThreadId();
	RundownProtection _rp = RundownProtection::v_init;
	LONG _dwRefCount = 1;

	void AddRef()
	{
		InterlockedIncrementNoFence(&_dwRefCount);
	}

	void Release()
	{
		if (!InterlockedDecrement(&_dwRefCount))
		{
			delete this;
		}
	}

	_NODISCARD BOOL AcquireProtection()
	{
		return _rp.Acquire();
	}

	void ReleaseProtection()
	{
		if (_rp.Release())
		{
			ZwAlertThreadByThreadId((HANDLE)(ULONG_PTR)_dwThreadId);
		}
	}

	void RunDown()
	{
		if (GetCurrentThreadId() != _dwThreadId) __debugbreak();

		if (_rp.Acquire()) 
		{ 
			_rp.Rundown_l(); 

			if (!_rp.Release())
			{
				do 
				{
					ZwWaitForAlertByThreadId(0, 0);
				} while (!_rp.IsRundownCompleted());
			}
		}
	}
};