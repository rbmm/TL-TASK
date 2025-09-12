#include "stdafx.h"

_NT_BEGIN

#include "undname.h"
#include "module.h"
#include "../inc/rtlframe.h"

typedef RTL_FRAME<DATA_BLOB> AFRAME;

static void* __cdecl fAlloc(ULONG cb)
{
	if (DATA_BLOB* prf = AFRAME::get())
	{
		if (cb > prf->cbData)
		{
			return 0;
		}
		prf->cbData -= cb;
		PVOID pv = prf->pbData;
		prf->pbData += cb;
		return pv;
	}

	return 0;
}

static void __cdecl fFree(void* )
{
}


PCSTR __cdecl GetParameter(long /*i*/)
{
	return const_cast<PSTR>("");
}

PSTR _unDName(PSTR buffer, PCSTR mangled, DWORD cb, DWORD flags)
{
	PSTR psz = 0;
	if (PUCHAR pbData = new UCHAR[32*PAGE_SIZE])
	{
		AFRAME af;
		af.pbData = pbData, af.cbData = 32*PAGE_SIZE;
		psz = __unDNameEx(buffer, mangled, cb, fAlloc, fFree, GetParameter, flags);
		delete [] pbData;
	}

	return psz;
}

PCSTR unDNameEx(_Out_ PSTR buffer, _In_ PCSTR mangled, _In_ DWORD cb, _In_ DWORD flags)
{
	if (*mangled != '?')
	{
		return mangled;
	}
	PSTR sz = _unDName(buffer, mangled, cb, flags);
	return sz ? sz : mangled;
}

void WINAPI DumpStack(_In_ ULONG FramesToSkip, _In_ PCSTR txt, ULONG (__cdecl * print) ( PCSTR Format, ...))
{
	PVOID pv[64], *ppv;
	
	ULONG n = RtlWalkFrameChain(pv, _countof(pv), FramesToSkip << RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT);
	
	if (n > FramesToSkip)
	{
		if (txt) print(">>> ************* %s\r\n", txt);

		n -= FramesToSkip, ppv = pv;

		do 
		{
			PVOID p = *ppv++;
			ULONG d;
			PCWSTR name;

			if (PCSTR psz = CModule::s_GetNameFromVa(p, &d, &name))
			{
				char undName[0x400];
				print(">> %p %S!%s + %x\r\n", p, name, unDNameEx(undName, psz, _countof(undName), UNDNAME_DEFAULT), d);
			}
			else
			{
				print(">> %p\n", p);
			}
		} while (--n);

		if (txt) print("<<<< ************* %s\r\n", txt);
	}
}

_NT_END