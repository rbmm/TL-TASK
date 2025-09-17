//#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define _NTDRIVER_
#define NOWINBASEINTERLOCK
#define _NTOS_
#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#define NDIS_INCLUDE_LEGACY_NAMES

#include "../inc/stdafx.h"

#include <ip2string.h>

_NT_BEGIN

#include <wdmsec.h>

#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>
#include <ndis/nblapi.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

_NT_END

void* __cdecl operator new(size_t size, NT::POOL_TYPE PoolType = NT::PagedPool);

void* __cdecl operator new[](size_t size, NT::POOL_TYPE PoolType = NT::PagedPool);

void __cdecl operator delete(PVOID pv);

void __cdecl operator delete(PVOID pv, size_t);

void __cdecl operator delete[](PVOID pv);
