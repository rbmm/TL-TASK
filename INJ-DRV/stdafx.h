#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define _NTDRIVER_
#define NOWINBASEINTERLOCK
#define _NTOS_

#include "../inc/StdAfx.h"

void* __cdecl operator new(size_t size, NT::POOL_TYPE PoolType = NT::PagedPool);

void* __cdecl operator new[](size_t size, NT::POOL_TYPE PoolType = NT::PagedPool);

void __cdecl operator delete(PVOID pv);

void __cdecl operator delete(PVOID pv, size_t);

void __cdecl operator delete[](PVOID pv);