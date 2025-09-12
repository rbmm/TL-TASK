#define _NTDRIVER_
#define NOWINBASEINTERLOCK
#define _NTOS_
#define SECURITY_KERNEL
#include "../inc/stdafx.h"

void* __cdecl operator new[](size_t ByteSize, NT::POOL_TYPE PoolType);
void* __cdecl operator new(size_t ByteSize, NT::POOL_TYPE PoolType);
