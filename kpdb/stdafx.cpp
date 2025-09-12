#include "stdafx.h"

#pragma warning(disable : 4996)

void* __cdecl operator new[](size_t ByteSize, NT::POOL_TYPE PoolType)
{
	return NT::ExAllocatePool(PoolType, ByteSize);
}

void* __cdecl operator new(size_t ByteSize, NT::POOL_TYPE PoolType)
{
	return NT::ExAllocatePool(PoolType, ByteSize);
}

void __cdecl operator delete(void* Buffer)
{
	NT::ExFreePool(Buffer);
}

void __cdecl operator delete[](void* Buffer)
{
	NT::ExFreePool(Buffer);
}

