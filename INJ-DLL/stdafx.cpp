#include "stdafx.h"

using namespace NT;

void* RtlGetProcessHeap()
{
	return RtlGetCurrentPeb()->ProcessHeap;
}

void* __cdecl operator new[](size_t ByteSize)
{
	return RtlAllocateHeap(RtlGetProcessHeap(), 0, ByteSize);
}

void* __cdecl operator new(size_t ByteSize)
{
	return RtlAllocateHeap(RtlGetProcessHeap(), 0, ByteSize);
}

void __cdecl operator delete(void* Buffer)
{
	RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete[](void* Buffer)
{
	RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}
