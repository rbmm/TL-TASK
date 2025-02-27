#include "stdafx.h"

void* __cdecl operator new[](size_t ByteSize)
{
	return HeapAlloc(GetProcessHeap(), 0, ByteSize);
}

void* __cdecl operator new(size_t ByteSize)
{
	return HeapAlloc(GetProcessHeap(), 0, ByteSize);
}

void __cdecl operator delete(void* Buffer)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete(void* Buffer, size_t)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete[](void* Buffer)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete[](void* Buffer, size_t)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void* __RPC_USER MIDL_user_allocate( _In_ size_t size)
{
	return LocalAlloc(0, size);
}

void __RPC_USER MIDL_user_free( _Pre_maybenull_ _Post_invalid_ void  * pv)
{
	LocalFree(pv);
}