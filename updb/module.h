#pragma once

#include "pdb_util.h"

class CModule : LIST_ENTRY
{
	UNICODE_STRING _Name {};
	PVOID _ImageBase;
	ULONG _size;
	BOOL _b = FALSE;
	NTSTATUS _status = 0;
	ULONG _nSymbols;
	RVAOFS _Symbols[];
	//CHAR Names[];
	void Init(PCWSTR fmt, ...);

	void Init(PCUNICODE_STRING Name, PVOID ImageBase, ULONG size)
	{
		_size = size, _ImageBase = ImageBase;
		RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, Name, &_Name);
		//DbgPrint("++CModule<%p>(%wZ) %p\n", this, Name, ImageBase);
	}

	static LIST_ENTRY s_head;
	inline static SRWLOCK _SRWLock;

	static NTSTATUS Create(_In_ PCUNICODE_STRING Name, _In_ HMODULE hmod, _In_ ULONG size, _Out_ CModule** ppmod);

public:
	~CModule();

	ULONG SymbolsCount() { return _nSymbols; }
	NTSTATUS GetStatus() { return _status; }
	PCUNICODE_STRING Name() { return &_Name; }

	ULONG GetRVAFromName(_In_ PCSTR Name);
	PVOID GetVaFromName(_In_ PCSTR Name);
	PCSTR GetNameFromVa(_In_ PVOID pv, _Out_ PULONG pdisp);
	PCSTR GetNameFromRva(_In_ ULONG rva, _Out_ PULONG pdisp);

	static NTSTATUS Create(_In_ PCWSTR psz, _In_ HMODULE hmod, _In_ ULONG size, _Out_ CModule** ppmod);

	static NTSTATUS Create(_In_ HMODULE hmod, _Out_ CModule** ppmod);

	void* operator new(size_t s, ULONG nSymbols, size_t cbNames)
	{
		if (PVOID pv = LocalAlloc(0, s + nSymbols * sizeof(RVAOFS) + cbNames))
		{
			reinterpret_cast<CModule*>(pv)->_nSymbols = nSymbols;
			return pv;
		}
		return 0;
	}

	void operator delete(void* pv)
	{
		LocalFree(pv);
	}

	static PVOID s_GetVaFromName(_In_ HMODULE hmod, _In_ PCSTR Name);
	static PCSTR s_GetNameFromVa(_In_ PVOID pv, _Out_ PULONG pdisp, _Out_ PCWSTR* ppname);

	static void Cleanup();
};

void WINAPI DumpStack(_In_ ULONG FramesToSkip, _In_ PCSTR txt = 0, ULONG (__cdecl * print) ( PCSTR Format, ...) = DbgPrint);
PSTR WINAPI _unDName(_Out_ PSTR buffer, _In_ PCSTR mangled, _In_ DWORD cb, _In_ DWORD flags);
PCSTR WINAPI unDNameEx(_Out_ PSTR buffer, _In_ PCSTR mangled, _In_ DWORD cb, _In_ DWORD flags);
