#pragma once

#include "pdb_util.h"

void LoadNtModule(ULONG n, const ULONG ph[]);
void DumpStack(PCSTR txt);
ULONG HashString(PCSTR lpsz, ULONG hash = 0);

class CModule : LIST_ENTRY
{
	PVOID _ImageBase;
	ULONG _size;
	ULONG _hash;
	ULONG _nSymbols;
	char _name[32];
	RVAOFS _Symbols[];
	//CHAR Names[];
	void Init(ULONG hash, PCSTR name, PVOID ImageBase, ULONG size)
	{
		_hash = hash, _size = size, _ImageBase = ImageBase;
		strcpy_s(_name, _countof(_name), name);
		DbgPrint("++CModule<%p>(%s) %p\n", this, name, ImageBase);
	}

	static LIST_ENTRY s_head;

	CModule()
	{
		InsertHeadList(&s_head, this);
	}

	~CModule()
	{
		DbgPrint("--CModule<%p>(%s) %p\n", this, _name, _ImageBase);
	}

	PCSTR GetNameFromRva(ULONG rva, PULONG pdisp, PCSTR* ppname);
public:

	void* operator new(size_t s, ULONG nSymbols, ULONG cbNames)
	{
		if (PVOID pv = ::operator new(s + nSymbols * sizeof(RVAOFS) + cbNames, NonPagedPoolNx))
		{
			reinterpret_cast<CModule*>(pv)->_nSymbols = nSymbols;
			return pv;
		}
		return 0;
	}

	void operator delete(void* pv)
	{
		ExFreePool(pv);
	}

	static NTSTATUS Create(ULONG hash, PCSTR name, PVOID ImageBase, ULONG size);
	static PVOID GetVaFromName(PCSTR pszModule, PCSTR Name);
	static PCSTR GetNameFromVa(PVOID pv, PULONG pdisp, PCSTR* ppname);

	PVOID GetVaFromName(PCSTR Name);
	static CModule* ByName(PCSTR pszModule)
	{
		return ByHash(HashString(pszModule));
	}

	static CModule* ByHash(ULONG hash);

	static void Cleanup();
};