#include "stdafx.h"

_NT_BEGIN

#include "module.h"
#include "pdb_util.h"

LIST_ENTRY CModule::s_head = { &s_head, &s_head };

CModule::~CModule()
{
	AcquireSRWLockExclusive(&_SRWLock);
	RemoveEntryList(this);
	ReleaseSRWLockExclusive(&_SRWLock);

	//DbgPrint("--CModule<%p>(%wZ) %p\n", this, &_Name, _ImageBase);
	_b ? delete [] _Name.Buffer : RtlFreeUnicodeString(&_Name);
}

NTSTATUS CModule::Create(_In_ PCWSTR psz, _In_ HMODULE hmod, _In_ ULONG size, _Out_ CModule** ppmod)
{
	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, psz);
	return Create(&Name, hmod, size, ppmod);
}

NTSTATUS CModule::Create(_In_ HMODULE hmod, _Out_ CModule** ppmod)
{
	_LDR_DATA_TABLE_ENTRY* ldte;
	NTSTATUS status = LdrFindEntryForAddress(hmod, &ldte);

	return 0 > status ? status : Create(&ldte->BaseDllName, (HMODULE)ldte->DllBase, ldte->SizeOfImage, ppmod);
}

PVOID CModule::s_GetVaFromName(HMODULE hmod, PCSTR Name)
{
	CModule* p = 0;
	PLIST_ENTRY entry = &s_head;

	AcquireSRWLockShared(&_SRWLock);

	while ((entry = entry->Flink) != &s_head)
	{
		p = static_cast<CModule*>(entry);

		if (hmod == p->_ImageBase)
		{
			ReleaseSRWLockShared(&_SRWLock);

			return p->GetVaFromName(Name);
		}
	}

	ReleaseSRWLockShared(&_SRWLock);

	if (0 <= CModule::Create(hmod, &p))
	{
		return p->GetVaFromName(Name);
	}

	return 0;
}

PCSTR CModule::s_GetNameFromVa(PVOID pv, PULONG pdisp, PCWSTR* ppname)
{
	CModule* p = 0;
	PLIST_ENTRY entry = &s_head;
	
	AcquireSRWLockShared(&_SRWLock);

	while ((entry = entry->Flink) != &s_head)
	{
		p = static_cast<CModule*>(entry);

		ULONG_PTR rva = (ULONG_PTR)pv - (ULONG_PTR)p->_ImageBase;
		
		if (rva < p->_size)
		{
			ReleaseSRWLockShared(&_SRWLock);
			*ppname = p->_Name.Buffer;

			return p->GetNameFromRva((ULONG)rva, pdisp);
		}
	}

	ReleaseSRWLockShared(&_SRWLock);

	_LDR_DATA_TABLE_ENTRY* ldte;
	if (0 <= LdrFindEntryForAddress(pv, &ldte))
	{
		if (0 <= CModule::Create(&ldte->BaseDllName, (HMODULE)ldte->DllBase, ldte->SizeOfImage, &p))
		{
			*ppname = p->_Name.Buffer;
			return p->GetNameFromRva((ULONG)((ULONG_PTR)pv - (ULONG_PTR)ldte->DllBase), pdisp);
		}
	}

	return 0;
}

ULONG CModule::GetRVAFromName(PCSTR Name)
{
	if (ULONG n = _nSymbols)
	{
		RVAOFS* Symbols = _Symbols;

		do 
		{
			if (!strcmp(Name, RtlOffsetToPointer(this, Symbols->ofs)))
			{
				return Symbols->rva;
			}
		} while (Symbols++, --n);
	}

	return 0;
}

PVOID CModule::GetVaFromName(PCSTR Name)
{
	if (ULONG rva = GetRVAFromName( Name))
	{
		return (PBYTE)_ImageBase + rva;
	}

	return 0;
}

PCSTR CModule::GetNameFromVa(_In_ PVOID pv, _Out_ PULONG pdisp)
{
	ULONG_PTR rva = (ULONG_PTR)pv - (ULONG_PTR)_ImageBase;
	return rva < _size ? GetNameFromRva((ULONG)rva, pdisp) : 0;
}

PCSTR CModule::GetNameFromRva(ULONG rva, PULONG pdisp)
{
	ULONG a = 0, b = _nSymbols, o, s_rva;

	if (!b)
	{
		*pdisp = rva;
		return "MZ";
	}

	RVAOFS* Symbols = _Symbols;

	do 
	{
		if (rva == (s_rva = Symbols[o = (a + b) >> 1].rva))
		{
			*pdisp = 0;
__0:
			return RtlOffsetToPointer(this, Symbols[o].ofs);
		}

		rva < s_rva ? b = o : a = o + 1;

	} while (a < b);

	if (rva < s_rva)
	{
		if (!o)
		{
			return 0;
		}
		s_rva = Symbols[--o].rva;
	}

	*pdisp = (ULONG)rva - s_rva;

	goto __0;
}

NTSTATUS CModule::Create(_In_ PCUNICODE_STRING Name, _In_ HMODULE hmod, _In_ ULONG size, _Out_ CModule** ppmod)
{
	PVOID ImageBase = PAGE_ALIGN(hmod);

	struct Z : SymStore 
	{
		CModule* _pModule = 0;
		CV_INFO_PDB* _lpcvh = 0;

		virtual NTSTATUS OnOpenPdb(NTSTATUS status, CV_INFO_PDB* lpcvh)
		{
			_lpcvh = lpcvh;
			return status;
		}

		virtual void Symbols(_In_ RVAOFS* pSymbols, _In_ ULONG nSymbols, _In_ PSTR names)
		{
			ULONG n = nSymbols, cbNames = 0;

			RVAOFS* p = pSymbols;
			do 
			{
				cbNames += (ULONG)strlen(names + p++->ofs) + 1;
			} while (--n);

			if (CModule* pDll = new(nSymbols, cbNames) CModule)
			{
				_pModule = pDll;

				p = pDll->_Symbols;
				PSTR names_copy = (PSTR)&p[nSymbols];
				cbNames = RtlPointerToOffset(pDll, names_copy);
				do 
				{
					p->rva = pSymbols->rva;
					p++->ofs = cbNames;
					ULONG ofs = pSymbols++->ofs;
					PCSTR name = names + ofs;
					ULONG len = (ULONG)strlen(name) + 1;
					memcpy(names_copy, name, len);
					names_copy += len, cbNames += len;

				} while (--nSymbols);
			}
		}

		static BOOL SpecialSymbol(_In_ PCSTR name)
		{
			// __IMPO
			// __DELA
			if (name[0] == '_' && name[1] == '_')
			{
				if ((name[2] == 'I' && name[3] == 'M' && name[4] == 'P' && name[5] == 'O') &&
					(name[2] == 'D' && name[3] == 'E' && name[4] == 'L' && name[5] == 'A'))
				{
					return TRUE;
				}
			}

			// WPP_

			return name[0] == 'W' && name[1] == 'P' && name[2] == 'P' && name[3] == '_';
		}

		virtual BOOL IncludeSymbol(_In_ PCSTR name)
		{
			return (name[0] != '?' || name[1] != '?') && __super::IncludeSymbol(name) && !SpecialSymbol(name);
		}

	} ss;

	NTSTATUS status = ss.GetSymbols(hmod, L"\\systemroot\\symbols");

	CModule* pModule;

	if (0 > status)
	{
		if (pModule = new(0, 0) CModule)
		{
			pModule->_status = status;

			if (CV_INFO_PDB* lpcvh = ss._lpcvh)
			{
				PCSTR PdbFileName = lpcvh->PdbFileName;
				if (PCSTR psz = strrchr(PdbFileName, '\\'))
				{
					PdbFileName = psz + 1;
				}

				GUID* Signature = &lpcvh->Signature;

				pModule->Init(L"%S*%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x", 
					PdbFileName, Signature->Data1, Signature->Data2, Signature->Data3,
					Signature->Data4[0], Signature->Data4[1], Signature->Data4[2], Signature->Data4[3],
					Signature->Data4[4], Signature->Data4[5], Signature->Data4[6], Signature->Data4[7],
					lpcvh->Age);

				pModule->_size = size, pModule->_ImageBase = ImageBase;
				goto __1;
				
			}
			goto __0;
		}
	}
	else
	{
		if (pModule = ss._pModule)
		{
__0:
			pModule->Init(Name, ImageBase, size);
__1:
			*ppmod = pModule;

			AcquireSRWLockExclusive(&_SRWLock);
			InsertHeadList(&s_head, pModule);
			ReleaseSRWLockExclusive(&_SRWLock);
			*ppmod = pModule;

			return status;
		}

		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

void CModule::Init(PCWSTR fmt, ...)
{
	PWSTR buf = 0;
	LONG cch = 0;
	va_list v;
	va_start(v, fmt);
	while (0 < (cch = _vsnwprintf(buf, cch, fmt, v)))
	{
		if (buf)
		{
			_b = TRUE;
			_Name.Buffer = buf;
			_Name.MaximumLength = (USHORT)(cch >>= 1);
			_Name.Length = (USHORT)(cch - 1);
			return ;
		}

		buf = new WCHAR[++cch];
	}

	delete [] buf;
}

void CModule::Cleanup()
{
	PLIST_ENTRY entry = s_head.Flink;

	while (entry != &s_head)
	{
		CModule* p = static_cast<CModule*>(entry);
		
		entry = entry->Flink;

		delete p;
	}
}

_NT_END

