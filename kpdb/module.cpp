#include "stdafx.h"

_NT_BEGIN

#include "module.h"
#include "pdb_util.h"

LIST_ENTRY CModule::s_head = { &s_head, &s_head };

CModule* CModule::ByHash(ULONG hash)
{
	CModule* p = 0;
	PLIST_ENTRY entry = &s_head;

	while ((entry = entry->Flink) != &s_head)
	{
		p = static_cast<CModule*>(entry);

		if (p->_hash== hash)
		{
			return p;
		}
	}

	return 0;
}

PVOID CModule::GetVaFromName(PCSTR pszModule, PCSTR Name)
{
	if (CModule* p = ByName(pszModule))
	{
		return p->GetVaFromName(Name);
	}

	return 0;
}

PVOID CModule::GetVaFromName(PCSTR Name)
{
	if (ULONG n = _nSymbols)
	{
		RVAOFS* Symbols = _Symbols;

		do 
		{
			if (!strcmp(Name, RtlOffsetToPointer(this, Symbols->ofs)))
			{
				return (PBYTE)_ImageBase + Symbols->rva;
			}
		} while (Symbols++, --n);
	}

	return 0;
}

PCSTR CModule::GetNameFromVa(PVOID pv, PULONG pdisp, PCSTR* ppname)
{
	PLIST_ENTRY entry = &s_head;
	
	while ((entry = entry->Flink) != &s_head)
	{
		CModule* p = static_cast<CModule*>(entry);

		ULONG_PTR rva = (ULONG_PTR)pv - (ULONG_PTR)p->_ImageBase;
		
		if (rva < p->_size)
		{
			return p->GetNameFromRva((ULONG)rva, pdisp, ppname);
		}
	}

	return 0;
}

PCSTR CModule::GetNameFromRva(ULONG rva, PULONG pdisp, PCSTR* ppname)
{
	*ppname = _name;
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

NTSTATUS CModule::Create(ULONG hash, PCSTR name, PVOID ImageBase, ULONG size)
{
	DbgPrint("%hs(%08x, %hs, %p, %08x) %p\r\n", __FUNCTION__, hash, name, ImageBase, size);
	
	// if (ImageBase == &__ImageBase) return 0; // load pdb for self ?!

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

	NTSTATUS status = ss.GetSymbols((HMODULE)ImageBase, L"\\systemroot\\symbols");

	if (0 <= status)
	{
		if (CModule* pModule = ss._pModule)
		{
			pModule->Init(hash, name, ImageBase, size);
			return STATUS_SUCCESS;
		}

		return STATUS_UNSUCCESSFUL;
	}

	return status;
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

