#include "STDAFX.H"

_NT_BEGIN

#include "PDB.h"

class PdbReader
{
	DbiHeader* _pdh;
	PIMAGE_SECTION_HEADER _pish;
	OMAP* _pvOmapFromSrc;
	PVOID _BaseAddress, _PdbBase;
	PLONG _StreamSizes;
	PULONG _StreamPages;
	PUSHORT _pFileInfo;
	ULONG _pageSize, _pagesUsed, _nStreams, _nSections, _nOmapFromSrc;
	BOOLEAN _bUnmap, _Is64Bit;

	PULONG GetStreamPages(ULONG iStream)
	{
		if (iStream < _nStreams)
		{
			ULONG pageSize = _pageSize;
			PLONG StreamSizes = _StreamSizes;
			PULONG StreamPages = _StreamPages;

			do 
			{
				if (ULONG StreamSize = *StreamSizes++)
				{
					StreamPages += (StreamSize + pageSize - 1) / pageSize;
				}
			} while (--iStream);

			return StreamPages;
		}

		return 0;
	}

	BOOL Read(ULONG StreamPages[], ULONG ofs, PBYTE pb, ULONG cb)
	{
		PVOID PdbBase = _PdbBase;
		ULONG cbCopy, pagesUsed = _pagesUsed, Page, PageSize = _pageSize;

		StreamPages += ofs / PageSize;

		if (ofs %= PageSize)
		{
			if ((Page = *StreamPages++) >= pagesUsed) 
			{
				return FALSE;
			}

			memcpy(pb, RtlOffsetToPointer(PdbBase, Page * PageSize) + ofs, cbCopy = min(PageSize - ofs, cb));

			pb += cbCopy, cb -= cbCopy;
		}

		if (cb)
		{
			do 
			{
				if ((Page = *StreamPages++) >= pagesUsed) 
				{
					return FALSE;
				}

				memcpy(pb, RtlOffsetToPointer(PdbBase, Page * PageSize), cbCopy = min(PageSize, cb));

			} while (pb += cbCopy, cb -= cbCopy);
		}

		return TRUE;
	}

	BOOL ValidatePdbHeader(const GUID* signature = 0)
	{
		PdbHeader psh;
		return _StreamSizes[PDB_STREAM_PDB] > sizeof(PdbHeader) && 
			Read(PDB_STREAM_PDB, 0, &psh, sizeof(psh)) && 
			psh.impv == PDBImpv && 
			(!signature || psh.signature == *signature);
	}

public:

	BOOL Read(DWORD iStream, DWORD ofs, PVOID pb, DWORD cb)
	{
		PULONG StreamPages = GetStreamPages(iStream);
		return StreamPages ? Read(StreamPages, ofs, (PBYTE)pb, cb) : FALSE;
	}

	NTSTATUS getStream(ULONG iStream, void** ppv, PULONG pcb, LONG minSize = 1, ULONG mult = 1)
	{
		if (iStream >= _nStreams)
		{
			return STATUS_NOT_FOUND;
		}

		LONG cb = _StreamSizes[iStream];

		if (minSize > cb || cb % mult)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		if (PVOID pv = new CHAR[cb])
		{
			if (Read(iStream, 0, pv, cb))
			{
				*ppv = pv;
				*pcb = cb;
				return STATUS_SUCCESS;
			}

			delete [] pv;

			return STATUS_INVALID_IMAGE_FORMAT;
		}

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	void FreeStream(PVOID pv)
	{
		delete [] pv;
	}

	ULONG rva(ULONG segment, ULONG offset)
	{
		if (segment > _nSections || offset >= _pish[--segment].Misc.VirtualSize)
		{
			return 0;
		}

		offset += _pish[segment].VirtualAddress;

		if (OMAP* pvOmapFromSrc = _pvOmapFromSrc)
		{
			ULONG a = 0, o, r, b = _nOmapFromSrc;
			OMAP *s = 0, *q;

			if (offset < pvOmapFromSrc->rva)
			{
				return 0;
			}

			do 
			{
				o = (a + b) >> 1;

				q = pvOmapFromSrc + o;
				r = q->rva;

				if (r == offset)
				{
					return q->rvaTo;
				}

				if (r < offset)
				{
					s = q;
					a = o + 1;
				}
				else
				{
					b = o;
				}

			} while (a < b);

			return (offset - s->rva) + s->rvaTo;
		}

		return offset;
	}

	NTSTATUS Init(PdbFileHeader* header, SIZE_T ViewSize, const GUID* signature, ULONG Age)
	{
		ULONG pageSize = header->pageSize, pagesUsed = header->pagesUsed;

		if (ViewSize < pageSize * pagesUsed)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		ULONG directoryRoot = header->directoryRoot, directorySize = header->directorySize;

		if (directorySize < sizeof(ULONG))
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		ULONG directoryEnd = ((((directorySize + pageSize - 1) / pageSize) * sizeof(ULONG) + pageSize - 1) / pageSize) + directoryRoot;

		if (directoryEnd <= directoryRoot || directoryEnd > pagesUsed)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		PULONG pd = (PULONG)LocalAlloc(0, directorySize);
		if (!pd)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		_BaseAddress = pd, _PdbBase = header, _pageSize = pageSize, _pagesUsed = pagesUsed;

		if (!Read((PULONG)RtlOffsetToPointer(header, directoryRoot * pageSize), 0, (PBYTE)pd, directorySize))
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		ULONG nStreams = *pd++;
		_nStreams = nStreams;
		_StreamSizes = (PLONG)pd, _StreamPages = pd + _nStreams;

		if (nStreams <= PDB_STREAM_DBI || directorySize < (1 + nStreams) * sizeof(ULONG))
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		ULONG i = nStreams, k = 0;
		do 
		{
			k += (*pd++ + pageSize - 1) / pageSize;
		} while (--i);

		if (
			directorySize < (1 + nStreams + k) * sizeof(ULONG)
			||
			!ValidatePdbHeader(signature))
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		ULONG size;
		DbiHeader* pdh;

		NTSTATUS status;

		if (0 > (status = getStream(PDB_STREAM_DBI, (void**)&pdh, &size, sizeof(DbiHeader))))
		{
			return status;
		}

		_pdh = pdh;

		if (pdh->ver != DBIImpv)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		if (signature && pdh->age != Age)
		{
			return STATUS_REVISION_MISMATCH;
		}

		switch (pdh->machine)
		{
		case 0:
		case IMAGE_FILE_MACHINE_I386:
			_Is64Bit = FALSE;
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			_Is64Bit = TRUE;
			break;
		default: return STATUS_NOT_SUPPORTED;
		}
		ULONG a = sizeof(DbiHeader), b = a + pdh->gpmodiSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		ULONG secconSize = pdh->secconSize;

		a = b, b = a + secconSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		a = b, b = a + pdh->secmapSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		a = b, b = a + pdh->filinfSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		_pFileInfo = (PUSHORT)RtlOffsetToPointer(pdh, a);

		a = b, b = a + pdh->tsmapSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		a = b, b = a + pdh->ecinfoSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		a = b, b = a + pdh->dbghdrSize;

		if (a > b || b > size)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		if (sizeof(DbiDbgHdr) > pdh->dbghdrSize)
		{
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		DbiDbgHdr* pdbgHdr = (DbiDbgHdr*)RtlOffsetToPointer(pdh, a);

		SHORT snOmapFromSrc = pdbgHdr->snOmapFromSrc, snSectionHdr = pdbgHdr->snSectionHdr;

		if (0 < snOmapFromSrc)
		{
			if (0 > (status = getStream(snOmapFromSrc, (void**)&_pvOmapFromSrc, &size, 1, sizeof(OMAP))))
			{
				return status;
			}

			_nOmapFromSrc = size / sizeof(OMAP);
			snSectionHdr = pdbgHdr->snSectionHdrOrig;
		}

		if (0 <= (status = getStream(snSectionHdr, (void**)&_pish, &size, 1, sizeof(IMAGE_SECTION_HEADER))))
		{
			_nSections = size / sizeof(IMAGE_SECTION_HEADER);
		}

		return status;
	}

	DWORD getStreamSize(ULONG iStream)
	{
		return iStream < _nStreams ? _StreamSizes[iStream] : 0;
	}

	USHORT getPublicSymbolsStreamIndex()
	{
		return _pdh->symrecStream;
	}

	DbiModuleInfo* getModuleInfo(ULONG& gpmodiSize)
	{
		gpmodiSize = _pdh->gpmodiSize;
		return (DbiModuleInfo*)(_pdh + 1);
	}

	PUSHORT getFileInfo(ULONG& filinfSize)
	{
		filinfSize = _pdh->filinfSize;
		return _pFileInfo;
	}

	~PdbReader()
	{
		if (PVOID pv = _BaseAddress)
		{
			LocalFree(pv);
		}
	}
};

#include "pdb_util.h"

size_t __fastcall strnlen(_In_ size_t numberOfElements, _In_ const char *str);

template<typename T>
BOOL IsValidSymbol(T* ps, ULONG cb)
{
	if (FIELD_OFFSET(T, name) < cb)
	{
		ULONG len = sizeof(USHORT) + static_cast<SYM_HEADER*>(ps)->len;
		if (FIELD_OFFSET(T, name) < len && len <= cb)
		{
			len -= FIELD_OFFSET(T, name);
			if (strnlen(len, ps->name) < len)
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

C_ASSERT(sizeof(SYM_HEADER) == 4);
C_ASSERT(FIELD_OFFSET(PUBSYM32, pubsymflags) == 4);

DbiModuleInfo** getModules(_In_ PdbReader* pdb, _Out_ PULONG pn)
{
	*pn = 0;

	ULONG size, nModules, cb;
	PUSHORT pFileInfo = pdb->getFileInfo(size);
	union {
		PBYTE pb;
		DbiModuleInfo* module;
	};

	if (!pFileInfo || !(nModules = *pFileInfo) || !(module = pdb->getModuleInfo(size)))
	{
		return 0;
	}

	if (size < sizeof(DbiModuleInfo) + 2)
	{
		return 0;
	}

	PCSTR end = RtlOffsetToPointer(module, size - 2);

	if (end[0] || end[1])
	{
		return 0;
	}

	if (DbiModuleInfo** ppm = new DbiModuleInfo*[nModules])
	{
		DbiModuleInfo** _ppm = ppm;
		*pn = nModules;
		do 
		{
			*ppm++ = module;
			PCSTR objectName = module->buf + strlen(module->buf) + 1;

			cb = (RtlPointerToOffset(module, objectName + strlen(objectName)) + __alignof(DbiModuleInfo)) & ~(__alignof(DbiModuleInfo) - 1);

			size -= cb, pb += cb;

		} while (--nModules && size > sizeof(DbiModuleInfo) + 1);

		if (!nModules && !size)
		{
			return _ppm;
		}

		*pn = 0;
		delete [] _ppm;
	}

	return 0;
}

struct MI 
{
	USHORT imod = MAXUSHORT;
	PBYTE _pb = 0;
	ULONG _cb;

	~MI()
	{
		if (PVOID pv = _pb)
		{
			delete [] pv;
		}
	}

	ULONG rva(DbiModuleInfo* pm, PdbReader* pdb, ULONG ibSym, PCSTR name)
	{
		USHORT s = pm->stream;
		if (s != MAXUSHORT)
		{
			union {
				PVOID pv;
				PBYTE pb;
				SYM_HEADER* ph;
				PROCSYM32* ps;
			};
			ULONG cb;
			if (s == imod)
			{
				cb = _cb, pb = _pb;
			}
			else
			{
				if (0 > pdb->getStream(s, &pv, &cb))
				{
					return 0;
				}
				if (_pb)
				{
					delete [] _pb;
					_pb = 0;
				}
				_pb = pb;
				_cb = cb;
				imod = s;
			}

			if (ibSym < cb) // Offset of actual symbol in $$Symbols
			{
				pb += ibSym, cb -= ibSym;

				if (IsValidSymbol(ps, cb))
				{
					switch (ph->type)
					{
					case S_GPROC32:
					case S_LPROC32:
					case S_GPROC32_ID:
					case S_LPROC32_ID:
					case S_LPROC32_DPC:
					case S_LPROC32_DPC_ID:
						if (!strcmp(ps->name, name))
						{
							return pdb->rva(ps->seg, ps->off);
						}
					}
				}
			}
		}

		return 0;
	}
};

int __cdecl compare(RVAOFS& a, RVAOFS& b)
{
	ULONG a_rva = a.rva, b_rva = b.rva;
	if (a_rva < b_rva) return -1;
	if (a_rva > b_rva) return +1;
	return 0;
}

struct MD 
{
	ULONG n;
	DbiModuleInfo** pmm;

	MD(PdbReader* pdb) : pmm(getModules(pdb, &n))
	{
	}

	~MD()
	{
		if (PVOID pv = pmm)
		{
			delete [] pv;
		}
	}

	DbiModuleInfo* operator[](ULONG i)
	{
		return i < n ? pmm[i] : 0;
	}
};

BOOL IsRvaExist(ULONG rva, RVAOFS *pSymbols, ULONG b)
{
	if (!b || pSymbols->rva > rva)
	{
		return 0;
	}

	ULONG a = 0, o, r;

	do 
	{
		if ((r = pSymbols[o = (a + b) >> 1].rva) == rva)
		{
			return TRUE;
		}

		r < rva ? a = o + 1 : b = o;

	} while (a < b);

	return FALSE;
}

ULONG LoadSymbols(PdbReader* pdb,
				  PVOID stream, 
				  ULONG size, 
				  MD& md, 
				  RVAOFS* pSymbolsBase,
				  ULONG nSymbols,
				  BOOL bSecondLoop)
{
	union {
		PVOID pv;
		PBYTE pb;
		SYM_HEADER* psh;
		PUBSYM32* pbs;
		PROCSYM32* pps;
		REFSYM2* pls;
	};

	pv = stream;

	DWORD n = 0, len;

	PSTR name = 0;
	MI mi;

	RVAOFS* pSymbols = pSymbolsBase + nSymbols;

	do 
	{
		len = psh->len + sizeof(WORD);

		if (size < len) 
		{
			return 0;
		}

		ULONG rva = 0;

		switch (psh->type)
		{
		case S_DATAREF:
		case S_PROCREF:
		case S_LPROCREF:
			if (bSecondLoop && IsValidSymbol(pls, size))
			{
				if (DbiModuleInfo* pm = md[pls->imod - 1])
				{
					name = pls->name;
					if (!*name)
					{
						continue;
					}
					if (rva = mi.rva(pm, pdb, pls->ibSym, pls->name))
					{
						if (!IsRvaExist(rva, pSymbolsBase, nSymbols))
						{
							break;
						}
					}
				}
			}
			continue;

		case S_PUB32:
			if (!bSecondLoop && IsValidSymbol(pbs, size))
			{
				name = pbs->name;
				if (!*name)
				{
					continue;
				}
				if (rva = pdb->rva(pbs->seg, pbs->off))
				{
					break;
				}
			}
			continue;
		default:
			continue;
		}

		pSymbols->rva = rva;
		pSymbols++->ofs = RtlPointerToOffset(stream, name);
		n++;

	} while (pb += len, size -= len);

	return n;
}

BOOL SymStore::IncludeSymbol(_In_ PCSTR name)
{
	switch (*name)
	{
	case '_':
		//__imp_ not include
		if (name[1] == '_' && name[2] == 'i' && name[3] == 'm' && name[4] == 'p' && name[5] == '_')
		{
			//__imp_load_ include
			if (name[6] == 'l' && name[7] == 'o' && name[8] == 'a' && name[9] == 'd' && name[10] == '_')
			{
				break;
			}
			return FALSE;
		}
		break;
	case '?':
		// ??_C@_ `string` - not include
		if (name[1] == '?' && name[2] == '_' && name[3] == 'C' && name[4] == '@' && name[5] == '_')
		{
			return FALSE;
		}
		break;
	}

	return TRUE;
}

ULONG GetMaxSymCount(PVOID stream, ULONG size, SymStore* pss)
{
	union {
		PVOID pv;
		PBYTE pb;
		SYM_HEADER* psh;
		PUBSYM32* pbs;
		REFSYM2* pls;
	};

	pv = stream;

	ULONG n = 0, len;

	PSTR name = 0;

	do 
	{
		len = psh->len + sizeof(WORD);

		if (size < len) 
		{
			return 0;
		}

		switch (psh->type)
		{
		case S_DATAREF:
		case S_PROCREF:
		case S_LPROCREF:
			if (IsValidSymbol(pls, size))
			{
				name = pls->name;
				break;
			}
			continue;

		case S_PUB32:
			if (IsValidSymbol(pbs, size))
			{
				name = pbs->name;
				break;
			}
			continue;
		default:
			continue;
		}

		if (pss->IncludeSymbol(name))
		{
			n++;
		}
		else
		{
			*name = 0;
		}

	} while (pb += len, size -= len);

	return n;
}

NTSTATUS LoadPublicSymbols(PdbReader* pdb, PVOID stream, ULONG size, SymStore* pss)
{
	if (ULONG n = GetMaxSymCount(stream, size, pss))
	{
		if (RVAOFS* pSymbols = new RVAOFS[n])
		{
			MD md(pdb);

			if (n = LoadSymbols(pdb, stream, size, md, pSymbols, 0, FALSE))
			{
				qsort(pSymbols, n, sizeof(RVAOFS), (QSORTFN)compare);
			}

			if (n += LoadSymbols(pdb, stream, size, md, pSymbols, n, TRUE))
			{
				qsort(pSymbols, n, sizeof(RVAOFS), (QSORTFN)compare);

				pss->Symbols(pSymbols, n, (PSTR)stream);
			}

			delete [] pSymbols;

			return STATUS_SUCCESS;
		}

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS ParsePDB(PdbFileHeader* header, SIZE_T ViewSize, const GUID* signature, DWORD age, SymStore* pss)
{
	PdbReader pdb{};

	ULONG size;
	PVOID pv;
	NTSTATUS status = pdb.Init(header, ViewSize, signature, age);

	if (0 <= status)
	{
		status = STATUS_NOT_FOUND;

		USHORT symrecStream = pdb.getPublicSymbolsStreamIndex();

		if (symrecStream != MAXUSHORT)
		{
			if (0 <= (status = pdb.getStream(symrecStream, &pv, &size)))
			{
				status = LoadPublicSymbols(&pdb, pv, size, pss);
				pdb.FreeStream(pv);
			}
		}
	}

	return status; 
}

_NT_END