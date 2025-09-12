#include "stdafx.h"

_NT_BEGIN

#include "module.h"

ULONG* __fastcall findDWORD(SIZE_T, const ULONG*, ULONG);

ULONG HashString(PCSTR lpsz, ULONG hash /*= 0*/)
{
	while (char c = *lpsz++) hash = hash * 33 + (c | 0x20);
	return hash;
}

void LoadNtModule(ULONG n, const ULONG ph[])
{
	ULONG cb = 0x10000;
	NTSTATUS status;
	do 
	{
		status = STATUS_INSUFF_SERVER_RESOURCES;
		if (PRTL_PROCESS_MODULES buf = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, cb += PAGE_SIZE))
		{
			if (0 <= (status = NtQuerySystemInformation(SystemModuleInformation, buf, cb, &cb)))
			{
				if (ULONG NumberOfModules = buf->NumberOfModules)
				{
					PRTL_PROCESS_MODULE_INFORMATION Modules = buf->Modules;
					do 
					{
						PCSTR name = Modules->FullPathName + Modules->OffsetToFileName;
						ULONG hash = HashString(name);

						// DbgPrint("%08X %hs\r\n", hash, name);

						if (findDWORD(n, ph, hash))
						{
							CModule::Create(hash, name, Modules->ImageBase, Modules->ImageSize);
						}
					} while (Modules++, --NumberOfModules);
				}
			}

			ExFreePool(buf);
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);
}

void DumpStack(PCSTR txt)
{
	PVOID pv[32];
	if (ULONG n = RtlWalkFrameChain(pv, _countof(pv), 0))
	{
		DbgPrint(">>> ************* %s\n", txt);

		do 
		{
			PVOID p = pv[--n];
			ULONG d;
			PCSTR name;

			if (PCSTR psz = CModule::GetNameFromVa(p, &d, &name))
			{
				DbgPrint(">> %p %s!%s + %x\n", p, name, psz, d);
			}
			else
			{
				DbgPrint(">> %p\n", p);
			}
		} while (n);

		DbgPrint("<<<< ************* %s\n", txt);
	}
}

_NT_END