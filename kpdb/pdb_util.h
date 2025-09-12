#pragma once

#ifndef _CV_INFO_PDB_DEFINED_
#define _CV_INFO_PDB_DEFINED_

struct CV_INFO_PDB 
{
	DWORD CvSignature;
	GUID Signature;
	DWORD Age;
	char PdbFileName[];
};

#endif

struct RVAOFS
{
	ULONG rva, ofs;
};

struct __declspec(novtable) SymStore 
{
	NTSTATUS GetSymbols(HMODULE hmod, PCWSTR NtSymbolPath);

	NTSTATUS GetSymbols(PCWSTR PdbPath);

	virtual void Symbols(_In_ RVAOFS* pSymbols, _In_ ULONG nSymbols, _In_ PSTR names) = 0;

	virtual NTSTATUS OnOpenPdb(NTSTATUS status, CV_INFO_PDB* /*lpcvh*/)
	{
		return status;
	}

	virtual BOOL IncludeSymbol(_In_ PCSTR name);

private:

	NTSTATUS GetSymbols(HANDLE hFile, PGUID signature, DWORD age);
};