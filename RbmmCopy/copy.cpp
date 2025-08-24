#include "stdafx.h"

_NT_BEGIN

#include "print.h"

extern volatile UCHAR guz = 0;

NTSTATUS CopyStream(HANDLE hFromFile, 
					HANDLE hToFile, 
					PVOID buf, 
					ULONG cb, 
					PLARGE_INTEGER StreamSize)
{
	if (!StreamSize->QuadPart)
	{
		return STATUS_SUCCESS;
	}
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	ULONG len;
	LARGE_INTEGER ByteOffset = {};
	do 
	{
		len = (ULONG)min(cb, StreamSize->QuadPart);

		if (0 > (status = NtReadFile(hFromFile, 0, 0, 0, &iosb, buf, len, &ByteOffset, 0)) ||
			0 > (status = NtWriteFile(hToFile, 0, 0, 0, &iosb, buf, len, &ByteOffset, 0)))
		{
			break;
		}

	} while (ByteOffset.QuadPart += len, StreamSize->QuadPart -= len);

	return status;
}

NTSTATUS CopyStream(POBJECT_ATTRIBUTES poaFrom, 
					POBJECT_ATTRIBUTES poaTo, 
					PVOID buf, 
					ULONG cb, 
					PLARGE_INTEGER StreamSize)
{
	DbgPrint("\t%wZ\r\n", poaTo->ObjectName);

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	HANDLE hFromFile, hToFile;
	if (0 <= (status = NtOpenFile(&hFromFile, FILE_GENERIC_READ, poaFrom, &iosb, FILE_SHARE_READ, 
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_FOR_BACKUP_INTENT|FILE_OPEN_REPARSE_POINT|FILE_NON_DIRECTORY_FILE)))
	{
		if (0 <= (status = NtCreateFile(&hToFile, FILE_GENERIC_WRITE, poaTo, &iosb, StreamSize, 0, 
			FILE_SHARE_VALID_FLAGS, FILE_OVERWRITE_IF, 
			FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_FOR_BACKUP_INTENT|FILE_OPEN_REPARSE_POINT|FILE_NON_DIRECTORY_FILE, 0, 0)))
		{
			status = CopyStream(hFromFile, hToFile, buf, cb, StreamSize);

			NtClose(hToFile);
		}

		NtClose(hFromFile);
	}

	return status;
}

#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())

static ULONG _S_T0, _S_T1;
BOOLEAN _S_T;

// BOOLEAN RtlpValidTrustSubjectContext(PSID CallerSid, PSID AceSid, PNTSTATUS pstatus);
// BOOLEAN RtlIsValidProcessTrustLabelSid(PSID Sid); // S-1-19-x-y

BOOLEAN GetTrustedLevel(_In_ PSID Sid, _Out_ PULONG p, _Out_ PULONG q)
{
	static const SID_IDENTIFIER_AUTHORITY TRUST_AUTHORITY = SECURITY_PROCESS_TRUST_AUTHORITY;
	if (SECURITY_PROCESS_TRUST_AUTHORITY_RID_COUNT == *RtlSubAuthorityCountSid(Sid) &&
		!memcmp(&TRUST_AUTHORITY, RtlIdentifierAuthoritySid(Sid), sizeof(TRUST_AUTHORITY)))
	{
		*p = *RtlSubAuthoritySid(Sid, 0), *q = *RtlSubAuthoritySid(Sid, 1);
		return TRUE;
	}

	return FALSE;
}

void InitTrustedLevel()
{
	PVOID stack = alloca(guz);

	union {
		PVOID buf;
		PTOKEN_SID_INFORMATION ptsi;
	};

	ULONG cb = 0, rcb = sizeof(TOKEN_SID_INFORMATION) + SECURITY_SID_SIZE(SECURITY_PROCESS_TRUST_AUTHORITY_RID_COUNT);

	NTSTATUS status;
	do
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		if (0 <= (status = NtQueryInformationToken(NtCurrentProcessToken(), TokenProcessTrustLevel, buf, cb, &rcb)))
		{
			if (PSID Sid = ptsi->Sid)
			{
				GetTrustedLevel(Sid, &_S_T0, &_S_T1);
				_S_T = TRUE;
				DbgPrint("My TL=[%u-%u]\r\n", _S_T0, _S_T1);
			}
			break;
		}
	} while (STATUS_BUFFER_TOO_SMALL == status);
}

BOOLEAN IsMoreTrustedSD(PSECURITY_DESCRIPTOR SecurityDescriptor, PBOOLEAN pbTrusted)
{
	PACL Acl;
	BOOLEAN bPresent, bDefault;
	if (0 <= RtlGetSaclSecurityDescriptor(SecurityDescriptor, &bPresent, &Acl, &bDefault) && bPresent && Acl)
	{
		if (ULONG AceCount = Acl->AceCount)
		{
			union {
				PVOID pv;
				PBYTE pb;
				PACE_HEADER ph;
				PSYSTEM_PROCESS_TRUST_LABEL_ACE pah;
			};

			pv = Acl + 1;

			do 
			{
				switch (ph->AceType)
				{
				case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
					ULONG T0, T1;

					if (GetTrustedLevel(&pah->SidStart, &T0, &T1))
					{
						*pbTrusted = TRUE;
						// DbgPrint("TL: %08X[%u-%u]\r\n", pah->Mask, T0, T1);
					}

					if (_S_T0 < T0 || _S_T1 < T1 || !_S_T)
					{
						return TRUE;
					}
				}
			} while (pb += ph->AceSize, --AceCount);
		}
	}

	return FALSE;
}

struct CS 
{
	LARGE_INTEGER _M_nSize {};
	PVOID _M_Bufeer = new UCHAR[0x20000 + 0x100000];// SD, EA, streams
	ULONG _M_cb = 0x20000, _M_cb2 = 0x100000;
	ULONG _M_nFolders = 0, _M_nFiles = 0, _M_nEA = 0, _M_nAlt = 0, _M_nTL = 0, _M_nRP = 0;
	ULONG _M_Tick = NextTick();
	BOOLEAN _M_TL = FALSE, _M_MT = FALSE;
	USHORT _M_len = 0, _M_len0;
	WCHAR _M_buf[MAXSHORT];

	ULONG NextTick()
	{
		return GetTickCount() + 500;
	}

	NTSTATUS Copy(POBJECT_ATTRIBUTES poaFrom, PFILE_BASIC_INFORMATION pfbi);

	~CS()
	{
		if (_M_Bufeer)
		{
			delete [] _M_Bufeer;
		}
	}

	BOOL Stat()
	{
		if (_M_Tick <= GetTickCount())
		{
			DbgPrint("FILE=%x(%x) DIR=%x EA=%x ALT=%x TL=%x RP=%x SIZE=%I64u\r\n", 
				_M_nFiles, _M_nFiles + _M_nFolders, _M_nFolders, _M_nEA, _M_nAlt, _M_nTL, _M_nRP, _M_nSize);

			_M_Tick = NextTick();

			return TRUE;
		}

		return FALSE;
	}

	NTSTATUS SetDestantion(PCWSTR pszTo, PCWSTR FileName)
	{
		UNICODE_STRING Destination = { 0, sizeof(_M_buf), _M_buf }, ObjectName;

		RtlAppendUnicodeToString(&Destination, L"\\Device\\D8F86BDE6363440e821FB5F0B9C9FF4F");

		_M_len0 = Destination.Length;

		NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(pszTo, &ObjectName, 0, 0);

		if (0 <= status)
		{
			status = RtlAppendUnicodeStringToString(&Destination, &ObjectName);
			RtlFreeUnicodeString(&ObjectName);
			if (0 <= status)
			{
				status = RtlAppendUnicodeToString(&Destination, FileName);
			}
		}

		_M_len = Destination.Length;

		return status;
	}
};

NTSTATUS CS::Copy(POBJECT_ATTRIBUTES poaFrom, PFILE_BASIC_INFORMATION pfbi)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	USHORT Length = _M_len;
	UNICODE_STRING Destination = { Length, sizeof(_M_buf), _M_buf }, ObjectName;
	PWSTR pszPath = (PWSTR)RtlOffsetToPointer(_M_buf, _M_len0);

	ULONG CreateDisposition, CreateOptions;

	if (FILE_ATTRIBUTE_DIRECTORY & pfbi->FileAttributes)
	{
		_M_nFolders++;
		CreateDisposition = FILE_OPEN_IF;
		CreateOptions = FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_REPARSE_POINT|FILE_OPEN_FOR_BACKUP_INTENT;

		if (0 > (status = RtlAppendUnicodeToString(&Destination, L"\\")))
		{
			return status;
		}
		Length += sizeof(WCHAR);
	}
	else
	{
		_M_nFiles++;
		CreateDisposition = FILE_OVERWRITE_IF;
		CreateOptions = FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_REPARSE_POINT|FILE_OPEN_FOR_BACKUP_INTENT;
	}

	if (Stat())
	{
		DbgPrint("[%08x] %ws\r\n", pfbi->FileAttributes, pszPath);
	}

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName }, oaTo = { sizeof(oaTo), 0, &ObjectName };

	if (0 <= (status = NtOpenFile(&oa.RootDirectory, FILE_GENERIC_READ|ACCESS_SYSTEM_SECURITY, 
		poaFrom, &iosb, FILE_SHARE_READ, CreateOptions)))
	{
		PUCHAR pb = (PBYTE)_M_Bufeer;
		ULONG cb = _M_cb, len;

		if (0 <= (status = NtQuerySecurityObject(oa.RootDirectory, 
			ACCESS_FILTER_SECURITY_INFORMATION|
			PROCESS_TRUST_LABEL_SECURITY_INFORMATION|
			SCOPE_SECURITY_INFORMATION|
			ATTRIBUTE_SECURITY_INFORMATION|
			LABEL_SECURITY_INFORMATION|
			SACL_SECURITY_INFORMATION|
			DACL_SECURITY_INFORMATION|
			GROUP_SECURITY_INFORMATION|
			OWNER_SECURITY_INFORMATION,
			oaTo.SecurityDescriptor = pb, cb, &len)))
		{
			reinterpret_cast<SECURITY_DESCRIPTOR*>(pb)->Control |= 
				SE_SACL_PROTECTED|SE_DACL_PROTECTED|SE_DACL_PRESENT|SE_SACL_PRESENT;

			len += __alignof(FILE_STREAM_INFORMATION) - 1;
			len &= ~(__alignof(FILE_STREAM_INFORMATION) - 1);
			pb += len, cb -= len, len = 0;

			PFILE_STREAM_INFORMATION pfsi = (PFILE_STREAM_INFORMATION)pb;

			if (0 <= (status = NtQueryInformationFile(oa.RootDirectory, &iosb, pfsi, cb, FileStreamInformation)))
			{
				len = ((ULONG)iosb.Information + (__alignof(FILE_FULL_EA_INFORMATION) - 1)) 
					& ~(__alignof(FILE_FULL_EA_INFORMATION) - 1);

				pb += len, cb -= len, len = 0;

				PVOID EaBuffer = 0;
				ULONG EaLength = 0;

				switch (status = ZwQueryEaFile(oa.RootDirectory, &iosb, pb, cb, FALSE, 0, 0, 0, FALSE))
				{
				case STATUS_SUCCESS:
					EaBuffer = pb;
					EaLength = (ULONG)iosb.Information;
					_M_nEA++;

					[[fallthrough]];

				case STATUS_NO_EAS_ON_FILE:

					BOOLEAN bTrustLabel = FALSE, bMoreTrust = IsMoreTrustedSD(oaTo.SecurityDescriptor, &bTrustLabel);

					if (bTrustLabel)
					{
						_M_nTL++;
					}

					if (bMoreTrust || _M_MT)
					{
						ObjectName.Buffer = _M_buf;
						ObjectName.Length = _M_len;
					}
					else
					{
						ObjectName.Buffer = pszPath;
						ObjectName.Length = _M_len - _M_len0;
					}

					ObjectName.MaximumLength = ObjectName.Length;

					switch (status = NtCreateFile(&oaTo.RootDirectory, 
						FILE_GENERIC_WRITE|ACCESS_SYSTEM_SECURITY, 
						&oaTo, &iosb, 0, pfbi->FileAttributes, FILE_SHARE_VALID_FLAGS, 
						CreateDisposition, CreateOptions, EaBuffer, EaLength))
					{
					case STATUS_SINGLE_STEP:
						if (ObjectName.Buffer == pszPath)
						{
							break;
						}
						oaTo.RootDirectory = (HANDLE)iosb.Information;

						[[fallthrough]];

					case STATUS_SUCCESS:

						cb = _M_cb2, pb = (PBYTE)_M_Bufeer + _M_cb;

						ULONG NextEntryOffset = 0;
						do 
						{
							pfsi = (PFILE_STREAM_INFORMATION)RtlOffsetToPointer(pfsi, NextEntryOffset);

							ObjectName.Buffer = pfsi->StreamName;

							if (ObjectName.MaximumLength = ObjectName.Length = (USHORT)pfsi->StreamNameLength)
							{
								_M_nSize.QuadPart += pfsi->StreamSize.QuadPart;

								STATIC_UNICODE_STRING(DATA, "::$DATA");
								if (0 > (status = RtlEqualUnicodeString(&DATA, &ObjectName, FALSE) 
									? CopyStream(oa.RootDirectory, oaTo.RootDirectory, pb, cb, &pfsi->StreamSize)
									: (_M_nAlt++, CopyStream(&oa, &oaTo, pb, cb, &pfsi->StreamSize))))
								{
									DbgPrint("!! CopyStream[%x]: %ws%wZ\r\n", bTrustLabel, pszPath, &ObjectName);
									goto __0;
								}
							}

						} while (NextEntryOffset = pfsi->NextEntryOffset);

						if (FILE_ATTRIBUTE_DIRECTORY & pfbi->FileAttributes)
						{
							enum { cb_buf = 0x10000 };

							if (PVOID buf = new UCHAR[cb_buf])
							{
								BOOLEAN TL = _M_TL, MT = _M_MT;

								_M_TL = bTrustLabel, _M_MT = bMoreTrust;

								while (0 <= (status = NtQueryDirectoryFile(oa.RootDirectory, 0, 0, 0, &iosb, 
									buf, cb_buf, FileDirectoryInformation, FALSE, 0, FALSE)))
								{
									NextEntryOffset = 0;
									PFILE_DIRECTORY_INFORMATION pfdi = (PFILE_DIRECTORY_INFORMATION)buf;

									do 
									{
										(ULONG_PTR&)pfdi += NextEntryOffset;

										switch (pfdi->FileNameLength)
										{
										case 2*sizeof(WCHAR):
											if ('.' != pfdi->FileName[1])
											{
												break;
											}
											[[fallthrough]];
										case sizeof(WCHAR):
											if ('.' == pfdi->FileName[0])
											{
												continue;
											}
											break;
										}

										ObjectName.MaximumLength = ObjectName.Length = (USHORT)pfdi->FileNameLength;
										ObjectName.Buffer = pfdi->FileName;

										Destination.Length = Length;
										if (0 > (status = RtlAppendUnicodeStringToString(&Destination, &ObjectName)))
										{
											break;
										}

										_M_len = Destination.Length;

										if (FILE_ATTRIBUTE_REPARSE_POINT & pfdi->FileAttributes)
										{
											_M_nRP++;
											continue;
										}

										FILE_BASIC_INFORMATION fbi = {
											pfdi->CreationTime, 
											pfdi->LastAccessTime, 
											pfdi->LastWriteTime, 
											pfdi->ChangeTime, 
											pfdi->FileAttributes
										};

										Copy(&oa, &fbi);

									} while (NextEntryOffset = pfdi->NextEntryOffset);
								}

								_M_TL = TL, _M_MT = MT;

								_M_len = Length;

								if (STATUS_NO_MORE_FILES == status)
								{
									status = STATUS_SUCCESS;
								}

								delete [] buf;
							}
						}

						status = NtSetInformationFile(oaTo.RootDirectory, &iosb, pfbi, sizeof(*pfbi), FileBasicInformation);

__0:
						NtClose(oaTo.RootDirectory);
					}

					break;
				}
			}
		}

		NtClose(oa.RootDirectory);
	}

	if (0 > status)
	{
		DbgPrint("!! %X %ws\r\n", status, pszPath);
	}

	return status;
}

EXTERN_C 
NTSYSAPI 
NTSTATUS 
NTAPI 
NtQueryAttributesFile(_In_ POBJECT_ATTRIBUTES poa, _Out_ PFILE_BASIC_INFORMATION pfbi);

void RemoveEnd(PWSTR psz)
{
	psz += wcslen(psz);
__loop:
	switch (*--psz)
	{
	case '\\':
	case '/':
	case ' ':
		*psz = 0;
		goto __loop;
	}
}

NTSTATUS robocopy(PWSTR pszFrom, PWSTR pszTo)
{
	RemoveEnd(pszFrom);
	RemoveEnd(pszTo);

	InitTrustedLevel();

	NTSTATUS status = STATUS_NO_MEMORY;

	if (CS* pcs = new CS)
	{
		if (pcs->_M_Bufeer)
		{
			UNICODE_STRING ObjectName;
			PWSTR FileName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };

			if (0 <= (status = RtlDosPathNameToNtPathName_U_WithStatus(pszFrom, &ObjectName, &FileName, 0)))
			{
				if (FileName && '\\' == *--FileName)
				{
					FILE_BASIC_INFORMATION fbi;
					if (0 <= (status = NtQueryAttributesFile(&oa, &fbi)))
					{
						if (0 <= (status = pcs->SetDestantion(pszTo, FileName)))
						{
							status = pcs->Copy(&oa, &fbi);
						}
					}
				}
				else
				{
					status = STATUS_OBJECT_PATH_SYNTAX_BAD;
				}

				RtlFreeUnicodeString(&ObjectName);
			}

			pcs->_M_Tick = 0;
			pcs->Stat();

			DbgPrint("copy=%x\r\n", status);
		}

		delete pcs;
	}

	return status;
}

_NT_END