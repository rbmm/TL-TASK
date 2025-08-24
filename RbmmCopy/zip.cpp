#include "stdafx.h"
#include <compressapi.h>
#include "zip.h"

HRESULT Unzip(_In_ LPCVOID CompressedData,
			  _In_ ULONG CompressedDataSize,
			  _Out_ PVOID* pUncompressedBuffer,
			  _Out_ ULONG* pUncompressedDataSize)
{
	ULONG dwError;
	COMPRESSOR_HANDLE DecompressorHandle;

	if (NOERROR == (dwError = NT::BOOL_TO_ERROR(CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, 0, &DecompressorHandle))))
	{
		SIZE_T UncompressedBufferSize = 0;
		PVOID UncompressedBuffer = 0;

		while (ERROR_INSUFFICIENT_BUFFER == (dwError = NT::BOOL_TO_ERROR(Decompress(
			DecompressorHandle, CompressedData, CompressedDataSize, 
			UncompressedBuffer, UncompressedBufferSize, &UncompressedBufferSize))) && !UncompressedBuffer)
		{
			if (!(UncompressedBuffer = LocalAlloc(LMEM_FIXED, UncompressedBufferSize)))
			{
				dwError = ERROR_OUTOFMEMORY;
				break;
			}
		}

		if (NOERROR == dwError)
		{
			if (UncompressedBuffer)
			{
				*pUncompressedDataSize = (ULONG)UncompressedBufferSize;
				*pUncompressedBuffer = UncompressedBuffer, UncompressedBuffer = 0;
			}
			else
			{
				dwError = ERROR_INTERNAL_ERROR;
			}
		}

		if (UncompressedBuffer)
		{
			LocalFree(UncompressedBuffer);
		}

		CloseDecompressor(DecompressorHandle);
	}

	return HRESULT_FROM_WIN32(dwError);
}