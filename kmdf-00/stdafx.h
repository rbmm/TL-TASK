#ifndef __cplusplus
#	error requires C++
#endif

#ifdef _M_IX86
#define _X86_
#elif defined _M_AMD64
#define _AMD64_
#elif defined _M_ARM64
#define _ARM64_
#endif

#define DECLSPEC_DEPRECATED_DDK

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 0

#define _NT_BEGIN namespace NT {
#define _NT_END }

#pragma warning(disable : 4073 4074 4075 4097 4514 4005 4200 4201 4238 4307 4324 4471 4480 4530 4706 5040)

#define DBG 1
#include <sdkddkver.h>
#include <ntifs.h>
#include <wdf.h>