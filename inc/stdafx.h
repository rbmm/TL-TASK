#pragma once

#ifndef __cplusplus
#	error requires C++
#endif

#define DECLSPEC_DEPRECATED_DDK

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _NO_CRT_STDIO_INLINE
#define _NO_CPP_INLINES
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 0
#define _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#define __EDG__
#define USE_ATL_THUNK2

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#define DPAPI_IMP DECLSPEC_IMPORT
#define _CRTIMP DECLSPEC_IMPORT
#define _CRTIMP_ALT DECLSPEC_IMPORT

#define _NT_BEGIN namespace NT {
#define _NT_END }

#pragma warning(disable : 4073 4074 4075 4097 4514 4005 4200 4201 4238 4307 4324 4480 4530 4706 5040)

_NT_BEGIN

struct _SECURITY_QUALITY_OF_SERVICE;
struct _CONTEXT;

_NT_END

#include <stdlib.h>
//#include <wchar.h>
#include <stdio.h>
#include <string.h>


#ifndef _CRT_CONCATENATE
#define _CRT_CONCATENATE_(a, b) a ## b
#define _CRT_CONCATENATE(a, b)  _CRT_CONCATENATE_(a, b)
#endif

#define RANDOM_NAME _CRT_CONCATENATE(_, __COUNTER__)

#define RtlOsDeploymentState				RANDOM_NAME
#define RtlInitializeCorrelationVector		RANDOM_NAME
#define RtlIncrementCorrelationVector		RANDOM_NAME
#define RtlExtendCorrelationVector			RANDOM_NAME
#define RtlValidateCorrelationVector		RANDOM_NAME
#define RtlRaiseCustomSystemEventTrigger	RANDOM_NAME
#define RtlCaptureContext					RANDOM_NAME
#define RtlGetNonVolatileToken				RANDOM_NAME
#define RtlFreeNonVolatileToken				RANDOM_NAME
#define RtlFlushNonVolatileMemory			RANDOM_NAME
#define RtlDrainNonVolatileFlush			RANDOM_NAME
#define RtlWriteNonVolatileMemory			RANDOM_NAME
#define RtlFillNonVolatileMemory			RANDOM_NAME
#define RtlFlushNonVolatileMemoryRanges		RANDOM_NAME
#define RtlCaptureContext2					RANDOM_NAME
#define RtlGetSystemGlobalData				RANDOM_NAME
#define RtlSetSystemGlobalData				RANDOM_NAME
#define CUSTOM_SYSTEM_EVENT_TRIGGER_INIT	RANDOM_NAME

#define _INC_MMSYSTEM  /* Prevent inclusion of mmsystem.h in windows.h */

#include <WinSock2.h>
#include <intrin.h>

#undef RtlOsDeploymentState
#undef RtlInitializeCorrelationVector
#undef RtlIncrementCorrelationVector
#undef RtlExtendCorrelationVector
#undef RtlValidateCorrelationVector
#undef RtlRaiseCustomSystemEventTrigger
#undef RtlCaptureContext
#undef RtlGetNonVolatileToken
#undef RtlFreeNonVolatileToken
#undef RtlFlushNonVolatileMemory
#undef RtlDrainNonVolatileFlush
#undef RtlWriteNonVolatileMemory
#undef RtlFillNonVolatileMemory
#undef RtlFlushNonVolatileMemoryRanges
#undef RtlCaptureContext2
#undef RtlGetSystemGlobalData
#undef RtlSetSystemGlobalData
#undef CUSTOM_SYSTEM_EVENT_TRIGGER_INIT

#ifdef SECURITY_WIN32
#define InitSecurityInterfaceW _InitSecurityInterfaceW_
#include <Sspi.h>
#undef InitSecurityInterfaceW
#endif // SECURITY_WIN32

#undef _INC_MMSYSTEM

_NT_BEGIN

#ifdef _RTL_RUN_ONCE_DEF
#undef _RTL_RUN_ONCE_DEF
#endif

typedef
VOID
NTAPI
KNORMAL_ROUTINE (
				 __in_opt PVOID NormalContext,
				 __in_opt PVOID SystemArgument1,
				 __in_opt PVOID SystemArgument2
				 );
typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;

typedef
VOID
NTAPI
KKERNEL_ROUTINE (
				 __in struct _KAPC *Apc,
				 __deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
				 __deref_inout_opt PVOID *NormalContext,
				 __deref_inout_opt PVOID *SystemArgument1,
				 __deref_inout_opt PVOID *SystemArgument2
				 );
typedef KKERNEL_ROUTINE *PKKERNEL_ROUTINE;

typedef
VOID
NTAPI
KRUNDOWN_ROUTINE (
				  __in struct _KAPC *Apc
				  );
typedef KRUNDOWN_ROUTINE *PKRUNDOWN_ROUTINE;

#ifdef NOWINBASEINTERLOCK

#if !defined(_X86_)

#define InterlockedPopEntrySList(Head) ExpInterlockedPopEntrySList(Head)

#define InterlockedPushEntrySList(Head, Entry) ExpInterlockedPushEntrySList(Head, Entry)

#define InterlockedFlushSList(Head) ExpInterlockedFlushSList(Head)

#else // !defined(_X86_)

EXTERN_C_START

__declspec(dllimport)
PSLIST_ENTRY
__fastcall
InterlockedPopEntrySList (PSLIST_HEADER ListHead);

__declspec(dllimport)
PSLIST_ENTRY
__fastcall
InterlockedPushEntrySList (PSLIST_HEADER ListHead,PSLIST_ENTRY ListEntry);

EXTERN_C_END

#define InterlockedFlushSList(Head) \
	ExInterlockedFlushSList(Head)

#endif // !defined(_X86_)

#endif//NOWINBASEINTERLOCK

#include <ntifs.h>

#include "ntpebteb.h"
#include "sysinfo.h"
#include "sys api.h"
#include "misc.h"

_NT_END

#pragma warning(disable : 4312 4838)
//#pragma warning(disable : 4312 4838 4456 4457 4458 4459)

//warning C4312: 'type cast': conversion from '' to '' of greater size
//warning C4838: conversion from 'unsigned long' to 'LONG' requires a narrowing conversion
//warning C4456: declaration of '' hides previous local declaration
//warning C4457: declaration of '' hides function parameter
//warning C4458: declaration of '' hides class member
//warning C4459: declaration of '' hides global declaration

#define ZwSetValueKey(KeyHandle,ValueName,TitleIndex,Type,Data,DataSize) \
	ZwSetValueKey(KeyHandle,const_cast<PUNICODE_STRING>(ValueName),TitleIndex,Type,Data,DataSize)

#define ZwQueryValueKey(KeyHandle,ValueName,KeyValueInformationClass,KeyValueInformation,Length,ResultLength) \
	ZwQueryValueKey(KeyHandle,const_cast<PUNICODE_STRING>(ValueName),KeyValueInformationClass,KeyValueInformation,Length,ResultLength)

#define ZwDeleteValueKey(KeyHandle,ValueName) ZwDeleteValueKey(KeyHandle,const_cast<PUNICODE_STRING>(ValueName))

enum __MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation
};

#define MemoryWorkingSetInformation			((MEMORY_INFORMATION_CLASS)MemoryWorkingSetInformation) 
#define MemoryMappedFilenameInformation		((MEMORY_INFORMATION_CLASS)MemoryMappedFilenameInformation) 
#define MemoryRegionInformation				((MEMORY_INFORMATION_CLASS)MemoryRegionInformation) 
#define MemoryWorkingSetExInformation		((MEMORY_INFORMATION_CLASS)MemoryWorkingSetExInformation) 

enum __OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectAllTypeInformation = ObjectTypesInformation,
	ObjectHandleInformation
};

#define ObjectNameInformation				((OBJECT_INFORMATION_CLASS)ObjectNameInformation)
#define ObjectTypesInformation				((OBJECT_INFORMATION_CLASS)ObjectTypesInformation)
#define ObjectAllTypeInformation			((OBJECT_INFORMATION_CLASS)ObjectAllTypeInformation)
#define ObjectHandleInformation				((OBJECT_INFORMATION_CLASS)ObjectHandleInformation)

#define swprintf     _swprintf
#define vswprintf    _vswprintf
#define _swprintf_l  __swprintf_l
#define _vswprintf_l __vswprintf_l
