
/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   Transport Inspect Proxy Callout Driver Sample.

   This sample callout driver intercepts all transport layer traffic (e.g.
   TCP, UDP, and non-error ICMP) sent to or receive from a (configurable)
   remote peer and queue them to a worker thread for out-of-band processing.
   The sample performs inspection of inbound and outbound connections as
   well as all packets belong to those connections.  In addition the sample
   demonstrates special considerations required to be compatible with Windows
   Vista and Windows Server 2008’s IpSec implementation.

   Inspection parameters are configurable via the following registry
   values --

   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Inspect\Parameters

    o  BlockTraffic (REG_DWORD) : 0 (permit, default); 1 (block)
    o  RemoteAddressToInspect (REG_SZ) : literal IPv4/IPv6 string
                                                (e.g. “10.0.0.1”)
   The sample is IP version agnostic. It performs inspection for
   both IPv4 and IPv6 traffic.

Environment:

    Kernel mode

--*/

#include "stdafx.h"


_NT_BEGIN

#include "inspect.h"

#define INITGUID
#include <guiddef.h>
#include <fwpmk.h>

IN_ADDR  remoteAddrStorageV4;
IN6_ADDR remoteAddrStorageV6;

// 
// Configurable parameters (addresses and ports are in host order)
//

BOOLEAN configPermitTraffic = TRUE;

UINT8* configInspectRemoteAddrV4 = NULL;
UINT8* configInspectRemoteAddrV6 = NULL;


// 
// Callout and sublayer GUIDs
//

// bb6e405b-19f4-4ff3-b501-1a3dc01aae01
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4,
    0xbb6e405b,
    0x19f4,
    0x4ff3,
    0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x01
);
// cabf7559-7c60-46c8-9d3b-2155ad5cf83f
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V6,
    0xcabf7559,
    0x7c60,
    0x46c8,
    0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x3f
);
// 07248379-248b-4e49-bf07-24d99d52f8d0
DEFINE_GUID(
    TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V4,
    0x07248379,
    0x248b,
    0x4e49,
    0xbf, 0x07, 0x24, 0xd9, 0x9d, 0x52, 0xf8, 0xd0
);
// 6d126434-ed67-4285-925c-cb29282e0e06
DEFINE_GUID(
    TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V6,
    0x6d126434,
    0xed67,
    0x4285,
    0x92, 0x5c, 0xcb, 0x29, 0x28, 0x2e, 0x0e, 0x06
);
// 76b743d4-1249-4614-a632-6f9c4d08d25a
DEFINE_GUID(
    TL_INSPECT_ALE_CONNECT_CALLOUT_V4,
    0x76b743d4,
    0x1249,
    0x4614,
    0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5a
);

// ac80683a-5b84-43c3-8ae9-eddb5c0d23c2
DEFINE_GUID(
    TL_INSPECT_ALE_CONNECT_CALLOUT_V6,
    0xac80683a,
    0x5b84,
    0x43c3,
    0x8a, 0xe9, 0xed, 0xdb, 0x5c, 0x0d, 0x23, 0xc2
);

// 7ec7f7f5-0c55-4121-adc5-5d07d2ac0cef
DEFINE_GUID(
    TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V4,
    0x7ec7f7f5,
    0x0c55,
    0x4121,
    0xad, 0xc5, 0x5d, 0x07, 0xd2, 0xac, 0x0c, 0xef
);

// b74ac2ed-4e71-4564-9975-787d5168a151
DEFINE_GUID(
    TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V6,
    0xb74ac2ed,
    0x4e71,
    0x4564,
    0x99, 0x75, 0x78, 0x7d, 0x51, 0x68, 0xa1, 0x51
);

// 2e207682-d95f-4525-b966-969f26587f03
DEFINE_GUID(
    TL_INSPECT_SUBLAYER,
    0x2e207682,
    0xd95f,
    0x4525,
    0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

// 
// Callout driver global variables
//

HANDLE gParametersKey;

HANDLE gEngineHandle;
UINT32 gAleConnectCalloutIdV4, gOutboundTlCalloutIdV4;
UINT32 gAleRecvAcceptCalloutIdV4, gInboundTlCalloutIdV4;
UINT32 gAleConnectCalloutIdV6, gOutboundTlCalloutIdV6;
UINT32 gAleRecvAcceptCalloutIdV6, gInboundTlCalloutIdV6;

HANDLE gInjectionHandle;

LIST_ENTRY gConnList;
KSPIN_LOCK gConnListLock;
LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;

KEVENT gWorkerEvent;

BOOLEAN gDriverUnloading = FALSE;
void* gThreadObj;

inline NTSTATUS ifRegSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
    switch (pkvpi->Type)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
        if (pkvpi->DataLength >= sizeof(WCHAR) &&
            !(pkvpi->DataLength & 1) &&
            !*(PWSTR)(pkvpi->Data + pkvpi->DataLength - sizeof(WCHAR)))
        {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS IsRegMultiSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	ULONG DataLength;
	return REG_MULTI_SZ == pkvpi->Type && 
		sizeof(WCHAR) < (DataLength = pkvpi->DataLength) && 
		!(DataLength & (sizeof(WCHAR) - 1)) &&
		!*(PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength - 2 * sizeof(WCHAR)) &&
		!*(PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength - sizeof(WCHAR)) ? STATUS_SUCCESS : STATUS_OBJECT_TYPE_MISMATCH;
}

extern volatile UCHAR guz = 0;

NTSTATUS
TLInspectLoadConfig(
					_In_ HANDLE hKey,
					_Out_ PULONG pn,
					_Out_ FWPM_FILTER_CONDITION** pfilterConditions
					)
{
	NTSTATUS status;
	DECLARE_CONST_UNICODE_STRING(valueName, L"WhiteList");

	union {
		PVOID buf;
		PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi;
	};

	ULONG cb = 0, rcb = sizeof(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64) + 0x20;
	PVOID stack = alloca(guz);

	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		status = ZwQueryValueKey(hKey, const_cast<PUNICODE_STRING>(&valueName), KeyValuePartialInformationAlign64, buf, cb, &rcb);

	} while (STATUS_BUFFER_OVERFLOW == status);

	if (0 <= status && 0 <= (status = IsRegMultiSz(pkvpi)))
	{
		PCWSTR terminator, AddressString = (PCWSTR)pkvpi->Data;

		union {
			IN_ADDR  ipv4;
			in6_addr ipv6;
		};

		ULONG s = 0, n = 0;

		while (*AddressString)
		{
			if (0 <= RtlIpv4StringToAddressW(
				AddressString,
				TRUE,
				&terminator,
				&ipv4))
			{
				s += sizeof(FWPM_FILTER_CONDITION), n++;
			}
			else if (0 <= RtlIpv6StringToAddressW(
				AddressString,
				&terminator,
				(::in6_addr *)&ipv6
				))
			{
				s += sizeof(IN6_ADDR) + sizeof(FWPM_FILTER_CONDITION), n++;
			}

			AddressString += 1 + wcslen(AddressString);
		}

		if (n)
		{
#pragma warning(suppress : 4996)
			if (FWPM_FILTER_CONDITION* filterConditions = (FWPM_FILTER_CONDITION*)ExAllocatePool(NonPagedPoolNx, s))
			{
				*pfilterConditions = filterConditions, *pn = n;

				in6_addr* pipv6 = (in6_addr*)(filterConditions + n);
				AddressString = (PCWSTR)pkvpi->Data;

				do 
				{
					filterConditions->fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
					filterConditions->matchType = FWP_MATCH_NOT_EQUAL;

					if (0 <= (status = RtlIpv4StringToAddressW(
						AddressString,
						TRUE,
						&terminator,
						&ipv4
						)))
					{
						filterConditions->conditionValue.uint32 = _byteswap_ulong(ipv4.S_un.S_addr);
						filterConditions++->conditionValue.type = FWP_UINT32;
					}
					else if (0 <= (status = RtlIpv6StringToAddressW(
						AddressString,
						&terminator,
						(::in6_addr*)pipv6
						)))
					{
						filterConditions->conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)pipv6++->u.Byte;
						filterConditions++->conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
					}
				} while (*(AddressString += 1 + wcslen(AddressString)));

				return STATUS_SUCCESS;
			}

			return STATUS_NO_MEMORY;
		}

		return STATUS_DEVICE_CONFIGURATION_ERROR;
	}

	return status;
}

NTSTATUS
TLInspectLoadConfig(
    _In_ HANDLE hKey
)
{
    NTSTATUS status;
    DECLARE_CONST_UNICODE_STRING(valueName, L"RemoteAddressToInspect");

    union {
        ULONG64 align;
        KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 kvpi;
        UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64) + INET6_ADDRSTRLEN];
    };

    ULONG rcb;

    if (0 <= (status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformationAlign64, &kvpi, sizeof(buf), &rcb)) &&
        0 <= (status = ifRegSz(&kvpi)))
    {
        PCWSTR terminator;

        status = RtlIpv4StringToAddressW(
            (PWSTR)kvpi.Data,
            TRUE,
            &terminator,
            &remoteAddrStorageV4
        );

        if (NT_SUCCESS(status))
        {
            remoteAddrStorageV4.S_un.S_addr =
                RtlUlongByteSwap(remoteAddrStorageV4.S_un.S_addr);

            configInspectRemoteAddrV4 = &remoteAddrStorageV4.S_un.S_un_b.s_b1;
        }
        else
        {
            status = RtlIpv6StringToAddressW(
                (PWSTR)kvpi.Data,
                &terminator,
                (::in6_addr*) & remoteAddrStorageV6
            );

            if (NT_SUCCESS(status))
            {
                configInspectRemoteAddrV6 = (UINT8*)(&remoteAddrStorageV6.u.Byte[0]);
            }
			else
			{
				status = STATUS_DEVICE_CONFIGURATION_ERROR;
			}
        }
    }

    return status;
}

NTSTATUS
TLInspectAddFilter(
				   _In_ const wchar_t* filterName,
				   _In_ const wchar_t* filterDesc,
				   _In_ UINT32 numFilterConditions,
				   _In_ FWPM_FILTER_CONDITION* filterConditions,
				   _In_ UINT64 context,
				   _In_ const GUID& layerKey,
				   _In_ const GUID& calloutKey
				   )
{
	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 
		{}, 
		{ const_cast<wchar_t*>(filterName), const_cast<wchar_t*>(filterDesc) },
		FWPM_FILTER_FLAG_NONE, 
		0, 
		{}, 
		layerKey, 
		TL_INSPECT_SUBLAYER, 
		{FWP_EMPTY},
		numFilterConditions, filterConditions,
		{ FWP_ACTION_CALLOUT_TERMINATING, calloutKey },
		{context}
	};

	status = FwpmFilterAdd(
		gEngineHandle,
		&filter,
		NULL,
		NULL);

	DbgPrint("FwpmFilterAdd(%ws)=%x\r\n", filterName, status);

	return status;
}

NTSTATUS
TLInspectAddFilter(
    _In_ const wchar_t* filterName,
    _In_ const wchar_t* filterDesc,
    _In_reads_opt_(16) const UINT8* remoteAddr,
    _In_ UINT64 context,
    _In_ const GUID& layerKey,
    _In_ const GUID& calloutKey
)
{
    NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER_CONDITION filterConditions;

	FWPM_FILTER filter = { 
		{}, 
		{ const_cast<wchar_t*>(filterName), const_cast<wchar_t*>(filterDesc) },
		FWPM_FILTER_FLAG_NONE, 
		0, 
		{}, 
		layerKey, 
		TL_INSPECT_SUBLAYER, 
		{FWP_EMPTY},
		1, &filterConditions,
		{FWP_ACTION_CALLOUT_TERMINATING, calloutKey},
		{context}
	};

    if (remoteAddr)
    {
        filterConditions.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        filterConditions.matchType = FWP_MATCH_EQUAL;

        if (IsEqualGUID(layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
            IsEqualGUID(layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
            IsEqualGUID(layerKey, FWPM_LAYER_INBOUND_TRANSPORT_V4) ||
            IsEqualGUID(layerKey, FWPM_LAYER_OUTBOUND_TRANSPORT_V4))
        {
            filterConditions.conditionValue.type = FWP_UINT32;
            filterConditions.conditionValue.uint32 = *(UINT32*)remoteAddr;
        }
        else
        {
            filterConditions.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            filterConditions.conditionValue.byteArray16 = (FWP_BYTE_ARRAY16*)remoteAddr;
        }
    }

    status = FwpmFilterAdd(
        gEngineHandle,
        &filter,
        NULL,
        NULL);

	DbgPrint("FwpmFilterAdd(%ws)=%x\r\n", filterName, status);

    return status;
}

NTSTATUS
TLInspectRegisterALEClassifyCallouts(
    _In_ const GUID& layerKey,
    _In_ const GUID& calloutKey,
    _Inout_ void* deviceObject,
    _Out_ UINT32* calloutId
)
/* ++

   This function registers callouts and filters at the following layers
   to intercept inbound or outbound connect attempts.

      FWPM_LAYER_ALE_AUTH_CONNECT_V4
      FWPM_LAYER_ALE_AUTH_CONNECT_V6
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
      FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    FWPS_CALLOUT sCallout = {  };
    FWPM_CALLOUT mCallout = {  };

    FWPM_DISPLAY_DATA displayData = {  };

    BOOLEAN calloutRegistered = FALSE;

    sCallout.calloutKey = calloutKey;

    if (IsEqualGUID(layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
        IsEqualGUID(layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6))
    {
        sCallout.classifyFn = TLInspectALEConnectClassify;
        sCallout.notifyFn = TLInspectALEConnectNotify;
    }
    else
    {
        sCallout.classifyFn = TLInspectALERecvAcceptClassify;
        sCallout.notifyFn = TLInspectALERecvAcceptNotify;
    }

    status = FwpsCalloutRegister(
        deviceObject,
        &sCallout,
        calloutId
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = const_cast<PWSTR>(L"Transport Inspect ALE Classify Callout");
    displayData.description = const_cast<PWSTR>(L"Intercepts inbound or outbound connect attempts");

    mCallout.calloutKey = calloutKey;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = layerKey;

    status = FwpmCalloutAdd(
        gEngineHandle,
        &mCallout,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = TLInspectAddFilter(
        L"Transport Inspect ALE Classify",
        L"Intercepts inbound or outbound connect attempts",
        (IsEqualGUID(layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
            IsEqualGUID(layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)) ?
        configInspectRemoteAddrV4 : configInspectRemoteAddrV6,
        0,
        layerKey,
        calloutKey
    );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status))
    {
        if (calloutRegistered)
        {
            FwpsCalloutUnregisterById(*calloutId);
            *calloutId = 0;
        }
    }

    return status;
}

NTSTATUS
TLInspectRegisterTransportCallouts(
    _In_ const GUID& layerKey,
    _In_ const GUID& calloutKey,
    _Inout_ void* deviceObject,
    _Out_ UINT32* calloutId
)
/* ++

   This function registers callouts and filters that intercept transport
   traffic at the following layers --

      FWPM_LAYER_OUTBOUND_TRANSPORT_V4
      FWPM_LAYER_OUTBOUND_TRANSPORT_V6
      FWPM_LAYER_INBOUND_TRANSPORT_V4
      FWPM_LAYER_INBOUND_TRANSPORT_V6

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    FWPS_CALLOUT sCallout = {  };
    FWPM_CALLOUT mCallout = {  };

    FWPM_DISPLAY_DATA displayData = {  };

    BOOLEAN calloutRegistered = FALSE;

    sCallout.calloutKey = calloutKey;
    sCallout.classifyFn = TLInspectTransportClassify;
    sCallout.notifyFn = TLInspectTransportNotify;

    status = FwpsCalloutRegister(
        deviceObject,
        &sCallout,
        calloutId
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = const_cast<PWSTR>(L"Transport Inspect Callout");
    displayData.description = const_cast<PWSTR>(L"Inspect inbound/outbound transport traffic");

    mCallout.calloutKey = calloutKey;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = layerKey;

    status = FwpmCalloutAdd(
        gEngineHandle,
        &mCallout,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = TLInspectAddFilter(
        L"Transport Inspect Filter (Outbound)",
        L"Inspect inbound/outbound transport traffic",
        (IsEqualGUID(layerKey, FWPM_LAYER_OUTBOUND_TRANSPORT_V4) ||
            IsEqualGUID(layerKey, FWPM_LAYER_INBOUND_TRANSPORT_V4)) ?
        configInspectRemoteAddrV4 : configInspectRemoteAddrV6,
        0,
        layerKey,
        calloutKey
    );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status))
    {
        if (calloutRegistered)
        {
            FwpsCalloutUnregisterById(*calloutId);
            *calloutId = 0;
        }
    }

    return status;
}

NTSTATUS
TLInspectRegisterCallouts(
    _Inout_ void* deviceObject
)
/* ++

   This function registers dynamic callouts and filters that intercept
   transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and
   INBOUND/OUTBOUND transport layers.

   Callouts and filters will be removed during DriverUnload.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER TLInspectSubLayer = {
		TL_INSPECT_SUBLAYER,
		{ 
			const_cast<PWSTR>(L"Transport Inspect Sub-Layer"), 
				const_cast<PWSTR>(L"Sub-Layer for use by Transport Inspect callouts") 
		},
	};

    BOOLEAN engineOpened = FALSE;
    BOOLEAN inTransaction = FALSE;

    FWPM_SESSION session = { };

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &gEngineHandle
    );
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    engineOpened = TRUE;

    status = FwpmTransactionBegin(gEngineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    inTransaction = TRUE;


    // FWPM_SUBLAYER_UNIVERSAL to be
    // compatible with Vista's IpSec
    // implementation.

    status = FwpmSubLayerAdd(gEngineHandle, &TLInspectSubLayer, NULL);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    if (configInspectRemoteAddrV4)
    {
        status = TLInspectRegisterALEClassifyCallouts(
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            TL_INSPECT_ALE_CONNECT_CALLOUT_V4,
            deviceObject,
            &gAleConnectCalloutIdV4
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        status = TLInspectRegisterALEClassifyCallouts(
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V4,
            deviceObject,
            &gAleRecvAcceptCalloutIdV4
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        status = TLInspectRegisterTransportCallouts(
            FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V4,
            deviceObject,
            &gOutboundTlCalloutIdV4
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        status = TLInspectRegisterTransportCallouts(
            FWPM_LAYER_INBOUND_TRANSPORT_V4,
            TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V4,
            deviceObject,
            &gInboundTlCalloutIdV4
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

    if (configInspectRemoteAddrV6)
    {
        status = TLInspectRegisterALEClassifyCallouts(
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            TL_INSPECT_ALE_CONNECT_CALLOUT_V6,
            deviceObject,
            &gAleConnectCalloutIdV6
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        status = TLInspectRegisterALEClassifyCallouts(
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            TL_INSPECT_ALE_RECV_ACCEPT_CALLOUT_V6,
            deviceObject,
            &gAleRecvAcceptCalloutIdV6
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        status = TLInspectRegisterTransportCallouts(
            FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
            TL_INSPECT_OUTBOUND_TRANSPORT_CALLOUT_V6,
            deviceObject,
            &gOutboundTlCalloutIdV6
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        status = TLInspectRegisterTransportCallouts(
            FWPM_LAYER_INBOUND_TRANSPORT_V6,
            TL_INSPECT_INBOUND_TRANSPORT_CALLOUT_V6,
            deviceObject,
            &gInboundTlCalloutIdV6
        );
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(gEngineHandle);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    inTransaction = FALSE;

Exit:

    if (!NT_SUCCESS(status))
    {
        if (inTransaction)
        {
            FwpmTransactionAbort(gEngineHandle);
            _Analysis_assume_lock_not_held_(gEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
        }
        if (engineOpened)
        {
            FwpmEngineClose(gEngineHandle);
            gEngineHandle = NULL;
        }
    }

    return status;
}

void
TLInspectUnregisterCallouts(void)
{
    FwpmEngineClose(gEngineHandle);
    gEngineHandle = NULL;

    FwpsCalloutUnregisterById(gOutboundTlCalloutIdV6);
    FwpsCalloutUnregisterById(gOutboundTlCalloutIdV4);
    FwpsCalloutUnregisterById(gInboundTlCalloutIdV6);
    FwpsCalloutUnregisterById(gInboundTlCalloutIdV4);

    FwpsCalloutUnregisterById(gAleConnectCalloutIdV6);
    FwpsCalloutUnregisterById(gAleConnectCalloutIdV4);
    FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV6);
    FwpsCalloutUnregisterById(gAleRecvAcceptCalloutIdV4);
}

_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
TLInspectEvtDriverUnload(
    _In_ PDRIVER_OBJECT driverObject
)
{
	DbgPrint("%hs(%p)++\r\n", __FUNCTION__, driverObject);

	TLInspectUnregisterCallouts();

	KLOCK_QUEUE_HANDLE connListLockHandle;
	KLOCK_QUEUE_HANDLE packetQueueLockHandle;

	UNREFERENCED_PARAMETER(driverObject);

	KeAcquireInStackQueuedSpinLock(
		&gConnListLock,
		&connListLockHandle
		);
	KeAcquireInStackQueuedSpinLock(
		&gPacketQueueLock,
		&packetQueueLockHandle
		);

	gDriverUnloading = TRUE;

	KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
	KeReleaseInStackQueuedSpinLock(&connListLockHandle);

	KeSetEvent(
		&gWorkerEvent,
		IO_NO_INCREMENT,
		FALSE
		);

    KeWaitForSingleObject(
        gThreadObj,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );

    ObfDereferenceObject(gThreadObj);

	FwpsInjectionHandleDestroy(gInjectionHandle);

    if (PDEVICE_OBJECT DeviceObject = driverObject->DeviceObject)
    {
        IoDeleteDevice(DeviceObject);
    }

	NtClose(gParametersKey);
	DbgPrint("%hs(%p)--\r\n", __FUNCTION__, driverObject);
}

NTSTATUS OpenParameters(_Out_ PHANDLE KeyHandle, _In_ PCUNICODE_STRING registryPath)
{
	UNICODE_STRING str = {};
	int len = 0;
	while (0 < (len = _snwprintf(str.Buffer, len, L"%wZ\\Parameters", registryPath)))
	{
		if (str.Buffer)
		{
			str.MaximumLength = str.Length = (USHORT)len * sizeof(WCHAR);

			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &str, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE };

			return ZwOpenKey(KeyHandle, KEY_READ, &oa);
		}

		str.Buffer = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

EXTERN_C
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PCUNICODE_STRING registryPath)
{
	NTSTATUS status;
	HANDLE threadHandle;

	// Request NX Non-Paged Pool when available
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	DbgPrint("%hs(%p, %wZ)\r\n", __FUNCTION__, driverObject, registryPath);

	driverObject->DriverUnload = TLInspectEvtDriverUnload;

	if (0 <= (status = OpenParameters(&gParametersKey, registryPath)))
	{
		if (0 <= (status = TLInspectLoadConfig(gParametersKey)))
		{
			InitializeListHead(&gConnList);
			KeInitializeSpinLock(&gConnListLock);

			InitializeListHead(&gPacketQueue);
			KeInitializeSpinLock(&gPacketQueueLock);

			KeInitializeEvent(
				&gWorkerEvent,
				NotificationEvent,
				FALSE
				);

			if (0 <= (status = PsCreateSystemThread(
				&threadHandle,
				THREAD_ALL_ACCESS,
				NULL,
				NULL,
				NULL,
				TLInspectWorker,
				NULL
				)))
			{
				status = ObReferenceObjectByHandle(
					threadHandle,
					0,
					NULL,
					KernelMode,
					&gThreadObj,
					NULL
					);

				NtClose(threadHandle);

				if (0 <= status)
				{
					PDEVICE_OBJECT DeviceObject;
					if (0 <= (status = IoCreateDevice(driverObject, 0, 0, 
						FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject)))
					{
						DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

						if (0 <= (status = FwpsInjectionHandleCreate(
							AF_UNSPEC,
							FWPS_INJECTION_TYPE_TRANSPORT,
							&gInjectionHandle
							)))
						{
							if (0 <= (status = TLInspectRegisterCallouts(DeviceObject)))
							{
								DbgPrint("%hs [ok]\r\n", __FUNCTION__);

								return STATUS_SUCCESS;
							}
							FwpsInjectionHandleDestroy(gInjectionHandle);
						}

						IoDeleteDevice(DeviceObject);
					}

					ObfDereferenceObject(gThreadObj);
				}
			}
		}

		NtClose(gParametersKey);
	}

	DbgPrint("%hs=%x\r\n", __FUNCTION__, status);
	return status;
};

_NT_END