/*++
Copyright (c) 1990-2000    Microsoft Corporation All Rights Reserved

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.


Environment:

    user and kernel

--*/

#define WHILE(a) \
__pragma(warning(suppress:4127)) while(a)

//
// Define an Interface Guid so that app can find the device and talk to it.
//

struct __declspec(uuid("CDC35B6E-0BE4-4936-BF5F-5537380A7C1A")) GUID_DEVINTERFACE_ECHO;
// {}

