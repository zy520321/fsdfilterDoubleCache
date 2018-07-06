 /*++

Copyright (c) 1998-1999 Microsoft Corporation

Module Name:

    fspyTx.c

Abstract:

    This module contains the support routines for the KTM transactions.
    This feature is only available in windows VISTA and later.

Environment:

    Kernel mode

--*/

#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#include <ntifs.h>
#include <stdio.h>
#include "filespy.h"
#include "fspyKern.h"


//////////////////////////////////////////////////////////////////////////
//                                                                      //
//                 KTM transaction support routines                     //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

#if WINVER >= 0x0600


NTSTATUS
SpyIsAttachedToNtfs (
    __in PDEVICE_OBJECT DeviceObject,
    __out PBOOLEAN AttachToNtfs
    )
/*++

Routine Description:

    This routine determines if this device object is attached to a NTFS
    file system stack.

Arguments:

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack.

    AttachToNtfs - Pointer to receive the result.

Return Value:

    The function value is the status of the operation.

--*/
{
    PNAME_CONTROL driverName;
	UNICODE_STRING gNtfsDriverName;
    NTSTATUS status;

    if (!IS_WINDOWSXP_OR_LATER()) {

        return STATUS_NOT_SUPPORTED;
    }
	
	RtlInitUnicodeString(&gNtfsDriverName,L"\\FileSystem\\Ntfs");
    //
    //  Get the base file system device object.
    //

    ASSERT( NULL != gSpyDynamicFunctions.GetDeviceAttachmentBaseRef );
    DeviceObject = (gSpyDynamicFunctions.GetDeviceAttachmentBaseRef)( DeviceObject );

    status = NLAllocateNameControl( &driverName, &gFileSpyNameBufferLookasideList );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    driverName->Name.Length = 0;

    __try {

        //
        //  Get the name of driver.
        //

        status = NLGetObjectName( DeviceObject->DriverObject, driverName );

        if (!NT_SUCCESS(status)) {

            __leave;
        }

        if (driverName->Name.Length == 0) {

            *AttachToNtfs = FALSE;
            __leave;
        }

        //
        //  Compare to "\\FileSystem\\Ntfs"
        //

        *AttachToNtfs = RtlEqualUnicodeString( &driverName->Name,
                                               &gNtfsDriverName,
                                               TRUE );

    } 
	__finally 
	{
        //
        //  Remove the reference added by IoGetDeviceAttachmentBaseRef.
        //

        ObDereferenceObject( DeviceObject );

        NLFreeNameControl( driverName, &gFileSpyNameBufferLookasideList );
    }

    return status;
}

#endif

