 /*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    fspyLib.c

Abstract:

    This contains library support routines for FileSpy.  These routines
    do the main work for logging the I/O operations --- creating the log
    records, recording the relevant information, attach/detach from
    devices, etc.

    As of the Windows XP SP1 IFS Kit version of this sample and later, this
    sample can be built for each build environment released with the IFS Kit
    with no additional modifications.  To provide this capability, additional
    compile-time logic was added -- see the '#if WINVER' locations.  Comments
    tagged with the 'VERSION NOTE' header have also been added as appropriate to
    describe how the logic must change between versions.

    If this sample is built in the Windows XP environment or later, it will run
    on Windows 2000 or later.  This is done by dynamically loading the routines
    that are only available on Windows XP or later and making run-time decisions
    to determine what code to execute.  Comments tagged with 'MULTIVERISON NOTE'
    mark the locations where such logic has been added.

Environment:

    Kernel mode

--*/

// #ifndef _WIN2K_COMPAT_SLIST_USAGE
// #define _WIN2K_COMPAT_SLIST_USAGE
// #endif

#include <stdio.h>

#include <ntifs.h>
#include "filespy.h"
#include "fspyKern.h"
#include "UsbSecure.h"
#include "Fake_function.h"
//#include "VMProtectDDK.h"


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, SpyReadDriverParameters)
#pragma alloc_text(PAGE, SpyAttachDeviceToDeviceStack)
#pragma alloc_text(PAGE, SpyQueryInformationFile)
#pragma alloc_text(PAGE, SpyIsAttachedToDeviceByName)
#pragma alloc_text(PAGE, SpyIsAttachedToDevice)
#pragma alloc_text(PAGE, SpyIsAttachedToDeviceW2K)
#pragma alloc_text(PAGE, SpyAttachToMountedDevice)
#pragma alloc_text(PAGE, SpyCleanupMountedDevice)
#pragma alloc_text(PAGE, SpyAttachToDeviceOnDemand)
#pragma alloc_text(PAGE, SpyAttachToDeviceOnDemandW2K)
#pragma alloc_text(PAGE, SpyStartLoggingDevice)
#pragma alloc_text(PAGE, SpyStopLoggingDevice)
#pragma alloc_text(PAGE, SpyAttachToFileSystemDevice)
#pragma alloc_text(PAGE, SpyDetachFromFileSystemDevice)
#pragma alloc_text(PAGE, SpyGetAttachList)

#if WINVER >= 0x0501
#pragma alloc_text(INIT, SpyLoadDynamicFunctions)
#pragma alloc_text(INIT, SpyGetCurrentVersion)
#pragma alloc_text(PAGE, SpyIsAttachedToDeviceWXPAndLater)
#pragma alloc_text(PAGE, SpyAttachToDeviceOnDemandWXPAndLater)
#pragma alloc_text(PAGE, SpyEnumerateFileSystemVolumes)
#pragma alloc_text(PAGE, SpyGetBaseDeviceObjectName)
#endif

#endif

//////////////////////////////////////////////////////////////////////////
//                                                                      //
//                     Library support routines                         //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

VOID
SpyReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine tries to read the FileSpy-specific parameters from
    the registry.  These values will be found in the registry location
    indicated by the RegistryPath passed in.

Arguments:

    RegistryPath - the path key which contains the values that are
        the FileSpy parameters

Return Value:

    None.

--*/
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE driverRegKey;
    NTSTATUS status;
    ULONG bufferSize, resultLength;
    PVOID buffer = NULL;
    UNICODE_STRING valueName;
    PKEY_VALUE_PARTIAL_INFORMATION pValuePartialInfo;

    //
    //  All the global values are already set to default values.  Any
    //  values we read from the registry will override these defaults.
    //

    //
    //  Do the initial setup to start reading from the registry.
    //

    InitializeObjectAttributes( &attributes,
                                RegistryPath,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                NULL);

    status = ZwOpenKey( &driverRegKey,
                        KEY_READ,
                        &attributes);

    if (!NT_SUCCESS(status)) {

        driverRegKey = NULL;
        goto SpyReadDriverParameters_Exit;
    }

    bufferSize = sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( ULONG );
    buffer = ExAllocatePoolWithTag( NonPagedPool,
                                    bufferSize,
                                    FILESPY_POOL_TAG );

    if (NULL == buffer) {

        goto SpyReadDriverParameters_Exit;
    }

    //
    //  Read the gMaxRecordsToAllocate from the registry
    //

    RtlInitUnicodeString(&valueName, MAX_RECORDS_TO_ALLOCATE);

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              buffer,
                              bufferSize,
                              &resultLength);

    if (NT_SUCCESS(status)) {

        pValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) buffer;
        ASSERT(pValuePartialInfo->Type == REG_DWORD);
        

    }

    //
    //  Read the gMaxNamesToAllocate from the registry
    //

    RtlInitUnicodeString(&valueName, MAX_NAMES_TO_ALLOCATE);

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              buffer,
                              bufferSize,
                              &resultLength);

    if (NT_SUCCESS(status)) {

        pValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) buffer;
        ASSERT(pValuePartialInfo->Type == REG_DWORD);
     

    }

    //
    //  Read the initial debug setting from the registry
    //

    RtlInitUnicodeString(&valueName, DEBUG_LEVEL);

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              buffer,
                              bufferSize,
                              &resultLength );

    if (NT_SUCCESS( status )) {

        pValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) buffer;
        ASSERT( pValuePartialInfo->Type == REG_DWORD );
     

    }

    //
    //  Read the attachment mode setting from the registry
    //

    RtlInitUnicodeString(&valueName, ATTACH_MODE);

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              buffer,
                              bufferSize,
                              &resultLength );

    if (NT_SUCCESS( status )) {

        pValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) buffer;
        ASSERT( pValuePartialInfo->Type == REG_DWORD );
     
    }

    goto SpyReadDriverParameters_Exit;

SpyReadDriverParameters_Exit:

    if (NULL != buffer) {

        ExFreePoolWithTag( buffer, FILESPY_POOL_TAG );
    }

    if (NULL != driverRegKey) {

        ZwClose(driverRegKey);
    }

    return;
}

#if WINVER >= 0x0501
VOID
SpyLoadDynamicFunctions (
    VOID
    )
/*++

Routine Description:

    This routine tries to load the function pointers for the routines that
    are not supported on all versions of the OS.  These function pointers are
    then stored in the global structure gSpyDynamicFunctions.

    This support allows for one driver to be built that will run on all
    versions of the OS Windows 2000 and greater.  Note that on Windows 2000,
    the functionality may be limited.

Arguments:

    None.

Return Value:

    None.

--*/
{
    UNICODE_STRING functionName;

    RtlZeroMemory( &gSpyDynamicFunctions, sizeof( gSpyDynamicFunctions ) );

    //
    //  For each routine that we would want to use, lookup its address in the
    //  kernel or HAL.  If it is not present, that field in our global
    //  gSpyDynamicFunctions structure will be set to NULL.
    //

    RtlInitUnicodeString( &functionName, L"FsRtlRegisterFileSystemFilterCallbacks" );
    gSpyDynamicFunctions.RegisterFileSystemFilterCallbacks = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"IoAttachDeviceToDeviceStackSafe" );
    gSpyDynamicFunctions.AttachDeviceToDeviceStackSafe = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"IoEnumerateDeviceObjectList" );
    gSpyDynamicFunctions.EnumerateDeviceObjectList = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"IoGetLowerDeviceObject" );
    gSpyDynamicFunctions.GetLowerDeviceObject = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"IoGetDeviceAttachmentBaseRef" );
    gSpyDynamicFunctions.GetDeviceAttachmentBaseRef = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"IoGetDiskDeviceObject" );
    gSpyDynamicFunctions.GetStorageStackDeviceObject = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"IoGetAttachedDeviceReference" );
    gSpyDynamicFunctions.GetAttachedDeviceReference = MmGetSystemRoutineAddress( &functionName );

    RtlInitUnicodeString( &functionName, L"RtlGetVersion" );
    gSpyDynamicFunctions.GetVersion = MmGetSystemRoutineAddress( &functionName );

#if WINVER >= 0x0600

    //
    //  Lookup routine addresses for Ktm transaction support.
    //  These routines are only available in windows VISTA and later.
    //
    
//     RtlInitUnicodeString( &functionName, L"ZwCreateTransactionManager" );
//     gSpyDynamicFunctions.CreateTransactionManager = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"ZwCreateResourceManager" );
//     gSpyDynamicFunctions.CreateResourceManager = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"TmEnableCallbacks" );
//     gSpyDynamicFunctions.EnableTmCallbacks = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"TmCreateEnlistment" );
//     gSpyDynamicFunctions.CreateEnlistment = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"IoGetTransactionParameterBlock" );
//     gSpyDynamicFunctions.GetTransactionParameterBlock = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"TmPrePrepareComplete" );
//     gSpyDynamicFunctions.PrePrepareComplete = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"TmPrepareComplete" );
//     gSpyDynamicFunctions.PrepareComplete = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"TmCommitComplete" );
//     gSpyDynamicFunctions.CommitComplete = MmGetSystemRoutineAddress( &functionName );
// 
//     RtlInitUnicodeString( &functionName, L"TmRollbackComplete" );
//     gSpyDynamicFunctions.RollbackComplete = MmGetSystemRoutineAddress( &functionName );

#endif // WINVER >= 0x0600

}

VOID
SpyGetCurrentVersion (
    VOID
    )
/*++

Routine Description:

    This routine reads the current OS version using the correct routine based
    on what routine is available.

Arguments:

    None.

Return Value:

    None.

--*/
{
    if (NULL != gSpyDynamicFunctions.GetVersion) {

        RTL_OSVERSIONINFOW versionInfo;
        NTSTATUS status;

        //
        //  VERSION NOTE: RtlGetVersion does a bit more than we need, but
        //  we are using it if it is available to show how to use it.  It
        //  is available on Windows XP and later.  RtlGetVersion and
        //  RtlVerifyVersionInfo (both documented in the IFS Kit docs) allow
        //  you to make correct choices when you need to change logic based
        //  on the current OS executing your code.
        //

        versionInfo.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOW );

        status = (gSpyDynamicFunctions.GetVersion)( &versionInfo );

        ASSERT( NT_SUCCESS( status ) );

        gSpyOsMajorVersion = versionInfo.dwMajorVersion;
        gSpyOsMinorVersion = versionInfo.dwMinorVersion;

    } else {

        PsGetVersion( &gSpyOsMajorVersion,
                      &gSpyOsMinorVersion,
                      NULL,
                      NULL );
    }
}

#endif
////////////////////////////////////////////////////////////////////////
//                                                                    //
//                  Memory allocation routines                        //
//                                                                    //
////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////
//                                                                    //
//                  Logging routines                                  //
//                                                                    //
////////////////////////////////////////////////////////////////////////
#if WINVER >= 0x0501 /* See comment in DriverEntry */
/*
VOID
SpyLogPreFsFilterOperation (
    __in PFS_FILTER_CALLBACK_DATA Data,
    __inout PRECORD_LIST RecordList
    )
{
    NAME_LOOKUP_FLAGS lookupFlags = 0;

    PRECORD_FS_FILTER_OPERATION pRecordFsFilterOp;

    pRecordFsFilterOp = &RecordList->LogRecord.Record.RecordFsFilterOp;

    //
    //  Record the information we use for an originating Irp.  We first
    //  need to initialize some of the RECORD_LIST and RECORD_IRP fields.
    //  Then get the interesting information from the Irp.
    //

    SetFlag( RecordList->LogRecord.RecordType, RECORD_TYPE_FS_FILTER_OP );

    pRecordFsFilterOp->FsFilterOperation = Data->Operation;
    pRecordFsFilterOp->FileObject = (FILE_ID) Data->FileObject;
    pRecordFsFilterOp->DeviceObject = (FILE_ID) Data->DeviceObject;
    pRecordFsFilterOp->ProcessId = (FILE_ID)PsGetCurrentProcessId();
    pRecordFsFilterOp->ThreadId = (FILE_ID)PsGetCurrentThreadId();

    KeQuerySystemTime( &pRecordFsFilterOp->OriginatingTime );

    //
    //  Do not query for the name on any of the release operations
    //  because a file system resource is currently being held and
    //  we may deadlock.
    //

    switch (Data->Operation) {

        case FS_FILTER_RELEASE_FOR_CC_FLUSH:
        case FS_FILTER_RELEASE_FOR_SECTION_SYNCHRONIZATION:
        case FS_FILTER_RELEASE_FOR_MOD_WRITE:

        /*    SPY_LOG_PRINT( SPYDEBUG_TRACE_DETAILED_CONTEXT_OPS,
                           ("FileSpy!SpyLogPreFsFilterOp:   RelOper\n") );

            SetFlag( lookupFlags, NLFL_ONLY_CHECK_CACHE );
            break;
    }

    //
    //  Only set the volumeName if the next device is a file system
    //  since we only want to prepend the volumeName if we are on
    //  top of a local file system.
    //

    SpySetName( RecordList,
                Data->DeviceObject,
                Data->FileObject,
                lookupFlags,
                NULL );
}
*/

#endif

NTSTATUS
SpyAttachDeviceToDeviceStack (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice,
    __deref_out PDEVICE_OBJECT *AttachedToDeviceObject
    )
/*++

Routine Description:

    This routine attaches the SourceDevice to the TargetDevice's stack and
    returns the device object SourceDevice was directly attached to in
    AttachedToDeviceObject.  Note that the SourceDevice does not necessarily
    get attached directly to TargetDevice.  The SourceDevice will get attached
    to the top of the stack of which TargetDevice is a member.

    VERSION NOTE:

    In Windows XP, a new API was introduced to close a rare timing window that
    can cause IOs to start being sent to a device before its
    AttachedToDeviceObject is set in its device extension.  This is possible
    if a filter is attaching to a device stack while the system is actively
    processing IOs.  The new API closes this timing window by setting the
    device extension field that holds the AttachedToDeviceObject while holding
    the IO Manager's lock that protects the device stack.

    A sufficient work around for earlier versions of the OS is to set the
    AttachedToDeviceObject to the device object that the SourceDevice is most
    likely to attach to.  While it is possible that another filter will attach
    in between the SourceDevice and TargetDevice, this will prevent the
    system from bug checking if the SourceDevice receives IOs before the
    AttachedToDeviceObject is correctly set.

    For a driver built in the Windows 2000 build environment, we will always
    use the work-around code to attach.  For a driver that is built in the
    Windows XP or later build environments (therefore you are building a
    multiversion driver), we will determine which method of attachment to use
    based on which APIs are available.


Arguments:

    SourceDevice - The device object to be attached to the stack.

    TargetDevice - The device that we currently think is the top of the stack
        to which SourceDevice should be attached.

    AttachedToDeviceObject - This is set to the device object to which
        SourceDevice is attached if the attach is successful.

Return Value:

    Return STATUS_SUCCESS if the device is successfully attached.  If
    TargetDevice represents a stack to which devices can no longer be attached,
    STATUS_NO_SUCH_DEVICE is returned.

--*/
{

    PAGED_CODE();

#if WINVER >= 0x0501
    if (IS_WINDOWSXP_OR_LATER()) {

        ASSERT( NULL != gSpyDynamicFunctions.AttachDeviceToDeviceStackSafe );

        return (gSpyDynamicFunctions.AttachDeviceToDeviceStackSafe)( SourceDevice,
                                                     TargetDevice,
                                                     AttachedToDeviceObject );

    } else {
#endif

        *AttachedToDeviceObject = TargetDevice;
        *AttachedToDeviceObject = IoAttachDeviceToDeviceStack( SourceDevice,
                                                               TargetDevice );

        if (*AttachedToDeviceObject == NULL) {

            return STATUS_NO_SUCH_DEVICE;
        }

        return STATUS_SUCCESS;

#if WINVER >= 0x0501
    }
#endif

}


////////////////////////////////////////////////////////////////////////
//                                                                    //
//                    FileName cache routines                         //
//                                                                    //
////////////////////////////////////////////////////////////////////////


NTSTATUS
SpyQueryInformationFile (
    __in PDEVICE_OBJECT NextDeviceObject,
    __in PFILE_OBJECT FileObject,
    __out_bcount_part(Length,*LengthReturned) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __out_opt PULONG LengthReturned
    )

/*++

Routine Description:

    This routine returns the requested information about a specified file.
    The information returned is determined by the FileInformationClass that
    is specified, and it is placed into the caller's FileInformation buffer.

Arguments:

    NextDeviceObject - Supplies the device object where this IO should start
        in the device stack.

    FileObject - Supplies the file object about which the requested
        information should be returned.

    FileInformation - Supplies a buffer to receive the requested information
        returned about the file.  This must be a buffer allocated from kernel
        space.

    Length - Supplies the length, in bytes, of the FileInformation buffer.

    FileInformationClass - Specifies the type of information which should be
        returned about the file.

    LengthReturned - the number of bytes returned if the operation was
        successful.

Return Value:

    The status returned is the final completion status of the operation.

--*/

{
    PIRP irp = NULL;
    PIO_STACK_LOCATION irpSp = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    KEVENT event;
    NTSTATUS status;

    PAGED_CODE();

    //
    //  In DBG builds, make sure that we have valid parameters before we do
    //  any work here.
    //

    ASSERT( NULL != NextDeviceObject );
    ASSERT( NULL != FileObject );
    ASSERT( NULL != FileInformation );

    //
    //  The parameters look ok, so setup the Irp.
    //

    KeInitializeEvent( &event, NotificationEvent, FALSE );
    ioStatusBlock.Status = STATUS_SUCCESS;
    ioStatusBlock.Information = 0;

    irp = IoAllocateIrp( NextDeviceObject->StackSize, FALSE );

    if (irp == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    //  Set our current thread as the thread for this
    //  IRP so that the IO Manager always knows which
    //  thread to return to if it needs to get back into
    //  the context of the thread that originated this
    //  IRP.
    //

    irp->Tail.Overlay.Thread = PsGetCurrentThread();

    //
    //  Set that this IRP originated from the kernel so that
    //  the IO Manager knows that the buffers do not
    //  need to be probed.
    //

    irp->RequestorMode = KernelMode;

    //
    //  Initialize the UserIosb and UserEvent in the IRP.
    //

    irp->UserIosb = &ioStatusBlock;
    irp->UserEvent = NULL;

    //
    //  Set the IRP_SYNCHRONOUS_API to denote that this
    //  is a synchronous IO request.
    //

    irp->Flags = IRP_SYNCHRONOUS_API;

    irpSp = IoGetNextIrpStackLocation( irp );

    irpSp->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    irpSp->FileObject = FileObject;

    //
    //  Setup the parameters for IRP_MJ_QUERY_INFORMATION.  These
    //  were supplied by the caller of this routine.
    //  The buffer we want to be filled in should be placed in
    //  the system buffer.
    //

    irp->AssociatedIrp.SystemBuffer = FileInformation;

    irpSp->Parameters.QueryFile.Length = Length;
    irpSp->Parameters.QueryFile.FileInformationClass = FileInformationClass;

    //
    //  Set up the completion routine so that we know when our
    //  request for the file name is completed.  At that time,
    //  we can free the IRP.
    //

    IoSetCompletionRoutine( irp,
                            SpyQueryCompletion,
                            &event,
                            TRUE,
                            TRUE,
                            TRUE );

    status = IoCallDriver( NextDeviceObject, irp );

    if (STATUS_PENDING == status) {

        KeWaitForSingleObject( &event,
                               Executive,
                               KernelMode,
                               FALSE,
                               NULL );
    }

    //
    //  Verify the completion has actually been run
    //

    ASSERT(KeReadStateEvent(&event) || !NT_SUCCESS(ioStatusBlock.Status));


    if (ARGUMENT_PRESENT(LengthReturned)) {

        *LengthReturned = (ULONG) ioStatusBlock.Information;
    }

    return ioStatusBlock.Status;
}

NTSTATUS
SpyQueryCompletion (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PKEVENT SynchronizingEvent
    )
/*++

Routine Description:

    This routine does the cleanup necessary once the query request completed
    by the file system.

Arguments:

    DeviceObject - This will be NULL since we originated this
        Irp.

    Irp - The IO request structure containing the information
        about the current state of our file name query.

    SynchronizingEvent - The event to signal to notify the
        originator of this request that the operation is
        complete.

Return Value:

    Returns STATUS_MORE_PROCESSING_REQUIRED so that IO Manager
    will not try to free the Irp again.

--*/
{

    UNREFERENCED_PARAMETER( DeviceObject );

    //
    //  Make sure that the Irp status is copied over to the users
    //  IO_STATUS_BLOCK so that the originator of this IRP will know
    //  the final status of this operation.
    //

    ASSERT( NULL != Irp->UserIosb );
    *Irp->UserIosb = Irp->IoStatus;

    //
    //  Signal SynchronizingEvent so that the originator of this
    //  Irp know that the operation is completed.
    //

    KeSetEvent( SynchronizingEvent, IO_NO_INCREMENT, FALSE );

    //
    //  We are now done, so clean up the IRP that we allocated.
    //

    IoFreeIrp( Irp );

    //
    //  If we return STATUS_SUCCESS here, the IO Manager will
    //  perform the cleanup work that it thinks needs to be done
    //  for this IO operation.
    //
    //  We can do this cleanup work more efficiently than the IO Manager
    //  since we are handling a very specific case.
    //
    //  Since the IO Manager has already performed all the work we want it to
    //  do on this IRP, we do the cleanup work, return
    //  STATUS_MORE_PROCESSING_REQUIRED, and ask the IO Manager to resume
    //  processing by calling IoCompleteRequest.
    //
    //  See NLQueryCompletion for a more verbose comment on this.
    //

    return STATUS_MORE_PROCESSING_REQUIRED;
}



////////////////////////////////////////////////////////////////////////
//                                                                    //
//         Common attachment and detachment routines                  //
//                                                                    //
////////////////////////////////////////////////////////////////////////

//
//  VERSION NOTE:
//
//  To be able to safely find out if our filter is attached to a device given
//  its name on Windows 2000 and later, we need to use the approach in
//  SpyIsAttachedToDeviceByName.  This method uses APIs that are
//  available on Windows 2000 and later.  On Windows XP or later, you could
//  change this routine to separate the translation from DeviceName to device
//  object from the search to see if our filter's device is attached to the
//  device stack.  In Windows XP and later, the logic to translate the
//  DeviceName to the device object is the same, but you can use the logic
//  in SpyIsAttachedToDeviceWXPAndLater to find your filter's device object
//  in the device stack safely.
//

NTSTATUS
SpyIsAttachedToDeviceByName (
    __in PNAME_CONTROL DeviceName,
    __out PBOOLEAN IsAttached,
    __deref_out PDEVICE_OBJECT *StackDeviceObject,
    __deref_out PDEVICE_OBJECT *OurAttachedDeviceObject
    )
/*++

Routine Description:

    This routine maps a device name (DOS or NT style) to a file system device
    stack, if one exists.  Then this routine walks the device stack to find
    a device object belonging to our driver.

    The APIs used here to walk the device stack are all safe to use while you
    are guaranteed that the device stack will not go away.  We enforce this
    guarantee
Arguments:

    DeviceName - The name of the device to check file spy's attachment to.

    IsAttached - This is set to TRUE if our filter is attached to this device
        stack, otherwise this is set to FALSE.

    StackDeviceObject - Set to a device object in the stack identified by the
        DeviceName.  If this is non-NULL, the caller is responsible for removing
        the reference put on this object before it was returned.

    AttachedDeviceObject - Set to the DeviceObject which FileSpy has previously
        attached to the device stack identify by DeviceName.  If this is
        non-NULL, the caller is responsible for removing the reference put on
        this object before it was returned.

Return Value:

    Returns STATUS_SUCCESS if we were able to successfully translate the
    DeviceName into a device stack and return the StackDeviceObject.  If an
    error occurs during the translation of the DeviceName into a device stack,
    the appropriate error code is returned.

--*/
{
    PNAME_CONTROL volumeName = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK openStatus;
    PFILE_OBJECT volumeFileObject;
    HANDLE fileHandle;
    PDEVICE_OBJECT baseFsDeviceObject;

    PAGED_CODE();

    //
    //  Initialize return state
    //

    ASSERT( NULL != StackDeviceObject );
    ASSERT( NULL != OurAttachedDeviceObject );
    ASSERT( NULL != IsAttached );

    *StackDeviceObject = NULL;
    *OurAttachedDeviceObject = NULL;
    *IsAttached = FALSE;

    //
    //  Setup the name to open
    //

    status = NLAllocateNameControl( &volumeName, &gFileSpyNameBufferLookasideList );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    status = NLCheckAndGrowNameControl( volumeName,
                                         sizeof(L"\\DosDevices\\") +
                                         DeviceName->Name.Length );
    if (!NT_SUCCESS( status )) {

        return status;
    }

    RtlAppendUnicodeToString( &volumeName->Name, L"\\DosDevices\\" );
    RtlAppendUnicodeStringToString( &volumeName->Name, &DeviceName->Name );

    //
    //  Initialize objectAttributes.  Note that this does not *copy* the
    //  volume name, so we cannot release volumeName until we're done with
    //  objectAttributes.
    //

    InitializeObjectAttributes( &objectAttributes,
                                &volumeName->Name,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                NULL );

    //
    //  Open the file object for the given device.
    //

    status = ZwCreateFile( &fileHandle,
                           SYNCHRONIZE|FILE_READ_DATA,
                           &objectAttributes,
                           &openStatus,
                           NULL,
                           0,
                           FILE_SHARE_READ|FILE_SHARE_WRITE,
                           FILE_OPEN,
                           FILE_SYNCHRONOUS_IO_NONALERT,
                           NULL,
                           0 );

    NLFreeNameControl( volumeName, &gFileSpyNameBufferLookasideList );

    if (STATUS_OBJECT_PATH_NOT_FOUND == status ||
        STATUS_OBJECT_NAME_INVALID == status) {

        //
        //  Maybe this name didn't need the "\DosDevices\" prepended to the
        //  name.  Try the open again using just the DeviceName passed in.
        //

         InitializeObjectAttributes( &objectAttributes,
                                     &DeviceName->Name,
                                     OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                     NULL,
                                     NULL );

        //
        //  Open the file object for the given device.
        //

        status = ZwCreateFile( &fileHandle,
                               SYNCHRONIZE|FILE_READ_DATA,
                               &objectAttributes,
                               &openStatus,
                               NULL,
                               0,
                               FILE_SHARE_READ|FILE_SHARE_WRITE,
                               FILE_OPEN,
                               FILE_SYNCHRONOUS_IO_NONALERT,
                               NULL,
                               0 );

        if (!NT_SUCCESS( status )) {

            return status;
        }

        //
        //  We were able to open the device using the name passed in, so
        //  now we will fall through and do the rest of this work.
        //

    } else if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Get a pointer to the volumes file object.
    //

    status = ObReferenceObjectByHandle( fileHandle,
                                        FILE_READ_DATA,
                                        *IoFileObjectType,
                                        KernelMode,
                                        &volumeFileObject,
                                        NULL );

    if(!NT_SUCCESS( status )) {

        ZwClose( fileHandle );
        return status;
    }

    //
    //  Get the device object we want to attach to (parent device object
    //  in chain).
    //

    baseFsDeviceObject = IoGetBaseFileSystemDeviceObject( volumeFileObject );

    if (baseFsDeviceObject == NULL) {

        ObDereferenceObject( volumeFileObject );
        ZwClose( fileHandle );

        return STATUS_INVALID_DEVICE_STATE;
    }

	if(baseFsDeviceObject->DeviceType!=FILE_DEVICE_DISK_FILE_SYSTEM)//在驱动里强制只针对磁盘的文件系统的分区 也就是说 硬盘或者移动硬盘
 	{
		ObReferenceObject( baseFsDeviceObject );
		ObDereferenceObject( volumeFileObject );
		ZwClose( fileHandle );

		return STATUS_INVALID_DEVICE_STATE;
 	}
    //
    //  Now see if we are attached to this device stack.  Note that we need to
    //  keep this file object open while we do this search to ensure that the
    //  stack won't get torn down while SpyIsAttachedToDevice does its work.
    //

    *IsAttached = SpyIsAttachedToDevice( baseFsDeviceObject,
                                         OurAttachedDeviceObject );

    //
    //  Return the base file system's device object to represent this device
    //  stack even if we didn't find our device object in the stack.
    //

    ObReferenceObject( baseFsDeviceObject );
    *StackDeviceObject = baseFsDeviceObject;

    //
    //  Close our handle
    //

    ObDereferenceObject( volumeFileObject );
    ZwClose( fileHandle );

    return STATUS_SUCCESS;
}

//
//  VERSION NOTE:
//
//  In Windows 2000, the APIs to safely walk an arbitrary file system device
//  stack were not supported.  If we can guarantee that a device stack won't
//  be torn down during the walking of the device stack, we can walk from
//  the base file system's device object up to the top of the device stack
//  to see if we are attached.  We know the device stack will not go away if
//  we are in the process of processing a mount request OR we have a file object
//  open on this device.
//
//  In Windows XP and later, the IO Manager provides APIs that will allow us to
//  walk through the chain safely using reference counts to protect the device
//  object from going away while we are inspecting it.  This can be done at any
//  time.
//
//  MULTIVERSION NOTE:
//
//  If built for Windows XP or later, this driver is built to run on
//  multiple versions.  When this is the case, we will test for the presence of
//  the new IO Manager routines that allow for a filter to safely walk the file
//  system device stack and use those APIs if they are present to determine if
//  we have already attached to this volume.  If these new IO Manager routines
//  are not present, we will assume that we are at the bottom of the file
//  system stack and walk up the stack looking for our device object.
//

BOOLEAN
SpyIsAttachedToDevice (
    __in PDEVICE_OBJECT DeviceObject,
    __deref_opt_out PDEVICE_OBJECT *AttachedDeviceObject
    )
{
    PAGED_CODE();

#if WINVER >= 0x0501
    if (IS_WINDOWSXP_OR_LATER()) {

        ASSERT( NULL != gSpyDynamicFunctions.GetLowerDeviceObject &&
                NULL != gSpyDynamicFunctions.GetDeviceAttachmentBaseRef );

        return SpyIsAttachedToDeviceWXPAndLater( DeviceObject,
                                                 AttachedDeviceObject );
    } else {
#endif

        return SpyIsAttachedToDeviceW2K( DeviceObject, AttachedDeviceObject );

#if WINVER >= 0x0501
    }
#endif
}

BOOLEAN
SpyIsAttachedToDeviceW2K (
    __in PDEVICE_OBJECT DeviceObject,
    __deref_opt_out PDEVICE_OBJECT *AttachedDeviceObject
    )
/*++

Routine Description:

    VERSION: Windows 2000

    This routine walks up the device stack from the DeviceObject passed in
    looking for a device object that belongs to our filter.

    Note:  For this routine to operate safely, the caller must ensure two
        things:
        * the DeviceObject is the base file system's device object and therefore
        is at the bottom of the file system stack
        * this device stack won't be going away while we walk up this stack.  If
        we currently have a file object open for this device stack or we are
        in the process of mounting this device, this guarantee is satisfied.

Arguments:

    DeviceObject - The device chain we want to look through

    AttachedDeviceObject - Set to the DeviceObject which FileSpy
            has previously attached to DeviceObject.  If this is non-NULL,
            the caller must clear the reference put on this device object.

Return Value:

    TRUE if we are attached, FALSE if not

--*/
{
    PDEVICE_OBJECT currentDeviceObject;

    PAGED_CODE();

    for (currentDeviceObject = DeviceObject;
         currentDeviceObject != NULL;
         currentDeviceObject = currentDeviceObject->AttachedDevice) {

        if (IS_FILESPY_DEVICE_OBJECT( currentDeviceObject )) {

            //
            //  We are attached.  If requested, return the found device object.
            //

            if (ARGUMENT_PRESENT( AttachedDeviceObject )) {

                ObReferenceObject( currentDeviceObject );
                *AttachedDeviceObject = currentDeviceObject;
            }

            return TRUE;
        }
    }

    //
    //  We did not find ourselves on the attachment chain.  Return a NULL
    //  device object pointer (if requested) and return we did not find
    //  ourselves.
    //

    if (ARGUMENT_PRESENT( AttachedDeviceObject )) {

        *AttachedDeviceObject = NULL;
    }

    return FALSE;
}

#if WINVER >= 0x0501

BOOLEAN
SpyIsAttachedToDeviceWXPAndLater (
    __in PDEVICE_OBJECT DeviceObject,
    __deref_opt_out PDEVICE_OBJECT *AttachedDeviceObject
    )
/*++

Routine Description:

    VERSION: Windows XP and later

    This walks down the attachment chain looking for a device object that
    belongs to this driver.  If one is found, the attached device object
    is returned in AttachedDeviceObject.

Arguments:

    DeviceObject - The device chain we want to look through

    AttachedDeviceObject - Set to the DeviceObject which FileSpy
            has previously attached to DeviceObject.

Return Value:

    TRUE if we are attached, FALSE if not

--*/
{
    PDEVICE_OBJECT currentDevObj;
    PDEVICE_OBJECT nextDevObj;

    PAGED_CODE();

    //
    //  Get the device object at the TOP of the attachment chain
    //

    ASSERT( NULL != gSpyDynamicFunctions.GetAttachedDeviceReference );
    currentDevObj = (gSpyDynamicFunctions.GetAttachedDeviceReference)( DeviceObject );

    //
    //  Scan down the list to find our device object.
    //

    do {

        if (IS_FILESPY_DEVICE_OBJECT( currentDevObj )) {

            //
            //  We have found that we are already attached.  If we are
            //  returning the device object, leave it referenced else remove
            //  the reference.
            //

            if (NULL != AttachedDeviceObject) {

                *AttachedDeviceObject = currentDevObj;

            } else {

                ObDereferenceObject( currentDevObj );
            }

            return TRUE;
        }

        //
        //  Get the next attached object.  This puts a reference on
        //  the device object.
        //

        ASSERT( NULL != gSpyDynamicFunctions.GetLowerDeviceObject );
        nextDevObj = (gSpyDynamicFunctions.GetLowerDeviceObject)( currentDevObj );

        //
        //  Dereference our current device object, before
        //  moving to the next one.
        //

        ObDereferenceObject( currentDevObj );

        currentDevObj = nextDevObj;

    } while (NULL != currentDevObj);

    //
    //  Mark no device returned.
    //

    if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

        *AttachedDeviceObject = NULL;
    }

    return FALSE;
}

#endif //WINVER >= 0x0501

NTSTATUS
SpyAttachToMountedDevice (
    __in PDEVICE_OBJECT DeviceObject,
    __in PDEVICE_OBJECT FilespyDeviceObject
    )
/*++

Routine Description:

    This routine will attach the FileSpyDeviceObject to the filter stack
    that DeviceObject is in.

    NOTE:  If there is an error in attaching, the caller is responsible
        for deleting the FileSpyDeviceObject.

Arguments:

    DeviceObject - The device object in the stack to which we want to attach.

    FilespyDeviceObject - The filespy device object that is to be attached to
            "DeviceObject".

Return Value:

    Returns STATUS_SUCCESS if the filespy deviceObject could be attached,
    otherwise an appropriate error code is returned.

--*/
{
    PFILESPY_DEVICE_EXTENSION devExt = FilespyDeviceObject->DeviceExtension;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
	UNICODE_STRING  szNTFSDriverName;
	UNICODE_STRING  szFastFatDriverName;

    PAGED_CODE();
    ASSERT( IS_FILESPY_DEVICE_OBJECT( FilespyDeviceObject ) );
#if WINVER >= 0x0501
    ASSERT( !SpyIsAttachedToDevice( DeviceObject, NULL ) );
#endif

    //
    //  Insert pointer from extension back to owning device object
    //
	
 	VirtualizerStart();
	RtlInitUnicodeString(&szNTFSDriverName,L"\\FileSystem\\Ntfs");
	RtlInitUnicodeString(&szFastFatDriverName,L"\\FileSystem\\FastFat");
	VirtualizerEnd();
    devExt->NLExtHeader.ThisDeviceObject = FilespyDeviceObject;

    //
    //  Propagate flags from Device Object we are trying to attach to.
    //  Note that we do this before the actual attachment to make sure
    //  the flags are properly set once we are attached (since an IRP
    //  can come in immediately after attachment but before the flags would
    //  be set).
    //

    SetFlag( FilespyDeviceObject->Flags,
             FlagOn( DeviceObject->Flags,
                     (DO_BUFFERED_IO |
                      DO_DIRECT_IO |
                      DO_SUPPORTS_TRANSACTIONS) ));

    SetFlag( FilespyDeviceObject->Characteristics,
             FlagOn( DeviceObject->Characteristics,
                     (FILE_DEVICE_SECURE_OPEN) ));

    //
    //  It is possible for this attachment request to fail because this device
    //  object has not finished initializing.  This can occur if this filter
    //  loaded just as this volume was being mounted.
    //

	if(!RtlEqualUnicodeString(&DeviceObject->DriverObject->DriverName,&szNTFSDriverName,TRUE)&& 
		!RtlEqualUnicodeString(&DeviceObject->DriverObject->DriverName,&szFastFatDriverName,TRUE))
		return STATUS_UNSUCCESSFUL;

    for (i=0; i < 8; i++) {

        LARGE_INTEGER interval;

        //
        //  Attach our device object to the given device object
        //  The only reason this can fail is if someone is trying to dismount
        //  this volume while we are attaching to it.
        //

        status = SpyAttachDeviceToDeviceStack( FilespyDeviceObject,
                                               DeviceObject,
                                               &devExt->NLExtHeader.AttachedToDeviceObject );

        if (NT_SUCCESS(status) ) {

            //
            //  Do all common initializing of the device extension.
            //

            SetFlag(devExt->Flags,IsVolumeDeviceObject);

            SpyInitDeviceNamingEnvironment( FilespyDeviceObject );

           
            //
            //  Add this device to our attachment list
            //

            ExAcquireFastMutex( &gSpyDeviceExtensionListLock );
            InsertTailList( &gSpyDeviceExtensionList, &devExt->NextFileSpyDeviceLink );
            ExReleaseFastMutex( &gSpyDeviceExtensionListLock );
            SetFlag(devExt->Flags,ExtensionIsLinked);




#if WINVER >= 0x0600

            //
            //  Check if attached to a NTFS volume.
            //

            {
                BOOLEAN AttachToNtfs;

                status = SpyIsAttachedToNtfs( FilespyDeviceObject,
                                              &AttachToNtfs );

                if (NT_SUCCESS( status ) &&
                    AttachToNtfs) {

                    SetFlag(devExt->Flags,IsAttachedToNTFS);
                }
            }
#endif

		 	VirtualizerStart();
			if(RtlEqualUnicodeString(&DeviceObject->DriverObject->DriverName,&szNTFSDriverName,TRUE))
			{
				ExAcquireFastMutex(&g_HookMutex);
				if(NTFSAcquireFileForNtCreateSection== NULL)
				{
					NTFSAcquireFileForNtCreateSection =DeviceObject->DriverObject->FastIoDispatch->AcquireFileForNtCreateSection;
					if(NTFSAcquireFileForNtCreateSection !=  NULL)
					{
						DeviceObject->DriverObject->FastIoDispatch->AcquireFileForNtCreateSection = PfpFastAcquireForCreateSection;
					}

				}
				if(NTFSReleaseFileForNtCreateSection == NULL)
				{
					NTFSReleaseFileForNtCreateSection =DeviceObject->DriverObject->FastIoDispatch->ReleaseFileForNtCreateSection;
					DeviceObject->DriverObject->FastIoDispatch->ReleaseFileForNtCreateSection=PfpFastReleaseForCreateSection;
				}
				if(NTFSAcquireForCcFlush== NULL)
				{
					NTFSAcquireForCcFlush=DeviceObject->DriverObject->FastIoDispatch->AcquireForCcFlush;
					if(NTFSAcquireForCcFlush!= NULL)
					{
						DeviceObject->DriverObject->FastIoDispatch->AcquireForCcFlush =PfpAcquireFileForCcFlush;
					}
				}
				if(NTFSReleaseForCcFlush== NULL)
				{

					NTFSReleaseForCcFlush = DeviceObject->DriverObject->FastIoDispatch->ReleaseForCcFlush;
					if(NTFSReleaseForCcFlush != NULL)
					{
						DeviceObject->DriverObject->FastIoDispatch->ReleaseForCcFlush = PfpReleaseFileForCcFlush;
					}
				}
				if(NTFSAcquireForModWrite== NULL)
				{
					NTFSAcquireForModWrite = DeviceObject->DriverObject->FastIoDispatch->AcquireForModWrite;
					if(NTFSAcquireForModWrite != NULL)
					{ 
						DeviceObject->DriverObject->FastIoDispatch->AcquireForModWrite = PfpAcquireFileForModWrite;
					}
				}
				if(NTFSReleaseForModWrite== NULL)
				{
					NTFSReleaseForModWrite =  DeviceObject->DriverObject->FastIoDispatch->ReleaseForModWrite;
					if(NTFSReleaseForModWrite != NULL)
					{
						DeviceObject->DriverObject->FastIoDispatch->ReleaseForModWrite = PfpReleaseForModWrite;
					}
				}
				//////////////////////////////////////////////////////////////////////////
				if(g_NtfsRead== NULL )
				{
					g_NtfsRead= DeviceObject->DriverObject->MajorFunction[IRP_MJ_READ];
					if(g_NtfsRead)
					{
						 DeviceObject->DriverObject->MajorFunction[IRP_MJ_READ] = Fake_PfpRead;
					}
				}



				if(g_NtfsWrite== NULL)
				{
					g_NtfsWrite= DeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE];
					if(g_NtfsWrite)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE] = Fake_PfpWrite;
					}
				}

				if(g_NtfsClose== NULL)
				{
					g_NtfsClose= DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLOSE];
					if(g_NtfsClose)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLOSE] = Fake_PfpFsdClose;
					}
				}

				if(g_NtfsQuery== NULL)
				{
					g_NtfsQuery= DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];
					if(g_NtfsQuery)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = Fake_PfpQueryInformation;
					}
				}

				if(g_NtfsSet==NULL)
				{
					g_NtfsSet= DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION];
					if(g_NtfsSet)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = Fake_PfpSetInformation;
					}
				}

				if(g_NtfsQueryEA==NULL)
				{
					g_NtfsQueryEA= DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_EA];
					if(g_NtfsQueryEA)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_EA] = Fake_PfpFsdQueryEa;
					}
				}

				if(g_NtfsSetEA==NULL)
				{
					g_NtfsSetEA= DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_EA];
					if(g_NtfsSetEA)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_EA] = Fake_PfpFsdSetEa;
					}
				}


				if(g_NtfsFlush==NULL)
				{
					g_NtfsFlush= DeviceObject->DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS];
					if(g_NtfsFlush)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = Fake_PfpFsdFlushBuffers;
					}
				}

				if(g_NtfsCleanup==NULL)
				{
					g_NtfsCleanup= DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLEANUP];
					if(g_NtfsCleanup)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLEANUP] = Fake_PfpFsdCleanup;
					}
				}
				//////////////////////////////////////////////////////////////////////////
				ExReleaseFastMutex(&g_HookMutex);
			}

			if(RtlEqualUnicodeString(&DeviceObject->DriverObject->DriverName,&szFastFatDriverName,TRUE))
			{
				ExAcquireFastMutex(&g_HookMutex);
				
				if(FastFatAcquireForCcFlush== NULL)
				{
					FastFatAcquireForCcFlush=DeviceObject->DriverObject->FastIoDispatch->AcquireForCcFlush;
					if(FastFatAcquireForCcFlush!= NULL)
					{
						DeviceObject->DriverObject->FastIoDispatch->AcquireForCcFlush =PfpAcquireFileForCcFlush;
					}
				}
				if(FastFatReleaseForCcFlush== NULL)
				{

					FastFatReleaseForCcFlush = DeviceObject->DriverObject->FastIoDispatch->ReleaseForCcFlush;
					if(FastFatReleaseForCcFlush != NULL)
					{
						DeviceObject->DriverObject->FastIoDispatch->ReleaseForCcFlush = PfpReleaseFileForCcFlush;
					}
				}
				

				//////////////////////////////////////////////////////////////////////////
				if(g_Fat32Read==NULL)
				{
					g_Fat32Read= DeviceObject->DriverObject->MajorFunction[IRP_MJ_READ];
					if(g_Fat32Read)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_READ] = Fake_PfpReadFat;
					}
				}



				if(g_Fat32Write==NULL)
				{
					g_Fat32Write= DeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE];
					if(g_Fat32Write)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE] = Fake_PfpWriteFat;
					}
				}

				if(g_Fat32Close==NULL)
				{
					g_Fat32Close= DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLOSE];
					if(g_Fat32Close)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLOSE] = Fake_PfpFsdCloseFat;
					}
				}

				if(g_Fat32Query==NULL)
				{
					g_Fat32Query= DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];
					if(g_Fat32Query)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = Fake_PfpQueryInformationFat;
					}
				}

				if(g_Fat32Set==NULL)
				{
					g_Fat32Set= DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION];
					if(g_Fat32Set)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = Fake_PfpSetInformationFat;
					}
				}

				if(g_Fat32QueryEA==NULL)
				{
					g_Fat32QueryEA= DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_EA];
					if(g_Fat32QueryEA)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_QUERY_EA] = Fake_PfpFsdQueryEaFat;
					}
				}

				if(g_Fat32SetEA==NULL)
				{
					g_Fat32SetEA= DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_EA];
					if(g_Fat32SetEA)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_SET_EA] = Fake_PfpFsdSetEaFat;
					}
				}

				if(g_Fat32Flush==NULL)
				{
					g_Fat32Flush= DeviceObject->DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS];
					if(g_Fat32Flush)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = Fake_PfpFsdFlushBuffersFat;
					}
				}

				if(g_Fat32Cleanup==NULL)
				{
					g_Fat32Cleanup= DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLEANUP];
					if(g_Fat32Cleanup)
					{
						DeviceObject->DriverObject->MajorFunction[IRP_MJ_CLEANUP] = Fake_PfpFsdCleanupFat;
					}
				}
				ExReleaseFastMutex(&g_HookMutex);
			}
			VirtualizerEnd();
            return STATUS_SUCCESS;
        }

        //
        //  Delay, giving the device object a chance to finish its
        //  initialization so we can try again
        //

        interval.QuadPart = (500 * DELAY_ONE_MILLISECOND);   //delay 1/2 second
        KeDelayExecutionThread( KernelMode, FALSE, &interval );
    }

    return status;
}


VOID
SpyCleanupMountedDevice (
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This cleans up any allocated memory in the device extension.

Arguments:

    DeviceObject - The device we are cleaning up

Return Value:

--*/
{
    PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;

    PAGED_CODE();

    ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));

    SpyCleanupDeviceNamingEnvironment( DeviceObject );

    //
    //  Cleanup the name lookup device extension header.
    //

    NLCleanupDeviceExtensionHeader( &devExt->NLExtHeader );

    //
    //  Cleanup the user names.
    //

    if (devExt->UserNames.Buffer != NULL) {

        ExFreePoolWithTag( devExt->UserNames.Buffer,
                           FILESPY_DEVNAME_TAG );
    }

    //
    //  Unlink from global list.
    //

    if (FlagOn(devExt->Flags,ExtensionIsLinked)) {

        ExAcquireFastMutex( &gSpyDeviceExtensionListLock );
        RemoveEntryList( &devExt->NextFileSpyDeviceLink );
        ExReleaseFastMutex( &gSpyDeviceExtensionListLock );
        ClearFlag(devExt->Flags,ExtensionIsLinked);
    }
}

////////////////////////////////////////////////////////////////////////
//                                                                    //
//                    Start/stop logging routines                     //
//                                                                    //
////////////////////////////////////////////////////////////////////////

//
//  VERSION NOTE:
//
//  On Windows 2000, we will try to attach a new FileSpy device object to the
//  device stack represented by the DeviceObject parameter.  We cannot get the
//  real storage stack device at this time, so this field will be set to NULL
//  in the device extension.  We also cannot get the device name as it is named
//  in the storage stack for this volume (e.g., \Device\HarddiskVolume1), so we
//  will just use the users name for the device for our device name.  On
//  Windows 2000, this information is only available as the device mounts.
//
//  On Windows XP and later, we will try to attach a new FileSpy device object
//  to the device stack represented by the DeviceObject parameter.  We are able
//  to get the disk device object for this stack, so that will be appropriately
//  set in the device extension.  We will also be able to get the device name
//  as it is named by the storage stack.
//
//  MULTIVERSION NOTE:
//
//  In SpyAttachToDeviceOnDemand, you see the code to determine which method of
//  determining if we are already attached based on the dynamically loaded
//  functions present.  If this driver is build for Windows 2000 specifically,
//  this logic will not be used.
//

NTSTATUS
SpyAttachToDeviceOnDemand (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL UserDeviceName,
    __deref_out PDEVICE_OBJECT *FileSpyDeviceObject
    )
/*++

Routine Description:

    This routine does what is necessary to attach to a device sometime after
    the device has been mounted.

Arguments:

    DeviceObject - The device object that represents the file system stack
        for the volume named by UserDeviceName.

    UserDeviceName - Name of device for which logging should be started

    FileSpyDeviceObject - Set to the new filespy device object that was
        attached if we could successfully attach.

Return Value:

    STATUS_SUCCESS if we were able to attach, or an appropriate error code
    otherwise.

--*/
{
    PAGED_CODE();

    //
    //  If this device is a DFS device, we do not want to attach to it, so
    //  do this quick check here and return an error if this is the case.
    //
    //  DFS will just redirect the operation to the appropriate redirector.  If
    //  you are interested in monitoring these IOs, you should attach to the
    //  redirectors.  You cannot attach to these on demand by naming the DFS
    //  device, therefore we fail these requests.
    //

    if (DeviceObject->DeviceType == FILE_DEVICE_DFS) {

        return STATUS_NOT_SUPPORTED;
    }

#if WINVER >= 0x0501
    if (IS_WINDOWSXP_OR_LATER()) {

        ASSERT( NULL != gSpyDynamicFunctions.GetDeviceAttachmentBaseRef &&
                NULL != gSpyDynamicFunctions.GetStorageStackDeviceObject );

        return SpyAttachToDeviceOnDemandWXPAndLater( DeviceObject,
                                                     UserDeviceName,
                                                     FileSpyDeviceObject );
    } else {
#endif

        return SpyAttachToDeviceOnDemandW2K( DeviceObject,
                                             UserDeviceName,
                                             FileSpyDeviceObject );
#if WINVER >= 0x0501
    }
#endif
}

NTSTATUS
SpyAttachToDeviceOnDemandW2K (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL UserDeviceName,
    __deref_out PDEVICE_OBJECT *FileSpyDeviceObject
    )
/*++

Routine Description:

    VERSION: Windows 2000

    This routine does what is necessary to attach to a device sometime after
    the device has been mounted.

    Note that on Windows 2000, we cannot get the disk device object, therefore
    we will just use the Users device name as our name here.

Arguments:

    DeviceObject - The device object that represents the file system stack
        for the volume named by UserDeviceName.

    UserDeviceName - Name of device for which logging should be started

    FileSpyDeviceObject - Set to the new filespy device object that was
        attached if we could successfully attach.

Return Value:

    STATUS_SUCCESS if we were able to attach, or an appropriate error code
    otherwise.

--*/
{
    NTSTATUS status;
    PFILESPY_DEVICE_EXTENSION devExt;

    PAGED_CODE();

    ASSERT( FileSpyDeviceObject != NULL );

    //
    //  Create a new device object so we can attach it in the filter stack
    //

    status = IoCreateDevice( gFileSpyDriverObject,
                             sizeof( FILESPY_DEVICE_EXTENSION ),
                             NULL,
                             DeviceObject->DeviceType,
                             0,
                             FALSE,
                             FileSpyDeviceObject );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Initialize device extension (don't know the storage stack device)
    //

	devExt = (*FileSpyDeviceObject)->DeviceExtension;

	devExt->pVirtualRootDir = PfpCreateVirtualDirObject(L"\\",NULL);

	if(devExt ->pVirtualRootDir == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
//	InitializeListHead(devExt ->DiskFileObejcts_List);

	//ExInitializeFastMutex(&devExt ->DiskFileObject_Mutex);
//	ExInitializeResourceLite(&devExt ->DiskObjectsResource);
	NLInitDeviceExtensionHeader( &devExt->NLExtHeader,
								*FileSpyDeviceObject,
								NULL );
	devExt->Flags = 0;

	PfpCreateShadowDeviceForDevice(*FileSpyDeviceObject);

    

    //
    //  Set Device Name - we will just use the user-entered device
    //  name on W2K.  No DOS name since we don't have the storage stack
    //  device object.
    //

    status = NLAllocateAndCopyUnicodeString( &devExt->NLExtHeader.DeviceName,
                                             &UserDeviceName->Name,
                                             FILESPY_DEVNAME_TAG );

    if (!NT_SUCCESS(status)) {

        goto ErrorAndCleanup;
    }

    //
    //  Call the routine to attach to a mounted device.
    //

    status = SpyAttachToMountedDevice( DeviceObject,
                                       *FileSpyDeviceObject );

    if (!NT_SUCCESS( status )) {

        goto ErrorAndCleanup;
    }

    return status;


ErrorAndCleanup:

    
    SpyCleanupMountedDevice( *FileSpyDeviceObject );

    IoDeleteDevice( *FileSpyDeviceObject );
    *FileSpyDeviceObject = NULL;

    return status;
}

#if WINVER >= 0x0501

NTSTATUS
SpyAttachToDeviceOnDemandWXPAndLater (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL UserDeviceName,
    __deref_out PDEVICE_OBJECT *FileSpyDeviceObject
    )
/*++

Routine Description:

    This routine does what is necessary to attach to a device sometime after
    the device has been mounted.

Arguments:

    DeviceObject - The device object that represents the file system stack
        for the volume named by UserDeviceName.

    UserDeviceName - Name of device for which logging should be started

    FileSpyDeviceObject - Set to the new filespy device object that was
        attached if we could successfully attach.

Return Value:

    STATUS_SUCCESS if we were able to attach, or an appropriate error code
    otherwise.

--*/
{

    NTSTATUS status;
    PFILESPY_DEVICE_EXTENSION devExt;
    PDEVICE_OBJECT baseFileSystemDeviceObject = NULL;
    PDEVICE_OBJECT storageStackDeviceObject = NULL;
    PNAME_CONTROL devName = NULL;
    PDEVICE_OBJECT getNameDeviceObject;
	UNREFERENCED_PARAMETER(UserDeviceName);
    PAGED_CODE();

    ASSERT( FileSpyDeviceObject != NULL );

    //
    //  If this is a network file system, there will not be a disk device
    //  associated with this device, so there is no need to make this request
    //  of the IO Manager.  We will get the name of the network file system
    //  later from the baseFileSystemDeviceObject vs. the
    //  storageStackDeviceObject which is used to retrieve the device name for
    //  local volumes.
    //

    baseFileSystemDeviceObject = (gSpyDynamicFunctions.GetDeviceAttachmentBaseRef)( DeviceObject );

    if (FILE_DEVICE_NETWORK_FILE_SYSTEM != baseFileSystemDeviceObject->DeviceType) {

        //
        //  If this is not a network file system, query the IO Manager to get
        //  the storageStackDeviceObject.  We will only attach if this device
        //  has a storage stack device object.
        //
        //  It may not have a storage stack device object for the following
        //  reasons:
        //  - It is a control device object for a driver
        //  - There is no media in the device.
        //

        status = (gSpyDynamicFunctions.GetStorageStackDeviceObject)( baseFileSystemDeviceObject,
                                                                     &storageStackDeviceObject );

        if (!NT_SUCCESS( status )) {

          
            storageStackDeviceObject = NULL;
            goto SpyAttachToDeviceOnDemand_Exit;
        }
    }

    //
    //  Create a new device object so we can attach it in the filter stack.
    //

    status = IoCreateDevice( gFileSpyDriverObject,
                             sizeof( FILESPY_DEVICE_EXTENSION ),
                             NULL,
                             DeviceObject->DeviceType,
                             0,
                             FALSE,
                             FileSpyDeviceObject );

    if (!NT_SUCCESS( status )) {

        goto SpyAttachToDeviceOnDemand_Exit;
    }
	
    //
    //  Initialize device extension
    //
   


    devExt = (*FileSpyDeviceObject)->DeviceExtension;

    NLInitDeviceExtensionHeader( &devExt->NLExtHeader,
                                 *FileSpyDeviceObject,
                                 storageStackDeviceObject );
    devExt->Flags = 0;



    //
    //  Get the name of getNameDeviceObject (either the storage stack device
    //  object or base file system device object).
    //

    if (NULL != storageStackDeviceObject) {

        getNameDeviceObject = storageStackDeviceObject;

    } else {

        ASSERT( (NULL != baseFileSystemDeviceObject) &&
                (FILE_DEVICE_NETWORK_FILE_SYSTEM == baseFileSystemDeviceObject->DeviceType));

        getNameDeviceObject = baseFileSystemDeviceObject;
    }

    devName = NLGetAndAllocateObjectName( getNameDeviceObject,
                                          &gFileSpyNameBufferLookasideList );

    if (devName == NULL) {

        goto SpyAttachToDeviceOnDemand_Abnormal_Exit;
    }

    //
    //  Allocate a buffer for the device name and copy it to the device
    //  extension.
    //

    status = NLAllocateAndCopyUnicodeString( &devExt->NLExtHeader.DeviceName,
                                             &devName->Name,
                                             FILESPY_DEVNAME_TAG );

    if (!NT_SUCCESS(status)) {

        goto SpyAttachToDeviceOnDemand_Abnormal_Exit;
    }

    //
    //  Call the routine to attach to a mounted device.
    //

    status = SpyAttachToMountedDevice( DeviceObject,
                                       *FileSpyDeviceObject );

    if (!NT_SUCCESS( status )) {

        goto SpyAttachToDeviceOnDemand_Abnormal_Exit;
    }

    //
    //  We successfully attached, so get the DOS device name.
    //

	devExt = (*FileSpyDeviceObject)->DeviceExtension;

	devExt ->pVirtualRootDir = PfpCreateVirtualDirObject(L"\\",NULL);

	if(devExt ->pVirtualRootDir == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//InitializeListHead(devExt ->DiskFileObejcts_List);

	//ExInitializeFastMutex(&devExt ->DiskFileObject_Mutex);
	//ExInitializeResourceLite(&devExt ->DiskObjectsResource);
    NLGetDosDeviceName( DeviceObject, &devExt->NLExtHeader );
	PfpCreateShadowDeviceForDevice(*FileSpyDeviceObject);
    goto SpyAttachToDeviceOnDemand_Exit;


//
//  Error cleanup
//

SpyAttachToDeviceOnDemand_Abnormal_Exit:

   
    SpyCleanupMountedDevice( *FileSpyDeviceObject );

    IoDeleteDevice( *FileSpyDeviceObject );
    *FileSpyDeviceObject = NULL;

//
//  Normal exit
//

SpyAttachToDeviceOnDemand_Exit:

    if (devName != NULL) {

        NLFreeNameControl( devName, &gFileSpyNameBufferLookasideList );
    }

    if (NULL != baseFileSystemDeviceObject) {

        ObDereferenceObject( baseFileSystemDeviceObject );
    }

    if (NULL != storageStackDeviceObject) {

        ObDereferenceObject( storageStackDeviceObject );
    }

    return status;
}

#endif

NTSTATUS
SpyStartLoggingDevice (
    __in PCWSTR UserDeviceName
    )
/*++

Routine Description:

    This routine ensures that we are attached to the specified device
    then turns on logging for that device.

    Note:  Since all network drives through LAN Manager are represented by _
        one_ device object, we want to only attach to this device stack once
        and use only one device extension to represent all these drives.
        Since FileSpy does not do anything to filter I/O on the LAN Manager's
        device object to only log the I/O to the requested drive, the user
        will see all I/O to a network drive it he/she is attached to a
        network drive.

Arguments:

    UserDeviceName - Name of device provided by the user for which logging
        should be started.

Return Value:

    STATUS_SUCCESS if the logging has been successfully started, or
    an appropriate error code if the logging could not be started.

--*/
{
    PNAME_CONTROL userDeviceName;
    NTSTATUS status;
    PFILESPY_DEVICE_EXTENSION devExt;
    BOOLEAN isAttached = FALSE;
    PDEVICE_OBJECT stackDeviceObject;
    PDEVICE_OBJECT filespyDeviceObject;

    PAGED_CODE();

    //
    //  Check to see if we have previously attached to this device by
    //  opening this device by name (provided by the user) then looking
    //  through its list of devices attached to it.
    //

    status = NLAllocateNameControl( &userDeviceName, &gFileSpyNameBufferLookasideList );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Note that we discard the null terminator since we're converting the WSTR
    //  to a unicode string.
    //

    userDeviceName->Name.Length = wcslen( UserDeviceName ) * sizeof(WCHAR);
    status = NLCheckAndGrowNameControl( userDeviceName,
                                        (USHORT)(userDeviceName->Name.Length) );

    if (!NT_SUCCESS( status )) {

        NLFreeNameControl( userDeviceName,
                           &gFileSpyNameBufferLookasideList );
        return status;
    }

    RtlCopyMemory( userDeviceName->Name.Buffer,
                   UserDeviceName,
                   userDeviceName->Name.Length );

    status = SpyIsAttachedToDeviceByName( userDeviceName,
                                          &isAttached,
                                          &stackDeviceObject,
                                          &filespyDeviceObject );

    if (!NT_SUCCESS( status )) {

        //
        //  There was an error, so return the error code.
        //

        return status;
    }

    if (isAttached) {

        //
        //  We are already attached, so just make sure that logging is turned on
        //  for this device.
        //

        ASSERT( NULL != filespyDeviceObject );

        devExt = filespyDeviceObject->DeviceExtension;
        SetFlag(devExt->Flags,LogThisDevice);

        //
        //  If the device's type is FILE_DEVICE_NETWORK_FILE_SYSTEM we can't
        //  get a DOS device name for it.  In this case we will store the
        //  name provided by the user in a list of provided user names for
        //  the device.
        //

        if (stackDeviceObject->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

            SpyStoreUserName( devExt, userDeviceName );
        }

        //
        //  Clear the reference that was returned from SpyIsAttachedToDevice.
        //

        ObDereferenceObject( filespyDeviceObject );

    } else {

        status = SpyAttachToDeviceOnDemand( stackDeviceObject,
                                            userDeviceName,
                                            &filespyDeviceObject );

        if (!NT_SUCCESS( status )) {

            ObDereferenceObject( stackDeviceObject );

            NLFreeNameControl( userDeviceName,
                               &gFileSpyNameBufferLookasideList );
            return status;
        }
		
        ASSERT( filespyDeviceObject != NULL );

        devExt = filespyDeviceObject->DeviceExtension;
		devExt->bUsbDevice = ((GetStorageDeviceBusType(devExt->NLExtHeader.StorageStackDeviceObject->Vpb->RealDevice,&devExt->pszUsbDiskSeriNUM ,&devExt->nLenExcludeTermiter)==7)?TRUE:FALSE);
		if(devExt->bUsbDevice)
		{
			//GetUsbStorageDeviceID(,devExt->NLExtHeader.StorageStackDeviceObject->Vpb->RealDevice);
			PfpInitUsbDeviceWithSecure(filespyDeviceObject);
		}       
		//
        //  We successfully attached so finish our device extension
        //  initialization.  Along this code path, we want to turn on
        //  logging and store our device name.
        //

        SetFlag(devExt->Flags, LogThisDevice);

        //
        //  If the device's type is FILE_DEVICE_NETWORK_FILE_SYSTEM we can't
        //  get a DOS device name for it.  In this case we will store the
        //  name provided by the user in a list of provided user names for
        //  the device.
        //

        if (stackDeviceObject->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

            SpyStoreUserName( devExt, userDeviceName );
        }

        //
        //  Finished all initialization of the new device object,  so clear the
        //  initializing flag now.  This allows other filters to now attach
        //  to our device object.
        //

        ClearFlag(filespyDeviceObject->Flags, DO_DEVICE_INITIALIZING);
    }

    NLFreeNameControl( userDeviceName, &gFileSpyNameBufferLookasideList );

    ObDereferenceObject( stackDeviceObject );
    return STATUS_SUCCESS;
}

NTSTATUS
SpyStopLoggingDevice (
    __in PCWSTR UserDeviceName
    )
/*++

Routine Description:

    This routine stop logging the specified device.  Since you can not
    physically detach from devices, this routine simply sets a flag saying
    to not log the device anymore.

    Note:  Since all network drives are represented by _one_ device object,
        and, therefore, one device extension, if the user detaches from one
        network drive, it has the affect of detaching from _all_ network
        devices.

Arguments:

    UserDeviceName - The user-provided name of the device to stop logging.

Return Value:
    NT Status code

--*/
{
    PNAME_CONTROL volumeName;
    PDEVICE_OBJECT deviceObject;
    PDEVICE_OBJECT filespyDeviceObject;
    BOOLEAN isAttached = FALSE;
    PFILESPY_DEVICE_EXTENSION devExt;
    NTSTATUS status;

    PAGED_CODE();

    status = NLAllocateNameControl( &volumeName, &gFileSpyNameBufferLookasideList );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    volumeName->Name.Length = wcslen( UserDeviceName ) * sizeof(WCHAR);
    status = NLCheckAndGrowNameControl( volumeName,
                                        (USHORT)(volumeName->Name.Length) );

    if (!NT_SUCCESS( status )) {

        NLFreeNameControl( volumeName, &gFileSpyNameBufferLookasideList );
        return status;
    }

    RtlCopyMemory( volumeName->Name.Buffer,
                   UserDeviceName,
                   volumeName->Name.Length);


    status = SpyIsAttachedToDeviceByName( volumeName,
                                          &isAttached,
                                          &deviceObject,
                                          &filespyDeviceObject );

    NLFreeNameControl( volumeName, &gFileSpyNameBufferLookasideList );

    if (!NT_SUCCESS( status )) {

        //
        //  We could not get the DeviceObject from this DeviceName, so
        //  return the error code.
        //

        return status;
    }

    //
    //  Find FileSpy's device object from the device stack to which
    //  DeviceObject is attached.
    //

    if (isAttached) {

        //
        //  FileSpy is attached and FileSpy's DeviceObject was returned.
        //

        ASSERT( NULL != filespyDeviceObject );

        devExt = filespyDeviceObject->DeviceExtension;

        //
        //  Stop logging
        //

        ClearFlag(devExt->Flags,LogThisDevice);

        status = STATUS_SUCCESS;

        ObDereferenceObject( filespyDeviceObject );

    } else {

        status = STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject( deviceObject );

    return status;
}

////////////////////////////////////////////////////////////////////////
//                                                                    //
//       Attaching/detaching to all volumes in system routines        //
//                                                                    //
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyAttachToFileSystemDevice (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL DeviceName
    )
/*++

Routine Description:

    This will attach to the given file system device object.  We attach to
    these devices so we will know when new devices are mounted.

Arguments:

    DeviceObject - The device to attach to

    DeviceName - Contains the name of this device.

Return Value:

    Status of the operation

--*/
{
    PDEVICE_OBJECT filespyDeviceObject;
    PFILESPY_DEVICE_EXTENSION devExt;
    UNICODE_STRING fsrecName;
    NTSTATUS status;
    PNAME_CONTROL fsName;

    PAGED_CODE();

    //
    //  See if this is a file system we care about.  If not, return.
    //

    if (!IS_SUPPORTED_DEVICE_TYPE(DeviceObject->DeviceType)) {

        return STATUS_SUCCESS;
    }

    //
    //  See if this is Microsoft's file system recognizer device (see if the
    //  name of the driver is the FS_REC driver).  If so skip it.  We don't
    //  need to attach to file system recognizer devices since we can just
    //  wait for the real file system driver to load.  Therefore, if we can
    //  identify them, we won't attach to them.
    //

    RtlInitUnicodeString( &fsrecName, L"\\FileSystem\\Fs_Rec" );


    fsName = NLGetAndAllocateObjectName( DeviceObject->DriverObject,
                                         &gFileSpyNameBufferLookasideList );

    if (fsName == NULL) {

        //
        //  If we can't get a name, don't attach
        //

     

    } else if (RtlCompareUnicodeString( &fsName->Name,
                                        &fsrecName, TRUE ) == 0) {

        //
        //  If it is a recognizer, don't attach
        //

        NLFreeNameControl( fsName, &gFileSpyNameBufferLookasideList );
        return STATUS_SUCCESS;
    }

    NLFreeNameControl( fsName, &gFileSpyNameBufferLookasideList );

    //
    //  Create a new device object we can attach with.
    //

    status = IoCreateDevice( gFileSpyDriverObject,
                             sizeof( FILESPY_DEVICE_EXTENSION ),
                             (PUNICODE_STRING) NULL,
                             DeviceObject->DeviceType,
                             0,
                             FALSE,
                             &filespyDeviceObject );

    if (!NT_SUCCESS( status )) {

        
        return status;
    }

	devExt = filespyDeviceObject->DeviceExtension;

	devExt  ->pVirtualRootDir = PfpCreateVirtualDirObject(L"\\",NULL);

	if(devExt ->pVirtualRootDir == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
// 	InitializeListHead(devExt ->DiskFileObejcts_List);
// 
// 	ExInitializeFastMutex(&devExt ->DiskFileObject_Mutex);
// 	ExInitializeResourceLite(&devExt ->DiskObjectsResource);
// 	
    //
    //  Propagate flags from Device Object we are trying to attach to.
    //  Note that we do this before the actual attachment to make sure
    //  the flags are properly set once we are attached (since an IRP
    //  can come in immediately after attachment but before the flags would
    //  be set).
    //

    SetFlag( filespyDeviceObject->Flags,
             FlagOn( DeviceObject->Flags,
                     (DO_BUFFERED_IO |
                      DO_DIRECT_IO |
                      DO_SUPPORTS_TRANSACTIONS) ));

    SetFlag( filespyDeviceObject->Characteristics,
             FlagOn( DeviceObject->Characteristics,
                     (FILE_DEVICE_SECURE_OPEN) ));

    //
    //  Load extension, set device object associated with extension.
    //

   // devExt = filespyDeviceObject->DeviceExtension;

    NLInitDeviceExtensionHeader( &devExt->NLExtHeader,
                                 filespyDeviceObject,
                                 NULL );

    SpyInitDeviceNamingEnvironment( filespyDeviceObject );

    devExt->Flags = 0;


    //
    //  Set the name.  We allocate from non-paged pool so this memory is always
    //  available for debugging (never gets paged out).
    //

    status = NLAllocateAndCopyUnicodeString( &devExt->NLExtHeader.DeviceName,
                                             &DeviceName->Name,
                                             FILESPY_DEVNAME_TAG );

    if (!NT_SUCCESS(status)) {

        goto ErrorCleanupDevice;
    }

    //
    //  Do the attachment
    //

    status = SpyAttachDeviceToDeviceStack( filespyDeviceObject,
                                           DeviceObject,
                                           &devExt->NLExtHeader.AttachedToDeviceObject );

    if (!NT_SUCCESS( status )) {

        

        goto ErrorCleanupDevice;
    }


    //
    //  The NETWORK device objects function as both CDOs (control device object)
    //  and VDOs (volume device object) so insert the NETWORK CDO devices into
    //  the list of attached device so we will properly enumerate it.
    //

    if (FILE_DEVICE_NETWORK_FILE_SYSTEM == DeviceObject->DeviceType) {

        ExAcquireFastMutex( &gSpyDeviceExtensionListLock );
        InsertTailList( &gSpyDeviceExtensionList, &devExt->NextFileSpyDeviceLink );
        ExReleaseFastMutex( &gSpyDeviceExtensionListLock );

        SetFlag(devExt->Flags,ExtensionIsLinked);
    }
	

	PfpCreateShadowDeviceForDevice(filespyDeviceObject);
    //
    //  Flag we are no longer initializing this device object
    //

    ClearFlag( filespyDeviceObject->Flags, DO_DEVICE_INITIALIZING );

    //
    //  Display who we have attached to
    //

    

    //
    //  VERSION NOTE:
    //
    //  In Windows XP, the IO Manager provided APIs to safely enumerate all the
    //  device objects for a given driver.  This allows filters to attach to
    //  all mounted volumes for a given file system at some time after the
    //  volume has been mounted.  There is no support for this functionality
    //  in Windows 2000.
    //
    //  MULTIVERSION NOTE:
    //
    //  If built for Windows XP or later, this driver is built to run on
    //  multiple versions.  When this is the case, we will test
    //  for the presence of the new IO Manager routines that allow for volume
    //  enumeration.  If they are not present, we will not enumerate the volumes
    //  when we attach to a new file system.
    //

#if WINVER >= 0x0501

    if (IS_WINDOWSXP_OR_LATER()) {

#       define FSDEnumErrorMsg "FileSpy!SpyAttachToFileSystemDevice: Error attaching to existing volumes for \"%wZ\", status=%08x\n"
        ASSERT( NULL != gSpyDynamicFunctions.EnumerateDeviceObjectList &&
                NULL != gSpyDynamicFunctions.GetStorageStackDeviceObject &&
                NULL != gSpyDynamicFunctions.GetDeviceAttachmentBaseRef &&
                NULL != gSpyDynamicFunctions.GetLowerDeviceObject );

        //
        //  Enumerate all the mounted devices that currently
        //  exist for this file system and attach to them.
        //

//         status = SpyEnumerateFileSystemVolumes( DeviceObject );
// 
//         if (!NT_SUCCESS( status )) {
// 
//             
//             IoDetachDevice( devExt->NLExtHeader.AttachedToDeviceObject );
//             goto ErrorCleanupDevice;
//         }
    }

#endif

    return STATUS_SUCCESS;

    /////////////////////////////////////////////////////////////////////
    //                  Cleanup error handling
    /////////////////////////////////////////////////////////////////////

ErrorCleanupDevice:

    SpyCleanupMountedDevice( filespyDeviceObject );

    IoDeleteDevice( filespyDeviceObject );

    return status;
}

VOID
SpyDetachFromFileSystemDevice (
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    Given a base file system device object, this will scan up the attachment
    chain looking for our attached device object.  If found it will detach
    us from the chain.

Arguments:

    DeviceObject - The file system device to detach from.

Return Value:

--*/
{
    PDEVICE_OBJECT ourAttachedDevice;
    PFILESPY_DEVICE_EXTENSION devExt;

    PAGED_CODE();

    //
    //  We have to iterate through the device objects in the filter stack
    //  attached to DeviceObject.  If we are attached to this filesystem device
    //  object, We should be at the top of the stack, but there is no guarantee.
    //  If we are in the stack and not at the top, we can safely call
    //  IoDetachDevice at this time because the IO Manager will only really
    //  detach our device object from the stack at a safe time.
    //

    //
    //  Skip the base file system device object (since it can't be us).
    //

    ourAttachedDevice = DeviceObject->AttachedDevice;

    while (NULL != ourAttachedDevice) {

        if (IS_FILESPY_DEVICE_OBJECT( ourAttachedDevice )) {

            devExt = ourAttachedDevice->DeviceExtension;

            //
            //  Display who we detached from.
            //

        

            //
            //  Unlink from global list.
            //

            if (FlagOn(devExt->Flags,ExtensionIsLinked)) {

                ExAcquireFastMutex( &gSpyDeviceExtensionListLock );
                RemoveEntryList( &devExt->NextFileSpyDeviceLink );
                ExReleaseFastMutex( &gSpyDeviceExtensionListLock );
                ClearFlag(devExt->Flags,ExtensionIsLinked);
            }

            //
            //  Detach us from the object just below us
            //  Cleanup and delete the object.
            //
			if( devExt && !devExt->bShadow)
			{
				if(devExt->pVirtualRootDir)
				{
					PfpDeleteVirtualDir(&(PDISKDIROBEJECT)devExt->pVirtualRootDir);
				}
				if(devExt->pszUsbDiskSeriNUM!= NULL)
				{
					ExFreePool_A(devExt->pszUsbDiskSeriNUM);
				}
				if(devExt->pShadowDevice)
				{
					IoDeleteDevice( devExt->pShadowDevice );
					devExt->pShadowDevice= NULL;
				}

				if(devExt->bUsbDevice)
				{
				 
					if(devExt->pUsbSecureConfig)
					{
						((PUSBSECURE)devExt->pUsbSecureConfig) ->pUsbVolumeDevice = NULL;
					}
					if( g_UsbDeviceSignal)
					{
						KdPrint(("set event in DetachfromFileSystem\r\n"));
						KeSetEvent(g_UsbDeviceSignal ,IO_NO_INCREMENT, FALSE);
					}
				}
			}
            SpyCleanupMountedDevice( ourAttachedDevice );
            IoDetachDevice( DeviceObject );
            IoDeleteDevice( ourAttachedDevice );

            return;
        }

        //
        //  Look at the next device up in the attachment chain.
        //

        DeviceObject = ourAttachedDevice;
        ourAttachedDevice = ourAttachedDevice->AttachedDevice;
    }
}

#if WINVER >= 0x0501

NTSTATUS
SpyEnumerateFileSystemVolumes (
    __in PDEVICE_OBJECT FSDeviceObject
    )
/*++

Routine Description:

    Enumerate all the mounted devices that currently exist for the given file
    system and attach to them.  We do this because this filter could be loaded
    at any time and there might already be mounted volumes for this file system.

Arguments:

    FSDeviceObject - The device object for the file system we want to enumerate.

    Name - An already initialized name control used to retrieve names.

Return Value:

    The status of the operation

--*/
{
    PDEVICE_OBJECT newDeviceObject;
    PFILESPY_DEVICE_EXTENSION newDevExt;
    PDEVICE_OBJECT *devList;
    PDEVICE_OBJECT storageStackDeviceObject;
    NTSTATUS status;
    PNAME_CONTROL devName;
    ULONG numDevices;
    ULONG i;
    BOOLEAN hasLock = FALSE;

    PAGED_CODE();

    //
    //  Find out how big of an array we need to allocate for the
    //  mounted device list.
    //

    ASSERT( NULL != gSpyDynamicFunctions.EnumerateDeviceObjectList );
    status = (gSpyDynamicFunctions.EnumerateDeviceObjectList)(
                                    FSDeviceObject->DriverObject,
                                    NULL,
                                    0,
                                    &numDevices );

    //
    //  We only need to get this list of there are devices.  If we
    //  don't get an error there are no devices so return.
    //

    if (NT_SUCCESS( status )) {

        return status;
    }

    ASSERT(STATUS_BUFFER_TOO_SMALL == status);

    //
    //  Allocate memory for the list of known devices.
    //

    numDevices += 8;        //grab a few extra slots

    devList = ExAllocatePoolWithTag( NonPagedPool,
                                     (numDevices * sizeof(PDEVICE_OBJECT)),
                                     FILESPY_POOL_TAG );
    if (NULL == devList) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    //  Now get the list of devices.  If we get an error again
    //  something is wrong, so just fail.
    //

    status = (gSpyDynamicFunctions.EnumerateDeviceObjectList)(
                    FSDeviceObject->DriverObject,
                    devList,
                    (numDevices * sizeof(PDEVICE_OBJECT)),
                    &numDevices );

    if (!NT_SUCCESS( status ))  {

        ExFreePoolWithTag( devList, FILESPY_POOL_TAG );
        return status;
    }

    //
    //  Allocate the name.  We'll use this same name buffer each time
    //  through the for loop.
    //

    status = NLAllocateNameControl( &devName, &gFileSpyNameBufferLookasideList );

    if (!NT_SUCCESS( status )) {

        //
        //  Must dereference each element of the list from
        //  IoEnumerateDeviceObjectList.
        //

        for (i=0; i<numDevices; i++) {

            ObDereferenceObject( devList[i] );
        }

        ExFreePoolWithTag( devList, FILESPY_POOL_TAG );
        goto SkipAttach;
    }

    //
    //  Walk the given list of devices and attach to them if we should.
    //

    for (i=0; i < numDevices; i++) {

        devName->Name.Length = 0;

        storageStackDeviceObject = NULL;
        newDeviceObject = NULL;

        __try {

            //
            //  Do not attach if:
            //      - This is the control device object (the one passed in)
            //      - The device type does not match
            //      - We are already attached to it
            //

            if ((devList[i] == FSDeviceObject) ||
                (devList[i]->DeviceType != FSDeviceObject->DeviceType) ||
                SpyIsAttachedToDevice( devList[i], NULL )) {

                __leave;
            }

            //
            //  See if this device has a name.  If so, then it must
            //  be a control device so don't attach to it.  This handles
            //  drivers with more then one control device.
            //  We also don't want to attach if we could not get a name.
            //

            status = SpyGetBaseDeviceObjectName( devList[i], devName );

            if (!NT_SUCCESS(status) || (devName->Name.Length > 0)) {

                __leave;
            }

            //
            //  Get the disk device object associated with this
            //  file  system device object.  Only try to attach if we
            //  have a disk device object.
            //

            ASSERT( NULL != gSpyDynamicFunctions.GetStorageStackDeviceObject );
            status = (gSpyDynamicFunctions.GetStorageStackDeviceObject)( devList[i],
                                                                         &storageStackDeviceObject );

            if (!NT_SUCCESS( status )) {

                storageStackDeviceObject = NULL;
                __leave;
            }

            //
            //  Allocate a new device object to attach with.
            //

            status = IoCreateDevice( gFileSpyDriverObject,
                                 sizeof( FILESPY_DEVICE_EXTENSION ),
                                 (PUNICODE_STRING) NULL,
                                 devList[i]->DeviceType,
                                 0,
                                 FALSE,
                                 &newDeviceObject );

            if (!NT_SUCCESS( status )) {

              /*  SPY_LOG_PRINT( SPYDEBUG_ERROR,
                               ("FileSpy!SpyEnumberateFileSystemVolumes: Error creating volume device object, status=%08x\n",
                                status) );
                */newDeviceObject = NULL;
                __leave;
            }

            //
            //  Initialize the device extension.
            //

			newDevExt = newDeviceObject->DeviceExtension;

			newDevExt  ->pVirtualRootDir = PfpCreateVirtualDirObject(L"\\",NULL);
			if(newDevExt ->pVirtualRootDir == NULL)
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}
// 			InitializeListHead(newDevExt ->DiskFileObejcts_List);
// 
// 			ExInitializeFastMutex(&newDevExt ->DiskFileObject_Mutex);
// 
// 			ExInitializeResourceLite(&newDevExt ->DiskObjectsResource);
			PfpCreateShadowDeviceForDevice(newDeviceObject);

            newDevExt = newDeviceObject->DeviceExtension;

            NLInitDeviceExtensionHeader( &newDevExt->NLExtHeader,
                                         newDeviceObject,
                                         storageStackDeviceObject );

            newDevExt->Flags = 0;

            //
            //  Initialize UserNames' buffer.
            //

            RtlInitEmptyUnicodeString( &newDevExt->UserNames, NULL, 0 );


            //
            //  Get the device name, reusing the name NAME_CONTROL.
            //

            devName->Name.Length = 0;

            status = NLGetObjectName( storageStackDeviceObject,
                                      devName );

            if (!NT_SUCCESS( status )) {

                __leave;
            }

            //
            //  Copy it to the device extension.  We allocate from non-paged
            //  pool so this memory is always available for debugging (never
            //  gets paged out).
            //

            status = NLAllocateAndCopyUnicodeString( &newDevExt->NLExtHeader.DeviceName,
                                                     &devName->Name,
                                                     FILESPY_DEVNAME_TAG );

            if (!NT_SUCCESS(status)) {

                __leave;
            }

            //
            //  We have done a lot of work since the last time we tested to
            //  see if we were already attached to this device object.  Test
            //  again, this time with a lock, and attach if we are not
            //  attached.  The lock is used to atomically test if we are
            //  attached, and then do the attach.
            //

            ExAcquireFastMutex( &gSpyAttachLock );
            hasLock = TRUE;

            if (SpyIsAttachedToDevice( devList[i], NULL )) {

                __leave;
            }

            //
            //  Attach to this device object.
            //

            status = SpyAttachToMountedDevice( devList[i],
                                               newDeviceObject );

            //
            //  Handle normal vs error cases, but keep going.
            //

            if (!NT_SUCCESS( status )) {

                //
                //  The attachment failed, cleanup.  Note that we
                //  continue processing so we will cleanup the reference
                //  counts and try to attach to the rest of the volumes.
                //
                //  One of the reasons this could have failed is because
                //  this volume is just being mounted as we are
                //  attaching and the DO_DEVICE_INITIALIZING flag has
                //  not yet been cleared.  A filter could handle this
                //  situation by pausing for a short period of time and
                //  retrying the attachment.
                //

                __leave;
            }

            //
            //  We are now attached,  clear initializing flag now.  This
            //  allows other filters to now attach to our device object.
            //

            ClearFlag( newDeviceObject->Flags, DO_DEVICE_INITIALIZING );

            //
            //  Release the lock.
            //

            ExReleaseFastMutex( &gSpyAttachLock );
            hasLock = FALSE;

            //
            //  If we just successfully attached, then get the DOS device
            //  name.  We could not do this above because a mutex was held.
            //

            NLGetDosDeviceName( newDeviceObject,
                                &newDevExt->NLExtHeader );


			newDevExt->bUsbDevice = ((GetStorageDeviceBusType(newDevExt->NLExtHeader.StorageStackDeviceObject->Vpb->RealDevice,&newDevExt->pszUsbDiskSeriNUM ,&newDevExt->nLenExcludeTermiter)==7)?TRUE:FALSE);

			if(newDevExt->bUsbDevice)
			{
				//GetUsbStorageDeviceID(,newDevExt->NLExtHeader.StorageStackDeviceObject->Vpb->RealDevice);
				PfpInitUsbDeviceWithSecure(newDeviceObject);
			}
            //
            //  Mark not to free the device object
            //

            newDeviceObject = NULL;

        } 
		__finally 
		{

            if (hasLock) {

                ExReleaseFastMutex( &gSpyAttachLock );
            }

            //
            //  Remove reference added by IoGetDiskDeviceObject.  We only
            //  need to hold this reference until we are successfully
            //  attached to the current volume.  Once we are successfully
            //  attached to devList[i], the IO Manager will make sure that
            //  the underlying storageStackDeviceObject will not go away
            //  until the file system stack is torn down.
            //

            if (storageStackDeviceObject != NULL) {

                ObDereferenceObject( storageStackDeviceObject );
            }

            //
            //  Cleanup the device object if still defined
            //

            if (newDeviceObject != NULL) {

                SpyCleanupMountedDevice( newDeviceObject );
                IoDeleteDevice( newDeviceObject );
            }

            //
            //  Dereference the object (reference added by
            //  IoEnumerateDeviceObjectList).
            //

            ObDereferenceObject( devList[i] );
        }
    }

    NLFreeNameControl( devName, &gFileSpyNameBufferLookasideList );

SkipAttach:

    //
    //  We are going to ignore any errors received while loading.  We
    //  simply won't be attached to those volumes if we get an error
    //

    status = STATUS_SUCCESS;

    //
    //  Free the memory we allocated for the list.
    //

    ExFreePoolWithTag( devList, FILESPY_POOL_TAG );

    return status;
}
#endif

////////////////////////////////////////////////////////////////////////
//                                                                    //
//             Private Filespy IOCTLs helper routines                 //
//                                                                    //
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyGetAttachList (
    __out_bcount_part(BufferSize,*ReturnLength) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG_PTR ReturnLength
    )
/*++

Routine Description:
    This returns an array of structure identifying all of the devices
    we are currently physical attached to and whether logging is on or
    off for the given device

Arguments:
    Buffer - buffer to receive the attachment list
    BufferSize - total size in bytes of the return buffer
    ReturnLength - receives number of bytes we actually return

Return Value:
    NT Status code

--*/
{
    PLIST_ENTRY link;
    PFILESPY_DEVICE_EXTENSION devExt;
    PATTACHED_DEVICE pAttDev;
    ULONG retlen = 0;
    UNICODE_STRING attachedDevName;

    PAGED_CODE();

    pAttDev = Buffer;

    __try {

        ExAcquireFastMutex( &gSpyDeviceExtensionListLock );

        for (link = gSpyDeviceExtensionList.Flink;
             link != &gSpyDeviceExtensionList;
             link = link->Flink) {

             devExt = CONTAINING_RECORD(link,
                                        FILESPY_DEVICE_EXTENSION,
                                        NextFileSpyDeviceLink);

            if (BufferSize < sizeof(ATTACHED_DEVICE)) {

                break;
            }

            pAttDev->LoggingOn = BooleanFlagOn(devExt->Flags,LogThisDevice);

            //
            //  We set up a unicode string to represent the buffer where we
            //  want to copy the device name (and DOS name if available).
            //  We will reserve space for the terminating NULL that the
            //  caller is expecting.
            //
            //  NOTE: Since DeviceNames is an imbedded array in the
            //  ATTACHED_DEVICE structure, sizeof( pAttDev->DeviceNames )
            //  returns the correct size.  RtlCopyUnicodeString ensure that the
            //  copy does not extend past the MaximumLength of our destination
            //  string.
            //

            RtlInitEmptyUnicodeString( &attachedDevName,
                                       pAttDev->DeviceNames,
                                       (sizeof( pAttDev->DeviceNames ) -
                                        sizeof( UNICODE_NULL )) );

            RtlCopyUnicodeString( &attachedDevName,
                                  &devExt->NLExtHeader.DeviceName );

            //
            //  If we have a list of user names then this must be
            //  a device that has no DOS device name.  Append the list
            //  of user names.  Otherwise, if we have a DOS device name
            //  append it.
            //

            if (devExt->UserNames.Buffer != NULL) {

                RtlAppendUnicodeToString( &attachedDevName, L", " );
                RtlAppendUnicodeStringToString( &attachedDevName,
                                                &devExt->UserNames );

            } else if (devExt->NLExtHeader.DosName.Length != 0) {

                RtlAppendUnicodeToString( &attachedDevName, L", " );
                RtlAppendUnicodeStringToString( &attachedDevName,
                                                &devExt->NLExtHeader.DosName );
            }

            attachedDevName.Buffer[attachedDevName.Length/sizeof(WCHAR)] = UNICODE_NULL;

            retlen += sizeof( ATTACHED_DEVICE );
            BufferSize -= sizeof( ATTACHED_DEVICE );
            pAttDev++;
        }

    } 
	__finally 
	{
        ExReleaseFastMutex( &gSpyDeviceExtensionListLock );
    }

    *ReturnLength = retlen;
    return STATUS_SUCCESS;
}


VOID
SpyCloseControlDevice (
    VOID
    )
/*++

Routine Description:

    This is the routine that is associated with IRP_MJ_
    This routine does the cleanup involved in closing the ControlDevice.
    On the close of the Control Device, we need to empty the queue of
    logRecords that are waiting to be returned to the user.

Arguments:

    None.

Return Value:

    None.

--*/
{
    KIRQL oldIrql;

    //
    //  Set the gControlDeviceState to CLEANING_UP so that we can
    //  signal that we are cleaning up the device.
    //

    KeAcquireSpinLock( &gControlDeviceStateLock, &oldIrql );
    gControlDeviceState = CLEANING_UP;
    KeReleaseSpinLock( &gControlDeviceStateLock, oldIrql );

   
    //SpyNameDeleteAllNames();

    //
    //  All the cleanup is done, so set the gControlDeviceState
    //  to CLOSED.
    //

    KeAcquireSpinLock( &gControlDeviceStateLock, &oldIrql );
    gControlDeviceState = CLOSED;
    KeReleaseSpinLock( &gControlDeviceStateLock, oldIrql );
}

////////////////////////////////////////////////////////////////////////
//                                                                    //
//               Device name tracking helper routines                 //
//                                                                    //
////////////////////////////////////////////////////////////////////////


//
//  VERSION NOTE:
//
//  This helper routine is only needed when enumerating all volumes in the
//  system, which is only supported on Windows XP and later.
//

#if WINVER >= 0x0501

NTSTATUS
SpyGetBaseDeviceObjectName (
    __in PDEVICE_OBJECT DeviceObject,
    __inout PNAME_CONTROL Name
    )
/*++

Routine Description:

    This locates the base device object in the given attachment chain and then
    returns the name of that object.

    If no name can be found, an empty string is returned.

Arguments:

    Object - The object whose name we want

    Name - A name control that is already initialized.

Return Value:

    None

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    //
    //  Get the base file system device object.
    //

    ASSERT( NULL != gSpyDynamicFunctions.GetDeviceAttachmentBaseRef );
    DeviceObject = (gSpyDynamicFunctions.GetDeviceAttachmentBaseRef)( DeviceObject );

    //
    //  Get the name of that object.
    //

    status = NLGetObjectName( DeviceObject, Name );

    //
    //  Remove the reference added by IoGetDeviceAttachmentBaseRef.
    //

    ObDereferenceObject( DeviceObject );

    return status;
}

#endif

BOOLEAN
SpyFindSubString (
    __in PUNICODE_STRING String,
    __in PUNICODE_STRING SubString
    )
/*++

Routine Description:
    This routine looks to see if SubString is a substring of String.  This
    does a case insensitive test.

Arguments:
    String - the string to search in
    SubString - the substring to find in String

Return Value:
    Returns TRUE if the substring is found in string and FALSE otherwise.

--*/
{
    ULONG index;

    //
    //  First, check to see if the strings are equal.
    //

    if (RtlEqualUnicodeString( String, SubString, TRUE )) {

        return TRUE;
    }

    //
    //  String and SubString aren't equal, so now see if SubString
    //  is in String any where.
    //

    for (index = 0;
         index + (SubString->Length/sizeof(WCHAR)) <= (String->Length/sizeof(WCHAR));
         index++) {

        if (_wcsnicmp( &String->Buffer[index],
                       SubString->Buffer,
                       (SubString->Length / sizeof(WCHAR)) ) == 0) {

            //
            //  SubString is found in String, so return TRUE.
            //

            return TRUE;
        }
    }

    return FALSE;
}

VOID
SpyStoreUserName (
    __inout PFILESPY_DEVICE_EXTENSION devExt,
    __in PNAME_CONTROL UserName
    )
/*++

Routine Description:

    Stores the current device name in the device extension.  If
    this name is already in the device name list of this extension,
    it will not be added.  If there is already a name for this device,
    the new device name is appended to the DeviceName in the device extension.

Arguments:

    devExt - The device extension that will store the
        device name.

    UserName - The device name as specified by the user to be stored.

Return Value:

    None

--*/
{
    PNAME_CONTROL tempName;
    NTSTATUS status;

    //
    //  If the user-supplied name isn't on the UserNames list and
    //  is not the same as the device name, add it to UserNames.
    //

    if (!SpyFindSubString( &devExt->UserNames, &UserName->Name ) &&
        !SpyFindSubString( &devExt->NLExtHeader.DeviceName,
                           &UserName->Name )) {

        //
        //  Allocate a name control to build up the new user name in.  After the
        //  new user name string is built, we'll reallocate the UserNames buffer
        //  and copy the new string there.
        //

        status = NLAllocateNameControl( &tempName, &gFileSpyNameBufferLookasideList );

        if (!NT_SUCCESS( status )) {

            return;
        }

        //
        //  We didn't find this name in the list, and it is not
        //  the same as the device name; so if there are no names
        //  in the list, just append UserName.  Otherwise, append a
        //  delimiter then append UserName.
        //

        if (devExt->UserNames.Length == 0) {

            status = NLCheckAndGrowNameControl( tempName,
                                                devExt->UserNames.Length +
                                                 UserName->Name.Length );

            if (!NT_SUCCESS( status )) {

                goto SpyStoreUserName_ErrorExit;
            }

            RtlCopyUnicodeString( &tempName->Name, &devExt->UserNames );
            RtlAppendUnicodeStringToString( &tempName->Name, &UserName->Name );


        } else {

            status = NLCheckAndGrowNameControl( tempName,
                                                devExt->UserNames.Length +
                                                 UserName->Name.Length +
                                                 2*sizeof(WCHAR) );

            if (!NT_SUCCESS( status )) {

                goto SpyStoreUserName_ErrorExit;
            }

            RtlCopyUnicodeString( &tempName->Name, &devExt->UserNames );
            RtlAppendUnicodeToString( &tempName->Name, L", " );
            RtlAppendUnicodeStringToString( &tempName->Name, &UserName->Name );
        }

        //
        //  Now reallocate the UserNames buffer and place the new string.
        //

        if (devExt->UserNames.Buffer != NULL) {

            ExFreePoolWithTag( devExt->UserNames.Buffer,
                               FILESPY_USERNAME_TAG );
        }

        devExt->UserNames.MaximumLength = tempName->Name.Length;
        devExt->UserNames.Buffer = ExAllocatePoolWithTag( NonPagedPool,
                                                          tempName->Name.Length,
                                                          FILESPY_USERNAME_TAG );

        if (devExt->UserNames.Buffer == NULL) {

            goto SpyStoreUserName_ErrorExit;
        }

        RtlCopyUnicodeString( &devExt->UserNames, &tempName->Name );

        NLFreeNameControl( tempName, &gFileSpyNameBufferLookasideList );
    }

    return;

SpyStoreUserName_ErrorExit:

    NLFreeNameControl( tempName, &gFileSpyNameBufferLookasideList );
    return;
}

////////////////////////////////////////////////////////////////////////
//                                                                    //
//                        Debug support routines                      //
//                                                                    //
////////////////////////////////////////////////////////////////////////
#if WINVER >= 0x0501 /* See comment in DriverEntry */


#endif

