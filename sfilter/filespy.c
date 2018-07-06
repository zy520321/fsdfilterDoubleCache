/*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    filespy.c

Abstract:

    This is the main module of FileSpy.

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

//
//  Fixes Win2K compatibility regarding lookaside lists.
//

#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
//#include "filespy.h"
#include "fspyKern.h"
//#include "Aes.h"
#include "MD5.h"
#include <wdmsec.h>
#include "LOG.h"
#include "UsbSecure.h"
#include "PfpCreate.h"
//
//  list of known device types
//

const PCHAR DeviceTypeNames[] = {
    "",
    "BEEP",
    "CD_ROM",
    "CD_ROM_FILE_SYSTEM",
    "CONTROLLER",
    "DATALINK",
    "DFS",
    "DISK",
    "DISK_FILE_SYSTEM",
    "FILE_SYSTEM",
    "INPORT_PORT",
    "KEYBOARD",
    "MAILSLOT",
    "MIDI_IN",
    "MIDI_OUT",
    "MOUSE",
    "MULTI_UNC_PROVIDER",
    "NAMED_PIPE",
    "NETWORK",
    "NETWORK_BROWSER",
    "NETWORK_FILE_SYSTEM",
    "NULL",
    "PARALLEL_PORT",
    "PHYSICAL_NETCARD",
    "PRINTER",
    "SCANNER",
    "SERIAL_MOUSE_PORT",
    "SERIAL_PORT",
    "SCREEN",
    "SOUND",
    "STREAMS",
    "TAPE",
    "TAPE_FILE_SYSTEM",
    "TRANSPORT",
    "UNKNOWN",
    "VIDEO",
    "VIRTUAL_DISK",
    "WAVE_IN",
    "WAVE_OUT",
    "8042_PORT",
    "NETWORK_REDIRECTOR",
    "BATTERY",
    "BUS_EXTENDER",
    "MODEM",
    "VDM",
    "MASS_STORAGE",
    "SMB",
    "KS",
    "CHANGER",
    "SMARTCARD",
    "ACPI",
    "DVD",
    "FULLSCREEN_VIDEO",
    "DFS_FILE_SYSTEM",
    "DFS_VOLUME",
    "SERENUM",
    "TERMSRV",
    "KSEC"
};

//
//  We need this because the compiler doesn't like doing sizeof an external
//  array in the other file that needs it (fspylib.c)
//

ULONG SizeOfDeviceTypeNames = sizeof( DeviceTypeNames );




//
//  We only need a global TM and a RM to enlist in the transactions and
//  receive transaction notifications.
//

//
//  Since functions in drivers are non-pageable by default, these pragmas
//  allow the driver writer to tell the system what functions can be paged.
//
//  Use the PAGED_CODE() macro at the beginning of these functions'
//  implementations while debugging to ensure that these routines are
//  never called at IRQL > APC_LEVEL (therefore the routine cannot
//  be paged).
//
#if DBG && WINVER >= 0x0501
VOID
DriverUnload(
    __in PDRIVER_OBJECT DriverObject
    );
#endif

#ifdef ALLOC_PRAGMA

#pragma alloc_text(INIT, DriverEntry)
#if DBG && WINVER >= 0x0501
#pragma alloc_text(PAGE, DriverUnload)
#endif
#pragma alloc_text(PAGE, SpyFsNotification)

#pragma alloc_text(PAGE, SpyFsControl)
#pragma alloc_text(PAGE, SpyFsControlMountVolume)
#pragma alloc_text(PAGE, SpyFsControlMountVolumeComplete)
#pragma alloc_text(PAGE, SpyFsControlLoadFileSystem)
#pragma alloc_text(PAGE, SpyFsControlLoadFileSystemComplete)
#pragma alloc_text(PAGE, SpyFastIoCheckIfPossible)
#pragma alloc_text(PAGE, SpyFastIoRead)
#pragma alloc_text(PAGE, SpyFastIoWrite)
#pragma alloc_text(PAGE, SpyFastIoQueryBasicInfo)
#pragma alloc_text(PAGE, SpyFastIoQueryStandardInfo)
#pragma alloc_text(PAGE, SpyFastIoLock)
#pragma alloc_text(PAGE, SpyFastIoUnlockSingle)
#pragma alloc_text(PAGE, SpyFastIoUnlockAll)
#pragma alloc_text(PAGE, SpyFastIoUnlockAllByKey)
#pragma alloc_text(PAGE, SpyFastIoDeviceControl)
#pragma alloc_text(PAGE, SpyFastIoDetachDevice)
#pragma alloc_text(PAGE, SpyFastIoQueryNetworkOpenInfo)
#pragma alloc_text(PAGE, SpyFastIoMdlRead)
#pragma alloc_text(PAGE, SpyFastIoPrepareMdlWrite)
#pragma alloc_text(PAGE, SpyFastIoReadCompressed)
#pragma alloc_text(PAGE, SpyFastIoWriteCompressed)
#pragma alloc_text(PAGE, SpyFastIoQueryOpen)
#pragma alloc_text(PAGE, SpyCommonDeviceIoControl)

#endif



NPAGED_LOOKASIDE_LIST PfpFileLockLookasideList;
NPAGED_LOOKASIDE_LIST g_DiskFileObejctLookasideList;
NPAGED_LOOKASIDE_LIST g_PfpFCBLookasideList;
NPAGED_LOOKASIDE_LIST g_EresourceLookasideList;
NPAGED_LOOKASIDE_LIST g_FaseMutexInFCBLookasideList;
NPAGED_LOOKASIDE_LIST g_ListEntryInFCBLookasideList;
NPAGED_LOOKASIDE_LIST g_NTFSFCBLookasideList;
NPAGED_LOOKASIDE_LIST g_UserFileObejctLookasideList;
PAGED_LOOKASIDE_LIST  gFileSpyNameBufferLookasideList;
NPAGED_LOOKASIDE_LIST NtfsIrpContextLookasideList;
NPAGED_LOOKASIDE_LIST NtfsIoContextLookasideList;
NPAGED_LOOKASIDE_LIST PfpCreateContextLookasideList;

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for the general purpose file system
    filter driver.  This routine creates the device object that represents
    this driver in the system and registers it for watching all file systems
    that register or unregister themselves as active file systems.

Arguments:

    DriverObject - Pointer to driver object created by the system.

Return Value:

    The function value is the final status from the initialization operation.

--*/
{
    UNICODE_STRING nameString;
    NTSTATUS status;
    PFAST_IO_DISPATCH fastIoDispatch;
    ULONG i;
    UNICODE_STRING linkString;
	UNICODE_STRING ustrSecDDL;
	PWCHAR	szBuf = NULL;
	UCHAR szIDA[]={0xff,0x74,0x51,0xe8,0x00};
	gAllFileCount = 0;
	NtfsLarge0.QuadPart=0;
	NtfsLarge1.HighPart=1;
	NtfsLarge1.LowPart =0;
	gFileSpyAttachMode = FILESPY_ATTACH_ON_DEMAND;
	g_ShadowDeivceName = ExAllocatePoolWithTag(PagedPool,(wcslen(L"\\Device\\ShadowDevicePfp0000")+1)*sizeof(WCHAR),'pfp0');

	
	if(g_ShadowDeivceName== NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlInitUnicodeString(&ustrSecDDL,L"D:P(A;;GA;;;AU)");

	g_SectorSize  =	512; 

	g_ShadowDosDeivceName = ExAllocatePoolWithTag(PagedPool,(1+wcslen(L"\\DosDevices\\PFP0000"))*sizeof(WCHAR),'pfp0');
	if(g_ShadowDosDeivceName == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	wcscpy (g_ShadowDeivceName,L"\\Device\\ShadowDevicePfp0000");
	wcscpy (g_ShadowDosDeivceName,L"\\DosDevices\\PFP0000");

	RtlZeroMemory(szVcbPlacer,sizeof(UCHAR)*300);

	g_nRunningState = 1;	
	g_nHIDEState    = 1;	
	ExeHasLoggon    = 0;
	g_bUseExternKey = FALSE;
    //////////////////////////////////////////////////////////////////////
    //
    //  General setup for all filter drivers.  This sets up the filter
    //  driver's DeviceObject and registers the callback routines for
    //  the filter driver.
    //
    //////////////////////////////////////////////////////////////////////

#if WINVER >= 0x0501
    //
    //  Try to load the dynamic functions that may be available for our use.
    //

    SpyLoadDynamicFunctions();

    //
    //  Now get the current OS version that we will use to determine what logic
    //  paths to take when this driver is built to run on various OS version.
    //

    SpyGetCurrentVersion();
#endif

    //
    //  Read the custom parameters for FileSpy from the registry
    //

    SpyReadDriverParameters( RegistryPath );

    

    //
    //  Save our Driver Object.
    //

    gFileSpyDriverObject = DriverObject;

    //
    //  Initialize the lookaside list for name buffering.  This is used in
    //  several places to avoid having a large name buffer on the stack.  It is
    //  also needed by the name lookup routines (NLxxx).
    //
	ExInitializePagedLookasideList( &gFileSpyNameBufferLookasideList,
									NULL,
									NULL,
									0,
									FILESPY_LOOKASIDE_SIZE,
									FILESPY_NAME_BUFFER_TAG,
									0 );

	ExInitializeNPagedLookasideList(&NtfsIrpContextLookasideList,
									NULL,
									NULL,
									0,
									sizeof(IRP_CONTEXT),
									'1110',
									0);
	

	ExInitializeNPagedLookasideList(&NtfsIoContextLookasideList,
									NULL,
									NULL,
									0,
									sizeof(NTFS_IO_CONTEXT),
									'1111',
									0);
	
	
	ExInitializeNPagedLookasideList(&PfpCreateContextLookasideList,
									NULL,
									NULL,
									0,
									sizeof(CREATECONTEXT),
									'1112',
									0);

	ExInitializePagedLookasideList(&g_VirualDirLookasideList,
									NULL,
									NULL,
									0,
									sizeof(DISKDIROBEJECT),
									'1113',
									0);
	ExInitializePagedLookasideList(&g_VirualDiskFileLookasideList,
									NULL,
									NULL,
									0,
									sizeof(VIRTUALDISKFILE),
									'1114',
									0);

	ExInitializeNPagedLookasideList(&g_DiskFileObejctLookasideList,
									NULL,
									NULL,
									0,
									sizeof(DISKFILEOBJECT),
									'1115',
									0);
	ExInitializeNPagedLookasideList(&g_PfpFCBLookasideList,
									NULL,
									NULL,
									0,
									sizeof(PfpFCB),
									'1116',
									0);
	ExInitializeNPagedLookasideList(&g_EresourceLookasideList,
									NULL,
									NULL,
									0,
									sizeof(ERESOURCE),
									'1117',
									0);

	ExInitializeNPagedLookasideList(&g_FaseMutexInFCBLookasideList,
									NULL,
									NULL,
									0,
									sizeof(FAST_MUTEX),
									'1118',
									0);
								 
	ExInitializeNPagedLookasideList(&g_ListEntryInFCBLookasideList,
									NULL,
									NULL,
									0,
									sizeof(LIST_ENTRY),
									'1119',
									0);

	ExInitializeNPagedLookasideList(&g_NTFSFCBLookasideList,
		NULL,
		NULL,
		0,
		sizeof(NTFSFCB),
		'1120',
		0);


	ExInitializeNPagedLookasideList(&g_UserFileObejctLookasideList,
		NULL,
		NULL,
		0,
		sizeof(USERFILEOBJECT),
		'1121',
		0);
	 

#if DBG && WINVER >= 0x0501

    //
    //  MULTIVERSION NOTE:
    //
    //  We can only support unload for testing environments if we can enumerate
    //  the outstanding device objects that our driver has.
    //

    //
    //  Unload is useful for development purposes. It is not recommended for
    //  production versions.
    //

    if (IS_WINDOWSXP_OR_LATER())
	{

        ASSERT( NULL != gSpyDynamicFunctions.EnumerateDeviceObjectList );

       // gFileSpyDriverObject->DriverUnload = DriverUnload;
    }
#endif

    //
    //  Create the device object that will represent the FileSpy device.
    //

	//VirtualizerStart();
    RtlInitUnicodeString( &nameString, FILESPY_FULLDEVICE_NAME1 );

    //
    //  Create the "control" device object.  Note that this device object does
    //  not have a device extension (set to NULL).  Most of the fast IO routines
    //  check for this condition to determine if the fast IO is directed at the
    //  control device.
    //
	status =  IoCreateDeviceSecure(DriverObject,
		0,
		&nameString,
		FILE_DEVICE_DISK_FILE_SYSTEM,
		0,
		FALSE,
		&ustrSecDDL,NULL,&gControlDeviceObject);

	//VirtualizerEnd();
    if (STATUS_OBJECT_PATH_NOT_FOUND == status) 
	{

        //
        //  The "\FileSystem\Filter' path does not exist in the object name
        //  space, so we must be dealing with an OS pre-Windows XP.  Try
        //  the second name we have to see if we can create a device by that
        //  name.
        //
		////VirtualizerStart();
        RtlInitUnicodeString( &nameString, FILESPY_FULLDEVICE_NAME2 );
		
		status =  IoCreateDeviceSecure(DriverObject,
			0,
			&nameString,
			FILE_DEVICE_DISK_FILE_SYSTEM,
			0,
			FALSE,
			&ustrSecDDL,NULL,&gControlDeviceObject);
		////VirtualizerEnd();
        if (!NT_SUCCESS( status )) 
		{
            return status;
        }

        //
        //  We were able to successfully create the file spy control device
        //  using this second name, so we will now fall through and create the
        //  symbolic link.
        //

    } else if (!NT_SUCCESS( status ))
	{
        return status;
    }

	gControlDeviceState = CLOSED;

	//VirtualizerStart();
    RtlInitUnicodeString( &linkString, FILESPY_DOSDEVICE_NAME );
    status = IoCreateSymbolicLink( &linkString, &nameString );
	//VirtualizerEnd();

    if (!NT_SUCCESS(status))
	{

        //
        //  Remove the existing symbol link and try and create it again.
        //  If this fails then quit.
        //
		////VirtualizerStart();
        IoDeleteSymbolicLink( &linkString );
        status = IoCreateSymbolicLink( &linkString, &nameString );
		////VirtualizerEnd();
        if (!NT_SUCCESS(status))
		{
            IoDeleteDevice(gControlDeviceObject);
            return status;
        }
    }

    //
    //  Initialize the driver object with this device driver's entry points.
    //

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) 
	{

        DriverObject->MajorFunction[i] = SpyDispatch;
    }

	 
    DriverObject->MajorFunction[IRP_MJ_CREATE]						= PfpCreate ;
	DriverObject->MajorFunction[IRP_MJ_READ]						= PfpRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE]						= PfpWrite;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]						= PfpFsdClose;
	DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]			= (PDRIVER_DISPATCH)PfpQueryInformation;
	DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION]				= (PDRIVER_DISPATCH)PfpSetInformation;
	DriverObject->MajorFunction[IRP_MJ_QUERY_EA]					= (PDRIVER_DISPATCH)PfpFsdQueryEa;
	DriverObject->MajorFunction[IRP_MJ_SET_EA]						= (PDRIVER_DISPATCH)PfpFsdSetEa;
	DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]				= (PDRIVER_DISPATCH)PfpFsdFlushBuffers;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP]                     = (PDRIVER_DISPATCH)PfpFsdCleanup;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL]			= SpyFsControl;
	DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL]                = (PDRIVER_DISPATCH)PfpFsdLockControl;
	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]			= FsDirectoryControl;
	DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY]				= PfpFsQueryAndSetSec;
	DriverObject->MajorFunction[IRP_MJ_SET_SECURITY]				= PfpFsQueryAndSetSec;
	 
    //
    //  Allocate fast I/O data structure and fill it in.  This structure
    //  is used to register the callbacks for FileSpy in the fast I/O
    //  data paths.
    //

	
    fastIoDispatch = ExAllocatePoolWithTag( NonPagedPool,
                                            sizeof( FAST_IO_DISPATCH ),
                                            FILESPY_POOL_TAG );

    if (!fastIoDispatch) 
	{
        IoDeleteDevice( gControlDeviceObject );
        return STATUS_INSUFFICIENT_RESOURCES;
    }

	//VirtualizerStart();
    RtlZeroMemory( fastIoDispatch, sizeof( FAST_IO_DISPATCH ) );
    fastIoDispatch->SizeOfFastIoDispatch		= sizeof( FAST_IO_DISPATCH );

    fastIoDispatch->FastIoCheckIfPossible		= SpyFastIoCheckIfPossible;
    fastIoDispatch->FastIoRead					= SpyFastIoRead;
    fastIoDispatch->FastIoWrite					= SpyFastIoWrite;
    fastIoDispatch->FastIoQueryBasicInfo		= SpyFastIoQueryBasicInfo;
    fastIoDispatch->FastIoQueryStandardInfo		= SpyFastIoQueryStandardInfo;

    fastIoDispatch->FastIoLock					= SpyFastIoLock;
    fastIoDispatch->FastIoUnlockSingle			= SpyFastIoUnlockSingle;
    fastIoDispatch->FastIoUnlockAll				= SpyFastIoUnlockAll;
    fastIoDispatch->FastIoUnlockAllByKey		= SpyFastIoUnlockAllByKey;

    fastIoDispatch->FastIoDeviceControl			= SpyFastIoDeviceControl;
    fastIoDispatch->FastIoDetachDevice			= SpyFastIoDetachDevice;

    fastIoDispatch->FastIoQueryNetworkOpenInfo	  =  SpyFastIoQueryNetworkOpenInfo;
	fastIoDispatch->AcquireFileForNtCreateSection =  PfpFastAcquireForCreateSection;
	fastIoDispatch->ReleaseFileForNtCreateSection =  PfpFastReleaseForCreateSection;
  
    fastIoDispatch->MdlRead						= SpyFastIoMdlRead;
    fastIoDispatch->MdlReadComplete				= SpyFastIoMdlReadComplete;
    fastIoDispatch->PrepareMdlWrite				= SpyFastIoPrepareMdlWrite;
    fastIoDispatch->MdlWriteComplete			= SpyFastIoMdlWriteComplete;

    fastIoDispatch->FastIoReadCompressed		= SpyFastIoReadCompressed;
    fastIoDispatch->FastIoWriteCompressed		= SpyFastIoWriteCompressed;
    fastIoDispatch->MdlReadCompleteCompressed	= SpyFastIoMdlReadCompleteCompressed;
    fastIoDispatch->MdlWriteCompleteCompressed	= SpyFastIoMdlWriteCompleteCompressed;
    fastIoDispatch->FastIoQueryOpen				= SpyFastIoQueryOpen;

    DriverObject->FastIoDispatch = fastIoDispatch;
	//VirtualizerEnd();
    //////////////////////////////////////////////////////////////////////
    //
    //  Initialize global data structures that are used for FileSpy's
    //  logging of I/O operations.
    //
    //////////////////////////////////////////////////////////////////////

    //
    //  A fast mutex was used in this case because the mutex is never acquired
    //  at DPC level or above.  Spinlocks were chosen in other cases because
    //  they are acquired at DPC level or above.  Another consideration is
    //  that on an MP machine, a spin lock will literally spin trying to
    //  acquire the lock when the lock is already acquired.  Acquiring a
    //  previously acquired fast mutex will suspend the thread, thus freeing
    //  up the processor.
    //

	ExInitializeResourceLite(&g_ProcessInfoResource);

    ExInitializeFastMutex( &gSpyDeviceExtensionListLock );
    InitializeListHead( &gSpyDeviceExtensionList );

    KeInitializeSpinLock( &gControlDeviceStateLock );

	KeInitializeSpinLock( &gAllFileOpenedLOCK);
	
    ExInitializeFastMutex( &gSpyAttachLock );
	ExInitializeFastMutex(&g_HookMutex);
	ExInitializeFastMutex(&g_BackUpMetux);
	 
	ExInitializeResourceLite(&g_HideEresource);
	//ExInitializeFastMutex(&g_DiskFileObjectsFastMutex);
	
	ExInitializeResourceLite(&g_FolderResource);
	ExInitializeFastMutex(&g_DelayCloseMutex);

	InitializeListHead(&g_ProcessInofs);
	InitializeListHead(&g_FolderProtectList);

	InitializeListHead(&g_DiskObjects);

	InitializeListHead(&g_HideObjHead);
	InitializeListHead(&g_BackUp_FileInfoLists);
	InitializeListHead(&g_BackUpList);

	 
	InitializeListHead(&g_ProcessExclude);//在内存中记录了所有被打开的磁盘文件
	InitializeListHead(&g_DelayCloseList);//在内存中记录了所有被打开的磁盘文件

	ExInitializeResourceLite(&g_ProcessExcludeResource);
	//ExInitializeFastMutex(&g_ProcessExcludeFastMutex);

	ExInitializeFastMutex(&g_LogMutex);


	InitializeListHead(&g_RecyclePaths);

	ExInitializeFastMutex(&g_fastRecycle);
	

	KeInitializeSpinLock( &gCreateContextLock );
	KeInitializeSpinLock( &gCreateContextLock1 );


	InitializeListHead(&g_CreateContext);
	InitializeListHead(&g_CreateContext1);

	KeInitializeEvent(&g_EventCreateThread,NotificationEvent, FALSE);
	KeInitializeEvent(&g_EventCreateThread1,NotificationEvent, FALSE);
	g_CreateNum.QuadPart=0;
 
	ExInitializeFastMutex(&g_UsbMutex);
	InitializeListHead(&g_UsbSecureListHead);

	
	g_LogMaxCount = 500;
	g_LogEvent  = NULL;
	g_UsbDeviceSignal = NULL;
	szRootforCycle[0]=L'\0';
	g_bRegisterProtect = TRUE;
    //
    //  Initialize the naming environment
    //

	ExInitializeNPagedLookasideList( &PfpFileLockLookasideList,
									NULL,
										ExFreePool,
										0,
										sizeof(FILE_LOCK),
										FILESPY_LOGRECORD_TAG,
										100 );

    SpyInitNamingEnvironment();

  
    //
    //  If we are supposed to attach to all devices, register a callback
    //  with IoRegisterFsRegistrationChange so that we are called whenever a
    //  file system registers with the IO Manager.
    //
    //  VERSION NOTE:
    //
    //  On Windows XP and later this will also enumerate all existing file
    //  systems (except the RAW file systems).  On Windows 2000 this does not
    //  enumerate the file systems that were loaded before this filter was
    //  loaded.
    //

	 //if (gFileSpyAttachMode == FILESPY_ATTACH_ALL_VOLUMES)
	{

		 
        status = IoRegisterFsRegistrationChange( DriverObject,
                                                 SpyFsNotification );
		 

        if (!NT_SUCCESS( status )) 
		{

            DriverObject->FastIoDispatch = NULL;
            ExFreePoolWithTag( fastIoDispatch, FILESPY_POOL_TAG );
            IoDeleteDevice( gControlDeviceObject );
            return status;
        }
    }


    //
    //  Clear the initializing flag on the control device object since we
    //  have now successfully initialized everything.
    //
	//VirtualizerStart();
    ClearFlag( gControlDeviceObject->Flags, DO_DEVICE_INITIALIZING );
	//////////////////////////////////////////////////////////////////////////

	CacheManagerCallbacks.AcquireForLazyWrite  = &PfpAcquireFCBForLazyWrite;
	CacheManagerCallbacks.ReleaseFromLazyWrite = &PfpReleaseFCBFromLazyWrite;
	CacheManagerCallbacks.AcquireForReadAhead  = &PfpAcquireFCBForReadAhead;
	CacheManagerCallbacks.ReleaseFromReadAhead = &PfpReleaseFCBFromReadAhead;
	//VirtualizerEnd();
	//////////////////////////////////////////////////////////////////////////

	szBuf = (PWCHAR )ExAllocatePool_A(NonPagedPool,100);
	memset(szBuf,0, 100);
	wcscpy(szBuf,L"BitSecPLUG.dll");
	RtlInitUnicodeString(&g_p1,szBuf);
	szBuf = (PWCHAR )ExAllocatePool_A(NonPagedPool,100);
	memset(szBuf,0, 100);
	wcscpy(szBuf,L"CreateSelfExtractor.exe");
	RtlInitUnicodeString(&g_p2,szBuf);
	szBuf = (PWCHAR )ExAllocatePool_A(NonPagedPool,100);
	memset(szBuf,0, 100);
	wcscpy(szBuf,L"PfpDrv.sys");
	RtlInitUnicodeString(&g_p3,szBuf);
	szBuf = (PWCHAR )ExAllocatePool_A(NonPagedPool,100);
	memset(szBuf,0, 100);
	wcscpy(szBuf,L"SecurityGUI.exe");
	RtlInitUnicodeString(&g_p4,szBuf);
	szBuf = (PWCHAR )ExAllocatePool_A(NonPagedPool,100);
	memset(szBuf,0, 100);
	wcscpy(szBuf,L"ProcessFilter.CFG");
	RtlInitUnicodeString(&g_p5,szBuf);
	szBuf = (PWCHAR )ExAllocatePool_A(NonPagedPool,100);
	memset(szBuf,0, 100);
	wcscpy(szBuf,L"Keyfile.CFG");
	RtlInitUnicodeString(&g_p6,szBuf);
	

	// i don't care if this call sucess.
	
	
	g_szBackupDir  = NULL;
	
	memcpy(szPrivateKey,L"个人文档加密系统",16);

	aes_init();


	

	g_pKeyFileContent = NULL;
	g_keyFileLen	  = 0;

	memset(g_digestForUserPSW,0,16);
	memset(g_digestForKeyPSW,0,16);
	g_KeyFilePath		=  NULL;

	g_pKeyContent		= NULL;
	g_keyLen			= 0;
	g_ourProcessHandle	= INVALID_HANDLE_VALUE;

	g_bInitialized      = FALSE;

	g_bProtectSySself	= TRUE;
	g_bEncrypteUDISK	= FALSE;
	//驱动起来的时候，就针对所有的硬盘的分区全部挂接
	
	g_DriverDir =  NULL;
	g_ConfigFile = INVALID_HANDLE_VALUE;
	
	g_RegistryPath.Buffer   =ExAllocatePool_A(NonPagedPool,RegistryPath->MaximumLength);
	if(g_RegistryPath.Buffer   )
	{
		g_RegistryPath.Length= RegistryPath->Length;
		g_RegistryPath.MaximumLength= RegistryPath->MaximumLength;
		memcpy(g_RegistryPath.Buffer,RegistryPath->Buffer,RegistryPath->MaximumLength);
		IoRegisterDriverReinitialization(DriverObject,PfpInitDriverAtStartUp,&g_RegistryPath);
		//IoRegisterBootDriverReinitialization(DriverObject,PfpInitDriverAtStartUp,&g_RegistryPath);
	}
	
	
	return STATUS_SUCCESS;
}

NTSTATUS 
PfpInitDriverAtStartUp( IN PDRIVER_OBJECT  DriverObject, 
					   IN PVOID  Context, 
					   IN ULONG  Count 
/*UNICODE_STRING pRegistryKeyPath*/)
{
	
	UNICODE_STRING*		pRegistryKeyPath =(UNICODE_STRING*) Context;
	OBJECT_ATTRIBUTES	Objs;
	UNICODE_STRING		strKeyName;
	HANDLE	hkeyPfpdrv	= INVALID_HANDLE_VALUE;
	ULONG   nReturned	= 0;
	PVOID	pBuffer		= NULL;
	HANDLE	hCreatethread =INVALID_HANDLE_VALUE;
	WCHAR	szConfigFile[] = L"ProcessFilter.CFG";
	WCHAR	Letter[] = L"C:\\";
	OBJECT_ATTRIBUTES			ObjectAttributes;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(Count);
	
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	PsCreateSystemThread(&hCreatethread ,
		THREAD_ALL_ACCESS ,
		&ObjectAttributes,
		NULL,
		NULL,
		PfpCreateFileWorker,
		NULL); 
	ZwClose(hCreatethread );

	PsCreateSystemThread(&hCreatethread ,
		THREAD_ALL_ACCESS ,
		&ObjectAttributes,
		NULL,
		NULL,
		PfpCreateFileWorker1,
		NULL); 
	ZwClose(hCreatethread );

	PsCreateSystemThread(&hCreatethread ,
		THREAD_ALL_ACCESS ,
		&ObjectAttributes,
		NULL,
		NULL,
		PfpSaveFileWorker,
		NULL); 
	ZwClose(hCreatethread );
	
	KeInitializeEvent( &g_EventSaveFile,NotificationEvent, FALSE );

	for(;Letter[0]<=L'Z'; Letter[0]++)
	{
		SpyStartLoggingDevice(Letter);
	}
	 


	PsSetCreateProcessNotifyRoutine(pfpCreateProcessNotify,FALSE);
	 

	RtlInitUnicodeString(&strKeyName,L"ImagePath");
	InitializeObjectAttributes(&Objs,pRegistryKeyPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL );

	ZwOpenKey(&hkeyPfpdrv,GENERIC_READ,&Objs);




	if(hkeyPfpdrv!= INVALID_HANDLE_VALUE)
	{
		ZwQueryValueKey(hkeyPfpdrv,&strKeyName, KeyValueFullInformation,NULL,0,&nReturned );
		pBuffer  = ExAllocatePool(PagedPool,nReturned);
		if( pBuffer && STATUS_SUCCESS == ZwQueryValueKey(hkeyPfpdrv,&strKeyName, KeyValueFullInformation,pBuffer,nReturned,&nReturned ))
		{
			PKEY_VALUE_FULL_INFORMATION pKeyValue = (PKEY_VALUE_FULL_INFORMATION)pBuffer;
			if(pKeyValue ->DataLength>0)
			{
				LONG nIndex = 0;
				UNICODE_STRING ConfigFile;
				OBJECT_ATTRIBUTES objectAttributes;
				PWCHAR pValue =(PWCHAR) ExAllocatePool(PagedPool,pKeyValue->DataLength+(ULONG)(1+wcslen(szConfigFile))*sizeof(WCHAR));
				if(pValue )
				{
					memcpy(pValue,(((PUCHAR)pKeyValue)+pKeyValue->DataOffset),pKeyValue->DataLength);
					pValue[nIndex = (pKeyValue->DataLength/sizeof(WCHAR))]=L'\0';
					nIndex --;	
					while(nIndex >=0 && pValue[nIndex]!=L'\\')nIndex--;
					if(nIndex >0)
					{
						NTSTATUS		ntstatus;
						IO_STATUS_BLOCK iostatus;
					 
						nIndex ++;
						wcscpy(&pValue[nIndex],L"ProcessFilter.CFG");
						//记录下面 驱动所在的路径
						{
							g_DriverDir = (PWCHAR) ExAllocatePool(PagedPool,(nIndex+1+30)*sizeof(WCHAR));
							memset(g_DriverDir,0,(nIndex+1+30)*sizeof(WCHAR));
							memcpy(g_DriverDir,pValue,sizeof(WCHAR)*nIndex);
						}

						RtlInitUnicodeString(&ConfigFile,pValue);
						InitializeObjectAttributes( &objectAttributes,
													&ConfigFile,
													OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
													NULL,
													NULL );

						ntstatus = ZwCreateFile( &g_ConfigFile,
												SYNCHRONIZE|FILE_READ_DATA|FILE_WRITE_DATA,
												&objectAttributes,
												&iostatus,
												NULL,
												FILE_ATTRIBUTE_NORMAL,
												0,
												FILE_OPEN_IF,
												FILE_SYNCHRONOUS_IO_NONALERT|FILE_WRITE_THROUGH,
												NULL,
												0 );

						if(g_ConfigFile != INVALID_HANDLE_VALUE)
						{
							FsRtlEnterFileSystem();

							PfpInitSystemSettings(g_ConfigFile );
							FsRtlExitFileSystem();
							g_bInitialized = TRUE;
							ZwClose(g_ConfigFile);
						}
					}
					ExFreePool(pValue);
				}
			}

		}
		if(pBuffer)
		{
			ExFreePool(pBuffer  );
		}
		ZwClose(hkeyPfpdrv);
	}
	 
	wcscpy(g_szRegisterKey,L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\PfpDrv");
	g_nLenOfKey = wcslen(g_szRegisterKey);

	wcscpy(g_szRegisterKeyMin,L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot\\Minimal\\PfpDrv.sys");
	g_nLenOfKeyMin = wcslen(g_szRegisterKeyMin);

	wcscpy(g_szRegisterKeyNetwork,L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot\\Network\\PfpDrv.sys");
	g_nLenOfKeyNetwork = wcslen(g_szRegisterKeyNetwork);
	
	g_nLenOfKeyDir = g_nLenOfKey -7;

	memset(&g_RegistrContext,0,sizeof(g_RegistrContext));
	CmRegisterCallback(RegistryCallback, &g_RegistrContext, &g_RegistrContext.registryCallbackCookie);
	return STATUS_SUCCESS;
}
VOID
SpyFsNotification (
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN FsActive
    )
/*++

Routine Description:

    This routine is invoked whenever a file system has either registered or
    unregistered itself as an active file system.

    For the former case, this routine creates a device object and attaches it
    to the specified file system's device object.  This allows this driver
    to filter all requests to that file system.

    For the latter case, this file system's device object is located,
    detached, and deleted.  This removes this file system as a filter for
    the specified file system.

Arguments:

    DeviceObject - Pointer to the file system's device object.

    FsActive - Boolean indicating whether the file system has registered
        (TRUE) or unregistered (FALSE) itself as an active file system.

Return Value:

    None.

--*/
{
    PNAME_CONTROL devName;

    PAGED_CODE();

    //
    //  The DeviceObject passed in is always the base device object at this
    //  point because it is the file system's control device object.  We can
    //  just query this object's name directly.
    //

    devName = NLGetAndAllocateObjectName( DeviceObject,
                                          &gFileSpyNameBufferLookasideList );

    if (devName == NULL) 
	{
        return;
    }

    if (FsActive) 
	{

        SpyAttachToFileSystemDevice( DeviceObject, devName );

    } else 
	{

        SpyDetachFromFileSystemDevice( DeviceObject );
    }

    //
    //  We're done with name (SpyAttachToFileSystemDevice copies the name to
    //  the device extension) so free it.
    //

    NLFreeNameControl( devName, &gFileSpyNameBufferLookasideList );
}


NTSTATUS
SpyPassThrough (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
/*++

Routine Description:

    This routine is the main dispatch routine for the general purpose file
    system driver.  It simply passes requests onto the next driver in the
    stack, which is presumably a disk file system, while logging any
    relevant information if logging is turned on for this DeviceObject.

Arguments:

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

    Irp - Pointer to the request packet representing the I/O request.

Return Value:

    The function value is the status of the operation.

Note:

    This routine passes the I/O request through to the next driver
    *without* removing itself from the stack (like sfilter) since it could
    want to see the result of this I/O request.

    To remain in the stack, we have to copy the caller's parameters to the
    next stack location.  Note that we do not want to copy the caller's I/O
    completion routine into the next stack location, or the caller's routine
    will get invoked twice.  This is why we NULL out the Completion routine.
    If we are logging this device, we set our own Completion routine.

--*/
{
    PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
	
    ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));

    
    IoSkipCurrentIrpStackLocation( Irp );
    
	return  IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject,	Irp );
}

NTSTATUS
SpyDispatch (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
)
/*++

Routine Description:

    This function completes all requests on the gControlDeviceObject
    (FileSpy's device object) and passes all other requests on to the
    SpyPassThrough function.

Arguments:

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

    Irp - Pointer to the request packet representing the I/O request.

Return Value:

    If this is a request on the gControlDeviceObject, STATUS_SUCCESS
    will be returned unless the device is already attached.  In that case,
    STATUS_DEVICE_ALREADY_ATTACHED is returned.

    If this is a request on a device other than the gControlDeviceObject,
    the function will return the value of SpyPassThrough().

--*/
{
    NTSTATUS			status = STATUS_SUCCESS;
    PIO_STACK_LOCATION	irpStack = IoGetCurrentIrpStackLocation( Irp );
	PFILE_OBJECT		pFile = irpStack ->FileObject;
	PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;	

	WCHAR			FileExt[256]	= {0};
	LONG			nLength			= 256;
	PDEVICE_OBJECT	pNextDevice		= NULL;

	BOOLEAN			bForMyFILEOBJECT = FALSE;
	ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));
    //
    //  File systems should NEVER receive power IRPs
    //

    ASSERT(irpStack->MajorFunction != IRP_MJ_POWER);

    if (DeviceObject == gControlDeviceObject) 
	{


        Irp->IoStatus.Information = 0;


        switch (irpStack->MajorFunction) 
		{

            case IRP_MJ_DEVICE_CONTROL:

                //
                //  This is a private device control IRP for our control device.
                //  Pass the parameter information along to the common routine
                //  use to service these requests.
                //
                //  All of FileSpy's IOCTLs are buffered, therefore both the
                //  input and output buffer are represented by the
                //  Irp->AssociatedIrp.SystemBuffer.
                //

                status = SpyCommonDeviceIoControl( Irp->AssociatedIrp.SystemBuffer,
                         irpStack->Parameters.DeviceIoControl.InputBufferLength,
                         Irp->AssociatedIrp.SystemBuffer,
                         irpStack->Parameters.DeviceIoControl.OutputBufferLength,
                         irpStack->Parameters.DeviceIoControl.IoControlCode,
                         &Irp->IoStatus );
                break;

            case IRP_MJ_CLEANUP:

                //
                //  This is the cleanup that we will see when all references
                //  to a handle opened to FileSpy's control device object are
                //  cleaned up.  We don't have to do anything here since we
                //  wait until the actual IRP_MJ_CLOSE to clean up the name
                //  cache.  Just complete the IRP successfully.
                //

                status = STATUS_SUCCESS;

                break;

            default:

                status = STATUS_INVALID_DEVICE_REQUEST;
        }

        Irp->IoStatus.Status = status;

        //
        //  We have completed all processing for this IRP, so tell the
        //  I/O Manager.  This IRP will not be passed any further down
        //  the stack since no drivers below FileSpy care about this
        //  I/O operation that was directed to FileSpy.
        //

        IoCompleteRequest( Irp, IO_DISK_INCREMENT );
        return status;
    }
	FsRtlEnterFileSystem();
	
	if(devExt->bShadow)	
	{
		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)devExt->pRealDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject;	
		goto PASSTHROUGH;
	}
	else
	{
		PDISKFILEOBJECT		pDiskFileObject = NULL;
		
		PFILE_OBJECT		pFileObject;
		PPfpFCB				pFcb;
		//PERESOURCE			pDeviceResource= NULL;
		pNextDevice =		devExt->NLExtHeader.AttachedToDeviceObject;
		
		pFileObject = irpStack ->FileObject;
		if(!PfpFileObjectHasOurFCB(pFileObject))
			goto PASSTHROUGH;

		pFcb = (PPfpFCB)pFileObject->FsContext;

		bForMyFILEOBJECT  = TRUE;
// 		pDeviceResource = PfpGetDeviceResource((PDEVICE_OBJECT)DeviceObject);
// 
// 		if(pDeviceResource== NULL)
// 		{
// 			goto PASSTHROUGH;
// 		}	

// 		switch(irpStack->MajorFunction)
// 		{
// 		case IRP_MJ_QUERY_VOLUME_INFORMATION:
// 		case IRP_MJ_SET_VOLUME_INFORMATION:
// 			
				
			//ExAcquireResourceSharedLite(pDeviceResource,TRUE);
			
			ASSERT(pFcb->pDiskFileObject);
			pDiskFileObject		 = pFcb->pDiskFileObject;
			
			irpStack->FileObject = pDiskFileObject->pDiskFileObjectWriteThrough;
			if(irpStack->FileObject == NULL)
			{
// 				if(pDeviceResource)
// 				{
// 					ExReleaseResource(pDeviceResource);
// 				}
				
				FsRtlExitFileSystem();
				Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
				Irp->IoStatus.Information = 0;

				IoCompleteRequest( Irp, IO_DISK_INCREMENT );

				return STATUS_INVALID_DEVICE_REQUEST;
			}
			//
			// This is a regular FSCTL that we need to let the filters see
			// Just do the callbacks for all the filters & passthrough
			//

			IoCopyCurrentIrpStackLocationToNext( Irp );
			IoSetCompletionRoutine(Irp,PfpFsControlCompletion,
									&pFileObject,
									TRUE,
									TRUE,
									TRUE );

			status = IoCallDriver(devExt->NLExtHeader.AttachedToDeviceObject,Irp);
			
// 			if(pDeviceResource)
// 			{
// 				ExReleaseResource(pDeviceResource);
// 			}

			
// 			break;
// 		
// 		default:
// 			break;
// 		}

	}

PASSTHROUGH:
	
 

	if(bForMyFILEOBJECT)
	{
		FsRtlExitFileSystem();
		return status;
	}
	else
	{
		FsRtlExitFileSystem();
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(pNextDevice,Irp);
	}
	
    
}


//
//
//



NTSTATUS
SpyFsControl (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    )

/*++

Routine Description:

    This routine is invoked whenever an I/O Request Packet (IRP) w/a major
    function code of IRP_MJ_FILE_SYSTEM_CONTROL is encountered.  For most
    IRPs of this type, the packet is simply passed through.  However, for
    some requests, special processing is required.

Arguments:

    DeviceObject - Pointer to the device object for this driver.

    Irp - Pointer to the request packet representing the I/O request.

Return Value:

    The function value is the status of the operation.

--*/

{
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp );
	

	PFILE_OBJECT				pFileObject_Disk = NULL;
	PFILE_OBJECT                pTemp = NULL;
	 PFILESPY_DEVICE_EXTENSION devExt;
	NTSTATUS					Status=STATUS_SUCCESS;
	PDISKFILEOBJECT				pDiskFileObject = NULL;
	PPfpFCB						pFcb;
	//PERESOURCE					pDeviceResource= NULL;
	PFILE_OBJECT				pFileObject;
    PAGED_CODE();

    //
    //  If this is for our control device object, fail the operation
    //

    if (gControlDeviceObject == DeviceObject) 
	{
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest( Irp, IO_DISK_INCREMENT );

        return STATUS_INVALID_DEVICE_REQUEST;
    }

	FsRtlEnterFileSystem();
    ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));
	 devExt = DeviceObject->DeviceExtension;
    //
    //  Process the minor function code.
    //
	 

	 switch (pIrpSp->MinorFunction)
	 {

	 case IRP_MN_MOUNT_VOLUME:

		 Status = SpyFsControlMountVolume ( DeviceObject, Irp );
		 FsRtlExitFileSystem();
		 return Status;

	 case IRP_MN_LOAD_FILE_SYSTEM:

		 Status = SpyFsControlLoadFileSystem ( DeviceObject, Irp );
		 FsRtlExitFileSystem();
		 return Status;
	 default:
		 break;
	 }
	
	 pFileObject = pIrpSp->FileObject;
	 if(!PfpFileObjectHasOurFCB(pFileObject))
		 goto PASSTHROUGH;

// 	 pDeviceResource = PfpGetDeviceResource((PDEVICE_OBJECT)DeviceObject);
// 
// 	 if(pDeviceResource== NULL)
// 	 {
// 		 ASSERT(0);
// 		 goto PASSTHROUGH;
// 	 }


	// ExAcquireResourceExclusiveLite(pDeviceResource,TRUE);

	 pFcb = (PPfpFCB)pFileObject->FsContext;

	 ASSERT(pFcb->pDiskFileObject);
	 pDiskFileObject = pFcb->pDiskFileObject;
	
  	 pTemp  = pIrpSp->FileObject;
	 pIrpSp->FileObject = pDiskFileObject->pDiskFileObjectWriteThrough;
	
	
    //
    // This is a regular FSCTL that we need to let the filters see
    // Just do the callbacks for all the filters & passthrough
    //

	IoCopyCurrentIrpStackLocationToNext( Irp );
	IoSetCompletionRoutine(Irp,PfpFsControlCompletion,
							&pTemp,
							TRUE,
							TRUE,
							TRUE );

	Status = IoCallDriver(devExt->NLExtHeader.AttachedToDeviceObject,Irp);
// 	if(pDeviceResource)
// 	{
// 		ExReleaseResource(pDeviceResource);
// 	}
	 FsRtlExitFileSystem();
	
 	return Status;

PASSTHROUGH:	

	FsRtlExitFileSystem();

 	Status = SpyPassThrough(DeviceObject,Irp);
	

	return Status;
}


NTSTATUS
PfpFsControlCompletion (
					IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context 
					)
{
	PIO_STACK_LOCATION pstack=IoGetCurrentIrpStackLocation(Irp);
	UNREFERENCED_PARAMETER( DeviceObject );
	
	
	pstack->FileObject = *(PFILE_OBJECT*)Context;
	
	
	if(Irp->PendingReturned)
	{
		IoMarkIrpPending( Irp );
	}

	return STATUS_SUCCESS;
}
NTSTATUS
SpyFsControlCompletion (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PVOID Context
    )

/*++

Routine Description:

    This routine is invoked for the completion of a mount/LoadFS request.  This
    will load the IRP and then signal the waiting dispatch routine.

Arguments:

    DeviceObject - Pointer to this driver's device object that was attached to
            the file system device object

    Irp - Pointer to the IRP that was just completed.

    Context - Pointer to the device object allocated during the down path so
            we wouldn't have to deal with errors here.

Return Value:

    The return value is always STATUS_SUCCESS.

--*/

{
    

    ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));
    UNREFERENCED_PARAMETER( DeviceObject );
	UNREFERENCED_PARAMETER(Irp);
    //
    //  Log the completion (if we need to)
    //

    
#if WINVER >= 0x0501
    if (IS_WINDOWSXP_OR_LATER()) {

        PKEVENT event = &((PSPY_COMPLETION_CONTEXT_WXP_OR_LATER)Context)->WaitEvent;

        //
        //  Wake up the dispatch routine
        //

        KeSetEvent(event, IO_NO_INCREMENT, FALSE);

    } else {
#endif

        //
        //  For Windows 2000, if we are not at passive level, we should
        //  queue this work to a worker thread using the workitem that is in
        //  Context.
        //

        if (KeGetCurrentIrql() > PASSIVE_LEVEL) {

            //
            //  We are not at passive level, but we need to be to do our work,
            //  so queue off to the worker thread.

            ExQueueWorkItem( &(((PSPY_COMPLETION_CONTEXT_W2K)Context)->WorkItem),
                             DelayedWorkQueue );

        } else {

            PSPY_COMPLETION_CONTEXT_W2K completionContext = Context;

            //
            //  We are already at passive level, so we will just call our
            //  worker routine directly.
            //

            (completionContext->WorkItem.WorkerRoutine)(completionContext->WorkItem.Parameter);
        }

#if WINVER >= 0x0501
    }
#endif

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
SpyFsControlMountVolume (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    )

/*++

Routine Description:

    This processes a MOUNT VOLUME request

Arguments:

    DeviceObject - Pointer to the device object for this driver.

    Irp - Pointer to the request packet representing the I/O request.

Return Value:

    The function value is the status of the operation.

--*/

{
    PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION pIrpSp = IoGetCurrentIrpStackLocation( Irp );
    PDEVICE_OBJECT newDeviceObject;
    PFILESPY_DEVICE_EXTENSION newDevExt;
    NTSTATUS status;
    
    PSPY_COMPLETION_CONTEXT_W2K completionContext;
    PNAME_CONTROL newDeviceName;

	//////////////////////////////////////////////////////////////////////////
	
	

	//////////////////////////////////////////////////////////////////////////
    PAGED_CODE();
    ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));

    //
    //  We should only see these FS_CTLs to control device objects.
    //

    ASSERT(!FlagOn(devExt->Flags,IsVolumeDeviceObject));

    //
    //  This is a mount request.  Create a device object that can be
    //  attached to the file system's volume device object if this request
    //  is successful.  We allocate this memory now since we can not return
    //  an error after the completion routine.
    //
    //  Since the device object we are going to attach to has not yet been
    //  created (it is created by the base file system) we are going to use
    //  the type of the file system control device object.  We are assuming
    //  that the file system control device object will have the same type
    //  as the volume device objects associated with it.
    //

    status = IoCreateDevice( gFileSpyDriverObject,
                             sizeof( FILESPY_DEVICE_EXTENSION ),
                             NULL,
                             DeviceObject->DeviceType,
                             0,
                             FALSE,
                             &newDeviceObject );

    if (!NT_SUCCESS( status )) 
	{
        return SpyPassThrough( DeviceObject, Irp );
    }

	newDevExt = newDeviceObject->DeviceExtension;
    //
    //  Initialize the name lookup device extension header
    //
    //  We need to save the RealDevice object pointed to by the VPB
    //  parameter because this VPB may be changed by the underlying
    //  file system.  Both FAT and CDFS may change the VPB address if
    //  the volume being mounted is one they recognize from a previous
    //  mount.
    //
    //

    NLInitDeviceExtensionHeader( &newDevExt->NLExtHeader,
                                 newDeviceObject,
                                 pIrpSp->Parameters.MountVolume.Vpb->RealDevice );

    newDevExt->Flags = 0;

    RtlInitEmptyUnicodeString( &newDevExt->UserNames, NULL, 0 );


    //
    //  Get the name of this device
    //

#   define MVInsufResMsg "FileSpy!SpyFsControlMountVolume: Error getting device name, insufficient resources, status=%08x\n"


    newDeviceName = NLGetAndAllocateObjectName( newDevExt->NLExtHeader.StorageStackDeviceObject,
                                                &gFileSpyNameBufferLookasideList );

    if (newDeviceName == NULL) {

        //
        //  Can't allocate space for retrieving the device name. Skip device.
        //

       // SPY_LOG_PRINT( SPYDEBUG_ERROR,
        //               (MVInsufResMsg,
       //                 status) );

        IoDeleteDevice( newDeviceObject );
        return SpyPassThrough( DeviceObject, Irp );
    }

    //
    //  Save the name in our device object extension
    //

    status = NLAllocateAndCopyUnicodeString( &newDevExt->NLExtHeader.DeviceName,
                                             &newDeviceName->Name,
                                             FILESPY_DEVNAME_TAG );

    //
    //  Release name control
    //

    NLFreeNameControl( newDeviceName, &gFileSpyNameBufferLookasideList );

    //
    //  If we couldn't copy the name we are low on resources, quit now
    //

    if (!NT_SUCCESS(status)) 
	{
        IoDeleteDevice( newDeviceObject);
        return SpyPassThrough( DeviceObject, Irp );
    }

    //
    //  Since we have our own private completion routine we need to
    //  do our own logging of this operation, do it now.
    //

 
    //
    //  Send the IRP to the legacy filters.  Note that the IRP we are sending
    //  down is for our CDO, not the new VDO that we have been passing to
    //  the mini-filters.
    //

    //
    //  VERSION NOTE:
    //
    //  On Windows 2000, we cannot simply synchronize back to the dispatch
    //  routine to do our post-mount processing.  We need to do this work at
    //  passive level, so we will queue that work to a worker thread from
    //  the completion routine.
    //
    //  For Windows XP and later, we can safely synchronize back to the dispatch
    //  routine.  The code below shows both methods.  Admittedly, the code
    //  would be simplified if you chose to only use one method or the other,
    //  but you should be able to easily adapt this for your needs.
    //

#if WINVER >= 0x0501
    if (IS_WINDOWSXP_OR_LATER()) 
	{

        SPY_COMPLETION_CONTEXT_WXP_OR_LATER lCompletionContext;

        IoCopyCurrentIrpStackLocationToNext ( Irp );

       
        KeInitializeEvent( &lCompletionContext.WaitEvent,
                           NotificationEvent,
                           FALSE );

        IoSetCompletionRoutine( Irp,
                                SpyFsControlCompletion,
                                &lCompletionContext,     //context parameter
                                TRUE,
                                TRUE,
                                TRUE );

        status = IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject, Irp );

        //
        //  Wait for the operation to complete
        //

        if (STATUS_PENDING == status) 
		{

            status = KeWaitForSingleObject( &lCompletionContext.WaitEvent,
                                            Executive,
                                            KernelMode,
                                            FALSE,
                                            NULL );
            ASSERT(STATUS_SUCCESS == status);
        }

        //
        //  Verify the IoCompleteRequest was called
        //

        ASSERT(KeReadStateEvent(&lCompletionContext.WaitEvent) ||
               !NT_SUCCESS(Irp->IoStatus.Status));

        status = SpyFsControlMountVolumeComplete( DeviceObject,
                                                  Irp,
                                                  newDeviceObject );

    } 
	else 
	{
#endif
        completionContext = ExAllocatePoolWithTag( NonPagedPool,
                                                   sizeof( SPY_COMPLETION_CONTEXT_W2K ),
                                                   FILESPY_CONTEXT_TAG );

        if (completionContext == NULL)
		{

            IoSkipCurrentIrpStackLocation( Irp );

            status = IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject, Irp );

        } else 
		{

           

            ExInitializeWorkItem( &completionContext->WorkItem,
                                  SpyFsControlMountVolumeCompleteWorker,
                                  completionContext );

            completionContext->DeviceObject = DeviceObject,
            completionContext->Irp = Irp;
            completionContext->NewDeviceObject = newDeviceObject;

            IoCopyCurrentIrpStackLocationToNext ( Irp );

            IoSetCompletionRoutine( Irp,
                                    SpyFsControlCompletion,
                                    completionContext,     //context parameter
                                    TRUE,
                                    TRUE,
                                    TRUE );

            status = IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject, Irp );
        }
#if WINVER >= 0x0501
    }
#endif

    return status;
}

VOID
SpyFsControlMountVolumeCompleteWorker (
    __in PSPY_COMPLETION_CONTEXT_W2K Context
    )
/*++

Routine Description:

    The worker thread routine that will call our common routine to do the
    post-MountVolume work.

Arguments:

    Context - The context passed to this worker thread.

Return Value:

    None.

--*/
{
    SpyFsControlMountVolumeComplete( Context->DeviceObject,
                                     Context->Irp,
                                     Context->NewDeviceObject );

    ExFreePoolWithTag( Context, FILESPY_CONTEXT_TAG );
}

NTSTATUS
SpyFsControlMountVolumeComplete (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PDEVICE_OBJECT NewDeviceObject
    )
/*++

Routine Description:

    This does the post-Mount work and must be done at PASSIVE_LEVEL.

Arguments:

    DeviceObject - The device object for this operation,

    Irp - The IRP for this operation that we will complete once we are finished
        with it.

Return Value:

    Returns the status of the mount operation.

--*/
{
    PVPB vpb;
    PFILESPY_DEVICE_EXTENSION newDevExt = NewDeviceObject->DeviceExtension;
    PDEVICE_OBJECT attachedDeviceObject;
    NTSTATUS status;
    BOOLEAN justAttached = FALSE;
	UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    //
    //  Get the correct VPB from the real device object saved in our
    //  device extension.  We do this because the VPB in the IRP stack
    //  may not be the correct VPB when we get here.  The underlying
    //  file system may change VPBs if it detects a volume it has
    //  mounted previously.
    //

    vpb = newDevExt->NLExtHeader.StorageStackDeviceObject->Vpb;

    //
    //  See if the mount was successful.
    //

    if (NT_SUCCESS( Irp->IoStatus.Status )) 
	{

        //
        //  Acquire lock so we can atomically test if we area already attached
        //  and if not, then attach.  This prevents a double attach race
        //  condition.
        //

        ExAcquireFastMutex( &gSpyAttachLock );

        //
        //  The mount succeeded.  If we are not already attached, attach to the
        //  device object.  Note: one reason we could already be attached is
        //  if the underlying file system revived a previous mount.
        //

        if (!SpyIsAttachedToDevice( vpb->DeviceObject,
            &attachedDeviceObject ))
		{

            //
            //  Attach to the new mounted volume.  The correct file system
            //  device object that was just mounted is pointed to by the VPB.
            //

            status = SpyAttachToMountedDevice( vpb->DeviceObject,
                                               NewDeviceObject );
            if (NT_SUCCESS( status )) 
			{

                justAttached = TRUE;

                //
                //  We completed initialization of this device object, so now
                //  clear the initializing flag.
                //

                ClearFlag( NewDeviceObject->Flags, DO_DEVICE_INITIALIZING );

            } else 
			{

                //
                //  The attachment failed, cleanup.  Since we are in the
                //  post-mount phase, we can not fail this operation.
                //  We simply won't be attached.  The only reason this should
                //  ever happen at this point is if somebody already started
                //  dismounting the volume therefore not attaching should
                //  not be a problem.
                //

                SpyCleanupMountedDevice( NewDeviceObject );
                IoDeleteDevice( NewDeviceObject );
            }

            ASSERT( NULL == attachedDeviceObject );

        } else 
		{

            //
            //  We were already attached, cleanup device object
            //
            SpyCleanupMountedDevice( NewDeviceObject );
            IoDeleteDevice( NewDeviceObject );

            //
            //  Remove the reference added by SpyIsAttachedToDevice.
            //

            ObDereferenceObject( attachedDeviceObject );
        }

        //
        //  Release the lock
        //

        ExReleaseFastMutex( &gSpyAttachLock );

        //
        //  If we just attached, then get DOS device name.  Otherwise, we
        //  were already attached and NewDeviceObject is not valid.
        //  We could not do this above because a mutex was held.
        //

        if (justAttached &&
            (newDevExt->NLExtHeader.StorageStackDeviceObject != NULL)) 
		{

            NLGetDosDeviceName( NewDeviceObject,
                                &newDevExt->NLExtHeader );

			newDevExt->bUsbDevice = ((GetStorageDeviceBusType(newDevExt->NLExtHeader.StorageStackDeviceObject->Vpb->RealDevice,&newDevExt->pszUsbDiskSeriNUM,&newDevExt->nLenExcludeTermiter)==7)?TRUE:FALSE);
			if(newDevExt->bUsbDevice)
			{
				//GetUsbStorageDeviceID(&newDevExt->pszUsbDiskSeriNUM ,,newDevExt->NLExtHeader.StorageStackDeviceObject->Vpb->RealDevice);
		PfpInitUsbDeviceWithSecure(NewDeviceObject);
			}
			PfpCreateShadowDeviceForDevice(NewDeviceObject);
			
			
			newDevExt ->pVirtualRootDir = PfpCreateVirtualDirObject(L"\\",NULL);
		
			
        } else 
		{

            newDevExt->NLExtHeader.DosName.Length = 0;
        }


    } else
	 {

         //
        //  The mount request failed.  Cleanup and delete the device
        //  object we created
        //

        SpyCleanupMountedDevice( NewDeviceObject );
        IoDeleteDevice( NewDeviceObject );
    }

    //
    //  Continue processing the operation
    //

    status = Irp->IoStatus.Status;

    IoCompleteRequest( Irp, IO_DISK_INCREMENT );

    return status;
}


NTSTATUS
SpyFsControlLoadFileSystem (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    )

/*++

Routine Description:

    This routine is invoked whenever an I/O Request Packet (IRP) w/a major
    function code of IRP_MJ_FILE_SYSTEM_CONTROL is encountered.  For most
    IRPs of this type, the packet is simply passed through.  However, for
    some requests, special processing is required.

Arguments:

    DeviceObject - Pointer to the device object for this driver.

    Irp - Pointer to the request packet representing the I/O request.

Return Value:

    The function value is the status of the operation.

--*/

{
    PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
    NTSTATUS status;
    PSPY_COMPLETION_CONTEXT_W2K completionContext;
    

    PAGED_CODE();
    ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));

    //
    //  This is a "load file system" request being sent to a file system
    //  recognizer device object.  This IRP_MN code is only sent to
    //  file system recognizers.
    //
    //  NOTE:  Since we no longer are attaching to the standard Microsoft file
    //         system recognizers we will normally never execute this code.
    //         However, there might be 3rd party file systems which have their
    //         own recognizer which may still trigger this IRP.
    //

    //
    //  VERSION NOTE:
    //
    //  On Windows 2000, we cannot simply synchronize back to the dispatch
    //  routine to do our post-load filesystem processing.  We need to do
    //  this work at passive level, so we will queue that work to a worker
    //  thread from the completion routine.
    //
    //  For Windows XP and later, we can safely synchronize back to the dispatch
    //  routine.  The code below shows both methods.  Admittedly, the code
    //  would be simplified if you chose to only use one method or the other,
    //  but you should be able to easily adapt this for your needs.
    //

#if WINVER >= 0x0501

    if (IS_WINDOWSXP_OR_LATER()) {

        SPY_COMPLETION_CONTEXT_WXP_OR_LATER lCompletionContext;

        IoCopyCurrentIrpStackLocationToNext( Irp );

       
        KeInitializeEvent( &lCompletionContext.WaitEvent,
                           NotificationEvent,
                           FALSE );

        IoSetCompletionRoutine(
					Irp,
					SpyFsControlCompletion,
					&lCompletionContext,
					TRUE,
					TRUE,
					TRUE );

        //
        //  Detach from the file system recognizer device object.
        //

        IoDetachDevice( devExt->NLExtHeader.AttachedToDeviceObject );

        //
        //  Call the driver
        //

        status = IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject, Irp );

        //
        //  Wait for the completion routine to be called
        //

        if (STATUS_PENDING == status) 
		{

            status = KeWaitForSingleObject( &lCompletionContext.WaitEvent,
                                            Executive,
                                            KernelMode,
                                            FALSE,
                                            NULL );

            ASSERT(STATUS_SUCCESS == status);
        }

        ASSERT(KeReadStateEvent(&lCompletionContext.WaitEvent) ||
               !NT_SUCCESS(Irp->IoStatus.Status));

        status = SpyFsControlLoadFileSystemComplete( DeviceObject, Irp );

    } else
	{
#endif
        completionContext = ExAllocatePoolWithTag( NonPagedPool,
                                                   sizeof( SPY_COMPLETION_CONTEXT_W2K ),
                                                   FILESPY_CONTEXT_TAG );

        if (completionContext == NULL) 
		{

            IoSkipCurrentIrpStackLocation( Irp );
            status = IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject, Irp );

        } else
		{

            
            ExInitializeWorkItem( &completionContext->WorkItem,
                                  SpyFsControlLoadFileSystemCompleteWorker,
                                  completionContext );

            completionContext->DeviceObject = DeviceObject;
            completionContext->Irp = Irp;
            completionContext->NewDeviceObject = NULL;

            IoSetCompletionRoutine(
                Irp,
                SpyFsControlCompletion,
                &completionContext,
                TRUE,
                TRUE,
                TRUE );

            //
            //  Detach from the file system recognizer device object.
            //

            IoDetachDevice( devExt->NLExtHeader.AttachedToDeviceObject );

            //
            //  Call the driver
            //

            status = IoCallDriver( devExt->NLExtHeader.AttachedToDeviceObject, Irp );
        }
#if WINVER >= 0x0501
    }
#endif

    return status;
}

VOID
SpyFsControlLoadFileSystemCompleteWorker (
    __in PSPY_COMPLETION_CONTEXT_W2K Context
    )
/*++

Routine Description:

    The worker thread routine that will call our common routine to do the
    post-LoadFileSystem work.

Arguments:

    Context - The context passed to this worker thread.

Return Value:

    None.

--*/
{
    SpyFsControlLoadFileSystemComplete( Context->DeviceObject,
                                        Context->Irp );

    ExFreePoolWithTag( Context, FILESPY_CONTEXT_TAG );
}

NTSTATUS
SpyFsControlLoadFileSystemComplete (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    )
/*++

Routine Description:

    This does the post-LoadFileSystem work and must be done at PASSIVE_LEVEL.

Arguments:

    DeviceObject - The device object for this operation,

    Irp - The IRP for this operation that we will complete once we are finished
        with it.

Return Value:

    Returns the status of the load file system operation.

--*/
{
    PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
    NTSTATUS status;

    PAGED_CODE();

    //
    //  Display the name if requested
    //

    //
    //  Check status of the operation
    //

    if (!NT_SUCCESS( Irp->IoStatus.Status ) &&
        (Irp->IoStatus.Status != STATUS_IMAGE_ALREADY_LOADED)) 
	{

        //
        //  The load was not successful.  Simply reattach to the recognizer
        //  driver in case it ever figures out how to get the driver loaded
        //  on a subsequent call.
        //

        SpyAttachDeviceToDeviceStack( DeviceObject,
                                      devExt->NLExtHeader.AttachedToDeviceObject,
                                      &devExt->NLExtHeader.AttachedToDeviceObject );

        ASSERT(devExt->NLExtHeader.AttachedToDeviceObject != NULL);

    } else 
	{

        //
        //  The load was successful, delete the Device object
        //

        SpyCleanupMountedDevice( DeviceObject );
        IoDeleteDevice( DeviceObject );
    }

    //
    //  Continue processing the operation
    //

    status = Irp->IoStatus.Status;

    IoCompleteRequest( Irp, IO_DISK_INCREMENT );

    return status;
}

/////////////////////////////////////////////////////////////////////////////
//
//                      FastIO Handling routines
//
/////////////////////////////////////////////////////////////////////////////

BOOLEAN
SpyFastIoCheckIfPossible (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in BOOLEAN CheckForReadOperation,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for checking to see
    whether fast I/O is possible for this file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be operated on.

    FileOffset - Byte offset in the file for the operation.

    Length - Length of the operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    CheckForReadOperation - Indicates whether the caller is checking for a
        read (TRUE) or a write operation.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT    deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    BOOLEAN           returnValue = FALSE;
    
    
    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
	
	//
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

        //
        //  We have a valid DeviceObject, so look at its FastIoDispatch
        //  table for the next driver's Fast IO routine.
        //
		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpFastIoCheckIfPossible( FileObject,
													FileOffset,
													Length,
													Wait,
													LockKey,
													CheckForReadOperation,
													IoStatus,
													deviceObject);
		}
        else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoCheckIfPossible )) 
			{

				returnValue = (fastIoDispatch->FastIoCheckIfPossible)( FileObject,
														   FileOffset,
														   Length,
														   Wait,
														   LockKey,
														   CheckForReadOperation,
														   IoStatus,
														   deviceObject);
		}
        }
    }

    return returnValue;
}

BOOLEAN
SpyFastIoRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading from a
    file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be read.

    FileOffset - Byte offset in the file of the read.

    Length - Length of the read operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    Buffer - Pointer to the caller's buffer to receive the data read.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    BOOLEAN returnValue = FALSE;
    PAGED_CODE();
    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

	deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
	
    if (NULL != deviceObject) 
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpCopyReadA(FileObject,
										FileOffset,
										Length,
										Wait,
										LockKey,
										Buffer,
										IoStatus,
										DeviceObject);
		}
        else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoRead )) 
			{

				returnValue = (fastIoDispatch->FastIoRead)( FileObject,
															FileOffset,
															Length,
															Wait,
															LockKey,
															Buffer,
															IoStatus,
															deviceObject);
			}
		}
    }

    return returnValue;
}

BOOLEAN
SpyFastIoWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for writing to a
    file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be written.

    FileOffset - Byte offset in the file of the write operation.

    Length - Length of the write operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    Buffer - Pointer to the caller's buffer that contains the data to be
        written.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    
    BOOLEAN returnValue = FALSE;
    

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpCopyWriteA(FileObject,
										FileOffset,
										Length,
										Wait,
										LockKey,
										Buffer,
										IoStatus,
										DeviceObject);
		}
		else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoWrite ))
			{

				returnValue = (fastIoDispatch->FastIoWrite)( FileObject,
															 FileOffset,
															 Length,
															 Wait,
															 LockKey,
															 Buffer,
															 IoStatus,
															 deviceObject);
			}
		}
    } 
    return returnValue;
}

BOOLEAN
SpyFastIoQueryBasicInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_BASIC_INFORMATION)) PFILE_BASIC_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying basic
    information about the file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    Buffer - Pointer to the caller's buffer to receive the information about
        the file.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    BOOLEAN returnValue = FALSE;
    
   

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
	 //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpFastQueryBasicInfo(FileObject,
									Wait,
									Buffer,
									IoStatus,
									deviceObject);
		}else

		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
												FastIoQueryBasicInfo )) 
			{

				returnValue = (fastIoDispatch->FastIoQueryBasicInfo)( FileObject,
																	  Wait,
																	  Buffer,
																	  IoStatus,
																	  deviceObject);
			}
		}
    }

   
    return returnValue;
}

BOOLEAN
SpyFastIoQueryStandardInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_STANDARD_INFORMATION)) PFILE_STANDARD_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying standard
    information about the file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    Buffer - Pointer to the caller's buffer to receive the information about
        the file.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    
    BOOLEAN returnValue = FALSE;
    

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
   //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpFastQueryStdInfo(FileObject,
												Wait,
												Buffer,
												IoStatus,
												deviceObject);
		}else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryStandardInfo )) 
			{

				returnValue = (fastIoDispatch->FastIoQueryStandardInfo)( FileObject,
																		 Wait,
																		 Buffer,
																		 IoStatus,
																		 deviceObject );

			}
		}
    }

    
    return returnValue;
}

BOOLEAN
SpyFastIoLock (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for locking a byte
    range within a file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be locked.

    FileOffset - Starting byte offset from the base of the file to be locked.

    Length - Length of the byte range to be locked.

    ProcessId - ID of the process requesting the file lock.

    Key - Lock key to associate with the file lock.

    FailImmediately - Indicates whether or not the lock request is to fail
        if it cannot be immediately be granted.

    ExclusiveLock - Indicates whether the lock to be taken is exclusive (TRUE)
        or shared.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    
    BOOLEAN returnValue = FALSE;
  

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject)
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue= PfpFastLock(FileObject,
									FileOffset,
									Length,
									ProcessId,
									Key,
									FailImmediately,
									ExclusiveLock,
									IoStatus,
									deviceObject);
		}
        else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoLock )) 
			{

				returnValue = (fastIoDispatch->FastIoLock)( FileObject,
															FileOffset,
															Length,
															ProcessId,
															Key,
															FailImmediately,
															ExclusiveLock,
															IoStatus,
															deviceObject);
			}

        }
    }

    

    return returnValue;
}

BOOLEAN
SpyFastIoUnlockSingle (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking a byte
    range within a file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    FileOffset - Starting byte offset from the base of the file to be
        unlocked.

    Length - Length of the byte range to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    Key - Lock key associated with the file lock.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    
    BOOLEAN returnValue = FALSE;
   

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    
    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpFastUnlockSingle(FileObject,
												FileOffset,
												Length,
												ProcessId,
												Key,
												IoStatus,
												deviceObject);
		}
		else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
												FastIoUnlockSingle ))
			{

				returnValue = (fastIoDispatch->FastIoUnlockSingle)( FileObject,
																	FileOffset,
																	Length,
																	ProcessId,
																	Key,
																	IoStatus,
																	deviceObject);

			}
		}
    }

   

    return returnValue;
}

BOOLEAN
SpyFastIoUnlockAll (
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking all
    locks within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
  

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

 
    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject)
	{
		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpFastUnlockAll(FileObject,
											ProcessId,
											IoStatus,
											deviceObject);
		}
		else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoUnlockAll )) 
			{

				returnValue = (fastIoDispatch->FastIoUnlockAll)( FileObject,
																 ProcessId,
																 IoStatus,
																 deviceObject);

			}
		}
    }

   

    return returnValue;
}

BOOLEAN
SpyFastIoUnlockAllByKey (
    __in PFILE_OBJECT FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking all
    locks within a file based on a specified key.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    Key - Lock key associated with the locks on the file to be released.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
    

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{
		if(PfpFileObjectHasOurFCB(FileObject))
		{
			
			returnValue = PfpFastUnlockAllByKey(FileObject,
												ProcessId,
												Key,
												IoStatus,
												deviceObject);
		}
        else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
												FastIoUnlockAllByKey )) {

				returnValue = (fastIoDispatch->FastIoUnlockAllByKey)( FileObject,
																	  ProcessId,
																	  Key,
																	  IoStatus,
																	  deviceObject);
			}
		}
    }
 
    return returnValue;
}

BOOLEAN
SpyFastIoDeviceControl (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for device I/O
    control operations on a file.

    If this I/O is directed to gControlDevice, then the parameters specify
    control commands to FileSpy.  These commands are interpreted and handled
    appropriately.

    If this is I/O directed at another DriverObject, this function simply
    invokes the next driver's corresponding routine, or returns FALSE if
    the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object representing the device to be
        serviced.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    InputBuffer - Optional pointer to a buffer to be passed into the driver.

    InputBufferLength - Length of the optional InputBuffer, if one was
        specified.

    OutputBuffer - Optional pointer to a buffer to receive data from the
        driver.

    OutputBufferLength - Length of the optional OutputBuffer, if one was
        specified.

    IoControlCode - I/O control code indicating the operation to be performed
        on the device.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

Notes:

    This function does not check the validity of the input/output buffers
    because the IOCTLs are implemented as METHOD_BUFFERED.  In this case,
    the I/O manager does the buffer validation checks for us.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
   

    PAGED_CODE();

    //
    //  Get a pointer to the current location in the Irp. This is where
    //  the function codes and parameters are located.
    //

    if (DeviceObject == gControlDeviceObject) {

        SpyCommonDeviceIoControl( InputBuffer,
                                  InputBufferLength,
                                  OutputBuffer,
                                  OutputBufferLength,
                                  IoControlCode,
                                  IoStatus );

        returnValue = TRUE;

    } else {

        ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );       

        deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

        if (NULL != deviceObject) {

            fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

            if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoDeviceControl )) 
			{

                returnValue = (fastIoDispatch->FastIoDeviceControl)( FileObject,
                                                             Wait,
                                                             InputBuffer,
                                                             InputBufferLength,
                                                             OutputBuffer,
                                                             OutputBufferLength,
                                                             IoControlCode,
                                                             IoStatus,
                                                             deviceObject);

            } else 
			{

                IoStatus->Status = STATUS_SUCCESS;
            }
        }

    }

    return returnValue;
}


VOID
SpyFastIoDetachDevice (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice
    )
/*++

Routine Description:

    This routine is invoked on the fast path to detach from a device that
    is being deleted.  This occurs when this driver has attached to a file
    system volume device object, and then, for some reason, the file system
    decides to delete that device (it is being dismounted, it was dismounted
    at some point in the past and its last reference has just gone away, etc.)

Arguments:

    SourceDevice - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

    TargetDevice - Pointer to the file system's volume device object.

Return Value:

    None.

--*/
{
     
  
    PFILESPY_DEVICE_EXTENSION devext;

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( SourceDevice ) );

    devext = SourceDevice->DeviceExtension;
	if( devext && !devext->bShadow)
	{
		if(devext->pVirtualRootDir)
		{
			PfpDeleteVirtualDir(&(PDISKDIROBEJECT)devext->pVirtualRootDir);
		}
		if(devext->pszUsbDiskSeriNUM!= NULL)
		{
			ExFreePool_A(devext->pszUsbDiskSeriNUM);
		}
		if(devext->pShadowDevice)
		{
			IoDeleteDevice( devext->pShadowDevice );
			devext->pShadowDevice= NULL;
		}
		if(devext->bUsbDevice )
		{
			
			if(devext->pUsbSecureConfig)
			{
				((PUSBSECURE)devext->pUsbSecureConfig) ->pUsbVolumeDevice = NULL;
			}
			if(g_UsbDeviceSignal)
			{
				KdPrint(("set event in FastioDetach\r\n"));
				KeSetEvent(g_UsbDeviceSignal ,IO_NO_INCREMENT, FALSE);
			}
		}
	}
    SpyCleanupMountedDevice( SourceDevice );
    IoDetachDevice( TargetDevice );
    IoDeleteDevice( SourceDevice );
 
}

BOOLEAN
SpyFastIoQueryNetworkOpenInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying network
    information about a file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller can handle the file system
        having to wait and tie up the current thread.

    Buffer - Pointer to a buffer to receive the network information about the
        file.

    IoStatus - Pointer to a variable to receive the final status of the query
        operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
  

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    

    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) {

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			return FALSE;
			returnValue =PfpFastQueryNetworkOpenInfo(FileObject,
													Wait,
													Buffer,
													IoStatus,
													deviceObject);
		}
        else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
												FastIoQueryNetworkOpenInfo )) {

				returnValue = (fastIoDispatch->FastIoQueryNetworkOpenInfo)( FileObject,
																	Wait,
																	Buffer,
																	IoStatus,
																	deviceObject);

			}
		}
    }

   return returnValue;
}

BOOLEAN
SpyFastIoMdlRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading a file
    using MDLs as buffers.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object that is to be read.

    FileOffset - Supplies the offset into the file to begin the read operation.

    Length - Specifies the number of bytes to be read from the file.

    LockKey - The key to be used in byte range lock checks.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data read.

    IoStatus - Variable to receive the final status of the read operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
    
	
    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
 
    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject)
	{

	
		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpMdlReadA(  FileObject,
										FileOffset,
										Length,
										LockKey,
										MdlChain,
										IoStatus,
										DeviceObject);
		}
		else
        
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlRead )) 
			{

				returnValue = (fastIoDispatch->MdlRead)( FileObject,
														 FileOffset,
														 Length,
														 LockKey,
														 MdlChain,
														 IoStatus,
														 deviceObject);
			}
		}
    }    

    return returnValue;
}

BOOLEAN
SpyFastIoMdlReadComplete (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL read operation.

    This function simply invokes the next driver's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the MdlRead function is supported by the underlying driver, and
    therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the MDL read upon.

    MdlChain - Pointer to the MDL chain used to perform the read operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
   

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

		
		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = FsRtlMdlReadCompleteDev ( FileObject,										
													MdlChain,										
													DeviceObject);
		}
		else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;
			
			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlReadComplete )) 
			{

				returnValue = (fastIoDispatch->MdlReadComplete)( FileObject,
																 MdlChain,
																 deviceObject);
			}
		}
    }

   return returnValue;
}

BOOLEAN
SpyFastIoPrepareMdlWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for preparing for an
    MDL write operation.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be written.

    FileOffset - Supplies the offset into the file to begin the write
        operation.

    Length - Specifies the number of bytes to be write to the file.

    LockKey - The key to be used in byte range lock checks.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data written.

    IoStatus - Variable to receive the final status of the write operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
   
	
    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
 
    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject)
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = PfpPrepareMdlWriteA( FileObject,
												FileOffset,
												Length,
												LockKey,
												MdlChain,
												IoStatus,
												deviceObject);
		}
		else
		
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, PrepareMdlWrite )) 
			{

				returnValue = (fastIoDispatch->PrepareMdlWrite)( FileObject,
																 FileOffset,
																 Length,
																 LockKey,
																 MdlChain,
																 IoStatus,
																 deviceObject);
			}
		}
    }

    return returnValue;
}

BOOLEAN
SpyFastIoMdlWriteComplete (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL write operation.

    This function simply invokes the next driver's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the PrepareMdlWrite function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not
    assumed by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the MDL write upon.

    FileOffset - Supplies the file offset at which the write took place.

    MdlChain - Pointer to the MDL chain used to perform the write operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
    
    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    
    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject)
	{

		if(PfpFileObjectHasOurFCB(FileObject))
		{
			returnValue = FsRtlMdlWriteCompleteDev(FileObject,
													FileOffset,
													MdlChain,
													deviceObject);
		}
        else
		{
			fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
												MdlWriteComplete )) {

				returnValue = (fastIoDispatch->MdlWriteComplete)( FileObject,
																  FileOffset,
																  MdlChain,
																  deviceObject);

			}
		}
    }

    return returnValue;
}

BOOLEAN
SpyFastIoReadCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __out_bcount(CompressedDataInfoLength) struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading
    compressed data from a file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be read.

    FileOffset - Supplies the offset into the file to begin the read operation.

    Length - Specifies the number of bytes to be read from the file.

    LockKey - The key to be used in byte range lock checks.

    Buffer - Pointer to a buffer to receive the compressed data read.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data read.

    IoStatus - Variable to receive the final status of the read operation.

    CompressedDataInfo - A buffer to receive the description of the
        compressed data.

    CompressedDataInfoLength - Specifies the size of the buffer described by
        the CompressedDataInfo parameter.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
    

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
 
    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) {

        fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            FastIoReadCompressed )) {

            returnValue = (fastIoDispatch->FastIoReadCompressed)( FileObject,
                                                      FileOffset,
                                                      Length,
                                                      LockKey,
                                                      Buffer,
                                                      MdlChain,
                                                      IoStatus,
                                                      CompressedDataInfo,
                                                      CompressedDataInfoLength,
                                                      deviceObject);
        }
    }

   return returnValue;
}

BOOLEAN
SpyFastIoWriteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __out_bcount(CompressedDataInfoLength) struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for writing
    compressed data to a file.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be written.

    FileOffset - Supplies the offset into the file to begin the write
        operation.

    Length - Specifies the number of bytes to be write to the file.

    LockKey - The key to be used in byte range lock checks.

    Buffer - Pointer to the buffer containing the data to be written.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data written.

    IoStatus - Variable to receive the final status of the write operation.

    CompressedDataInfo - A buffer to containing the description of the
        compressed data.

    CompressedDataInfoLength - Specifies the size of the buffer described by
        the CompressedDataInfo parameter.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
  

    PAGED_CODE();

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
 
    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) {

        fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoWriteCompressed )) {

            returnValue = (fastIoDispatch->FastIoWriteCompressed)( FileObject,
                                                       FileOffset,
                                                       Length,
                                                       LockKey,
                                                       Buffer,
                                                       MdlChain,
                                                       IoStatus,
                                                       CompressedDataInfo,
                                                       CompressedDataInfoLength,
                                                       deviceObject);
        }
    }
    return returnValue;
}

BOOLEAN
SpyFastIoMdlReadCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL read compressed operation.

    This function simply invokes the next driver's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the read compressed function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not
    assumed by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the compressed read
        upon.

    MdlChain - Pointer to the MDL chain used to perform the read operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
  

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

   
    //
    // Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) {

        fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
                                            MdlReadCompleteCompressed )) {

            returnValue = (fastIoDispatch->MdlReadCompleteCompressed)( FileObject,
                                                               MdlChain,
                                                               deviceObject);

        }
    }

    
    return returnValue;
}

BOOLEAN
SpyFastIoMdlWriteCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
)
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing a
    write compressed operation.

    This function simply invokes the next driver's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the write compressed function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not
    assumed by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the compressed write
        upon.

    FileOffset - Supplies the file offset at which the file write operation
        began.

    MdlChain - Pointer to the MDL chain used to perform the write operation.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.

--*/
{
    PDEVICE_OBJECT deviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
     
    BOOLEAN returnValue = FALSE;
    

    ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );

    //
    //  Pass through logic for this type of Fast I/O
    //

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) {

        fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlWriteCompleteCompressed )) {

            returnValue = (fastIoDispatch->MdlWriteCompleteCompressed)( FileObject,
                                                                FileOffset,
                                                                MdlChain,
                                                                deviceObject);

        }
    }

    return returnValue;
}

BOOLEAN
SpyFastIoQueryOpen (
    __in PIRP Irp,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for opening a file
    and returning network information it.

    This function simply invokes the next driver's corresponding routine, or
    returns FALSE if the next driver does not implement the function.

Arguments:

    Irp - Pointer to a create IRP that represents this open operation.  It is
        to be used by the file system for common open/create code, but not
        actually completed.

    NetworkInformation - A buffer to receive the information required by the
        network about the file being opened.

    DeviceObject - Pointer to device object Filespy attached to the file system
        filter stack for the volume receiving this I/O request.

Return Value:

    Return TRUE if the request was successfully processed via the
    fast i/o path.

    Return FALSE if the request could not be processed via the fast
    i/o path.  The IO Manager will then send this i/o to the file
    system through an IRP instead.

--*/
{
    PDEVICE_OBJECT		deviceObject;
    PFAST_IO_DISPATCH	fastIoDispatch;
    PWCHAR				pszFilename =  NULL;  
	PFILE_OBJECT		pFileObject;
	
	
    BOOLEAN				returnValue = FALSE;
	PDISKFILEOBJECT		pDiskFileObject;
	PLIST_ENTRY			pDiskFileObjectLists= NULL;
	BOOLEAN				bFound = FALSE;
	PDISKDIROBEJECT		pVirtualRootDir = NULL;
	PDISKDIROBEJECT		pParentDir = NULL;
	PWCHAR				pRemainer = NULL;
	BOOLEAN				bComplete = FALSE;
	PPfpFCB				pFcb = NULL;
	ULONG				nNameLenInBytes = 0;
	PAGED_CODE();

	ASSERT( IS_FILESPY_DEVICE_OBJECT( DeviceObject ) );
	
	if(((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->bShadow)
	{
		DeviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->pRealDevice;
		goto FROMSHADOW;
	}
	pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	 
	
	if(pFileObject->FileName.Length==0)
		return FALSE;
 	 
	pVirtualRootDir = PfpGetVirtualRootDirFromSpyDevice(DeviceObject);
	
	if(pVirtualRootDir==  NULL)
		return FALSE;

	if(!NT_SUCCESS(PfpGetFullPathPreCreate(Irp,&pszFilename,&nNameLenInBytes,DeviceObject)))
	{
		return FALSE;
	}
	
	FsRtlEnterFileSystem();
	
	ExAcquireResourceSharedLite( pVirtualRootDir->AccssLocker,TRUE);
	pParentDir  = PfpPareseToDirObject(pVirtualRootDir,pszFilename,&pRemainer,&bComplete);

	 
	if(bComplete)
	{
		UNICODE_STRING TempString;
		PVIRTUALDISKFILE pVirtualDiskFile = NULL;
	
		TempString.Buffer = pRemainer;
		TempString.Length = (wcslen(pRemainer)<<1);
		TempString.MaximumLength  = TempString.Length +2;
		pVirtualDiskFile = PfpFindVirtualDiskFileObjectInParent(pParentDir,&TempString);
		if(pVirtualDiskFile )
		{
			
			ExAcquireResourceSharedLite( pVirtualDiskFile->pVirtualDiskLocker,TRUE);
			KdPrint(("SpyFastIoQueryOpen function accquire file resource %Xh\r\n",pVirtualDiskFile->pVirtualDiskLocker));
			pDiskFileObject= PpfGetDiskFileObjectFromVirtualDisk(pVirtualDiskFile);
			
			if(pDiskFileObject)
			{
				pFcb = ((PPfpFCB)pDiskFileObject->pFCB);
				NetworkInformation->CreationTime.QuadPart	= pFcb->CreationTime ;
				NetworkInformation->LastAccessTime.QuadPart = pFcb->CurrentLastAccess ;
				NetworkInformation->LastWriteTime.QuadPart	= pFcb->LastModificationTime ;
				NetworkInformation->ChangeTime	.QuadPart	= pFcb->LastChangeTime ;
				NetworkInformation->AllocationSize.QuadPart	= pFcb->Header.AllocationSize.QuadPart;
				NetworkInformation->EndOfFile.QuadPart		= pFcb->Header.FileSize.QuadPart;
				NetworkInformation->FileAttributes	= pFcb->Attribute;
				bFound = TRUE;
			}
			KdPrint(("SpyFastIoQueryOpen function release file resource %Xh\r\n",pVirtualDiskFile->pVirtualDiskLocker));
			ExReleaseResourceLite(pVirtualDiskFile->pVirtualDiskLocker);
			
		}
		
		
	}
	/*if(pParentDir)*/
	{
		ExReleaseResourceLite( pVirtualRootDir->AccssLocker);
	}
	

	FsRtlExitFileSystem();

	if(pszFilename)
	{
		ExFreePool_A(pszFilename);
	}
	return bFound;
		
	 
   
    //
    // Pass through logic for this type of Fast I/O
    //
FROMSHADOW:

    deviceObject = ((PFILESPY_DEVICE_EXTENSION) (DeviceObject->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;

    if (NULL != deviceObject) 
	{

        fastIoDispatch = deviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryOpen )) 
		{

            PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation( Irp );

            //
            //  Before calling the next filter, we must make sure their device
            //  object is in the current stack entry for the given IRP
            //

            irpSp->DeviceObject = deviceObject;

            returnValue = (fastIoDispatch->FastIoQueryOpen)( Irp,
                                                             NetworkInformation,
                                                             deviceObject );
            //
            //  Restore the IRP back to our device object
            //

            irpSp->DeviceObject = DeviceObject;
        }
    }

    

    return returnValue;
}

NTSTATUS
PfpInitSystemSettings(HANDLE hFile)
{	
	NTSTATUS		status = STATUS_SUCCESS;
	LARGE_INTEGER	nFileLen	=	{0};
	IO_STATUS_BLOCK ioState		=	{0};				
	PUCHAR			pBuffer		=	NULL;
	ULONG			FileLen		=	0;
	FILE_STANDARD_INFORMATION StardInfo={0};
	
	
	if(hFile== INVALID_HANDLE_VALUE|| hFile==0)
	{
		return status;
	}

	if(ZwQueryInformationFile(hFile,&ioState,&StardInfo,sizeof(StardInfo),FileStandardInformation)== STATUS_SUCCESS)
	{
		if(StardInfo.EndOfFile.QuadPart==0)
			return status;

		nFileLen.QuadPart = StardInfo.EndOfFile.QuadPart;
		pBuffer			  = ExAllocatePool(PagedPool,(SIZE_T)nFileLen.QuadPart);

		if(pBuffer == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		else
		{	
			PUCHAR pTempBuffer=pBuffer;
			//这个地方要加hash 值来保证文件没有被修改过
			FileLen				= (ULONG )nFileLen.QuadPart;
			nFileLen.QuadPart	= 0;
			if(STATUS_SUCCESS==(status=ZwReadFile(hFile,NULL,NULL,NULL,&ioState,pTempBuffer,FileLen ,&nFileLen,NULL)))
			{
				ULONG nSizeHide,nSizeProtector,nSizeProcessInfo,nSysVersion,nSizeBackupFolder,nSizeOfUsbSecure;
				ASSERT(FileLen == ioState.Information );
				
				nSysVersion    =*(ULONG*)pTempBuffer;
				pTempBuffer		+=sizeof(ULONG);
				
				g_bLog			= ((*(ULONG*)pTempBuffer== 1)?TRUE:FALSE);
				pTempBuffer		+=sizeof(ULONG);

				g_bProtectSySself = ((*(ULONG*)pTempBuffer== 1)?TRUE:FALSE);
				pTempBuffer		+=sizeof(ULONG);
				
				g_bEncrypteUDISK = ((*(ULONG*)pTempBuffer== 1)?TRUE:FALSE);
				pTempBuffer		+=sizeof(ULONG);
				
				g_AllowDisplayFrameOnWindow = ((*(ULONG*)pTempBuffer== 1)?TRUE:FALSE);
				pTempBuffer		+=sizeof(ULONG);

				nSizeBackupFolder = *(ULONG*)pTempBuffer;
				pTempBuffer		+=sizeof(ULONG);

				nSizeHide		= *(ULONG*)pTempBuffer;
				pTempBuffer		+=sizeof(ULONG);

				nSizeProtector	= *(ULONG*)pTempBuffer;
				pTempBuffer		+=sizeof(ULONG);
				
				nSizeProcessInfo =  *(ULONG*)pTempBuffer;				
				pTempBuffer+=sizeof(ULONG);
				
				nSizeOfUsbSecure = *(ULONG*)pTempBuffer;				
				pTempBuffer+=sizeof(ULONG);

				if(nSizeBackupFolder>0)
				{
					g_szBackupDir = ExAllocatePool(PagedPool,nSizeBackupFolder+sizeof(WCHAR));
					if(g_szBackupDir )
					{						
						memcpy(g_szBackupDir,pTempBuffer,nSizeBackupFolder);
						g_szBackupDir[nSizeBackupFolder/sizeof(WCHAR)]=L'\0';
					}
				}
				
				pTempBuffer+=nSizeBackupFolder;
				if(nSizeHide)
				{
					ExAcquireResourceExclusiveLite(&g_HideEresource,TRUE);
					InitHidderFromBufferReadFromFile(pTempBuffer,nSizeHide);
					ExReleaseResourceLite(&g_HideEresource);
				}
				
				pTempBuffer+=nSizeHide;
				
				if(nSizeProtector)
				{
					ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
					InitFolerdProtectorFromBuffer(pTempBuffer,nSizeProtector);
					ExReleaseResourceLite(&g_FolderResource);
				}
				pTempBuffer +=nSizeProtector;
				if(nSizeOfUsbSecure!= 0)
				{
					PfpInitUsbSecureS(pTempBuffer,nSizeOfUsbSecure);
				}
				pTempBuffer+=nSizeOfUsbSecure;
				if(nSizeProcessInfo !=0)				
				{	
					ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
					PfpInitProcessInfosFromBuffer(pTempBuffer,nSizeProcessInfo,&ioState);
					ExReleaseResourceLite(&g_ProcessInfoResource);
				}
			}else
			{
				status = ioState.Status;
			}
			ExFreePool(pBuffer);
		}
	}else
	{
		status = ioState.Status;
	}
	return status;
}


NTSTATUS  PfpSaveSystemSettingsEx()
{
	KeSetEvent(&g_EventSaveFile,IO_NO_INCREMENT, FALSE);
	return STATUS_SUCCESS;
}

 NTSTATUS PfpSaveSystemSettings( )
{
	ULONG nHiderSize,nFolderProSize,nProcessInfoSize,nBackupFolderSize,nUsbSecureSize;
	PVOID						pProcessinfoBuffer = NULL;
	PVOID						pBufferForHideAndFolderProtector = NULL;
	PUCHAR						pTemp  = NULL;
	IO_STATUS_BLOCK				iostatus;
	NTSTATUS status				= STATUS_SUCCESS;
	FILE_END_OF_FILE_INFORMATION enfofFile;
	UNICODE_STRING				ConfigFile;
	PWCHAR						pszConfigFile  = NULL;
	OBJECT_ATTRIBUTES			objectAttributes;
	HANDLE						hFile= INVALID_HANDLE_VALUE;
	WCHAR						szDrvierLetter[3]={0};
	PDEVICE_OBJECT				pSpyDevice = NULL;
	WCHAR						szConfigFile[] =L"ProcessFilter.CFG"; 
	if(g_DriverDir==  NULL)
	{
		return STATUS_SUCCESS;
	}
	
	pszConfigFile   = ExAllocatePool_A(PagedPool,(wcslen(g_DriverDir)+20)*sizeof(WCHAR));
	if(pszConfigFile   == NULL)
	{
		return STATUS_SUCCESS;
	}

	wcscpy(pszConfigFile   ,g_DriverDir);
	wcscat(pszConfigFile   ,L"ProcessFilter.tmp");
	memcpy(szDrvierLetter, g_DriverDir,4);

	RtlInitUnicodeString(&ConfigFile,pszConfigFile);
	InitializeObjectAttributes( &objectAttributes,
		&ConfigFile,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL );

	status = ZwCreateFile( &hFile,
		SYNCHRONIZE|FILE_READ_DATA|FILE_WRITE_DATA,
		&objectAttributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0 );


	if(hFile== INVALID_HANDLE_VALUE)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto ERROREXIT;
	}


	nHiderSize		= 0;
	nFolderProSize	= 0;
	nProcessInfoSize= 0;
	nHiderSize		= CalcHideObjectSizeForWritingFile();
	nFolderProSize	= CalcFolderProctectionLen();
	nUsbSecureSize  = PfpGetUsbSecurLenForSave();
	nBackupFolderSize = (g_szBackupDir?wcslen(g_szBackupDir)*sizeof(WCHAR):0);

	pBufferForHideAndFolderProtector = ExAllocatePool(PagedPool,10*sizeof(ULONG)+nHiderSize+nUsbSecureSize+nFolderProSize+nBackupFolderSize);
	if(pBufferForHideAndFolderProtector== NULL )
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto ERROREXIT;
	}
	
	pProcessinfoBuffer = PfpGetAllPrograms(&nProcessInfoSize );
	
	pTemp = (PUCHAR)pBufferForHideAndFolderProtector ;
	
	*(ULONG*)pTemp = 1;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = g_bLog;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = g_bProtectSySself;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = g_bEncrypteUDISK;
	pTemp +=sizeof(ULONG);
	
	*(ULONG*)pTemp =g_AllowDisplayFrameOnWindow;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = nBackupFolderSize;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = nHiderSize;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = nFolderProSize;
	pTemp +=sizeof(ULONG);

	*(ULONG*)pTemp = nProcessInfoSize;
	pTemp +=sizeof(ULONG);
	*(ULONG*)pTemp = nUsbSecureSize;
	pTemp +=sizeof(ULONG);

	if(nBackupFolderSize)
	{
		memcpy(pTemp,g_szBackupDir,nBackupFolderSize);
	}
	pTemp +=nBackupFolderSize;
	if(nHiderSize)
	{
		WriteHidderObjectsIntoBufferForWrittingFile(pTemp,&nHiderSize);
	}
	pTemp +=nHiderSize;
	if(nFolderProSize)
	{
		CopyFolderItemsIntoUserBuffer(pTemp,nFolderProSize);
	}
	pTemp+=nFolderProSize;

	if(nUsbSecureSize)
	{
		ULONG nLeft = nUsbSecureSize;
		PfpWriteUsbSecurIntoBuffer(pTemp,&nLeft );
	}
	pTemp+=nUsbSecureSize;
	//write head and hider and folders under protection
	status = ZwWriteFile(hFile,
									NULL,
									NULL,
									NULL,
									&iostatus,
									pBufferForHideAndFolderProtector,
									10*sizeof(ULONG)+nHiderSize+nFolderProSize+nBackupFolderSize+nUsbSecureSize,
									NULL,NULL
									);
	// write processinfor into file speratlly

	if(nProcessInfoSize!= 0)
	{
		status = ZwWriteFile(hFile,
										NULL,
										NULL,
										NULL,
										&iostatus,
										pProcessinfoBuffer,
										nProcessInfoSize,
										NULL,NULL);
	}
	

	RtlZeroMemory(&enfofFile ,sizeof(FILE_END_OF_FILE_INFORMATION));				
	enfofFile.EndOfFile.QuadPart = 10*sizeof(ULONG)+nHiderSize+nFolderProSize+nBackupFolderSize+nUsbSecureSize+nProcessInfoSize;
	ZwSetInformationFile(   hFile,
							&iostatus,
							&enfofFile,
							sizeof(FILE_END_OF_FILE_INFORMATION),
							FileEndOfFileInformation);
//do rename operation
	if(!PfpGetDeviceDosNameFromFileHandle(hFile,szDrvierLetter))
	{
		goto ERROREXIT;
	}
	pSpyDevice = PfpGetSpyDeviceFromName(szDrvierLetter);
	
	if(pSpyDevice )
	{
		PFILE_OBJECT pFileObject = NULL;
		PFILE_RENAME_INFORMATION pReNameInfo=NULL;
		ULONG		 nLen = 0;
		pReNameInfo = ExAllocatePool(PagedPool,nLen=(sizeof(FILE_RENAME_INFORMATION )+(wcslen(szConfigFile)<<1)+2));
		if(pReNameInfo==NULL)
			goto ERROREXIT;

		ObReferenceObjectByHandle(hFile,
			0,
			*IoFileObjectType,
			KernelMode,
			&pFileObject,
			NULL);
		if(pFileObject== NULL)
		{
			ExFreePool(pReNameInfo);goto ERROREXIT;
		}
		pReNameInfo->FileNameLength  = wcslen(szConfigFile)<<1;
		pReNameInfo->ReplaceIfExists = TRUE;
		pReNameInfo->RootDirectory	 = NULL;
		memcpy(pReNameInfo->FileName,szConfigFile,pReNameInfo->FileNameLength);
		PfpSetFileInforByIrp(pFileObject,(PUCHAR)pReNameInfo,nLen,FileRenameInformation,((PFILESPY_DEVICE_EXTENSION)pSpyDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject);
		ExFreePool(pReNameInfo);
		ObDereferenceObject(pFileObject);
	}


ERROREXIT:
	if(hFile!= INVALID_HANDLE_VALUE)
	{
		ZwClose(hFile);
	}
	if(pszConfigFile)
	{
		ExFreePool_A(pszConfigFile);
	}
	if(pProcessinfoBuffer)
	{
		ExFreePool(pProcessinfoBuffer);
	}
	if(pBufferForHideAndFolderProtector)
	{
		ExFreePool(pBufferForHideAndFolderProtector);
	}

	return status;
}

BOOLEAN 
PfpSetBackupForProcess(PPROCESSINFO pProcInfo,BackUpSetting* pBackInfo)
{
	BackupType* pBackType = NULL;
	PFILETYPE	pFileType = NULL;
	LONG n;
	if(pProcInfo== NULL || pBackInfo== NULL) return FALSE;

	if(pBackInfo->nCount==0) return FALSE;

	pBackType = &pBackInfo->BackupInfo;

	if(pBackInfo->nCount==0)
	{
		return FALSE;
	};
	for( n=0;n<pBackInfo->nCount;++n)
	{
		pFileType = PfpGetFileTypeFromProcessInfo(pProcInfo,&pBackType[n].szFiletype[0]);
		if(pFileType != NULL)
		{
			pFileType->bSelected = pBackType[n].bSelected  ;
			pFileType->bBackUp   = pBackType[n].bBackup ;
		}else
		{
			PfpAddFileTypeIntoProcessInfo(pProcInfo,pBackType[n].szFiletype,pBackType[n].bSelected, pBackType[n].bBackup);
		}
	}
	return TRUE;
}
BOOLEAN 
PfpGetBackupInfoFromProg(PPROCESSINFO pProcInfo,BackUpSetting* pBackInfo)
{
	BackupType* pBackType = NULL;
	PFILETYPE	pFileType = NULL;
	LONG n=0;
	if(pProcInfo== NULL || pBackInfo== NULL) return FALSE;

	if(pBackInfo->nCount==0) return FALSE;

	pBackType = &pBackInfo->BackupInfo;

// 	if(pBackInfo->nCount==1)
// 	{
// 		return FASLE;
// 	}
	for(;n<pBackInfo->nCount;++n)
	{
		pFileType = PfpGetFileTypeFromProcessInfo(pProcInfo,&pBackType[n].szFiletype[0]);
		if(pFileType != NULL)
		{
			pBackType[n].bSelected = pFileType->bSelected;
			pBackType[n].bBackup   = pFileType->bBackUp;
		}
	}
	return TRUE;
}
BOOLEAN
PfpIsFileTypeNeedBackup(PPROCESSINFO pProcInfo,WCHAR* szFileType)
{
	
	PLIST_ENTRY  plistFileType = NULL;
	PWCHAR		 pszTemp1= NULL;
	PWCHAR		 pszTemp2= NULL;

	PFILETYPE	 pFileType = NULL;
	if(szFileType== NULL||pProcInfo== NULL)
		return FALSE;
	if(!pProcInfo->bNeedBackUp) return FALSE;

	for(plistFileType = pProcInfo->FileTypes.Flink;plistFileType != &pProcInfo->FileTypes;plistFileType = plistFileType->Flink)
	{

		pFileType  = CONTAINING_RECORD(plistFileType,FILETYPE,list);

		pszTemp1   = (pFileType->FileExt[0]==L'.')?&pFileType->FileExt[1]:&pFileType->FileExt[0];
		pszTemp2   = (szFileType[0]==L'.')?&szFileType[1]:&szFileType[0];

		if(pFileType && pFileType->bSelected && pFileType->bBackUp &&  _wcsicmp(pszTemp1,pszTemp2)==0)
		{
			return pFileType->bBackUp;
		}
	}

	
	return FALSE;
}
BOOLEAN
PfpNeedBackup(UCHAR* szHashValue,WCHAR* szFileType)
{
	PPROCESSINFO pProcInfo = NULL;
	PLIST_ENTRY  plistTemp = NULL;
	PLIST_ENTRY  plistFileType = NULL;
	PWCHAR		 pszTemp1= NULL;
	PWCHAR		 pszTemp2= NULL;

	PFILETYPE	 pFileType = NULL;
	if(szFileType== NULL||szHashValue== NULL)
		return FALSE;

	for(plistTemp = g_ProcessInofs.Flink;  plistTemp !=&g_ProcessInofs;plistTemp = plistTemp->Flink )
	{
		pProcInfo = CONTAINING_RECORD(plistTemp,PROCESSINFO,list);

		if(pProcInfo != NULL && memcmp(pProcInfo->ProcessHashValue,szHashValue,PROCESSHASHVALULENGTH)==0)
		{
			for(plistFileType = pProcInfo->FileTypes.Flink;plistFileType != &pProcInfo->FileTypes;plistFileType = plistFileType->Flink)
			{

				pFileType  = CONTAINING_RECORD(plistFileType,FILETYPE,list);

				pszTemp1   = (pFileType->FileExt[0]==L'.')?&pFileType->FileExt[1]:&pFileType->FileExt[0];
				pszTemp2   = (szFileType[0]==L'.')?&szFileType[1]:&szFileType[0];

				if(pFileType && _wcsicmp(pszTemp1,pszTemp2)==0)
				{
					return pFileType->bBackUp;
				}
			}
		}
	}
	return FALSE;


}

PPROCESSINFO  GetProcessInfoUsingHashValue(UCHAR* 	HashValue,LONG nsize)
{
	PPROCESSINFO pProcInfo = NULL;
	PLIST_ENTRY  plistTemp = NULL;	

	if(HashValue== NULL || nsize!= PROCESSHASHVALULENGTH)
		return NULL;
	
	for(plistTemp = g_ProcessInofs.Flink;  plistTemp !=&g_ProcessInofs;plistTemp = plistTemp->Flink )
	{
		pProcInfo = CONTAINING_RECORD(plistTemp,PROCESSINFO,list);

		if(pProcInfo != NULL && memcmp(pProcInfo->ProcessHashValue,HashValue,PROCESSHASHVALULENGTH)==0)
		{
			InterlockedIncrement (&pProcInfo->nRef);
			return pProcInfo;
		}
	}
	return NULL;
}

VOID 
PfpEnableBackupForProg(UCHAR* szHashValue,BOOLEAN bEnable)
{
	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);
	
	if(pProcInfo )
	{
		pProcInfo->bNeedBackUp = bEnable;
		InterlockedDecrement (&pProcInfo->nRef);
	}
}

VOID 
PfpEnableEnCryptForProg(UCHAR* szHashValue,BOOLEAN bEnable)
{
	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{
		pProcInfo->bEnableEncrypt = bEnable;
		InterlockedDecrement (&pProcInfo->nRef);
	}
}

VOID 
PfpEnableInherForProg(UCHAR* szHashValue,BOOLEAN bEnable)
{
	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{
		pProcInfo->bAllowInherent = bEnable;
		InterlockedDecrement (&pProcInfo->nRef);
	}

}

VOID 
PfpSetForcEncryption(UCHAR* szHashValue,BOOLEAN bEnable)
{

	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{
		pProcInfo->bForceEncryption = bEnable;
		InterlockedDecrement (&pProcInfo->nRef);
	}
}

BOOLEAN IsBrower(UCHAR* pHashValue)
{
	BOOLEAN bBrowser = FALSE;
	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(pHashValue,PROCESSHASHVALULENGTH);
	if(pProcInfo)
	{
		bBrowser = pProcInfo->bBowser;
		InterlockedDecrement (&pProcInfo->nRef);
	}
	return bBrowser;
}
VOID 
PfpGetBrowserEncryptTypeValue(UCHAR* szHashValue,ULONG* nTypeValue)
{
	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{
		if(pProcInfo->bBowser)
		{
			*nTypeValue = pProcInfo->nEncryptTypes ;
		}
		InterlockedDecrement (&pProcInfo->nRef);
	}
}
VOID 
PfpSetBrowserEncryptTypeValue(UCHAR* szHashValue,ULONG nTypeValue)
{
	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{
		if(pProcInfo->bBowser)
		{
			pProcInfo->nEncryptTypes = nTypeValue   ;
		}
		InterlockedDecrement (&pProcInfo->nRef);
	}
}

VOID 
PfpGetBrowserEncryptFileTypesNum(UCHAR* szHashValue,ULONG nEncrytType,ULONG* plNum)
{
	LONG nIndexofBrowserFileTypesArray =-1;
	LIST_ENTRY	*plistHead = NULL;
	LIST_ENTRY  *plistTemp = NULL;
	PPROCESSINFO pProcInfo = NULL;
	if(szHashValue== NULL ||plNum== NULL)
	{
		return ;
	}
	*plNum =0;

	pProcInfo  = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{		
		if(pProcInfo->bBowser)
		{
			nIndexofBrowserFileTypesArray=Type2ArrayIndex(nEncrytType);
			if(nIndexofBrowserFileTypesArray!=-1)
			{
				plistHead  = &pProcInfo->FileTypesForBrowser[nIndexofBrowserFileTypesArray];
			}
			if(plistHead && !IsListEmpty(plistHead))
			{
				plistTemp =plistHead->Flink;
				while(plistTemp != plistHead)
				{
					(*plNum)++;
					plistTemp = plistTemp->Flink;
				};
			}
		}
		InterlockedDecrement (&pProcInfo->nRef);
	}

}

LONG  Type2ArrayIndex(ULONG nType)
{
	LONG n= -1;
	switch(nType)
	{
	case PIC_TYPE:
		n =0;
		break;
	case COOKIE_TYPE:
		n=1;
		break;
	case VEDIO_TYPE:
		n = 2;
		break;
	case TEXT_TYPE:
		n = 3;
		break;
	case SCRIPT_TYPE:
		n = 4;
		break;
	default:
		n =-1;
		break;
	}
	return n;
};
VOID 
PfpSetBrowserAllowCreateExeFile(UCHAR* szHashValue,BOOLEAN bEnable)
{

	PPROCESSINFO pProcInfo = GetProcessInfoUsingHashValue(szHashValue,PROCESSHASHVALULENGTH);

	if(pProcInfo )
	{
		pProcInfo->bAllCreateExeFile = bEnable;
		InterlockedDecrement (&pProcInfo->nRef);
	}
}



VOID 
PfpCreateShadowDeviceForDevice(IN PDEVICE_OBJECT newDeviceObject)
{
	PDEVICE_OBJECT pShadowDevice	 = NULL;
	PFILESPY_DEVICE_EXTENSION newDevExt = newDeviceObject->DeviceExtension;
	UNICODE_STRING	deviceName_u;
	UNICODE_STRING	DosdeviceName_u;
	UNICODE_STRING	ustrSecDDL;
	NTSTATUS status;

	RtlInitUnicodeString(&ustrSecDDL,L"D:P(A;;GA;;;AU)");


	RtlInitUnicodeString(&deviceName_u,g_ShadowDeivceName);
	RtlInitUnicodeString(&DosdeviceName_u,g_ShadowDosDeivceName);


	status =  IoCreateDeviceSecure(gFileSpyDriverObject,
									sizeof(FILESPY_DEVICE_EXTENSION),
									&deviceName_u,
									newDeviceObject->DeviceType,
									newDeviceObject->Characteristics,
									FALSE,
									&ustrSecDDL,NULL,&pShadowDevice);

	if(NT_SUCCESS(status))
	{
		newDevExt->pShadowDevice = pShadowDevice;
		((PFILESPY_DEVICE_EXTENSION)(pShadowDevice->DeviceExtension))->pRealDevice = newDeviceObject;
		((PFILESPY_DEVICE_EXTENSION)(pShadowDevice->DeviceExtension))->bShadow	  = TRUE;

		pShadowDevice->StackSize			= newDeviceObject->StackSize;
		pShadowDevice->AlignmentRequirement = newDeviceObject->AlignmentRequirement;

		pShadowDevice->Flags				= newDeviceObject->Flags;
		pShadowDevice->Type					= newDeviceObject->Type;

		{
			wcscpy(((PFILESPY_DEVICE_EXTENSION)(pShadowDevice->DeviceExtension))->DeviceNames,g_ShadowDeivceName);

			IncreaseNum(g_ShadowDosDeivceName,wcslen(g_ShadowDosDeivceName)-1);
			IncreaseNum(g_ShadowDeivceName,wcslen(g_ShadowDeivceName)-1);
		}
	}
	ClearFlag( pShadowDevice->Flags, DO_DEVICE_INITIALIZING );
}





BOOLEAN PfpEncryptBuffer(PVOID pBuffer, ULONG Len,aes_encrypt_ctx* pCtx)
{
	ULONG nBlock;
	if(pBuffer== NULL)
		return TRUE;
	ASSERT( (Len&(ULONG)15) ==0 );

	for(nBlock=0 ;nBlock<Len;nBlock+=16)
	{
		if(EXIT_SUCCESS != aes_encrypt(&((UCHAR*)pBuffer)[nBlock],&((UCHAR*)pBuffer)[nBlock],pCtx))
			return FALSE;
	}
	return TRUE;
}
BOOLEAN PfpDecryptBuffer(PVOID pBuffer, ULONG Len,aes_decrypt_ctx* pCtx)
{
	ULONG nBlock;
	if(pBuffer== NULL)
		return TRUE;
	ASSERT( (Len&(ULONG)15) ==0 );
	for(nBlock=0 ;nBlock<Len;nBlock+=16)
	{
		if(EXIT_SUCCESS != aes_decrypt(&((UCHAR*)pBuffer)[nBlock],&((UCHAR*)pBuffer)[nBlock],pCtx))
			return FALSE;
	}
	return TRUE;
}


VOID PfpGetKeyFileContent(PWCHAR szKeyFile,PVOID *pFileContent,ULONG *nsize)
{
	OBJECT_ATTRIBUTES	objectAttributes;	
	UNICODE_STRING		szUncidoeFullPathWithDevice;
	HANDLE				FileHandle;
	NTSTATUS			ntstatus;
	IO_STATUS_BLOCK		iostatus;
	ULONG				Length;
	PVOID				pBuffer = NULL;
	LARGE_INTEGER		Offset;
	PWCHAR			    pFullPath = NULL;
	if(szKeyFile== NULL ||pFileContent == NULL ||*pFileContent != NULL ||nsize== NULL)
		return ;
	
	*nsize =0;
	FileHandle = INVALID_HANDLE_VALUE;
	*pFileContent = NULL;
	
	pFullPath  = ExAllocatePool(PagedPool,sizeof(WCHAR)*(1+wcslen(szKeyFile)+wcslen(L"\\DosDevices\\")));

	if(pFullPath  == NULL)
		return ;

	wcscpy(pFullPath,L"\\DosDevices\\");
	wcscat(pFullPath,szKeyFile);


	szUncidoeFullPathWithDevice.Buffer = pFullPath;
	szUncidoeFullPathWithDevice.Length = wcslen(pFullPath)*sizeof(WCHAR);
	szUncidoeFullPathWithDevice.MaximumLength = 	szUncidoeFullPathWithDevice.Length +2;

	InitializeObjectAttributes( &objectAttributes,
								&szUncidoeFullPathWithDevice,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL );

	ntstatus = ZwCreateFile( &FileHandle,
							SYNCHRONIZE|FILE_READ_DATA,
							&objectAttributes,
							&iostatus,
							NULL,
							FILE_ATTRIBUTE_NORMAL,
							0,
							FILE_OPEN,
							FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0 );
		
	if(!NT_SUCCESS(ntstatus))
	{
		goto EXIT;
	}

	Length= PfpGetFileSize(FileHandle);
	
	if(Length>1024*1024)
	{
		goto EXIT;
	}


	pBuffer		= ExAllocatePool(PagedPool,Length);
	if(pBuffer == NULL)
	{
		goto EXIT;;
	}
	Offset.QuadPart = 0;
	ntstatus = ZwReadFile(FileHandle,
							NULL,
							NULL,
							NULL,
							&iostatus,
							pBuffer,
							Length,
							&Offset,	
							NULL);
	if(NT_SUCCESS(ntstatus) && iostatus.Information!=0)
	{
		*pFileContent	= pBuffer;
		*nsize			= Length;
		pBuffer			= NULL;
	}
	
EXIT:
	if(FileHandle!= INVALID_HANDLE_VALUE)
	{
		ZwClose(FileHandle);
	}
	if(pFullPath)
	{
		ExFreePool(pFullPath);
	}
	if(pBuffer)
	{
		ExFreePool(pBuffer);
	}
	return ;
}



BOOLEAN PfpWriteKeyFileContent(PWCHAR szKeyFile,PVOID pFileContent,ULONG nsize)
{
	OBJECT_ATTRIBUTES	objectAttributes;
	UNICODE_STRING		szUncidoeFullPathWithDevice;
	HANDLE				FileHandle;
	NTSTATUS			ntstatus;
	IO_STATUS_BLOCK		iostatus;
	LARGE_INTEGER		Offset;
	BOOLEAN				bReturn		= FALSE;
	PWCHAR			    pFullPath	= NULL;
	if(szKeyFile== NULL ||pFileContent == NULL ||nsize== 0)
		return FALSE;

	
	FileHandle = INVALID_HANDLE_VALUE;
	pFullPath  = ExAllocatePool(PagedPool,sizeof(WCHAR)*(1+wcslen(szKeyFile)+wcslen(L"\\DosDevices\\")));

	if(pFullPath  == NULL)
		return FALSE;
	
	wcscpy(pFullPath,L"\\DosDevices\\");
	wcscat(pFullPath,szKeyFile);
	szUncidoeFullPathWithDevice.Buffer = pFullPath;
	szUncidoeFullPathWithDevice.Length = wcslen(pFullPath)*sizeof(WCHAR);
	szUncidoeFullPathWithDevice.MaximumLength = 	szUncidoeFullPathWithDevice.Length +2;

	InitializeObjectAttributes( &objectAttributes,
								&szUncidoeFullPathWithDevice,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL );

	ntstatus = ZwCreateFile(&FileHandle,
							SYNCHRONIZE|FILE_GENERIC_WRITE,
							&objectAttributes,
							&iostatus,
							NULL,
							FILE_ATTRIBUTE_NORMAL,
							0,
							FILE_OVERWRITE_IF,
							FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0 );

	if(!NT_SUCCESS(ntstatus))
	{
		goto EXIT;
	}

	Offset.QuadPart=0;
	
	ntstatus = ZwWriteFile(FileHandle,
							NULL,
							NULL,
							NULL,
							&iostatus,
							pFileContent,
							nsize,
							&Offset,	
							NULL);

	if(NT_SUCCESS(ntstatus) && iostatus.Information!=0)
	{
		bReturn = TRUE;			
	}

	ZwClose(FileHandle);
	
EXIT:
	if(pFullPath)
	{
		ExFreePool(pFullPath);
	}
	return bReturn ;
}


VOID	PfpIncreFileOpen()
{
	KIRQL   oldIrql;
	KeAcquireSpinLock( &gAllFileOpenedLOCK, &oldIrql );		

	gAllFileCount++;
	KeReleaseSpinLock( &gAllFileOpenedLOCK, oldIrql );
}
VOID	PfpDecreFileOpen()
{
	KIRQL   oldIrql;
	KeAcquireSpinLock( &gAllFileOpenedLOCK, &oldIrql );		
	
	if(gAllFileCount>0)
		gAllFileCount--;
	

	KeReleaseSpinLock( &gAllFileOpenedLOCK, oldIrql );
}
ULONG	PfpGetFileOpenCount()
{
	KIRQL   oldIrql;
	ULONG	nCount = 0;
	KeAcquireSpinLock( &gAllFileOpenedLOCK, &oldIrql );		

	nCount  = gAllFileCount;

	KeReleaseSpinLock( &gAllFileOpenedLOCK, oldIrql );
	return nCount;
}


VOID PfpSaveFileWorker ( PVOID Context )
{
	UNREFERENCED_PARAMETER(Context);
	while(1)
	{
		if(NT_SUCCESS(KeWaitForSingleObject(&g_EventSaveFile,Executive,KernelMode,FALSE,(PLARGE_INTEGER)NULL)))
		{
			PfpSaveSystemSettings();
			KeClearEvent(&g_EventSaveFile);
		}
	};
}