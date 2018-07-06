/*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    fspyKern.h

Abstract:
    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    only visible within the kernel.

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
#ifndef __FSPYKERN_H__
#define __FSPYKERN_H__

#include "namelookupdef.h"
 
#include "Aes.h"
//
//  VERSION NOTE:
//
//  The following useful macros are defined in NTIFS.H in Windows XP and later.
//  We will define them locally if we are building for the Windows 2000
//  environment.
//

#if WINVER == 0x0500
//
//  These macros are used to test, set and clear flags respectively
//

// #ifndef FlagOn
// #define FlagOn(_F,_SF)        ((_F) & (_SF))
// #endif
// 
// #ifndef BooleanFlagOn
// #define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
// #endif
// 
// #ifndef SetFlag
// #define SetFlag(_F,_SF)       ((_F) |= (_SF))
// #endif
// 
// #ifndef ClearFlag
// #define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
// #endif


#define RtlInitEmptyUnicodeString(_ucStr,_buf,_bufSize) \
    ((_ucStr)->Buffer = (_buf), \
     (_ucStr)->Length = 0, \
     (_ucStr)->MaximumLength = (USHORT)(_bufSize))


#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#define ExFreePoolWithTag( a, b ) ExFreePool( (a) )
#endif /* WINVER == 0x0500 */

//
//  This controls how FileSpy is built.  It has 2 options:
//  0 - Build using NameHashing (old way, see fspyHash.c)
//  1 - Build using StreamContexts (new Way, see fspyCtx.c)
//
//  VERSION NOTE:
//
//  Filter stream contexts are only supported on Windows XP and later
//  OS versions.  This support was not available in Windows 2000 or NT 4.0.
//

#define USE_STREAM_CONTEXTS 0

#if USE_STREAM_CONTEXTS && WINVER < 0x0501
#error Stream contexts on only supported on Windows XP or later.
#endif

//
//  POOL Tag definitions
//

#define FILESPY_POOL_TAG                'yPsF'
#define FILESPY_LOGRECORD_TAG           'rLsF'
#define FILESPY_CONTEXT_TAG             'xCsF'
#define FILESPY_NAME_BUFFER_TAG         'bNsF'
#define FILESPY_DEVNAME_TAG             'nDsF'
#define FILESPY_USERNAME_TAG            'nUsF'
#define FILESPY_TRANSACTION_TAG         'xTsF'

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE) -1)
#endif

#define CONSTANT_UNICODE_STRING(s)   { sizeof( s ) - sizeof( WCHAR ), sizeof(s), s }

//
//  Delay values for KeDelayExecutionThread()
//  (Values are negative to represent relative time)
//

#define DELAY_ONE_MICROSECOND   (-10)
#define DELAY_ONE_MILLISECOND   (DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND        (DELAY_ONE_MILLISECOND*1000)



#define NTFS_NTC_DATA_HEADER             ((NODE_TYPE_CODE)0x0700)
#define NTFS_NTC_VCB                     ((NODE_TYPE_CODE)0x0701)
#define NTFS_NTC_FCB                     ((NODE_TYPE_CODE)0x0702)
#define NTFS_NTC_IRP_CONTEXT             ((NODE_TYPE_CODE)0x070A)

//
//  Don't use look-aside-list in the debug versions.
//
#ifndef DBG
#define DBG 1
#endif

#if DBG
#define MEMORY_DBG
#endif

//---------------------------------------------------------------------------
//  Macros for FileSpy DbgPrint levels.
//---------------------------------------------------------------------------



//---------------------------------------------------------------------------
//  Generic Resource acquire/release macros
//---------------------------------------------------------------------------

#define SpyAcquireResourceExclusive( _r, _wait )                            \
    (ASSERT( ExIsResourceAcquiredExclusiveLite((_r)) ||                     \
            !ExIsResourceAcquiredSharedLite((_r)) ),                        \
     KeEnterCriticalRegion(),                                               \
     ExAcquireResourceExclusiveLite( (_r), (_wait) ))

#define SpyAcquireResourceShared( _r, _wait )                               \
    (KeEnterCriticalRegion(),                                               \
     ExAcquireResourceSharedLite( (_r), (_wait) ))

#define SpyReleaseResource( _r )                                            \
    (ASSERT( ExIsResourceAcquiredSharedLite((_r)) ||                        \
             ExIsResourceAcquiredExclusiveLite((_r)) ),                     \
     ExReleaseResourceLite( (_r) ),                                         \
     KeLeaveCriticalRegion())

//---------------------------------------------------------------------------
//  Macro to test if we are logging for this device
//
//  NOTE: We don't bother synchronizing to check the gControlDeviceState since
//    we can tolerate a stale value here.  We just look at it here to avoid
//    doing the logging work if we can.  We synchronize to check the
//    gControlDeviceState before we add the log record to the gOutputBufferList
//    and discard the log record if the ControlDevice is no longer OPENED.
//---------------------------------------------------------------------------




//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------

//
//  Debugger definitions
//

typedef enum _SPY_DEBUG_FLAGS {

    SPYDEBUG_DISPLAY_ATTACHMENT_NAMES       = 0x00000001,
    SPYDEBUG_ERROR                          = 0x00000002,
    SPYDEBUG_TRACE_NAME_REQUESTS            = 0x00000004,
    SPYDEBUG_TRACE_IRP_OPS                  = 0x00000010,
    SPYDEBUG_TRACE_FAST_IO_OPS              = 0x00000020,
    SPYDEBUG_TRACE_FSFILTER_OPS             = 0x00000040,
    SPYDEBUG_TRACE_TX_OPS                   = 0x00000080,
    SPYDEBUG_TRACE_CONTEXT_OPS              = 0x00000100,
    SPYDEBUG_TRACE_DETAILED_CONTEXT_OPS     = 0x00000200,
    SPYDEBUG_TRACE_MISMATCHED_NAMES         = 0x00001000,
    SPYDEBUG_ASSERT_MISMATCHED_NAMES        = 0x00002000,

    SPYDEBUG_BREAK_ON_DRIVER_ENTRY          = 0x80000000

} SPY_DEBUG_FLAGS;

//
//  FileSpy global variables.
//
ULONG gFileSpyAttachMode;
FAST_MUTEX gSpyAttachLock;
/*
#if WINVER >= 0x0501
ULONG gFileSpyAttachMode = FILESPY_ATTACH_ALL_VOLUMES;
#else
ULONG gFileSpyAttachMode = FILESPY_ATTACH_ON_DEMAND;
#endif
*/
//UNICODE_STRING gInsufficientUnicode;// = CONSTANT_UNICODE_STRING(L"[-=Insufficient Resources=-]");
//UNICODE_STRING gEmptyUnicode ;//= CONSTANT_UNICODE_STRING(L"");

//
//  This lookaside list is used to allocate NAME_CONTROLs.  A name control
//  has a small buffer that should be big enough to handle most object names,
//  and can be resized if necessary.  These name controls are used in many
//  places to avoid allocating a large name buffer on the stack.
//
//  We allocate space for the name control from the lookaside list, which is
//  efficient because the size of the allocation is known and constant.  If more
//  buffer space is needed, we use NLCheckAndGrowNameControl which then
//  allocates more space from paged pool.
//

#define FILESPY_LOOKASIDE_SIZE  sizeof( NAME_CONTROL )

#pragma prefast(suppress: __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not an issue for kernel mode drivers");


//
//  The list of device extensions for the volume device objects we are
//  attached to (the volumes we are spying on).  Note:  This list does NOT
//  include FileSystem control device objects we are attached to.  This
//  list is used to answer the question "Which volumes are we logging?"
//

FAST_MUTEX gSpyDeviceExtensionListLock;
LIST_ENTRY gSpyDeviceExtensionList;



// NOTE:  Like the gControlDeviceStateLock, gOutputBufferLock MUST be a spinlock
//   since we try to acquire it during the completion path in SpyLog, which
//   could be called at DISPATCH_LEVEL (only KSPIN_LOCKs can be acquired at
//   DISPATCH_LEVEL).
//
// KSPIN_LOCK gOutputBufferLock;
// LIST_ENTRY gOutputBufferList;


// ULONG gLogSequenceNumber;// = 0;
// KSPIN_LOCK gLogSequenceLock;
// 

// LONG gMaxNamesToAllocate ;///= DEFAULT_MAX_NAMES_TO_ALLOCATE;
// LONG gNamesAllocated ;//= 0;
// 
// LONG gStaticBufferInUse ;//= FALSE;




//
//  Statistics definitions.  Note that we don't do interlocked operations
//  because loosing a count once in a while isn't important enough vs the
//  overhead.
//


#define INC_STATS(field)    (gStats.field++)
#define INC_LOCAL_STATS(var) ((var)++)

//
//  Attachment lock.
//

//extern FAST_MUTEX gSpyAttachLock;

//
//  FileSpy Registry values.
//

#define DEFAULT_MAX_RECORDS_TO_ALLOCATE 100;
#define DEFAULT_MAX_NAMES_TO_ALLOCATE   100;
#define DEFAULT_FILESPY_DEBUG_LEVEL     SPYDEBUG_ERROR;
#define MAX_RECORDS_TO_ALLOCATE         L"MaxRecords"
#define MAX_NAMES_TO_ALLOCATE           L"MaxNames"
#define DEBUG_LEVEL                     L"DebugFlags"
#define ATTACH_MODE                     L"AttachMode"


//
//  Our Control Device State information.
//

typedef enum _CONTROL_DEVICE_STATE {

    OPENED,
    CLOSED,
    CLEANING_UP

} CONTROL_DEVICE_STATE;
//
// NOTE 1:  There are some cases where we need to hold both the
//   gControlDeviceStateLock and the gOutputBufferLock at the same time.  In
//   these cases, you should acquire the gControlDeviceStateLock then the
//   gOutputBufferLock.
// NOTE 2:  The gControlDeviceStateLock MUST be a spinlock since we try to
//   acquire it during the completion path in SpyLog, which could be called at
//   DISPATCH_LEVEL (only KSPIN_LOCKs can be acquired at DISPATCH_LEVEL).
//
CONTROL_DEVICE_STATE gControlDeviceState;
KSPIN_LOCK gControlDeviceStateLock;

//
//  Given a device type, return a valid name.
//

 extern const PCHAR DeviceTypeNames[];
 extern  ULONG SizeOfDeviceTypeNames;

#define GET_DEVICE_TYPE_NAME( _type ) \
            ((((_type) > 0) &&      \
            ((_type) < (SizeOfDeviceTypeNames / sizeof(PCHAR)))) ? \
                DeviceTypeNames[ (_type) ] : \
                "[Unknown]")

//
//  Filespy global variables for transaction supports.
//

#if WINVER >= 0x0600

/*extern HANDLE gKtmTransactionManagerHandle;

extern HANDLE gKtmResourceManagerHandle;

extern PKRESOURCEMANAGER gKtmResourceManager;

extern NPAGED_LOOKASIDE_LIST gTransactionList;

extern UNICODE_STRING gNtfsDriverName;
*/
#endif

//---------------------------------------------------------------------------
//      Global defines
//---------------------------------------------------------------------------

//
//  Macro to test for device types we want to attach to.
//

#define IS_SUPPORTED_DEVICE_TYPE(_type) \
    (((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) )
//  || \
//      ((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM) || \
//      ((_type) == FILE_DEVICE_NETWORK_FILE_SYSTEM))


//---------------------------------------------------------------------------
//      Device Extension defines
//---------------------------------------------------------------------------

typedef enum _FSPY_DEV_FLAGS 
{

    //
    //  If set, this is an attachment to a volume device object,
    //  If not set, this is an attachment to a file system control device
    //  object.
    //

    IsVolumeDeviceObject = 0x00000001,

    //
    //  If set, logging is turned on for this device.
    //

    LogThisDevice = 0x00000002,

    //
    //  If set, contexts are initialized.
    //

    ContextsInitialized = 0x00000004,

    //
    //  If set, this is linked into the extension list.
    //

    ExtensionIsLinked = 0x00000008,

    //
    //  If set, this is an attachment to a NTFS volume.
    //

    IsAttachedToNTFS = 0x00000010,

} FSPY_DEV_FLAGS;



//
//  NL_EXTENSION is the part of a device extension that is needed
//  by the name lookup routines.  All the non-namelookup data contained
//  here should be needed by any filter.  Simply use this as part of
//  any filter's device extension.
//

typedef struct _NL_DEVICE_EXTENSION_HEADER {

	//
	//  Device Object this device extension is attached to
	//

	PDEVICE_OBJECT ThisDeviceObject;

	//
	//  Device object this filter is directly attached to
	//

	PDEVICE_OBJECT AttachedToDeviceObject;

	//
	//  When attached to Volume Device Objects, the physical device object
	//  that represents that volume.  NULL when attached to Control Device
	//  objects.
	//

	PDEVICE_OBJECT StorageStackDeviceObject;

	//
	//  DOS representation of the device name.
	//

	UNICODE_STRING DosName;

	//
	//  Name for this device.  If attached to a Volume Device Object it is the
	//  name of the physical disk drive.  If attached to a Control Device
	//  Object it is the name of the Control Device Object.  This is in the
	//  "\Device\...\" format.
	//

	UNICODE_STRING DeviceName;

} NL_DEVICE_EXTENSION_HEADER, *PNL_DEVICE_EXTENSION_HEADER;


//
//  Define the device extension structure that the FileSpy driver
//  adds to each device object it is attached to.  It stores
//  the context FileSpy needs to perform its logging operations on
//  a device.
//

extern PAGED_LOOKASIDE_LIST  gFileSpyNameBufferLookasideList;
typedef struct _FILESPY_DEVICE_EXTENSION {

    //
    //  Include all fields in NL_EXTENSION.  All these fields
    //  are used by the name lookup routines.  With this syntax
    //  we can reference NL_EXTENSION fields on a
    //  FILESPY_DEVICE_EXTENSION object directly.  For example:
    //      FILESPY_DEVICE_EXTENSION FilespyDevExt;
    //      PDEVICE_OBJECT foo;
    //      foo = FilespyDevExt->ThisDeviceObject;
    //

    NL_DEVICE_EXTENSION_HEADER NLExtHeader;

    //
    //  Linked list of devices we are attached to.
    //

    LIST_ENTRY NextFileSpyDeviceLink;

    //
    //  Flags for this device.
    //

    FSPY_DEV_FLAGS Flags;

    //
    //  Linked list of contexts associated with this volume along with the
    //  lock.
    //

    LIST_ENTRY CtxList;
    ERESOURCE CtxLock;

    //
    //  When renaming a directory there is a window where the current names
    //  in the context cache may be invalid.  To eliminate this window we
    //  increment this count every time we start doing a directory rename
    //  and decrement this count when it is completed.  When this count is
    //  non-zero then we query for the name every time so we will get a
    //  correct name for that instance in time.
    //

    ULONG AllContextsTemporary;

    //
    //  Names the user used to start logging this device.  This is
    //  used for devices where the DeviceType field of the device
    //  object is FILE_DEVICE_NETWORK_FILE_SYSTEM.  We cannot get
    //  a nice name (DOS device name, for example) for such devices,
    //  so we store the names the user has supplied and use them
    //  when constructing file names.
    //

    UNICODE_STRING UserNames;

	PDEVICE_OBJECT pShadowDevice;
	PDEVICE_OBJECT pRealDevice ;
	
	BOOLEAN		   bShadow;	
	WCHAR		   DeviceNames[50];
	 
	PVOID		   pVirtualRootDir;
 
	BOOLEAN		   bUsbDevice;
	UCHAR		*  pszUsbDiskSeriNUM;
	ULONG		   nLenExcludeTermiter;
	ULONG		   nSerialNumber;	
	PVOID		   pUsbSecureConfig;
} FILESPY_DEVICE_EXTENSION, *PFILESPY_DEVICE_EXTENSION;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////



WCHAR *   g_ShadowDeivceName;
WCHAR *   g_ShadowDosDeivceName;

PDRIVER_OBJECT gFileSpyDriverObject;
PDEVICE_OBJECT gControlDeviceObject;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
#define IS_FILESPY_DEVICE_OBJECT( _devObj )                               \
    (((_devObj) != NULL) &&                                               \
     ((_devObj)->DriverObject == gFileSpyDriverObject) &&                 \
     ((_devObj)->DeviceExtension != NULL))

#if WINVER >= 0x0600

typedef struct _FILESPY_TRANSACTION_CONTEXT {

    LIST_ENTRY List;

    //
    //  Pointer to a transaction object.
    //

    PKTRANSACTION Transaction;

    //
    //  Pointer to the device object Filespy attached to the file system stack
    //

    PDEVICE_OBJECT DeviceObject;

    //
    //  Pointer to a file object bound to this transaction.
    //  Note there can be multiple file objects bound to a transaction. 
    //  This file object is the one that triggers the enlistment. 
    //

    PFILE_OBJECT FileObject;

} FILESPY_TRANSACTION_CONTEXT, *PFILESPY_TRANSACTION_CONTEXT;

#endif

#if WINVER >= 0x0501
//
//  MULTIVERSION NOTE:
//
//  If built in the Windows XP environment or later, we will dynamically import
//  the function pointers for routines that were not supported on Windows 2000
//  so that we can build a driver that will run, with modified logic, on
//  Windows 2000 or later.
//
//  Below are the prototypes for the function pointers that we need to
//  dynamically import because not all OS versions support these routines.
//

typedef
NTSTATUS
(*PSPY_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS) (
    __in PDRIVER_OBJECT DriverObject,
    __in PFS_FILTER_CALLBACKS Callbacks
    );

typedef
NTSTATUS
(*PSPY_ENUMERATE_DEVICE_OBJECT_LIST) (
    __in  PDRIVER_OBJECT DriverObject,
    __out_bcount_part_opt(DeviceObjectListSize,(*ActualNumberDeviceObjects)*sizeof(PDEVICE_OBJECT)) PDEVICE_OBJECT *DeviceObjectList,
    __in  ULONG DeviceObjectListSize,
    __out PULONG ActualNumberDeviceObjects
    );

typedef
NTSTATUS
(*PSPY_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE) (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice,
    __out PDEVICE_OBJECT *AttachedToDeviceObject
    );

typedef
PDEVICE_OBJECT
(*PSPY_GET_LOWER_DEVICE_OBJECT) (
    __in  PDEVICE_OBJECT  DeviceObject
    );

typedef
PDEVICE_OBJECT
(*PSPY_GET_DEVICE_ATTACHMENT_BASE_REF) (
    __in PDEVICE_OBJECT DeviceObject
    );

typedef
NTSTATUS
(*PSPY_GET_STORAGE_STACK_DEVICE_OBJECT) (
    __in  PDEVICE_OBJECT  FileSystemDeviceObject,
    __out PDEVICE_OBJECT  *DiskDeviceObject
    );

typedef
PDEVICE_OBJECT
(*PSPY_GET_ATTACHED_DEVICE_REFERENCE) (
    __in PDEVICE_OBJECT DeviceObject
    );

typedef
NTSTATUS
(*PSPY_GET_VERSION) (
    __inout PRTL_OSVERSIONINFOW VersionInformation
    );


typedef struct _SPY_DYNAMIC_FUNCTION_POINTERS {

    PSPY_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS RegisterFileSystemFilterCallbacks;
    PSPY_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE AttachDeviceToDeviceStackSafe;
    PSPY_ENUMERATE_DEVICE_OBJECT_LIST EnumerateDeviceObjectList;
    PSPY_GET_LOWER_DEVICE_OBJECT GetLowerDeviceObject;
    PSPY_GET_DEVICE_ATTACHMENT_BASE_REF GetDeviceAttachmentBaseRef;
    PSPY_GET_STORAGE_STACK_DEVICE_OBJECT GetStorageStackDeviceObject;
    PSPY_GET_ATTACHED_DEVICE_REFERENCE GetAttachedDeviceReference;
    PSPY_GET_VERSION GetVersion;


} SPY_DYNAMIC_FUNCTION_POINTERS, *PSPY_DYNAMIC_FUNCTION_POINTERS;



#pragma prefast(suppress: __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not an issue for kernel mode drivers");
SPY_DYNAMIC_FUNCTION_POINTERS gSpyDynamicFunctions;// = {0};

ULONG gSpyOsMajorVersion;// = 0;
ULONG gSpyOsMinorVersion;// = 0;



//
//  Here is what the major and minor versions should be for the various
//  OS versions:
//
//  OS Name                                 MajorVersion    MinorVersion
//  ---------------------------------------------------------------------
//  Windows 2000                             5                 0
//  Windows XP                               5                 1
//  Windows Server 2003                      5                 2
//  Windows Vista                            6                 0
//

#define IS_WINDOWSXP_OR_LATER() \
    (((gSpyOsMajorVersion == 5) && (gSpyOsMinorVersion >= 1)) || \
     (gSpyOsMajorVersion > 5))

#define IS_VISTA_OR_LATER() \
    (gSpyOsMajorVersion >= 6)

#endif

//
//  Structure used to pass context information from dispatch routines to
//  completion routines for FSCTRL operations.  We need a different structures
//  for Windows 2000 from what we can use on Windows XP and later because
//  we handle the completion processing differently.
//


typedef struct _SPY_COMPLETION_CONTEXT_W2K {

   

    WORK_QUEUE_ITEM WorkItem;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    PDEVICE_OBJECT NewDeviceObject;

} SPY_COMPLETION_CONTEXT_W2K, *PSPY_COMPLETION_CONTEXT_W2K;

#if WINVER >= 0x0501
typedef struct _SPY_COMPLETION_CONTEXT_WXP_OR_LATER {

   

    KEVENT WaitEvent;

} SPY_COMPLETION_CONTEXT_WXP_OR_LATER,
  *PSPY_COMPLETION_CONTEXT_WXP_OR_LATER;
#endif

//
//  The context used to send getting the DOS device name off to a worker
//  thread.
//

typedef struct _DOS_NAME_COMPLETION_CONTEXT {

    WORK_QUEUE_ITEM WorkItem;

    //
    //  The device object to get the DOS name of.
    //

    PDEVICE_OBJECT DeviceObject;

} DOS_NAME_COMPLETION_CONTEXT, *PDOS_NAME_COMPLETION_CONTEXT;


#ifndef FORCEINLINE
#define FORCEINLINE __inline
#endif


////////////////////////////////////////////////////////////////////////
//
//    Prototypes for the routines this driver uses to filter the
//    the data that is being seen by this file systems.
//
//                   implemented in filespy.c
//
////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

VOID
DriverUnload (
    __in PDRIVER_OBJECT DriverObject
    );

NTSTATUS
SpyDispatch (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

NTSTATUS
SpyPassThrough (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );


NTSTATUS
PfpCreate  (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

NTSTATUS 
PfpCommonCreate(__in PVOID	IrpContextParam	,
				__in PDEVICE_OBJECT DeviceObject,
				__in PIRP			Irp);
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
    );

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
    );

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
    );

BOOLEAN
SpyFastIoQueryBasicInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_BASIC_INFORMATION)) PFILE_BASIC_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoQueryStandardInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_STANDARD_INFORMATION)) PFILE_STANDARD_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

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
    );

BOOLEAN
SpyFastIoUnlockSingle (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoUnlockAll (
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoUnlockAllByKey (
    __in PFILE_OBJECT FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

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
    );

VOID
SpyFastIoDetachDevice (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice
    );

BOOLEAN
SpyFastIoQueryNetworkOpenInfo (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Wait,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoMdlRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoMdlReadComplete (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoPrepareMdlWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __inout PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoMdlWriteComplete (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

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
    );

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
    );

BOOLEAN
SpyFastIoMdlReadCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoMdlWriteCompleteCompressed (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SpyFastIoQueryOpen (
    __in PIRP Irp,
    __out_bcount(sizeof(FILE_NETWORK_OPEN_INFORMATION)) PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT DeviceObject
    );


NTSTATUS
SpyCommonDeviceIoControl (
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __inout PIO_STATUS_BLOCK IoStatus
    );



//-----------------------------------------------------
//
//  These routines are only used if Filespy is attaching
//  to all volumes in the system instead of attaching to
//  volumes on demand.
//
//-----------------------------------------------------

NTSTATUS
SpyFsControl (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

NTSTATUS
SpyFsControlMountVolume (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

VOID
SpyFsControlMountVolumeCompleteWorker (
    __in PSPY_COMPLETION_CONTEXT_W2K Context
    );

NTSTATUS
SpyFsControlMountVolumeComplete (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PDEVICE_OBJECT NewDeviceObject
    );

NTSTATUS
SpyFsControlLoadFileSystem (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

NTSTATUS
SpyFsControlLoadFileSystemComplete (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

VOID
SpyFsControlLoadFileSystemCompleteWorker (
    __in PSPY_COMPLETION_CONTEXT_W2K Context
    );

VOID
SpyFsNotification (
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN FsActive
    );

NTSTATUS
SpyMountCompletion (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PVOID Context
    );

NTSTATUS
SpyLoadFsCompletion (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PVOID Context
    );

////////////////////////////////////////////////////////////////////////
//
//                  Library support routines
//                   implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

VOID
SpyReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    );

#if WINVER >= 0x0501
VOID
SpyLoadDynamicFunctions (
    VOID
    );

VOID
SpyGetCurrentVersion (
    VOID
    );
#endif

////////////////////////////////////////////////////////////////////////
//
//                  Memory allocation routines
//                   implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

PVOID
SpyAllocateBuffer (
    __inout_opt PLONG Counter,
    __in LONG MaxCounterValue,
    __out_opt PULONG RecordType
    );

VOID
SpyFreeBuffer (
    __in PVOID Buffer,
    __in PLONG Counter
    );

////////////////////////////////////////////////////////////////////////
//
//                      Logging routines
//                   implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////



#if WINVER >= 0x0501 /* See comment in DriverEntry */


#endif

NTSTATUS
SpyAttachDeviceToDeviceStack (
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice,
    __deref_out PDEVICE_OBJECT *AttachedToDeviceObject
    );


////////////////////////////////////////////////////////////////////////
//
//                    FileName cache routines
//                    implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////


NTSTATUS
SpyQueryInformationFile (
    __in PDEVICE_OBJECT NextDeviceObject,
    __in PFILE_OBJECT FileObject,
    __out_bcount_part(Length,*LengthReturned) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __out_opt PULONG LengthReturned
    );


NTSTATUS
SpyQueryCompletion (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PKEVENT SynchronizingEvent
    );

////////////////////////////////////////////////////////////////////////
//
//         Common attachment and detachment routines
//              implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyIsAttachedToDeviceByName (
    __in PNAME_CONTROL DeviceName,
    __out PBOOLEAN IsAttached,
    __deref_out PDEVICE_OBJECT *StackDeviceObject,
    __deref_out PDEVICE_OBJECT *OurAttachedDeviceObject
    );

BOOLEAN
SpyIsAttachedToDevice (
    __in PDEVICE_OBJECT DeviceObject,
    __deref_opt_out PDEVICE_OBJECT *AttachedDeviceObject
    );

BOOLEAN
SpyIsAttachedToDeviceW2K (
    __in PDEVICE_OBJECT DeviceObject,
    __deref_opt_out PDEVICE_OBJECT *AttachedDeviceObject
    );

#if WINVER >= 0x0501
BOOLEAN
SpyIsAttachedToDeviceWXPAndLater (
    __in PDEVICE_OBJECT DeviceObject,
    __deref_opt_out PDEVICE_OBJECT *AttachedDeviceObject
    );
#endif

NTSTATUS
SpyAttachToMountedDevice (
    __in PDEVICE_OBJECT DeviceObject,
    __in PDEVICE_OBJECT FilespyDeviceObject
    );

VOID
SpyCleanupMountedDevice (
    __in PDEVICE_OBJECT DeviceObject
    );

////////////////////////////////////////////////////////////////////////
//
//                 Start/stop logging routines and helper functions
//                  implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyAttachToDeviceOnDemand (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL UserDeviceName,
    __deref_out PDEVICE_OBJECT *FileSpyDeviceObject
    );

NTSTATUS
SpyAttachToDeviceOnDemandW2K (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL UserDeviceName,
    __deref_out PDEVICE_OBJECT *FileSpyDeviceObject
    );

#if WINVER >= 0x0501
NTSTATUS
SpyAttachToDeviceOnDemandWXPAndLater (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL UserDeviceName,
    __deref_out PDEVICE_OBJECT *FileSpyDeviceObject
    );
#endif

NTSTATUS
SpyStartLoggingDevice (
    __in PCWSTR UserDeviceName
    );

NTSTATUS
SpyStopLoggingDevice (
    __in PCWSTR deviceName
    );

////////////////////////////////////////////////////////////////////////
//
//       Attaching/detaching to all volumes in system routines
//                  implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyAttachToFileSystemDevice (
    __in PDEVICE_OBJECT DeviceObject,
    __in PNAME_CONTROL Name
    );

VOID
SpyDetachFromFileSystemDevice (
    __in PDEVICE_OBJECT DeviceObject
    );

#if WINVER >= 0x0501
NTSTATUS
SpyEnumerateFileSystemVolumes (
    __in PDEVICE_OBJECT FSDeviceObject
    );
#endif

////////////////////////////////////////////////////////////////////////
//
//             Private Filespy IOCTLs helper routines
//                  implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyGetAttachList (
    __out_bcount_part(BufferSize,*ReturnLength) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG_PTR ReturnLength
    );

VOID
SpyGetLog (
    __out_bcount(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __inout PIO_STATUS_BLOCK IoStatus
    );

VOID
SpyCloseControlDevice (
    VOID
    );

////////////////////////////////////////////////////////////////////////
//
//               Device name tracking helper routines
//                  implemented in fspylib.c
//
////////////////////////////////////////////////////////////////////////

NTSTATUS
SpyGetBaseDeviceObjectName (
    __in PDEVICE_OBJECT DeviceObject,
    __inout PNAME_CONTROL Name
    );

BOOLEAN
SpyFindSubString (
    __in PUNICODE_STRING String,
    __in PUNICODE_STRING SubString
    );

VOID
SpyStoreUserName (
    __inout PFILESPY_DEVICE_EXTENSION DeviceExtension,
    __in PNAME_CONTROL UserName
    );



#if WINVER >= 0x0501 /* See comment in DriverEntry */



#endif

////////////////////////////////////////////////////////////////////////
//
//                      COMMON Naming Routines
//
//  Common named routines implemented differently between name Context
//  and name Hashing
//
////////////////////////////////////////////////////////////////////////

VOID
SpyInitNamingEnvironment (
    VOID
    );

VOID
SpyInitDeviceNamingEnvironment (
    __in PDEVICE_OBJECT DeviceObject
    );

VOID
SpyCleanupDeviceNamingEnvironment (
    __in PDEVICE_OBJECT DeviceObject
    );



VOID
SpyNameDeleteAllNames (
    VOID
    );


#if USE_STREAM_CONTEXTS

////////////////////////////////////////////////////////////////////////
//
//                  Stream Context name routines
//                    implemented in fspyCtx.c
//
////////////////////////////////////////////////////////////////////////

//
//  Structure for tracking an individual stream context.  Note that the buffer
//  for the FileName is allocated as part of this structure and follows
//  immediately after it.
//

typedef struct _SPY_STREAM_CONTEXT
{

    //
    //  OS Structure used to track contexts per stream.  Note how we use
    //  the following fields:
    //      OwnerID     -> Holds pointer to our DeviceExtension
    //      InstanceId  -> Holds Pointer to FsContext associated
    //                     with this structure
    //  We use these values to get back to these structures
    //

    FSRTL_PER_STREAM_CONTEXT ContextCtrl;

    //
    //  Linked list used to track contexts per device (in our device
    //  extension).
    //

    LIST_ENTRY ExtensionLink;

    //
    //  This is a counter of how many threads are currently using this
    //  context.  The count is used in this way:
    //  - It is set to 1 when it is created.
    //  - It is incremented every time it is returned to a thread
    //  - It is decremented when the thread is done with it.
    //  - It is decremented when the underlying stream that is using it is freed
    //  - The context is deleted when this count goes to zero
    //

    LONG UseCount;

    //
    //  Holds the name of the file
    //

    UNICODE_STRING Name;

    //
    //  Flags for this context.  All flags are set or cleared via
    //  the interlocked bit routines except when the entry is being
    //  created, at this time we know nobody is using this entry.
    //



    //
    //  Contains the FsContext value for the stream we are attached to.  We
    //  track this so we can delete this entry at any time.
    //

    PFSRTL_ADVANCED_FCB_HEADER Stream;

} SPY_STREAM_CONTEXT, *PSPY_STREAM_CONTEXT;

//
//  Macros for locking the context lock
//

#define SpyAcquireContextLockShared(_devext) \
            SpyAcquireResourceShared( &(_devext)->CtxLock, TRUE )

#define SpyAcquireContextLockExclusive(_devext) \
            SpyAcquireResourceExclusive( &(_devext)->CtxLock, TRUE )

#define SpyReleaseContextLock(_devext) \
            SpyReleaseResource( &(_devext)->CtxLock )


VOID
SpyDeleteAllContexts (
    __in PDEVICE_OBJECT DeviceObject
    );

VOID
SpyDeleteContext (
    __in PDEVICE_OBJECT DeviceObject,
    __in PSPY_STREAM_CONTEXT pContext
    );

VOID
SpyLinkContext (
    __in PDEVICE_OBJECT DeviceObject,
    __in PFILE_OBJECT FileObject,
    __inout PSPY_STREAM_CONTEXT *ppContext
    );

NTSTATUS
SpyCreateContext (
    __in PDEVICE_OBJECT DeviceObject,
    __in PFILE_OBJECT FileObject,
    __in NAME_LOOKUP_FLAGS LookupFlags,
    __deref_out PSPY_STREAM_CONTEXT *pRetContext
    );

#define SpyFreeContext( pCtx ) \
    (ASSERT((pCtx)->UseCount == 0), \
     ExFreePool( (pCtx) ))

NTSTATUS
SpyGetContext (
    __in PDEVICE_OBJECT DeviceObject,
    __in PFILE_OBJECT pFileObject,
    __in NAME_LOOKUP_FLAGS LookupFlags,
    __deref_out PSPY_STREAM_CONTEXT *pRetContext
    );

PSPY_STREAM_CONTEXT
SpyFindExistingContext (
    __in PDEVICE_OBJECT DeviceObject,
    __in PFILE_OBJECT FileObject
    );

VOID
SpyReleaseContext (
    __in PSPY_STREAM_CONTEXT pContext
    );
#endif


#if !USE_STREAM_CONTEXTS
////////////////////////////////////////////////////////////////////////
//
//                  Name Hash support routines
//                  implemented in fspyHash.c
//
////////////////////////////////////////////////////////////////////////

typedef struct _HASH_ENTRY 
{

    LIST_ENTRY List;
    PFILE_OBJECT FileObject;
    UNICODE_STRING Name;

} HASH_ENTRY, *PHASH_ENTRY;


PHASH_ENTRY
SpyHashBucketLookup (
    __in PLIST_ENTRY ListHead,
    __in PFILE_OBJECT FileObject
);


VOID
SpyNameDelete (
    __in PFILE_OBJECT FileObject
    );

#endif


#if WINVER >= 0x0600

////////////////////////////////////////////////////////////////////////
//
//                  KTM transaction support routines
//                  implemented in fspyTx.c
//
////////////////////////////////////////////////////////////////////////


NTSTATUS
SpyIsAttachedToNtfs (
    __in PDEVICE_OBJECT DeviceObject,
    __out PBOOLEAN IsAttachToNtfs
    );

#endif

//
//  Include definitions
//





typedef struct _RTL_USER_PROCESS_PARAMETERS 
{   
	UCHAR			Reserved1[16];  
	PVOID			Reserved2[10];  
	UNICODE_STRING ImagePathName; 
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS,  *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA { 
	UCHAR		Reserved1[8];  
	PVOID		Reserved2[3];  
	LIST_ENTRY  InMemoryOrderModuleList;
} PEB_LDR_DATA,  *PPEB_LDR_DATA;

typedef struct _PEB { 
	UCHAR	Reserved1[2];  
	UCHAR	BeingDebugged;  
	UCHAR	Reserved2[1];  
	PVOID	Reserved3[2];
	PPEB_LDR_DATA Ldr;  
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  
	UCHAR	Reserved4[104]; 
	PVOID	Reserved5[52];  
	PVOID	PostProcessInitRoutine;  
	UCHAR	Reserved6[128];  
	PVOID	Reserved7[1];  
	ULONG	SessionId;
} PEB,  *PPEB;



LONG		g_SectorSize;


extern NPAGED_LOOKASIDE_LIST PfpFileLockLookasideList;
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
struct TOP_LEVEL_CONTEXT;

//
//  Context structure for asynchronous I/O calls.  Most of these fields
//  are actually only required for the Read/Write Multiple routines, but
//  the caller must allocate one as a local variable anyway before knowing
//  whether there are multiple requests are not.  Therefore, a single
//  structure is used for simplicity.
//

typedef struct _NTFS_IO_CONTEXT
{

	//
	//  These two fields are used for multiple run Io
	//

	LONG IrpCount;
	PIRP MasterIrp;
	UCHAR IrpSpFlags;
	BOOLEAN AllocatedContext;
	BOOLEAN PagingIo;

	union 
	{


		//  This element handles the asynchronous non-cached Io


		struct 
		{

			PERESOURCE Resource;
			ERESOURCE_THREAD ResourceThreadId;
			ULONG RequestedByteCount;
			LONGLONG StartingOffset;
		} Async;


		//  and this element handles the synchronous non-cached Io.


		KEVENT SyncEvent;

	} Wait;

	PIRP OriginatingIrp ;
	BOOLEAN bNeedEncrypt;

} NTFS_IO_CONTEXT;


//////////////////////////////////////////////////////////////////////////
// 下面的数据结构是由多个usermode的 file_object 对应一个在磁盘上打开的FILE_OBJECT
//////////////////////////////////////////////////////////////////////////

typedef struct _USERFILEOBEJCT
{
	LIST_ENTRY		list;	

	PFILE_OBJECT	UserFileObj;	
	PFILE_OBJECT	DiskFileobj;
	HANDLE			DiskFileHandle;

}USERFILEOBJECT,*PUSERFILEOBJECT;



typedef struct _DISKFILEOBEJECT
{
	LIST_ENTRY		list;					//

	LIST_ENTRY		UserFileObjList;		// USERFILEOBJECT 的链表 usermode 传递过来的文件对象，可以有多个打开的usermode的文件对象
	ERESOURCE		UserObjectResource;
	LONG			nReferenceCount;		//跟踪磁盘文件打开的被引用的次数
	PFILE_OBJECT	pDiskFileObjectWriteThrough;		//对应于usermode 在磁盘上打开的 实际的文件对象
	HANDLE			hFileWriteThrough	;				//打开的磁盘上的文件的句柄：主要是内核中使用ntcreatefile NTReadFile 时候使用的
	PDEVICE_OBJECT	pOurSpyDevice;
	PVOID			pFCB;

	BOOLEAN			bFileNOTEncypted; //文件已经存在 ，并且是明文形式
	BOOLEAN			bAllHandleClosed;
	BOOLEAN			bNeedBackUp;
	UNICODE_STRING	FullFilePath;			//打开的 文件对应的全路径
	UNICODE_STRING	FileNameOnDisk;
	//////////////////////////////////////////////////////////////////////////
	HANDLE			hBackUpFileHandle;
	PFILE_OBJECT	hBackUpFileObject;
	BOOLEAN			bProcessOpened;
	BOOLEAN			bUnderSecurFolder;
	BOOLEAN			bFileTypeNeedEncrypt;
	BOOLEAN			bOpeningAfterAllGothroughCleanup;
	PVOID			pVirtualDiskFile; 
	PERESOURCE		pParentDirResource;
}DISKFILEOBJECT,*PDISKFILEOBJECT;



typedef struct _DISKDIROBEJECT
{
	LIST_ENTRY		list;
	PVOID			pParent;
	ERESOURCE*		AccssLocker;
	UNICODE_STRING	DirName;
	
	LIST_ENTRY		ChildVirtualDirLists;
	
	LIST_ENTRY		VirtualDiskFileLists;
	BOOLEAN			bRoot;
}DISKDIROBEJECT,*PDISKDIROBEJECT;

typedef struct _VirtualDiskFile
{
	LIST_ENTRY		list;
	UNICODE_STRING	FileName;
	ERESOURCE*		pVirtualDiskLocker;
	LIST_ENTRY		listForDiskFileObject;
	//PDISKFILEOBJECT pDiskFileObj;
	DISKDIROBEJECT* pParentDir; 
}VIRTUALDISKFILE,*PVIRTUALDISKFILE;
#define CCB_FLAG_CLEANUP 0x01
typedef struct _TAGPFPCCB
{
	UCHAR Flags;
	int		i;
	WCHAR  szExeName[50];
}PfpCCB,*PPfpCCB;

typedef struct _TAGNTFSFCB
{
	UCHAR sz[64];
	PERESOURCE Resource;
	PERESOURCE PageioResource;

}NTFSFCB ,*PNTFSFCB;

UCHAR szVcbPlacer[ 300];
typedef struct _TAGPFPFCB
{
	FSRTL_ADVANCED_FCB_HEADER	Header;
	// added for aglined to NTFS;
	PERESOURCE					Resource;// this will be treated as pageio resource
	UCHAR						szAlinged[4];
	LIST_ENTRY					FcbLinks;
	NTFSFCB*					NtFsFCB;//+0x050 // this filed will be used by call back of ntfs.
	PVOID						Vcb;//+0x054
	ULONG						State            ;
	ULONG						NonCachedUnCleanupCount;
	ULONG						UncleanCount;
	ULONG						OpenCount;
	SHARE_ACCESS				ShareAccess;//+0x068
	ULONG						AttributeTypeCode_PLACE ;
	UNICODE_STRING				AttributeName_PLACE    ;
	PFILE_OBJECT				FileObject_PLACE      ;
	PVOID						NoPagedFCB;
	PVOID						LazyWriteThread[2];
	SECTION_OBJECT_POINTERS		SegmentObject;
	//
	//  The following field is used by the oplock module
	//  to maintain current oplock information.
	//

	OPLOCK		Oplock;

	//
	//  The following field is used by the filelock module
	//  to maintain current byte range locking information.
	//
	// this field is protected by the fastmutex in Header.

	PLIST_ENTRY PendingEofAdvances;
	PFILE_LOCK	FileLock;
	ULONG		FcbState;
	ULONG		CCBFlags;

	UCHAR		Flags;

	LONGLONG	CreationTime;                                          //  offset = 0x000

	LONGLONG	LastModificationTime;                                  //  offset = 0x008
	//
	//  Last time any attribute was modified.
	//

	LONGLONG		LastChangeTime;                                        //  offset = 0x010

	//
	//  Last time the file was accessed.  This field may not always
	//  be updated (write-protected media), and even when it is
	//  updated, it may only be updated if the time would change by
	//  a certain delta.  It is meant to tell someone approximately
	//  when the file was last accessed, for purposes of possible
	//  file migration.
	//

	LONGLONG		LastAccessTime;                                        //  offset = 0x018


	ULONG			Attribute;
	ULONG			LinkCount;

	LONGLONG		CurrentLastAccess;

	BOOLEAN			bNeedEncrypt;
	PDISKFILEOBJECT	pDiskFileObject;

	BOOLEAN			bModifiedByOther; //当这个cleanup里面把 UncleanCount 减为零的时候，就说明所有的Process 全部把自己的close 关闭了
	//如果没有立即收到Close 的irp话，那么就是说明系统有这个Fileobject的reference。
	//当可信的进程打开的时候很显然肯定要increament 这个UncleanCount 的值 ，同时把这个条件 设为FALSE
	//当非可信的进程有要求写的时候，判断是不是为TRUE，如果是那么ok 让它打开，
	//当非可惜进程要求写的时候，判断为false，那么返回 说明这个文件正在编辑，以只读方式打开？？？
	PFAST_MUTEX		Other_Mutex;
	UCHAR			szAlinged1[36];
	PVOID			CreateSectionThread;	//+0x12c
	UCHAR			szAligned2[20]; //+0x130
	BOOLEAN			bWriteHead;
}PfpFCB,*PPfpFCB;


//////////////////////////////////////////////////////////////////////////
//下面的数据结构 记录了每个进程的那些的类型的文件需要加密的（读和写）
//////////////////////////////////////////////////////////////////////////
#define FILETYPELEN 50
typedef struct _tagFILETYPE
{
	LIST_ENTRY	list;

	WCHAR 		FileExt[50];// 文件类型，也就是文件的后缀
	BOOLEAN		bBackUp;
	BOOLEAN		bSelected;
}FILETYPE,*PFILETYPE;

////////////////////////////////////////////////////////////////////////////
// 下面这个结构也写在磁盘上，初始化的时候要从磁盘文件读进来
//1：初始化的时候要从磁盘文件读进来
//2：程序在用户设置以后，会立即更新磁盘上的数据
//	(1):用户添加一个进程
//	(2):用户删除一个进程
//	(3):用户对一个进程删除一个或多个文件类型
//	(4):用户对一个进程添加一个或多个文件类型
//////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
//访问这个数据结构的时候是同步的 ，所以没有必要使用同步方式的数据
//////////////////////////////////////////////////////////////////////////

#define PROCESSHASHVALULENGTH  512
typedef struct _tagCreatedFile
{
	LIST_ENTRY  list;
	WCHAR szDriverLetter[3];
	WCHAR *szFullPathWithOutDriverLetter;
}PROCESSCREATEDFILE,*PPROCESSCREATEDFILE;

typedef struct _tagCCBRecord
{
	LIST_ENTRY   list;
	PfpCCB*		 pCCB;	
}CCBRECORD,*PCCBRECORD;
//每个进程创建的文件
typedef struct _tagCreatedFileWithCCB
{
	LIST_ENTRY  list;
	WCHAR		szDriverLetter[3];
	WCHAR *		szFullPathWithOutDriverLetter;
	LIST_ENTRY  ListHeadForCCofFileObject;
}PROCESSCREATEDFILEWithCCBs,*PPROCESSCREATEDFILEWithCCBs;


typedef struct _tagHANDLEOFEXE
{
	LIST_ENTRY  list;
	HANDLE		Handle;
	LIST_ENTRY  listForDiskFile; //这个是我们创建的文件
	LIST_ENTRY  ListForUsermodeFile;
}HandleOfExe,*PHandleOfExe;



typedef struct _tagPROCESSINFO
{
	LIST_ENTRY		list;

	HANDLE			hProcess;			//每个当前在运行的进程的ID,每个进程在创建的时候 
	LIST_ENTRY		hProcessList;			
	FAST_MUTEX      HandleMutex;
	//我们要把这个进程的句柄放到这个内存数据段中，这个值是不保存到磁盘上的

	UNICODE_STRING	ProcessName ;		// ！！！！为了方便，现在只检测进程的名字来判断它访问的文件类型是不是加密的

	UCHAR			ProcessHashValue[PROCESSHASHVALULENGTH];	//每个进程的hash 值 用来判断是不是伪造的进程。！！！！
	//产品中应该使用进程的Image的一部分的hash值来判断
	BOOLEAN			bAllowInherent;

	FAST_MUTEX      FileTypesMutex;	
	LIST_ENTRY		FileTypes;			//此进程所访问或者创建的需要加密的文件类型
	LIST_ENTRY		FileTypesForBrowser[5];			
	LONG			nRef;
	BOOLEAN			bNeedBackUp;
	BOOLEAN			bEnableEncrypt;
	BOOLEAN			bForceEncryption;
	BOOLEAN			bAlone;
	BOOLEAN			bBowser;
	BOOLEAN			bAllCreateExeFile;
	ULONG			nEncryptTypes;
}PROCESSINFO,*PPROCESSINFO;


typedef short NODE_TYPE_CODE;
typedef short NODE_BYTE_SIZE;
typedef NTFS_IO_CONTEXT *PNTFS_IO_CONTEXT;
typedef struct _IRP_CONTEXT 
{

	//
	//  Type and size of this record (must be NTFS_NTC_IRP_CONTEXT)
	//
	//  Assumption here is that this structure is allocated from pool so
	//  base of structure is on an odd 64-bit boundary.
	//

	NODE_TYPE_CODE NodeTypeCode;
	NODE_BYTE_SIZE NodeByteSize;

	//
	//  Irp Context flags
	//

	ULONG Flags;

	//
	//  The following field contains the NTSTATUS value used when we are
	//  unwinding due to an exception.  We will temporarily store the Ccb
	//  for a delayed or deferred close here while the request is queued.
	//

	NTSTATUS ExceptionStatus;


	//
	//  This is the IrpContext for the top level request.
	//

	struct _IRP_CONTEXT *TopLevelIrpContext;

	//
	//  The following union contains pointers to the IoContext for I/O
	//  based requests and a pointer to a security context for requests
	//  which need to capture the subject context in the calling thread.
	//

	union 
	{


		//  The following context block is used for non-cached Io.

		struct _NTFS_IO_CONTEXT *NtfsIoContext;

		//  The following is the captured subject context.

		PSECURITY_SUBJECT_CONTEXT SubjectContext;

		//  The following is used during create for oplock cleanup.

		struct _OPLOCK_CLEANUP *OplockCleanup;

	} Union;

	//
	//  A pointer to the originating Irp.  We will store the Scb for
	//  delayed or async closes here while the request is queued.
	//

	PIRP OriginatingIrp;

	//
	//  Major and minor function codes copied from the Irp
	//

	UCHAR MajorFunction;
	UCHAR MinorFunction;

	//
	//  The following field is used to maintain a queue of records that
	//  have been deallocated while processing this irp context.
	//

	LIST_ENTRY RecentlyDeallocatedQueue;

	//PIO_WORKITEM  
	//  This structure is used for posting to the Ex worker threads.
	//

	WORK_QUEUE_ITEM WorkQueueItem;
	PIO_WORKITEM	WorkItem;


	PfpFCB*			FcbWithPagingExclusive;

	//
	//  Originating Device (required for workque algorithms)
	//

	PDEVICE_OBJECT RealDevice;

	PFILE_OBJECT   Fileobject_onDisk;
	PDEVICE_OBJECT pNextDevice;
	PPROCESSINFO   pProcessInfo;
	HANDLE		   hProcessOrignal;
} IRP_CONTEXT;
typedef IRP_CONTEXT *PIRP_CONTEXT;

//
//  The top level context is used to determine whether this request has
//  other requests below it on the stack.
//

typedef struct _TOP_LEVEL_CONTEXT 
{

	BOOLEAN TopLevelRequest;
	BOOLEAN ValidSavedTopLevel;
	BOOLEAN OverflowReadThread;

	ULONG Ntfs;

	PIRP SavedTopLevelIrp;

	PIRP_CONTEXT TopLevelIrpContext;

} TOP_LEVEL_CONTEXT;
typedef TOP_LEVEL_CONTEXT *PTOP_LEVEL_CONTEXT;


//
//  The Irp Context record is allocated for every orginating Irp.  It is
//  created by the Fsd dispatch routines, and deallocated by the
//  NtfsComplete request routine.
//


#define IRP_CONTEXT_FLAG_EXCESS_LOG_FULL    (0x00000001)
#define IRP_CONTEXT_FLAG_WROTE_LOG          (0x00000002)
#define IRP_CONTEXT_FLAG_WAIT               (0x00000004)
#define IRP_CONTEXT_FLAG_WRITE_THROUGH      (0x00000008)
#define IRP_CONTEXT_LARGE_ALLOCATION        (0x00000010)
#define IRP_CONTEXT_DEFERRED_WRITE          (0x00000020)
#define IRP_CONTEXT_FLAG_ALLOC_CONTEXT      (0x00000040)
#define IRP_CONTEXT_FLAG_ALLOC_SECURITY     (0x00000080)
#define IRP_CONTEXT_MFT_RECORD_15_USED      (0x00000100)
#define IRP_CONTEXT_MFT_RECORD_RESERVED     (0x00000200)
#define IRP_CONTEXT_FLAG_IN_FSP             (0x00000400)
#define IRP_CONTEXT_FLAG_RAISED_STATUS      (0x00000800)
#define IRP_CONTEXT_FLAG_IN_TEARDOWN        (0x00001000)
#define IRP_CONTEXT_FLAG_ACQUIRE_VCB_EX     (0x00002000)
#define IRP_CONTEXT_FLAG_CALL_SELF          (0x00004000)
#define IRP_CONTEXT_FLAG_DONT_DELETE        (0x00008000)
#define IRP_CONTEXT_FLAG_HOTFIX_UNDERWAY    (0x00010000)
#define IRP_CONTEXT_FLAG_FORCE_POST         (0X00020000)
#define IRP_CONTEXT_FLAG_WRITE_SEEN         (0X00040000)
#define IRP_CONTEXT_FLAG_MODIFIED_BITMAP    (0x00080000)
#define IRP_CONTEXT_FLAG_DASD_OPEN          (0x00100000)
#define IRP_CONTEXT_FLAG_QUOTA_DISABLE      (0x00200000)
#define IRP_CONTEXT_FLAG_CHECKPOINT_ACTIVE  (0x01000000)

//////////////////////////////////////////////////////////////////////////





PPROCESSCREATEDFILEWithCCBs
PfpCreateProcessCreatedFileWithCCB(PWCHAR szDriver,PWCHAR pszFilePath);

VOID
PfpDeleteProcessCreatedFileWithCCB(PPROCESSCREATEDFILEWithCCBs* ppFileWithCCB);
BOOLEAN 
PfpCanProcessbeStoped(PCHAR pHashValue,ULONG nHashLen);


VOID
PfpDeleteCCBFromHandleOfExe(HandleOfExe *pHandleOfexe,
							PPfpCCB pCCB,
							BOOLEAN *bEmpty,
							PPROCESSCREATEDFILEWithCCBs* pProcessCreatedFileWithCCB);

PPROCESSCREATEDFILEWithCCBs
PfpGetCreatedFileWithCCBFromHandleOfexe(HandleOfExe *pHandleOfexe,
										WCHAR* pszDriverLetter,
										PWCHAR pszFilePathWithoutDriver);

VOID
PfpAddCCBIntoProcessCreatedFilesWithCCBs(PPROCESSCREATEDFILEWithCCBs pCreatesFilesWithCCB,
										 PCCBRECORD pCcbRecord);

VOID 
PfpAddCreateFilesWithCCBsIntoHandleOfExe(HandleOfExe *pHandleOfexe,
										 PPROCESSCREATEDFILEWithCCBs pCreatesFilesWithCCB);

PHandleOfExe
PfpGetHandleInfoUsingHanlde(IN PPROCESSINFO pProcessInfo,
							IN HANDLE hProcess);

VOID 
PfpAddCreatedFileIntoProcess(IN PPROCESSINFO pProcessInfo,
							 IN HANDLE HandleOfProcess,
							 IN WCHAR* Driver,
							 IN WCHAR* szFullPath);

BOOLEAN 
PfpIsFileInProcessCreated(IN PPROCESSINFO pProcessInfo,
						  IN HANDLE HandleOfProcess,
						  IN WCHAR* Driver,
						  IN WCHAR* szFullPath);

BOOLEAN 
PfpIsFileInProcessCreated_Internal(IN PHandleOfExe pHandleOfProcess,
								   IN WCHAR* Driver,
								   IN WCHAR* szFullPath);
VOID
PfpRemoveAllCreatedFile(IN PHandleOfExe pHandleInfo);


#define MAX_PATH 512
typedef struct _CONFIGDATA
{
	ULONG	nNextOffset;
	BOOLEAN bBackup;
	WCHAR	szEXEPath [MAX_PATH];
	UCHAR	EXEHashValue[PROCESSHASHVALULENGTH];
	LONG	bAllowInherent;
	LONG	bEnableEncrypt;
	LONG	bForceEncryption;
	LONG	szBytesOfFileTypes;
	LONG	bAbone;
	LONG    bCreateExeFile;
	LONG    bBrowser;
	ULONG	BrowserEncryptTypeValue;
	WCHAR	szFileTypes[1];
	
}ConfigData,*PConfigData;


typedef struct _RECYCLEPATH
{
	LIST_ENTRY	list;
	PWCHAR		pPath ;
}RecyclePath,*PRecyclePath;


LIST_ENTRY	g_RecyclePaths;
FAST_MUTEX	g_fastRecycle;
WCHAR		szRootforCycle[3];


VOID		AddIntoRecycleList(PWCHAR pPath);
VOID		ClearAllRecycleList();
BOOLEAN		IsRecyclePath(PWCHAR pPath);

typedef struct _BackupType
{
	WCHAR			szFiletype[20];
	BOOLEAN			bBackup;
	BOOLEAN			bSelected;
}BackupType, *PBackupType;

typedef struct _BackUpSetting
{	
	UCHAR 			HashValue[PROCESSHASHVALULENGTH];
	LONG			nCount;
	BackupType		BackupInfo;
}BackUpSetting,*PBACKUPSETTING;


typedef struct _ENABLEPROCESS
{
	UCHAR 			HashValue[PROCESSHASHVALULENGTH];
	BOOLEAN			bEnable;
}EnableProc,*PEnableProc;

BOOLEAN 
PfpSetBackupForProcess(PPROCESSINFO pProcInfo,BackUpSetting* pBackInfo);

BOOLEAN 
PfpGetBackupInfoFromProg(PPROCESSINFO pProcInfo,BackUpSetting* pBackInfo);

BOOLEAN
PfpNeedBackup(UCHAR* szHashValue,WCHAR* szFileType);

BOOLEAN
PfpIsFileTypeNeedBackup(PPROCESSINFO pProcInfo,WCHAR* szFileType);


VOID 
PfpEnableBackupForProg(UCHAR* szHashValue,BOOLEAN bEnable);

VOID 
PfpEnableEnCryptForProg(UCHAR* szHashValue,BOOLEAN bEnable);

VOID 
PfpEnableInherForProg(UCHAR* szHashValue,BOOLEAN bEnable);

VOID 
PfpSetForcEncryption(UCHAR* szHashValue,BOOLEAN bEnable);

PHandleOfExe	
PfpAddHanldeIntoProcessInfo(
							IN HANDLE hHandle,
							IN PPROCESSINFO	pProcInfo
							);

ULONG 
PfpCalcProgramLen();

BOOLEAN 
PfpCopyAllProgramsIntoBuffer(IN PVOID pBuffer,
							 IN ULONG* Len);
PVOID 
PfpGetAllPrograms(ULONG* szLen );

NTSTATUS
PfpCopyOneDataIntoUserBuffer(IN OUT PVOID		pUserBuffer,
							 IN OUT ULONG *		Len,
							 IN PPROCESSINFO	pProcInfo);

VOID 
PfpCopyFileTypesIntoBuffer(
						   IN PVOID pBuffer,
						   IN PPROCESSINFO pProcInfo);

ULONG 
PfpCalcFileTypesLen(IN PPROCESSINFO pProcInfo);

// VOID 
// PfpAddHandleIntoProceInfo(
// 						  IN OUT PPROCESSINFO	pProcInfo,
// 						  IN HANDLE				Handle
// 						  );
VOID 
PfpDeleteHandle(
					   IN OUT PPROCESSINFO	pProcInfo,
					   IN HANDLE			Handle
						  );

VOID 
PfpDeleteAllHandle(
				   IN OUT PPROCESSINFO	pProcInfo				
				   );


BOOLEAN 
PfpDelProcessInfo(UCHAR* pszHashValue,ULONG nLength);

BOOLEAN 
PfpClearAllProcInfos();



 
//FAST_MUTEX  g_ProcessInofsLock;
LIST_ENTRY	g_ProcessInofs;

ERESOURCE   g_ProcessInfoResource;


PPROCESSINFO  
PfpCreateAndInitProcessInfo(IN UNICODE_STRING FullPath,
							IN UCHAR*         HashValue,
							IN ULONG          szLen,
							IN HANDLE         hProcess,
							IN BOOLEAN        bInherite,
							IN PWCHAR		  pszFileTypes,
							IN BOOLEAN		  bNeedBackup,
							IN BOOLEAN		  bEnAbleEncrypt,
							IN BOOLEAN		  bForceEncryption,
							IN BOOLEAN		  bAlone,
							IN BOOLEAN		  bBrowser,
							IN BOOLEAN		  bCreateExEFile,
							IN ULONG		  lEncryptTypeValue
							);

VOID 
AddProcessInfoIntoGlobal(PConfigData		pData);

VOID 
PfpInitProcessInfosFromBuffer(IN PUCHAR pBuffer,
							  IN ULONG nLen,
							  IN OUT IO_STATUS_BLOCK *IoStatus);

VOID
PfpAddProcessIntoGlobal(IN PPROCESSINFO pProcessInfo);

VOID
PfpAddFileTypesToProcessInfo(IN PPROCESSINFO pProcessInfo,
							 IN PWCHAR pszFileTypes);

VOID 
PfpAddFileTypeIntoProcessInfo(IN PPROCESSINFO pProcessInfo,
							  IN PWCHAR pszFileType,BOOLEAN bSelected, BOOLEAN bBackup);

PFILETYPE
PfpGetFileTypeFromProcessInfo(IN PPROCESSINFO pProcessInfo,
							  IN PWCHAR pszFileType);

VOID 
PfpDeleteAllFileTypesOfProcessInfo(
								   IN PPROCESSINFO pProcessInfo);

VOID 
PfpDeleteFileTypeFromProcessInfo(IN PPROCESSINFO pProcessInfo,
								 IN PWCHAR       pszFileType);


//////////////////////////////////////////////////////////////////////////
BOOLEAN			
IncreaseNum(__in PWCHAR pNum,
			__in LONG nIndex);

NTSTATUS		
GetProcessImageName(HANDLE hProcess,PUNICODE_STRING ProcessImageName);

BOOLEAN
QuerySymbolicLink(PUNICODE_STRING SymbolicLinkName,WCHAR* pBuffer,USHORT BufferLen);

BOOLEAN	
VFSVolumeDeviceToDosName(UNICODE_STRING DeviceHardLink,WCHAR* DriveLetter);

BOOLEAN	VFSVolumeDeviceToDosNameEx(UNICODE_STRING DeviceHardLinkPath,WCHAR* DriveLetter,long *HardDiskLeninchars);
VOID 
ReplaceHardDeviceNameWithDos(PUNICODE_STRING ProcessImageName);
BOOLEAN			
PfpGetHashValueForEXE(PWCHAR	szFullPath,
					  ULONG		nFullPathSizeInBytes,
					  UCHAR*	HashValue,
					  ULONG	nLegnth);

PDEVICE_OBJECT	
PfpGetSpyDeviceFromName(PWCHAR pName);

BOOLEAN
PfpGetDeviceDosNameFromFileHandle(IN HANDLE  hFile,
								  OUT WCHAR * szDosName);

BOOLEAN			
PfpCopyDeviceChar(PWCHAR		pChar ,
				  PWCHAR		pProcessImagePath,
				  __out LONG *	Length);

/*BOOLEAN			
PfpGetExeFileHash(	PWCHAR	szFullPath,
					UCHAR*	HashValue,
					LONG	nLegnth);*/

VOID 			
PfpUpperCase(PWCHAR pszBuffer);


BOOLEAN			
PfpFileExtentionExistInProcInfo(
								PPROCESSINFO  ProcInof,
								PWCHAR ext
								); 	   

BOOLEAN			
PfpFileExtentionExistInProcInfoNotSelete(
								PPROCESSINFO  ProcInof,
								PWCHAR ext
								); 	

PPROCESSINFO	
PfpGetProcessInfoUsingProcessId(
							 HANDLE hProcess
							 );

BOOLEAN
PfpIsThereValidProcessInfo();

PPROCESSINFO	
PfpGetProcessInfoUsingHashValue(
								UCHAR * pHash,
								LONG Length,
								PWCHAR pszProcessImageFullPath
								);

PPROCESSINFO	
PfpGetProcessInfoUsingFullPath(
								PWCHAR pszProcessImageFullPath
								);

BOOLEAN			
PfpGetFileExtFromFileObject(
							PFILE_OBJECT pObject,
							WCHAR * FileExt,
							LONG* nLength
							);

BOOLEAN			
PfpGetFileExtFromFileName(
							PUNICODE_STRING pFilePath,
							WCHAR * FileExt,
							LONG* nLength
							);

BOOLEAN	
PfpPROCESSINFOHasProtectedFileTypes(
									PPROCESSINFO ProcInfo);


NTSTATUS 
PfpDoBackUpWorkAboutCreate(PDISKFILEOBJECT pDiskFileObject,
						   PDEVICE_OBJECT pDevice,
						   PPROCESSINFO pProcessInfo,
						   PWCHAR FullPathName);
//////////////////////////////////////////////////////////////////////////


LIST_ENTRY g_ProcessExclude;//在内存中记录了所有被打开的磁盘文件
ERESOURCE   g_ProcessExcludeResource;
//FAST_MUTEX	g_ProcessExcludeFastMutex;

typedef struct _PROCESSEXCLUD
{
	HANDLE Handle;
	LIST_ENTRY list;
}ProcessExclud,*PProcessExclud;

BOOLEAN 
PfpFindExcludProcess(HANDLE hHandle);

BOOLEAN 
PfpAddExcludProcess(HANDLE hHandle);

BOOLEAN 
PfpDelExcludProcess(HANDLE hHandle);

//////////////////////////////////////////////////////////////////////////

LIST_ENTRY g_DiskObjects;//在内存中记录了所有被打开的磁盘文件

//FAST_MUTEX	g_DiskFileObjectsFastMutex;

//////////////////////////////////////////////////////////////////////////
//这个pFullPaht 一定要是唯一的 标识这个文件的，不能是通过其他方式打开的，
//也就是说不能是link 或者后面有:$DATA 后缀 也不能是dos下面是用的短的文件名。
//////////////////////////////////////////////////////////////////////////

PDISKFILEOBJECT 
PfpGetDiskFileObject(
					UNICODE_STRING*  FullPath_U,
					PLIST_ENTRY     pListHead);

PDISKFILEOBJECT 
PfpGetDiskFileObjectByUsingFCBONDisk(
									 PVOID FileObjectContext,					 
									 PLIST_ENTRY     pListHead	 );

FAST_MUTEX*
PfpGetDiskFileObjectMutex(PDEVICE_OBJECT  pSpyDevice );

PERESOURCE
PfpGetDeviceResource(PDEVICE_OBJECT  pSpyDevice );

PDISKDIROBEJECT
PfpGetVirtualRootDirFromSpyDevice(PDEVICE_OBJECT  pSpyDevice );
//////////////////////////////////////////////////////////////////////////
//这个是由用户的FILEOBJECT 来得到对应的在磁盘上的FILEOBJECT
//因为我们在FILEOBJECT的Context2里面存放了一个DISKFILEOBEJCT的指针，这样可以不要搜索对应的DISKFILEOBJECT
typedef enum _tagFILEOBJECTTYPE
{
	FILEOBJECT_FROM_USERMODE,
	FILEOBEJCT_ON_DISK,
	FILEOBJECT_WITH_WRITETHROUGH
}FILEOBJECTTYPE;


PUSERFILEOBJECT
PfpGetUserFileobjects(PLIST_ENTRY pUserFileobjects,
					  PFILE_OBJECT pUserObject);
BOOLEAN
PfpAreAllFileOBJECTEnterCleanup(PLIST_ENTRY pUserFileobjects);

BOOLEAN		
PfpCheckCreateFileResult(NTSTATUS ntstatus, 
						 IO_STATUS_BLOCK * iostatus);



//////////////////////////////////////////////////////////////////////////
/*
these routines will be used to read and write the encryption head.
*/

NTSTATUS
PfpWrite (
		  __in PDEVICE_OBJECT DeviceObject,
		  __in PIRP Irp
		  );


NTSTATUS
PfpRead (
		 __in PDEVICE_OBJECT DeviceObject,
		 __in PIRP Irp
		 );



BOOLEAN		
PfpCheckEncryptInfo(PVOID szBuffer,
					ULONG Length);




PVOID	
PfpCreateFCB();

VOID	
PfpDeleteFCB(
			 PPfpFCB* ppFcb
			 );

PVOID	
PfpCreateCCB();

VOID	
PfpDeleteCCB(
			 PPfpCCB ppCcb
			 );
BOOLEAN	
PfpFileObjectHasOurFCB(
					   IN PFILE_OBJECT pFileObject
					   );

PUSERFILEOBJECT 
PfpCreateUserFileObject(PFILE_OBJECT userfileobject , 
						PFILE_OBJECT diskfileobject,
						HANDLE diskfilehandle
						);

PDISKFILEOBJECT	
PfpCreateDiskFileObject(
						UNICODE_STRING* pFullPath,
						PDEVICE_OBJECT  pDevice	
						);

VOID	
PfpAddUserFileObjectIntoDiskFileObject(
									   PDISKFILEOBJECT pDiskFileObject,
									   PUSERFILEOBJECT pUserFileObject
									   );

VOID
PfpAddDiskFileObjectIntoList(
							   PDISKFILEOBJECT pDiskFileObject,
							   PLIST_ENTRY     pListHead );
// remove the entry from diskfileobject,and delete the pUserFileobject's memory
VOID
PfpRemoveUserFileObejctFromDiskFileObject(
											PLIST_ENTRY pListHead,
											PUSERFILEOBJECT pUserFileObejct
											);
VOID
PfpDeleteUserFileObject(
						PUSERFILEOBJECT* pUserFileObejct
						);
VOID
PfpRemoveDiskFileObjectFromListEntry(
									PDISKFILEOBJECT pDiskFileObject										
								  );

PUSERFILEOBJECT 
PfpRemoveUFOFromDFOByHandle(
							PDISKFILEOBJECT pDiskFileObject,
							PFILE_OBJECT    pFileObject);

VOID 
PfpDeleteDiskFileObject(
						PDISKFILEOBJECT *pDiskFileObject
						);

BOOLEAN 
IsEmptyDiskFileObject(
					  PDISKFILEOBJECT pDiskFileObject
					  );


typedef enum _OPENFILETYPE
{
	OPEN_FILE_EXIST,
	SUPERSEDE,
	OVERWRITE,
	CREATNEWFILE
}OPENFILETYPE;





NTSTATUS 
PfpCommonWrite(	PIRP_CONTEXT irpContext,
				PIRP Irp
				);

NTSTATUS 
PfpCommonRead( PIRP_CONTEXT IrpContext,
			   PIRP Irp
			   );

//
//  The following routines are used to set up and restore the top level
//  irp field in the local thread.  They are contained in Pfpdata.c
//



BOOLEAN
PfpZeroData (
			  IN PIRP_CONTEXT IrpContext,
			  IN PPfpFCB Scb,
			  IN PFILE_OBJECT FileObject,
			  IN LONGLONG StartingZero,
			  IN LONGLONG ByteCount
			  );


PIRP_CONTEXT
PfpCreateIrpContext (
					 IN PIRP Irp OPTIONAL,
					 IN BOOLEAN Wait
					 );

VOID
PfpDeleteIrpContext (
					 IN OUT PIRP_CONTEXT *IrpContext
					 );


NTSTATUS 
PfpCompleteMdl ( 
				IN PIRP_CONTEXT IrpContext, 
				IN PIRP Irp 
				);

VOID
PfpCompleteRequest (
					IN OUT PIRP_CONTEXT *IrpContext OPTIONAL,
					IN OUT PIRP *Irp OPTIONAL,
					IN NTSTATUS Status
					);



NTSTATUS
PfpNonCachedIoWrite( 
			    IN PIRP_CONTEXT  pIrpContext,
			    IN PIRP			 Irp,
				IN PPfpFCB		 pFcb,
				IN LONGLONG		 StartingOffset,
				IN LONG			 BytesToWrite
				);


NTSTATUS
PfpNonCachedAsyncIoCompleteWrite(
					   IN PDEVICE_OBJECT  DeviceObject,
					   IN PIRP  Irp,
					   IN PVOID  Context
					   );

NTSTATUS
PfpNonCachedSyncIoCompleteWrite(
						   IN PDEVICE_OBJECT  DeviceObject,
						   IN PIRP  Irp,
						   IN PVOID  Context
						   );
NTSTATUS
PfpNonCachedIoWriteEncrypt( 
						   IN PIRP_CONTEXT		pIrpContext,
						   IN PIRP				Irp,
						   IN PPfpFCB			pFcb,
						   IN LONGLONG			StartingOffset,
						   IN LONG				BytesToWrite,
						   IN PVOID				pSystemBuffer
						   );



NTSTATUS
PfpNonCachedIoRead( 
					IN PIRP_CONTEXT  pIrpContext,
					IN PIRP Irp,
					IN PPfpFCB pFcb,
					IN LONGLONG StartingOffset,
					IN LONG BytesToWrite
					);
VOID 
PfpNonCachedNonAlignedIo ( 
								IN PIRP_CONTEXT IrpContext, 
								IN PIRP		Irp, 
								IN PPfpFCB	Scb, 
								IN LONGLONG	StartingVbo, 
								IN ULONG	ByteCount );
NTSTATUS
PfpNonCachedAsyncIoCompleteRead(
								 IN PDEVICE_OBJECT  DeviceObject,
								 IN PIRP  Irp,
								 IN PVOID  Context
								 );

NTSTATUS
PfpNonCachedSyncIoCompleteRead(
								IN PDEVICE_OBJECT  DeviceObject,
								IN PIRP  Irp,
								IN PVOID  Context
								);

//////////////////////////////////////////////////////////////////////////
//Implementation in Pfpdeviosup.c
PVOID
PfpMapUserBuffer (
				  IN OUT PIRP Irp
				  );


VOID
PfpLockUserBuffer (
				   IN PIRP_CONTEXT IrpContext,
				   IN OUT PIRP Irp,
				   IN LOCK_OPERATION Operation,
				   IN ULONG BufferLength
				   );



NTSTATUS
PfpQueryInformation (               //  implemented in FileInfo.c
					 IN PDEVICE_OBJECT VolumeDeviceObject,
					 IN PIRP Irp
					 );


NTSTATUS 
PfpCommonQueryInformation ( 
							IN PIRP_CONTEXT IrpContext, 
							IN PIRP Irp 
							);



NTSTATUS
PfpSetInformation (                 //  implemented in FileInfo.c
				   IN PDEVICE_OBJECT VolumeDeviceObject,
				   IN PIRP Irp
				   );

NTSTATUS
PfpSetFileInfo (
				IN PIRP_CONTEXT IrpContext,
				IN PFILE_OBJECT FileObject,
				IN PPfpFCB Fcb,							  
				IN FILE_INFORMATION_CLASS InformationClass 
				);
NTSTATUS
PfpSetEndOfFileInfo (					  
					  IN PFILE_OBJECT FileObject,
					  IN PIRP Irp,
					  IN PPfpFCB Fcb
					  );
NTSTATUS
PfpSetPositionInfo (
					IN PIRP Irp,
					IN PFILE_OBJECT FileObject
					);
NTSTATUS
PfpSetAllocationInfo (
					   IN PFILE_OBJECT FileObject,
					   IN PIRP Irp,
					   IN PPfpFCB Fcb					
					   );
NTSTATUS 
PfpCommonSetInformation ( 
						   IN PIRP_CONTEXT IrpContext, 
						   IN PIRP Irp );

NTSTATUS
PfpQueryFileInfo (
					IN PIRP_CONTEXT IrpContext,
					IN PFILE_OBJECT FileObject,
					IN PPfpFCB Fcb,							  
					IN FILE_INFORMATION_CLASS InformationClass
									  );

NTSTATUS
PfpQueryAndSetComplete(
					   IN PDEVICE_OBJECT  DeviceObject,
					   IN PIRP  Irp,
					   IN PVOID  Context
					   );

#define CanFsdWait( I)  IoIsOperationSynchronous(I)

BOOLEAN
PfpWaitForIoAtEof (
				   IN PFSRTL_ADVANCED_FCB_HEADER Header,
				   IN OUT PLARGE_INTEGER FileOffset,
				   IN ULONG Length,
				   IN PEOF_WAIT_BLOCK EofWaitBlock
				   );

VOID
PfpFinishIoAtEof (
				  IN PFSRTL_ADVANCED_FCB_HEADER Header
				  );
//////////////////////////////////////////////////////////////////////////



//
//  The following macro is used to set the is fast i/o possible field in
//  the common part of the non paged fcb
//
//
//      BOOLEAN
//      NtfsIsFastIoPossible (
//          IN PSCB Scb
//          );
//
#define PfpIsFastIoPossible(S) (BOOLEAN)((!FsRtlOplockIsFastIoPossible( &(S)->Oplock ))? \
FastIoIsNotPossible: \
	((((S)->FileLock == NULL|| !FsRtlAreThereCurrentFileLocks( (S)->FileLock )))? \
FastIoIsPossible: FastIoIsQuestionable))

#define PfpRestoreTopLevelIrp(TLC) {                   \
	(TLC)->Ntfs = 0;                                    \
	IoSetTopLevelIrp( (PIRP) (TLC)->SavedTopLevelIrp ); \
}

#define PfpGetTopLevelContext() (                      \
	(PTOP_LEVEL_CONTEXT) IoGetTopLevelIrp()             \
	)
#define GetExceptionInformation (struct _EXCEPTION_POINTERS *)_exception_info

#define FsRtlLockFsRtlHeader(H) {                           \
	EOF_WAIT_BLOCK eb;                                      \
	LARGE_INTEGER ef = {FILE_WRITE_TO_END_OF_FILE, -1};     \
	ExAcquireFastMutex( (H)->FastMutex );                   \
	if (((H)->Flags & FSRTL_FLAG_EOF_ADVANCE_ACTIVE)) {     \
	PfpWaitForIoAtEof( (H), &ef, 0, &eb );             \
	}                                                       \
	(H)->Flags |= FSRTL_FLAG_EOF_ADVANCE_ACTIVE;            \
	ExReleaseFastMutex( (H)->FastMutex );                   \
}

#define FsRtlUnlockFsRtlHeader(H) {                         \
	ExAcquireFastMutex( (H)->FastMutex );                   \
	PfpFinishIoAtEof( (H) );                               \
	ExReleaseFastMutex( (H)->FastMutex );                   \
}



#define PfpUpdateIrpContextWithTopLevel(IC,TLC) {          \
	if ((TLC)->TopLevelIrpContext == NULL) {                \
	(TLC)->TopLevelIrpContext = (IC);                   \
	}                                                       \
	(IC)->TopLevelIrpContext = (TLC)->TopLevelIrpContext;   \
	}

//#define SetFlag(F,SF) { (F) |= (SF); }

#define PfpNormalizeAndRaiseStatus(IC,STAT,NOR_STAT) {                          \
	(IC)->ExceptionStatus = (STAT);                                              \
	ExRaiseStatus(FsRtlNormalizeNtstatus((STAT),NOR_STAT));                      \
}
#define PfpAcquireFsrtlHeader(S) { ExAcquireFastMutex((S)->Header.FastMutex); }
#define PfpReleaseFsrtlHeader(S){  ExReleaseFastMutex((S)->Header.FastMutex);}


#define SafeZeroMemory(AT,BYTE_COUNT) {                            \
	try {                                                          \
	RtlZeroMemory((AT), (BYTE_COUNT));                         \
} except(EXCEPTION_EXECUTE_HANDLER) {                          \
	PfpRaiseStatus( IrpContext, STATUS_INVALID_USER_BUFFER, NULL );\
}                                                              \
}

#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))


#define PfpAcquireExclusivePagingIo(IC,FCB) {                  \
	ASSERT((IC)->FcbWithPagingExclusive == NULL);               \
	ExAcquireResourceExclusive((FCB)->Header.Resource, TRUE);  \
	(IC)->FcbWithPagingExclusive = (FCB);                       \
}

#define PfpReleasePagingIo(IC,FCB) {                                   \
	ASSERT((IC)->FcbWithPagingExclusive == (FCB));                      \
	ExReleaseResource((FCB)->Header.Resource);                         \
	(IC)->FcbWithPagingExclusive = NULL;                                \
}

#define PfpGetTopLevelContext() ( (PTOP_LEVEL_CONTEXT) IoGetTopLevelIrp() )
#define PfpIsTopLevelRequest(IC) ( ((BOOLEAN) ((PfpGetTopLevelContext())->TopLevelRequest) && (((IC) == (IC)->TopLevelIrpContext))) )


VOID
PfpRaiseStatus (
				 IN PIRP_CONTEXT IrpContext,
				 IN NTSTATUS Status,				 
				 IN PPfpFCB Fcb OPTIONAL
				 );
LONG
PfpExceptionFilter (
					IN PIRP_CONTEXT IrpContext OPTIONAL,
					IN PEXCEPTION_POINTERS ExceptionPointer
					);

NTSTATUS
PfpProcessException (
					  IN PIRP_CONTEXT IrpContext,
					  IN PIRP Irp OPTIONAL,
					  IN NTSTATUS ExceptionCode
					  );


//
//Implementation in pfpData.c
//
LONG
PfpProcessExceptionFilter (
						   IN PEXCEPTION_POINTERS ExceptionPointer
						   );

PTOP_LEVEL_CONTEXT
PfpSetTopLevelIrp (
				   IN PTOP_LEVEL_CONTEXT TopLevelContext,
				   IN BOOLEAN ForceTopLevel,
				   IN BOOLEAN SetTopLevel
				   );




//
//  Work queue routines for posting and retrieving an Irp, implemented in
//  workque.c
//

VOID
PfpAddToWorkque (
				 IN PIRP_CONTEXT IrpContext,
				 IN PIRP Irp OPTIONAL
				);


VOID
PfpOplockComplete (
					IN PVOID Context,
					IN PIRP Irp
					);

VOID
PfpPrePostIrp (
				IN PVOID Context,
				IN PIRP Irp OPTIONAL
				);


NTSTATUS
PfpPostRequest (
				 IN PIRP_CONTEXT IrpContext,
				 IN PIRP Irp OPTIONAL
				 );

//Implementation in Pfpdisp.c
VOID
NtfsFspDispatch (
				 IN PVOID Context
				 );



VOID
PfpAcquireSharedFcb (
					  IN PIRP_CONTEXT	IrpContext,
					  IN PPfpFCB		Fcb,					  
					  IN BOOLEAN		NoDeleteCheck
					  );
BOOLEAN
PfpAcquireExclusiveFcb (
						 IN PIRP_CONTEXT	IrpContext,
						 IN PPfpFCB			Fcb						 
						 );
VOID
PfpReleaseFcb (
			   IN PIRP_CONTEXT	IrpContext,
			   IN PPfpFCB		Fcb
			   );


NTSTATUS
PfpFsdCleanup (                        //  implemented in Cleanup.c
				IN PDEVICE_OBJECT VolumeDeviceObject,
				IN PIRP Irp
				);
NTSTATUS
PfpCommonCleanup (                        //  implemented in Cleanup.c
				  IN PIRP_CONTEXT IrpContext,
				  IN PIRP Irp
				  );
NTSTATUS
PfpFsdClose (                          //  implemented in Close.c
			  IN PDEVICE_OBJECT VolumeDeviceObject,
			  IN PIRP Irp
			  );


VOID
PfpDecrementCleanupCounts (
						   IN PPfpFCB pFcb,							
						   IN BOOLEAN NonCachedHandle
						   );

VOID
PfpIncrementCleanupCounts (
						   IN PPfpFCB pFcb,
						   IN BOOLEAN NonCachedHandle
						   );



//////////////////////////////////////////////////////////////////////////
PPROCESSINFO PfpGetProcessInfoForCurProc();

//BOOLEAN		PfpFileIsProtected(PFILE_OBJECT pFileObject,PPROCESSINFO pProcInfo);
BOOLEAN		PfpFileIsNotSelectedInProcess(PFILE_OBJECT pFileObject,PPROCESSINFO pProcInfo);
//////////////////////////////////////////////////////////////////////////
#define ENCRYPTIONHEADLENGTH   2*1024

typedef enum _FILESTATE
{
	ACCESSING_FILE_EXIST, //accessing file, file already exist on disk.
	ACCESSING_FILE_NONEXIST,// accessing file, but not exist .
	ACCESSING_FILE_EXIST_READONLY,
	ACCESSING_DIR_EXIST,// accessing directory.
	INVALID_ACCESS
}FILESTATE;

NTSTATUS 
PfpCreateRealDiskFile( 
					  PDISKFILEOBJECT	pDiskFileObject,					  
					  IO_STATUS_BLOCK*	iostatus,
					  ULONG				CreateDisposition,
					  LARGE_INTEGER		AllocationSize,//when operatype!=OPEN_FILE_EXIST, this parameter is valid 
					  BOOLEAN			DeleteOnClose,
					  PVOID				EaBuffer,
					  ULONG				EALength,
					  ULONG			FileAttributes,
					  PIO_SECURITY_CONTEXT SecurityContext,
					  PACCESS_MASK		DesiredAccess,
					  IN USHORT			ShareAccess,
					  FILESTATE			AcsType);

NTSTATUS
PfpCloseRealDiskFile( 
					 HANDLE *		FileHandle,
					 PFILE_OBJECT *	pFileObject
					 );


//这个函数检查 irp里面的fileobject对应的文件在磁盘上是否存在，或者是否只读
FILESTATE 
PfpGetFileAttriForRequest(
						  IN PIRP				pIrp, 
						  IN PDEVICE_OBJECT		pDeviceObject,
						  IN OUT LONGLONG *		FileSize);

FILESTATE 
PfpGetFileAttriForRequestEx(IN PDEVICE_OBJECT pDeviceObject,
						  IN PWCHAR szFullPathWithOutDevice,
						  IN ULONG	lLenInBytes,
						  IN OUT LONGLONG *		FileSize);


BOOLEAN

PfpGetParentPath(
				 WCHAR*	pszFilePath,
				 ULONG	nPathLenInbytes,
				 WCHAR** pDirPath,
				 LONG*	nSize);

NTSTATUS 
PfpOpenDirByShadowDevice(
			IN WCHAR *		  pDirPath,
			IN HANDLE *		  pHandleReturned,
			IN PDEVICE_OBJECT pDevice);


NTSTATUS PfpOpenFileByShadowDevice(
								   WCHAR * pDirPath,
								   HANDLE *pHandleReturned,
								   PDEVICE_OBJECT pDevice);

void PfpEncryptFile(
					PFILE_OBJECT pFileObject,
					PDEVICE_OBJECT pTargetDevice);

void PfpEnOrDecryptDir(
					   PFILE_OBJECT pDirObj,
					   PDEVICE_OBJECT  pShadowDevice, 
					   PDEVICE_OBJECT pTargetDevice,
					   PDEVICE_OBJECT pCurrentDevice,
					   BOOLEAN bEncrypt,PWCHAR pszSourceDirPath);
NTSTATUS
PfpQueryForLongName(IN WCHAR *pDirPath,
					IN ULONG nLenofChar,
					IN PDEVICE_OBJECT pDevice,
					IN OUT WCHAR** pOutFullPath/*,
					ULONG* pFolder_File_Unknow*/);
NTSTATUS
PfpGetFileSizofEncryptedByShadowDevice(IN WCHAR *			pDirPath,
									   IN WCHAR*			pFileName,
									   IN LONG				NameLenInBytes,	
									   IN PDEVICE_OBJECT	pDevice,
									   LARGE_INTEGER	*	pFileSize,
									   LARGE_INTEGER	*	pAllocation
									   );

BOOLEAN 
PfpFileExistInDir(IN PDEVICE_OBJECT pNextDevice,
				  IN  HANDLE	hDir,
				  IN  WCHAR *	pFileName,
				  OUT BOOLEAN *	bReadonly,
				  BOOLEAN*		bDir,
				  LONGLONG	*	FileSize);

NTSTATUS 
PfpGetFullPathPreCreate(
						 IN PIRP	pIrp,
						 IN WCHAR**  pszFullPathWithOutDeviceName,
						 IN ULONG*	szLenReturnedInBytes,
						 IN PDEVICE_OBJECT pDevice
						 );

BOOLEAN 
PfpIsStreamPath(WCHAR*pszFullPathWithOutDeviceName,
								  IN ULONG szLenInBytes);

BOOLEAN
PfpGetDeviceLetter(IN PDEVICE_OBJECT pDevice,WCHAR* szLetter);

NTSTATUS 
PfpGetFullPathForFileObject(IN  PFILE_OBJECT  hFile,
							IN OUT WCHAR** pFullPath,
							IN OUT LONG *nLen,
							IN PDEVICE_OBJECT pNextDevice);

IO_STATUS_BLOCK
PfpOpenExistingFcb (
					IN PIRP_CONTEXT IrpContext,
					IN PFILE_OBJECT FileObject,
					IN PPfpFCB	*	ppFcb,
					IN PDISKFILEOBJECT *pDiskFileObject,
					IN PACCESS_MASK DesiredAccess,
					IN USHORT		ShareAccess,
					IN LARGE_INTEGER		AllocationSize,				
					IN UCHAR		FileAttributes,
					IN ULONG		CreateDisposition,
					IN BOOLEAN		DeleteOnClose,
					OUT PBOOLEAN	OplockPostIrp
					);

IO_STATUS_BLOCK
PfpOpenExistingFile (
					 IN PIRP_CONTEXT	IrpContext,
					 IN PFILE_OBJECT	FileObject,	
					 IN OUT PPfpFCB	*	Fcb,
					 IN PDISKFILEOBJECT* pDiskFileObject,
					 IN PACCESS_MASK	DesiredAccess,					 
					 IN USHORT			ShareAccess,
					 IN LARGE_INTEGER			AllocationSize,	
					 IN UCHAR			FileAttributes	,
					 IN ULONG			CreateDisposition,					
					 IN BOOLEAN			NoEaKnowledge,
					 IN BOOLEAN			DeleteOnClose,
					 PIO_SECURITY_CONTEXT SecurityContext,
					 FILESTATE			AcsType
					 );

IO_STATUS_BLOCK
PfpSupersedeOrOverwriteFile (
							 IN PIRP_CONTEXT	IrpContext,
							 IN PFILE_OBJECT	FileObject,
							 IN PPfpFCB			Fcb,
							 IN LARGE_INTEGER			AllocationSize,							 
							 IN UCHAR			FileAttributes,
							 IN ULONG			CreateDisposition					
							 );



IO_STATUS_BLOCK
PfpCreateNewFile (
				  IN PIRP_CONTEXT		IrpContext,
				  IN PFILE_OBJECT		FileObject,	
				  IN OUT PPfpFCB	*	Fcb,
				  IN PDISKFILEOBJECT*	pDiskFileObject,
				  IN PACCESS_MASK		DesiredAccess,
				  IN USHORT				ShareAccess,
				  IN LARGE_INTEGER				AllocationSize,
				  IN PFILE_FULL_EA_INFORMATION EaBuffer,
				  IN ULONG				EaLength,
				  IN UCHAR				FileAttributes,					 
				  IN BOOLEAN			NoEaKnowledge,
				  IN BOOLEAN			DeleteOnClose,
				  IN BOOLEAN			TemporaryFile,
				  IN PIO_SECURITY_CONTEXT SecurityContext, 
				  IN ULONG CreateDisposition
				  );


BOOLEAN
PfpCheckFileAccess (					
					IN UCHAR DirentAttributes,
					IN PACCESS_MASK DesiredAccess
					);

IO_STATUS_BLOCK 
PfpEncapCreateFile(
				   IN PIRP_CONTEXT			IrpContext,
				   IN PIRP					pIrp,
				   IN FILESTATE				Type,
				  
				   IN BOOLEAN				bFirstOPEN,
				   IN UNICODE_STRING *		pFullPathName,
				   IN OUT PDISKFILEOBJECT * pDiskFileObject,
				   PBOOLEAN				OplockPostIrp);

BOOLEAN			
PfpInitFCBFromEncryptBuffer(
							IN PVOID Buffer ,
							IN ULONG Len,
							IN PPfpFCB pFcb);
BOOLEAN			
PfpInitFCBFromFileOnDISK(
						 IN PFILE_OBJECT	hFileObject	,
						 IN PPfpFCB			pFcb,
						 BOOLEAN			bNewCreated,
						 PDEVICE_OBJECT		pNextDevice);

//this data structure should be initialized at system startup

 extern  NPAGED_LOOKASIDE_LIST NtfsIrpContextLookasideList;
 extern  NPAGED_LOOKASIDE_LIST NtfsIoContextLookasideList;

 //////////////////////////////////////////////////////////////////////////
 // cache callback fucntions
 //
 //////////////////////////////////////////////////////////////////////////
CACHE_MANAGER_CALLBACKS CacheManagerCallbacks;

BOOLEAN
PfpAcquireFCBForLazyWrite (
						   IN PVOID OpaqueScb,
						   IN BOOLEAN Wait
						   );

VOID
PfpReleaseFCBFromLazyWrite (
							IN PVOID OpaqueScb
							);

BOOLEAN
PfpAcquireFCBForReadAhead (
						   IN PVOID OpaqueScb,
						   IN BOOLEAN Wait
						   );
VOID
PfpReleaseFCBFromReadAhead (
							IN PVOID OpaqueScb
							);

//////////////////////////////////////////////////////////////////////////
//
//Fastio routines;
//////////////////////////////////////////////////////////////////////////


BOOLEAN
PfpPrepareMdlWriteA (
					 IN PFILE_OBJECT FileObject,
					 IN PLARGE_INTEGER FileOffset,
					 IN ULONG Length,
					 IN ULONG LockKey,
					 OUT PMDL *MdlChain,
					 OUT PIO_STATUS_BLOCK IoStatus,
					 IN PDEVICE_OBJECT DeviceObject
					 );


BOOLEAN
PfpMdlReadA (
			 IN PFILE_OBJECT FileObject,
			 IN PLARGE_INTEGER FileOffset,
			 IN ULONG Length,
			 IN ULONG LockKey,
			 OUT PMDL *MdlChain,
			 OUT PIO_STATUS_BLOCK IoStatus,
			 IN PDEVICE_OBJECT DeviceObject
			 );

BOOLEAN
PfpCopyWriteA (
			   IN PFILE_OBJECT FileObject,
			   IN PLARGE_INTEGER FileOffset,
			   IN ULONG Length,
			   IN BOOLEAN Wait,
			   IN ULONG LockKey,
			   IN PVOID Buffer,
			   OUT PIO_STATUS_BLOCK IoStatus,
			   IN PDEVICE_OBJECT DeviceObject
			   );

BOOLEAN
PfpCopyReadA (
			  IN PFILE_OBJECT	FileObject,
			  IN PLARGE_INTEGER FileOffset,
			  IN ULONG Length,
			  IN BOOLEAN Wait,
			  IN ULONG LockKey,
			  OUT PVOID Buffer,
			  OUT PIO_STATUS_BLOCK IoStatus,
			  IN PDEVICE_OBJECT DeviceObject
			  );


//////////////////////////////////////////////////////////////////////////
//fast query info
//
//////////////////////////////////////////////////////////////////////////

BOOLEAN
PfpFastIoCheckIfPossible (
						   IN PFILE_OBJECT FileObject,
						   IN PLARGE_INTEGER FileOffset,
						   IN ULONG Length,
						   IN BOOLEAN Wait,
						   IN ULONG LockKey,
						   IN BOOLEAN CheckForReadOperation,
						   OUT PIO_STATUS_BLOCK IoStatus,
						   IN PDEVICE_OBJECT DeviceObject
						   );

BOOLEAN
PfpFastQueryBasicInfo (
						IN PFILE_OBJECT FileObject,
						IN BOOLEAN Wait,
						IN OUT PFILE_BASIC_INFORMATION Buffer,
						OUT PIO_STATUS_BLOCK IoStatus,
						IN PDEVICE_OBJECT DeviceObject
						);

BOOLEAN
PfpFastQueryStdInfo (
					  IN PFILE_OBJECT FileObject,
					  IN BOOLEAN Wait,
					  IN OUT PFILE_STANDARD_INFORMATION Buffer,
					  OUT PIO_STATUS_BLOCK IoStatus,
					  IN PDEVICE_OBJECT DeviceObject
					  );

BOOLEAN
PfpFastQueryNetworkOpenInfo (
							  IN PFILE_OBJECT FileObject,
							  IN BOOLEAN Wait,
							  OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
							  OUT PIO_STATUS_BLOCK IoStatus,
							  IN PDEVICE_OBJECT DeviceObject
							  );

FAST_MUTEX  g_HookMutex;
PFAST_IO_ACQUIRE_FILE NTFSAcquireFileForNtCreateSection;
PFAST_IO_RELEASE_FILE NTFSReleaseFileForNtCreateSection;
VOID
PfpFastAcquireForCreateSection (
							 IN PFILE_OBJECT FileObject
							 );

VOID
PfpFastReleaseForCreateSection (
							 IN PFILE_OBJECT FileObject
							 );

PFAST_IO_ACQUIRE_FOR_CCFLUSH  NTFSAcquireForCcFlush;
PFAST_IO_RELEASE_FOR_CCFLUSH  NTFSReleaseForCcFlush;



PFAST_IO_ACQUIRE_FOR_CCFLUSH  FastFatAcquireForCcFlush;
PFAST_IO_RELEASE_FOR_CCFLUSH  FastFatReleaseForCcFlush;


NTSTATUS
PfpAcquireFileForCcFlush (
						   IN PFILE_OBJECT   FileObject,
						   IN PDEVICE_OBJECT DeviceObject
						   );

NTSTATUS
PfpReleaseFileForCcFlush (
						   IN PFILE_OBJECT	 FileObject,
						   IN PDEVICE_OBJECT DeviceObject
						   );

PFAST_IO_ACQUIRE_FOR_MOD_WRITE NTFSAcquireForModWrite;
PFAST_IO_RELEASE_FOR_MOD_WRITE NTFSReleaseForModWrite;

NTSTATUS
PfpAcquireFileForModWrite (
							IN PFILE_OBJECT		FileObject,
							IN PLARGE_INTEGER	EndingOffset,
							OUT PERESOURCE *	ResourceToRelease,
							IN PDEVICE_OBJECT	DeviceObject
							);
NTSTATUS
PfpReleaseForModWrite(IN PFILE_OBJECT FileObject,
					  IN PERESOURCE   ResourceToRelease,
					  IN PDEVICE_OBJECT DeviceObject);
///////////////////////////////////////////////////////////////////////
//
//
//lock routines;
///////////////////////////////////////////////////////////////////////
  

BOOLEAN
PfpFastLock (
			  IN PFILE_OBJECT FileObject,
			  IN PLARGE_INTEGER FileOffset,
			  IN PLARGE_INTEGER Length,
			  PEPROCESS ProcessId,
			  ULONG Key,
			  BOOLEAN FailImmediately,
			  BOOLEAN ExclusiveLock,
			  OUT PIO_STATUS_BLOCK IoStatus,
			  IN PDEVICE_OBJECT DeviceObject
			  );

BOOLEAN
PfpFastUnlockSingle (
					  IN PFILE_OBJECT FileObject,
					  IN PLARGE_INTEGER FileOffset,
					  IN PLARGE_INTEGER Length,
					  PEPROCESS ProcessId,
					  ULONG Key,
					  OUT PIO_STATUS_BLOCK IoStatus,
					  IN PDEVICE_OBJECT DeviceObject
					  );
BOOLEAN
PfpFastUnlockAll (
				   IN PFILE_OBJECT FileObject,
				   PEPROCESS ProcessId,
				   OUT PIO_STATUS_BLOCK IoStatus,
				   IN PDEVICE_OBJECT DeviceObject
				   );

BOOLEAN
PfpFastUnlockAllByKey (
						IN PFILE_OBJECT FileObject,
						PVOID ProcessId,
						ULONG Key,
						OUT PIO_STATUS_BLOCK IoStatus,
						IN PDEVICE_OBJECT DeviceObject
						);


NTSTATUS
PfpCommonLockControl (
					   IN PIRP_CONTEXT IrpContext,
					   IN PIRP Irp
					   );

NTSTATUS
PfpFsdLockControl (
					IN PDEVICE_OBJECT VolumeDeviceObject,
					IN PIRP Irp
					);

//////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////

NTSTATUS
PfpFsdSetEa (
			  IN PDEVICE_OBJECT VolumeDeviceObject,
			  IN PIRP Irp
			  );

NTSTATUS
PfpFsdQueryEa (
				IN PDEVICE_OBJECT VolumeDeviceObject,
				IN PIRP Irp
				);

NTSTATUS
PfpFsdFlushBuffers (
					IN PDEVICE_OBJECT VolumeDeviceObject,
					IN PIRP Irp
					);


NTSTATUS
PfpCommonFlushBuffers (
					   IN PIRP_CONTEXT IrpContext,
					   IN PIRP Irp
					   );

NTSTATUS
PfpFlushUserStream (
					IN PIRP_CONTEXT IrpContext,
					IN PPfpFCB Scb,
					IN PLONGLONG FileOffset OPTIONAL,
					IN ULONG Length
					);
BOOLEAN
PfpCreateFileLock (
					IN PPfpFCB Scb,
					IN BOOLEAN RaiseOnError
					);


/////////////////////////////////////////////////////////////////////////////
//
//  Name lookup functions.
//
/////////////////////////////////////////////////////////////////////////////

NTSTATUS
NLGetFullPathName (
				   __in PFILE_OBJECT FileObject,
				   __inout PNAME_CONTROL FileNameControl,
				   __in PNL_DEVICE_EXTENSION_HEADER NLExtHeader,
				   __in NAME_LOOKUP_FLAGS LookupFlags,
				   __in PPAGED_LOOKASIDE_LIST LookasideList,
				   __out PBOOLEAN CacheName
				   );

PNAME_CONTROL
NLGetAndAllocateObjectName (
							__in PVOID Object,
							__in PPAGED_LOOKASIDE_LIST LookasideList
							);

NTSTATUS
NLGetObjectName (
				 __in PVOID Object,
				 __inout PNAME_CONTROL ObjectNameCtrl
				 );

VOID
NLGetDosDeviceName (
					__in PDEVICE_OBJECT DeviceObject,
					__in PNL_DEVICE_EXTENSION_HEADER NLExtHeader
					);

/////////////////////////////////////////////////////////////////////////////
//
//  General support routines
//
/////////////////////////////////////////////////////////////////////////////

NTSTATUS
NLAllocateAndCopyUnicodeString (
								__inout PUNICODE_STRING DestName,
								__in PUNICODE_STRING SrcName,
								__in ULONG PoolTag
								);

/////////////////////////////////////////////////////////////////////////////
//
//  Name lookup device extension header functions.
//
/////////////////////////////////////////////////////////////////////////////

VOID
NLInitDeviceExtensionHeader (
							 __in PNL_DEVICE_EXTENSION_HEADER NLExtHeader,
							 __in PDEVICE_OBJECT ThisDeviceObject,
							 __in_opt PDEVICE_OBJECT StorageStackDeviceObject
							 );

VOID
NLCleanupDeviceExtensionHeader(
							   __in PNL_DEVICE_EXTENSION_HEADER NLExtHeader
							   );

/////////////////////////////////////////////////////////////////////////////
//
//  Routines to support generic name control structures that allow us
//  to get names of arbitrary size.
//
/////////////////////////////////////////////////////////////////////////////

NTSTATUS
NLAllocateNameControl (
					   __out PNAME_CONTROL *NameControl,
					   __in PPAGED_LOOKASIDE_LIST LookasideList
					   );

VOID
NLFreeNameControl (
				   __in PNAME_CONTROL NameControl,
				   __in PPAGED_LOOKASIDE_LIST LookasideList
				   );

NTSTATUS
NLCheckAndGrowNameControl (
						   __inout PNAME_CONTROL NameCtrl,
						   __in USHORT NewSize
						   );

VOID
NLInitNameControl (
				   __inout PNAME_CONTROL NameCtrl
				   );

VOID
NLCleanupNameControl (
					  __inout PNAME_CONTROL NameCtrl
					  );

NTSTATUS
NLReallocNameControl (
					  __inout PNAME_CONTROL NameCtrl,
					  __in ULONG NewSize,
					  __out_opt PWCHAR *RetOriginalBuffer
					  );
VOID
PfpFspDispatch (
				IN PVOID Context
				);
VOID
PfpFspDispatchEX (
				  IN PDEVICE_OBJECT  DeviceObject,
				  IN PVOID  Context 

				  );

VOID 
PfpCreateShadowDeviceForDevice(IN PDEVICE_OBJECT newDeviceObject);


NTSTATUS
PfpFsControlCompletion (
						IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context 
						);

NTSTATUS 
PfpWriteHeadForEncryption(
						  PVOID pEncryptHead,
						  ULONG Len,
						  IN PFILE_OBJECT pDiskFile,
						  PDEVICE_OBJECT  pNextDevice
						  );
NTSTATUS 
PfpWriteFileByAllocatedIrp(
						   IN PVOID				pBuffer,
						   IN ULONG				Len,
						   IN LARGE_INTEGER		Offset,
						   IN PFILE_OBJECT		pDiskFile,
						   IN PDEVICE_OBJECT	pNextDevice,
						   IN OUT PIO_STATUS_BLOCK pIostatus
						   );
NTSTATUS
PfpNonCachedWriteByIrpComplete(
							 IN PDEVICE_OBJECT  DeviceObject,
							 IN PIRP			Irp,
							 IN PVOID			Context
								);
NTSTATUS
PfpNonCachedReadByIrpCompete(
							IN PDEVICE_OBJECT  DeviceObject,
							IN PIRP  Irp,
							IN PVOID  Context
							);

NTSTATUS 
PfpReadHeadForEncryption(
						 PVOID pEncryptHead,
						 ULONG Len,
						 IN PFILE_OBJECT pDiskFile,
						 PDEVICE_OBJECT  pNextDevice,
						 PIO_STATUS_BLOCK pIostatus
						 );

NTSTATUS 
PfpReadFileByAllocatedIrp(
						  PVOID				pBuffer,
						  ULONG				Len,
						  LARGE_INTEGER		Offset,
						  IN PFILE_OBJECT	pDiskFile,
						  PDEVICE_OBJECT		pNextDevice,
						  PIO_STATUS_BLOCK	pIostatus
						  );
PVOID 
PfpCreateEncryptHead(IN PPfpFCB pFcb);
VOID
pfpCreateProcessNotify(
					   IN HANDLE  ParentId,
					   IN HANDLE  ProcessId,
					   IN BOOLEAN  Create
					   );

VOID
PfpImageLoadNotification (
							   IN PUNICODE_STRING  FullImageName,
							   IN HANDLE  ProcessId, // where image is mapped
							   IN PIMAGE_INFO  ImageInfo
							   );

VOID
PfpThreadCreationNotification (
								  IN HANDLE  ProcessId,
								  IN HANDLE  ThreadId,
								  IN BOOLEAN  Create
								  );

BOOLEAN
PfpIsRequestWriteAccess(PIRP pIrp);


//////////////////////////////////////////////////////////////////////////
//
//dir control routines
//////////////////////////////////////////////////////////////////////////

LIST_ENTRY g_HideObjHead;
ERESOURCE  g_HideEresource;

NTSTATUS
DirControlCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);


BOOLEAN
IS_MY_HIDE_OBJECT_EX(const WCHAR *pFolerPathWithBackSplash, ULONG FolderLenth,const WCHAR *pItemName,ULONG NameLenth, ULONG Flag);


BOOLEAN IsThereHideItmesInFolder(WCHAR* pszFolder,ULONG nLeninBytes);

BOOLEAN  IsThereSecureFolderNeedHide(WCHAR* pszFolder,ULONG nLeninBytes);

NTSTATUS 
PfpQueryDirectoryByIrp(	IN PDEVICE_OBJECT pNextDevice,
					   IN PFILE_OBJECT	  pDirFileObject,
					   IN FILE_INFORMATION_CLASS FileInformationClass,
					   IN PVOID			pBuffer, //新申请的buffer
					   IN ULONG			Len,//userbuffer中剩余的 字节
					   IN PUNICODE_STRING pFilterUnicode,
					   PIO_STATUS_BLOCK  pIostatus);
NTSTATUS 
PfpQueryDirectory(IN PIRP pOrignalIrp,
				  IN PDEVICE_OBJECT pNextDevice,
				  IN PVOID pBuffer, //新申请的buffer
				  IN ULONG Len,//userbuffer中剩余的 字节
				  PIO_STATUS_BLOCK pIostatus);

NTSTATUS
FsDirectoryControl(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp);

NTSTATUS
PfpFsQueryAndSetSec(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp);

VOID
FsShutDown(IN PDEVICE_OBJECT DeviceObject);

VOID
DelHideObject(PWCHAR Name, ULONG Flag);

VOID
AddHideObject(PWCHAR Name, ULONG Flag);


ULONG 
CalcHidderLen();

ULONG 
CopyHidderIntoBuffer(PVOID pOutBufer, ULONG nBufLen);

ULONG
PfpGetParentPathFromFileObject(
							   PFILE_OBJECT pParentObject,
							   PWCHAR szParentPath);


VOID 
PfpSetBackUpDir(PWCHAR Path,ULONG InputLen);
VOID 
PfpGetBackUpDir(PWCHAR OutPutBuffer,ULONG OutputLen,IO_STATUS_BLOCK*IoStatus );

VOID 
PfpGetRunState(PVOID OutPutBuffer,IO_STATUS_BLOCK*IoStatus );

VOID
PfpGetHideLen(PVOID OutPutBuffer,IO_STATUS_BLOCK*IoStatus,ULONG Flag);

VOID
PfpGetHides(PVOID OutPutBuffer,ULONG inuputLen,IO_STATUS_BLOCK*IoStatus,ULONG Flag);


//////////////////////////////////////////////////////////////////////////
//
//这里是 文件实时备份的 系统线程函数
//////////////////////////////////////////////////////////////////////////
FAST_MUTEX g_BackUpMetux;
LIST_ENTRY g_BackUpList;
HANDLE     g_BackUpThread;
KEVENT	   g_ThreadEvent;

//Created by create and write and close funtcion and send into list  ,so backup thread can retriver it and do it's work.
#define REQUEST_FROM_CREATE 1
#define REQUEST_FROM_WRITE  2
#define REQUEST_FROM_CLOSE  3
#define REQUEST_FROM_DELETE 4

#define REQUEST_FROM_RENAME 5

typedef struct _BACKUPINFO
{
	LIST_ENTRY		List;
	PVOID			pBuffer; //如果这个pbuffer的值为空那么就说明这个文件全部写完了数据了
	LARGE_INTEGER	Offset;
	ULONG			nLength;
	WCHAR			*pszExeName;
	WCHAR			*pFileName;
	WCHAR			*pOrginalFileFullPath;
	ULONG			Request_Place;
	KEVENT*			Event;
}BackUpInfo,*PBackUpInfo;

HANDLE 
PfpCreateBackUpThread();

HANDLE 
PfpCreateMonitorThreadForUserModeExe();

PBackUpInfo
PfpRemoveBackUpInfoFromGlobal();

VOID 
PfpDeleteBackUpInfo(PBackUpInfo pBackUpInfo);

VOID 
PfpBackupThread(IN PVOID pContext);


//////////////////////////////////////////////////////////////////////////
///
//////////////////////////////////////////////////////////////////////////
VOID 
PfpMonitorThread(IN PVOID pContext);

VOID 
PfpDelayCloseThread(IN PVOID pContext);


VOID  
PfpCreateDelayCloseThread();
//////////////////////////////////////////////////////////////////////////
PBackUpInfo 
PfpCreateBackUpInfoAndInsertIntoGlobalList(IN PWCHAR			szExeName,
										   IN UNICODE_STRING	FullFilePath,
										   IN PVOID				pBuffer,
										   IN LONGLONG			offset,
										   IN LONG				len,
										   IN ULONG				nRequestFlag
										   );


VOID Sleep();

//below structure is used by BackupThread 

typedef struct _BACKUP_FILEINFO
{
	LIST_ENTRY	 list;
	PFILE_OBJECT pFileObject_BackUp;
	HANDLE		 hBackUpFile;
	PWCHAR		 pExeName;
	PWCHAR		 pFileName;
	
}BackUpFileInfo,*PBackUpFileInfo;

LIST_ENTRY g_BackUp_FileInfoLists;

NTSTATUS
PfpCreateBackUpFile_Real(IN PFILE_OBJECT*pFileObject,
						 IN HANDLE * hReturn,
						 IN PWCHAR pszFullPath);

PBackUpFileInfo
PfpCreateBackUpFile(IN PBackUpInfo pBackUpInfo,IN BOOLEAN* bNeedCopy);

VOID 
PfpWriteBackupFile(IN PBackUpFileInfo pBackupFile,IN PBackUpInfo pBackUpInfo);

VOID 
PfpDeleteFile(PBackUpFileInfo pBackupFile,PBackUpInfo pBackUpInfo);

VOID 
PfpRenameFile(PBackUpFileInfo pBackupFile,PBackUpInfo pBackUpInfo);


VOID 
PfpRenameFileUsingFileobeject(PFILE_OBJECT pBackFileObject, PWCHAR szTargetFileName);


VOID 
PfpDeleteBackUpFileStuct(IN PBackUpFileInfo pBackUpFile);

VOID 
PfpCloseBackUpFile(IN PBackUpFileInfo pBackUpFile);

PBackUpFileInfo
PfpGetBackFileInfo(IN PBackUpInfo pBackUpInfo);

VOID 
PfpSetProcessNameInFileContext2(IN PPfpCCB pCcb,IN PPROCESSINFO pProcInfo);

BOOLEAN 
PfpMakeBackUpDirExist(IN PWCHAR szDirFullPaht);

PWCHAR g_szBackupDir;

//////////////////////////////////////////////////////////////////////////
/*
*	和用户模式进行通信约定
*/

#define CDO_FLAG_FILE			1L
#define CDO_FLAG_DIRECTORY		2L


typedef struct _HIDE_OBJECT
{
	LIST_ENTRY	linkfield;	
	ULONG		Namesize;
	WCHAR		Name[1024];
	ULONG		Flag;//directory/or file
	ULONG		nHide;//1 :hide /2:show
} HIDE_FILE, *PHIDE_FILE;

//////////////////////////////////////////////////////////////////////////
typedef struct _FILETYPEPERIOD
{
	LIST_ENTRY		list ;
	ULONG			nPeriodeType;//1：天2：周 3：月
	ULONG			nCout;//多少个周期。
	WCHAR			szFileType[10];
}FileTypePeriod,*PFileTypePeriod;

typedef struct _PeriodicBACKUPINFO
{	
	LIST_ENTRY		list;
	PWCHAR			szProcessName;
	LIST_ENTRY		FileTypes;
}PeriodicBackUpInfo,*PPeriodicBackUpInfo;




LIST_ENTRY g_PeriodicBackUpInfo_ListHead;

PPROCESSINFO  GetProcessInfoUsingHashValue(UCHAR* 	HashValue,LONG nsize);
//这2个函数是用来初始化隐藏文件（夹）的函数
ULONG 
CalcHideObjectSizeForWritingFile();

VOID  
InitHidderFromBufferReadFromFile(PVOID pBuffer, 
								 ULONG nLen);
VOID  
WriteHidderObjectsIntoBufferForWrittingFile(PVOID pBuffer, 
											ULONG *nLen);

BOOLEAN 
PfpIsBackUpPeriodic(IN  PWCHAR szProcessName,
							IN  PWCHAR szFileType,
							OUT ULONG* nPeriodType,
							OUT ULONG* nCout);//检查当前备份是否是定期的

BOOLEAN	
PfpGetLastCreateDateofSubDir(IN PWCHAR szParent,
							 OUT LARGE_INTEGER * CreateTime,
							 IN OUT  PWCHAR szSubFolder);


BOOLEAN
PfpIsDateLessThandPeriodDate(LARGE_INTEGER CurrentDate ,LARGE_INTEGER FolderDate,ULONG nPeriodType, ULONG nCout);

VOID
PfpGetBackUpFolderNameForPeriod(LARGE_INTEGER CurrentDate,ULONG nPeriodType, ULONG nCout,PWCHAR szFolderName);


VOID
PfpGetProcessHandleFromID(IN HANDLE ProcessID,
						  OUT HANDLE* ProcessHandle);

NTSTATUS
PfpOpenOriganlFileForBackup(IN WCHAR* szFullPath,
							OUT HANDLE * FileHandle, 
							OUT IO_STATUS_BLOCK* iostatus);

BOOLEAN
PfpGenerateFullFilePathWithShadowDeviceName(IN PDEVICE_OBJECT pSpyDevice,
											IN WCHAR*szFullPathWithoutDeviceName,
											OUT WCHAR** FullPathWithDeviceName);

VOID 
PfpCopyFile(IN HANDLE hDestination,
			IN HANDLE hSource);

ULONG 
PfpGetFileSize(IN HANDLE hFile);
//////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////
VOID	PfpGetKeyFileContent(PWCHAR szKeyFile,PVOID *pFileContent,ULONG *nsize);
BOOLEAN PfpWriteKeyFileContent(PWCHAR szKeyFile,PVOID pFileContent,ULONG nsize);
WCHAR szPrivateKey[16];

aes_encrypt_ctx  ase_en_context;
aes_decrypt_ctx	 ase_den_context;

BOOLEAN PfpEncryptBuffer(PVOID pBuffer, ULONG Len,aes_encrypt_ctx* pCtx);
BOOLEAN PfpDecryptBuffer(PVOID pBuffer, ULONG Len,aes_decrypt_ctx* pCtx);

PVOID g_pKeyFileContent;
UCHAR g_VerifyValues[240];
ULONG g_keyFileLen;

PVOID g_pKeyContent;
ULONG g_keyLen;



ULONG					gAllFileCount;
KSPIN_LOCK				gAllFileOpenedLOCK;
VOID	PfpIncreFileOpen();
VOID	PfpDecreFileOpen();
ULONG	PfpGetFileOpenCount();

BOOLEAN 
PfpIsFileEncrypted(UNICODE_STRING * pFileFullPath,PDEVICE_OBJECT DeviceObject);

BOOLEAN
PfpIsFileEncryptedAccordtoFileSize(LONGLONG Filesize);

typedef struct _tagDelayClose
{
	LIST_ENTRY	list;
	WCHAR		szDriver[3];
	LONG		nCount;
	PDISKFILEOBJECT pDiskFileObject;
}DALAYCLOSE,*PDALAYCLOSE;
//////////////////////////////////////////////////////////////////////////

//延迟 关闭
FAST_MUTEX g_DelayCloseMutex ;
LIST_ENTRY g_DelayCloseList;

VOID 
PfpAddDiskFileObjectIntoDelayClose(IN WCHAR szDriver[3],
								   IN PDISKFILEOBJECT pDiskFileObject);

PDISKFILEOBJECT 
PfpFindDiskFileObjectFromDelayClose(IN WCHAR szDriver[3],
									IN UNICODE_STRING * pFullPathWithoutDriver);

VOID
PfpDeleteDiskFileObjectFromDelayCloseUnderDir(IN WCHAR szDriver[3],
									IN UNICODE_STRING * pFullPathWithoutDriver);

VOID
PfpDeleteDiskFileObjectFromDelayCloseUnderDirByUsigObejct(PDISKDIROBEJECT pParent);

 

PDISKFILEOBJECT 
PfpGetDiskFileObjectFromDelayCloseByUsingFCBONDisk(PVOID FileObjectContext);

//////////////////////////////////////////////////////////////////////////
//
//dir control routines
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
//
//这里主要是用来 处理 批量加密的时候使用的数据结构
//
//////////////////////////////////////////////////////////////////////////

typedef struct _ENANDDECRYPTPARAM
{
	PVOID	pBuffer;
	ULONG   Len;
	BOOL	bEncrypt;
}DEANDENCRYPTPARAM,*PDEANDENCRYPTPARAM;

//////////////////////////////////////////////////////////////////////////
//FOLDER Protect structures
typedef enum _TAGCommandAction
{
	NEW =0,
	DELETEITEM,
	RESET,
	QUERY
}CommandAction;

typedef enum _TAGPROTECTTYPE
{
	NOACCESS_INVISIBLE =0,
	NOACCESS_VISABLE
}PROTECTTYPE;

typedef enum _FOLDERSTATE
{
	LOCKED =0,
	UNLOCK
}FOLDERSTATE;

typedef struct _tagFolderFileType
{
	WCHAR szFileType[50];
	ULONG bBackup;
}FOLDERFILETYPE,*PFOLDERFILETYPE;

typedef struct _TagFolderProtect
{
	PROTECTTYPE		Type;
	ULONG			bEncryptRealTime;
	ULONG			EncryptForFileTypes;
	ULONG			bBackup;
	ULONG			Action;	
	ULONG			State;
	ULONG			FileTypesNum;
	FOLDERFILETYPE	FileTypes[100];
	WCHAR			szDisplayName[50];//如果超过49个字符 就显示49个字符
	WCHAR			szFullPath[1];	
}FOLDERPROTECT,*PFOLDERPROTECT;

 
ERESOURCE  g_FolderResource;
LIST_ENTRY g_FolderProtectList;


typedef struct _TagFileTypeForFolder
{
	LIST_ENTRY		list;
	WCHAR szFileType[50];
	ULONG bBackup;
}FILETYPEOFFOLDERITEM,*PFILETYPEOFFOLDERITEM;


typedef struct _TagFolderProtectITEM
{
	LIST_ENTRY		list;
	PROTECTTYPE		Type;
	BOOLEAN			bEncryptRealTime;
	BOOLEAN			bBackup;
	ULONG			bEncryptForFileType;
	PWCHAR			pFileTypesForEncryption;
	LIST_ENTRY	    pListHeadOfFileTypes;
	ULONG			State;
	WCHAR			szDisplayName[50];//如果超过49个字符 就显示49个字符
	ULONG			szFullPathSize;
	WCHAR			szFullPath[1];
}FOLDERPROTECTITEM,*PFOLDERPROTECTITEM;


BOOLEAN IsFileTypeEncryptForFolder(IN		WCHAR* szDriver,
								   IN		WCHAR* szFolderWithoutDriverLetter,
								   IN		LONG   FolderLen,
								   IN		WCHAR* szFileType);

BOOLEAN IsFileNeedBackupForFolder(IN		WCHAR* szDriver,
								  IN		WCHAR* szFolderWithoutDriverLetter,
								  IN		LONG   FolderLen,
								  IN		WCHAR* pszFiletype);

BOOLEAN SetFileTypesForFolderEncryption(IN WCHAR *pFolderPath,IN WCHAR* szFileTypes);
BOOLEAN QueryFileTypesForFolderEncryption(IN WCHAR *pFolderPath,OUT WCHAR* szFileTypes,ULONG nLen);
BOOLEAN QueryFileTypesLenForFolderEncryption(IN WCHAR *pFolderPath,ULONG *pnLen);

BOOLEAN IsFolderUnderProtect(WCHAR *pFolderPath,ULONG nsize);
BOOLEAN	AddNewFolderUnderProtection(PFOLDERPROTECT pProtectFolder);
BOOLEAN DeleteFolderFromProtection(WCHAR *pFullPath);
BOOLEAN QueryFolerProtection(PFOLDERPROTECT pProtectFolder);
BOOLEAN ModifyFolerProtection(PFOLDERPROTECT pProtectFolder);
ULONG	CalcFolderProctectionLen();
ULONG   CopyFolderItemsIntoUserBuffer(PVOID pBuffer,ULONG nLen);
BOOLEAN IsFileOrFolderUnderProtect(WCHAR *pFolderPath,LONG nLen,BOOLEAN* bEncrypt,BOOLEAN *bBackup,BOOLEAN* bLocked);
VOID	InitFolerdProtectorFromBuffer (PVOID pBuffer,ULONG nLen);
//这个函数从全局的list entry中判断这个传入的路径是不是个人安全文件中的Child,如果是那么就返回这个个人安全文夹的保护设置
BOOLEAN GetFolderProtectProperty(IN		WCHAR* szDriver,
								 IN		WCHAR* szFolderWithoutDriverLetter,
								 IN		LONG   FolderLen,
								 OUT	PROTECTTYPE* ProtectType,
								 OUT	BOOLEAN* bEncrypt,
								 OUT	BOOLEAN *bBackup,
								 OUT	BOOLEAN* bLocked,
								 OUT	ULONG* EncryptMode);


BOOLEAN SetLockFolderState(PWCHAR pStrFolderPath,ULONG nLen,FOLDERSTATE state);

//////////////////////////////////////////////////////////////////////////
// OUR CONTROL Process HANLDE 
HANDLE  g_ourProcessHandle;
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

NTSTATUS 
PfpInitSystemSettings(HANDLE hFile);
NTSTATUS 
PfpSaveSystemSettings( );
//////////////////////////////////////////////////////////////////////////

NTSTATUS 
PfpInitDriverAtStartUp( IN PDRIVER_OBJECT  DriverObject, 
					   IN PVOID  Context, 
					   IN ULONG  Count );

UNICODE_STRING  g_RegistryPath; 
///
//
NTSTATUS 
PfpRenameOrDelBackUpFile(IN PPfpFCB Fcb,							  
						 IN FILE_INFORMATION_CLASS InformationClass , BOOLEAN bDelete );

NTSTATUS
PfpReBuildFullPathForDiskFileObjectAfterRename(PFILE_OBJECT pDiskFile,
											   PFILE_RENAME_INFORMATION pRenameInfo,
											   PIO_STACK_LOCATION pOrginalSp,PPfpFCB Fcb,PIRP_CONTEXT IrpContext);
//////////////////////////////////////////////////////////////////////////
#define try_return(S) { S; goto try_exit; };

typedef ULONG ACCESS_MASK, *PACCESS_MASK;
#define READ_AHEAD_GRANULARITY (0x10000) 

LARGE_INTEGER NtfsLarge0  ;    
LARGE_INTEGER NtfsLarge1  ;    

__declspec(dllimport) void   VirtualizerStart(void);
__declspec(dllimport) void   VirtualizerEnd(void);

#define FAT_DIRENT_ATTR_READ_ONLY        0x01
#define FAT_DIRENT_ATTR_HIDDEN           0x02
#define FAT_DIRENT_ATTR_SYSTEM           0x04
#define FAT_DIRENT_ATTR_VOLUME_ID        0x08
#define FAT_DIRENT_ATTR_DIRECTORY        0x10
#define FAT_DIRENT_ATTR_ARCHIVE          0x20
#define FAT_DIRENT_ATTR_DEVICE           0x40
#define FAT_DIRENT_ATTR_LFN              (FAT_DIRENT_ATTR_READ_ONLY | \
											FAT_DIRENT_ATTR_HIDDEN |    \
											FAT_DIRENT_ATTR_SYSTEM |    \
											FAT_DIRENT_ATTR_VOLUME_ID)

#define CCB_FLAG_DELETE_ON_CLOSE         (0x0400)
#define FCB_STATE_FILE_DELETED           (0x00000001)
#define FCB_STATE_NONPAGED               (0x00000002)
#define FCB_STATE_PAGING_FILE            (0x00000004)
#define FCB_STATE_DUP_INITIALIZED        (0x00000008)
#define FCB_STATE_UPDATE_STD_INFO        (0x00000010)
#define FCB_STATE_PRIMARY_LINK_DELETED   (0x00000020)
#define FCB_STATE_IN_FCB_TABLE           (0x00000040)
#define FCB_STATE_SYSTEM_FILE            (0x00000100)
#define FCB_STATE_COMPOUND_DATA          (0x00000200)
#define FCB_STATE_COMPOUND_INDEX         (0x00000400)
#define FCB_STATE_LARGE_STD_INFO         (0x00000800)
 #define FCB_STATE_DELETE_ON_CLOSE		(0x00001000)

#define FCB_INFO_CHANGED_CREATE          FILE_NOTIFY_CHANGE_CREATION        //  (0x00000040)
#define FCB_INFO_CHANGED_LAST_MOD        FILE_NOTIFY_CHANGE_LAST_WRITE      //  (0x00000010)
#define FCB_INFO_CHANGED_LAST_CHANGE     (0x80000000)
#define FCB_INFO_CHANGED_LAST_ACCESS     FILE_NOTIFY_CHANGE_LAST_ACCESS     //  (0x00000020)
#define FCB_INFO_CHANGED_ALLOC_SIZE      (0x40000000)
#define FCB_INFO_CHANGED_FILE_SIZE       FILE_NOTIFY_CHANGE_SIZE            //  (0x00000008)
#define FCB_INFO_CHANGED_FILE_ATTR       FILE_NOTIFY_CHANGE_ATTRIBUTES      //  (0x00000004)
#define FCB_INFO_CHANGED_EA_SIZE         FILE_NOTIFY_CHANGE_EA              //  (0x00000080)

#define FCB_INFO_MODIFIED_SECURITY       FILE_NOTIFY_CHANGE_SECURITY        //  (0x00000100)


#define Li0 (NtfsLarge0)
 

#define MAX_ZERO_THRESHOLD               (0x00400000)
#define HASHVALUEOFFSET					 600

#define CCB_FLAG_IGNORE_CASE                (0x00000001)
#define CCB_FLAG_OPEN_AS_FILE               (0x00000002)
#define CCB_FLAG_WILDCARD_IN_EXPRESSION     (0x00000004)
#define CCB_FLAG_OPEN_BY_FILE_ID            (0x00000008)
#define CCB_FLAG_USER_SET_LAST_MOD_TIME     (0x00000010)
#define CCB_FLAG_USER_SET_LAST_CHANGE_TIME  (0x00000020)
#define CCB_FLAG_USER_SET_LAST_ACCESS_TIME  (0x00000040)
#define CCB_FLAG_TRAVERSE_CHECK             (0x00000080)

#define CCB_FLAG_RETURN_DOT                 (0x00000100)
#define CCB_FLAG_RETURN_DOTDOT              (0x00000200)
#define CCB_FLAG_DOT_RETURNED               (0x00000400)
#define CCB_FLAG_DOTDOT_RETURNED            (0x00000800)

#define CCB_FLAG_DELETE_FILE                (0x00001000)
#define CCB_FLAG_DENY_DELETE                (0x00002000)

#define CCB_FLAG_ALLOCATED_FILE_NAME        (0x00004000)
//#define CCB_FLAG_CLEANUP                    (0x00008000)
#define CCB_FLAG_SYSTEM_HIVE                (0x00010000)

#define CCB_FLAG_PARENT_HAS_DOS_COMPONENT   (0x00020000)
//#define CCB_FLAG_DELETE_ON_CLOSE            (0x00040000)
#define CCB_FLAG_CLOSE                      (0x00080000)

#define CCB_FLAG_UPDATE_LAST_MODIFY         (0x00100000)
#define CCB_FLAG_UPDATE_LAST_CHANGE         (0x00200000)
#define CCB_FLAG_SET_ARCHIVE                (0x00400000)

#define CCB_FLAG_DIR_NOTIFY                 (0x00800000)
#define CCB_FLAG_ALLOW_XTENDED_DASD_IO      (0x01000000)

//#define FCB_STATE_DELETE_ON_CLOSE			(0x00000001)
#define FCB_STATE_TEMPORARY					(0x00080000)

#define VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatchPtr, FieldName) \
	(((FastIoDispatchPtr) != NULL) && \
	(((FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
	(FIELD_OFFSET(FAST_IO_DISPATCH, FieldName) + sizeof(VOID *))) && \
	((FastIoDispatchPtr)->FieldName != NULL))


#include "fspydef.h"



ULONG g_nRunningState;

ULONG g_nHIDEState;

BOOLEAN	g_bInitialized;	
ULONG	ExeHasLoggon;


typedef struct _tagMODIFYPSW
{
	UINT nModifyType; //1:修改user psw，2:修改key file 的密码 3：2个密码同时都要修改
	WCHAR szUserName[50];
	WCHAR szOldUserPSW[25];
	WCHAR szNewUserPSW[25];
	WCHAR szOldKeyPSW[25];
	WCHAR szNewKeyPSW[25];
}MODIFYPSW,*PMODIFYPSW;

unsigned char g_digestForUserPSW[16];
unsigned char g_digestForKeyPSW[16];

PWCHAR		g_KeyFilePath;


PWCHAR		g_DriverDir;
HANDLE		g_ConfigFile;
BOOLEAN		g_bProtectSySself;
BOOLEAN		g_bEncrypteUDISK;

BOOLEAN PfpIsFileSysProtected(PUNICODE_STRING pFileName);


ULONG GetStorageDeviceBusType(IN PDEVICE_OBJECT DeviceObject,UCHAR ** pszId,ULONG * nLen);



HANDLE PfpGetHandleFromObject(PFILE_OBJECT pFileobject);

BOOLEAN	PfpIsAllFileObjectThroughCleanup(PDISKFILEOBJECT pDiskFileobject);
VOID
PfpCloseFileHasGoThroughCleanupAndNotUsed(PDISKFILEOBJECT pDiskFileObject);

ULONG	PfpGetUncleanupCount(PDISKFILEOBJECT pDiskFileobject);

BOOLEAN PfpIsBackupFileObjectStillValid(PDISKFILEOBJECT pDiskFileobject);

UNICODE_STRING g_p1,g_p2,g_p3,g_p4,g_p5,g_p6;

BOOLEAN IsFileUnderBackupDir(WCHAR *szDevice, UNICODE_STRING* pFilePath);


BOOLEAN  IsDirectory(ULONG Action);
BOOLEAN  IsOpenDirectory(UCHAR Action);

BOOL	 IsFileTypeBelongExeType(WCHAR* pExt);

VOID	 DoLog(WCHAR* szDevice, UNICODE_STRING *pFilePath,UNICODE_STRING * pProcessImage,BOOLEAN bCreate,BOOLEAN bEncrypted);


BOOLEAN		DoDecryptOnSameFile(HANDLE hFile,PFILE_OBJECT pFileObject,PDEVICE_OBJECT pNextDevice);
BOOLEAN		DoEncryptOnSameFile(HANDLE hFile,PFILE_OBJECT pFileObject,PDEVICE_OBJECT pNextDevice);



BOOLEAN	
PfpGetDosNameFromFullPath (IN WCHAR *pszFullPath, 
						   IN LONG Len,
						   OUT WCHAR* szDosName);

BOOLEAN
PfpIsDeviceOfUSBType(PDEVICE_OBJECT pOurDeviceObject);



BOOLEAN
PfpDoesPathInvalid(PWCHAR szFullPath);

BOOLEAN 
PfpIsFileNameValid(PWCHAR szFileName,ULONG len);

VOID
PfpSetFileNotEncryptSize(IN PFILE_OBJECT hFileObject,
						 IN LARGE_INTEGER filesize,
						 IN PDEVICE_OBJECT pNextDevice);


NTSTATUS
PfpSetFileInforByIrp(IN PFILE_OBJECT hFileObject,
					 IN PUCHAR pBuffer,
					 IN ULONG  len,
					 IN FILE_INFORMATION_CLASS Information,
					 IN PDEVICE_OBJECT pNextDevice);


NTSTATUS
PfpQueryFileInforByIrp(IN PFILE_OBJECT hFileObject,
					 IN OUT PUCHAR pBuffer,
					 IN ULONG  len,
					 IN FILE_INFORMATION_CLASS Information,
					 IN PDEVICE_OBJECT pNextDevice);




typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	USHORT   e_magic;                     // Magic number
	USHORT   e_cblp;                      // Bytes on last page of file
	USHORT   e_cp;                        // Pages in file
	USHORT   e_crlc;                      // Relocations
	USHORT   e_cparhdr;                   // Size of header in paragraphs
	USHORT   e_minalloc;                  // Minimum extra paragraphs needed
	USHORT   e_maxalloc;                  // Maximum extra paragraphs needed
	USHORT   e_ss;                        // Initial (relative) SS value
	USHORT   e_sp;                        // Initial SP value
	USHORT   e_csum;                      // Checksum
	USHORT   e_ip;                        // Initial IP value
	USHORT   e_cs;                        // Initial (relative) CS value
	USHORT   e_lfarlc;                    // File address of relocation table
	USHORT   e_ovno;                      // Overlay number
	USHORT   e_res[4];                    // Reserved words
	USHORT   e_oemid;                     // OEM identifier (for e_oeminfo)
	USHORT   e_oeminfo;                   // OEM information; e_oemid specific
	USHORT   e_res2[10];                  // Reserved words
	LONG     e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define IMAGE_DOS_SIGNATURE                 0x4D5A      // MZ
#define IMAGE_OS2_SIGNATURE                 0x4E45      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x4C45      // LE
#define IMAGE_NT_SIGNATURE                  0x50450000  // PE00

BOOLEAN
PfpFileIsPe(PUCHAR pBuffer,ULONG nlen,ULONG* nlenNeed);

#define ExFreePool_A(a) ExFreePool(a)
#define ExAllocatePool_A(a,b) ExAllocatePoolWithTag(a,b,'Pf88')




typedef struct _HashValue
{
	UCHAR HashValue[PROCESSHASHVALULENGTH];
}PROGHASHVALUEITEM,*PPROGHASHVALUEITEM;


ULONG PfpGetProgNum();

NTSTATUS 
PfpGetHashValueIntoArray(PPROGHASHVALUEITEM pHashValueArray,ULONG nSize);


typedef struct _FILETYPE_ENCRYPT 
{
	WCHAR	psztype[50];
	BOOLEAN   bEncrypt;//对此类型的文件要求加密	
	BOOLEAN   bBackUp;	//对此类型的文件要求备份
 
}FILETYPE_INFO,*PFILETYPE_INFO;

typedef struct _tagProgProtection
{   
	ULONG	 bEncrypt;//是否加密
	ULONG	 bForceEncrypt;//是否是强制加密
	ULONG	 bEnableBackupForProg;//此程序是否要求实时备份
	ULONG	 bAllowInherent;//对此程序是否允许子程序访问它产生的加密文件
	ULONG	 bAlone;

}PROGPROTECTION,*PPROGPROTECTION;


typedef struct _tagAddProtectionForProg
{	
	PROGHASHVALUEITEM hashValue;
	WCHAR			  szExeFullPath[1024];
	PROGPROTECTION	  protectInfo;
	ULONG			  nNumFileTypes;
	FILETYPE_INFO	  FileTypes[1];
}ADDPROTECTIONFORPROG,*PADDPROTECTIONFORPROG;



typedef struct _tagSetFileTypesByArray
{
	PROGHASHVALUEITEM	hashvalue;
	ULONG				nEncryptionTypeValue;
	ULONG				nFileTypes;
	FILETYPE_INFO		Filetype[1];
}SETFILETYPESBYARRAY,*PSETFILETYPESBYARRAY;

NTSTATUS 
PfpGetFileTypesForProg(IN PUCHAR pHashValue,
					   IN ULONG nSize,
					   IN OUT PFILETYPE_INFO pFileTypeArray,
					   IN ULONG nSizeType);


NTSTATUS
PfpGetFileFileTypeNumForProg(IN PUCHAR pHashValue,
							 IN ULONG nSize,
							 IN OUT ULONG *nNUM);

NTSTATUS
PfpGetProtectionInfoForProg(IN PUCHAR pHashValue,
							IN ULONG nSize,
							IN OUT PPROGPROTECTION pProtection);

NTSTATUS
PfpAddProtectionFroProg(IN PADDPROTECTIONFORPROG pProtecForAdding);


VOID
PfpAddFileTypesToProcessInfoByFileTypeArray(IN PPROCESSINFO pProcessInfo,
											IN PFILETYPE_INFO pFileTypes,
											IN ULONG nNum);



//////////////////////////////////////////////////////////////////////////
typedef struct _tagFolderPath
{
	WCHAR szFolderPath[1024];
}FOLDERPATH,*PFOLDERPATH;





typedef struct _tagSetFileTypesForFolder
{
	FOLDERPATH		folderPath;
	ULONG			nNumofFileTypes;
	FOLDERFILETYPE	FileTyps[1];
}SETFILETYPESFORFOLDER,*PSETFILETYPESFORFOLDER;

typedef struct _tagFolderProtectSetting
{
	WCHAR szFolderPath[1024];
	ULONG nEnabler;
}FOLDERPROTECTSETTING,*PFOLDERPROTECTSETTING;
typedef struct _tagFodlerProtectorInfo
{
	PROTECTTYPE Type;	
	ULONG		bEncryptRealTime;
	ULONG		EncryptForFileTypes;
	ULONG		bBackup;	
	ULONG       State;	
	WCHAR		szDisplayName[50];
}FODLERPROTECTORINFO,*PFODLERPROTECTORINFO;

typedef struct _tagAddProtectedFolder
{
	WCHAR		szFolderPath[1024];
	FODLERPROTECTORINFO FolderProtectInfo;
}ADDPROTECTEDFOLDER,*PADDPROTECTEDFOLDER,*PFolderWithProtectorInfo,FolderWithProtectorInfo;



typedef struct _tagFolderDisplayName
{
	WCHAR szFolderPath[1024];
	WCHAR szDisplayName[50];
}FOLDERDISPLAYNAME,*PFOLDERDISPLAYNAME;


NTSTATUS
PfpEnableFolderRealTimeEncrypt(IN PFOLDERPROTECTSETTING pFolderEnable);

NTSTATUS
PfpChangeFolderProtectType(IN PFOLDERPROTECTSETTING pFolderEnable);

NTSTATUS
PfpChangeFolderState(IN PFOLDERPROTECTSETTING pFolderEnable);


NTSTATUS
PfpEnableFolderBackup(IN PFOLDERPROTECTSETTING pFolderEnable);


NTSTATUS
PfpChangeEncryptionTypeForFolder(IN PFOLDERPROTECTSETTING pFolderEnable);

PFOLDERPROTECTITEM
PfpGetFolderItem(PWCHAR szFolderPath,ULONG nSize);

BOOLEAN  LockAllFolders();

NTSTATUS
PfpIsFolderLocked(PWCHAR szFolderPath,BOOLEAN* pbLocked);


NTSTATUS
PfpSetDisplayNameForFolder(PWCHAR szFolderPath,PWCHAR szDisplayName);


NTSTATUS
PfpGetDisplayNameForFolder(PWCHAR szFolderPath,PWCHAR szDisplayName,ULONG nLen);


NTSTATUS 
PfpAddProtectedFolder(PWCHAR szFolderPath,PFODLERPROTECTORINFO pProtectioInfo);

NTSTATUS 
PfpDelProtectedFolder(PWCHAR szFolderPath);

NTSTATUS 
PfpSetProtectedFolder(PWCHAR szFolderPath,PFODLERPROTECTORINFO pProtectioInfo);


NTSTATUS 
PfpGetProtectedFolderNum(ULONG *pNum);

NTSTATUS 
PfpGetFolderPathIntoArray(PFOLDERPATH pFolderPathArray,ULONG* pnNum);

NTSTATUS
PfpGetNumofFiletypsForProtectedFolder(PWCHAR lpszFolderPath,ULONG* pnNum);

ULONG
PfpGetNumofFileTypes(PFOLDERPROTECTITEM FolderItem);


NTSTATUS
PfpGetFileTypesForProtectedFolder(IN PWCHAR pszFolderPath,
								  IN PFOLDERFILETYPE pFiletypesArray,
								  IN OUT ULONG* pnLen);

NTSTATUS
PfpGetFolderProtectInfo(IN PWCHAR lpszFolderPath,
						IN PFODLERPROTECTORINFO pFolderProtectorInfo);

NTSTATUS 
PfpSetFileTypesForFolder(PSETFILETYPESFORFOLDER  pFiletypesForFolder);


VOID
PfpDeleteAllFileTypesOfFolder(PFOLDERPROTECTITEM FolderItem);


ULONG 
PfpCopyFileTypesIntoBufferForFolder(IN OUT PFOLDERFILETYPE pFolderTypes,IN OUT ULONG nNum,IN PLIST_ENTRY  pFileTypeHead);

//////////////////////////////////////////////////////////////////////////
//for hider item

ULONG 
PfpGetNumOfHidder();

typedef struct _tagHidderItem
{
	WCHAR	szFullPath[1024];
	ULONG   bDir;
	ULONG   nHide;
}HIDDERITEM,*PHIDDERITEM;


NTSTATUS
PfpGetHidderItemsByArray(IN PHIDDERITEM pItemArray,
						 IN OUT ULONG* pNums);


NTSTATUS
PfpAddHidderItem(IN PHIDDERITEM pItemArray,
				 IN OUT ULONG*  pNums);
NTSTATUS 
PfpSetHideItemState(IN PHIDDERITEM pItem);

BOOLEAN g_bUsbDeviceEncryptedForFileType;
// 
// NTSTATUS
// PfpSetUsbEncryptMode(BOOLEAN bEncryptByFileType);
// 
// NTSTATUS
// PfpGetUsbEncryptMode(BOOLEAN* pbEncryptByFileType);
// 
// LIST_ENTRY g_UsbFileTypes;
// FAST_MUTEX g_UsbFileTypeLock;
// 
// 
// typedef struct _tagUsbFileTypeItem
// {
// 	LIST_ENTRY	listHead;
// 	WCHAR		szFiletype[50];
// }USBFILETYPEITEM,*PUSBFILETYPEITEM;
// 
// typedef struct _tagRemovedeviceFileType
// {
// 	WCHAR szFiletype[50];
// }FILETYPE_REMOVEABLEDEVICE,*PFILETYPE_REMOVEABLEDEVICE;
// 
// 
// NTSTATUS
// PfpSetFileTypesForUsb(IN PFILETYPE_REMOVEABLEDEVICE pUsbEncryptFileTypes,
// 					  IN ULONG nNum);
// 
// NTSTATUS
// PfpGetFileTypesForUsb(IN OUT PFILETYPE_REMOVEABLEDEVICE pUsbEncryptFileTypes,
// 					  IN OUT ULONG* pnNum);
// 
// NTSTATUS
// PfpGetNumofFileTypesForUsb(IN OUT ULONG* pnNum);
// 
// 
// VOID
// PfpRemoveALLFileTypeOfUsb();

////////////////////////////////

typedef struct _tagBrowserFileType
{	
	PROGHASHVALUEITEM hashValue;
	ULONG			  lBrowserEncryptType;
}BROWSERFILETYPE,*PBROWSERFILETYPE;

#define 	PIC_TYPE		0x00000001
#define		COOKIE_TYPE		0x00000002
#define		VEDIO_TYPE		0x00000004
#define		TEXT_TYPE		0x00000008
#define		SCRIPT_TYPE		0x00000010
#define		ALL_TYPE		0x00000020

typedef struct _tagBrowserProtection
{   
	PROGHASHVALUEITEM	hashValue;
	WCHAR				szExeFullPath[1024];
	PROGPROTECTION		ProgProtection;
	ULONG				bAllowCreateExeFile;	
}BROWSERPROTECTION,*PBROWSERPROTECTION;

//////////////////////////////////////////
//browser api
ULONG PfpGetBrowserCount();
NTSTATUS 
PfpGetBrowserHashValueIntoArray(PPROGHASHVALUEITEM pHashValueArray,ULONG nSize);

VOID 
PfpSetBrowserAllowCreateExeFile(UCHAR* szHashValue,BOOLEAN bEnable);

VOID 
PfpGetBrowserEncryptTypeValue(UCHAR* szHashValue,ULONG* nTypeValue);
VOID
PfpSetBrowserEncryptTypeValue(UCHAR* szHashValue,ULONG nTypeValue);

VOID 
PfpGetBrowserEncryptFileTypesNum(UCHAR* szHashValue,ULONG nEncrytType,ULONG* plNum);

NTSTATUS 
PfpGetBrowserEncryptFileTypes(UCHAR* szHashValue,ULONG nEncrytType,PFILETYPE_INFO pFileTypes, ULONG lNum);

VOID
PfpAddFileTypesForBrowserInfoByFileTypeArray(IN PPROCESSINFO   pProcessInfo,
											IN ULONG		  nEncryptionType,
											IN PFILETYPE_INFO pFileTypes,
											IN ULONG nNum);

VOID 
PfpDeleteAllFileTypesOfBrowser(
							   IN PPROCESSINFO pProcessInfo,
							   IN ULONG			nEncryptType);

LONG  Type2ArrayIndex(ULONG nType);

NTSTATUS
PfpAddBrowserProtection(PBROWSERPROTECTION pBrowser);

NTSTATUS
PfpGetBrowserProtection(PPROGHASHVALUEITEM phashValue,PBROWSERPROTECTION pBrowser);
//////////////////////////////////////////////////////////////////////////
//LOG API s

typedef struct _tagREADLOG
{
	ULONG Operation;//1 create 0: close  2:process exit
	ULONG encrypt;  //1: encrypt 0; not encrypt ,process id
	WCHAR szName[20];
	ULONG ProcessID;
	WCHAR FilePath[1024];
}READLOG,*PREADLOG;

BOOLEAN		GetLogInfoFromQueNew(PREADLOG szLogOut);




BOOLEAN  IsFileDirectroy(PWCHAR szFullPathWithoutDeicve,ULONG nLenWchar, PDEVICE_OBJECT pDevice);
BOOLEAN  IsFileUnderDirecotry(PWCHAR pszDir,ULONG nLenChar,PWCHAR pFilePath,ULONG nLenCharFile);

PDISKDIROBEJECT 
PfpCreateVirtualDirObject(PWCHAR pDirName,PDISKDIROBEJECT pParent);

VOID 
PfpDeleteVirtualDir(PDISKDIROBEJECT* pVirtualDir);

PDISKFILEOBJECT 
PfpFindDiskFileObjectInParent(PDISKDIROBEJECT pParent ,UNICODE_STRING* FileFullPath);


VOID
PfpAddDiskFileObjectIntoItsVirtualDiskFile(PVIRTUALDISKFILE pVirtualDiskFile,PDISKFILEOBJECT pDiskFile);


PDISKDIROBEJECT 
PfpMakeVirtualChildDirForFile(PDISKDIROBEJECT pTopVirtualDir,PWCHAR* pRemainFilePath);

PDISKDIROBEJECT 
PfpPareseToDirObject(PDISKDIROBEJECT pParentDir,PWCHAR szFullFileName,PWCHAR* pRemainer,BOOLEAN* bComplete);


PDISKDIROBEJECT
PfpGetDiskDirObject(PDISKDIROBEJECT pParentDir,PWCHAR szFullFileDir,ULONG nLeninBytes);

PERESOURCE
PfpCloseDiskFilesUnderVirtualDirHasGoneThroughCleanUp(PDISKDIROBEJECT pVirtualParent,PDISKDIROBEJECT pVirtualDir);


VOID
PfpCloseDiskFileObjectHasGoneThroughCleanUpInVirtualDiskFile(PVIRTUALDISKFILE pVirtualDiskFileObject);



extern PAGED_LOOKASIDE_LIST g_VirualDirLookasideList;
extern PAGED_LOOKASIDE_LIST g_VirualDiskFileLookasideList;

extern NPAGED_LOOKASIDE_LIST g_PfpFCBLookasideList;
extern NPAGED_LOOKASIDE_LIST g_EresourceLookasideList;
extern NPAGED_LOOKASIDE_LIST g_FaseMutexInFCBLookasideList;
extern NPAGED_LOOKASIDE_LIST g_ListEntryInFCBLookasideList;
extern NPAGED_LOOKASIDE_LIST g_NTFSFCBLookasideList;
extern NPAGED_LOOKASIDE_LIST g_UserFileObejctLookasideList;

extern NPAGED_LOOKASIDE_LIST g_DiskFileObejctLookasideList;

PVIRTUALDISKFILE CreateVirDiskFileAndInsertIntoParentVirtual(PDISKDIROBEJECT pParent,PWCHAR szFileName);


PVIRTUALDISKFILE 
PfpFindVirtualDiskFileObjectInParent(PDISKDIROBEJECT pParent ,UNICODE_STRING* FileFullPath);
PDISKFILEOBJECT
PpfGetDiskFileObjectFromVirtualDisk(PVIRTUALDISKFILE pVirtualDiskFile);

BOOLEAN 
PfpDeleteVirtualDiskFile(PVIRTUALDISKFILE pVirtualDiskFile,PDISKFILEOBJECT pDiskFileObject);

VOID
PfpCloseDiskFileObjectHasGoneThroughCleanUp(PDISKFILEOBJECT pDiskFileObject);

VOID 
PfpCloseDiskFileObjectsUnderDir(PWCHAR pszFolderPath);

BOOLEAN 
PfpIsDirParentOfHide(PWCHAR szDirFullPath,ULONG nLen);
BOOLEAN 
PfpIsDirParentOfSecureFolder(PWCHAR szDirFullPath,ULONG nLen);


BOOLEAN g_AllowDisplayFrameOnWindow;



ULONG GetVolumeSerialNumber(WCHAR* szDriverLetter);

BOOLEAN GetUsbStorageDeviceID(UCHAR ** pszId,ULONG * nLen,IN PDEVICE_OBJECT DeviceObject);


BOOLEAN IsBrower(UCHAR* pHashValue);


//

HANDLE  g_ExcludeID;
HANDLE GetExcludeProcessID(WCHAR* pszProcessName);

//////////////////////////////////////////////////////////////////////////
KEVENT g_EventSaveFile;
NTSTATUS  PfpSaveSystemSettingsEx();
VOID PfpSaveFileWorker ( PVOID Context );

//////////////////////////////////////////////////////////////////////////

//used in secure folder protect mode
enum
{
	ENCRYPT_ALL=0,
	ENCRYPT_TYPES,
	ENCRYPT_NONE
};

//////////////////////////////////////////////////////////////////////////

typedef struct _REGISTRY_EVENT {
	REG_NOTIFY_CLASS eventType;
	TIME_FIELDS time; 
	HANDLE processId;
	ULONG dataType;
	ULONG dataLengthB;
	ULONG registryPathLengthB;
	UCHAR registryData[];
} REGISTRY_EVENT, * PREGISTRY_EVENT;

typedef struct _REGISTRY_EVENT_PACKET {
	LIST_ENTRY Link;
	PREGISTRY_EVENT pRegistryEvent;
} REGISTRY_EVENT_PACKET, * PREGISTRY_EVENT_PACKET; 

typedef struct _CAPTURE_REGISTRY_MANAGER 
{
	PDEVICE_OBJECT deviceObject;
	BOOLEAN bReady;
	LARGE_INTEGER registryCallbackCookie;
	LIST_ENTRY lQueuedRegistryEvents;
	KTIMER connectionCheckerTimer;
	KDPC connectionCheckerFunction;
	KSPIN_LOCK lQueuedRegistryEventsSpinLock;
	ULONG lastContactTime;
} CAPTURE_REGISTRY_MANAGER , *PCAPTURE_REGISTRY_MANAGER;

WCHAR g_szRegisterKey[100]; 
ULONG g_nLenOfKey;


WCHAR g_szRegisterKeyMin[100]; 
ULONG g_nLenOfKeyMin;


WCHAR g_szRegisterKeyNetwork[100]; 
ULONG g_nLenOfKeyNetwork;

ULONG g_nLenOfKeyDir;
 
BOOLEAN g_bRegisterProtect;
CAPTURE_REGISTRY_MANAGER g_RegistrContext;
NTSTATUS RegistryCallback(IN PVOID CallbackContext, IN PVOID Argument1, IN PVOID Argument2);
BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PUNICODE_STRING pPartialRegistryPath, PVOID pRegistryObject);
BOOLEAN QueueRegistryEvent(PREGISTRY_EVENT pRegistryEvent);

BOOLEAN IsProtectedRegisterKey(PUNICODE_STRING pRegisterPath);
//////////////////////////////////////////////////////////////////////////
//这个是为了从外面传加密key使用的
BOOLEAN g_bUseExternKey;

//register releated functions

#endif /* __FSPYKERN_H__ */

