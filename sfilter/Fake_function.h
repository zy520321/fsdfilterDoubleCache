 /*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    fspydef.h

Abstract:
    Header file which contains the definitions that may be
    shared with the file spy kernel debugger extensions


Environment:

    Kernel mode

--*/
#ifndef __FSPYDEF_FAKE_FUNCTIONS
#define __FSPYDEF_FAKE_FUNCTIONS
NTSTATUS Fake_PfpRead( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpReadFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpReadType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpReadType *PFAKE_PFPREAD ;
PFAKE_PFPREAD  g_NtfsRead;
PFAKE_PFPREAD  g_Fat32Read;

NTSTATUS Fake_PfpWrite( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpWriteFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpWriteType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpWriteType* PFAKE_PFPWRITE;
PFAKE_PFPWRITE g_NtfsWrite;
PFAKE_PFPWRITE g_Fat32Write;


NTSTATUS Fake_PfpFsdClose( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpFsdCloseFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpFsdCloseType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpFsdCloseType* PFAKE_PFPFSDCLOSE;
PFAKE_PFPFSDCLOSE g_NtfsClose;
PFAKE_PFPFSDCLOSE g_Fat32Close;

NTSTATUS Fake_PfpQueryInformation( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpQueryInformationFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpQueryInformationType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpQueryInformationType* PFAKE_PFPQUERYINFORMATION;
PFAKE_PFPQUERYINFORMATION g_NtfsQuery;
PFAKE_PFPQUERYINFORMATION g_Fat32Query;

NTSTATUS Fake_PfpSetInformation( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpSetInformationFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpSetInformationType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpSetInformationType* PFAKE_PFPSETINFORMATION;
PFAKE_PFPSETINFORMATION g_NtfsSet;
PFAKE_PFPSETINFORMATION g_Fat32Set;


NTSTATUS Fake_PfpFsdQueryEa( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpFsdQueryEaFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpFsdQueryEaType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpFsdQueryEaType* PFAKE_PFPFSDQUERYEA;
PFAKE_PFPFSDQUERYEA g_NtfsQueryEA;
PFAKE_PFPFSDQUERYEA g_Fat32QueryEA;

NTSTATUS Fake_PfpFsdSetEa( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpFsdSetEaFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpFsdSetEaType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpFsdSetEaType* PFAKE_PFPFSDSETEA;
PFAKE_PFPFSDSETEA g_NtfsSetEA;
PFAKE_PFPFSDSETEA g_Fat32SetEA;

NTSTATUS Fake_PfpFsdFlushBuffers( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );

NTSTATUS Fake_PfpFsdFlushBuffersFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpFsdFlushBuffersType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpFsdFlushBuffersType* PFAKE_PFPFSDFLUSHBUFFERS;
PFAKE_PFPFSDFLUSHBUFFERS g_NtfsFlush;
PFAKE_PFPFSDFLUSHBUFFERS g_Fat32Flush;

NTSTATUS Fake_PfpFsdCleanup( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
NTSTATUS Fake_PfpFsdCleanupFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef NTSTATUS Fake_PfpFsdCleanupType( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
typedef Fake_PfpFsdCleanupType* PFAKE_PFPFSDCLEANUP;
PFAKE_PFPFSDCLEANUP g_NtfsCleanup;
PFAKE_PFPFSDCLEANUP g_Fat32Cleanup;

NTSTATUS Fake_PfpFsQueryAndSetSec( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp );
 



#endif

