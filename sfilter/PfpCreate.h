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
#ifndef __FSPYCREATE
#define __FSPYCREATE

#define HASH_SIZE            128        // MUST be a power of 2

#include "windef.h"
typedef struct _tagCreateContext
{
	LIST_ENTRY list;
	HANDLE	phFileCreated;
	ACCESS_MASK  DesiredAccess;
	WCHAR * pFilePath;
	IO_STATUS_BLOCK  IoStatusBlock;
	LARGE_INTEGER  AllocationSize  ;
	ULONG  FileAttributes;
	ULONG  ShareAccess;
	ULONG  CreateDisposition;
	ULONG  CreateOptions;
	PVOID  EaBuffer ;
	ULONG  EaLength;
	KEVENT	hEvent;
	NTSTATUS ntstatus;
}CREATECONTEXT,*PCREATECONTEXT;

extern NPAGED_LOOKASIDE_LIST PfpCreateContextLookasideList;
VOID
PfpCreateFileWorker (
						/*__in PUSB_DEVICE_INITIALIZE_WORKITEM Context*/
						PVOID  Context
						);

VOID
PfpCreateFileWorker1 (
					 /*__in PUSB_DEVICE_INITIALIZE_WORKITEM Context*/
					 PVOID  Context
						);

KSPIN_LOCK gCreateContextLock;
KEVENT	   g_EventCreateThread;	
LIST_ENTRY g_CreateContext;


KSPIN_LOCK gCreateContextLock1;
KEVENT	   g_EventCreateThread1;	
LIST_ENTRY g_CreateContext1;
LARGE_INTEGER	g_CreateNum;
VOID		InsertCreateContextIntoLists(PCREATECONTEXT pCreateContext);
#endif

