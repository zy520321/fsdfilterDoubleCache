 /*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    filespy.c

Abstract:

    This module contains all of the routines for tracking names by
    hashing the FileObject.  This cache is limited in size by the
    following registry setting "MaxNames".

Environment:

    Kernel mode

--*/

#include <ntifs.h>
#include "filespy.h"
#include "fspyKern.h"
 

#if !USE_STREAM_CONTEXTS

////////////////////////////////////////////////////////////////////////
//
//                    Local definitions
//
////////////////////////////////////////////////////////////////////////

#define HASH_FUNC(FileObject) \
    (((UINT_PTR)(FileObject) >> 8) & (HASH_SIZE - 1))

////////////////////////////////////////////////////////////////////////
//
//                    Global Variables
//
////////////////////////////////////////////////////////////////////////

//
//  NOTE:  Must use KSPIN_LOCKs to synchronize access to hash buckets since
//         we may try to acquire them at DISPATCH_LEVEL.
//

LIST_ENTRY gHashTable[HASH_SIZE];
KSPIN_LOCK gHashLockTable[HASH_SIZE];
ULONG gHashMaxCounters[HASH_SIZE];
ULONG gHashCurrentCounters[HASH_SIZE];

UNICODE_STRING OutOfBuffers = CONSTANT_UNICODE_STRING(L"[-=Out Of Buffers=-]");
UNICODE_STRING PagingFile = CONSTANT_UNICODE_STRING(L"[-=Paging File=-]");


////////////////////////////////////////////////////////////////////////
//
//                    Local prototypes
//
////////////////////////////////////////////////////////////////////////

VOID
SpyDeleteContextCallback(
    __in PVOID Context
    );


//
//  Linker commands
//

#ifdef ALLOC_PRAGMA

#pragma alloc_text(PAGE, SpyInitNamingEnvironment)
#pragma alloc_text(PAGE, SpyInitDeviceNamingEnvironment)
#pragma alloc_text(PAGE, SpyCleanupDeviceNamingEnvironment)

#endif  // ALLOC_PRAGMA


////////////////////////////////////////////////////////////////////////
//
//                    Main routines
//
////////////////////////////////////////////////////////////////////////


VOID
SpyInitNamingEnvironment(
    VOID
    )
/*++

Routine Description:

    Init global variables.

Arguments:

    None

Return Value:

    None.

--*/
{
    int i;

    PAGED_CODE();

    //
    //  Initialize the hash table.
    //

    for (i = 0; i < HASH_SIZE; i++){

        InitializeListHead( &gHashTable[i] );
        KeInitializeSpinLock( &gHashLockTable[i] );
    }
}


VOID
SpyInitDeviceNamingEnvironment (
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    Initialize the per DeviceObject naming environment.

Arguments:

    DeviceObject - The device object to initialize.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( DeviceObject );
}


VOID
SpyCleanupDeviceNamingEnvironment (
    __in PDEVICE_OBJECT DeviceObject
    )
/*++

Routine Description:

    Initialize the per DeviceObject naming environment.

Arguments:

    DeviceObject - The device object to initialize.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( DeviceObject );
}



////////////////////////////////////////////////////////////////////////
//
//                    FileName cache routines
//
////////////////////////////////////////////////////////////////////////

PHASH_ENTRY
SpyHashBucketLookup (
    __in PLIST_ENTRY  ListHead,
    __in PFILE_OBJECT FileObject
    )
/*++

Routine Description:

    This routine looks up the FileObject in the give hash bucket.  This routine
    does NOT lock the hash bucket; it must be locked by the caller.

Arguments:

    ListHead - hash list to search
    FileObject - the FileObject to look up.

Return Value:

    A pointer to the hash table entry.  NULL if not found

--*/
{
    PHASH_ENTRY pHash;
    PLIST_ENTRY pList;

    pList = ListHead->Flink;

    while (pList != ListHead){

        pHash = CONTAINING_RECORD( pList, HASH_ENTRY, List );

        if (FileObject == pHash->FileObject) {

            return pHash;
        }

        pList = pList->Flink;
    }

    return NULL;
}
/*
VOID
SpySetName (
    __inout PRECORD_LIST RecordList,
    __in PDEVICE_OBJECT DeviceObject,
    __in_opt PFILE_OBJECT FileObject,
    __in ULONG LookupFlags,
    __in_opt PVOID Context
    )
/*++

Routine Description:

    This routine looks up the FileObject in the hash table.  If the FileObject
    is found in the hash table, copy the associated file name to RecordList.
    Otherwise, calls NLGetFullPathName to try to get the name of the FileObject.
    If successful, copy the file name to the RecordList and insert into hash
    table.

Arguments:

    RecordList - RecordList to copy name to.
    FileObject - the FileObject to look up.
    LookInFileObject - see routine description
    DeviceExtension - contains the volume name (e.g., "c:") and
        the next device object which may be needed.

Return Value:

    None.

--*/
/*
{
    PFILESPY_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
    UINT_PTR hashIndex;
    KIRQL oldIrql;
    PHASH_ENTRY pHash;
    PHASH_ENTRY newHash;
    PLIST_ENTRY listHead;
    PNAME_CONTROL newName = NULL;
    PCHAR buffer = NULL;
    NTSTATUS status;
    BOOLEAN cacheName;

    UNREFERENCED_PARAMETER( Context );

    try {

        if (FileObject == NULL) {

            SpyCopyFileNameToLogRecord( &RecordList->LogRecord, &gEmptyUnicode );
            leave;
        }

        hashIndex = HASH_FUNC(FileObject);

        INC_STATS(TotalContextSearches);

        listHead = &gHashTable[hashIndex];

        //
        //  Don't bother checking the hash if we are in create, we must always
        //  generate a name.
        //

        if (!FlagOn(LookupFlags, NLFL_IN_CREATE)) {

            //
            //  Acquire the hash lock
            //

            KeAcquireSpinLock( &gHashLockTable[hashIndex], &oldIrql );

            pHash = SpyHashBucketLookup( &gHashTable[hashIndex], FileObject );

            if (pHash != NULL) {

                //
                //  Copy the found file name to the LogRecord
                //

                SpyCopyFileNameToLogRecord( &RecordList->LogRecord, &pHash->Name );

                KeReleaseSpinLock( &gHashLockTable[hashIndex], oldIrql );

                INC_STATS( TotalContextFound );

                leave;
            }

            KeReleaseSpinLock( &gHashLockTable[hashIndex], oldIrql );
        }

#if WINVER >= 0x0501
        //
        //  We can not allocate paged pool if this is a paging file.  If it is
        //  a paging file set a default name and return
        //

        if (FsRtlIsPagingFile( FileObject )) {

            SpyCopyFileNameToLogRecord( &RecordList->LogRecord, &PagingFile );
            leave;
        }
#endif

        //
        //  We did not find the name in the hash.  Allocate name control buffer
        //  (for getting name) and a buffer for inserting this name into the
        //  hash.
        //

        buffer = SpyAllocateBuffer( &gNamesAllocated, gMaxNamesToAllocate, NULL );

        status = NLAllocateNameControl( &newName, &gFileSpyNameBufferLookasideList );

        if ((buffer != NULL) && NT_SUCCESS(status)) {

            //
            //  Init the new hash entry in case we need to use it
            //

            newHash = (PHASH_ENTRY)buffer;
            RtlInitEmptyUnicodeString( &newHash->Name,
                                       (PWCHAR)(buffer + sizeof(HASH_ENTRY)),
                                       RECORD_SIZE - sizeof(HASH_ENTRY) );

            //
            //  Retrieve the name
            //

            status = NLGetFullPathName( FileObject,
                                        newName,
                                        &devExt->NLExtHeader,
                                        LookupFlags | NLFL_USE_DOS_DEVICE_NAME,
                                        &gFileSpyNameBufferLookasideList,
                                        &cacheName );

            if (NT_SUCCESS( status ) && cacheName) {

                //
                //  We got a name and the name should be cached, save it in the
                //  log record and the hash buffer.
                //

                SpyCopyFileNameToLogRecord( &RecordList->LogRecord, &newName->Name );

                RtlCopyUnicodeString( &newHash->Name, &newName->Name );
                newHash->FileObject = FileObject;

                //
                //  Acquire the hash lock
                //

                KeAcquireSpinLock( &gHashLockTable[hashIndex], &oldIrql );

                //
                //  Search again because it may have been stored in the hash table
                //  since we did our last search and dropped the lock.
                //

                pHash = SpyHashBucketLookup( &gHashTable[hashIndex], FileObject );

                if (pHash != NULL) {

                    //
                    //  We found it in the hash table this time, don't need to
                    //  cache it again.
                    //

                    KeReleaseSpinLock( &gHashLockTable[hashIndex], oldIrql );

                    leave;
                }

                //
                //  It not found in the hash, add the new entry.
                //

                InsertHeadList( listHead, &newHash->List );

                gHashCurrentCounters[hashIndex]++;

                if (gHashCurrentCounters[hashIndex] > gHashMaxCounters[hashIndex]) {

                    gHashMaxCounters[hashIndex] = gHashCurrentCounters[hashIndex];
                }

                //
                //  Since we inserted the new hash entry, mark the buffer as empty
                //  so we won't try and free it
                //

                buffer = NULL;

                KeReleaseSpinLock( &gHashLockTable[hashIndex], oldIrql );

            } else {

                //
                //  Either the name should not be cached or we couldn't get a
                //  name, return whatever name they gave us
                //

                SpyCopyFileNameToLogRecord( &RecordList->LogRecord, &newName->Name );

                INC_STATS( TotalContextTemporary );
            }

        } else {

            //
            //  Set a default string even if there is no buffer.
            //

            SpyCopyFileNameToLogRecord( &RecordList->LogRecord, &OutOfBuffers );
        }

    } finally {

        //
        //  Free memory
        //

        if (buffer != NULL) {

            SpyFreeBuffer( buffer, &gNamesAllocated );
        }

        if (newName != NULL) {

            NLFreeNameControl( newName, &gFileSpyNameBufferLookasideList );
        }
    }
}
*/

/*
VOID
SpyNameDeleteAllNames (
    VOID
    )
/*++

Routine Description:

    This will free all entries from the hash table

Arguments:

    None

Return Value:

    None

--
{
    KIRQL oldIrql;
    PHASH_ENTRY pHash;
    PLIST_ENTRY pList;
    ULONG i;

    INC_STATS( TotalContextDeleteAlls );
    for (i=0; i<HASH_SIZE; i++) {

        KeAcquireSpinLock( &gHashLockTable[i], &oldIrql );

        while (!IsListEmpty( &gHashTable[i] )) {

            pList = RemoveHeadList( &gHashTable[i] );
            pHash = CONTAINING_RECORD( pList, HASH_ENTRY, List );
            SpyFreeBuffer( pHash, &gNamesAllocated );
        }

        gHashCurrentCounters[i] = 0;

        KeReleaseSpinLock( &gHashLockTable[i], oldIrql );
    }
}*/

/*
VOID
SpyNameDelete (
    __in PFILE_OBJECT FileObject
    )
/*++

Routine Description:

    This routine looks up the FileObject in the hash table.  If it is found,
    it deletes it and frees the memory.

Arguments:

    FileObject - the FileObject to look up.

Return Value:

    None


{
    UINT_PTR hashIndex;
    KIRQL oldIrql;
    PHASH_ENTRY pHash;
    PLIST_ENTRY pList;
    PLIST_ENTRY listHead;

    hashIndex = HASH_FUNC(FileObject);

    KeAcquireSpinLock( &gHashLockTable[hashIndex], &oldIrql );

    listHead = &gHashTable[hashIndex];

    pList = listHead->Flink;

    while (pList != listHead) {

        pHash = CONTAINING_RECORD( pList, HASH_ENTRY, List );

        if (FileObject == pHash->FileObject) {

            INC_STATS( TotalContextNonDeferredFrees );
            gHashCurrentCounters[hashIndex]--;
            RemoveEntryList( pList );
            SpyFreeBuffer( pHash, &gNamesAllocated );
            break;
        }

        pList = pList->Flink;
    }

    KeReleaseSpinLock( &gHashLockTable[hashIndex], oldIrql );
}
--*/
#endif

