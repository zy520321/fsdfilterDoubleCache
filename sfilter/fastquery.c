
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
//#include "filespy.h"
#include "fspyKern.h"

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
						   )

						   /*++

						   Routine Description:

						   This routine checks if fast i/o is possible for a read/write operation

						   Arguments:

						   FileObject - Supplies the file object used in the query

						   FileOffset - Supplies the starting byte offset for the read/write operation

						   Length - Supplies the length, in bytes, of the read/write operation

						   Wait - Indicates if we can wait

						   LockKey - Supplies the lock key

						   CheckForReadOperation - Indicates if this is a check for a read or write
						   operation

						   IoStatus - Receives the status of the operation if our return value is
						   FastIoReturnError

						   Return Value:

						   BOOLEAN - TRUE if fast I/O is possible and FALSE if the caller needs
						   to take the long route

						   --*/

{
	PPfpFCB Fcb;

	LARGE_INTEGER LargeLength;

	UNREFERENCED_PARAMETER( DeviceObject );
	UNREFERENCED_PARAMETER( IoStatus );
	UNREFERENCED_PARAMETER( Wait );

	PAGED_CODE();

	//
	//  Decode the file object to get our fcb, the only one we want
	//  to deal with is a UserFileOpen
	//

	Fcb = FileObject->FsContext;
	LargeLength = RtlConvertUlongToLargeInteger( Length );

	//
	//  Based on whether this is a read or write operation we call
	//  fsrtl check for read/write
	//

	if (CheckForReadOperation) 
	{

		if (Fcb->FileLock == NULL
			|| FsRtlFastCheckLockForRead( Fcb->FileLock,
			FileOffset,
			&LargeLength,
			LockKey,
			FileObject,
			PsGetCurrentProcess() )) 
		{
			return TRUE;
		}

	} else 
	{

		if (Fcb->FileLock == NULL
			|| FsRtlFastCheckLockForWrite( Fcb->FileLock,
			FileOffset,
			&LargeLength,
			LockKey,
			FileObject,
			PsGetCurrentProcess() )
			) 
		{

			return TRUE;
		}
	}

	return FALSE;
}


BOOLEAN
PfpFastQueryBasicInfo (
						IN PFILE_OBJECT		FileObject,
						IN BOOLEAN			Wait,
						IN OUT PFILE_BASIC_INFORMATION Buffer,
						OUT PIO_STATUS_BLOCK IoStatus,
						IN PDEVICE_OBJECT	 DeviceObject
						)

						/*++

						Routine Description:

						This routine is for the fast query call for basic file information.

						Arguments:

						FileObject - Supplies the file object used in this operation

						Wait - Indicates if we are allowed to wait for the information

						Buffer - Supplies the output buffer to receive the basic information

						IoStatus - Receives the final status of the operation

						Return Value:

						BOOLEAN _ TRUE if the operation is successful and FALSE if the caller
						needs to take the long route.

						--*/

{
	BOOLEAN		Results = FALSE;	
	PPfpFCB		Fcb;	
	//PFAST_IO_DISPATCH fastIoDispatch;	
	BOOLEAN		FcbAcquired = FALSE;
	PDISKFILEOBJECT	pDiskFileObject = NULL;
	BOOLEAN     returnValue = FALSE;
	PAGED_CODE();
	 
	//
	//  Determine the type of open for the input file object.  The callee really
	//  ignores the irp context for us.
	//	
	Fcb    = FileObject->FsContext;

	pDiskFileObject  = Fcb->pDiskFileObject;


	ASSERT(pDiskFileObject );
	ASSERT(pDiskFileObject ->pDiskFileObjectWriteThrough);
	FsRtlEnterFileSystem();

	__try 
	{

		if (ExAcquireResourceSharedLite( Fcb->Header.Resource, Wait )) 
		{

			FcbAcquired = TRUE;

			if (FlagOn( Fcb->FcbState, FCB_STATE_FILE_DELETED ))
			{

					try_return( NOTHING );
			}

		} else 
		{

			try_return( NOTHING );
		}	

		//
		//  Fill in the basic information fields
		//
// 		fastIoDispatch = DeviceObject->DriverObject->FastIoDispatch;
// 
// 		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
// 			FastIoQueryBasicInfo ))
// 		{
// 			Results = (fastIoDispatch->FastIoQueryBasicInfo)( pDiskFileObject ->pDiskFileObjectWriteThrough,
// 																	Wait,
// 																	Buffer,
// 																	IoStatus,
// 																	DeviceObject);
// 		}
// 		if(Results)
// 		{
// 			Fcb->CreationTime			= Buffer->CreationTime.QuadPart   ;
// 			Fcb->LastModificationTime	= Buffer->LastWriteTime.QuadPart  ;
// 			Fcb->LastChangeTime			= Buffer->ChangeTime.QuadPart     ;
// 			Fcb->CurrentLastAccess		= Buffer->LastAccessTime.QuadPart ;
// 			Fcb->Attribute				= Buffer->FileAttributes			;
// 		}
// 		else
		{
			Buffer->CreationTime.QuadPart	= Fcb->CreationTime  ;
			Buffer->LastWriteTime.QuadPart  = Fcb->LastModificationTime  ;
			Buffer->ChangeTime.QuadPart     = Fcb->LastChangeTime  ;
			Buffer->LastAccessTime.QuadPart = Fcb->CurrentLastAccess ;
			Buffer->FileAttributes			=  FILE_ATTRIBUTE_NORMAL ;
			if (FlagOn( Fcb->FcbState, FCB_STATE_TEMPORARY )) 
			{
				SetFlag( Buffer->FileAttributes, FILE_ATTRIBUTE_TEMPORARY );
			}
		}
		//Buffer->FileAttributes			= Fcb->Attribute;

		//ClearFlag( Buffer->FileAttributes,~FILE_ATTRIBUTE_VALID_FLAGS| FILE_ATTRIBUTE_TEMPORARY );

		
		//
		//  If there are no flags set then explicitly set the NORMAL flag.
		//

// 		if (Buffer->FileAttributes == 0) 
// 		{
// 
// 			Buffer->FileAttributes = FILE_ATTRIBUTE_NORMAL;
// 		}

		Results = TRUE;

		IoStatus->Information = sizeof(FILE_BASIC_INFORMATION);

		IoStatus->Status = STATUS_SUCCESS;	

try_exit:  NOTHING;

	}
	__finally 
	{

		if (FcbAcquired) { ExReleaseResourceLite( Fcb->Header.Resource ); }

		FsRtlExitFileSystem();
	}

	//
	//  Return to our caller
	//

	return Results;
}


BOOLEAN
PfpFastQueryStdInfo (
					  IN PFILE_OBJECT FileObject,
					  IN BOOLEAN Wait,
					  IN OUT PFILE_STANDARD_INFORMATION Buffer,
					  OUT PIO_STATUS_BLOCK IoStatus,
					  IN PDEVICE_OBJECT DeviceObject
					  )

					  /*++

					  Routine Description:

					  This routine is for the fast query call for standard file information.

					  Arguments:

					  FileObject - Supplies the file object used in this operation

					  Wait - Indicates if we are allowed to wait for the information

					  Buffer - Supplies the output buffer to receive the basic information

					  IoStatus - Receives the final status of the operation

					  Return Value:

					  BOOLEAN _ TRUE if the operation is successful and FALSE if the caller
					  needs to take the long route.

					  --*/

{
	BOOLEAN Results = FALSE;	
	PPfpFCB Fcb;
	PPfpCCB Ccb;
	PFAST_IO_DISPATCH fastIoDispatch;	
	BOOLEAN		FcbAcquired = FALSE;
	PDISKFILEOBJECT	pDiskFileObject = NULL;
	/*FILEOBJECTTYPE lFileObjectType;*/
	
	
	BOOLEAN FsRtlHeaderLocked = FALSE;

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();
 
	Fcb = (PPfpFCB)FileObject->FsContext;
	Ccb = (PPfpCCB)FileObject->FsContext2;

	
	pDiskFileObject  = Fcb->pDiskFileObject;
	

	ASSERT(pDiskFileObject );
	ASSERT(pDiskFileObject ->pDiskFileObjectWriteThrough);
	//
	//  Determine the type of open for the input file object.  The callee really
	//  ignores the irp context for us.
	//

	FsRtlEnterFileSystem();

	__try 
	{

	
		if (Fcb->Header.Resource != NULL) 
		{
			ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
		}

		FsRtlLockFsRtlHeader( &Fcb->Header );
		FsRtlHeaderLocked = TRUE;

// 		if (ExAcquireResourceShared( Fcb->Resource, Wait )) 
// 		{
// 
// 			FcbAcquired = TRUE;
// 
// 			
// 		} else 
// 		{
// 			try_return( NOTHING );
// 		}

		//
		//  Fill in the standard information fields.  If the
		//  Scb is not initialized then take the long route
		//
		fastIoDispatch = DeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
			FastIoQueryStandardInfo ))
		{
			Results = (fastIoDispatch->FastIoQueryStandardInfo)( pDiskFileObject->pDiskFileObjectWriteThrough,
																Wait,
																Buffer,
																IoStatus,
																DeviceObject);
		}
		if(Results)
		{
			//Fcb->LinkCount = Buffer->NumberOfLinks	;
			Buffer->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
			Buffer->EndOfFile.QuadPart			= Fcb->Header.FileSize.QuadPart;

			//Buffer->Directory = FALSE;
		}		

// 		IoStatus->Information = sizeof(FILE_STANDARD_INFORMATION);
// 		
// 		IoStatus->Status = Results;

	//	Results = TRUE;		

 
	} 
	__finally 
	{

		//if (FcbAcquired) { ExReleaseResource( Fcb->Resource ); }

		if (FsRtlHeaderLocked)
		{
			FsRtlUnlockFsRtlHeader( &Fcb->Header );
			if (Fcb->Header.Resource != NULL) 
			{
				ExReleaseResourceLite( Fcb->Header.Resource );
			}
		}

		FsRtlExitFileSystem();
	}

	//
	//  And return to our caller
	//

	return Results;
}


BOOLEAN
PfpFastQueryNetworkOpenInfo (
							  IN PFILE_OBJECT FileObject,
							  IN BOOLEAN Wait,
							  OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
							  OUT PIO_STATUS_BLOCK IoStatus,
							  IN PDEVICE_OBJECT DeviceObject
							  )

							  /*++

							  Routine Description:

							  This routine is for the fast query network open call.

							  Arguments:

							  FileObject - Supplies the file object used in this operation

							  Wait - Indicates if we are allowed to wait for the information

							  Buffer - Supplies the output buffer to receive the information

							  IoStatus - Receives the final status of the operation

							  Return Value:

							  BOOLEAN _ TRUE if the operation is successful and FALSE if the caller
							  needs to take the long route.

							  --*/

{
	BOOLEAN Results = FALSE;

	PPfpFCB Fcb;	
	PPfpCCB Ccb;
	BOOLEAN FcbAcquired = FALSE;
	//PFAST_IO_DISPATCH fastIoDispatch;	
	
	
	PDISKFILEOBJECT	pDiskFileObject = NULL;

	BOOLEAN FsRtlHeaderLocked = FALSE;
	 

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();
  
	
	//
	//  Determine the type of open for the input file object.  The callee really
	//  ignores the irp context for us.
	//
	Fcb   = FileObject->FsContext;
	Ccb   = FileObject->FsContext2;

	pDiskFileObject  = Fcb->pDiskFileObject;


	ASSERT(pDiskFileObject );
	ASSERT(pDiskFileObject ->pDiskFileObjectWriteThrough);
	FsRtlEnterFileSystem();

	__try {

		if (ExAcquireResourceSharedLite( Fcb->Header.Resource, Wait ))
		{

			FcbAcquired = TRUE;

			if (FlagOn( Fcb->FcbState, FCB_STATE_FILE_DELETED ))
			{

				try_return( NOTHING );
			}

		} else 
		{

			try_return( NOTHING );
		}
		//
		//  Fill in the basic information fields
		//
// 		fastIoDispatch = DeviceObject->DriverObject->FastIoDispatch;
// 
// 		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch,
// 			FastIoQueryStandardInfo ))
// 		{
// 			Results = (fastIoDispatch->FastIoQueryNetworkOpenInfo)( pDiskFileObject->pDiskFileObjectWriteThrough,
// 				Wait,
// 				Buffer,
// 				IoStatus,
// 				DeviceObject);
// 		}
// 		if(Results)
		{
			 
			Buffer->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
			Buffer->EndOfFile				= Fcb->Header.FileSize;
			Buffer->CreationTime.QuadPart	= Fcb->CreationTime				     ;
			Buffer->LastWriteTime.QuadPart  = Fcb->LastModificationTime		  ;
			Buffer->ChangeTime.QuadPart		=Fcb->LastChangeTime				       ;			
			Buffer->LastAccessTime.QuadPart =Fcb->CurrentLastAccess ;

			Buffer->FileAttributes			= FILE_ATTRIBUTE_NORMAL;
			if (FlagOn( Fcb->FcbState, FCB_STATE_TEMPORARY )) 
			{
				SetFlag( Buffer->FileAttributes, FILE_ATTRIBUTE_TEMPORARY );
			}
		}
// 		else
// 		{
// 			Buffer->CreationTime.QuadPart   = Fcb->CreationTime;
// 			Buffer->LastWriteTime.QuadPart  = Fcb->LastModificationTime;
// 			Buffer->ChangeTime.QuadPart     = Fcb->LastChangeTime;
// 			Buffer->LastAccessTime.QuadPart = Fcb->CurrentLastAccess;
// 
// 			Buffer->FileAttributes = Fcb->Attribute;
// 
// 			ClearFlag( Buffer->FileAttributes,~FILE_ATTRIBUTE_VALID_FLAGS | FILE_ATTRIBUTE_TEMPORARY );
// 
// 
// 
// 			Buffer->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
// 			Buffer->EndOfFile				= Fcb->Header.FileSize;
// 
// 			//
// 			//  If not the unnamed data stream then use the Scb
// 			//  compression value.
// 			//
// 			ClearFlag( Buffer->FileAttributes, FILE_ATTRIBUTE_COMPRESSED );
// 
// 			//
// 			//  Set the temporary flag if set in the Scb.
// 			//
// 
  		
// 
// 			//
// 			//  If there are no flags set then explicitly set the NORMAL flag.
// 			//
// 
// 			if (Buffer->FileAttributes == 0) 
// 			{
// 				Buffer->FileAttributes = FILE_ATTRIBUTE_NORMAL;
// 			}
// 
// 		}
		
		IoStatus->Information = sizeof(FILE_NETWORK_OPEN_INFORMATION);
  
		IoStatus->Status = STATUS_SUCCESS;

		//Results = TRUE;

try_exit:  NOTHING;

	} 
	__finally
	{

		if (FcbAcquired) { ExReleaseResourceLite( Fcb-> Header.Resource ); }

		FsRtlExitFileSystem();
	}

	//
	//  And return to our caller
	//

	return Results;
}

VOID
PfpFastAcquireForCreateSection (
								IN PFILE_OBJECT FileObject
							 )
{
	if(!PfpFileObjectHasOurFCB(FileObject))
	{	
		if(NTFSAcquireFileForNtCreateSection)
			NTFSAcquireFileForNtCreateSection(FileObject);
	}
	else
	{	
		ExAcquireResourceExclusiveLite(((PPfpFCB)FileObject->FsContext)->Header.Resource,TRUE);
	}
}

VOID
PfpFastReleaseForCreateSection (
								IN PFILE_OBJECT FileObject
							 )
{
	if(!PfpFileObjectHasOurFCB(FileObject))
	{
		 
		if(NTFSReleaseFileForNtCreateSection)
		{
			NTFSReleaseFileForNtCreateSection(FileObject);
		}
	}
	else
	{	
		if(ExIsResourceAcquiredLite(((PPfpFCB)FileObject->FsContext)->Header.Resource))
		{
			ExReleaseResourceLite(((PPfpFCB)FileObject->FsContext)->Header.Resource);	 
		}
	}
}


NTSTATUS
PfpAcquireFileForCcFlush (
						   IN PFILE_OBJECT FileObject,
						   IN PDEVICE_OBJECT DeviceObject
						   )
{	
	UNICODE_STRING  szDriverName;
	NTSTATUS ntstatus =STATUS_SUCCESS;
	RtlInitUnicodeString(&szDriverName,L"\\FileSystem\\Ntfs");

	if(!PfpFileObjectHasOurFCB(FileObject))
	{
		if(RtlEqualUnicodeString(&DeviceObject->DriverObject->DriverName,&szDriverName,FALSE)&& NTFSAcquireForCcFlush)		
		{
			ntstatus  =NTFSAcquireForCcFlush(FileObject,DeviceObject);
		}else
		{
			ntstatus  =FastFatAcquireForCcFlush(FileObject,DeviceObject);
		}
		
	}
	else
	{	
		ExAcquireResourceSharedLite(((PPfpFCB)FileObject->FsContext)->Header.Resource,TRUE);

	}	

	return ntstatus;

	UNREFERENCED_PARAMETER( DeviceObject );
}

NTSTATUS
PfpReleaseFileForCcFlush (
						   IN PFILE_OBJECT FileObject,
						   IN PDEVICE_OBJECT DeviceObject
						   )
{
	UNICODE_STRING  szDriverName;
	NTSTATUS ntstatus =STATUS_SUCCESS;
	RtlInitUnicodeString(&szDriverName,L"\\FileSystem\\Ntfs");

	if(!PfpFileObjectHasOurFCB(FileObject))
	{

		if(RtlEqualUnicodeString(&DeviceObject->DriverObject->DriverName,&szDriverName,FALSE)&&NTFSReleaseForCcFlush)
		{
			ntstatus  = NTFSReleaseForCcFlush(FileObject,DeviceObject);
		}else
		{
			ntstatus  = FastFatReleaseForCcFlush(FileObject,DeviceObject);
		}
		
	}
	else
	{	
		ExReleaseResourceLite(((PPfpFCB)FileObject->FsContext)->Header.Resource);
	}

	return STATUS_SUCCESS;
	
}

NTSTATUS
PfpAcquireFileForModWrite (
						   IN PFILE_OBJECT FileObject,
						   IN PLARGE_INTEGER EndingOffset,
						   OUT PERESOURCE *ResourceToRelease,
						   IN PDEVICE_OBJECT DeviceObject
						   )
{
	BOOLEAN AcquiredFile;
	NTSTATUS ntstatus = STATUS_SUCCESS;
	PPfpFCB pPfpFcb= (PPfpFCB) (FileObject->FsContext);
	

	

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();

	//
	//  Acquire the Scb only for those files that the write will
	//  acquire it for, i.e., not the first set of system files.
	//  Otherwise we can deadlock, for example with someone needing
	//  a new Mft record.
	//

	if(!PfpFileObjectHasOurFCB(FileObject))
	{

		if(NTFSAcquireForModWrite)
		{
			ntstatus= NTFSAcquireForModWrite(FileObject,EndingOffset,ResourceToRelease,DeviceObject);
		}
		return ntstatus;
	}

	//
	//  Figure out which resource to acquire.
	//

	if (pPfpFcb->Header.Resource != NULL) 
	{
		*ResourceToRelease = pPfpFcb->Header.Resource;
	} else
	{
		*ResourceToRelease = pPfpFcb-> Resource;
	}

	//
	//  Try to acquire the resource with Wait FALSE
	//

	AcquiredFile = ExAcquireResourceExclusiveLite( *ResourceToRelease, FALSE );

	//
	//  If we got the resource, check if he is possibly trying to extend
	//  ValidDataLength.  If so that will cause us to go into useless mode
	//  possibly doing actual I/O writing zeros out to the file past actual
	//  valid data in the cache.  This is so inefficient that it is better
	//  to tell MM not to do this write.
	//

	if (AcquiredFile)
	{
		ExAcquireFastMutex( pPfpFcb->Header.FastMutex );
		if ((EndingOffset->QuadPart > pPfpFcb->Header.FileSize.QuadPart) &&
			(EndingOffset->QuadPart < (pPfpFcb->Header.FileSize.QuadPart + PAGE_SIZE - 1)) &&
			!FlagOn(pPfpFcb->Header.Flags, FSRTL_FLAG_USER_MAPPED_FILE))
		{

				ExReleaseResourceLite(*ResourceToRelease);
				AcquiredFile = FALSE;
				*ResourceToRelease = NULL;
		}
		ExReleaseFastMutex( pPfpFcb->Header.FastMutex );
		
	} else 
	{
		*ResourceToRelease = NULL;
	}
	

	return (AcquiredFile ? STATUS_SUCCESS : STATUS_CANT_WAIT);
}

NTSTATUS
PfpReleaseForModWrite(IN PFILE_OBJECT FileObject,
					  IN PERESOURCE   ResourceToRelease,
					  IN PDEVICE_OBJECT DeviceObject)
{

	NTSTATUS ntstatus =STATUS_SUCCESS;
	if(!PfpFileObjectHasOurFCB(FileObject))
	{
		if(NTFSReleaseForModWrite)
		{
			ntstatus = NTFSReleaseForModWrite(FileObject,ResourceToRelease,DeviceObject);
		}
		
	}else	
	{
		ExReleaseResourceLite(((PPfpFCB)FileObject->FsContext)->Header.Resource);
	}

	return ntstatus;
}