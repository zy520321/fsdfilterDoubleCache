 
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
//#include "filespy.h"
#include "fspyKern.h"


NTSTATUS
PfpFsdLockControl (
					IN PDEVICE_OBJECT VolumeDeviceObject,
					IN PIRP Irp
					)

					/*++

					Routine Description:

					This routine implements the FSD part of Lock Control.

					Arguments:

					VolumeDeviceObject - Supplies the volume device object where the
					file exists

					Irp - Supplies the Irp being processed

					Return Value:

					NTSTATUS - The FSD status for the IRP

					--*/

{
	TOP_LEVEL_CONTEXT TopLevelContext;
	PTOP_LEVEL_CONTEXT ThreadTopLevelContext;
	PFILESPY_DEVICE_EXTENSION	pExt				= NULL;
	PDEVICE_OBJECT				pAttachedDevice		= NULL;

	NTSTATUS					Status				= STATUS_SUCCESS;
	PIRP_CONTEXT				IrpContext			= NULL;
	//PERESOURCE					pDeviceResource		= NULL;

	UNREFERENCED_PARAMETER( VolumeDeviceObject );

	PAGED_CODE();

	pExt			 = VolumeDeviceObject->DeviceExtension;
	pAttachedDevice  = pExt->NLExtHeader.AttachedToDeviceObject;
	


	//
	//  Call the common Lock Control routine
	//
	if(!PfpFileObjectHasOurFCB(IoGetCurrentIrpStackLocation(Irp)->FileObject))
	{
		goto PASSTHROUGH;
	}


// 	pDeviceResource = PfpGetDeviceResource((PDEVICE_OBJECT)VolumeDeviceObject);
// 
// 	if(pDeviceResource== NULL)
// 	{
// 		ASSERT(0);
// 		goto PASSTHROUGH;
// 	}
	FsRtlEnterFileSystem();
	//ExAcquireResourceSharedLite(pDeviceResource,TRUE);

	ThreadTopLevelContext = PfpSetTopLevelIrp( &TopLevelContext, FALSE, FALSE  );

	do 
	{

		__try 
		{

			//
			//  We are either initiating this request or retrying it.
			//

			if (IrpContext == NULL)
			{

				IrpContext = PfpCreateIrpContext( Irp, CanFsdWait( Irp ) );
				PfpUpdateIrpContextWithTopLevel( IrpContext, ThreadTopLevelContext );

			}

			Status = PfpCommonLockControl( IrpContext, Irp );
			break;

		} 
		__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) 
		{

			//
			//  We had some trouble trying to perform the requested
			//  operation, so we'll abort the I/O request with
			//  the error status that we get back from the
			//  execption code
			//

			Status = PfpProcessException( IrpContext, Irp, GetExceptionCode() );
		}

	} while (Status == STATUS_CANT_WAIT ||
		Status == STATUS_LOG_FILE_FULL);

	if (ThreadTopLevelContext == &TopLevelContext) 
	{
		PfpRestoreTopLevelIrp( ThreadTopLevelContext );
	}
// 	if(pDeviceResource)
// 	{
// 		ExReleaseResource(pDeviceResource);
// 	}

	FsRtlExitFileSystem();

	//
	//  And return to our caller
	//

//	DebugTrace( -1, Dbg, ("NtfsFsdLockControl -> %08lx\n", Status) );
	
	return Status;

PASSTHROUGH:

	IoSkipCurrentIrpStackLocation(Irp);
	Status = IoCallDriver(pAttachedDevice,Irp);
	
	return Status;
}


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
			  )

			  /*++

			  Routine Description:

			  This is a call back routine for doing the fast lock call.

			  Arguments:

			  FileObject - Supplies the file object used in this operation

			  FileOffset - Supplies the file offset used in this operation

			  Length - Supplies the length used in this operation

			  ProcessId - Supplies the process ID used in this operation

			  Key - Supplies the key used in this operation

			  FailImmediately - Indicates if the request should fail immediately
			  if the lock cannot be granted.

			  ExclusiveLock - Indicates if this is a request for an exclusive or
			  shared lock

			  IoStatus - Receives the Status if this operation is successful

			  Return Value:

			  BOOLEAN - TRUE if this operation completed and FALSE if caller
			  needs to take the long route.

			  --*/

{
	BOOLEAN Results;
	
	PPfpFCB Fcb;
	BOOLEAN ResourceAcquired = FALSE;

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();

	

	//
	//  Decode the type of file object we're being asked to process and
	//  make sure that is is only a user file open.
	//

	

	Fcb = FileObject->FsContext;

	//
	//  Acquire shared access to the Fcb this operation can always wait
	//

	FsRtlEnterFileSystem();

	if (Fcb->FileLock == NULL) 
	{
		(VOID) ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
		ResourceAcquired = TRUE;
	}

	__try 
	{

		//
		//  We check whether we can proceed
		//  based on the state of the file oplocks.
		//

		if ((Fcb->Oplock != NULL) &&
			!FsRtlOplockIsFastIoPossible( &Fcb->Oplock ))
		{

				try_return( Results = FALSE );
		}

		//
		//  If we don't have a file lock, then get one now.
		//

		if (Fcb->FileLock == NULL
			&& !PfpCreateFileLock( Fcb, FALSE ))
		{

				try_return( Results = FALSE );
		}

		//
		//  Now call the FsRtl routine to do the actual processing of the
		//  Lock request
		//

		if (Results = FsRtlFastLock( Fcb->FileLock,
									FileObject,
									FileOffset,
									Length,
									ProcessId,
									Key,
									FailImmediately,
									ExclusiveLock,
									IoStatus,
									NULL,
									FALSE )) 
		{

				//
				//  Set the flag indicating if Fast I/O is questionable.  We
				//  only change this flag is the current state is possible.
				//  Retest again after synchronizing on the header.
				//

				if (Fcb->Header.IsFastIoPossible == FastIoIsPossible) 
				{

					PfpAcquireFsrtlHeader( Fcb );
					Fcb->Header.IsFastIoPossible = PfpIsFastIoPossible( Fcb );
					PfpReleaseFsrtlHeader( Fcb );
				}
		}

try_exit:  NOTHING;
	} 
	__finally 
	{

		//DebugUnwind( NtfsFastLock );

		//
		//  Release the Fcb, and return to our caller
		//

		if (ResourceAcquired) 
		{
			ExReleaseResourceLite( Fcb->Header.Resource );
		}

		FsRtlExitFileSystem();

		//DebugTrace( -1, Dbg, ("NtfsFastLock -> %08lx\n", Results) );
	}

	return Results;
}


BOOLEAN
PfpFastUnlockSingle (
					  IN PFILE_OBJECT FileObject,
					  IN PLARGE_INTEGER FileOffset,
					  IN PLARGE_INTEGER Length,
					  PEPROCESS ProcessId,
					  ULONG Key,
					  OUT PIO_STATUS_BLOCK IoStatus,
					  IN PDEVICE_OBJECT DeviceObject
					  )

					  /*++

					  Routine Description:

					  This is a call back routine for doing the fast unlock single call.

					  Arguments:

					  FileObject - Supplies the file object used in this operation

					  FileOffset - Supplies the file offset used in this operation

					  Length - Supplies the length used in this operation

					  ProcessId - Supplies the process ID used in this operation

					  Key - Supplies the key used in this operation

					  Status - Receives the Status if this operation is successful

					  Return Value:

					  BOOLEAN - TRUE if this operation completed and FALSE if caller
					  needs to take the long route.

					  --*/

{
	BOOLEAN Results;
	PPfpFCB Fcb;
	
	BOOLEAN ResourceAcquired = FALSE;

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();

	//DebugTrace( +1, Dbg, ("NtfsFastUnlockSingle\n") );

	IoStatus->Information = 0;

	//
	//  Decode the type of file object we're being asked to process and
	//  make sure that is is only a user file open.
	//

	Fcb = FileObject->FsContext;	

	//
	//  Acquire exclusive access to the Fcb this operation can always wait
	//

	FsRtlEnterFileSystem();

	if (Fcb->FileLock == NULL) 
	{
		(VOID) ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
		ResourceAcquired = TRUE;
	} 

	__try 
	{

		//
		//  We check whether we can proceed based on the state of the file oplocks.
		//

		if ((Fcb->Oplock != NULL) &&
			!FsRtlOplockIsFastIoPossible( &Fcb->Oplock )) 
		{

				try_return( Results = FALSE );
		}

		//
		//  If we don't have a file lock, then get one now.
		//

		if (Fcb->FileLock == NULL
			&& !PfpCreateFileLock( Fcb, FALSE )) 
		{

				try_return( Results = FALSE );
		}

		//
		//  Now call the FsRtl routine to do the actual processing of the
		//  Lock request.  The call will always succeed.
		//

		Results = TRUE;
		IoStatus->Status = FsRtlFastUnlockSingle( Fcb->FileLock,
													FileObject,
													FileOffset,
													Length,
													ProcessId,
													Key,
													NULL,
													FALSE );

		//
		//  Set the flag indicating if Fast I/O is possible.  We are
		//  only concerned if there are no longer any filelocks on this
		//  file.
		//

		if (!FsRtlAreThereCurrentFileLocks( Fcb->FileLock ) &&
			(Fcb->Header.IsFastIoPossible != FastIoIsPossible)) 
		{

				PfpAcquireFsrtlHeader( Fcb );
				Fcb->Header.IsFastIoPossible = PfpIsFastIoPossible( Fcb );
				PfpReleaseFsrtlHeader( Fcb );
		}

try_exit:  NOTHING;
	} 
	__finally 
	{

		

		//
		//  Release the Fcb, and return to our caller
		//

		if (ResourceAcquired) 
		{
			ExReleaseResourceLite( Fcb->Header.Resource );
		}

		FsRtlExitFileSystem();

		
	}

	return Results;
}


BOOLEAN
PfpFastUnlockAll (
				   IN PFILE_OBJECT FileObject,
				   PEPROCESS ProcessId,
				   OUT PIO_STATUS_BLOCK IoStatus,
				   IN PDEVICE_OBJECT DeviceObject
				   )

				   /*++

				   Routine Description:

				   This is a call back routine for doing the fast unlock all call.

				   Arguments:

				   FileObject - Supplies the file object used in this operation

				   ProcessId - Supplies the process ID used in this operation

				   Status - Receives the Status if this operation is successful

				   Return Value:

				   BOOLEAN - TRUE if this operation completed and FALSE if caller
				   needs to take the long route.

				   --*/

{
	BOOLEAN Results;
	
	
	
	PPfpFCB Fcb;
	
	

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();

	

	IoStatus->Information = 0;

	//
	//  Decode the type of file object we're being asked to process and
	//  make sure that is is only a user file open.
	//

	//
	//  Acquire exclusive access to the Fcb this operation can always wait
	//

	FsRtlEnterFileSystem();
	
	Fcb = FileObject ->FsContext;
	
	if (Fcb->FileLock == NULL)
	{

		(VOID) ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );

	} else 
	{

		(VOID) ExAcquireResourceSharedLite( Fcb->Header.Resource, TRUE );
	}

	__try 
	{

		//
		//  We check whether we can proceed based on the state of the file oplocks.
		//

		if (!FsRtlOplockIsFastIoPossible( &Fcb->Oplock )) 
		{

			try_return( Results = FALSE );
		}

		//
		//  If we don't have a file lock, then get one now.
		//

		if (Fcb->FileLock == NULL
			&& !PfpCreateFileLock( Fcb, FALSE )) 
		{

				try_return( Results = FALSE );
		}

		//
		//  Now call the FsRtl routine to do the actual processing of the
		//  Lock request.  The call will always succeed.
		//

		Results = TRUE;
		IoStatus->Status = FsRtlFastUnlockAll( Fcb->FileLock,
												FileObject,
												ProcessId,
												NULL );

		//
		//  Set the flag indicating if Fast I/O is possible
		//

		PfpAcquireFsrtlHeader( Fcb );
		Fcb->Header.IsFastIoPossible = PfpIsFastIoPossible( Fcb);
		PfpReleaseFsrtlHeader( Fcb );

try_exit:  NOTHING;
	} 
	__finally
	{

		//DebugUnwind( NtfsFastUnlockAll );

		//
		//  Release the Fcb, and return to our caller
		//

		ExReleaseResourceLite( Fcb->Header.Resource );

		FsRtlExitFileSystem();

		//DebugTrace( -1, Dbg, ("NtfsFastUnlockAll -> %08lx\n", Results) );
	}

	return Results;
}


BOOLEAN
PfpFastUnlockAllByKey (
						IN PFILE_OBJECT FileObject,
						PVOID ProcessId,
						ULONG Key,
						OUT PIO_STATUS_BLOCK IoStatus,
						IN PDEVICE_OBJECT DeviceObject
						)

						/*++

						Routine Description:

						This is a call back routine for doing the fast unlock all by key call.

						Arguments:

						FileObject - Supplies the file object used in this operation

						ProcessId - Supplies the process ID used in this operation

						Key - Supplies the key used in this operation

						Status - Receives the Status if this operation is successful

						Return Value:

						BOOLEAN - TRUE if this operation completed and FALSE if caller
						needs to take the long route.

						--*/

{
	BOOLEAN Results;
	PPfpFCB Fcb;	
	

	UNREFERENCED_PARAMETER( DeviceObject );

	PAGED_CODE();

//	DebugTrace( +1, Dbg, ("NtfsFastUnlockAllByKey\n") );

	IoStatus->Information = 0;

	//
	//  Decode the type of file object we're being asked to process and
	//  make sure that is is only a user file open.
	//

	Fcb = FileObject->FsContext;
	
	//
	//  Acquire exclusive access to the Fcb this operation can always wait
	//

	FsRtlEnterFileSystem();

	if (Fcb->FileLock == NULL)
	{

		(VOID) ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );

	} else
	{

		(VOID) ExAcquireResourceSharedLite( Fcb->Header.Resource, TRUE );
	}

	__try 
	{

		//
		//  We check whether we can proceed based on the state of the file oplocks.
		//

		if (!FsRtlOplockIsFastIoPossible( &Fcb->Oplock )) 
		{

			try_return( Results = FALSE );
		}

		//
		//  If we don't have a file lock, then get one now.
		//

		if (Fcb->FileLock == NULL
			&& !PfpCreateFileLock( Fcb, FALSE )) 
		{

				try_return( Results = FALSE );
		}

		//
		//  Now call the FsRtl routine to do the actual processing of the
		//  Lock request.  The call will always succeed.
		//

		Results = TRUE;
		IoStatus->Status = FsRtlFastUnlockAllByKey( Fcb->FileLock,
													FileObject,
													ProcessId,
													Key,
													NULL );

		//
		//  Set the flag indicating if Fast I/O is possible
		//

		PfpAcquireFsrtlHeader( Fcb );
		Fcb->Header.IsFastIoPossible = PfpIsFastIoPossible( Fcb );
		PfpReleaseFsrtlHeader( Fcb );

try_exit:  NOTHING;
	} 
	__finally 
	{

		//DebugUnwind( NtfsFastUnlockAllByKey );

		//
		//  Release the Fcb, and return to our caller
		//

		ExReleaseResourceLite( Fcb->Header.Resource );

		FsRtlExitFileSystem();

		//DebugTrace( -1, Dbg, ("NtfsFastUnlockAllByKey -> %08lx\n", Results) );
	}

	return Results;
}


NTSTATUS
PfpCommonLockControl (
					   IN PIRP_CONTEXT IrpContext,
					   IN PIRP Irp
					   )

					   /*++

					   Routine Description:

					   This is the common routine for Lock Control called by both the fsd and fsp
					   threads.

					   Arguments:

					   Irp - Supplies the Irp to process

					   Return Value:

					   NTSTATUS - The return status for the operation

					   --*/

{
	NTSTATUS Status;
	PIO_STACK_LOCATION IrpSp;
	PFILE_OBJECT FileObject;	
	PPfpFCB Fcb;	
	
	BOOLEAN FcbAcquired = FALSE;
	BOOLEAN OplockPostIrp;

	//ASSERT_IRP_CONTEXT( IrpContext );
	//ASSERT_IRP( Irp );

	PAGED_CODE();

	//
	//  Get a pointer to the current Irp stack location
	//

	IrpSp = IoGetCurrentIrpStackLocation( Irp );


	//
	//  Extract and decode the type of file object we're being asked to process
	//

	FileObject = IrpSp->FileObject;
	Fcb = FileObject->FsContext;
	
	//
	//  Acquire exclusive access to the Fcb
	//

	if (Fcb->FileLock == NULL)
	{

		(VOID) ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
		FcbAcquired = TRUE;

	}

	OplockPostIrp = FALSE;

	__try 
	{

		//
		//  We check whether we can proceed based on the state of the file oplocks.
		//  This call might post the irp for us.
		//

		Status = FsRtlCheckOplock( &Fcb->Oplock,
									Irp,
									IrpContext,
									PfpOplockComplete,
									NULL );

		if (Status != STATUS_SUCCESS)
		{

			OplockPostIrp = TRUE;
			try_return( NOTHING );
		}

		//
		//  If we don't have a file lock, then get one now.
		//

		if (Fcb->FileLock == NULL) 
		{

			PfpCreateFileLock( Fcb, TRUE );
		}

		//
		//  Now call the FsRtl routine to do the actual processing of the
		//  Lock request
		//

		Status = FsRtlProcessFileLock( Fcb->FileLock, Irp, NULL );

		//
		//  Set the flag indicating if Fast I/O is possible
		//

		PfpAcquireFsrtlHeader( Fcb );
		Fcb->Header.IsFastIoPossible = PfpIsFastIoPossible( Fcb );
		PfpReleaseFsrtlHeader( Fcb );

try_exit: NOTHING;
	} 
	__finally
	{

		//DebugUnwind( NtfsCommonLockControl );

		//
		//  Release the Fcb, and return to our caller
		//

		if (FcbAcquired)
		{
			ExReleaseResourceLite( Fcb->Header.Resource);
		}

		//
		//  Only if this is not an abnormal termination and we did not post the irp
		//  do we delete the irp context
		//

		if (!AbnormalTermination() && !OplockPostIrp)
		{
			PfpCompleteRequest( &IrpContext, NULL, 0 );
		}
		
	}

	return Status;
}
