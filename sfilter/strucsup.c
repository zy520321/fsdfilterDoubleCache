 
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"

PIRP_CONTEXT
PfpCreateIrpContext (
					  IN PIRP Irp OPTIONAL,
					  IN BOOLEAN Wait
					  )

					  /*++

					  Routine Description:

					  This routine creates a new IRP_CONTEXT record

					  Arguments:

					  Irp - Supplies the originating Irp.  Won't be present if this is a defrag
					  operation.

					  Wait - Supplies the wait value to store in the context

					  Return Value:

					  PIRP_CONTEXT - returns a pointer to the newly allocate IRP_CONTEXT Record

					  --*/

{
	PIRP_CONTEXT IrpContext = NULL;
	PIO_STACK_LOCATION IrpSp;

	BOOLEAN AllocateFromPool = FALSE;

	//
	//  Allocate an IrpContext from zone if available, otherwise from
	//  non-paged pool.
	//

	IrpContext = (PIRP_CONTEXT)ExAllocateFromNPagedLookasideList( &NtfsIrpContextLookasideList );
	
	if( IrpContext  == NULL)
		return NULL;

	RtlZeroMemory( IrpContext, sizeof(IRP_CONTEXT) );

	//
	//  Set the proper node type code and node byte size
	//

	IrpContext->NodeTypeCode = NTFS_NTC_IRP_CONTEXT;
	IrpContext->NodeByteSize = sizeof(IRP_CONTEXT);

	//
	//  Set the originating Irp field
	//
	IrpSp	= IoGetCurrentIrpStackLocation(Irp);
	IrpContext->OriginatingIrp = Irp;

	if (ARGUMENT_PRESENT( Irp )) 
	{

		//
		//  Copy RealDevice for workque algorithms, and also set WriteThrough
		//  if there is a file object.
		//

		if (IrpSp->FileObject != NULL) 
		{		
			PFILE_OBJECT FileObject = IrpSp->FileObject;
			//
			//  Locate the volume device object and Vcb that we are trying to access
			//  so we can see if the request is WriteThrough.  We ignore the
			//  write-through flag for close and cleanup.
			//		
			
			if(FileObject->Flags&FO_WRITE_THROUGH)
				SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH);		

			//
			//  We would still like to find out the Vcb in all cases except for
			//  mount.
			//
		}
		//
		//  Major/Minor Function codes
		//
		IrpContext->MajorFunction = IrpSp->MajorFunction;
		IrpContext->MinorFunction = IrpSp->MinorFunction;
	}
	//
	//  Set the wait parameter
	//

	if (Wait) { SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT); }

	return IrpContext;
}



VOID
PfpDeleteIrpContext (
					  IN OUT PIRP_CONTEXT *IrpContext
					  )

					  /*++

					  Routine Description:

					  This routine deallocates and removes the specified IRP_CONTEXT record
					  from the Ntfs in memory data structures.  It should only be called
					  by NtfsCompleteRequest.

					  Arguments:

					  IrpContext - Supplies the IRP_CONTEXT to remove

					  Return Value:

					  None

					  --*/

{
	PPfpFCB Fcb;

	//ASSERT_IRP_CONTEXT( *IrpContext );

	//  DebugTrace( +1, Dbg, ("NtfsDeleteIrpContext, *IrpContext = %08lx\n", *IrpContext) );

	//
	//  Free any exclusive paging I/O resource, or IoAtEof condition,
	//  this field is overlayed, minimally in write.c.
	//
	//我们要记录那个文件的fcb吗？文件的大小发生变化或者是文件正在写？？

	Fcb = (*IrpContext)->FcbWithPagingExclusive;
	if (Fcb != NULL) 
	{
		FsRtlUnlockFsRtlHeader(&Fcb->Header);
		 (*IrpContext)->FcbWithPagingExclusive = NULL;
	}
	//
	//  If we can delete this Irp Context do so now.
	//

	if (!FlagOn( (*IrpContext)->Flags, IRP_CONTEXT_FLAG_DONT_DELETE )) 
	{

		//
		//  If there is an Io context pointer in the irp context and it is not
		//  on the stack, then free it.
		//

		if (FlagOn( (*IrpContext)->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT )
			&& ((*IrpContext)->Union.NtfsIoContext != NULL)) 
		{

				ExFreeToNPagedLookasideList( &NtfsIoContextLookasideList, (*IrpContext)->Union.NtfsIoContext );
		}

		//
		//  If we have captured the subject context then free it now.
		//

		
		//
		// Return the IRP context record to the lookaside or to pool depending
		// how much is currently in the lookaside
		//

		//ExFreePool(*IrpContext);
		ExFreeToNPagedLookasideList( &NtfsIrpContextLookasideList, *IrpContext );

		//
		//  Zero out the input pointer
		//

		*IrpContext = NULL;

	} 

	//
	//  And return to our caller
	//

	//  DebugTrace( -1, Dbg, ("NtfsDeleteIrpContext -> VOID\n") );

	return;
}




PTOP_LEVEL_CONTEXT
PfpSetTopLevelIrp (
					IN PTOP_LEVEL_CONTEXT TopLevelContext,
					IN BOOLEAN ForceTopLevel,
					IN BOOLEAN SetTopLevel
					)

					/*++

					Routine Description:

					This routine is called to set up the top level context in the thread local
					storage.  Ntfs always puts its own context in this location and restores
					the previous value on exit.  This routine will determine if this request is
					top level and top level ntfs.  It will return a pointer to the top level ntfs
					context stored in the thread local storage on return.

					Arguments:

					TopLevelContext - This is the local top level context for our caller.

					ForceTopLevel - Always use the input top level context.

					SetTopLevel - Only applies if the ForceTopLevel value is TRUE.  Indicates
					if we should make this look like the top level request.

					Return Value:

					PTOP_LEVEL_CONTEXT - Pointer to the top level ntfs context for this thread.
					It may be the same as passed in by the caller.  In that case the fields
					will be initialized.

					--*/

{
	PTOP_LEVEL_CONTEXT CurrentTopLevelContext;
	ULONG_PTR StackBottom;
	ULONG_PTR StackTop;
	BOOLEAN TopLevelRequest = TRUE;
	BOOLEAN TopLevelNtfs = TRUE;

	BOOLEAN ValidCurrentTopLevel = FALSE;

	//
	//  Get the current value out of the thread local storage.  If it is a zero
	//  value or not a pointer to a valid ntfs top level context or a valid
	//  Fsrtl value then we are the top level request.
	//

	CurrentTopLevelContext = PfpGetTopLevelContext();

	//
	//  Check if this is a valid Ntfs top level context.
	//

	IoGetStackLimits( &StackTop, &StackBottom);

	if (((ULONG_PTR) CurrentTopLevelContext <= StackBottom - sizeof( TOP_LEVEL_CONTEXT )) &&
		((ULONG_PTR) CurrentTopLevelContext >= StackTop) &&
		!FlagOn( (ULONG_PTR) CurrentTopLevelContext, 0x3 ) &&
		(CurrentTopLevelContext->Ntfs == 0x53465441)) 
	{

			ValidCurrentTopLevel = TRUE;
	}

	//
	//  If we are to force this request to be top level then set the
	//  TopLevelRequest flag according to the SetTopLevel input.
	//

	if (ForceTopLevel) 
	{

		TopLevelRequest = SetTopLevel;

		//
		//  If the value is NULL then we are top level everything.
		//

	} else if (CurrentTopLevelContext == NULL) 
	{

		NOTHING;

		//
		//  If this has one of the Fsrtl magic numbers then we were called from
		//  either the fast io path or the mm paging io path.
		//

	} else if ((ULONG_PTR) CurrentTopLevelContext <= FSRTL_MAX_TOP_LEVEL_IRP_FLAG) 
	{

		TopLevelRequest = FALSE;

	} else if (ValidCurrentTopLevel) 
	{

			TopLevelRequest = FALSE;
			TopLevelNtfs = FALSE;
	}

	//
	//  If we are the top level ntfs then initialize the caller's structure
	//  and store it in the thread local storage.
	//

	if (TopLevelNtfs) 
	{

		TopLevelContext->Ntfs = 0x53465441;
		TopLevelContext->SavedTopLevelIrp = (PIRP) CurrentTopLevelContext;
		TopLevelContext->TopLevelIrpContext = NULL;
		TopLevelContext->TopLevelRequest = TopLevelRequest;
		
		IoSetTopLevelIrp( (PIRP) TopLevelContext );
		return TopLevelContext;
	}

	return CurrentTopLevelContext;
}



NTSTATUS
PfpCompleteMdl (
				 IN PIRP_CONTEXT IrpContext,
				 IN PIRP Irp
				 )

				 /*++

				 Routine Description:

				 This routine performs the function of completing Mdl read and write
				 requests.  It should be called only from NtfsFsdRead and NtfsFsdWrite.

				 Arguments:

				 Irp - Supplies the originating Irp.

				 Return Value:

				 NTSTATUS - Will always be STATUS_PENDING or STATUS_SUCCESS.

				 --*/

{
	PFILE_OBJECT FileObject;
	PIO_STACK_LOCATION IrpSp;

	PAGED_CODE();

	//
	// Do completion processing.
	//

	FileObject = IoGetCurrentIrpStackLocation( Irp )->FileObject;

	switch( IrpContext->MajorFunction ) 
	{

	case IRP_MJ_READ:

		CcMdlReadComplete( FileObject, Irp->MdlAddress );
		break;

	case IRP_MJ_WRITE:

		ASSERT( FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) );

		IrpSp = IoGetCurrentIrpStackLocation( Irp );

		CcMdlWriteComplete( FileObject, &IrpSp->Parameters.Write.ByteOffset, Irp->MdlAddress );

		break;

	default:

		ASSERT(0);
		//DebugTrace( DEBUG_TRACE_ERROR, 0, ("Illegal Mdl Complete.\n") );

		//ASSERTMSG("Illegal Mdl Complete, About to bugcheck ", FALSE);
		//NtfsBugCheck( IrpContext->MajorFunction, 0, 0 );
		break;
	}

	//
	// Mdl is now deallocated.
	//

	Irp->MdlAddress = NULL;

	//
	// Complete the request and exit right away.
	//

	PfpCompleteRequest( &IrpContext, &Irp, STATUS_SUCCESS );

	//DebugTrace( -1, Dbg, ("NtfsCompleteMdl -> STATUS_SUCCESS\n") );

	return STATUS_SUCCESS;
}


VOID
PfpCompleteRequest (
					 IN OUT PIRP_CONTEXT *IrpContext OPTIONAL,
					 IN OUT PIRP *Irp OPTIONAL,
					 IN NTSTATUS Status
					 )

					 /*++

					 Routine Description:

					 This routine completes an IRP and deallocates the IrpContext

					 Arguments:

					 Irp - Supplies the Irp being processed

					 Status - Supplies the status to complete the Irp with

					 Return Value:

					 None.

					 --*/

{
	//
	//  If we have an Irp Context then unpin all of the repinned bcbs
	//  we might have collected, and delete the Irp context.  Delete Irp
	//  Context will zero out our pointer for us.
	//

	if (ARGUMENT_PRESENT(IrpContext)) 
	{

		(*IrpContext)->ExceptionStatus = Status;

		//
		//  Always store the status in the top level Irp Context unless
		//  there is already an error code.
		//

		if (NT_SUCCESS( (*IrpContext)->TopLevelIrpContext->ExceptionStatus ))
		{
			(*IrpContext)->TopLevelIrpContext->ExceptionStatus = Status;
		}
		if((*IrpContext)->WorkItem)
		{		
			IoFreeWorkItem((*IrpContext)->WorkItem);
			(*IrpContext)->WorkItem = NULL;
		}
		PfpDeleteIrpContext( IrpContext );
	}

	//
	//  If we have an Irp then complete the irp.
	//

	if (ARGUMENT_PRESENT( Irp ))
	{

		PIO_STACK_LOCATION IrpSp;

		if (NT_ERROR( Status ) &&
			FlagOn( (*Irp)->Flags, IRP_INPUT_OPERATION ))
		{

				(*Irp)->IoStatus.Information = 0;
		}

		IrpSp = IoGetCurrentIrpStackLocation( *Irp );

		(*Irp)->IoStatus.Status = Status;

		IoCompleteRequest( *Irp, IO_DISK_INCREMENT );

		//
		//  Zero out our input pointer
		//

		*Irp = NULL;
	}

	return;
}



LONG
PfpExceptionFilter (
					 IN PIRP_CONTEXT IrpContext OPTIONAL,
					 IN PEXCEPTION_POINTERS ExceptionPointer
					 )

					 /*++

					 Routine Description:

					 This routine is used to decide if we should or should not handle
					 an exception status that is being raised.  It inserts the status
					 into the IrpContext and either indicates that we should handle
					 the exception or bug check the system.

					 Arguments:

					 ExceptionPointer - Supplies the exception record to being checked.

					 Return Value:

					 ULONG - returns EXCEPTION_EXECUTE_HANDLER or bugchecks

					 --*/

{
	NTSTATUS ExceptionCode = ExceptionPointer->ExceptionRecord->ExceptionCode;
	UNREFERENCED_PARAMETER(IrpContext);
	

	return EXCEPTION_EXECUTE_HANDLER;
}




NTSTATUS
PfpProcessException (
					  IN PIRP_CONTEXT IrpContext,
					  IN PIRP Irp OPTIONAL,
					  IN NTSTATUS ExceptionCode
					  )

					  /*++

					  Routine Description:

					  This routine process an exception.  It either completes the request
					  with the saved exception status or it sends the request off to the Fsp

					  Arguments:

					  Irp - Supplies the Irp being processed

					  ExceptionCode - Supplies the normalized exception status being handled

					  Return Value:

					  NTSTATUS - Returns the results of either posting the Irp or the
					  saved completion status.

					  --*/

{
	BOOLEAN		 TopLevelRequest;
	PIRP_CONTEXT PostIrpContext = NULL;
	BOOLEAN		 Retry = FALSE;

	BOOLEAN		 ReleaseBitmap = FALSE;

	//ASSERT_OPTIONAL_IRP_CONTEXT( IrpContext );
	//ASSERT_OPTIONAL_IRP( Irp );

	//DebugTrace( 0, Dbg, ("NtfsProcessException\n") );

	//
	//  If there is not an irp context, we must have had insufficient resources
	//

	if (IrpContext == NULL) 
	{

		if (ARGUMENT_PRESENT( Irp )) 
		{

			PfpCompleteRequest( NULL, &Irp, ExceptionCode );
		}

		return ExceptionCode;
	}

	//
	//  Get the real exception status from the Irp Context.
	//

	ExceptionCode = IrpContext->ExceptionStatus;

	//
	//  All errors which could possibly have started a transaction must go
	//  through here.  Abort the transaction.
	//

	//
	//  Increment the appropriate performance counters.
	//

//	CollectExceptionStats( IrpContext->Vcb, ExceptionCode );

	__try 
	{

		//
		//  If this is an Mdl write request, then take care of the Mdl
		//  here so that things get cleaned up properly, and in the
		//  case of log file full we will just create a new Mdl.  By
		//  getting rid of this Mdl now, the pages will not be locked
		//  if we try to truncate the file while restoring snapshots.
		//

		if ((IrpContext->MajorFunction == IRP_MJ_WRITE) &&
			FlagOn(IrpContext->MinorFunction, IRP_MN_MDL) &&
			(Irp->MdlAddress != NULL)) 
		{

				PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

				CcMdlWriteComplete( IrpSp->FileObject,
									&IrpSp->Parameters.Write.ByteOffset,
									Irp->MdlAddress );

				Irp->MdlAddress = NULL;
		}

		//
		//  Exceptions at this point are pretty bad, we failed to undo everything.
		//

	}
	__except(PfpProcessExceptionFilter( GetExceptionInformation() )) 
	{

	}

	//
	//  If this isn't the top-level request then make sure to pass the real
	//  error back to the top level.
	//

	if (IrpContext != IrpContext->TopLevelIrpContext) 
	{

		//
		//  Make sure this error is returned to the top level guy.
		//  If the status is FILE_LOCK_CONFLICT then we are using this
		//  value to stop some lower level request.  Convert it to
		//  STATUS_CANT_WAIT so the top-level request will retry.
		//

		if (NT_SUCCESS( IrpContext->TopLevelIrpContext->ExceptionStatus )) 
		{

			if (ExceptionCode == STATUS_FILE_LOCK_CONFLICT) 
			{

				IrpContext->TopLevelIrpContext->ExceptionStatus = STATUS_CANT_WAIT;

			} else 
			{

				IrpContext->TopLevelIrpContext->ExceptionStatus = ExceptionCode;
			}
		}
	}

	// //
	//  If the status is cant wait then send the request off to the fsp.
	//

	TopLevelRequest = PfpIsTopLevelRequest( IrpContext );

	//
	//  We want to look at the LOG_FILE_FULL or CANT_WAIT cases and consider
	//  if we want to post the request.  We only post requests at the top
	//  level.
	//

	if (ExceptionCode == STATUS_CANT_WAIT) 
	{

		if (ARGUMENT_PRESENT( Irp )) 
		{

			//
			//  If we are top level, we will either post it or retry.
			//

			if (TopLevelRequest)
			{

				//
				//  See if we are supposed to post the request.
				//

// 				if (FlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_FORCE_POST ))
// 				{
// 
// 					PostIrpContext = IrpContext;
// 
// 					//
// 					//  Otherwise we will retry this request in the original thread.
// 					//
// 
// 				} else 
// 				{

					Retry = TRUE;
				//}

				//
				//  Otherwise we will complete the request, see if there is any
				//  related processing to do.
				//

			} else
			{

				//
				//  We are the top level Ntfs call.  If we are processing a
				//  LOG_FILE_FULL condition then there may be no one above us
				//  who can do the checkpoint.  Go ahead and fire off a dummy
				//  request.  Do an unsafe test on the flag since it won't hurt
				//  to generate an occasional additional request.
				//


				//
				//  If this is a paging write and we are not the top level
				//  request then we need to return STATUS_FILE_LOCk_CONFLICT
				//  to make MM happy (and keep the pages dirty) and to
				//  prevent this request from retrying the request.
				//

				ExceptionCode = STATUS_FILE_LOCK_CONFLICT;
			}
		}
	}

	//  We have the Irp.  We either need to complete this request or allow
	//  the top level thread to retry.
	//


	if (ARGUMENT_PRESENT(Irp)) 
	{

		//
		//  If this is a top level Ntfs request and we still have the Irp
		//  it means we will be retrying the request.  In that case
		//  mark the Irp Context so it doesn't go away.
		//

		if (Retry) 
		{

			SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_DONT_DELETE );
			PfpCompleteRequest( &IrpContext, NULL, ExceptionCode );

			//
			//  Clear the status code in the Irp Context.
			//

			IrpContext->ExceptionStatus = 0;

		} else
		{

			PfpCompleteRequest( &IrpContext, &Irp, ExceptionCode );
		}

	} else if (IrpContext != NULL) 
	{

		PfpCompleteRequest( &IrpContext, NULL, ExceptionCode );
	}

	return ExceptionCode;
}



VOID
PfpDecrementCleanupCounts (
							IN PPfpFCB pFcb,							
							IN BOOLEAN NonCachedHandle
							)

							/*++

							Routine Description:

							This procedure decrements the cleanup counts for the associated data structures
							and if necessary it also start to cleanup associated internal attribute streams

							Arguments:

							Scb - Supplies the Scb used in this operation

							Lcb - Optionally supplies the Lcb used in this operation

							NonCachedHandle - Indicates this handle is for a user non-cached handle.

							Return Value:

							None.

							--*/

{
	

	//ASSERT_SCB( pFcb );
	

	//
	//  First we decrement the appropriate cleanup counts
	//
	InterlockedDecrement( &pFcb->UncleanCount );
	

	if (NonCachedHandle) 
	{

		pFcb->NonCachedUnCleanupCount -= 1;
	}
	//
	//  And return to our caller
	//

	return;
}



VOID
PfpIncrementCleanupCounts (
							IN PPfpFCB pFcb,							
							IN BOOLEAN NonCachedHandle
							)

							/*++

							Routine Description:

							This routine increments the cleanup counts for the associated data structures

							Arguments:

							Scb - Supplies the Scb used in this operation

							Lcb - Optionally supplies the Lcb used in this operation

							NonCachedHandle - Indicates this handle is for a user non-cached handle.

							Return Value:

							None.

							--*/

{
	
	//
	//  This is really a pretty light weight procedure but having it be a procedure
	//  really helps in debugging the system and keeping track of who increments
	//  and decrements cleanup counts
	//

	InterlockedIncrement( &pFcb->UncleanCount );

	if (NonCachedHandle) 
	{

		pFcb->NonCachedUnCleanupCount += 1;
	}

	
	return;
}




BOOLEAN
PfpCreateFileLock (
					IN PPfpFCB Scb,
					IN BOOLEAN RaiseOnError
					)

					/*++

					Routine Description:

					This routine is called to create and initialize a file lock structure.
					A try-except is used to catch allocation failures if the caller doesn't
					want the exception raised.

					Arguments:

					Scb - Supplies the Scb to attach the file lock to.

					RaiseOnError - If TRUE then don't catch the allocation failure.

					Return Value:

					TRUE if the lock is allocated and initialized.  FALSE if there is an
					error and the caller didn't specify RaiseOnError.

					--*/

{
	PFILE_LOCK FileLock = NULL;
	BOOLEAN Success = TRUE;

	PAGED_CODE();

	//
	//  Use a try-except to catch all errors.
	//

	__try
	{

		FileLock = (PFILE_LOCK)ExAllocateFromNPagedLookasideList( &PfpFileLockLookasideList );

		FsRtlInitializeFileLock( FileLock, NULL, NULL );

		//
		//  Use the FsRtl header mutex to synchronize storing
		//  the lock structure, and only store it if no one
		//  else beat us.
		//

		PfpAcquireFsrtlHeader(Scb);

		if (Scb->FileLock == NULL)
		{
			Scb->FileLock = FileLock;
			FileLock = NULL;
		}

		PfpReleaseFsrtlHeader(Scb);

	} 
	__except( (!FsRtlIsNtstatusExpected( GetExceptionCode() ) || RaiseOnError)
		? EXCEPTION_CONTINUE_SEARCH
		: EXCEPTION_EXECUTE_HANDLER ) 
	{

		Success = FALSE;
	}

	if (FileLock != NULL) 
	{
		ExFreeToNPagedLookasideList( &PfpFileLockLookasideList, FileLock );
	}

	return Success;
}
