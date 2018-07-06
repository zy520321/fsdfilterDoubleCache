 
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
VOID
PfpAcquireSharedFcb (
					  IN PIRP_CONTEXT IrpContext,
					  IN PPfpFCB Fcb,					 
					  IN BOOLEAN NoDeleteCheck
					  )

					  /*++

					  Routine Description:

					  This routine acquires shared access to the Fcb.

					  This routine will raise if it cannot acquire the resource and wait
					  in the IrpContext is false.

					  Arguments:

					  Fcb - Supplies the Fcb to acquire

					  Scb - This is the Scb for which we are acquiring the Fcb

					  NoDeleteCheck - If TRUE then acquire the file even if it has been deleted.

					  Return Value:

					  None.

					  --*/

{
	NTSTATUS Status;

	Status = STATUS_CANT_WAIT;

	if (ExAcquireResourceSharedLite( Fcb->Resource,(BOOLEAN) BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))) 
	{

		//
		//  The link count should be non-zero or the file has been
		//  deleted.
		//

		if (NoDeleteCheck ||
			!FlagOn( Fcb->FcbState, FCB_STATE_FILE_DELETED ))
		{

				//
				//  It's possible that this is a recursive shared aquisition of an
				//  Fcb we own exclusively at the top level.  In that case we
				//  need to bump the acquisition count.
				//

				/*if (Fcb->ExclusiveFcbLinks.Flink != NULL) 
				{
					Fcb->BaseExclusiveCount += 1;
				}
				*/
				return;
		}

		//
		//  We need to release the Fcb and remember the status code.
		//

		ExReleaseResourceLite( Fcb->Resource );
		Status = STATUS_FILE_DELETED;
	}

	PfpRaiseStatus( IrpContext, Status, NULL );
}


VOID
PfpReleaseFcb (
				IN PIRP_CONTEXT IrpContext,
				IN PPfpFCB Fcb
				)

				/*++

				Routine Description:

				This routine releases the specified Fcb resource.  If the Fcb is acquired
				exclusive, and a transaction is still active, then the release is nooped
				in order to preserve two-phase locking.  If there is no longer an active
				transaction, then we remove the Fcb from the Exclusive Fcb List off the
				IrpContext, and clear the Flink as a sign.  Fcbs are released when the
				transaction is commited.

				Arguments:

				Fcb - Fcb to release

				Return Value:

				None.

				--*/

{
	//
	//  Check if this resource is owned exclusively and we are at the last
	//  release for this transaction.
	//

	/*if (Fcb->ExclusiveFcbLinks.Flink != NULL) {

		if (Fcb->BaseExclusiveCount == 1) {

			//
			//  If there is a transaction then noop this request.
			//

			if (IrpContext->TransactionId != 0) {

				return;
			}

			RemoveEntryList( &Fcb->ExclusiveFcbLinks );
			Fcb->ExclusiveFcbLinks.Flink = NULL;


			//
			//  This is a good time to free any Scb snapshots for this Fcb.
			//

			NtfsFreeSnapshotsForFcb( IrpContext, Fcb );
		}

		Fcb->BaseExclusiveCount -= 1;
	}

	ASSERT((Fcb->ExclusiveFcbLinks.Flink == NULL && Fcb->BaseExclusiveCount == 0) ||
		(Fcb->ExclusiveFcbLinks.Flink != NULL && Fcb->BaseExclusiveCount != 0));
*/
	UNREFERENCED_PARAMETER(IrpContext);
	ExReleaseResource( Fcb->Resource );
}


BOOLEAN
PfpAcquireExclusiveFcb (
						IN PIRP_CONTEXT IrpContext,
						IN PPfpFCB Fcb						 
						)
{
	if(ExAcquireResourceExclusiveLite(Fcb->Resource,BooleanFlagOn(IrpContext->Flags,IRP_CONTEXT_FLAG_WAIT)))
		return TRUE;
	else
		PfpRaiseStatus( IrpContext, STATUS_CANT_WAIT, NULL );	

	return FALSE;
}




BOOLEAN
PfpAcquireFCBForLazyWrite (
							IN PVOID OpaqueScb,
							IN BOOLEAN Wait
							)

							/*++

							Routine Description:

							The address of this routine is specified when creating a CacheMap for
							a file.  It is subsequently called by the Lazy Writer prior to its
							performing lazy writes to the file.  This callback is necessary to
							avoid deadlocks with the Lazy Writer.  (Note that normal writes
							acquire the Fcb, and then call the Cache Manager, who must acquire
							some of his internal structures.  If the Lazy Writer could not call
							this routine first, and were to issue a write after locking Caching
							data structures, then a deadlock could occur.)

							Arguments:

							OpaqueScb - The Scb which was specified as a context parameter for this
							routine.

							Wait - TRUE if the caller is willing to block.

							Return Value:

							FALSE - if Wait was specified as FALSE and blocking would have
							been required.  The Fcb is not acquired.

							TRUE - if the Scb has been acquired

							--*/

{
	BOOLEAN AcquiredFile = TRUE;

	ULONG CompressedStream = (ULONG)(LONGLONG)OpaqueScb & 1;

	PPfpFCB  Fcb = (PPfpFCB)OpaqueScb ;





	//
	//  Acquire the Scb only for those files that the write will
	//  acquire it for, i.e., not the first set of system files.
	//  Otherwise we can deadlock, for example with someone needing
	//  a new Mft record.
	//

	if (Fcb->Header.Resource != NULL) 
	{
		if(!ExAcquireResourceSharedLite(Fcb->Header.Resource,FALSE))
		{
			return FALSE;	
		}else
		{
			ExReleaseResourceLite(Fcb->Header.Resource);
			AcquiredFile = ExAcquireResourceSharedLite( Fcb->Header.Resource, Wait );
		}
	} 

	if (AcquiredFile) 
	{

		//
		// We assume the Lazy Writer only acquires this Scb once.  When he
		// has acquired it, then he has eliminated anyone who would extend
		// valid data, since they must take out the resource exclusive.
		// Therefore, it should be guaranteed that this flag is currently
		// clear (the ASSERT), and then we will set this flag, to insure
		// that the Lazy Writer will never try to advance Valid Data, and
		// also not deadlock by trying to get the Fcb exclusive.
		//

		ASSERT( Fcb->LazyWriteThread[CompressedStream] == NULL );

		Fcb->LazyWriteThread[CompressedStream] = PsGetCurrentThread();

		//
		//  Make Cc top level, so that we will not post or retry on errors.
		//  (If it is not NULL, it must be one of our internal calls to this
		//  routine, such as from Restart or Hot Fix.)
		//

		if (IoGetTopLevelIrp() == NULL) 
		{
			IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
		}
	}

	return AcquiredFile;
}


VOID
PfpReleaseFCBFromLazyWrite (
							 IN PVOID OpaqueScb
							 )

							 /*++

							 Routine Description:

							 The address of this routine is specified when creating a CacheMap for
							 a file.  It is subsequently called by the Lazy Writer after its
							 performing lazy writes to the file.

							 Arguments:

							 Scb - The Scb which was specified as a context parameter for this
							 routine.

							 Return Value:

							 None

							 --*/

{
	ULONG CompressedStream = (ULONG)(LONGLONG)OpaqueScb & 1;

	PPfpFCB Fcb = (PPfpFCB)OpaqueScb;





	//
	//  Clear the toplevel at this point, if we set it above.
	//

	if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP) 
	{
		IoSetTopLevelIrp( NULL );
	}

	Fcb->LazyWriteThread[CompressedStream] = NULL;

	if (Fcb->Header.Resource != NULL) 
	{
		ExReleaseResourceLite( Fcb->Header.Resource );
	} else if(Fcb->Resource )
	{
		ExReleaseResourceLite( Fcb->Resource );
	}

	return;
}




BOOLEAN
PfpAcquireFCBForReadAhead (
							IN PVOID OpaqueScb,
							IN BOOLEAN Wait
							)

							/*++

							Routine Description:

							The address of this routine is specified when creating a CacheMap for
							a file.  It is subsequently called by the Lazy Writer prior to its
							performing read ahead to the file.

							Arguments:

							Scb - The Scb which was specified as a context parameter for this
							routine.

							Wait - TRUE if the caller is willing to block.

							Return Value:

							FALSE - if Wait was specified as FALSE and blocking would have
							been required.  The Fcb is not acquired.

							TRUE - if the Scb has been acquired

							--*/

{
 	PPfpFCB Fcb			 = (PPfpFCB)OpaqueScb;
	BOOLEAN AcquiredFile = FALSE;
	//
	//  Acquire the Scb only for those files that the read wil
	//  acquire it for, i.e., not the first set of system files.
	//  Otherwise we can deadlock, for example with someone needing
	//  a new Mft record.
	//

	if ((Fcb->Header.Resource == NULL) ||
		ExAcquireResourceSharedLite( Fcb->Header.Resource, Wait ))
	{
		AcquiredFile = TRUE;			 
	}

	return AcquiredFile;
}


VOID
PfpReleaseFCBFromReadAhead (
							 IN PVOID OpaqueScb
							 )

							 /*++

							 Routine Description:

							 The address of this routine is specified when creating a CacheMap for
							 a file.  It is subsequently called by the Lazy Writer after its
							 read ahead.

							 Arguments:

							 Scb - The Scb which was specified as a context parameter for this
							 routine.

							 Return Value:

							 None

							 --*/

{
	PPfpFCB Fcb = (PPfpFCB)OpaqueScb;
	//
	//  Free our read ahead entry.
	//

	if (Fcb->Header.Resource != NULL) 
	{
		ExReleaseResourceLite( Fcb->Header.Resource );
	}

	return;
}