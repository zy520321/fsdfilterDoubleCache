 #include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"

VOID
PfpAddToWorkque (
				 IN PIRP_CONTEXT IrpContext,
				 IN PIRP Irp OPTIONAL
				 )

				 /*++

				 Routine Description:

				 This routine is called to acually store the posted Irp to the Fsp
				 workque.

				 Arguments:

				 IrpContext - Pointer to the IrpContext to be queued to the Fsp

				 Irp - I/O Request Packet.

				 Return Value:

				 None.

				 --*/

{
	
	PIO_STACK_LOCATION pStack ;
	UNREFERENCED_PARAMETER(Irp);
	pStack = IoGetCurrentIrpStackLocation(IrpContext->OriginatingIrp);
	ASSERT(pStack );
	ASSERT(pStack ->FileObject->DeviceObject);
	IrpContext->WorkItem =  IoAllocateWorkItem(pStack ->FileObject->DeviceObject);	

	IoQueueWorkItem(IrpContext->WorkItem,
					PfpFspDispatchEX,
					DelayedWorkQueue,
					(PVOID)IrpContext);


// 	ExInitializeWorkItem(   &IrpContext->WorkQueueItem,
// 								PfpFspDispatch,
// 							(PVOID)IrpContext );
// 
// 	ExQueueWorkItem( &IrpContext->WorkQueueItem, CriticalWorkQueue );

	return;
}



VOID
PfpOplockComplete (
				   IN PVOID Context,
				   IN PIRP Irp
				   )
{
	PAGED_CODE();

	//
	//  Check on the return value in the Irp.
	//

	if (Irp->IoStatus.Status == STATUS_SUCCESS) 
	{

		//
		//  Insert the Irp context in the workqueue.
		//

		PfpAddToWorkque( (PIRP_CONTEXT) Context, Irp );

		//
		//  Otherwise complete the request.
		//

	} else 
	{

		PfpCompleteRequest( ((PIRP_CONTEXT *)&Context), &Irp, Irp->IoStatus.Status );
	}

	return;
}

VOID
PfpPrePostIrp (
			   IN PVOID Context,
			   IN PIRP Irp OPTIONAL
			   )
{
	PIRP_CONTEXT IrpContext;
	PPfpFCB Fcb;
	PIO_STACK_LOCATION IrpSp = NULL;

	IrpContext = (PIRP_CONTEXT) Context;

	//ASSERT_IRP_CONTEXT( IrpContext );

	//
	//  Make sure if we are posting the request, which may be
	//  because of log file full, that we free any Fcbs or PagingIo
	//  resources which were acquired.
	//

	//
	//  Free any exclusive paging I/O resource, or IoAtEof condition,
	//  this field is overlayed, minimally in write.c.
	//

	Fcb = IrpContext->FcbWithPagingExclusive;
	if (Fcb != NULL) 
	{
		FsRtlUnlockFsRtlHeader(&Fcb->Header);
		//PfpReleasePagingIo(IrpContext, Fcb );
		IrpContext->FcbWithPagingExclusive = NULL;
	}

/*	while (!IsListEmpty(&IrpContext->ExclusiveFcbList))
	{

		PfpReleaseFcb( IrpContext,
						(PPfpFCB)CONTAINING_RECORD(IrpContext->ExclusiveFcbList.Flink,
						Fcb,
						ExclusiveFcbLinks ));
	}
*/
	
	IrpContext->OriginatingIrp = Irp;

	//
	//  Note that close.c uses a trick where the "Irp" is really
	//  a file object.
	//

	if (ARGUMENT_PRESENT( Irp )) 
	{

		if (Irp->Type == IO_TYPE_IRP)
		{

			IrpSp = IoGetCurrentIrpStackLocation( Irp );

			//
			//  We need to lock the user's buffer, unless this is an MDL-read,
			//  in which case there is no user buffer.
			//
			//  **** we need a better test than non-MDL (read or write)!

			if (IrpContext->MajorFunction == IRP_MJ_READ
				|| IrpContext->MajorFunction == IRP_MJ_WRITE) 
			{

					ClearFlag(IrpContext->MinorFunction, IRP_MN_DPC);

					//
					//  Lock the user's buffer if this is not an Mdl request.
					//

					if (!FlagOn( IrpContext->MinorFunction, IRP_MN_MDL )) 
					{

						PfpLockUserBuffer( IrpContext,
											Irp,
											(IrpContext->MajorFunction == IRP_MJ_READ) ?
												IoWriteAccess : IoReadAccess,
											(IrpContext->MajorFunction == IRP_MJ_READ)?
											IrpSp->Parameters.Read.Length:IrpSp->Parameters.Write.Length  );
					}

					//
					//  We also need to check whether this is a query directory operation.
					//

			} else if (IrpContext->MajorFunction == IRP_MJ_DIRECTORY_CONTROL
						&& IrpContext->MinorFunction == IRP_MN_QUERY_DIRECTORY) 
			{

				PfpLockUserBuffer( IrpContext,
										Irp,
										IoWriteAccess,
										IrpSp->Parameters.QueryDirectory.Length );

					//
					//  We also need to check whether this is a query ea operation.
					//

			} else if (IrpContext->MajorFunction == IRP_MJ_QUERY_EA) 
			{

				PfpLockUserBuffer( IrpContext,
									Irp,
									IoWriteAccess,
									IrpSp->Parameters.QueryEa.Length );

				//
				//  We also need to check whether this is a set ea operation.
				//

			} else if (IrpContext->MajorFunction == IRP_MJ_SET_EA) 
			{

				PfpLockUserBuffer( IrpContext,
									Irp,
									IoReadAccess,
									IrpSp->Parameters.SetEa.Length );

				//
				//  These two FSCTLs use neither I/O, so check for them.
				//

			} else if ((IrpContext->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
				(IrpContext->MinorFunction == IRP_MN_USER_FS_REQUEST) &&
				((IrpSp->Parameters.FileSystemControl.FsControlCode == FSCTL_GET_VOLUME_BITMAP) ||
				(IrpSp->Parameters.FileSystemControl.FsControlCode == FSCTL_GET_RETRIEVAL_POINTERS))) 
			{

					PfpLockUserBuffer( IrpContext,
										Irp,
										IoWriteAccess,
										IrpSp->Parameters.FileSystemControl.OutputBufferLength );
			}

			//
			//  Mark that we've already returned pending to the user
			//

			IoMarkIrpPending( Irp );
		}
	}

	return;
}


NTSTATUS
PfpPostRequest (
				IN PIRP_CONTEXT IrpContext,
				IN PIRP Irp OPTIONAL
				)
{
	ASSERT( !ARGUMENT_PRESENT( Irp )
			|| !FlagOn( Irp->Flags, IRP_PAGING_IO )
			|| (IrpContext->MajorFunction != IRP_MJ_READ
			&& IrpContext->MajorFunction != IRP_MJ_WRITE));

	//NtfsFreeSnapshotsForFcb( IrpContext, NULL );

	//RtlZeroMemory( &IrpContext->ScbSnapshot, sizeof(SCB_SNAPSHOT) );

	PfpPrePostIrp( IrpContext, Irp );

	PfpAddToWorkque( IrpContext, Irp );

	//
	//  And return to our caller
	//

	return STATUS_PENDING;
}
