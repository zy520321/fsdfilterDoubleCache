
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"

NTSTATUS
PfpFsdFlushBuffers (
					 IN PDEVICE_OBJECT VolumeDeviceObject,
					 IN PIRP Irp
					 )

					 /*++

					 Routine Description:

					 This routine implements the FSD part of flush buffers.

					 Arguments:

					 VolumeDeviceObject - Supplies the volume device object where the
					 file exists

					 Irp - Supplies the Irp being processed

					 Return Value:

					 NTSTATUS - The FSD status for the IRP
  
					 --*/

{
	TOP_LEVEL_CONTEXT	TopLevelContext;
	PTOP_LEVEL_CONTEXT	ThreadTopLevelContext;

	NTSTATUS			Status			= STATUS_SUCCESS;
	PIRP_CONTEXT		IrpContext		= NULL;
	PFILE_OBJECT		pFileObject		= NULL;
	PDISKFILEOBJECT		pDiskFileObj	= NULL;
	PUSERFILEOBJECT		pUserFileObjects= NULL;
	PFILESPY_DEVICE_EXTENSION dext		= NULL;
	PDEVICE_OBJECT      pNextDevice		= NULL;
	PIO_STACK_LOCATION	pSp				= NULL;
	PPfpFCB				pFcb			= NULL;
//	PERESOURCE			pDeviceResource= NULL;

	UNREFERENCED_PARAMETER( VolumeDeviceObject );

	PAGED_CODE();

	
	pSp = IoGetCurrentIrpStackLocation(Irp);
		
	pFileObject		= pSp->FileObject;
	

	dext		= ((PDEVICE_OBJECT)VolumeDeviceObject)->DeviceExtension;
	pNextDevice = dext->NLExtHeader.AttachedToDeviceObject;

	if(dext->bShadow)
	{
		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)dext->pRealDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject;
		goto BYPASS;
	}


	if(!PfpFileObjectHasOurFCB(pFileObject))
		goto BYPASS;

	
	//
	//  Call the common flush buffer routine
	//
// 	pDeviceResource = PfpGetDeviceResource((PDEVICE_OBJECT)VolumeDeviceObject);
// 
// 	if(pDeviceResource== NULL)
// 	{ASSERT(0);
// 		goto BYPASS;
// 	}
	FsRtlEnterFileSystem();
	

	//ExAcquireResourceExclusiveLite(pDeviceResource,TRUE);
	ThreadTopLevelContext = PfpSetTopLevelIrp( &TopLevelContext, FALSE, FALSE );

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

			Status = PfpCommonFlushBuffers( IrpContext, Irp );
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

	} while (Status == STATUS_CANT_WAIT ||Status == STATUS_LOG_FILE_FULL);

	if (ThreadTopLevelContext == &TopLevelContext)
	{
		PfpRestoreTopLevelIrp( ThreadTopLevelContext );
	}
// 	if(pDeviceResource)
// 	{
// 		ExReleaseResource(pDeviceResource);
// 	}
	FsRtlExitFileSystem();

	return Status;

BYPASS:
// 	if(pDeviceResource)
// 	{
// 		ExReleaseResource(pDeviceResource);
// 	}
	IoSkipCurrentIrpStackLocation(Irp);

	Status = IoCallDriver(pNextDevice,Irp);
	return Status;
}


NTSTATUS
PfpCommonFlushBuffers (
						IN PIRP_CONTEXT IrpContext,
						IN PIRP Irp
						)

						/*++

						Routine Description:

						This is the common routine for flush buffers called by both the fsd and fsp
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
	BOOLEAN  ScbAcquired = FALSE;
	PAGED_CODE();

	IrpSp = IoGetCurrentIrpStackLocation( Irp );

	//
	//  Extract and decode the file object
	//

	FileObject = IrpSp->FileObject;
	Fcb		   = (PPfpFCB)FileObject->FsContext;

	Status = STATUS_SUCCESS;

	__try
	{

		//
		//  Make sure the data gets out to disk.
		//

		PfpAcquireExclusivePagingIo( IrpContext, Fcb );

		//
		//  Acquire exclusive access to the Scb and enqueue the irp
		//  if we didn't get access
		//

		//PfpAcquireExclusiveFcb( IrpContext, Fcb );
		//ScbAcquired = TRUE;

		//
		//  Flush the stream and verify there were no errors.
		//

		Irp->IoStatus.Status= Status= PfpFlushUserStream( IrpContext, Fcb,NULL,0 );	


	}
	__finally
	{
// 		if(ScbAcquired)
// 		{
// 			PfpReleaseFcb(IrpContext,Fcb);
// 		}
		
		PfpReleasePagingIo	( IrpContext, Fcb );
		PfpCompleteRequest(&IrpContext,&Irp,Status);

		//DebugTrace( -1, Dbg, ("NtfsCommonFlushBuffers -> %08lx\n", Status) );
	}

	return Status;
}


NTSTATUS
PfpFlushUserStream (
					 IN PIRP_CONTEXT IrpContext,
					 IN PPfpFCB Scb,
					 IN PLONGLONG FileOffset OPTIONAL,
					 IN ULONG Length
					 )

					 /*++

					 Routine Description:

					 This routine flushes a user stream as a top-level action.  To do so
					 it checkpoints the current transaction first and frees all of the
					 caller's snapshots.  After doing the flush, it snapshots the input
					 Scb again, just in case the caller plans to do any more work on that
					 stream.  If the caller needs to modify any other streams (presumably
					 metadata), it must know to snapshot them itself after calling this
					 routine.

					 Arguments:

					 Scb - Stream to flush

					 FileOffset - FileOffset at which the flush is to start, or NULL for
					 entire stream.

					 Length - Number of bytes to flush.  Ignored if FileOffset not specified.

					 Return Value:

					 Status of the flush

					 --*/

{
	IO_STATUS_BLOCK IoStatus;
	BOOLEAN ScbAcquired = FALSE;

	PAGED_CODE();


	//  Set the wait flag in the IrpContext so we don't hit a case where the
	//  reacquire below fails because we can't wait.  If our caller was asynchronous
	//  and we get this far we will continue synchronously.
	//

	SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );

	//
	//  Now do the flush he wanted as a top-level action
	//

	CcFlushCache( &Scb->SegmentObject, (PLARGE_INTEGER)FileOffset, Length, &IoStatus );


	return IoStatus.Status;
}
