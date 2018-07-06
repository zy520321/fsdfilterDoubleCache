#include "Aes.h"
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
//#include "filespy.h"
#include "fspyKern.h"

NTSTATUS
PfpWrite (
		  __in PDEVICE_OBJECT DeviceObject,
		  __in PIRP Irp
		  )
{
	PIO_STACK_LOCATION 			pstack ;
	PFILE_OBJECT				pFileObject		= NULL;
	PFILESPY_DEVICE_EXTENSION	pExt  ;
	PDEVICE_OBJECT				pNextDriver;
	PDISKFILEOBJECT				pDiskFileObject = NULL;
	FILEOBJECTTYPE				typeOfFileobject;
	NTSTATUS					ntstatus	;
	PIRP_CONTEXT				Irp_Context		= NULL;
	TOP_LEVEL_CONTEXT			TopLevelContext;
	PTOP_LEVEL_CONTEXT			ThreadTopLevelContext;
	PPfpFCB						pFcb			= NULL;
//	 PERESOURCE					pDeviceResource= NULL;
	

	ntstatus			= STATUS_SUCCESS;
	
	pExt				= DeviceObject->DeviceExtension;
	pNextDriver			= pExt->NLExtHeader.AttachedToDeviceObject;

	

	if(pExt->bShadow)
	{
		pNextDriver = ((PFILESPY_DEVICE_EXTENSION)(pExt->pRealDevice->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
		goto PASSTHROUGH;
	}

	pstack		= IoGetCurrentIrpStackLocation(Irp);
	pFileObject = pstack->FileObject ;
	
	if(pFileObject == NULL)
	{
		goto PASSTHROUGH;
	}

	if(!PfpFileObjectHasOurFCB(pFileObject))
		goto PASSTHROUGH;

	pFcb = (PPfpFCB)pFileObject->FsContext;
	
	FsRtlEnterFileSystem();	
	if(pFcb->bModifiedByOther)
	{
		Irp->IoStatus.Information = pstack->Parameters.Write.Length;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp,IO_DISK_INCREMENT);
		goto RETURNED;
	}

	
// 	pDeviceResource = PfpGetDeviceResource((PDEVICE_OBJECT)DeviceObject);
// 
// 	if(pDeviceResource== NULL)
// 	{	ASSERT(0);
// 		Irp->IoStatus.Information = 0;
// 		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
// 		IoCompleteRequest(Irp,IO_DISK_INCREMENT);
// 		goto RETURNED;
// 	}
// 
//   	ExAcquireResourceExclusiveLite(pDeviceResource,TRUE);

	ASSERT(pFcb->pDiskFileObject);
	pDiskFileObject = pFcb->pDiskFileObject;
	
	if(pDiskFileObject->pDiskFileObjectWriteThrough== NULL)
	{
		Irp->IoStatus.Information	= 0;
		ntstatus =	Irp->IoStatus.Status		= STATUS_FILE_CLOSED;
		
		IoCompleteRequest(Irp,IO_DISK_INCREMENT);
		goto RETURNED;
	}
	typeOfFileobject = FILEOBJECT_FROM_USERMODE;
	switch(typeOfFileobject)
	{
	case FILEOBJECT_FROM_USERMODE:
		{				
			//
			ThreadTopLevelContext =  PfpSetTopLevelIrp(&TopLevelContext,FALSE,FALSE);	
			do {
				 __try
					{
						if(Irp_Context== NULL)
							Irp_Context = PfpCreateIrpContext(Irp,CanFsdWait(Irp));
						
						if(Irp_Context == NULL)
						{
							Irp->IoStatus.Information = 0;
							ntstatus =Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
							IoCompleteRequest(Irp,IO_DISK_INCREMENT);
							goto RETURNED;
						}
						if(ntstatus == STATUS_CANT_WAIT)
						{
							SetFlag(Irp_Context->Flags,IRP_CONTEXT_FLAG_WAIT);
						}
						PfpUpdateIrpContextWithTopLevel( Irp_Context, ThreadTopLevelContext );
						//pUserFileobject		= PfpGetUserFileobjects(&pDiskFileObject->UserFileObjList,pFileObject);
						

						//ASSERT(pUserFileobject );

						Irp_Context->Fileobject_onDisk = pDiskFileObject->pDiskFileObjectWriteThrough;
						Irp_Context->pNextDevice	   = pNextDriver;

						if(pstack->MinorFunction & IRP_MN_COMPLETE)
						{
							ntstatus = PfpCompleteMdl ( Irp_Context, Irp );
						}else
						{
							ntstatus = PfpCommonWrite ( Irp_Context, Irp );
						}


					}// the excrptionfilter will be customized to receive the result from the iocalldriver function
					__except (PfpExceptionFilter ( Irp_Context, GetExceptionInformation()))
					{
						NTSTATUS ExceptionCode;

						ExceptionCode = GetExceptionCode();

						if (ExceptionCode == STATUS_FILE_DELETED) 
						{

							Irp_Context->ExceptionStatus = ExceptionCode = STATUS_SUCCESS;

						} else if (ExceptionCode == STATUS_VOLUME_DISMOUNTED) 
						{

							Irp_Context->ExceptionStatus = ExceptionCode = STATUS_SUCCESS;
						}

						ntstatus = PfpProcessException( Irp_Context, Irp , ExceptionCode );			

					}

			} while ((ntstatus == STATUS_CANT_WAIT) &&
						(ThreadTopLevelContext == &TopLevelContext));

			if (ThreadTopLevelContext == &TopLevelContext) 
			{
				PfpRestoreTopLevelIrp( ThreadTopLevelContext );
			}
			/*
			1: process cache
			2: process pageio
			3: 
			*/
		}

		break;
	case FILEOBEJCT_ON_DISK:
		{

		}
		break;
	case FILEOBJECT_WITH_WRITETHROUGH:

		break;
	default:
		break;
	}

RETURNED:

//   	if(pDeviceResource)
//   	{
//   		ExReleaseResource(pDeviceResource);
//   	}
	FsRtlExitFileSystem();
	return ntstatus;

PASSTHROUGH:
	
	IoSkipCurrentIrpStackLocation(Irp);
	ntstatus = IoCallDriver(pNextDriver ,Irp);


	return ntstatus;
}

#define WriteToEof (StartingOffset < 0)

NTSTATUS PfpCommonWrite(PIRP_CONTEXT irpContext,PIRP Irp)
{

	BOOLEAN						Wait;
	BOOLEAN						PagingIo;
	BOOLEAN						NonCachedIo;
	BOOLEAN						SynchronousIo;
	PFILE_OBJECT				pFileObject;
	LONGLONG					StartingOffset;
	LONGLONG 					ByteCount;
	LONGLONG					ByteRange;
	NTSTATUS					NTStatus;
	PIO_STACK_LOCATION			IrpStack;
	
	NTFS_IO_CONTEXT				LocalContext;
	BOOLEAN						PagingIoResourceAcquired;
	
	PVOID						SystemBuffer ;			
	PPfpFCB						pFcb;
	PPfpCCB						Ccb;
	BOOLEAN						CalledByLazyWriter;
	BOOLEAN						RecursiveWriteThrough;
	BOOLEAN						DoingIoAtEof;
	LONGLONG					OldFileSize;
	BOOLEAN						SetWriteSeen;
	BOOLEAN						OriginalWait;
	
	BOOLEAN						plockPostIrp ;
	BOOLEAN						PostIrp ;
	BOOLEAN                     OplockPostIrp ;
	BOOLEAN						ScbAcquired;
	BOOLEAN						CcFileSizeChangeDue ;
	LONGLONG					LlTemp1;

	EOF_WAIT_BLOCK				EofWaitBlock;

	

	SystemBuffer	= NULL;
	ScbAcquired		= FALSE;
	OplockPostIrp   = FALSE;
	PostIrp			= FALSE;
	plockPostIrp	= FALSE;
	OriginalWait	= FALSE;
	SetWriteSeen	= FALSE;
	DoingIoAtEof	= FALSE;
	PagingIoResourceAcquired = FALSE;

	Wait          = IoIsOperationSynchronous(Irp);
	PagingIo      = BooleanFlagOn(Irp->Flags,IRP_PAGING_IO);
	NonCachedIo   = BooleanFlagOn(Irp->Flags,IRP_NOCACHE);
	
	
	IrpStack      = IoGetCurrentIrpStackLocation(Irp);
	pFileObject	  = IrpStack->FileObject;

	SynchronousIo = BooleanFlagOn(pFileObject->Flags,FO_SYNCHRONOUS_IO);
	
	StartingOffset  = IrpStack->Parameters.Write.ByteOffset.QuadPart ;
	ByteCount	    = (LONGLONG)IrpStack->Parameters.Write.Length ;
	ByteRange		= StartingOffset + ByteCount;

	pFileObject		= IrpStack->FileObject	;
	
	pFcb			= (PPfpFCB)pFileObject->FsContext;
	Ccb				= (PPfpCCB)pFileObject->FsContext2;
	//there's nothing needed us to do 
	if( (ULONG)ByteCount == 0 )
	{	
		Irp->IoStatus.Information = 0;
		
		PfpCompleteRequest (&irpContext,&Irp,STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}

	//if this is a nocache and no pageio 's ;and this file has been opened as cached, we should clear the cached's content from section to avoid 
	//
	if (!PagingIo &&(!NonCachedIo) &&!CcCanIWrite(pFileObject,
		(ULONG)ByteCount,
		(BOOLEAN)(FlagOn(irpContext->Flags, IRP_CONTEXT_FLAG_WAIT) &&!FlagOn(irpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP)),
		BooleanFlagOn(irpContext->Flags, IRP_CONTEXT_DEFERRED_WRITE))) 
	{

		BOOLEAN Retrying = BooleanFlagOn(irpContext->Flags, IRP_CONTEXT_DEFERRED_WRITE);

		PfpPrePostIrp( irpContext, Irp );

		SetFlag( irpContext->Flags, IRP_CONTEXT_DEFERRED_WRITE );

		CcDeferWrite(   pFileObject,
						(PCC_POST_DEFERRED_WRITE)PfpAddToWorkque ,
						irpContext,
						Irp,
						(ULONG)ByteCount,
						Retrying );

		return STATUS_PENDING;
	}
	
	
	if (NonCachedIo) 
	{

		//
		//  If there is a context pointer, we need to make sure it was
		//  allocated and not a stale stack pointer.
		//

		if (irpContext->Union.NtfsIoContext == NULL
			|| !FlagOn( irpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT )) 
		{

				//
				//  If we can wait, use the context on the stack.  Otherwise
				//  we need to allocate one.
				//

				if (Wait) 
				{

					irpContext->Union.NtfsIoContext = &LocalContext;
					ClearFlag( irpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );

				} else 
				{

					irpContext->Union.NtfsIoContext = (PNTFS_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &NtfsIoContextLookasideList );
					SetFlag( irpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );
				}
		}

		RtlZeroMemory( irpContext->Union.NtfsIoContext, sizeof( NTFS_IO_CONTEXT ));

		//
		//  Store whether we allocated this context structure in the structure
		//  itself.
		//

		irpContext->Union.NtfsIoContext->AllocatedContext =
										BooleanFlagOn( irpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );

		if (Wait) 
		{

			KeInitializeEvent( &irpContext->Union.NtfsIoContext->Wait.SyncEvent,
								NotificationEvent,
								FALSE );

			irpContext->Union.NtfsIoContext->OriginatingIrp					=	Irp ;
		} else 
		{

			irpContext->Union.NtfsIoContext->PagingIo						=	PagingIo;
			irpContext->Union.NtfsIoContext->Wait.Async.ResourceThreadId	=	ExGetCurrentResourceThread();
			irpContext->Union.NtfsIoContext->Wait.Async.RequestedByteCount	=	(ULONG)ByteCount;
			irpContext->Union.NtfsIoContext->OriginatingIrp					=	Irp ;
			irpContext->Union.NtfsIoContext->Wait.Async.Resource			=   pFcb->Header.Resource;
		}
	}	
	NTStatus  = STATUS_SUCCESS;

	__try
	{
		if (NonCachedIo &&
			!PagingIo &&			
			(pFileObject->SectionObjectPointer->DataSectionObject != NULL))
		{

				//
				//  Acquire the paging io resource to test the compression state.  If the
				//  file is compressed this will add serialization up to the point where
				//  CcCopyWrite flushes the data, but those flushes will be serialized
				//  anyway.  Uncompressed files will need the paging io resource
				//  exclusive to do the flush.
				//

				ExAcquireResourceExclusiveLite( pFcb->Header.Resource, TRUE );
				PagingIoResourceAcquired = TRUE;

				{

					if (WriteToEof) 
					{
						FsRtlLockFsRtlHeader( &pFcb->Header );
						irpContext->FcbWithPagingExclusive = (PPfpFCB) pFcb;
					}

					CcFlushCache( pFileObject->SectionObjectPointer,
									WriteToEof ? &pFcb->Header.FileSize : (PLARGE_INTEGER)&StartingOffset,
									(ULONG)ByteCount,
									&Irp->IoStatus );

					if (WriteToEof) 
					{
						FsRtlUnlockFsRtlHeader( &pFcb->Header );
						irpContext->FcbWithPagingExclusive = NULL;
					}

					//
					//  Make sure there was no error in the flush path.
					//

					if (!NT_SUCCESS( irpContext->TopLevelIrpContext->ExceptionStatus ) ||
						!NT_SUCCESS( Irp->IoStatus.Status )) 
					{
						
						PfpNormalizeAndRaiseStatus(irpContext,
													Irp->IoStatus.Status,STATUS_UNEXPECTED_IO_ERROR);
						
					}

					//
					//  Now purge the data for this range.
					//
					CcPurgeCacheSection(pFileObject->SectionObjectPointer,
										(PLARGE_INTEGER)&StartingOffset,
										(ULONG)ByteCount,
										FALSE );
				}

				//
				//  Convert to shared but don't release the resource.  This will synchronize
				//  this operation with defragging.
				//

				ExConvertExclusiveToSharedLite( pFcb->Header.Resource );
		}


		if (PagingIo)
		{

			//
			//  For all paging I/O, the correct resource has already been
			//  acquired shared - PagingIoResource if it exists, or else
			//  main Resource.  In some rare cases this is not currently
			//  true (shutdown & segment dereference thread), so we acquire
			//  shared here, but we starve exclusive in these rare cases
			//  to be a little more resilient to deadlocks!  Most of the
			//  time all we do is the test.
			//

			if ((pFcb->Header.Resource != NULL) &&
 				!ExIsResourceAcquiredSharedLite(pFcb->Header.Resource)/* &&
  				!ExIsResourceAcquiredShared(pFcb->Header.Resource)*/) 
			{

					ExAcquireSharedStarveExclusive( pFcb->Header.Resource, TRUE );
					PagingIoResourceAcquired = TRUE;
			}

			//
			//  Note that the lazy writer must not be allowed to try and
			//  acquire the resource exclusive.  This is not a problem since
			//  the lazy writer is paging IO and thus not allowed to extend
			//  file size, and is never the top level guy, thus not able to
			//  extend valid data length.
			//

			if ((pFcb->LazyWriteThread[0]  == PsGetCurrentThread()) ||
				(pFcb->LazyWriteThread[1]  == PsGetCurrentThread())) 
			{

					//DebugTrace( 0, Dbg, ("Lazy writer generated write\n") );
					CalledByLazyWriter = TRUE;

					//
					//  If the temporary bit is set in the Scb then set the temporary
					//  bit in the file object.  In case the temporary bit has changed
					//  in the Scb, this is a good file object to fix it in!
					//

					//
					//  Test if we are the result of a recursive flush in the write path.  In
					//  that case we won't have to update valid data.
					//

			} else 
			{

				//
				//  Check if we are recursing into write from a write via the
				//  cache manager.
				//

				if (FlagOn( irpContext->TopLevelIrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_SEEN ))
				{

					RecursiveWriteThrough = TRUE;

				} else 
				{

					SetFlag(irpContext->TopLevelIrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_SEEN);
					SetWriteSeen = TRUE;

					//
					//  This is could be someone who extends valid data,
					//  like the Mapped Page Writer or a flush, so we have to
					//  duplicate code from below to serialize this guy with I/O
					//  at the end of the file.  We do not extend valid data for
					//  metadata streams and need to eliminate them to avoid deadlocks
					//  later.
					//

					//if (!FlagOn(Scb->ScbState, SCB_STATE_MODIFIED_NO_WRITE)) 
					{

						ASSERT(!WriteToEof);

						//
						//  Now synchronize with the FsRtl Header
						//

						ExAcquireFastMutex( pFcb->Header.FastMutex );

						//
						//  Now see if we will change FileSize.  We have to do it now
						//  so that our reads are not nooped.
						//

						if (ByteRange > pFcb->Header.ValidDataLength.QuadPart) 
						{

							//
							//  Our caller may already be synchronized with EOF.
							//  The FcbWithPaging field in the top level IrpContext
							//  will have either the current Fcb/Scb if so.
							//

							if ((irpContext->TopLevelIrpContext->FcbWithPagingExclusive == pFcb) )
							{
								DoingIoAtEof = TRUE;
								OldFileSize = pFcb->Header.FileSize.QuadPart;
							} else 
							{

								//
								//  We can change FileSize and ValidDataLength if either, no one
								//  else is now, or we are still extending after waiting.
								//  We won't block the mapped page writer on IoAtEof.  Test
								//  the original state of the wait flag to know this.
								//

								if (FlagOn( pFcb->Header.Flags, FSRTL_FLAG_EOF_ADVANCE_ACTIVE )) 
								{

									if (!OriginalWait) 
									{

										ExReleaseFastMutex( pFcb->Header.FastMutex );

										try_return( NTStatus = STATUS_FILE_LOCK_CONFLICT );
									}

									DoingIoAtEof = PfpWaitForIoAtEof( &pFcb->Header, (PLARGE_INTEGER)&StartingOffset, (ULONG)ByteCount, &EofWaitBlock );

								} else 
								{

									DoingIoAtEof = TRUE;
								}

								//
								//  Set the Flag if we are changing FileSize or ValidDataLength,
								//  and save current values.
								//

								if (DoingIoAtEof)
								{

									SetFlag( pFcb->Header.Flags, FSRTL_FLAG_EOF_ADVANCE_ACTIVE );

									//
									//  Store this in the IrpContext until commit or post
									//

									irpContext->FcbWithPagingExclusive = (PPfpFCB)pFcb;

									OldFileSize = pFcb->Header.FileSize.QuadPart;
								}
							}

						}
						ExReleaseFastMutex( pFcb->Header.FastMutex );
					}
				}
			}

			//
			//  If are paging io, then we do not want
			//  to write beyond end of file.  If the base is beyond Eof, we will just
			//  Noop the call.  If the transfer starts before Eof, but extends
			//  beyond, we will truncate the transfer to the last sector
			//  boundary.
			//
			//  Just in case this is paging io, limit write to file size.
			//  Otherwise, in case of write through, since Mm rounds up
			//  to a page, we might try to acquire the resource exclusive
			//  when our top level guy only acquired it shared. Thus, =><=.
			//

			ExAcquireFastMutex( pFcb->Header.FastMutex );
			if (ByteRange > pFcb->Header.FileSize.QuadPart) 
			{

				if (StartingOffset >= pFcb->Header.FileSize.QuadPart) 
				{
					//DebugTrace( 0, Dbg, ("PagingIo started beyond EOF.\n") );

					Irp->IoStatus.Information = 0;

					//
					//  Make sure we do not advance ValidDataLength!
					//

					ByteRange = pFcb->Header.ValidDataLength.QuadPart;

					ExReleaseFastMutex( pFcb->Header.FastMutex );
					try_return( NTStatus = STATUS_SUCCESS );

				} else
				{

					//DebugTrace( 0, Dbg, ("PagingIo extending beyond EOF.\n") );

					ByteCount = pFcb->Header.FileSize.QuadPart - StartingOffset;
					ByteRange = pFcb->Header.FileSize.QuadPart;
				}
			}
			ExReleaseFastMutex( pFcb->Header.FastMutex );

			//
			//  If not paging I/O, then we must acquire a resource, and do some
			//  other initialization.
			//

		}else
		{
			if (!PagingIoResourceAcquired &&
				!ExAcquireSharedWaitForExclusive( pFcb->Header.Resource, Wait ))
			{
				PfpRaiseStatus( irpContext, STATUS_CANT_WAIT, NULL );
			}
			PagingIoResourceAcquired = TRUE;

			//
			//  Check if we have already gone through cleanup on this handle.
			//
			// how should i detect this condition
			if (FlagOn( Ccb->Flags, CCB_FLAG_CLEANUP )) 
			{
				PfpRaiseStatus( irpContext, STATUS_FILE_CLOSED, NULL );
			}

			//
			//  Now synchronize with the FsRtl Header
			//

			ExAcquireFastMutex( pFcb->Header.FastMutex );

			//
			//  Now see if we will change FileSize.  We have to do it now
			//  so that our reads are not nooped.
			//

			if ((ByteRange > pFcb->Header.ValidDataLength.QuadPart) || WriteToEof) 
			{

				//
				//  We expect this routine to be top level or, for the
				//  future, our caller is not already serialized.
				//

				ASSERT( irpContext->TopLevelIrpContext->FcbWithPagingExclusive == NULL );

				DoingIoAtEof = !FlagOn( pFcb->Header.Flags, FSRTL_FLAG_EOF_ADVANCE_ACTIVE ) ||
					PfpWaitForIoAtEof( &pFcb->Header, (PLARGE_INTEGER)&StartingOffset, (ULONG)ByteCount, &EofWaitBlock );

				//
				//  Set the Flag if we are changing FileSize or ValidDataLength,
				//  and save current values.
				//

				if (DoingIoAtEof) 
				{

					SetFlag( pFcb->Header.Flags, FSRTL_FLAG_EOF_ADVANCE_ACTIVE );

					//
					//  Store this in the IrpContext until commit or post
					//

					irpContext->FcbWithPagingExclusive = (PPfpFCB)pFcb;

					OldFileSize = pFcb->Header.FileSize.QuadPart;

					//
					//  Check for writing to end of File.  If we are, then we have to
					//  recalculate the byte range.
					//

					if (WriteToEof) 
					{

						StartingOffset = pFcb->Header.FileSize.QuadPart;
						ByteRange = StartingOffset + ByteCount;
					}
				}
			}

			ExReleaseFastMutex( pFcb->Header.FastMutex );

			//
			//  We cannot handle user noncached I/Os to compressed files, so we always
			//  divert them through the cache with write through.
			//
			//  The reason that we always handle the user requests through the cache,
			//  is that there is no other safe way to deal with alignment issues, for
			//  the frequent case where the user noncached I/O is not an integral of
			//  the Compression Unit.  We cannot, for example, read the rest of the
			//  compression unit into a scratch buffer, because we are not synchronized
			//  with anyone mapped to the file and modifying the other data.  If we
			//  try to assemble the data in the cache in the noncached path, to solve
			//  the above problem, then we have to somehow purge these pages away
			//  to solve cache coherency problems, but then the pages could be modified
			//  by a file mapper and that would be wrong, too.
			//
			//  Bottom line is we can only really support cached writes to compresed
			//  files.
			//	

			if (!Wait && NonCachedIo)
			{
				//
				//  Make sure we haven't exceeded our threshold for async requests
				//  on this thread.
				//

				if (ExIsResourceAcquiredSharedLite( pFcb->Header.Resource ) > 10) 
				{
					PfpRaiseStatus( irpContext, STATUS_CANT_WAIT, NULL );
				}

				irpContext->Union.NtfsIoContext->Wait.Async.Resource = pFcb->Header.Resource;
			}

			//
			//  Set the flag in our IrpContext to indicate that we have entered
			//  write.
			//

			ASSERT( !FlagOn( irpContext->TopLevelIrpContext->Flags,
				IRP_CONTEXT_FLAG_WRITE_SEEN ));

			SetFlag( irpContext->TopLevelIrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_SEEN );
			SetWriteSeen = TRUE;
		}
		//
		//  We assert that Paging Io writes will never WriteToEof.
		//
// 		if (FlagOn( pFcb->FcbState, FCB_STATE_FILE_DELETED ))
// 		{
// 			PfpRaiseStatus( irpContext, STATUS_FILE_DELETED, NULL);
// 		}

		ASSERT( !WriteToEof || !PagingIo );

		if (DoingIoAtEof)
		{

			//
			//  If this was a non-cached asynchronous operation we will
			//  convert it to synchronous.  This is to allow the valid
			//  data length change to go out to disk and to fix the
			//  problem of the Fcb being in the exclusive Fcb list.
			//

			if (!Wait && NonCachedIo) 
			{

				Wait = TRUE;
				SetFlag( irpContext->Flags, IRP_CONTEXT_FLAG_WAIT );

				RtlZeroMemory( irpContext->Union.NtfsIoContext, sizeof( NTFS_IO_CONTEXT ));

				//
				//  Store whether we allocated this context structure in the structure
				//  itself.
				//
				irpContext->Union.NtfsIoContext->OriginatingIrp		= Irp;
				irpContext->Union.NtfsIoContext->AllocatedContext	= BooleanFlagOn( irpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );

				KeInitializeEvent( &irpContext->Union.NtfsIoContext->Wait.SyncEvent,
									NotificationEvent,
									FALSE );

				//
				//  If this is async Io to a compressed stream
				//  then we will make this look synchronous.
				//

			} 

			if (!PagingIo) 
			{

				 NTStatus= FsRtlCheckOplock(	&pFcb->Oplock,
												Irp,
												irpContext,
												PfpOplockComplete,
												PfpPrePostIrp );

				if (NTStatus != STATUS_SUCCESS) 
				{

					OplockPostIrp = TRUE;
					PostIrp = TRUE;
					try_return( NOTHING );
				}

				//
				//  This oplock call can affect whether fast IO is possible.
				//  We may have broken an oplock to no oplock held.  If the
				//  current state of the file is FastIoIsNotPossible then
				//  recheck the fast IO state.
				//

				if (pFcb->Header.IsFastIoPossible == FastIoIsNotPossible) 
				{

					ExAcquireFastMutex(pFcb->Header.FastMutex);
					pFcb->Header.IsFastIoPossible = PfpIsFastIoPossible( pFcb );
					ExReleaseFastMutex( pFcb->Header.FastMutex );
				}

				//
				// We have to check for write access according to the current
				// state of the file locks, and set FileSize from the Fcb.
				//
				if(pFcb->FileLock != NULL) 
				{
					if (!FsRtlCheckLockForWriteAccess( pFcb->FileLock, Irp )) 
					{
						try_return( NTStatus = STATUS_FILE_LOCK_CONFLICT );
					}
				}
			}
			
		}


		if (ByteRange < StartingOffset) 
		{

			try_return( NTStatus = STATUS_INVALID_PARAMETER );
		}
		if (DoingIoAtEof)
		{

			//
			//  EXTENDING THE FILE
			//

			//
			//  If the write goes beyond the allocation size, add some
			//  file allocation.
			//

			if (ByteRange > pFcb->Header.AllocationSize.QuadPart)
			{
				//
				//  Note that we may have gotten all the space we need when
				//  we converted to nonresident above, so we have to check
				//  again if we are extending.
				//
				LARGE_INTEGER temp1;
				temp1.QuadPart = ByteRange+g_SectorSize-1;
				temp1.LowPart &=~((ULONG)g_SectorSize-1);

				ExAcquireFastMutex( pFcb->Header.FastMutex );

				pFcb->Header.AllocationSize.QuadPart =temp1.QuadPart;

			
				ExReleaseFastMutex( pFcb->Header.FastMutex );
				
			}

			//	
			//  Now synchronize with the FsRtl Header and set FileSize
			//  now so that our reads will not get truncated.
			//

			ExAcquireFastMutex( pFcb->Header.FastMutex );
			if (ByteRange > pFcb->Header.FileSize.QuadPart) 			
			{
				ASSERT( ByteRange <= pFcb->Header.AllocationSize.QuadPart );
				pFcb->Header.FileSize.QuadPart = ByteRange;
				SetFlag( pFileObject->Flags, FO_FILE_SIZE_CHANGED );
			}
			ExReleaseFastMutex( pFcb->Header.FastMutex  );


			//
			//  Extend the cache map, letting mm knows the new file size.
			//

			if (CcIsFileCached(pFileObject) && !PagingIo) 
			{
				CcSetFileSizes( pFileObject, (PCC_FILE_SIZES)&pFcb->Header.AllocationSize );
			} else 
			{
				CcFileSizeChangeDue = TRUE;
			}
		}


		//
		//  HANDLE THE NON-CACHED CASE
		//

		if (NonCachedIo)
		{
			ULONG BytesToWrite;

			//
			//  Round up to a sector boundry
			//

			BytesToWrite = ((ULONG)ByteCount + (g_SectorSize - 1))& ~(g_SectorSize - 1);

			//
			//  All requests should be well formed and
			//  make sure we don't wipe out any data
			//

			if ((((ULONG)StartingOffset) & (g_SectorSize - 1))
				|| ((BytesToWrite != (ULONG)ByteCount)
				&& ByteRange < pFcb->Header.ValidDataLength.QuadPart )) 
			{

					//**** we only reach this path via fast I/O and by returning not implemented we
					//**** force it to return to use via slow I/O

					//DebugTrace( 0, Dbg, ("NtfsCommonWrite -> STATUS_NOT_IMPLEMENTED\n") );

					try_return( NTStatus = STATUS_NOT_IMPLEMENTED );
			}

			//
			// If this noncached transfer is at least one sector beyond
			// the current ValidDataLength in the Scb, then we have to
			// zero the sectors in between.  This can happen if the user
			// has opened the file noncached, or if the user has mapped
			// the file and modified a page beyond ValidDataLength.  It
			// *cannot* happen if the user opened the file cached, because
			// ValidDataLength in the Fcb is updated when he does the cached
			// write (we also zero data in the cache at that time), and
			// therefore, we will bypass this action when the data
			// is ultimately written through (by the Lazy Writer).
			//
			//  For the paging file we don't care about security (ie.
			//  stale data), do don't bother zeroing.
			//
			//  We can actually get writes wholly beyond valid data length
			//  from the LazyWriter because of paging Io decoupling.
			//
			//  We drop this zeroing on the floor in any case where this
			//  request is a recursive write caused by a flush from a higher level write.
			//

			if (!CalledByLazyWriter &&
				!RecursiveWriteThrough &&
				(StartingOffset > pFcb->Header.ValidDataLength.QuadPart))
			{
					
					if(!pFcb->bNeedEncrypt)
					{
						if (!PfpZeroData( irpContext,
											pFcb,
											pFileObject,
											pFcb->Header.ValidDataLength.QuadPart,
											StartingOffset - pFcb->Header.ValidDataLength.QuadPart )) 
						{

								//
								//  The zeroing didn't complete but we might have moved
								//  valid data length up and committed.  We don't want
								//  to set the file size below this value.
								//

								ExAcquireFastMutex( pFcb->Header.FastMutex );
								if (OldFileSize < pFcb->Header.ValidDataLength.QuadPart) 
								{
									OldFileSize = pFcb->Header.ValidDataLength.QuadPart;
								}
								ExReleaseFastMutex( pFcb->Header.FastMutex );
								PfpRaiseStatus( irpContext, STATUS_CANT_WAIT, NULL );
						}
					}else
					{
// 						PDISKFILEOBJECT pDiskfileObject = NULL;
// 						LARGE_INTEGER   Offset;
// 						//IO_STATUS_BLOCK	iostatus;
// 						LONGLONG		ByteOffset1 = (pFcb->Header.ValidDataLength.QuadPart+(g_SectorSize - 1))&~(g_SectorSize - 1);
// 						LONGLONG		ByteCount1  = StartingOffset-ByteOffset1;
// 						PVOID			pTempBuffer = NULL;
// 						KEVENT			SyncEvent;
// 						ASSERT(ByteCount1  != 0);
// 						KeInitializeEvent(&SyncEvent,NotificationEvent,FALSE);
// 						if(ByteCount1!=0)
// 						{
// 							pTempBuffer  = ExAllocatePool_A(NonPagedPool,(ULONG)ByteCount1);
// 							ASSERT(pTempBuffer  );
// 							
// 							RtlZeroMemory(pTempBuffer,(ULONG)ByteCount1);
// 							// 这里做加密
// 							pDiskfileObject = CONTAINING_RECORD(pFcb,DISKFILEOBJECT,pFCB);
// 							Offset.QuadPart = ByteOffset1+ENCRYPTIONHEADLENGTH;
// 							ASSERT(0);
// 							ExFreePool(pTempBuffer);
// 							pTempBuffer = NULL;
// 						}
					}

					//
					//  Data was zeroed up to the StartingVbo.  Update our old file
					//  size to that point.
					//

					OldFileSize = StartingOffset;
			}


			{
				// this function will create a irp and send it to low driver 
				if(!((irpContext->Flags&IRP_CONTEXT_FLAG_WAIT)?TRUE:FALSE) && !PagingIoResourceAcquired )
				{						
					irpContext->Union.NtfsIoContext->Wait.Async.Resource = NULL;
				}

				irpContext->Union.NtfsIoContext->Wait.Async.StartingOffset = StartingOffset;
				if(!pFcb->bNeedEncrypt)
				{
					__try
					{	
						NTStatus = PfpNonCachedIoWrite( irpContext,
											Irp,
											pFcb,
											StartingOffset,
											BytesToWrite
											);
					}
					__except (PfpExceptionFilter ( irpContext, GetExceptionInformation()))
					{
						KdPrint(  ("NtfsCommonWrite -> %08lx\n", NTStatus) );
					}
				}
				else
				{
					PVOID	pSyncBufferEncrypt	= NULL;
					PVOID	pUserBuffer			= NULL;	
					PVOID	pAsyncBufferEncrypt = NULL;
					CHAR    szdebug[90]			= {0};
					BOOLEAN	bWait				= (irpContext->Flags&IRP_CONTEXT_FLAG_WAIT)?TRUE:FALSE;

					
					if(!pFcb->bWriteHead)
					{
						PVOID pEncryptHead ;
						pEncryptHead = PfpCreateEncryptHead(pFcb);

						if(pEncryptHead )
						{
							
							PfpWriteHeadForEncryption(	pEncryptHead,
														ENCRYPTIONHEADLENGTH,
														pFcb->pDiskFileObject->pDiskFileObjectWriteThrough,
														irpContext->pNextDevice
														);
							ExFreePool(pEncryptHead);
							pFcb->bWriteHead = TRUE;
						}
					}

					if( !bWait && pFcb->pDiskFileObject->bNeedBackUp)
					{
						pAsyncBufferEncrypt = ExAllocatePoolWithTag(NonPagedPool,BytesToWrite,'W001');
						if(pAsyncBufferEncrypt == NULL)
						{
							try_return( NTStatus = STATUS_INSUFFICIENT_RESOURCES );
						}
					}

					pSyncBufferEncrypt  = ExAllocatePoolWithTag(NonPagedPool,BytesToWrite,'W101');
					if(pSyncBufferEncrypt == NULL)
					{
						if(pAsyncBufferEncrypt)
						{
							ExFreePool(pAsyncBufferEncrypt);
							pAsyncBufferEncrypt= NULL;
						}
						try_return( NTStatus = STATUS_INSUFFICIENT_RESOURCES );
					}
				
					if(pUserBuffer= PfpMapUserBuffer(Irp))
					{
						RtlCopyMemory(pSyncBufferEncrypt,pUserBuffer,BytesToWrite);

						if(pAsyncBufferEncrypt)
						{
							RtlCopyMemory(pAsyncBufferEncrypt,pUserBuffer,BytesToWrite);
						}
					}else
					{//内存 不够用了！这里就删除 以前分配的内存 ，然后返回对应的错误
						if(pSyncBufferEncrypt != NULL||pAsyncBufferEncrypt!= NULL)
						{
							if(pAsyncBufferEncrypt)
							{
								ExFreePool(pAsyncBufferEncrypt);
								pAsyncBufferEncrypt= NULL;
							}	
							if(pSyncBufferEncrypt)
							{
								ExFreePool(pSyncBufferEncrypt);
								pSyncBufferEncrypt= NULL;
							}		
							
							try_return( NTStatus = STATUS_INSUFFICIENT_RESOURCES );
						}
					}
					//这里做加密
					
					memcpy(szdebug,pSyncBufferEncrypt,88);
					StartingOffset +=ENCRYPTIONHEADLENGTH;				
				
					//KdPrint (("in write %wZ offset %u size %u\n",&pFcb->pDiskFileObject->FullFilePath,(ULONG)StartingOffset,BytesToWrite));
					if(!bWait && !PagingIoResourceAcquired )
					{						
						irpContext->Union.NtfsIoContext->Wait.Async.Resource = NULL;
					}
					__try
					{
						NTStatus =PfpNonCachedIoWriteEncrypt(   irpContext,
							Irp,
							pFcb,
							StartingOffset,
							BytesToWrite,
							pSyncBufferEncrypt);

					}
					__except (PfpExceptionFilter ( irpContext, GetExceptionInformation()))
					{
						KdPrint(  ("NtfsCommonWrite -> %08lx\n", NTStatus) );
					}
					
					if(NTStatus== STATUS_SUCCESS ||NTStatus== STATUS_PENDING)
					{
						if(bWait)
						{
							if(pFcb->pDiskFileObject->bNeedBackUp)
							{	
								if(pFcb->pDiskFileObject->hBackUpFileObject!= NULL)
								{
									HANDLE			hFile;
									NTSTATUS		 ntstatus;
									IO_STATUS_BLOCK iostatus;
									ntstatus = ObOpenObjectByPointer(pFcb->pDiskFileObject->hBackUpFileObject,
																	OBJ_KERNEL_HANDLE ,
																	NULL,
																	GENERIC_WRITE,
																	*IoFileObjectType,
																	KernelMode,
																	&hFile );
									if(NT_SUCCESS(ntstatus))
									{
										LARGE_INTEGER offset;
										offset.QuadPart = StartingOffset;
										ntstatus = ZwWriteFile(hFile,NULL,NULL,NULL,&iostatus,pSyncBufferEncrypt,BytesToWrite,&offset,NULL);
										ZwClose(hFile);
									}
								}
							} 
							 
						}else
						{
							if(pFcb->pDiskFileObject->bNeedBackUp && pAsyncBufferEncrypt)
							{	
								if(pFcb->pDiskFileObject->hBackUpFileObject!= NULL)
								{
									HANDLE			hFile;
									NTSTATUS		ntstatus;
									IO_STATUS_BLOCK iostatus;
									ntstatus = ObOpenObjectByPointer(pFcb->pDiskFileObject->hBackUpFileObject,
																	OBJ_KERNEL_HANDLE ,
																	NULL,
																	GENERIC_WRITE,
																	*IoFileObjectType,
																	KernelMode,
																	&hFile );
									if(NT_SUCCESS(ntstatus))
									{
										LARGE_INTEGER offset;
										offset.QuadPart = StartingOffset;
										ntstatus = ZwWriteFile(hFile,NULL,NULL,NULL,&iostatus,pAsyncBufferEncrypt,BytesToWrite,&offset,NULL);
										ZwClose(hFile);
									}
								}
							} 
						}
					} 
					 
					if(bWait)
					{
						if(pSyncBufferEncrypt)ExFreePool(pSyncBufferEncrypt);
					}
					else
					{
						if(pAsyncBufferEncrypt)
						{
							ExFreePool(pAsyncBufferEncrypt);
						}
						 
					}					
				}

				if ( !(irpContext->Flags&IRP_CONTEXT_FLAG_WAIT ) )
				{
					irpContext->Union.NtfsIoContext = NULL;
					PagingIoResourceAcquired		= FALSE;
					Irp								= NULL;

					try_return( NTStatus );
				}
			}
			//
			//  If the call didn't succeed, raise the error status
			//

			if (!NT_SUCCESS( NTStatus = Irp->IoStatus.Status ))
			{
				// here, there may be so many error code , so we should explain it and choose some reseanable to return .
				PfpNormalizeAndRaiseStatus( irpContext, NTStatus, STATUS_UNEXPECTED_IO_ERROR );

			} else
			{

				//
				//  Else set the context block to reflect the entire write
				//  Also assert we got how many bytes we asked for.
				//

				ASSERT( Irp->IoStatus.Information == BytesToWrite );

				Irp->IoStatus.Information = (ULONG)ByteCount;
			}

			//
			// The transfer is either complete, or the Iosb contains the
			// appropriate status.
			//

			try_return( NTStatus );

		} // if No Intermediate Buffering
		ASSERT( !PagingIo );

		//
		// We delay setting up the file cache until now, in case the
		// caller never does any I/O to the file, and thus
		// FileObject->PrivateCacheMap == NULL.
		//

		if (pFileObject->PrivateCacheMap == NULL) 
		{

			//DebugTrace( 0, Dbg, ("Initialize cache mapping.\n") );

			//
			//  Get the file allocation size, and if it is less than
			//  the file size, raise file corrupt error.
			//

			if (pFcb->Header.FileSize.QuadPart > pFcb->Header.AllocationSize.QuadPart) 
			{

				PfpRaiseStatus( irpContext, STATUS_FILE_CORRUPT_ERROR,  pFcb );
			}

			//
			//  Now initialize the cache map.  Notice that we may extending
			//  the ValidDataLength with this write call.  At this point
			//  we haven't updated the ValidDataLength in the Scb header.
			//  This way we will get a call from the cache manager
			//  when the lazy writer writes out the data.
			//

			//
			//  Make sure we are serialized with the FileSizes, and
			//  will remove this condition if we abort.
			//

			if (!DoingIoAtEof) 
			{
				FsRtlLockFsRtlHeader( &pFcb->Header);
				irpContext->FcbWithPagingExclusive = (PPfpFCB)pFcb;
			}

			CcInitializeCacheMap(   pFileObject,
									(PCC_FILE_SIZES)&pFcb->Header.AllocationSize,
									FALSE,
									&CacheManagerCallbacks,
									pFcb );

			if (CcFileSizeChangeDue) 
			{
				CcSetFileSizes( pFileObject, (PCC_FILE_SIZES)&pFcb->Header.AllocationSize );
			}

			if (!DoingIoAtEof) 
			{
				FsRtlUnlockFsRtlHeader( &pFcb->Header);
				irpContext->FcbWithPagingExclusive = NULL;
			}

			CcSetReadAheadGranularity( pFileObject, READ_AHEAD_GRANULARITY );
		}

		//
		// If this write is beyond valid data length, then we
		// must zero the data in between.
		//

		
		LlTemp1 = StartingOffset - pFcb->Header.ValidDataLength.QuadPart;

		if (LlTemp1 > 0) 
		{

			//
			//  If the caller is writing zeros way beyond ValidDataLength,
			//  then noop it.
			//
		
			if (LlTemp1 > PAGE_SIZE &&
				ByteCount <= sizeof(LARGE_INTEGER) &&
				(RtlEqualMemory( PfpMapUserBuffer( Irp ),
				&Li0,
				(ULONG)ByteCount ) )) 
			{

					ByteRange = pFcb->Header.ValidDataLength.QuadPart;
					Irp->IoStatus.Information = (ULONG)ByteCount;
					try_return( NTStatus = STATUS_SUCCESS );
			}

			//
			// Call the Cache Manager to zero the data.
			//

			if (!PfpZeroData(  irpContext,
								pFcb,
								pFileObject,
								pFcb->Header.ValidDataLength.QuadPart,
								LlTemp1 ))
			{

					//
					//  The zeroing didn't complete but we might have moved
					//  valid data length up and committed.  We don't want
					//  to set the file size below this value.
					//

					ExAcquireFastMutex( pFcb->Header.FastMutex );
					if (OldFileSize < pFcb->Header.ValidDataLength.QuadPart) 
					{

						OldFileSize = pFcb->Header.ValidDataLength.QuadPart;
					}
					ExReleaseFastMutex( pFcb->Header.FastMutex );
					PfpRaiseStatus( irpContext, STATUS_CANT_WAIT, NULL);
			}

			//
			//  Data was zeroed up to the StartingVbo.  Update our old file
			//  size to that point.
			//

			OldFileSize = StartingOffset;
		}

		//
		//  We need to go through the cache for this
		//  file object.  First handle the noncompressed calls.
		//


		//
		// DO A NORMAL CACHED WRITE, if the MDL bit is not set,
		//

		if (!FlagOn(irpContext->MinorFunction, IRP_MN_MDL)) 
		{

			//DebugTrace( 0, Dbg, ("Cached write.\n") );

			//
			//  Get hold of the user's buffer.
			//

			SystemBuffer = PfpMapUserBuffer( Irp );

			//
			// Do the write, possibly writing through
			//
		//	KdPrint (("in write cache %wZ offset %u size %u\n",&pFcb->pDiskFileObject->FullFilePath,(ULONG)StartingOffset,ByteCount));
			if (!CcCopyWrite( pFileObject,
							(PLARGE_INTEGER)&StartingOffset,
							(ULONG)ByteCount,
							BooleanFlagOn(irpContext->Flags, IRP_CONTEXT_FLAG_WAIT),
							SystemBuffer ))
			{	
				PfpRaiseStatus( irpContext, STATUS_CANT_WAIT, NULL );

			} else if (!NT_SUCCESS( irpContext->ExceptionStatus ))
			{
				PfpRaiseStatus( irpContext, irpContext->ExceptionStatus, NULL );
			}

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = (ULONG)ByteCount;

			try_return( NTStatus = STATUS_SUCCESS );

		} else 
		{

			//
			//  DO AN MDL WRITE
			//

			//DebugTrace( 0, Dbg, ("MDL write.\n") );

			ASSERT( FlagOn(irpContext->Flags, IRP_CONTEXT_FLAG_WAIT) );

			//
			//  If we got this far and then hit a log file full the Mdl will
			//  already be present.
			//

			ASSERT(Irp->MdlAddress == NULL);
			//KdPrint (("in write cache %wZ offset %u size %u\n",&pFcb->pDiskFileObject->FullFilePath,(ULONG)StartingOffset,ByteCount));
			CcPrepareMdlWrite( pFileObject,
								(PLARGE_INTEGER)&StartingOffset,
								(ULONG)ByteCount,
								&Irp->MdlAddress,
								&Irp->IoStatus );

			NTStatus = Irp->IoStatus.Status;

			ASSERT( NT_SUCCESS( NTStatus ));

			try_return( NTStatus );
		}

try_exit: NOTHING;

		if (Irp)
		{

			if (PostIrp) 
			{

				//
				//  If we acquired this Scb exclusive, we won't need to release
				//  the Scb.  That is done in the oplock post request.
				//

				if (OplockPostIrp) 
				{

					ScbAcquired = FALSE;
				}

				//
				//  If we didn't post the Irp, we may have written some bytes to the
				//  file.  We report the number of bytes written and update the
				//  file object for synchronous writes.
				//

			} else 
			{

				//DebugTrace( 0, Dbg, ("Completing request with status = %08lx\n", Status) );

				//DebugTrace( 0, Dbg, ("                   Information = %08lx\n",
					//Irp->IoStatus.Information));

				//
				//  Record the total number of bytes actually written
				//

				LlTemp1 = Irp->IoStatus.Information;

				//
				//  If the file was opened for Synchronous IO, update the current
				//  file position.
				//

				if (SynchronousIo && !PagingIo) 
				{

					pFileObject->CurrentByteOffset.QuadPart = StartingOffset + LlTemp1;
				}

				//
				//  The following are things we only do if we were successful
				//

				if (NT_SUCCESS( NTStatus))
				{

					//
					//  Mark that the modify time needs to be updated on close.
					//  Note that only the top level User requests will generate
					//  correct

					if (!PagingIo) 
					{

						//
						//  Set the flag in the file object to know we modified this file.
						//

						SetFlag( pFileObject->Flags, FO_FILE_MODIFIED );

						//
						//  On successful paging I/O to a compressed data stream which is
						//  not mapped, we free any reserved space for the stream.
						//

					} 

					//
					//  If we extended the file size and we are meant to
					//  immediately update the dirent, do so. (This flag is
					//  set for either WriteThrough or noncached, because
					//  in either case the data and any necessary zeros are
					//  actually written to the file.)  Note that a flush of
					//  a user-mapped file could cause VDL to get updated the
					//  first time because we never had a cached write, so we
					//  have to be sure to update VDL here in that case as well.
					//

					if (DoingIoAtEof) 
					{
						BOOLEAN	bWriteHead = FALSE;

						ExAcquireFastMutex( pFcb->Header.FastMutex );
							
						//
						//  Now is the time to update valid data length.
						//  The Eof condition will be freed when we commit.
						//

						if (ByteRange > pFcb->Header.ValidDataLength.QuadPart) 
						{
							pFcb->Header.ValidDataLength.QuadPart = ByteRange;
							SetFlag( pFileObject->Flags, FO_FILE_SIZE_CHANGED );
							bWriteHead = TRUE;
						}
						DoingIoAtEof = FALSE;
						ExReleaseFastMutex( pFcb->Header.FastMutex );
						//当文件的大小或者vlidatedatalength 发生变化的时候要写入文件保证文件的一致性
						if(bWriteHead && pFcb->bNeedEncrypt)
						{
							PVOID pEncryptHead ;
							pEncryptHead = PfpCreateEncryptHead(pFcb);

							if(pEncryptHead )
							{

								PfpWriteHeadForEncryption(	pEncryptHead,
															ENCRYPTIONHEADLENGTH,
															pFcb->pDiskFileObject->pDiskFileObjectWriteThrough,
															irpContext->pNextDevice
															);
								ExFreePool(pEncryptHead);
								pFcb->bWriteHead = TRUE;
							}
						}
					}
				}

			}
		}


	}
	__finally
	{
		//DebugUnwind( NtfsCommonWrite );


		//
		//  Now is the time to restore FileSize on errors.
		//  The Eof condition will be freed when we commit.
		//

		if (DoingIoAtEof)
		{

			//
			//  Acquire the main resource to knock valid data to disk back.
			//

			ExAcquireFastMutex( pFcb->Header.FastMutex );
			pFcb->Header.FileSize.QuadPart = OldFileSize;

			if (pFileObject->SectionObjectPointer->SharedCacheMap != NULL) 
			{

				CcGetFileSizePointer(pFileObject)->QuadPart = OldFileSize;
			}
			ExReleaseFastMutex( pFcb->Header.FastMutex );
		}

		//
		//  If the Scb or PagingIo resource has been acquired, release it.
		//

		if (PagingIoResourceAcquired) 
		{
			ExReleaseResourceLite( pFcb->Header.Resource );
		}

		if (Irp) 
		{

			/*if (ScbAcquired) 
			{
				NtfsReleaseScb( irpContext, Scb );
			}*/

			//
			//  Now remember to clear the WriteSeen flag if we set it. We only
			//  do this if there is still an Irp.  It is possible for the current
			//  Irp to be posted or asynchronous.  In that case this is a top
			//  level request and the cleanup happens elsewhere.  For synchronous
			//  recursive cases the Irp will still be here.
			//

			if (SetWriteSeen) 
			{
				ClearFlag(irpContext->TopLevelIrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_SEEN);
			}
		}

		//
		//  Complete the request if we didn't post it and no exception
		//
		//  Note that FatCompleteRequest does the right thing if either
		//  IrpContext or Irp are NULL
		//

		if (!AbnormalTermination())
		{

			if (!PostIrp) 
			{

				PfpCompleteRequest(&irpContext,
									Irp ? &Irp : NULL,
									NTStatus);

			} else if (!OplockPostIrp) 
			{

				NTStatus = PfpPostRequest( irpContext, Irp );
			}
		}else
		{
			KdPrint(  ("NtfsCommonWrite -> %08lx\n", NTStatus) );
		}

		//DebugTrace( -1, Dbg, ("NtfsCommonWrite -> %08lx\n", NTStatus) );

	}
	return NTStatus;
}



NTSTATUS
PfpNonCachedIoWrite( 
			   IN PIRP_CONTEXT  pIrpContext,
			   IN PIRP Irp,
			   IN PPfpFCB pFcb,
			   IN LONGLONG StartingOffset,
			   IN LONG BytesToWrite
			   )
/*
this function will  use disk fileobject to call ntfs to get data from disk.

*/
{
	// create irp
	// check if the above can wait , if so just wait for low driver to complete irp,
	// else set the event ,s
	PDEVICE_OBJECT		pNextDevice;
	PIRP				pIrp;
	PIRP				pPreIrp;
	NTSTATUS			ntStatus;
	PIO_STACK_LOCATION	pIoStack;
	PIO_STACK_LOCATION	pIoPreStack;
	PFILE_OBJECT		pFileobejct_onDISK;
	BOOLEAN				Wait = (pIrpContext->Flags&IRP_CONTEXT_FLAG_WAIT)?TRUE:FALSE;
	
	UNREFERENCED_PARAMETER(pFcb);

	pPreIrp				= Irp;
	pIoPreStack			= IoGetCurrentIrpStackLocation( pPreIrp );


	pNextDevice			= pIrpContext->pNextDevice;	
	pFileobejct_onDISK	= pIrpContext->Fileobject_onDisk;
	
	if ( pNextDevice == NULL || pFileobejct_onDISK  == NULL)
		return STATUS_INVALID_PARAMETER;

	pIrp = IoAllocateIrp(pNextDevice->StackSize,FALSE);

	if( pIrp  == NULL )
		return STATUS_INSUFFICIENT_RESOURCES;
	
	pIrp->AssociatedIrp.SystemBuffer		= pPreIrp->AssociatedIrp.SystemBuffer;
	pIrp->MdlAddress						= pPreIrp->MdlAddress;
	pIrp->UserBuffer						= pPreIrp->UserBuffer;
	pIrp->Flags								= IRP_WRITE_OPERATION| IRP_NOCACHE|(Wait?IRP_SYNCHRONOUS_API:0);
	pIrp->UserEvent							= NULL;//&pIrpContext->Union.NtfsIoContext->Wait.SyncEvent;
	pIrp->RequestorMode						= KernelMode;
	pIrp->Tail.Overlay.Thread				= NULL;//(PETHREAD) PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject	= pFileobejct_onDISK;
	
	
	pIoStack  = IoGetNextIrpStackLocation(pIrp);

	pIoStack->MajorFunction							= IRP_MJ_WRITE;
	pIoStack->MinorFunction							= IRP_MN_NORMAL;
	pIoStack->DeviceObject							= pNextDevice;
	pIoStack->FileObject							= pFileobejct_onDISK;
	pIoStack->Parameters.Write.ByteOffset.QuadPart	= StartingOffset;
	pIoStack->Parameters.Write.Length				= BytesToWrite;

	ntStatus = IoSetCompletionRoutineEx(pNextDevice,
										pIrp,
										Wait?PfpNonCachedSyncIoCompleteWrite:PfpNonCachedAsyncIoCompleteWrite,
										pIrpContext->Union.NtfsIoContext,
										TRUE,
										TRUE,
										TRUE);

	if(!NT_SUCCESS(ntStatus))
	{
		IoFreeIrp(pIrp);
		pIrp = NULL;
		return ntStatus;
	}
	
	 
	if(!Wait )
	{
		IoMarkIrpPending(pPreIrp);
	}
	 
	ntStatus = IoCallDriver(pNextDevice,pIrp);

	if(Wait)
	{
		if( (ntStatus  == STATUS_PENDING ) ||NT_SUCCESS(ntStatus))
		{
			KeWaitForSingleObject(  &pIrpContext->Union.NtfsIoContext->Wait.SyncEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);
			ASSERT(BytesToWrite == pIrpContext->OriginatingIrp->IoStatus.Information );

		 
			ntStatus = STATUS_SUCCESS;
		}
		
	}else
	{
		ntStatus = STATUS_PENDING;
	}

	
	
	return ntStatus  ;
}	

NTSTATUS
PfpNonCachedIoWriteEncrypt( 
					IN PIRP_CONTEXT		pIrpContext,
					IN PIRP				Irp,
					IN PPfpFCB			pFcb,
					IN LONGLONG			StartingOffset,
					IN LONG				BytesToWrite,
					IN PVOID  			pSystemBuffer
					)
					/*
					this function will  use disk fileobject to call ntfs to get data from disk.

					*/
{
	PDEVICE_OBJECT		pNextDevice;
	PIRP				pIrp;
	NTSTATUS			ntStatus;
	PIO_STACK_LOCATION	pIoStack;
	PFILE_OBJECT		pFileobejct_onDISK;
	PMDL				pNewMdl;
	BOOLEAN				bWait = (pIrpContext->Flags&IRP_CONTEXT_FLAG_WAIT)?TRUE:FALSE;
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(pFcb);
	
	pNextDevice			= pIrpContext->pNextDevice;	
	pFileobejct_onDISK	= pIrpContext->Fileobject_onDisk;

	if ( pNextDevice == NULL || pFileobejct_onDISK  == NULL)
	{
		ExFreePool(pSystemBuffer);
		return STATUS_INVALID_PARAMETER;
	}

	pIrp = IoAllocateIrp(pNextDevice->StackSize,FALSE);

	if( pIrp  == NULL )
	{
		ExFreePool(pSystemBuffer);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//do encrypt
	{
		PfpEncryptBuffer(pSystemBuffer,BytesToWrite,&ase_en_context);
	}
	pNewMdl  = IoAllocateMdl(pSystemBuffer, BytesToWrite, FALSE, TRUE, NULL);
	MmBuildMdlForNonPagedPool(pNewMdl);
	
	pIrp->AssociatedIrp.SystemBuffer		= pSystemBuffer;
	pIrp->MdlAddress						= pNewMdl;
	 pIrp->UserBuffer						= MmGetMdlVirtualAddress(pNewMdl);
	pIrp->Flags								=  IRP_WRITE_OPERATION |IRP_NOCACHE|(bWait?IRP_SYNCHRONOUS_API:0);


	pIrp->UserEvent							= NULL;//Irp->UserEvent;//NULL;//&pIrpContext->Union.NtfsIoContext->Wait.SyncEvent;
	pIrp->RequestorMode						= KernelMode ;//;
 	pIrp->Tail.Overlay.Thread				= NULL;//Irp->Tail.Overlay.Thread;//NULL;//(PETHREAD) PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject	= NULL;//pFileobejct_onDISK;
  	pIrp->Tail.Overlay.AuxiliaryBuffer		= NULL;//Irp->Tail.Overlay.AuxiliaryBuffer;

	pIoStack  = IoGetNextIrpStackLocation(pIrp);

	pIoStack->MajorFunction							= IRP_MJ_WRITE;
	pIoStack->MinorFunction							= IRP_MN_NORMAL;
	pIoStack->DeviceObject							= pNextDevice;
	pIoStack->FileObject							= pFileobejct_onDISK;
	pIoStack->Parameters.Write.ByteOffset.QuadPart	= StartingOffset;
	pIoStack->Parameters.Write.Length				= BytesToWrite;

	pIrpContext->Union.NtfsIoContext->bNeedEncrypt  = TRUE;
	ntStatus = IoSetCompletionRoutineEx(pNextDevice,
											pIrp,
											bWait?PfpNonCachedSyncIoCompleteWrite:PfpNonCachedAsyncIoCompleteWrite,
											pIrpContext->Union.NtfsIoContext,
											TRUE,
											TRUE,
											TRUE);

	if(!NT_SUCCESS(ntStatus))
	{
		IoFreeMdl(pNewMdl);		
		IoFreeIrp(pIrp);
		pIrp = NULL;	 
		return ntStatus;
	}

 
	if(!bWait )
	{
		IoMarkIrpPending(Irp);
	}
 
	ntStatus = IoCallDriver(pNextDevice,pIrp);

	if(bWait)
	{
		if( (ntStatus  == STATUS_PENDING ) ||NT_SUCCESS(ntStatus))
		{
			KeWaitForSingleObject(  &pIrpContext->Union.NtfsIoContext->Wait.SyncEvent,
									Executive,
									KernelMode,
									FALSE,
									NULL);
			ASSERT(BytesToWrite == pIrpContext->OriginatingIrp->IoStatus.Information );
			
			 
			ntStatus = STATUS_SUCCESS;
		} 
	}else
	{
		ntStatus = STATUS_PENDING;
	}
 
	return ntStatus  ; 
}	




NTSTATUS
PfpNonCachedSyncIoCompleteWrite(
								IN PDEVICE_OBJECT  DeviceObject,
								IN PIRP  Irp,
								IN PVOID  Context
								)
{
	PNTFS_IO_CONTEXT    pNtfsIoContext;

	UNREFERENCED_PARAMETER(DeviceObject);

	pNtfsIoContext  = (PNTFS_IO_CONTEXT)Context;	

	pNtfsIoContext ->OriginatingIrp->IoStatus = Irp->IoStatus;
	
	KeSetEvent(&pNtfsIoContext ->Wait.SyncEvent,0,FALSE);

	if(pNtfsIoContext->bNeedEncrypt)
	{	
		IoFreeMdl(Irp->MdlAddress);
	} 
	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}



NTSTATUS
PfpNonCachedAsyncIoCompleteWrite(
								 IN PDEVICE_OBJECT  DeviceObject,
								 IN PIRP  Irp,
								 IN PVOID  Context
								 )
{

	PNTFS_IO_CONTEXT    pNtfsIoContext;
	PIRP				pOrignalIrp;
	PFILE_OBJECT		pUserFileObject;
	LONGLONG			ByteRange;
	PPfpFCB				pFcb;
	BOOLEAN				PagingIO;
	PERESOURCE			pResource;
	ERESOURCE_THREAD	ResourceThreadId;
	
	UNREFERENCED_PARAMETER(DeviceObject);

	pNtfsIoContext			= (PNTFS_IO_CONTEXT)Context;
	pOrignalIrp				= pNtfsIoContext->OriginatingIrp;
	ResourceThreadId		= pNtfsIoContext->Wait.Async.ResourceThreadId;
	pResource				= pNtfsIoContext->Wait.Async.Resource;
	pUserFileObject			= IoGetCurrentIrpStackLocation(pOrignalIrp)->FileObject;
	pFcb					= (PPfpFCB)pUserFileObject->FsContext;
	PagingIO				= pNtfsIoContext->PagingIo;

	pOrignalIrp->IoStatus	= Irp->IoStatus;
	ByteRange				= pNtfsIoContext->Wait.Async.RequestedByteCount+pNtfsIoContext->Wait.Async.StartingOffset;


	if( NT_SUCCESS(Irp->IoStatus.Status) )
	{
		ExAcquireFastMutex( pFcb->Header.FastMutex );

		if( ByteRange > pFcb->Header.ValidDataLength.QuadPart )
		{				
			pFcb->Header.ValidDataLength.QuadPart = ByteRange;				
		}

		ExReleaseFastMutex(pFcb->Header.FastMutex );

		if(!PagingIO)
		{
			SetFlag( pUserFileObject->Flags, FO_FILE_MODIFIED );
		}

		pOrignalIrp->IoStatus.Information = pNtfsIoContext->Wait.Async.RequestedByteCount;
		ASSERT(pNtfsIoContext->Wait.Async.RequestedByteCount ==Irp->IoStatus.Information );
	}	

	if( pResource )
	{
		ExReleaseResourceForThreadLite(pResource,ResourceThreadId);	
	}

	
	if(pNtfsIoContext->bNeedEncrypt)
	{	

		ExFreePool(MmGetSystemAddressForMdlSafe(Irp->MdlAddress,NormalPagePriority ));
		IoFreeMdl(Irp->MdlAddress);
		
	}
	ExFreeToNPagedLookasideList( &NtfsIoContextLookasideList, Context );


	if(pOrignalIrp->PendingReturned)
	{
		IoMarkIrpPending(pOrignalIrp);
	}
	IoCompleteRequest(pOrignalIrp,IO_DISK_INCREMENT);
	


	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

