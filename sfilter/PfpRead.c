#include "Aes.h"
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
//#include "filespy.h"
#include "fspyKern.h"



NTSTATUS
PfpRead (
		 __in PDEVICE_OBJECT DeviceObject,
		 __in PIRP Irp
		 )
{
	PIO_STACK_LOCATION 			pstack ;
	PFILE_OBJECT				pFileObject ;
	PFILESPY_DEVICE_EXTENSION	pExt  ;
	PDEVICE_OBJECT				pNextDriver;
	PDISKFILEOBJECT				pDiskFileObject = NULL;
	FILEOBJECTTYPE				typeOfFileobject;
	NTSTATUS					ntstatus	;
	PIRP_CONTEXT				Irp_Context ;
	TOP_LEVEL_CONTEXT			TopLevelContext;
	PTOP_LEVEL_CONTEXT			ThreadTopLevelContext;
	PPfpFCB						pFcb =  NULL;
	
	ntstatus			= STATUS_SUCCESS;

	pExt				= DeviceObject->DeviceExtension;
	pNextDriver			= pExt->NLExtHeader.AttachedToDeviceObject;

	FsRtlEnterFileSystem();

	if( pExt->bShadow )
	{
		pNextDriver = ((PFILESPY_DEVICE_EXTENSION)(pExt->pRealDevice->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
		goto PASSTHROUGH;
	}
	
	pstack		= IoGetCurrentIrpStackLocation(Irp);
	pFileObject = pstack->FileObject;
		

	if(pFileObject == NULL)
	{
		goto PASSTHROUGH;
	}
	
	
	
// 	pDeviceResource = PfpGetDeviceResource((PDEVICE_OBJECT)DeviceObject);
// 
// 	if(pDeviceResource== NULL)
// 	{
// 		ASSERT(0);
// 		goto PASSTHROUGH;
// 	}
// 
// 	ExAcquireResourceSharedLite(pDeviceResource,TRUE);

	if(!PfpFileObjectHasOurFCB(pFileObject))
		goto PASSTHROUGH;
	
	pFcb = (PPfpFCB)pFileObject->FsContext;	
	
	ASSERT(!pFcb->bModifiedByOther);
	
	


	ASSERT(pFcb->pDiskFileObject);
	pDiskFileObject = pFcb->pDiskFileObject;
	
	if( pDiskFileObject== NULL || pDiskFileObject->pDiskFileObjectWriteThrough== NULL)
	{
		Irp->IoStatus.Information	= 0;
		ntstatus =	Irp->IoStatus.Status		= STATUS_FILE_CLOSED;

		IoCompleteRequest(Irp,IO_DISK_INCREMENT);
		goto RETURNED;
	}

	typeOfFileobject =FILEOBJECT_FROM_USERMODE;
	switch(typeOfFileobject)
	{
	case FILEOBJECT_FROM_USERMODE:
		{
			ThreadTopLevelContext =  PfpSetTopLevelIrp(&TopLevelContext,FALSE,FALSE);	
			__try
			{
				Irp_Context = PfpCreateIrpContext(Irp,CanFsdWait(Irp));

				if(Irp_Context == NULL)
				{
					
					Irp->IoStatus.Information = 0;
					ntstatus =Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					IoCompleteRequest(Irp,IO_DISK_INCREMENT);
					goto RETURNED;
				}
				PfpUpdateIrpContextWithTopLevel( Irp_Context, ThreadTopLevelContext );			

				Irp_Context->Fileobject_onDisk = pDiskFileObject->pDiskFileObjectWriteThrough;
				Irp_Context->pNextDevice	   = pNextDriver;

				if(pstack->MinorFunction & IRP_MN_COMPLETE)
				{
					ntstatus = PfpCompleteMdl ( Irp_Context, Irp );
				}else
				{
					ntstatus = PfpCommonRead ( Irp_Context, Irp );
				}

			}			
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
			if (ThreadTopLevelContext == &TopLevelContext) 
			{
				PfpRestoreTopLevelIrp( ThreadTopLevelContext );
			}
		}
		/*
		1:cache 
		2:writethrough;
		3:pageio;
		*/

		break;
	case FILEOBEJCT_ON_DISK:

		break;
	case FILEOBJECT_WITH_WRITETHROUGH:

		break;
	default:
		break;
	}

RETURNED:
// 	if(pDeviceResource)
// 	{
// 		ExReleaseResource(pDeviceResource);
// 	}
	FsRtlExitFileSystem();

	return ntstatus;
	
PASSTHROUGH:

	
// 	if(pDeviceResource)
// 	{
// 		ExReleaseResource(pDeviceResource);
// 	}

	FsRtlExitFileSystem();


	IoSkipCurrentIrpStackLocation(Irp);
	
	ntstatus =IoCallDriver(pNextDriver ,Irp);
	
	
	return ntstatus;
}



NTSTATUS PfpCommonRead(PIRP_CONTEXT IrpContext,PIRP Irp)
/*++

Routine Description:

This is the common routine for Read called by both the fsd and fsp
threads.

Arguments:

Irp - Supplies the Irp to process

AcquireScb - Indicates if this routine should acquire the scb

Return Value:

NTSTATUS - The return status for the operation

--*/
{	
	typedef LONGLONG VBO;
	NTSTATUS					Status;
	PIO_STACK_LOCATION			IrpSp;
	PFILE_OBJECT				FileObject;

	
	EOF_WAIT_BLOCK				EofWaitBlock;
	PTOP_LEVEL_CONTEXT			TopLevelContext;

	VBO							StartingVbo;
	LONGLONG					ByteCount;
	LONGLONG					ByteRange;
	ULONG						RequestedByteCount;
	
	BOOLEAN						PostIrp = FALSE;
	BOOLEAN						OplockPostIrp = FALSE;
	BOOLEAN						PagingIoAcquired = FALSE;
	BOOLEAN						DoingIoAtEof = FALSE;

	BOOLEAN						Wait;
	BOOLEAN						PagingIo;
	BOOLEAN						NonCachedIo;
	BOOLEAN						SynchronousIo;

	NTFS_IO_CONTEXT				LocalContext;
	PPfpFCB						pFcb;
	PVOID						SystemBuffer = NULL;

	BOOLEAN						ResourceAcquired;

	ResourceAcquired = FALSE;
	//
	// A system buffer is only used if we have to access the
	// buffer directly from the Fsp to clear a portion or to
	// do a synchronous I/O, or a cached transfer.  It is
	// possible that our caller may have already mapped a
	// system buffer, in which case we must remember this so
	// we do not unmap it on the way out.
	//

	

	//ASSERT_IRP_CONTEXT( IrpContext );
	//ASSERT_IRP( Irp );

	//
	//  Get the current Irp stack location
	//

	IrpSp = IoGetCurrentIrpStackLocation( Irp );

	//
	// Initialize the appropriate local variables.
	//
	FileObject	  = IrpSp->FileObject	;
	Wait          = BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
	PagingIo      = BooleanFlagOn( Irp->Flags, IRP_PAGING_IO );
	NonCachedIo   = BooleanFlagOn( Irp->Flags,IRP_NOCACHE );
	SynchronousIo = BooleanFlagOn( FileObject->Flags, FO_SYNCHRONOUS_IO );

	//
	//  Extract starting Vbo and offset.
	//

	StartingVbo = IrpSp->Parameters.Read.ByteOffset.QuadPart;

	ByteCount = IrpSp->Parameters.Read.Length;
	ByteRange = StartingVbo + ByteCount;

	RequestedByteCount = (ULONG)ByteCount;
	


	pFcb	= (PPfpFCB)FileObject->FsContext;

	//
	//  Check for a null request, and return immediately
	//

	if ((ULONG)ByteCount == 0) 
	{
		PfpCompleteRequest( &IrpContext, &Irp, STATUS_SUCCESS );
		return STATUS_SUCCESS;
	}

	//
	//  Make sure there is an initialized NtfsIoContext block.
	//

	if ( NonCachedIo)
	{

		//
		//  If there is a context pointer, we need to make sure it was
		//  allocated and not a stale stack pointer.
		//

		if (IrpContext->Union.NtfsIoContext == NULL
			|| !FlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT ))
		{

			//
			//  If we can wait, use the context on the stack.  Otherwise
			//  we need to allocate one.
			//

			if (Wait) 
			{

				IrpContext->Union.NtfsIoContext = &LocalContext;
				ClearFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );

			} else
			{

				IrpContext->Union.NtfsIoContext = (PNTFS_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &NtfsIoContextLookasideList );
				SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );
			}
		}

		RtlZeroMemory( IrpContext->Union.NtfsIoContext, sizeof( NTFS_IO_CONTEXT ));

		//
		//  Store whether we allocated this context structure in the structure
		//  itself.
		//

		IrpContext->Union.NtfsIoContext->AllocatedContext = BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );

		if (Wait) 
		{
			KeInitializeEvent( &IrpContext->Union.NtfsIoContext->Wait.SyncEvent,
								NotificationEvent,
								FALSE );
			IrpContext->Union.NtfsIoContext->OriginatingIrp					=	Irp ;			

		} else 
		{
			IrpContext->Union.NtfsIoContext->PagingIo						=	PagingIo;
			IrpContext->Union.NtfsIoContext->Wait.Async.ResourceThreadId	=	ExGetCurrentResourceThread();
			IrpContext->Union.NtfsIoContext->Wait.Async.RequestedByteCount	=	(ULONG)ByteCount;
			IrpContext->Union.NtfsIoContext->OriginatingIrp					=	Irp ;			
		}
	}

	//
	//  Use a try-finally to free Scb and buffers on the way out.
	//  At this point we can treat all requests identically since we
	//  have a usable Scb for each of them.  (Volume, User or Stream file)
	//

	__try
	{

		//
		// This case corresponds to a non-directory file read.
		//

		LONGLONG FileSize;
		LONGLONG ValidDataLength;

		//
		//  If this is a noncached transfer and is not a paging I/O, and
		//  the file has a data section, then we will do a flush here
		//  to avoid stale data problems.  Note that we must flush before
		//  acquiring the Fcb shared since the write may try to acquire
		//  it exclusive.  This is not necessary for compressed files, since
		//  we will turn user noncached writes into cached writes.
		//

		if (!PagingIo &&
			NonCachedIo &&
			(FileObject->SectionObjectPointer->DataSectionObject != NULL))
		{

				ExAcquireResourceSharedLite( pFcb->Header.Resource, TRUE );

				//if (Scb->CompressionUnit == 0) 
				{

					//
					//  It is possible that this read is part of a top level request or
					//  is being called by MM to create an image section.  We will update
					//  the top-level context to reflect this.  All of the exception
					//  handling will correctly handle the log file full in this case.
					//

					TopLevelContext = PfpGetTopLevelContext();

					if (TopLevelContext->SavedTopLevelIrp != NULL) 
					{

						TopLevelContext->TopLevelRequest = FALSE;
					}

					CcFlushCache(	FileObject->SectionObjectPointer,
									(PLARGE_INTEGER)&StartingVbo,
									(ULONG)ByteCount,
									&Irp->IoStatus );

					//
					//  Make sure the data got out to disk.
					//

					ExReleaseResourceLite( pFcb->Header.Resource );
					ExAcquireResourceExclusiveLite( pFcb->Header.Resource, TRUE );
					ExReleaseResourceLite( pFcb->Header.Resource );

					//
					//  Check for errors in the flush.
					//
					if(!NT_SUCCESS( Irp->IoStatus.Status ))
					{
						PfpNormalizeAndRaiseStatus(IrpContext,
												Irp->IoStatus.Status,STATUS_UNEXPECTED_IO_ERROR);
					}
					
				} 
		}

		//
		//  We need shared access to the Scb before proceeding.
		//  We won't acquire the Scb for a non-cached read of the first 4
		//  file records.
		//

		//if (!NonCachedIo)
		{

				//
				//  Figure out if we have been entered during the posting
				//  of a top level request.
				//

				TopLevelContext = PfpGetTopLevelContext();

				//
				//  Initially we always force reads to appear to be top level
				//  requests.  If we reach this point the read not to the paging
				//  file so it is safe to determine if we are really a top level
				//  request.  If there is an Ntfs request above us we will clear
				//  the TopLevelRequest field in the TopLevelContext.
				//

				if (TopLevelContext->ValidSavedTopLevel)
				{
					TopLevelContext->TopLevelRequest = FALSE;
				}

				//
				//  If this is not a paging I/O (cached or user noncached I/O),
				//  then acquire the paging I/O resource.  (Note, you can only
				//  do cached I/O to user streams, and they always have a paging
				//  I/O resource.
				//

				if (!PagingIo)
				{

					//
					//  If we cannot acquire the resource, then raise.
					//

					if (!ExAcquireSharedWaitForExclusive( pFcb->Header.Resource, Wait ))
					{
						PfpRaiseStatus( IrpContext, STATUS_CANT_WAIT, NULL);
					}
					PagingIoAcquired = TRUE;

					
					//
					//  The reason that we always handle the user requests through the cache,
					//  is that there is no better way to deal with alignment issues, for
					//  the frequent case where the user noncached I/O is not an integral of
					//  the Compression Unit.  Also, the way we synchronize the case where
					//  a compression unit is being moved to a different spot on disk during
					//  a write, is to keep the pages locked in memory during the write, so
					//  that there will be no need to read the disk at the same time.  (If
					//  we allowed real noncached I/O, then we would somehow have to synchronize
					//  the noncached read with the write of the same data.)
					//
					//  Bottom line is we can only really support cached reads to compresed
					//  files.
					//


					//
					//  If this is async I/O directly to the disk we need to check that
					//  we don't exhaust the number of times a single thread can
					//  acquire the resource.
					//

					if (!Wait && NonCachedIo) 
					{

						if (ExIsResourceAcquiredSharedLite(pFcb->Header.Resource) > 10) 
						{
							PfpRaiseStatus( IrpContext, STATUS_CANT_WAIT, NULL );
						}

						IrpContext->Union.NtfsIoContext->Wait.Async.Resource = pFcb->Header.Resource;
					}					

// 					if (FlagOn( pFcb->FcbState, FCB_STATE_FILE_DELETED ))
// 					{
// 						PfpRaiseStatus( IrpContext, STATUS_FILE_DELETED, NULL);
// 					}

					//
					//  If this is a paging I/O, and there is a paging I/O resource, then
					//  we acquire the main resource here.  Note that for most paging I/Os
					//  (like faulting for cached I/O), we already own the paging I/O resource,
					//  so we acquire nothing here!  But, for other cases like user-mapped files,
					//  we do check if paging I/O is acquired, and acquire the main resource if
					//  not.  The point is, we need some guarantee still that the file will not
					//  be truncated.
					//

				} else if ((pFcb->Header.Resource != NULL) &&!ExIsResourceAcquiredSharedLite(pFcb->Header.Resource)) 
				{
					//
					//  If we cannot acquire the resource, then raise.
					//
				
						if (!ExAcquireResourceSharedLite( pFcb->Resource, Wait )) 
						{
							PfpRaiseStatus( IrpContext, STATUS_CANT_WAIT, NULL );
						}					
						ResourceAcquired = TRUE;	
// 
// 						if (FlagOn( pFcb->FcbState, FCB_STATE_FILE_DELETED ))
// 						{
// 							PfpRaiseStatus( IrpContext, STATUS_FILE_DELETED, NULL );
// 						}

						
				}
		}

	

		//
		//  We check whether we can proceed
		//  based on the state of the file oplocks.
		//

		//if (TypeOfOpen == UserFileOpen) 
		{

			Status = FsRtlCheckOplock( &pFcb->Oplock,
										Irp,
										IrpContext,
										PfpOplockComplete,
										PfpPrePostIrp );

			if (Status != STATUS_SUCCESS) 
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
				PfpAcquireFsrtlHeader( pFcb );
				pFcb->Header.IsFastIoPossible = PfpIsFastIoPossible( pFcb );
				PfpReleaseFsrtlHeader( pFcb );
			}

			//
			// We have to check for read access according to the current
			// state of the file locks.
			//

			if (!PagingIo
				&& pFcb->FileLock != NULL
				&& !FsRtlCheckLockForReadAccess( pFcb->FileLock,
				Irp ))
			{

					try_return( Status = STATUS_FILE_LOCK_CONFLICT );
			}
		}

		//
		//  Now synchronize with the FsRtl Header
		//

		ExAcquireFastMutex( pFcb->Header.FastMutex );

		//
		//  Now see if we are reading beyond ValidDataLength.  We have to
		//  do it now so that our reads are not nooped.  We only need to block
		//  on nonrecursive I/O (cached or page fault to user section, because
		//  if it is paging I/O, we must be part of a reader or writer who is
		//  synchronized.
		//

		if ((ByteRange > pFcb->Header.ValidDataLength.QuadPart) && !PagingIo) 
		{

			//
			//  We must serialize with anyone else doing I/O at beyond
			//  ValidDataLength, and then remember if we need to declare
			//  when we are done.  If our caller has already serialized
			//  with EOF then there is nothing for us to do here.
			//

			if ((IrpContext->TopLevelIrpContext->FcbWithPagingExclusive == pFcb))
			{

				DoingIoAtEof = TRUE;

			} else 
			{

				DoingIoAtEof = !FlagOn( pFcb->Header.Flags, FSRTL_FLAG_EOF_ADVANCE_ACTIVE ) ||
								PfpWaitForIoAtEof(  &pFcb->Header,
													(PLARGE_INTEGER)&StartingVbo,
													(ULONG)ByteCount,
													&EofWaitBlock );

				//
				//  Set the Flag if we are in fact beyond ValidDataLength.
				//

				if (DoingIoAtEof) 
				{
					SetFlag( pFcb->Header.Flags, FSRTL_FLAG_EOF_ADVANCE_ACTIVE );
					IrpContext->FcbWithPagingExclusive = (PPfpFCB) pFcb;
				}
			}
		}

		//
		//  Get file sizes from the Scb.
		//
		//  We must get ValidDataLength first since it is always
		//  increased second (the case we are unprotected) and
		//  we don't want to capture ValidDataLength > FileSize.
		//

		ValidDataLength = pFcb->Header.ValidDataLength.QuadPart;
		FileSize = pFcb->Header.FileSize.QuadPart;

		ExReleaseFastMutex( pFcb->Header.FastMutex );

		//
		// If the read starts beyond End of File, return EOF.
		//

		if (StartingVbo >= FileSize) 
		{

			//DebugTrace( 0, Dbg, ("End of File\n") );

			try_return ( Status = STATUS_END_OF_FILE );
		}

		//
		//  If the read extends beyond EOF, truncate the read
		//

		if (ByteRange > FileSize) 
		{

			ByteCount = FileSize - StartingVbo;
			ByteRange = StartingVbo + ByteCount;

			RequestedByteCount = (ULONG)ByteCount;

			if (NonCachedIo && !Wait)
			{
				IrpContext->Union.NtfsIoContext->Wait.Async.RequestedByteCount =(ULONG)ByteCount;
			}
		}

		
		//
		//  HANDLE THE NON-CACHED CASE
		//

		if (NonCachedIo) 
		{

			ULONG BytesToRead;

			ULONG SectorSize;

			ULONG ZeroOffset;
			ULONG ZeroLength = 0;

			//DebugTrace( 0, Dbg, ("Non cached read.\n") );

			//
			//  For a compressed stream, which is user-mapped, reserve space
			//  as pages come in.
			//

			//
			//  Start by zeroing any part of the read after Valid Data
			//

			
			if (ByteRange > ValidDataLength)
			{

				SystemBuffer = PfpMapUserBuffer( Irp );

				if (StartingVbo < ValidDataLength) 
				{

					//
					//  Assume we will zero the entire amount.
					//

					ZeroLength = (ULONG)ByteCount;

					//
					//  The new byte count and the offset to start filling with zeroes.
					//

					ByteCount = ValidDataLength - StartingVbo;
					ZeroOffset = (ULONG)ByteCount;

					//
					//  Now reduce the amount to zero by the zero offset.
					//

					ZeroLength -= ZeroOffset;

					//
					//  If this was non-cached I/O then convert it to synchronous.
					//  This is because we don't want to zero the buffer now or
					//  we will lose the data when the driver purges the cache.
					//

					if (!Wait) 
					{

						Wait = TRUE;
						SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );

						RtlZeroMemory( IrpContext->Union.NtfsIoContext, sizeof( NTFS_IO_CONTEXT ));

						//
						//  Store whether we allocated this context structure in the structure
						//  itself.
						//
						IrpContext->Union.NtfsIoContext->OriginatingIrp	  =	Irp ;	
						IrpContext->Union.NtfsIoContext->AllocatedContext = BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_ALLOC_CONTEXT );

						KeInitializeEvent( &IrpContext->Union.NtfsIoContext->Wait.SyncEvent,
											NotificationEvent,
											FALSE );
					}

				} else 
				{

					//
					//  All we have to do now is sit here and zero the
					//  user's buffer, no reading is required.
					//

					SafeZeroMemory( (PUCHAR)SystemBuffer, (ULONG)ByteCount );

					Irp->IoStatus.Information = (ULONG)ByteCount;

					try_return ( Status = STATUS_SUCCESS );
				}
			}


			//
			//  Get the sector size
			//

			SectorSize = 512;

			//
			//  Round up to a sector boundry
			//

			BytesToRead = ((ULONG)ByteCount + (SectorSize - 1)) & ~(SectorSize - 1);

			

			//
			//  Just to help reduce confusion.  At this point:
			//
			//  RequestedByteCount - is the number of bytes originally
			//                       taken from the Irp, but constrained
			//                       to filesize.
			//
			//  ByteCount -          is RequestedByteCount constrained to
			//                       ValidDataLength.
			//
			//  BytesToRead -        is ByteCount rounded up to sector
			//                       boundry.  This is the number of bytes
			//                       that we must physically read.
			//

			//
			//  Perform the actual IO
			//
			if ((((ULONG)StartingVbo) & (SectorSize - 1)
				|| BytesToRead > IrpSp->Parameters.Read.Length)) 
			{
					
					//
					//  If we can't wait, we must post this.
					//
					ULONG NewStart;
					ULONG NewEnd  ;
					PVOID pTempBuffer ;
					PVOID pUserBuffer ;
					BOOLEAN bEncrypt;
					if (!Wait) 
					{
						try_return( PostIrp = TRUE );
					}

					//
					//  Do the physical read.
					//
					bEncrypt = pFcb->bNeedEncrypt;
					NewStart= (ULONG)StartingVbo&(SectorSize - 1);
					NewEnd  = ((ULONG)StartingVbo+(ULONG)ByteCount+(SectorSize - 1))& ~(SectorSize - 1);

				//	ASSERT(FileObject->SectionObjectPointer == &Scb->NonpagedScb->SegmentObject);
					//这里吧 startvbo 转化到前面的与sector对齐的readoffset

					//调用PfpNonCachedIoRead 来实现 sector对齐的方式的读。
					pTempBuffer = ExAllocatePoolWithTag(NonPagedPool,NewEnd-NewStart,'R001');
					pUserBuffer = NULL;
					ASSERT(pTempBuffer);
					pUserBuffer						= Irp->AssociatedIrp.SystemBuffer ;
					Irp->AssociatedIrp.SystemBuffer = pTempBuffer;

					//KdPrint( ("read   offset =%x, count = %x, %wz \n",StartingVbo ,BytesToRead,&pFcb->pDiskFileObject->FullFilePath));
					PfpNonCachedNonAlignedIo(   IrpContext,
												Irp,
												pFcb,
												NewStart+(bEncrypt?ENCRYPTIONHEADLENGTH:0),
												(ULONG)(NewEnd-NewStart));
					// 解密
					if(bEncrypt)
					{
						//使用pTempBuffer 来做解密。解密后的数据仍然在这个buffer里面。
					}
					if(NewStart != StartingVbo)
					{
						RtlCopyMemory(pUserBuffer,((PUCHAR)pTempBuffer+(StartingVbo-NewStart)),RequestedByteCount);
					}else
					{
						RtlCopyMemory(pUserBuffer,pTempBuffer,RequestedByteCount);
					}
					if(ByteRange>ValidDataLength)
					{
						SafeZeroMemory( Add2Ptr( pUserBuffer, RequestedByteCount-(SIZE_T)(ByteRange-ValidDataLength )), (SIZE_T)(ByteRange-ValidDataLength) );
					}	

					Irp->AssociatedIrp.SystemBuffer = pUserBuffer;

					Irp->IoStatus.Information = RequestedByteCount;
					ExFreePool(pTempBuffer);
					pTempBuffer = NULL;
					//
					//  If the call didn't succeed, raise the error status
					//

					if (!NT_SUCCESS( Status = Irp->IoStatus.Status ))
					{
						PfpNormalizeAndRaiseStatus(	IrpContext,
													Status,
													STATUS_UNEXPECTED_IO_ERROR );
					}

					try_return( Status );
					// 检测前面的偏移是不是发生了变化
					//如果是 往前移动 systembuffer里面数据
					BytesToRead = (ULONG)ByteCount;

			} else 
			{
				ULONG OffsetNew=(ULONG)StartingVbo;
				if(pFcb->bNeedEncrypt)
				{
					OffsetNew+=ENCRYPTIONHEADLENGTH;
				}
				//KdPrint( ("read   offset =%08x , count =%08x, %wZ \n",OffsetNew ,BytesToRead,&pFcb->pDiskFileObject->FullFilePath));
				if (PfpNonCachedIoRead(	IrpContext,
										Irp,
										pFcb,
										OffsetNew,
										BytesToRead
										)== STATUS_PENDING)
				{

					IrpContext->Union.NtfsIoContext = NULL;
					PagingIoAcquired = FALSE;
					Irp = NULL;

					try_return( Status = STATUS_PENDING );
				}
				//
				//  If the call didn't succeed, raise the error status
				//

				if (!NT_SUCCESS( Status = Irp->IoStatus.Status ))
				{
					PfpNormalizeAndRaiseStatus(	IrpContext,
						Status,
						STATUS_UNEXPECTED_IO_ERROR );
				}

				//
				//  Else set the Irp information field to reflect the
				//  entire desired read.
				//

				//ASSERT( Irp->IoStatus.Information == BytesToRead );

				Irp->IoStatus.Information = RequestedByteCount;

				//
				//  If we rounded up to a sector boundry before, zero out
				//  the other garbage we read from the disk.
				//

				if (BytesToRead > (ULONG)ByteCount)
				{

					if (SystemBuffer == NULL) 
					{

						SystemBuffer = PfpMapUserBuffer( Irp );
					}

					SafeZeroMemory( (PUCHAR)SystemBuffer + (ULONG)ByteCount,
						BytesToRead - (ULONG)ByteCount );
				}

				//
				//  If we need to zero the tail of the buffer because of valid data
				//  then do so now.
				//

				if (ZeroLength != 0) 
				{

					if (SystemBuffer == NULL) 
					{

						SystemBuffer = PfpMapUserBuffer( Irp );
					}

					SafeZeroMemory( Add2Ptr( SystemBuffer, ZeroOffset ), ZeroLength );
				}

				//
				// The transfer is complete.
				//

				try_return( Status );
			}
			

		}   // if No Intermediate Buffering
		else 
		{//
		//  HANDLE THE CACHED CASE
		//

			//
			//  We need to go through the cache for this
			//  file object.  First handle the noncompressed calls.
			//
			//
			// We delay setting up the file cache until now, in case the
			// caller never does any I/O to the file, and thus
			// FileObject->PrivateCacheMap == NULL.
			//

			if (FileObject->PrivateCacheMap == NULL) 
			{

				//DebugTrace( 0, Dbg, ("Initialize cache mapping.\n") );

				//
				//  Now initialize the cache map.
				//
				//  Make sure we are serialized with the FileSizes, and
				//  will remove this condition if we abort.
				//

				if (!DoingIoAtEof) 
				{
					FsRtlLockFsRtlHeader(&pFcb->Header );
					IrpContext->FcbWithPagingExclusive = (PPfpFCB)pFcb;
				}

				CcInitializeCacheMap( FileObject,
										(PCC_FILE_SIZES)&pFcb->Header.AllocationSize,
										FALSE,
										&CacheManagerCallbacks,
										pFcb );

				if (!DoingIoAtEof) 
				{
					FsRtlUnlockFsRtlHeader( &pFcb->Header );
					IrpContext->FcbWithPagingExclusive = NULL;
				}

				CcSetReadAheadGranularity( FileObject, READ_AHEAD_GRANULARITY );
			}

			//
			// DO A NORMAL CACHED READ, if the MDL bit is not set,
			//

			//DebugTrace( 0, Dbg, ("Cached read.\n") );

			if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL)) 
			{

				//
				//  Get hold of the user's buffer.
				//

				SystemBuffer = PfpMapUserBuffer( Irp );

				//
				// Now try to do the copy.
				//

				if (!CcCopyRead( FileObject,
								(PLARGE_INTEGER)&StartingVbo,
								(ULONG)ByteCount,
								Wait,
								SystemBuffer,
								&Irp->IoStatus )) 
				{

					//DebugTrace( 0, Dbg, ("Cached Read could not wait\n") );

					try_return( PostIrp = TRUE );
				}

				Status = Irp->IoStatus.Status;

				ASSERT( NT_SUCCESS( Status ));

				try_return( Status );
			}

			//
			//  HANDLE A MDL READ
			//

			else 
			{

				//DebugTrace( 0, Dbg, ("MDL read.\n") );

				ASSERT( Wait );

				CcMdlRead( FileObject,
							(PLARGE_INTEGER)&StartingVbo,
							(ULONG)ByteCount,
							&Irp->MdlAddress,
							&Irp->IoStatus );

				Status = Irp->IoStatus.Status;

				ASSERT( NT_SUCCESS( Status ));

				try_return( Status );
			}

			//
			//  Handle the compressed calls.
			//


		}

try_exit: NOTHING;

		//
		//  If the request was not posted, deal with it.
		//

		if (Irp) 
		{

			if (!PostIrp) 
			{

				LONGLONG ActualBytesRead;

				//DebugTrace( 0, Dbg, ("Completing request with status = %08lx\n",
				//	Status));

				//DebugTrace( 0, Dbg, ("                   Information = %08lx\n",
				//	Irp->IoStatus.Information));

				//
				//  Record the total number of bytes actually read
				//

				ActualBytesRead = Irp->IoStatus.Information;

				//
				//  If the file was opened for Synchronous IO, update the current
				//  file position.  Make sure to use the original file object
				//  not an internal stream we may use within this routine.
				//

				if (!PagingIo) 
				{

					if (SynchronousIo) 
					{
						IrpSp->FileObject->CurrentByteOffset.QuadPart = StartingVbo + ActualBytesRead;
					}

					//
					//  On success, do the following to let us update last access time.
					//

					if (NT_SUCCESS( Status )) 
					{
						SetFlag( IrpSp->FileObject->Flags, FO_FILE_FAST_IO_READ );
					}
				}
			
			} else
			{

				//DebugTrace( 0, Dbg, ("Passing request to Fsp\n") );

				if (!OplockPostIrp) 
				{
					Status = PfpPostRequest( IrpContext, Irp );
				}
			}
		}

	}
	__finally 
	{

		//
		// If the Scb has been acquired, release it.
		//
		
// 		if(DoingIoAtEof)
// 		{
// 			PfpFinishIoAtEof(&pFcb->Header);
// 		}
		if (PagingIoAcquired) 
		{

			ExReleaseResourceLite( pFcb->Header.Resource );
		}

		if (Irp) 
		{

			if (ResourceAcquired) 
			{

				ExReleaseResourceLite( pFcb->Resource );
			}
		}

		//
		//  Complete the request if we didn't post it and no exception
		//
		//  Note that NtfsCompleteRequest does the right thing if either
		//  IrpContext or Irp are NULL
		//

		if (!PostIrp && !AbnormalTermination())
		{

			PfpCompleteRequest(	&IrpContext,
								Irp ? &Irp : NULL,
								Status );
		}

	//	DebugTrace( -1, Dbg, ("NtfsCommonRead -> %08lx\n", Status) );
	}

	return Status;
}


NTSTATUS
PfpNonCachedIoRead( 
				   IN PIRP_CONTEXT  pIrpContext,
				   IN PIRP Irp,
				   IN PPfpFCB pFcb,
				   IN LONGLONG StartingOffset,
				   IN LONG BytesToWrite
				   )
{
	PDEVICE_OBJECT		pNextDevice;
	PIRP				pIrp;
	PIRP				pPreIrp;
	NTSTATUS			ntStatus;
	PIO_STACK_LOCATION	pIoStack;
	PIO_STACK_LOCATION	pIoPreStack;
	PFILE_OBJECT		pFileobejct_onDISK;
	PFILE_OBJECT		pUserFileObejct;		
	BOOLEAN				Wait;
	PMDL				pNewMdl;	
	UNREFERENCED_PARAMETER(pFcb);

	pPreIrp				= Irp;
	pIoPreStack			= IoGetCurrentIrpStackLocation( pPreIrp );
	pUserFileObejct	    = pIoPreStack->FileObject;
	Wait				= ((pIrpContext->Flags&IRP_CONTEXT_FLAG_WAIT)?TRUE:FALSE );
	pNextDevice			= pIrpContext->pNextDevice;	
	pFileobejct_onDISK	= pIrpContext->Fileobject_onDisk;

	if ( pNextDevice == NULL || pFileobejct_onDISK  == NULL)
		return STATUS_INVALID_PARAMETER;


	if( pPreIrp ->MdlAddress== NULL)
	{
		__try 
		{

			ProbeForWrite( pPreIrp->UserBuffer, BytesToWrite, sizeof( UCHAR ) );	

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();			 
		}
	}
	//
	//We will allocate a irp for our own use
	pIrp = IoAllocateIrp(pNextDevice->StackSize,FALSE);

	if( pIrp  == NULL )
		return STATUS_INSUFFICIENT_RESOURCES;


	//map the user buffer into our new allocated irp,
	//Attention!!  the pPreIrp maybe has buffer in user space

	//pIrp->AssociatedIrp.SystemBuffer		= pPreIrp ->AssociatedIrp.SystemBuffer;
	pIrp->MdlAddress						= pPreIrp ->MdlAddress;
	pIrp->UserBuffer						= pPreIrp ->UserBuffer;
	if( pIrp->MdlAddress==  NULL)
	{		
		pNewMdl  = IoAllocateMdl(pIrp->UserBuffer, BytesToWrite, FALSE, TRUE, NULL);
		__try
		{
			MmProbeAndLockPages(pNewMdl, UserMode, IoWriteAccess );
			
			
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();			
			IoFreeMdl(pNewMdl);
			IoFreeIrp(pIrp);
			return ntStatus;
		}
		// pIrp->AssociatedIrp.SystemBuffer = MmGetSystemAddressForMdlSafe(pNewMdl, NormalPagePriority );

		if (!MmGetSystemAddressForMdlSafe(pNewMdl, NormalPagePriority )) 
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			MmUnlockPages(pNewMdl);
			IoFreeMdl(pNewMdl);
			IoFreeIrp(pIrp);
			return ntStatus;
		}
		pIrp->MdlAddress					    = pNewMdl;
	}
	
	pIrp->Flags								= IRP_NOCACHE|(Wait?IRP_SYNCHRONOUS_API:0);
	pIrp->UserEvent							= &pIrpContext->Union.NtfsIoContext->Wait.SyncEvent;
	pIrp->RequestorMode						= KernelMode;
	pIrp->Tail.Overlay.Thread				= (PETHREAD) PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject	= pFileobejct_onDISK;


	pIoStack  = IoGetNextIrpStackLocation(pIrp);

	pIoStack->MajorFunction					= IRP_MJ_READ;
	pIoStack->MinorFunction					= IRP_MN_NORMAL;
	pIoStack->DeviceObject					= pNextDevice;
	pIoStack->FileObject					= pFileobejct_onDISK;
	pIoStack->Parameters.Read.ByteOffset.QuadPart	= StartingOffset;
	pIoStack->Parameters.Read.Length		= BytesToWrite;

	ntStatus = IoSetCompletionRoutineEx(pNextDevice,
										pIrp,
										Wait?PfpNonCachedSyncIoCompleteRead:PfpNonCachedAsyncIoCompleteRead,
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

	if(!Wait)
	{
		IoMarkIrpPending(pPreIrp)		;
	}
	ntStatus = IoCallDriver(pNextDevice,pIrp);

	if(Wait)
	{
		if( (ntStatus  == STATUS_PENDING ))
		{
			KeWaitForSingleObject(  &pIrpContext->Union.NtfsIoContext->Wait.SyncEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);
			ntStatus  = STATUS_SUCCESS; 
		}
	}else
	{
		ntStatus = STATUS_PENDING;	
	}
	

	return ntStatus  ;
}
NTSTATUS
PfpNonCachedSyncIoCompleteRead(
								IN PDEVICE_OBJECT  DeviceObject,
								IN PIRP  Irp,
								IN PVOID  Context
								)
{
	PNTFS_IO_CONTEXT    pNtfsIoContext;
	UNREFERENCED_PARAMETER(DeviceObject);

	pNtfsIoContext  = (PNTFS_IO_CONTEXT)Context;	
	pNtfsIoContext ->OriginatingIrp->IoStatus = Irp->IoStatus;

	

	if(Irp->IoStatus.Status == STATUS_SUCCESS)
	{
		if(((PPfpFCB)(IoGetCurrentIrpStackLocation(pNtfsIoContext ->OriginatingIrp)->FileObject)->FsContext)->bNeedEncrypt)
		{
			PVOID	pBuffer = NULL;
			BOOLEAN bBufferCanbeWritten = TRUE; 
			
			if(NULL==(pBuffer = MmGetSystemAddressForMdlSafe ( Irp->MdlAddress,NormalPagePriority  )))
			{
				pNtfsIoContext ->OriginatingIrp->IoStatus.Status= STATUS_INSUFFICIENT_RESOURCES;
			}
				
		 
			if(pBuffer)
			{
				PfpDecryptBuffer(pBuffer,(ULONG)Irp->IoStatus.Information,&ase_den_context);
			}
			if(Irp->MdlAddress!= pNtfsIoContext ->OriginatingIrp->MdlAddress )
			{
				MmUnlockPages(Irp->MdlAddress);
				IoFreeMdl(Irp->MdlAddress);				
			}
			
		}
	}
	IoFreeIrp(Irp);
	
	KeSetEvent( &pNtfsIoContext ->Wait.SyncEvent,0,FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
PfpNonCachedAsyncIoCompleteRead(
							   IN PDEVICE_OBJECT  DeviceObject,
							   IN PIRP  Irp,
							   IN PVOID  Context
							   )
{
	PNTFS_IO_CONTEXT    pNtfsIoContext;
	PIRP				pOrignalIrp;
	
	LONGLONG			ByteRange;
	
	BOOLEAN				PagingIO;
	
	PERESOURCE			pResource;
	ERESOURCE_THREAD	ResourceThreadId;
	
	UNREFERENCED_PARAMETER(DeviceObject);

	pNtfsIoContext	= (PNTFS_IO_CONTEXT)Context;
	pOrignalIrp		= pNtfsIoContext->OriginatingIrp;
	ResourceThreadId= pNtfsIoContext->Wait.Async.ResourceThreadId;
	pResource		= pNtfsIoContext->Wait.Async.Resource;		
	PagingIO		= pNtfsIoContext->PagingIo;
	pOrignalIrp->IoStatus	= Irp->IoStatus;
	ByteRange				= pNtfsIoContext->Wait.Async.RequestedByteCount+pNtfsIoContext->Wait.Async.StartingOffset;

	if( NT_SUCCESS(Irp->IoStatus.Status) )
	{

		if(!PagingIO)
			SetFlag( IoGetCurrentIrpStackLocation(pOrignalIrp)->FileObject->Flags, FO_FILE_MODIFIED );

		pOrignalIrp->IoStatus.Information = pNtfsIoContext->Wait.Async.RequestedByteCount;
		// we should update the validatedatalength of fcb
	}		
	//set the flag of fileobject;
	//complete the original irp
	//delete the irpcontext

	if( pResource )
	{
		ExReleaseResourceForThreadLite(pResource,ResourceThreadId);	
	}

	ExFreeToNPagedLookasideList( &NtfsIoContextLookasideList, Context );

	if(Irp->IoStatus.Status == STATUS_SUCCESS)
	{
		if(((PPfpFCB)IoGetCurrentIrpStackLocation(pOrignalIrp)->FileObject->FsContext)->bNeedEncrypt)
		{	
			PVOID pBuffer = NULL;
			if(Irp->MdlAddress!= NULL)
			{
				pBuffer = MmGetSystemAddressForMdlSafe ( Irp->MdlAddress,NormalPagePriority  );
			}
 
			if(pBuffer== NULL)
			{
				pOrignalIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			}else
			{
				PfpDecryptBuffer(pBuffer,(ULONG)Irp->IoStatus.Information,&ase_den_context);
			}
			
			if(Irp->MdlAddress!= pOrignalIrp->MdlAddress )
			{
				MmUnlockPages(Irp->MdlAddress);
				IoFreeMdl(Irp->MdlAddress);				
			}
		}
	}
	if(pOrignalIrp->PendingReturned)
	{
		IoMarkIrpPending(pOrignalIrp);
	}
	IoCompleteRequest(pOrignalIrp,IO_DISK_INCREMENT);

	
	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID 
PfpNonCachedNonAlignedIo ( 
						  IN PIRP_CONTEXT IrpContext, 
						  IN PIRP		Irp, 
						  IN PPfpFCB	Scb, 
						  IN LONGLONG	StartingVbo, 
						  IN ULONG	ByteCount )
{
	UNREFERENCED_PARAMETER(IrpContext);
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(Scb);
	UNREFERENCED_PARAMETER(StartingVbo);
	UNREFERENCED_PARAMETER(ByteCount);
}