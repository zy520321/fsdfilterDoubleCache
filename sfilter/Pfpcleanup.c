 
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "log.h"
NTSTATUS
PfpFsdCleanup (
				IN PDEVICE_OBJECT VolumeDeviceObject,
				IN PIRP Irp
				)

				/*++

				Routine Description:

				This routine implements the FSD part of Cleanup.

				Arguments:

				VolumeDeviceObject - Supplies the volume device object where the
				file exists

				Irp - Supplies the Irp being processed

				Return Value:

				NTSTATUS - The FSD status for the IRP

				--*/

{
	PFILE_OBJECT		pFileObject		= NULL;
	TOP_LEVEL_CONTEXT	TopLevelContext;
	PTOP_LEVEL_CONTEXT	ThreadTopLevelContext;

	NTSTATUS			Status			= STATUS_SUCCESS;
	PIRP_CONTEXT		IrpContext		= NULL;
	
	PERESOURCE			pDeviceResource = NULL;
	PIO_STACK_LOCATION  iostack;
	PDEVICE_OBJECT      pNextDevice;
	
	PFILESPY_DEVICE_EXTENSION dext;
	

	PAGED_CODE();

	//
	//  If we were called with our file system device object instead of a
	//  volume device object, just complete this request with STATUS_SUCCESS
	//
	if ( VolumeDeviceObject == gControlDeviceObject ) 
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_DISK_INCREMENT );

		return STATUS_SUCCESS;
	}

	

	dext		= ((PDEVICE_OBJECT)VolumeDeviceObject)->DeviceExtension;
	pNextDevice = dext->NLExtHeader.AttachedToDeviceObject;
	
	if(dext->bShadow)
	{
		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)dext->pRealDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject;
		goto BYPASS;
	}

	iostack     = IoGetCurrentIrpStackLocation(Irp);

	pFileObject = iostack->FileObject;
	
	//
	//Check to see if this fileobject is cared by our filter driver.
	//
	if(!PfpFileObjectHasOurFCB(IoGetCurrentIrpStackLocation(Irp)->FileObject))
		goto BYPASS;
	

	//
	//  Call the common Cleanup routine
	//
 

	FsRtlEnterFileSystem();
 

	ThreadTopLevelContext = PfpSetTopLevelIrp( &TopLevelContext, FALSE, FALSE );

	//
	//  Do the following in a loop to catch the log file full and cant wait
	//  calls.
	//

	do {

		__try {

			//
			//  We are either initiating this request or retrying it.
			//

			if (IrpContext == NULL)
			{

				IrpContext = PfpCreateIrpContext( Irp, CanFsdWait( Irp ) );
				
				PfpUpdateIrpContextWithTopLevel( IrpContext, ThreadTopLevelContext );

			} 
			IrpContext->pNextDevice = pNextDevice;
			Status = PfpCommonCleanup( IrpContext, Irp );
			break;

		} 
		__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) {

			//
			//  We had some trouble trying to perform the requested
			//  operation, so we'll abort the I/O request with
			//  the error status that we get back from the
			//  execption code
			//
			KdPrint(("Cleanup function exception\r\n"));
			Status = PfpProcessException( IrpContext, Irp, GetExceptionCode() );
		}

	} while (Status == STATUS_CANT_WAIT);

	if (ThreadTopLevelContext == &TopLevelContext) 
	{
		PfpRestoreTopLevelIrp( ThreadTopLevelContext );
	}
	
	FsRtlExitFileSystem();

	return Status;

BYPASS:

	IoSkipCurrentIrpStackLocation(Irp);

	Status = IoCallDriver(pNextDevice,Irp);

	return Status;
}

NTSTATUS
PfpCommonCleanup (                        //  implemented in Cleanup.c
				IN PIRP_CONTEXT IrpContext,
				IN PIRP Irp
			  )
			  //
			  //Send this irp to lower driver, let fs know it's time to cleanup the diskobject.
			  //
{
	PFILE_OBJECT		pFileObject; // coming from the up	per layer calling into our filter driver	
	PDISKFILEOBJECT		pDiskFileObj;	
	NTSTATUS			status;	
	BOOLEAN				bEmpty;
	PPfpFCB				pFcb;
	PPfpCCB				pCcb;
	IO_STATUS_BLOCK		Iosb;
	PPROCESSINFO		pProcessInfo = NULL;
	PVOID				pEncryptHead= NULL;
	ULONG				nCleanupCount = 0;
	BOOLEAN				bWait= FALSE;
	BOOLEAN				bLastHandleClosed= FALSE;
	LARGE_INTEGER		TruncateSize;
	BOOLEAN				bHasCloseThisFile = FALSE;
	pFcb				= NULL;
	pDiskFileObj		= NULL;
	bEmpty				= TRUE;
	status				= STATUS_SUCCESS;
	
	if (!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)) 
	{

		status = PfpPostRequest( IrpContext, Irp );		

		return status;
	}

	
	pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

	pFcb = (PPfpFCB)pFileObject->FsContext;

	ASSERT(pFcb->pDiskFileObject);
	pDiskFileObj = pFcb->pDiskFileObject;

	//pFcb = pDiskFileObj->pFCB;
	pCcb = (PPfpCCB)pFileObject->FsContext2;	

	ExAcquireResourceExclusiveLite(((PVIRTUALDISKFILE)pDiskFileObj->pVirtualDiskFile)->pVirtualDiskLocker,TRUE	);
	KdPrint(("Cleanup function accquire file resource %Xh\r\n",((PVIRTUALDISKFILE)pDiskFileObj->pVirtualDiskFile)->pVirtualDiskLocker));
	ExAcquireResourceExclusiveLite(pFcb->Header.Resource,TRUE);

	//KdPrint (("in cleanup fileobejct %wZ\n",&pDiskFileObj->FullFilePath));

	__try
	{
		FsRtlCheckOplock( &pFcb->Oplock,Irp,IrpContext,NULL,NULL );

		//
		//  In this case, we have to unlock all the outstanding file
		//  locks, update the time stamps for the file and sizes for
		//  this attribute, and set the archive bit if necessary.
		//

		if (pFcb->FileLock != NULL) 
		{
			(VOID) FsRtlFastUnlockAll( pFcb->FileLock,pFileObject,IoGetRequestorProcess( Irp ),NULL );
		}

	}
	__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) 
	{
		KdPrint(("Cleanup function exception\r\n"));
	}
	
	//
	//  Update the FastIoField.
	//

	PfpAcquireFsrtlHeader( pFcb );
	pFcb->Header.IsFastIoPossible = PfpIsFastIoPossible( pFcb );
	PfpReleaseFsrtlHeader( pFcb );



	if (
// 		(!FlagOn( pFileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING ) &&
// 		(pFcb->NonCachedUnCleanupCount != 0) &&
// 		(pFcb->UncleanCount == (pFcb->NonCachedUnCleanupCount + 1)) ||
		/*(pFcb->UncleanCount==1)*/(nCleanupCount=PfpGetUncleanupCount(pDiskFileObj))==1&&
		(pFcb->SegmentObject.DataSectionObject != NULL) &&
		(pFcb->SegmentObject.ImageSectionObject == NULL)  &&
		MmCanFileBeTruncated( &pFcb->SegmentObject, NULL )) 
	{
		
		//
		//  Flush and purge the stream.
		//
		
		__try
		{
			
			
			CcFlushCache( &pFcb->SegmentObject, NULL, 0, &Iosb );		
			
			//
			//  If no error then purge the section.
			//
			if(NT_SUCCESS(Iosb.Status))
			{
				CcPurgeCacheSection( &pFcb->SegmentObject, NULL, 0, FALSE );
			}
		}
		__finally
		{				
			
		}
		//
		//  Ignore any errors in this path.
		//
	}

	

	TruncateSize.QuadPart = pFcb->Header.FileSize.QuadPart;
	CcUninitializeCacheMap(pFileObject,&TruncateSize,NULL);
	IoRemoveShareAccess( pFileObject, &pFcb->ShareAccess );

	if(!FlagOn(pCcb->Flags,CCB_FLAG_CLEANUP))
	{	
		PfpDecrementCleanupCounts(pFcb,BooleanFlagOn(pFileObject->Flags,FO_NO_INTERMEDIATE_BUFFERING));
		PfpDecreFileOpen();
		SetFlag(pFileObject->Flags,FO_CLEANUP_COMPLETE);
		pCcb->Flags|= CCB_FLAG_CLEANUP;
	}
	
	ExReleaseResourceLite(pFcb->Header.Resource);
	
	//如果是这个文件已经被设置了删除，并且这个时候所有的usermode的 handle全部关闭了，
	// 那么为了 让磁盘上的文件尽快的删除掉，这里就提前在cleanup里面关闭 磁盘上的文件。
	
	 
	if(PfpIsAllFileObjectThroughCleanup(pDiskFileObj) )
	{
		if(FlagOn(pFcb->FcbState,FCB_STATE_FILE_DELETED ))
		{
			 
			PfpCloseRealDiskFile(&(pDiskFileObj->hFileWriteThrough),&(pDiskFileObj->pDiskFileObjectWriteThrough));
			 
		}
		else if(pDiskFileObj->pDiskFileObjectWriteThrough && (pFileObject->Flags&FO_FILE_SIZE_CHANGED)&&  !((PPfpFCB)pDiskFileObj->pFCB)->bNeedEncrypt)
		{
			__try
			{
				FILE_END_OF_FILE_INFORMATION FileSize;
				FileSize.EndOfFile.QuadPart = pFcb->Header.FileSize.QuadPart;
				PfpSetFileNotEncryptSize(pFcb->pDiskFileObject->pDiskFileObjectWriteThrough,
					FileSize.EndOfFile,
					IrpContext->pNextDevice);
			}
			__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) 
			{
				KdPrint(("Cleanup function exception\r\n"));
			}
		}
		
	}
	 
	
	__try
	{
		if( !FlagOn(pFcb->FcbState,FCB_STATE_FILE_DELETED ) && 
			(pFileObject->Flags&FO_FILE_SIZE_CHANGED)&& 
			((PPfpFCB)pDiskFileObj->pFCB)->bNeedEncrypt)
		{
			pEncryptHead = PfpCreateEncryptHead(pDiskFileObj->pFCB);
			
			if(pEncryptHead )
			{

				PfpWriteHeadForEncryption(	pEncryptHead,
											ENCRYPTIONHEADLENGTH,
											pDiskFileObj->pDiskFileObjectWriteThrough,
											IrpContext->pNextDevice
											);


				if(pFcb->pDiskFileObject->bNeedBackUp)
				{

					if(pFcb->pDiskFileObject->hBackUpFileObject!= NULL)
					{
						HANDLE hFile;
						NTSTATUS ntstatus;
						IO_STATUS_BLOCK iostatus;LARGE_INTEGER offset= {0};
						ntstatus = ObOpenObjectByPointer(pFcb->pDiskFileObject->hBackUpFileObject,
														OBJ_KERNEL_HANDLE ,
														NULL,
														GENERIC_WRITE,
														*IoFileObjectType,
														KernelMode,
														&hFile );
						if(NT_SUCCESS(ntstatus))
						{
							ZwWriteFile(hFile,NULL,NULL,NULL,&iostatus,pEncryptHead,ENCRYPTIONHEADLENGTH,&offset,NULL);
							ZwClose(hFile);
						}
						//备份 主文件的最后一个usermode 的handle 已经被close掉了，那么这个备份的文件也应该在这个时候给close掉！
						//目的就是让用户能在应用程序退出后，能立即打开 这个备份的文件
						if(nCleanupCount==1)
						{
							PfpCloseRealDiskFile(&pFcb->pDiskFileObject->hBackUpFileHandle,&pFcb->pDiskFileObject->hBackUpFileObject);
						}
					}
				}
				
				ExFreePool(pEncryptHead);
				
			}
			//没有成功 怎么办？？？？
		}  
	}
	__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) 
	{
		KdPrint(("Cleanup function exception\r\n"));
	}

	__try
	{
		if(pDiskFileObj->bProcessOpened)
		{
			PPROCESSCREATEDFILEWithCCBs pCreatedFilewithCCb = NULL;
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);//ExAcquireFastMutex(&g_ProcessInofsLock);
			pProcessInfo = PfpGetProcessInfoUsingProcessId(PsGetProcessId(IoGetCurrentProcess()));
			ExReleaseResourceLite(&g_ProcessInfoResource);//ExReleaseFastMutex(&g_ProcessInofsLock);
			if(pProcessInfo )
			{   
				PHandleOfExe pHandleInfo= NULL;
				ExAcquireFastMutex(&pProcessInfo->HandleMutex);
				
				pHandleInfo = PfpGetHandleInfoUsingHanlde(pProcessInfo,PsGetProcessId(IoGetCurrentProcess()));
				if(pHandleInfo )
				{
					PfpDeleteCCBFromHandleOfExe(pHandleInfo,pCcb,&bHasCloseThisFile  ,&pCreatedFilewithCCb);
				}
				ExReleaseFastMutex(&pProcessInfo->HandleMutex);
				InterlockedDecrement(&pProcessInfo->nRef);
				if(bHasCloseThisFile && pCreatedFilewithCCb  )
				{
					UNICODE_STRING szUni;
					RtlInitUnicodeString(&szUni,pCreatedFilewithCCb->szFullPathWithOutDriverLetter);
					if(g_LogEvent&& g_bLog)
					{
						DoLog(pCreatedFilewithCCb->szDriverLetter,&szUni, &pProcessInfo->ProcessName,FALSE ,FALSE);  
					}
					PfpDeleteProcessCreatedFileWithCCB(&pCreatedFilewithCCb);
				}
			}
			
		}
	}
	__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) 
	{
		KdPrint(("Cleanup function exception\r\n"));
	}
	//ExFreePool_A(pCcb);

	ExReleaseResourceLite(((PVIRTUALDISKFILE)pDiskFileObj->pVirtualDiskFile)->pVirtualDiskLocker);
	KdPrint(("Cleanup function release file resource %Xh\r\r",((PVIRTUALDISKFILE)pDiskFileObj->pVirtualDiskFile)->pVirtualDiskLocker));
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status	  = status;

	PfpCompleteRequest(&IrpContext,&Irp,status);
	
	return status;
}


PVOID 
PfpCreateEncryptHead(IN PPfpFCB pFcb)
{
	PVOID			pBuffer = NULL;
	PVOID			pTemp;
	
	ULONG			Length;
	

	Length = ENCRYPTIONHEADLENGTH;
	pTemp  = pBuffer = ExAllocatePoolWithTag(NonPagedPool,ENCRYPTIONHEADLENGTH,'N001');
	
	RtlZeroMemory(pBuffer ,ENCRYPTIONHEADLENGTH);
	ASSERT(pBuffer );
	
	if(pTemp== NULL  )
		return NULL;

	*(LONGLONG*)pBuffer =(LONGLONG)0xA1F0B4CF378EB4C8;

	(PUCHAR)pBuffer+=sizeof(LONGLONG);
	*(LONGLONG*)pBuffer =pFcb->Header.FileSize.QuadPart;
	(PUCHAR)pBuffer += sizeof(LONGLONG);

	*(LONGLONG*)pBuffer =pFcb->Header.ValidDataLength.QuadPart;
	(PUCHAR)pBuffer += sizeof(LONGLONG);
	*(LONGLONG*)pBuffer = pFcb->Header.AllocationSize.QuadPart;

	return pTemp;
}
NTSTATUS 
PfpWriteFileByAllocatedIrp(
						  PVOID pBuffer,
						  ULONG Len,
						  LARGE_INTEGER Offset,
						  IN PFILE_OBJECT pDiskFile,
						  PDEVICE_OBJECT  pNextDevice,
						  PIO_STATUS_BLOCK pIostatus
						  )
{
	KEVENT				SyncEvent;	
	PIRP				pIrp ;
	NTSTATUS			ntStatus;
	PIO_STACK_LOCATION	pIoStack;

	KeInitializeEvent(&SyncEvent,NotificationEvent,FALSE);

	pIrp = IoAllocateIrp(pNextDevice->StackSize,FALSE);

	if( pIrp  == NULL )
		return STATUS_INSUFFICIENT_RESOURCES;


	//map the user buffer into our new allocated irp,
	//Attention!!  the pPreIrp maybe has buffer in user space


	pIrp->MdlAddress = IoAllocateMdl(pBuffer, Len, FALSE, TRUE, NULL);
	if (!pIrp->MdlAddress)
	{
		IoFreeIrp(pIrp);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	MmBuildMdlForNonPagedPool(pIrp->MdlAddress);

	pIrp->UserBuffer						= MmGetMdlVirtualAddress(pIrp->MdlAddress);;
	pIrp->Flags								= IRP_WRITE_OPERATION|IRP_NOCACHE;
	pIrp->UserEvent							= NULL;
	pIrp->RequestorMode						= KernelMode;
	pIrp->Tail.Overlay.Thread				= 0;//(PETHREAD) PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject	= pDiskFile;


	pIoStack  = IoGetNextIrpStackLocation(pIrp);

	pIoStack->MajorFunction							= IRP_MJ_WRITE;
	pIoStack->MinorFunction							= IRP_MN_NORMAL;
	pIoStack->DeviceObject							= pNextDevice;
	pIoStack->FileObject							= pDiskFile;
	pIoStack->Parameters.Write.ByteOffset			= Offset;
	pIoStack->Parameters.Write.Length				= Len;

	ntStatus = IoSetCompletionRoutineEx(pNextDevice,
		pIrp,
		PfpNonCachedWriteByIrpComplete,
		&SyncEvent,
		TRUE,
		TRUE,
		TRUE);

	if(!NT_SUCCESS(ntStatus))
	{
		IoFreeMdl(pIrp->MdlAddress);
		IoFreeIrp(pIrp);
		pIrp = NULL;
		return ntStatus;
	}

	ntStatus = IoCallDriver(pNextDevice,pIrp);

	if( ntStatus  == STATUS_PENDING )
	{

		KeWaitForSingleObject( &SyncEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL);
	}
	*pIostatus = pIrp->IoStatus;
	IoFreeMdl(pIrp->MdlAddress);
	IoFreeIrp(pIrp);
	return pIostatus->Status;
}

NTSTATUS 
PfpWriteHeadForEncryption(
						  PVOID pEncryptHead,
						  ULONG Len,
						  IN PFILE_OBJECT pDiskFile,
						  PDEVICE_OBJECT  pNextDevice
						  )
{
	IO_STATUS_BLOCK Iostatus;
	LARGE_INTEGER	Offset ={0};		
	return PfpWriteFileByAllocatedIrp(pEncryptHead,Len,Offset,pDiskFile,pNextDevice,&Iostatus);
}



NTSTATUS
PfpNonCachedWriteByIrpComplete(
								IN PDEVICE_OBJECT  DeviceObject,
								IN PIRP  Irp,
								IN PVOID  Context
								)
{
	PKEVENT    pEvent;
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	pEvent = (PKEVENT)Context;		
	KeSetEvent(pEvent,0,FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

