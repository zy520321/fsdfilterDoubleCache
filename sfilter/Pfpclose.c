  
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
NTSTATUS
PfpFsdClose (                          //  implemented in Close.c
			  IN PDEVICE_OBJECT VolumeDeviceObject,
			  IN PIRP Irp
			  )
			  //
			  //Send irp to lower driver to let fs know it's time to close the disk file object.
			  //
{
	//
	//
	// complete irp ,return the irp result coming from lower level fs driver.
	//
	
	PFILE_OBJECT		pFileObject; // coming from the upper layer calling into our filter driver
	PIO_STACK_LOCATION  iostack;
	PDISKFILEOBJECT		pDiskFileObj;
	NTSTATUS			status;
	PFILESPY_DEVICE_EXTENSION dext;
	PDEVICE_OBJECT      pNextDevice;
	PUSERFILEOBJECT		pUserFileObjects;
	BOOLEAN				bEmpty;
	PPfpFCB				pFcb;
	BOOLEAN				bAccquirGlobal		= FALSE;
	KIRQL               oldIrql;
	
	PERESOURCE			pParentResource = NULL;
 
	PPfpCCB				pCcb= NULL;
	HANDLE				hFileOnDisk = INVALID_HANDLE_VALUE;
	PFILE_OBJECT		hFileObjectOnDisk = NULL;
	BOOLEAN				bConverToShared = FALSE;
	pFcb		= NULL;
	pDiskFileObj= NULL;
	bEmpty		= TRUE;
	status		= STATUS_SUCCESS;
	
	FsRtlEnterFileSystem();
	if ( VolumeDeviceObject == gControlDeviceObject ) 
	{
		KeAcquireSpinLock( &gControlDeviceStateLock, &oldIrql );		

		gControlDeviceState = CLOSED;		

		KeReleaseSpinLock( &gControlDeviceStateLock, oldIrql );

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_DISK_INCREMENT );
		FsRtlExitFileSystem();
		return STATUS_SUCCESS;
	}
	

	dext		= ((PDEVICE_OBJECT)VolumeDeviceObject)->DeviceExtension;
	pNextDevice = dext->NLExtHeader.AttachedToDeviceObject;
	
	if(dext->bShadow)
	{
		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)(dext->pRealDevice->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
		goto BYPASS;
	}

	
	iostack     = IoGetCurrentIrpStackLocation(Irp);

	pFileObject = iostack->FileObject;
    
	//
	//Check to see if this fileobject is cared by our filter driver.
	//
	if(!PfpFileObjectHasOurFCB(pFileObject))
		goto BYPASS;
	
	
	pFcb = pFileObject->FsContext;
	pCcb = pFileObject->FsContext2;
	pDiskFileObj= pFcb->pDiskFileObject;
	ASSERT(pDiskFileObj);


	pParentResource = pDiskFileObj->pParentDirResource;
	
	ASSERT(pParentResource );
	if(ExIsResourceAcquiredExclusiveLite(pParentResource))
	{
		pParentResource  = NULL;		
	}else
	{
		if(ExIsResourceAcquiredSharedLite(pParentResource))
		{
			ExReleaseResourceLite(pParentResource);			
			bConverToShared  = TRUE;
		}
		ExAcquireResourceExclusiveLite(pParentResource,TRUE);
	}
	
	ExAcquireResourceExclusiveLite(&pDiskFileObj->UserObjectResource,TRUE);

	//
	//Delete the structure from diskfileobjects corresponding to the user opened handle. 
	//
	 
	//VirtualizerStart();
	pUserFileObjects = PfpGetUserFileobjects(&pDiskFileObj->UserFileObjList,pFileObject);	
	
	if(pUserFileObjects != NULL)	
	{
		PfpRemoveUserFileObejctFromDiskFileObject(&pDiskFileObj->UserFileObjList,pUserFileObjects );
	}
	
	
	bEmpty  = IsEmptyDiskFileObject(pDiskFileObj);
	ExReleaseResourceLite(&pDiskFileObj->UserObjectResource);
	 
	

	PfpDeleteUserFileObject(&pUserFileObjects ); 

	if(!FlagOn(pFileObject->Flags,FO_CLEANUP_COMPLETE ))
	{
		PfpDecreFileOpen();
	}
 
	if(bEmpty )
	{
		if(pDiskFileObj->bNeedBackUp)
		{//这个磁盘上的文件也关闭了！，那么发送消息给那个备份的Thread，去关闭备份的文件，
			
			PfpCloseRealDiskFile(&pDiskFileObj->hBackUpFileHandle,&pDiskFileObj->hBackUpFileObject);
		}

		//if(FlagOn(pFcb->FcbState,FCB_STATE_FILE_DELETED))//这个文件要求在close的 时候删除！那么 就不放到延迟 关闭的队列里面了		
		{
			//status = PfpCloseRealDiskFile(&(pDiskFileObj->hFileWriteThrough),&(pDiskFileObj->pDiskFileObjectWriteThrough));
			hFileObjectOnDisk	= pDiskFileObj->pDiskFileObjectWriteThrough;
			hFileOnDisk			= pDiskFileObj->hFileWriteThrough;

			pDiskFileObj->hFileWriteThrough				= INVALID_HANDLE_VALUE;
			pDiskFileObj->pDiskFileObjectWriteThrough	= NULL;
			PfpDeleteFCB(&pFcb);

			if(pDiskFileObj->pVirtualDiskFile == NULL)//这里说明这个diskfileobject 已经和virtualdiskfile 断开了
			{
				KdPrint(("there is a file dettached from VirtualDiskFile Object and handled by layzewriter %wZ\r\n",&pDiskFileObj->FileNameOnDisk));
				PfpDeleteDiskFileObject(&pDiskFileObj);
			}else
			{
				PfpDeleteVirtualDiskFile(pDiskFileObj->pVirtualDiskFile,pDiskFileObj);
			}			
		}	
	}	
 
	if(pParentResource )
	{
		if(bConverToShared)
		{
			ExConvertExclusiveToSharedLite(pParentResource);
		}else
		{
			ExReleaseResourceLite(pParentResource);
		}
		
	}
	//VirtualizerEnd();
	ExFreePool(pFileObject->FsContext2);
	FsRtlExitFileSystem();
	if(bEmpty)
	{
		PfpCloseRealDiskFile(&hFileOnDisk,&hFileObjectOnDisk);
	}
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status	  = STATUS_SUCCESS;
	
	IoCompleteRequest(Irp,IO_DISK_INCREMENT);
	
	return STATUS_SUCCESS;
	
BYPASS:

	if(pParentResource )
	{
		if(bConverToShared)
		{
			ExConvertExclusiveToSharedLite(pParentResource);
		}else
		{
			ExReleaseResourceLite(pParentResource);
		}

	}

	FsRtlExitFileSystem();

 	IoSkipCurrentIrpStackLocation(Irp);
	
	status = IoCallDriver(pNextDevice,Irp);
	
	return status;
	
}

VOID
PfpSetFileNotEncryptSize(PFILE_OBJECT hFileObject,LARGE_INTEGER filesize,PDEVICE_OBJECT pNextDevice)
{
	FILE_END_OF_FILE_INFORMATION	FileSize;
	NTSTATUS						ntstatus;
	FileSize.EndOfFile.QuadPart = filesize.QuadPart;

	ntstatus = PfpSetFileInforByIrp(hFileObject,(PUCHAR)&FileSize,sizeof(FILE_END_OF_FILE_INFORMATION),FileEndOfFileInformation,pNextDevice);
	
}

NTSTATUS
PfpSetFileInforByIrp(PFILE_OBJECT hFileObject,PUCHAR pBuffer,ULONG len,FILE_INFORMATION_CLASS Information,PDEVICE_OBJECT pNextDevice)
{
	
	PIRP							Irp;
	PIO_STACK_LOCATION				pSp;
	NTSTATUS						ntstatus;
	KEVENT							event;
	
	Irp = IoAllocateIrp(pNextDevice->StackSize,FALSE );

	if(Irp  == NULL)
	{	
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//VirtualizerStart();
	//IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.A;dvanceOnly;
	__try
	{
		Irp->AssociatedIrp.SystemBuffer = pBuffer ;
		Irp->Flags						= IRP_SYNCHRONOUS_API;
		Irp->RequestorMode				= KernelMode;
		Irp->UserIosb					= NULL;
		Irp->UserEvent					= NULL;
		Irp->Tail.Overlay.Thread		= NULL;

		pSp = IoGetNextIrpStackLocation(Irp);

		pSp->MajorFunction								= IRP_MJ_SET_INFORMATION;	
		pSp->Parameters.SetFile.Length					= len;
		pSp->Parameters.SetFile.FileInformationClass	= Information;	
		pSp->FileObject									= hFileObject;	
		pSp->DeviceObject								= pNextDevice;
		if(FileRenameInformation==Information)
		{
			pSp->Parameters.SetFile.ReplaceIfExists = ((PFILE_RENAME_INFORMATION)pBuffer)->ReplaceIfExists;
		}
		KeInitializeEvent(&event,NotificationEvent ,FALSE);

		IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,&event,TRUE,TRUE,TRUE);

		if( STATUS_PENDING == (ntstatus=IoCallDriver(pNextDevice,Irp) ))
		{
			KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);

		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) 
	{
		KdPrint(("PfpSetFileInforByIrp function exception\r\n"));
	}
	//VirtualizerEnd();
	ntstatus= Irp->IoStatus.Status;

	IoFreeIrp(Irp);	
	return ntstatus;
	
}



NTSTATUS
PfpQueryFileInforByIrp(IN PFILE_OBJECT hFileObject,
					   IN OUT PUCHAR pBuffer,
					   IN ULONG  len,
					   IN FILE_INFORMATION_CLASS Information,
					   IN PDEVICE_OBJECT pNextDevice)
{
	PIRP							Irp;
	PIO_STACK_LOCATION				pSp;
	NTSTATUS						ntstatus;
	KEVENT							event;

	Irp = IoAllocateIrp(pNextDevice->StackSize,FALSE );

	if(Irp  == NULL)
	{	
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	 
	//IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.A;dvanceOnly;
	Irp->AssociatedIrp.SystemBuffer = pBuffer ;
	Irp->Flags						= IRP_SYNCHRONOUS_API;
	Irp->RequestorMode				= KernelMode;
	Irp->UserIosb					= NULL;
	Irp->UserEvent					= NULL;
	Irp->Tail.Overlay.Thread		= NULL;

	pSp = IoGetNextIrpStackLocation(Irp);

	pSp->MajorFunction								= IRP_MJ_QUERY_INFORMATION;	
	pSp->Parameters.QueryFile.Length				= len;
	pSp->Parameters.QueryFile.FileInformationClass	= Information;	
	pSp->FileObject									= hFileObject;	
	pSp->DeviceObject								= pNextDevice;

	KeInitializeEvent(&event,NotificationEvent ,FALSE);

	IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,&event,TRUE,TRUE,TRUE);

	if( STATUS_PENDING == (ntstatus=IoCallDriver(pNextDevice,Irp) ))
	{
		KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);

	}
	 
	ntstatus= Irp->IoStatus.Status;

	IoFreeIrp(Irp);	
	return ntstatus;
	
}