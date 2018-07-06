  
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"


NTSTATUS
PfpFsdSetEa (
			 IN PDEVICE_OBJECT VolumeDeviceObject,
			 IN PIRP Irp
			 )
{
	PDISKFILEOBJECT			pDiskFileObeject; 
	
	IO_STATUS_BLOCK			IoStatusBlock;
	PIO_STACK_LOCATION		IrpSp;
	PFILE_FULL_EA_INFORMATION EaBuffer;
	ULONG					UserBufferLength;		
	PVOID					pEaBuf	=  NULL;	
	NTSTATUS				ntstatus;
	PPfpFCB					pFcb;
	PFILE_OBJECT			pFileObject;
	PERESOURCE					pDeviceResource= NULL;
	UNREFERENCED_PARAMETER(VolumeDeviceObject);

	
	IrpSp			  = IoGetCurrentIrpStackLocation(Irp);
	UserBufferLength  = IrpSp->Parameters.QueryEa.Length;
	pFileObject		  = IrpSp->FileObject;

	if(!PfpFileObjectHasOurFCB(pFileObject))
	{		
		return SpyPassThrough(VolumeDeviceObject,Irp);
	}
	FsRtlEnterFileSystem();
	pFcb = (PPfpFCB)pFileObject->FsContext;

	ASSERT(pFcb->pDiskFileObject);
	pDiskFileObeject = pFcb->pDiskFileObject;

	
	ASSERT(pDiskFileObeject);

	EaBuffer		  = PfpMapUserBuffer(Irp);

	pEaBuf			  = ExAllocatePoolWithTag(NonPagedPool,UserBufferLength,FILESPY_POOL_TAG);
	if(pEaBuf== NULL)
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES;
		Irp->IoStatus.Status = ntstatus;
		goto ONERROR;
	}

		
	RtlCopyMemory(pEaBuf,EaBuffer,UserBufferLength);

	ntstatus = ZwSetEaFile(    pDiskFileObeject->hFileWriteThrough,
					&IoStatusBlock,
					pEaBuf,
					UserBufferLength
					);

	 if(NT_SUCCESS(ntstatus))
	 {
		 Irp->IoStatus = IoStatusBlock;
	 }else
	 {
		Irp->IoStatus.Status = ntstatus;
	 }
	
	 
ONERROR:
	if(pEaBuf)
	{
		ExFreePool(pEaBuf);
		pEaBuf =NULL;
	}
	
	IoCompleteRequest(Irp, IO_DISK_INCREMENT );
	FsRtlExitFileSystem();
	return ntstatus;
}

NTSTATUS
PfpFsdQueryEa (
			   IN PDEVICE_OBJECT VolumeDeviceObject,
			   IN PIRP Irp
			   )
{
	PDISKFILEOBJECT			pDiskFileObeject; 
	
	IO_STATUS_BLOCK			IoStatusBlock;
	PIO_STACK_LOCATION		IrpSp;
	PFILE_FULL_EA_INFORMATION EaBuffer;
	ULONG					UserBufferLength;
	PFILE_GET_EA_INFORMATION UserEaList;
	ULONG					UserEaListLength;
	ULONG					UserEaIndex;
	BOOLEAN					RestartScan;
	BOOLEAN					ReturnSingleEntry;
	BOOLEAN					IndexSpecified;
	PVOID					pEaBuf	=  NULL;
	PVOID					pEaList =  NULL;
	NTSTATUS				ntstatus;
	PPfpFCB					pFcb;
	PFILE_OBJECT			pFileObject;
	PERESOURCE				pDeviceResource= NULL;
	UNREFERENCED_PARAMETER(VolumeDeviceObject);	

	IrpSp			  = IoGetCurrentIrpStackLocation(Irp);
	UserBufferLength  = IrpSp->Parameters.QueryEa.Length;
	UserEaList        = (PFILE_GET_EA_INFORMATION) IrpSp->Parameters.QueryEa.EaList;
	UserEaListLength  = IrpSp->Parameters.QueryEa.EaListLength;
	UserEaIndex       = IrpSp->Parameters.QueryEa.EaIndex;
	RestartScan       = BooleanFlagOn(IrpSp->Flags, SL_RESTART_SCAN);
	ReturnSingleEntry = BooleanFlagOn(IrpSp->Flags, SL_RETURN_SINGLE_ENTRY);
	IndexSpecified    = BooleanFlagOn(IrpSp->Flags, SL_INDEX_SPECIFIED);
	pFileObject		  = IrpSp->FileObject;

	if(!PfpFileObjectHasOurFCB(pFileObject))
	{
		return SpyPassThrough(VolumeDeviceObject,Irp);
	}
	FsRtlEnterFileSystem();
	pFcb = (PPfpFCB)pFileObject->FsContext;

	ASSERT(pFcb->pDiskFileObject);
	pDiskFileObeject = pFcb->pDiskFileObject;


	ASSERT(pDiskFileObeject);


	EaBuffer = PfpMapUserBuffer(Irp);

	pEaBuf	= ExAllocatePoolWithTag(NonPagedPool,UserBufferLength,FILESPY_POOL_TAG);
	if(pEaBuf== NULL)
	{
		Irp->IoStatus.Status= ntstatus = STATUS_INSUFFICIENT_RESOURCES;
		goto ONERROR;
	}
	
	if(UserEaListLength==0 ||UserEaList == NULL)
	{
		pEaList = NULL;
		UserEaListLength = 0;
	}else
	{
		pEaList	= ExAllocatePoolWithTag(NonPagedPool,UserEaListLength,FILESPY_POOL_TAG);

		if(pEaList== NULL)
		{
			Irp->IoStatus.Status=ntstatus = STATUS_INSUFFICIENT_RESOURCES;
			goto ONERROR;
		}
		RtlCopyMemory(pEaList,UserEaList,UserEaListLength);
	}
	
	
	ntstatus = ZwQueryEaFile(  pDiskFileObeject->hFileWriteThrough,
						&IoStatusBlock,
						pEaBuf,
						UserBufferLength,
						ReturnSingleEntry,
						pEaList,
						UserEaListLength,
						&UserEaIndex,
						RestartScan);

	if(NT_SUCCESS(ntstatus )&& IoStatusBlock.Information != 0)
	{
		RtlCopyMemory(EaBuffer,pEaBuf,IoStatusBlock.Information);
		Irp->IoStatus = IoStatusBlock;
	}
	

	Irp->IoStatus = IoStatusBlock;
	Irp->IoStatus .Status = ntstatus;
ONERROR:

	if(pEaList)
	{
		ExFreePool(pEaList);
		pEaList = NULL;
	}
	if(pEaBuf)
	{
		ExFreePool(pEaBuf);
		pEaBuf =NULL;
	}
	IoCompleteRequest(Irp, IO_DISK_INCREMENT );
	FsRtlExitFileSystem();
	return ntstatus;
}