
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"

/*
NTSTATUS
PfpSetUsbEncryptMode(IN BOOLEAN bEncryptByFileType)
{
	g_bUsbDeviceEncryptedForFileType = bEncryptByFileType;
	return STATUS_SUCCESS;
}

NTSTATUS
PfpGetUsbEncryptMode(IN OUT BOOLEAN* pbEncryptByFileType)
{
	if(pbEncryptByFileType == NULL)
		return STATUS_INVALID_PARAMETER;
	*pbEncryptByFileType = g_bUsbDeviceEncryptedForFileType ;
	return STATUS_SUCCESS;
}

NTSTATUS
PfpSetFileTypesForUsb(IN PFILETYPE_REMOVEABLEDEVICE pUsbEncryptFileTypes,
					  IN ULONG nNum)
{
	PUSBFILETYPEITEM pFileTypeItem = NULL;

	ULONG nIndex = 0;
	if(pUsbEncryptFileTypes== NULL || nNum==0)
		return STATUS_INVALID_PARAMETER;
	
	PfpRemoveALLFileTypeOfUsb();
	ExAcquireFastMutex(&g_UsbFileTypeLock);
	for(;nIndex <nNum;++nIndex)
	{
		pFileTypeItem  = ExAllocatePool_A(PagedPool,sizeof(USBFILETYPEITEM));
		if(!pFileTypeItem  )
		{
			ExReleaseFastMutex(&g_UsbFileTypeLock);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		memcpy(pFileTypeItem->szFiletype,pUsbEncryptFileTypes[nIndex].szFiletype,50*sizeof(WCHAR));
		
		InsertTailList(&g_UsbFileTypes, &pFileTypeItem->listHead);	
		
	}
	ExReleaseFastMutex(&g_UsbFileTypeLock);
	return STATUS_SUCCESS;
}

NTSTATUS
PfpGetFileTypesForUsb(IN OUT PFILETYPE_REMOVEABLEDEVICE pUsbEncryptFileTypes,
					  IN OUT ULONG* pnNum)
{
	PUSBFILETYPEITEM pFileType = NULL;
	PLIST_ENTRY pList = NULL;
	LONG nIndex = 0;
	if(pUsbEncryptFileTypes== NULL || pnNum== NULL||*pnNum== 0)return STATUS_INVALID_PARAMETER;
	
	ExAcquireFastMutex(&g_UsbFileTypeLock);

	for(pList = g_UsbFileTypes.Blink ; pList !=&g_UsbFileTypes;pList= pList->Blink)
	{
		pFileType = CONTAINING_RECORD(pList,USBFILETYPEITEM,listHead) ;
		
		if(pFileType )
		{			
			memcpy(pUsbEncryptFileTypes[nIndex].szFiletype,pFileType->szFiletype,sizeof(WCHAR)*50);
			nIndex++;
			if(nIndex==* pnNum )
				break;
		}
	}
	ExReleaseFastMutex(&g_UsbFileTypeLock);

	*pnNum = nIndex;
	return STATUS_SUCCESS;

}

NTSTATUS
PfpGetNumofFileTypesForUsb(IN OUT ULONG* pnNum)
{
	PUSBFILETYPEITEM pFileType = NULL;
	PLIST_ENTRY pList = NULL;
	
	
	if( pnNum== NULL||*pnNum== 0)return STATUS_INVALID_PARAMETER;
	*pnNum = 0;

	ExAcquireFastMutex(&g_UsbFileTypeLock);

	for(pList = g_UsbFileTypes.Blink ; pList !=&g_UsbFileTypes;pList= pList->Blink)
	{
		*pnNum ++;
	}

	ExReleaseFastMutex(&g_UsbFileTypeLock);

	
	return STATUS_SUCCESS;

}
VOID
PfpRemoveALLFileTypeOfUsb()
{
	PLIST_ENTRY pList;
	PUSBFILETYPEITEM pFileType = NULL;
	if(IsListEmpty(&g_UsbFileTypes))
		return ;
		
	ExAcquireFastMutex(&g_UsbFileTypeLock);
	
	for(pList = g_UsbFileTypes.Blink ; pList !=&g_HideObjHead;)
	{
		pFileType = CONTAINING_RECORD(pList,USBFILETYPEITEM,listHead) ;
		pList= pList->Blink;
		if(pFileType )
		{			
			RemoveEntryList(&pFileType ->listHead);
			ExFreePool(pFileType);
		}
	}
	ExReleaseFastMutex(&g_UsbFileTypeLock);
	
}*/