#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "UsbSecure.h"
VOID PfpInitUsbSecureS(IN PVOID pBuffer,IN ULONG llen)
{
	LONG nLeft = llen;
	PUSBSECURE pSecure = NULL;
	ExAcquireFastMutex(&g_UsbMutex);
	while(pSecure =PfpCreateOneSecureFromBuffer(pBuffer,nLeft))
	{
		nLeft-= *(ULONG*)pBuffer;
		
		(PUCHAR)pBuffer+=*(ULONG*)pBuffer;
		
		InsertHeadList(&g_UsbSecureListHead,&pSecure->List);

		if(nLeft<=0)
			break;
	}
	ExReleaseFastMutex(&g_UsbMutex);
}

VOID PfpWriteUsbSecurIntoBuffer(IN OUT PVOID pBuffer,IN OUT ULONG * pLLen)//pLLen 在返回的时候 存放的是Buffer 剩下的大小
{
	PUSBSECURE pUsbSecure = NULL;
	PLIST_ENTRY pListtemp =  NULL;
	PLIST_ENTRY pListHead =  NULL;
	ULONG		nLenReturned = 0;
	ULONG		nLenUsed = 0;
	if(IsListEmpty(&g_UsbSecureListHead))
		return  ;

	ExAcquireFastMutex(&g_UsbMutex);

	for(pListtemp  = g_UsbSecureListHead.Blink;pListtemp  != &g_UsbSecureListHead  ; pListtemp= pListtemp->Blink)
	{
		pUsbSecure = CONTAINING_RECORD(pListtemp,USBSECURE,List);
		//if(pUsbSecure-> nControlStatu!=3)
		{
			nLenUsed   = PfpPutOneSecureIntoBuffer(pBuffer,*pLLen,pUsbSecure);
			(PUCHAR)pBuffer+=nLenUsed  ;
			*pLLen-=nLenUsed  ;
		}
	}

	ExReleaseFastMutex(&g_UsbMutex);	
}

ULONG PfpGetUsbSecurLenForSave()
{
	PUSBSECURE pUsbSecure = NULL;
	PLIST_ENTRY pListtemp =  NULL;
	PLIST_ENTRY pListHead =  NULL;
	ULONG		nLenReturned = 0;
	if(IsListEmpty(&g_UsbSecureListHead))
		return 0;

	ExAcquireFastMutex(&g_UsbMutex);
	
	for(pListtemp  = g_UsbSecureListHead.Blink;pListtemp  != &g_UsbSecureListHead  ; pListtemp= pListtemp->Blink)
	{
		pUsbSecure = CONTAINING_RECORD(pListtemp,USBSECURE,List);
		//if(pUsbSecure->nControlStatu!=3)// 保存下 所有的 usb 的分区信息
		{
			nLenReturned +=PfpCalcOneUsbSecureSpaceForSaving(pUsbSecure );
		}
	}

	ExReleaseFastMutex(&g_UsbMutex);
	return nLenReturned ;
}
BOOLEAN PfpQueryUsbControlStatus(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen,BOOLEAN* pbEncryptALL,ULONG * pControlStatus)
{
	PUSBSECURE pUsbSecure = NULL;
 
	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL) 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}

	*pbEncryptALL   = pUsbSecure->bEncryptAll;
	*pControlStatus = pUsbSecure->nControlStatu;

	ExReleaseFastMutex(&g_UsbMutex);
	return TRUE;
}

BOOLEAN PfpQueryUsbFileTypesLen(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen,ULONG *nLen)//nLen 返回的时候 是记录 要使用多少
{
	PUSBSECURE pUsbSecure	= NULL;
	*nLen		= 0;
	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL  ) 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}
	
	*nLen = PfpGetFileTypeLenForOneSecure(pUsbSecure);
	ExReleaseFastMutex(&g_UsbMutex);
	return TRUE;
}
BOOLEAN PfpQueryUsbFileTypes(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen,IN WCHAR *pszBuffer,ULONG *nLen)
{
	PUSBSECURE pUsbSecure = NULL;
	ULONG	   nOrignalLen = *nLen;
	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL ) 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}

	PfpCopyUsbFileTypesIntoBuffer(pUsbSecure  ,pszBuffer,nLen);
	ExReleaseFastMutex(&g_UsbMutex);
	return (nOrignalLen != *nLen);
}

BOOLEAN PfpSetUsbFileEncryptType(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen,BOOLEAN bEncryptForce)
{

	PUSBSECURE pUsbSecure = NULL;

	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL ) 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}
	pUsbSecure->bEncryptAll = bEncryptForce;

	ExReleaseFastMutex(&g_UsbMutex);
	return TRUE;
}

BOOLEAN 
PfpQueryUsbFileEncryptType(	
						   IN ULONG VolumeID,
						   IN CHAR* pszDeviceID,
						   IN ULONG idLen,
						   ULONG*   bEncryptForce)
{
	PUSBSECURE pUsbSecure = NULL;

	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL||pUsbSecure->nControlStatu==3) 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}
	*bEncryptForce = (pUsbSecure->bEncryptAll?1:0) ;

	ExReleaseFastMutex(&g_UsbMutex);
	return TRUE;
}
BOOLEAN PfpSetUsbControlSTATUS(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen,USBControlSTATUS controlStatus)//3 没有配置的这个值 应该不能出现在这个参数中！因为3表示一种状态 没有设置过的状态 
{

	PUSBSECURE pUsbSecure = NULL;
	
	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL) 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}
	pUsbSecure->nControlStatu = controlStatus;

	ExReleaseFastMutex(&g_UsbMutex);
	return TRUE;

}
//所以当
BOOLEAN PfpSetUsbEncryptionFileTypes(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen,WCHAR *szFileTypes,ULONG nLen)
{
	PUSBSECURE pUsbSecure = NULL;
	PWCHAR     pszTemp = szFileTypes;

	if(pszTemp == NULL ||nLen==0)
		return FALSE;

	ExAcquireFastMutex(&g_UsbMutex);
	pUsbSecure  = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);

	if(pUsbSecure  == NULL )//没有初始化 
	{
		ExReleaseFastMutex(&g_UsbMutex);
		return FALSE;
	}
	PfpDeleteUsbFileTypeForOneSecure(pUsbSecure);
	PfpAddUsbFileTypesIntoOneSecure(pUsbSecure,szFileTypes,nLen);
	ExReleaseFastMutex(&g_UsbMutex);
	return TRUE;
}

ULONG   PfpQueryUsbConfigNum()
{
	LIST_ENTRY *plistHead = &g_UsbSecureListHead;
	LIST_ENTRY *pList	  = NULL;
	ULONG		nNum	  = 0;
	PUSBSECURE pUsbSecure = NULL;
	
	if(IsListEmpty(plistHead)) return 0;


	ExAcquireFastMutex(&g_UsbMutex);
	for(pList = plistHead->Blink ; pList !=plistHead;pList= pList->Blink)
	{
		pUsbSecure = CONTAINING_RECORD(pList,USBSECURE ,List) ;
		if(pUsbSecure /*&& pUsbSecure->pUsbVolumeDevice!= NULL*/ )
		{
			nNum++;
		}
	}	
	ExReleaseFastMutex(&g_UsbMutex);
	return nNum;
}
BOOLEAN PfpQueryAllUsbIDs(IN OUT PVOID pBuf,IN ULONG*  pLeft)
{
	LIST_ENTRY *plistHead = &g_UsbSecureListHead;
	LIST_ENTRY *pList	  = NULL;
	PUSBSECURE pUsbSecure = NULL;
	ULONG		nLenOrignal = *pLeft;
	PUSBQUERYIDS pUsbIDs = (PUSBQUERYIDS )pBuf;

	if(pUsbIDs == NULL)
		return FALSE;
	if(nLenOrignal ==0) 
		return FALSE;

	if(*pLeft <sizeof(USBQUERYIDS)) return FALSE;

	ExAcquireFastMutex(&g_UsbMutex);
	for(pList = plistHead->Blink ; pList !=plistHead;pList= pList->Blink)
	{
		pUsbSecure = CONTAINING_RECORD(pList,USBSECURE ,List) ;
		if(pUsbSecure)
		{
			pUsbIDs->VolumeID= pUsbSecure->VolumeID;
			memcpy(pUsbIDs->DeviceID,pUsbSecure->pszDeviceID,min(199,pUsbSecure->nLen));
			pUsbIDs->DeviceID[min(199,pUsbSecure->nLen)]=0;
			*pLeft = (*pLeft-sizeof(USBQUERYIDS));
			if(*pLeft <sizeof(USBQUERYIDS))
				break;
			pUsbIDs= (PUSBQUERYIDS)((PUCHAR)pUsbIDs+sizeof(USBQUERYIDS));
		}
	}	
	ExReleaseFastMutex(&g_UsbMutex);
	return (nLenOrignal!=*pLeft );
}

//下面的函数是内部使用的
PUSBSECURE PfpGetUsbSecure(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen)
{
	LIST_ENTRY *plistHead = &g_UsbSecureListHead;
	LIST_ENTRY *pList	  = NULL;
	PUSBSECURE pUsbSecure = NULL;
	PUSBSECURE pUsbItem   = NULL;

	if(IsListEmpty(plistHead)) return NULL;

	 
	for(pList = plistHead->Blink ; pList !=plistHead;pList= pList->Blink)
	{
		pUsbSecure = CONTAINING_RECORD(pList,USBSECURE ,List) ;
		if(pUsbSecure /*&&  !pUsbSecure->bDelete*/)
		{
			if(pUsbSecure ->VolumeID== VolumeID && pUsbSecure->nLen== idLen && memcmp(pUsbSecure->pszDeviceID,pszDeviceID,idLen)==0)
			{
				pUsbItem    = pUsbSecure ;
				break;
			}
		}
	}	
	 
	return pUsbItem    ;
}
BOOLEAN    PfpIsUsbConnectd(PUSBSECURE  pUsbSecure)
{
	ASSERT(pUsbSecure);
	if(pUsbSecure== NULL) return FALSE;
	return (pUsbSecure->pUsbVolumeDevice!= NULL);
}

BOOLEAN PfpCopyUsbFileTypesIntoBuffer(PUSBSECURE  pUsbSecure,PVOID pVOID,ULONG * nSize)
{
	LIST_ENTRY *plistHead = NULL;
	LIST_ENTRY *pListItem = NULL;	
	PFILETYPEFORUSB pFiletype = NULL;
	PWCHAR	   pWchar = NULL;
	pWchar  = (PWCHAR)pVOID;
	if(pUsbSecure== NULL ||pVOID== NULL ||*nSize==0) return FALSE;
	
	ExAcquireFastMutex(&pUsbSecure->FileTypesLock);
	plistHead  = &pUsbSecure->FileTypeListHead;

	for(pListItem  = plistHead->Blink;pListItem !=plistHead  ;pListItem  = pListItem->Blink )
	{
		pFiletype = CONTAINING_RECORD(pListItem,FILETYPEFORUSB ,list);
		if(*nSize<(wcslen(pFiletype->szFileType)+1)*sizeof(WCHAR))
			break;
		memcpy(pWchar,pFiletype ->szFileType,wcslen(pFiletype ->szFileType)<<1);
		pWchar+=wcslen(pFiletype ->szFileType);
		*pWchar=L'|';
		pWchar++;
		*nSize= *nSize-((1+wcslen(pFiletype ->szFileType))<<1);
	}

	ExReleaseFastMutex(&pUsbSecure->FileTypesLock);
	return TRUE;
}
ULONG PfpGetFileTypeLenForOneSecure(PUSBSECURE  pUsbSecure)
{
	LIST_ENTRY *plistHead = NULL;
	LIST_ENTRY* pListItem = NULL;	
	PFILETYPEFORUSB pFiletype = NULL;
	ULONG		nSizeInBytes = 0;
	if(pUsbSecure==NULL) return 0;

	plistHead  = &pUsbSecure->FileTypeListHead;
	
	ExAcquireFastMutex(&pUsbSecure->FileTypesLock);
	for(pListItem  = plistHead->Blink;pListItem !=plistHead  ;pListItem  = pListItem->Blink )
	{
		pFiletype = CONTAINING_RECORD(pListItem,FILETYPEFORUSB ,list);
		nSizeInBytes +=((wcslen(pFiletype->szFileType)+1)<<1);	
	}
	ExReleaseFastMutex(&pUsbSecure->FileTypesLock);
	return nSizeInBytes ;
}
VOID PfpDeleteUsbFileTypeForOneSecure(PUSBSECURE  pUsbSecure)
{
	LIST_ENTRY *plistHead	= NULL;
	LIST_ENTRY *pTemp		= NULL;
	PFILETYPEFORUSB pUsbFileType =NULL;
	if(pUsbSecure== NULL) return ;
	
	if(IsListEmpty(&pUsbSecure->FileTypeListHead)) return ;
	plistHead	 = &pUsbSecure->FileTypeListHead;

	ExAcquireFastMutex(&pUsbSecure->FileTypesLock);
	for(pTemp = plistHead->Blink ;pTemp!= plistHead;)
	{
		pUsbFileType  = CONTAINING_RECORD(pTemp,FILETYPEFORUSB,list );
		pTemp = pTemp->Blink;
		RemoveEntryList(&pUsbFileType->list);
		ExFreePool_A(pUsbFileType );
	}
	ExReleaseFastMutex(&pUsbSecure->FileTypesLock);
}


VOID PfpAddUsbFileTypesIntoOneSecure(PUSBSECURE  pUsbSecure,PWCHAR pszFileTypes,ULONG nLen)
{
	PWCHAR pszTemp = pszFileTypes;
	ULONG  nIndex  = 0;
	PFILETYPEFORUSB pUserFileType = NULL;
	nLen = (nLen>>1);
	if(pszTemp == NULL ||nLen==0) 
		return ;
	
	ExAcquireFastMutex(&pUsbSecure->FileTypesLock);
	while(((ULONG)(pszTemp-pszFileTypes)<nLen) && pszTemp[nIndex]!=L'\0' )
	{
		if(pszTemp[nIndex]== L'|')
		{
			if(nIndex!=0)
			{
				pUserFileType = ExAllocatePool_A(PagedPool,sizeof(FILETYPEFORUSB));
				memcpy(pUserFileType ->szFileType,pszTemp,min(49,nIndex)<<1);
				pUserFileType ->szFileType[min(49,nIndex)]=0;
				InsertHeadList(&pUsbSecure->FileTypeListHead,&pUserFileType ->list);
			}
			nIndex++;
			pszTemp= &pszTemp[nIndex];
			nIndex=0;

		}else
		{
			nIndex++;
		}
	}
	ExReleaseFastMutex(&pUsbSecure->FileTypesLock);
}

ULONG PfpCalcOneUsbSecureSpaceForSaving(PUSBSECURE pSecureItem)
{
	ULONG nReturned =0;
	nReturned+=sizeof(ULONG);//每个secureitem 的头4个字节存放一共的大小
	nReturned +=sizeof(ULONG);//encryptall
	nReturned +=sizeof(ULONG);//deviceid 's num 's space
	nReturned +=sizeof(ULONG);//deviceio nlen size
	nReturned +=pSecureItem->nLen;//device id len
	nReturned +=sizeof(ULONG);//volume id
	nReturned +=sizeof(USBControlSTATUS  );
	nReturned += 10<<1;//driver letter
	nReturned += 40<<1;//driver letter
	nReturned += sizeof(ULONG);//filetype's num's space;
	nReturned += PfpGetFileTypeLenForOneSecure(pSecureItem);
	nReturned = (nReturned+7)&~7;
	return nReturned ;
}

ULONG PfpPutOneSecureIntoBuffer(PVOID pBuf,ULONG nLen,PUSBSECURE  pUsbSecure)
{
	ULONG nLeft = 0;
	ULONG nLenForFileType = 0;
	PVOID pBufTemp= pBuf;
	ULONG  nLenOfSecureItem = (7*sizeof(ULONG)+100)+pUsbSecure->nLen+(nLenForFileType =PfpGetFileTypeLenForOneSecure(pUsbSecure));
	nLenOfSecureItem= (nLenOfSecureItem+7)&~7;
	if(nLen< nLenOfSecureItem)
	{
		return 0;
	}
	*(PULONG)pBufTemp = nLenOfSecureItem;
	(PUCHAR)pBufTemp+=sizeof(ULONG);//头开始的四个字节用来存放 总共的大小
	*(ULONG*)pBufTemp = (pUsbSecure->bEncryptAll?1:0);
	(PUCHAR)pBufTemp+=sizeof(ULONG);
	*(ULONG*)pBufTemp = pUsbSecure->nLen;
	(PUCHAR)pBufTemp +=sizeof(ULONG);
	memcpy((PUCHAR)pBufTemp ,pUsbSecure->pszDeviceID,pUsbSecure->nLen);
	(PUCHAR)pBufTemp +=pUsbSecure->nLen;
	
	*(ULONG*)pBufTemp =pUsbSecure->VolumeID;
	(PUCHAR)pBufTemp +=sizeof(ULONG);

	*(ULONG*)pBufTemp =pUsbSecure->nControlStatu;
	(PUCHAR)pBufTemp +=sizeof(ULONG);

	memcpy((PUCHAR)pBufTemp ,pUsbSecure->DriverLetter,10<<1);
	(PUCHAR)pBufTemp +=10<<1;
	

	memcpy((PUCHAR)pBufTemp ,pUsbSecure->DriverDescription,40<<1);
	(PUCHAR)pBufTemp +=40<<1;

	*(ULONG*)pBufTemp =nLenForFileType;
	(PUCHAR)pBufTemp +=sizeof(ULONG);

	
	//nLeft = nLen -(ULONG)((PUCHAR)pBufTemp -(PUCHAR)pBuf)-nLenForFileType ;
	//*(ULONG*)pBuf = (nLenForFileType +(ULONG)((PUCHAR)pBufTemp -(PUCHAR)pBuf) );
	
	
	PfpCopyUsbFileTypesIntoBuffer(pUsbSecure,pBufTemp,&nLenForFileType);
	

	return *(ULONG*)pBuf ;
}	

PUSBSECURE PfpCreateOneSecureFromBuffer(PVOID pBuf,ULONG nBufLen)
{
	PUSBSECURE pSecure = NULL;
	PUSBSECURE pSecureSecond = NULL;
	ULONG		nLenForFiletype = 0;
	if(nBufLen<(7*sizeof(ULONG)+100))
		return NULL;
	
	if(nBufLen<*(ULONG*)pBuf)return NULL;

	pSecure = ExAllocatePoolWithTag(NonPagedPool,sizeof(USBSECURE),'Pfp1');
	
	if(pSecure == NULL) return NULL;
	
	(PUCHAR)pBuf += sizeof(ULONG);

	pSecure->bEncryptAll = (*(PULONG)pBuf!=0)?TRUE:FALSE;
	(PUCHAR)pBuf+=sizeof(ULONG);

	pSecure->nLen = *(ULONG*)pBuf;
	(PUCHAR)pBuf+=sizeof(ULONG);
	
	pSecure->pszDeviceID = ExAllocatePool_A(PagedPool,pSecure->nLen +2);
	if(pSecure->pszDeviceID )
	{
		memset(pSecure->pszDeviceID,0,pSecure->nLen +2);
		memcpy(pSecure->pszDeviceID,(PUCHAR)pBuf,pSecure->nLen );
	}
	 
	(PUCHAR)pBuf+=pSecure->nLen ;

	pSecure->VolumeID = *(ULONG*)pBuf;
	(PUCHAR)pBuf+=sizeof(ULONG);

	pSecure->nControlStatu = *(ULONG*)pBuf;;
	(PUCHAR)pBuf+=sizeof(ULONG);

	memcpy(pSecure->DriverLetter,pBuf,20);
	(PUCHAR)pBuf+=20;

	memcpy(pSecure->DriverDescription,pBuf,80);
	(PUCHAR)pBuf+=80;
	pSecure->pUsbDevice =  NULL;
	pSecure->pUsbVolumeDevice = NULL;
	nLenForFiletype  = *(ULONG*)pBuf;
	(PUCHAR)pBuf+=sizeof(ULONG);
	InitializeListHead(&pSecure->FileTypeListHead);
	ExInitializeFastMutex(&pSecure->FileTypesLock);
	PfpAddUsbFileTypesIntoOneSecure(pSecure,pBuf,nLenForFiletype);
	 
	pSecureSecond = PfpGetUsbSecure(pSecure->VolumeID,pSecure->pszDeviceID,pSecure->nLen);
	if(pSecureSecond )
	{
		pSecure->pUsbVolumeDevice = pSecureSecond->pUsbVolumeDevice;
		RemoveEntryList(&pSecureSecond->List);		
		PfpDeleteUsbSecureMemory(pSecureSecond);
		
	}
	//InsertHeadList(&g_UsbSecureListHead,&pSecure->List);
	 
	return pSecure;
}
VOID PfpDeleteUsbSecureMemory(IN PUSBSECURE pUsbSecure)
{
	LIST_ENTRY* tmpListEntry = NULL;
	LIST_ENTRY* headListEntry = NULL;
	PFILETYPEFORUSB  pFileTypeItem = NULL;

	if(pUsbSecure == NULL) return ;

	if(IsListEmpty(&pUsbSecure->FileTypeListHead)) return ;

	headListEntry  = &pUsbSecure->FileTypeListHead;
	tmpListEntry   = headListEntry->Flink;
	while (tmpListEntry!= headListEntry)
	{
		pFileTypeItem  = CONTAINING_RECORD(tmpListEntry,FILETYPEFORUSB,list);
		tmpListEntry	= tmpListEntry->Flink;

		RemoveEntryList(&pFileTypeItem->list);
		ExFreePool_A(pFileTypeItem);
	};
	ExFreePool_A(pUsbSecure->pszDeviceID);
	ExFreePool_A(pUsbSecure);
}
VOID PfpDeleteUsbSecure(IN ULONG VolumeID,IN CHAR* pszDeviceID,IN ULONG idLen)
{
	LIST_ENTRY *plistHead = &g_UsbSecureListHead;
	LIST_ENTRY *pList	  = NULL;
	PUSBSECURE pUsbSecure = NULL;
	PUSBSECURE pUsbItem   = NULL;

	if(IsListEmpty(plistHead)) return  ;

	ExAcquireFastMutex(&g_UsbMutex);
	    
	pUsbItem = PfpGetUsbSecure(VolumeID,pszDeviceID,idLen);
	
	if(pUsbItem /*&& pUsbItem ->nControlStatu!=3*/)
	{
		RemoveEntryList(&pUsbItem->List);		
		PfpDeleteUsbSecureMemory(pUsbItem);
	}
		
	ExReleaseFastMutex(&g_UsbMutex);
	 
}


BOOLEAN GetUsbStorageDeviceID(UCHAR ** pszId,ULONG * nLen,IN PDEVICE_OBJECT DeviceObject)
{
	PIRP NewIrp;
	STORAGE_DEVICE_ID_DESCRIPTOR *Descriptor;
	STORAGE_PROPERTY_QUERY Query;

	KEVENT WaitEvent;
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatus;

	* pszId = NULL;
	* nLen   = 0;
	// first set the query properties
	Query.PropertyId = StorageDeviceUniqueIdProperty;
	Query.QueryType = PropertyStandardQuery;

	Descriptor = ExAllocatePoolWithTag(NonPagedPool,sizeof(STORAGE_DEVICE_ID_DESCRIPTOR)+256,'Pfp2');

	// initialize the waitable event
	KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

	// we should build the query irp ourselves
	NewIrp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY, DeviceObject, 
		(PVOID)&Query, sizeof(Query), (PVOID)Descriptor,256+ sizeof(STORAGE_DEVICE_ID_DESCRIPTOR), FALSE, &WaitEvent, &IoStatus);

	if (NULL == NewIrp)    // can't create new irp
	{
		return FALSE;
	}

	// send this irp to the storage device
	Status = IoCallDriver(DeviceObject, NewIrp);

	if (Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if(NT_SUCCESS(Status))
	{
		pszId= ExAllocatePoolWithTag(NonPagedPool,Descriptor->NumberOfIdentifiers+1,'Pfp3');
		if(pszId== NULL)
		{
			ExFreePool_A(Descriptor);
			return FALSE;
		}
		memcpy(pszId,Descriptor->Identifiers,Descriptor->NumberOfIdentifiers);
		pszId[Descriptor->NumberOfIdentifiers]=0;
		*nLen = Descriptor->NumberOfIdentifiers;
	}
	ExFreePool_A(Descriptor);
	return NT_SUCCESS(Status);
}

ULONG GetStorageDeviceBusType(IN PDEVICE_OBJECT DeviceObject,UCHAR ** pszId,ULONG * nLen)
{
	

	PIRP NewIrp;
	STORAGE_DEVICE_DESCRIPTOR *Descriptor;
	STORAGE_PROPERTY_QUERY Query;
	STORAGE_BUS_TYPE BusType ;
	//CHAR Buffer[BUFFER_SIZE];
	KEVENT WaitEvent;
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatus;
	return (ULONG)FALSE;
	// first set the query properties
	Query.PropertyId = StorageDeviceProperty;
	Query.QueryType = PropertyStandardQuery;
	*pszId = NULL;
	*nLen = 0;
	// initialize the waitable event
	KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);
	Descriptor = ExAllocatePoolWithTag(PagedPool,sizeof(STORAGE_DEVICE_DESCRIPTOR)+500,'Pfp8');
	if(!Descriptor)
	{
		return BusTypeUnknown;
	}
	// we should build the query irp ourselves
	NewIrp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY, DeviceObject, 
		(PVOID)&Query, sizeof(Query), (PVOID)Descriptor, 500+sizeof(STORAGE_DEVICE_DESCRIPTOR), FALSE, &WaitEvent, &IoStatus);

	if (NULL == NewIrp)    // can't create new irp
	{
		ExFreePool_A(Descriptor);
		return BusTypeUnknown;
	}

	// send this irp to the storage device
	Status = IoCallDriver(DeviceObject, NewIrp);

	if (Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if (!NT_SUCCESS(Status))
	{	
		ExFreePool_A(Descriptor);
		return BusTypeUnknown;
	}

	if(Descriptor->ProductIdOffset!=0)
	{
		
		UCHAR *pszProducID = ((UCHAR*)Descriptor+Descriptor->ProductIdOffset);
		ULONG nLenID = strlen(pszProducID);

		*pszId= ExAllocatePoolWithTag(NonPagedPool,nLenID+1,'Ppf4');
		if(*pszId!= NULL)
		{
			memcpy(*pszId,pszProducID,nLenID);
			(*pszId)[nLenID]=0;
			*nLen = nLenID;			
		}
	}
	


	BusType =Descriptor->BusType;
	ExFreePool_A(Descriptor);

	return BusType;
}


ULONG GetVolumeSerialNumber(WCHAR* szDriverLetter)
{
	NTSTATUS					status;
	OBJECT_ATTRIBUTES			objectAttributes;
	FILE_FS_VOLUME_INFORMATION * pVolumeInfo = NULL;
	UNICODE_STRING				functionName;
	IO_STATUS_BLOCK				iostatus;
	ULONG						nSerialNum = 0;
	HANDLE						fileHandle = INVALID_HANDLE_VALUE;
	WCHAR szLetter[100]			={0};
	wcscat(szLetter,L"\\DosDevices\\");
	wcscat(szLetter,szDriverLetter);
	RtlInitUnicodeString( &functionName,szLetter);

	InitializeObjectAttributes( &objectAttributes,
		&functionName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL );

	//
	//  Open the file object for the given device.
	//

	status = ZwCreateFile( &fileHandle,
		SYNCHRONIZE|FILE_READ_DATA,
		&objectAttributes,
		&iostatus,
		NULL,
		0,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0 );
	if(NT_SUCCESS(status))
	{
		pVolumeInfo  = ExAllocatePoolWithTag(PagedPool,sizeof(FILE_FS_VOLUME_INFORMATION)+256,'Pfp7');
		if(!pVolumeInfo  )
			goto EXIT;

		status=ZwQueryVolumeInformationFile(fileHandle,
			&iostatus,
			pVolumeInfo,
			sizeof(FILE_FS_VOLUME_INFORMATION)+256,
			FileFsVolumeInformation);
		if(NT_SUCCESS(status))
		{
			nSerialNum = ((FILE_FS_VOLUME_INFORMATION*)pVolumeInfo)-> VolumeSerialNumber;
		}
	}
EXIT:
	if(fileHandle!= INVALID_HANDLE_VALUE)
	{
		ZwClose(fileHandle);
	}
	if(pVolumeInfo)
		ExFreePool_A(pVolumeInfo);

	return nSerialNum;
}


VOID PfpInitUsbDeviceWithSecure(PDEVICE_OBJECT pOurDevice)
{
	//_USB_DEVICE_INITIALIZE_WORKITEM* completionContext;
	HANDLE handle = INVALID_HANDLE_VALUE;
	PFILESPY_DEVICE_EXTENSION DevExt	= pOurDevice->DeviceExtension;
	if(!DevExt ->bUsbDevice)
	{
		return ;
	}
	
	ObReferenceObject( pOurDevice );
	KdPrint(("send message to thread\r\n"));
	 
	
	PsCreateSystemThread(&handle ,
		THREAD_ALL_ACCESS ,
		NULL,
		NULL,
		NULL,
		PfpUsbInitSecureWorker,
		pOurDevice
		);
	//
	//  Mount manager could be on the call stack below us holding
	//  a lock.  NLPGetDosDeviceNameWorker will eventually query the mount
	//  manager which will cause a deadlock in this scenario.
	//  So, we need to do this work in a worker thread.
	//

	/*completionContext = (_USB_DEVICE_INITIALIZE_WORKITEM*)ExAllocatePool_A( NonPagedPool,
											sizeof( _USB_DEVICE_INITIALIZE_WORKITEM ));

	if (completionContext != NULL) 
	{

		//
		//  Initialize a work item.  CompletionContext keeps track
		//  of the work queue item and the data that we need
		//  to pass to NLPGetDosDeviceNameWorker in the worker thread.
		//

		ExInitializeWorkItem( &completionContext->WorkItem,
								PfpUsbInitSecureWorker,
								completionContext );

		//
		//  Don't let the DeviceObject get deleted while we get the DOS
		//  device name asynchronously.
		//

		ObReferenceObject( pOurDevice );

		//
		//  Setup the context.
		//

		completionContext->DeviceObject = pOurDevice;
		//completionContext->NLExtHeader = NLExtHeader;

		//
		//  Queue the work item so that it will be run in a
		//  worker thread at some point.
		//
		KdPrint(("send message to thread\r\n"));
		ExQueueWorkItem( &completionContext->WorkItem ,DelayedWorkQueue );
	}*/
}


VOID
PfpUsbInitSecureWorker (
						/*__in PUSB_DEVICE_INITIALIZE_WORKITEM Context*/
						PVOID  Context
						)
{
	WCHAR			szDriverLetter[3]	= {0};
	PDEVICE_OBJECT  pOurDevice			=(PDEVICE_OBJECT) Context ;/*Context->DeviceObject;*/
	PUSBSECURE      pUsbSecItem			= NULL;
	PFILESPY_DEVICE_EXTENSION DevExt	= pOurDevice->DeviceExtension;
	UNICODE_STRING	DosName;
	NTSTATUS		status;
	if(!PfpGetDeviceLetter(pOurDevice ,szDriverLetter))
	{
		DosName.Buffer=NULL;
		status = IoVolumeDeviceToDosName( DevExt->NLExtHeader.StorageStackDeviceObject,
			&DosName);
		if(!NT_SUCCESS(status ))
		{
			KdPrint(("Failed to get dos name from IoVolumeDeviceToDosName \r\n"));
			ObDereferenceObject(pOurDevice);
			return ;
		}else
		{
			KdPrint(("Get dos name from IoVolumeDeviceToDosName \r\n"));
			memcpy(szDriverLetter,DosName.Buffer,2*sizeof(WCHAR));
			ExFreePool(DosName.Buffer);
		}
	}
	

	KdPrint(("receved message \r\n"));


	DevExt->nSerialNumber = GetVolumeSerialNumber(szDriverLetter);
	
	pUsbSecItem = PfpGetUsbSecure(DevExt->nSerialNumber,DevExt->pszUsbDiskSeriNUM,DevExt->nLenExcludeTermiter);
	if(	pUsbSecItem == NULL)
	{
		pUsbSecItem = ExAllocatePoolWithTag(NonPagedPool,sizeof(USBSECURE),'Pfp5');

		if(pUsbSecItem == NULL)
		{
			 
			ExFreePool_A(Context);
			ObDereferenceObject(pOurDevice);

			return ;
		}

		pUsbSecItem->bEncryptAll = TRUE;

		pUsbSecItem->nLen = DevExt->nLenExcludeTermiter;

		pUsbSecItem->pszDeviceID = ExAllocatePool_A(PagedPool,DevExt->nLenExcludeTermiter +2);

		if(pUsbSecItem->pszDeviceID )
		{
			memset(pUsbSecItem->pszDeviceID,0,DevExt->nLenExcludeTermiter +2);
			memcpy(pUsbSecItem->pszDeviceID,DevExt->pszUsbDiskSeriNUM,DevExt->nLenExcludeTermiter );			
		}

		pUsbSecItem->VolumeID =DevExt-> nSerialNumber;

		pUsbSecItem->nControlStatu = 2;//代表没有初始化
		 
		memcpy(pUsbSecItem->DriverLetter,szDriverLetter,4);
		pUsbSecItem->DriverLetter[2]=L'\0';

		memcpy(pUsbSecItem->DriverDescription,szDriverLetter,4);
		pUsbSecItem->DriverDescription[0]=L'\0';

		ExInitializeFastMutex(&pUsbSecItem->FileTypesLock);
		InitializeListHead(&pUsbSecItem->FileTypeListHead);
		

		ExAcquireFastMutex(&g_UsbMutex);
		InsertHeadList(&g_UsbSecureListHead,&pUsbSecItem->List);
		ExReleaseFastMutex(&g_UsbMutex);
	}
	pUsbSecItem ->pUsbVolumeDevice	= pOurDevice;
	DevExt->pUsbSecureConfig		= pUsbSecItem;

	

	//ExFreePool_A(Context);
	ObDereferenceObject(pOurDevice);
	
	if(pUsbSecItem && g_UsbDeviceSignal)
	{
		KdPrint(("set event\r\n"));

		KeSetEvent(g_UsbDeviceSignal ,IO_NO_INCREMENT, FALSE);
	}else
	{
		KdPrint(("not set evnet due to (pUsbSecItem && g_UsbDeviceSignal)!= TRUE\r\n"));

	}
	PsTerminateSystemThread(0);
}


BOOLEAN  IsUsbDeviceNeedEncryption(PDEVICE_OBJECT pUsbDevice)
{
	PFILESPY_DEVICE_EXTENSION DevExt	= pUsbDevice->DeviceExtension;
	PUSBSECURE      pUsbSecItem			= DevExt->pUsbSecureConfig;

	return (pUsbSecItem && pUsbSecItem->nControlStatu==1);

}
BOOLEAN  IsFileNeedEncryptionForUsb(PDEVICE_OBJECT pDevice,WCHAR* pszFileType)
{

	PFILESPY_DEVICE_EXTENSION DevExt	= pDevice->DeviceExtension;
	PUSBSECURE      pUsbSecItem			= DevExt->pUsbSecureConfig;
	PFILETYPEFORUSB pFileTyps			= NULL;
	PLIST_ENTRY		pListHead			= NULL;
	PLIST_ENTRY		pListTemp			= NULL;
	BOOLEAN			bFound				= FALSE;
	WCHAR *			sztemp				= NULL;
	if(pUsbSecItem->bEncryptAll) return TRUE;

	if(IsListEmpty(&pUsbSecItem->FileTypeListHead))return FALSE;

	if(pszFileType== NULL) return FALSE;

	pListHead			 = &pUsbSecItem->FileTypeListHead;
	ExAcquireFastMutex(&pUsbSecItem->FileTypesLock);
	for(pListTemp = pListHead->Blink;pListTemp != pListHead;pListTemp= pListTemp->Blink)
	{
		pFileTyps = CONTAINING_RECORD(pListTemp,FILETYPEFORUSB,list);

		sztemp	= pFileTyps->szFileType;
		while(*sztemp == L'.' && *sztemp != L'\0')sztemp ++;//删除前面的‘.’符号
		while(*pszFileType == L'.' && *pszFileType != L'\0')pszFileType ++;//删除前面的‘.’符号

		if( _wcsicmp(sztemp,pszFileType)==0)
		{
			bFound =TRUE;
			break;
		}
	}
	ExReleaseFastMutex(&pUsbSecItem->FileTypesLock);
	return bFound;
}