#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"


VOID 
PfpAddDiskFileObjectIntoDelayClose(IN WCHAR szDriver[3],
								   IN PDISKFILEOBJECT pDiskFileObject)
{
	DALAYCLOSE* pDelayClose = NULL;

	ExAcquireFastMutex(&g_DelayCloseMutex);
	pDelayClose  = ExAllocatePool_A(PagedPool,sizeof(DALAYCLOSE));
	if( pDelayClose  )
	{
		pDelayClose->nCount=5;
		memcpy(pDelayClose->szDriver,szDriver,2*sizeof(WCHAR));
		pDelayClose->szDriver[2] =L'\0';
		pDelayClose->pDiskFileObject = pDiskFileObject;
		InsertHeadList(&g_DelayCloseList,&pDelayClose->list);
	}
	ExReleaseFastMutex(&g_DelayCloseMutex);
}

PDISKFILEOBJECT 
PfpFindDiskFileObjectFromDelayClose(IN WCHAR szDriver[3],
									IN UNICODE_STRING * pFullPathWithoutDriver)
{
	LIST_ENTRY *pListEntry = NULL;
	DALAYCLOSE* pDelayClose = NULL;
	PDISKFILEOBJECT pDiskFile_Object = NULL;

	if(IsListEmpty(&g_DelayCloseList)) return NULL;

	ExAcquireFastMutex(&g_DelayCloseMutex);
	for( pListEntry  = g_DelayCloseList.Blink; pListEntry!= &g_DelayCloseList; pListEntry= pListEntry->Blink)
	{
		pDelayClose  = CONTAINING_RECORD(pListEntry,DALAYCLOSE,list);
		if(_wcsnicmp(szDriver,pDelayClose->szDriver,2)==0 && RtlEqualUnicodeString(pFullPathWithoutDriver,&pDelayClose->pDiskFileObject->FullFilePath,FALSE))
		{
			RemoveEntryList(&pDelayClose->list);
			ExReleaseFastMutex(&g_DelayCloseMutex);
			pDiskFile_Object  = pDelayClose->pDiskFileObject;
			ExFreePool(pDelayClose);
			return pDiskFile_Object;
		}
	}
	ExReleaseFastMutex(&g_DelayCloseMutex);
	return NULL;
}

VOID
PfpDeleteDiskFileObjectFromDelayCloseUnderDirByUsigObejct(PDISKDIROBEJECT pParent)
{
// 	LIST_ENTRY *pListEntry = NULL;
// 	DALAYCLOSE* pDelayClose = NULL;
// 	PDISKFILEOBJECT pDiskFile_Object = NULL;
//  
// 	ExAcquireFastMutex(&g_DelayCloseMutex);
// 	if(IsListEmpty(&g_DelayCloseList))
// 	{
// 		ExReleaseFastMutex(&g_DelayCloseMutex);
// 		return  ;
// 	}
// 
// 	for( pListEntry  = g_DelayCloseList.Blink; pListEntry!= &g_DelayCloseList; pListEntry= pListEntry->Blink)
// 	{
// 		pDelayClose  = CONTAINING_RECORD(pListEntry,DALAYCLOSE,list);
// 		if(pDelayClose ->pDiskFileObject->pParentDir==pParent)
// 		{
// 			RemoveEntryList(&pDelayClose->list);
// 			pDiskFile_Object  = pDelayClose->pDiskFileObject;
// 			{
// 				if(pDiskFile_Object->bNeedBackUp)
// 				{
// 					PfpCloseRealDiskFile(&pDiskFile_Object->hBackUpFileHandle,&pDiskFile_Object->hBackUpFileObject);
// 				}
// 				PfpCloseRealDiskFile(&(pDiskFile_Object->hFileWriteThrough),&(pDiskFile_Object->pDiskFileObjectWriteThrough));
// 				PfpDeleteFCB(&((PPfpFCB)pDiskFile_Object->pFCB));
// 				PfpDeleteDiskFileObject(&pDiskFile_Object);
// 			}
// 			ExFreePool(pDelayClose);
// 		}
// 	}
// 	ExReleaseFastMutex(&g_DelayCloseMutex);
}
VOID
PfpDeleteDiskFileObjectFromDelayCloseUnderDir(IN WCHAR szDriver[3],
											  IN UNICODE_STRING * pFullPathWithoutDriver)
{
	LIST_ENTRY *pListEntry = NULL;
	DALAYCLOSE* pDelayClose = NULL;
	PDISKFILEOBJECT pDiskFile_Object = NULL;
	BOOLEAN		bEmpty = FALSE;
	ExAcquireFastMutex(&g_DelayCloseMutex);
	if(IsListEmpty(&g_DelayCloseList))
	{
		ExReleaseFastMutex(&g_DelayCloseMutex);
		return  ;
	}

	//do{

		
		for( pListEntry  = g_DelayCloseList.Blink; pListEntry!= &g_DelayCloseList; pListEntry= pListEntry->Blink)
		{
			pDelayClose  = CONTAINING_RECORD(pListEntry,DALAYCLOSE,list);
			if(_wcsnicmp(szDriver,pDelayClose->szDriver,2)==0 && 
				(pDelayClose->pDiskFileObject->FullFilePath.Length>pFullPathWithoutDriver->Length)&& 
				_wcsnicmp(pFullPathWithoutDriver->Buffer,pDelayClose->pDiskFileObject->FullFilePath.Buffer,pFullPathWithoutDriver->Length>>1)==0)
			{
				if( pFullPathWithoutDriver->Buffer[(pFullPathWithoutDriver->Length>>1)-1]==L'\\' ||
					pDelayClose->pDiskFileObject->FullFilePath.Buffer[pFullPathWithoutDriver->Length>>1]==L'\\')
				{
					RemoveEntryList(&pDelayClose->list);
					pDiskFile_Object  = pDelayClose->pDiskFileObject;
					{
						if(pDiskFile_Object->bNeedBackUp)
						{
							PfpCloseRealDiskFile(&pDiskFile_Object->hBackUpFileHandle,&pDiskFile_Object->hBackUpFileObject);
						}
						PfpCloseRealDiskFile(&(pDiskFile_Object->hFileWriteThrough),&(pDiskFile_Object->pDiskFileObjectWriteThrough));
						PfpDeleteFCB(&((PPfpFCB)pDiskFile_Object->pFCB));
						PfpDeleteDiskFileObject(&pDiskFile_Object);
					}
					ExFreePool(pDelayClose);
					//break;
				}				
			}
		}
		ExReleaseFastMutex(&g_DelayCloseMutex);
}
// 		bEmpty  = IsListEmpty(&g_DelayCloseList);
// 
// 		ExReleaseFastMutex(&g_DelayCloseMutex);
// 		if(pDiskFile_Object)
// 		{
// 			if(pDiskFile_Object->bNeedBackUp)
// 			{
// 				PfpCloseRealDiskFile(&pDiskFile_Object->hBackUpFileHandle,&pDiskFile_Object->hBackUpFileObject);
// 			}
// 			PfpCloseRealDiskFile(&(pDiskFile_Object->hFileWriteThrough),&(pDiskFile_Object->pDiskFileObjectWriteThrough));
// 			PfpDeleteFCB(&((PPfpFCB)pDiskFile_Object->pFCB));
// 			PfpDeleteDiskFileObject(&pDiskFile_Object);
// 
// 			pDiskFile_Object  = NULL;
// 		}

	//}while(!bEmpty);
// }
// VOID
// PfpRemoveFromDelayClose(IN PDISKFILEOBJECT pDiskFileObject)
// {
// 	/*LIST_ENTRY *pListEntry = NULL;
// 	DALAYCLOSE* pDelayClose = NULL;
// 
// 	ExAcquireFastMutex(&g_DelayCloseMutex);
// 	pDelayClose 	= CONTAINING_RECORD(pDiskFileObject,DALAYCLOSE,pDiskFileObject);
// 	RemoveEntryList(&pDelayClose ->list);
// 	
// 	ExReleaseFastMutex(&g_DelayCloseMutex);
// 	if(pDelayClose)
// 	{
// 		ExFreePool(pDelayClose);
// 	}*/
// 
// 
// 
// 	LIST_ENTRY *pListEntry = NULL;
// 	DALAYCLOSE* pDelayClose = NULL;
// 
// 	if(IsListEmpty(&g_DelayCloseList)) return  ;
// 
// 	ExAcquireFastMutex(&g_DelayCloseMutex);
// 	for( pListEntry  = g_DelayCloseList.Blink; pListEntry!= &g_DelayCloseList; pListEntry= pListEntry->Blink)
// 	{
// 		pDelayClose  = CONTAINING_RECORD(pListEntry,DALAYCLOSE,list);
// 		if(pDelayClose->pDiskFileObject == pDiskFileObject)
// 		{
// 			RemoveEntryList(&pDelayClose ->list);
// 			if(pDelayClose)
// 			{
// 				ExFreePool(pDelayClose);
// 			}
// 
// 			break;
// 		}
// 	}
// 	ExReleaseFastMutex(&g_DelayCloseMutex);
// }
PDISKFILEOBJECT 
PfpGetDiskFileObjectFromDelayCloseByUsingFCBONDisk(PVOID FileObjectContext)
{
	PLIST_ENTRY			plist = NULL;
	PDALAYCLOSE			pDelayClose = NULL ;
	PPfpFCB				pFcb	= NULL;
	PDISKFILEOBJECT		pDiskFile_Object = NULL;

	if(IsListEmpty(&g_DelayCloseList))
		return NULL;
	ExAcquireFastMutex(&g_DelayCloseMutex);

	for(plist = g_DelayCloseList.Blink; plist != &g_DelayCloseList; plist = plist->Blink)
	{
		pDelayClose  = CONTAINING_RECORD(plist,DALAYCLOSE,list);

		if( pDelayClose->pDiskFileObject->pDiskFileObjectWriteThrough && pDelayClose->pDiskFileObject->pDiskFileObjectWriteThrough->FsContext )		
		{
			if(pDelayClose->pDiskFileObject->pDiskFileObjectWriteThrough->FsContext == FileObjectContext )
			{
				RemoveEntryList(&pDelayClose->list);
				ExReleaseFastMutex(&g_DelayCloseMutex);
				pDiskFile_Object  = pDelayClose->pDiskFileObject;
				ExFreePool(pDelayClose);
				return pDiskFile_Object;
			
			}
		}
	}
	ExReleaseFastMutex(&g_DelayCloseMutex);
	return NULL;
}

VOID 
PfpDelayCloseThread(IN PVOID pContext)
{
	LIST_ENTRY *pListEntry = NULL;
	LIST_ENTRY *pListTemp  = NULL;
	DALAYCLOSE* pDelayClose= NULL;

	while(1)
	{ 
		Sleep();

		
		if(!IsListEmpty(&g_DelayCloseList))
		{

			ExAcquireFastMutex(&g_DelayCloseMutex);
			
			for( pListEntry  = g_DelayCloseList.Blink; pListEntry!= &g_DelayCloseList;)
			{
				
				pDelayClose  = CONTAINING_RECORD(pListEntry,DALAYCLOSE,list);
				pListEntry = pListEntry->Blink;
				if((--pDelayClose->nCount)<=0)
				{
					RemoveEntryList(&pDelayClose ->list);
					
					if(!((PPfpFCB)pDelayClose->pDiskFileObject->pFCB)->bNeedEncrypt && pDelayClose->pDiskFileObject->hFileWriteThrough != INVALID_HANDLE_VALUE && pDelayClose->pDiskFileObject->hFileWriteThrough!= NULL)
					{
						//PfpSetFileNotEncryptSize(pDelayClose->pDiskFileObject->hFileWriteThrough,((PPfpFCB)pDelayClose->pDiskFileObject->pFCB)->Header.FileSize);
					}		
					PfpCloseRealDiskFile(&(pDelayClose->pDiskFileObject->hFileWriteThrough),&(pDelayClose->pDiskFileObject->pDiskFileObjectWriteThrough));
					PfpDeleteFCB(&((PPfpFCB)pDelayClose->pDiskFileObject->pFCB));
					PfpDeleteDiskFileObject(&pDelayClose->pDiskFileObject);
					ExFreePool(pDelayClose);
				}

			}
			
			ExReleaseFastMutex(&g_DelayCloseMutex);
		}
		
		
	};
}

VOID 
PfpCreateDelayCloseThread()
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	PsCreateSystemThread(&handle ,
		THREAD_ALL_ACCESS ,
		NULL,
		NULL,
		NULL,
		PfpDelayCloseThread,
		NULL
		);
	
}