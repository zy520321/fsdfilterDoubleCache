
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
  


PPROCESSINFO  
PfpCreateAndInitProcessInfo(IN UNICODE_STRING FullPath,
							IN UCHAR*         HashValue,
							IN ULONG          szLen,
							IN HANDLE         hProcess,
							IN BOOLEAN        bInherite,
							IN PWCHAR		  pszFileTypes,
							IN BOOLEAN		  bNeedBackup,
							IN BOOLEAN		  bEnAbleEncrypt,
							IN BOOLEAN		  bForceEncryption,
							IN BOOLEAN		  bAlone,
							IN BOOLEAN		  bBrowser,
							IN BOOLEAN		  bCreateExEFile,
							IN ULONG		  lEncryptTypeValue
							)
{
	PPROCESSINFO  pProcessInfo = NULL;
	PHandleOfExe  pHandleInfo = NULL;
	LONG nIndexOfArray   =0;
	if(FullPath.Buffer== NULL|| FullPath.Length==0 )
		return NULL;

	if(HashValue== NULL || szLen!=PROCESSHASHVALULENGTH)
		return NULL;


	pProcessInfo = ExAllocatePoolWithTag(NonPagedPool,sizeof(PROCESSINFO),'N901');
	if(pProcessInfo == NULL )
		return NULL;

	pProcessInfo->ProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool,FullPath.MaximumLength,'N011');

	if(pProcessInfo->ProcessName.Buffer == NULL)
	{
		ExFreePool(pProcessInfo);
		return NULL;
	}

	RtlCopyMemory(pProcessInfo->ProcessName.Buffer,FullPath.Buffer,FullPath.Length);
	pProcessInfo->ProcessName.Length = FullPath.Length;
	pProcessInfo->ProcessName.MaximumLength =FullPath. MaximumLength;
	
	pProcessInfo->bNeedBackUp    = bNeedBackup;
	pProcessInfo->bAllowInherent = bInherite;
	pProcessInfo->bEnableEncrypt = bEnAbleEncrypt;
	pProcessInfo->bForceEncryption = bForceEncryption;
	pProcessInfo ->nRef          = 0;
	pProcessInfo ->bAlone		 = bAlone; 
	pProcessInfo->bBowser		 = bBrowser;
	pProcessInfo->bAllCreateExeFile = bCreateExEFile;
	pProcessInfo ->nEncryptTypes = lEncryptTypeValue;
	RtlCopyMemory(pProcessInfo->ProcessHashValue,HashValue,PROCESSHASHVALULENGTH);

	InitializeListHead(&pProcessInfo->list);
	InitializeListHead(&pProcessInfo->FileTypes);
	InitializeListHead(&pProcessInfo->hProcessList);
	for(0;nIndexOfArray<5;++nIndexOfArray)
	{
		InitializeListHead(&pProcessInfo->FileTypesForBrowser[nIndexOfArray]);
	}
	
	

	ExInitializeFastMutex (&pProcessInfo->FileTypesMutex);
	ExInitializeFastMutex (&pProcessInfo->HandleMutex);

	PfpAddFileTypesToProcessInfo(pProcessInfo,pszFileTypes);

	if(hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
	{
		pHandleInfo = ExAllocatePoolWithTag(PagedPool,sizeof(HandleOfExe),'2004');
		if(pHandleInfo )
		{
			pHandleInfo ->Handle = hProcess;
			InitializeListHead(&pHandleInfo->listForDiskFile);
			InsertHeadList(&pProcessInfo->hProcessList,&pHandleInfo->list);
		}else
		{
			ASSERT(0);
		}
	}
	return pProcessInfo;

}

VOID
PfpAddProcessIntoGlobal(PPROCESSINFO pProcessInfo)
{
	if(!pProcessInfo)
		return ;
	InsertHeadList(&g_ProcessInofs,&pProcessInfo->list);
}
VOID 
PfpAddFileTypeIntoProcessInfo(IN PPROCESSINFO pProcessInfo,
							  IN PWCHAR pszFileType,BOOLEAN bSelected, BOOLEAN bBackup)
{
	PFILETYPE pFileType = NULL;
	if(pProcessInfo== NULL ||pszFileType== NULL)
		return	;
	pFileType = ExAllocatePoolWithTag(NonPagedPool,sizeof(FILETYPE),'E001');
	if(pFileType )
	{
		memset(pFileType,0,sizeof(FILETYPE));
		pFileType->bSelected = bSelected;
		pFileType->bBackUp	 = bBackup;
		wcsncpy(pFileType->FileExt,pszFileType,min(FILETYPELEN-1,wcslen(pszFileType)));
		pFileType->FileExt[min(FILETYPELEN-1,wcslen(pszFileType))] = 0;
		InitializeListHead(&pFileType->list);
	
		ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
		InsertHeadList(&pProcessInfo->FileTypes,&pFileType->list);
		ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
	}
}

PFILETYPE
PfpGetFileTypeFromProcessInfo(IN PPROCESSINFO pProcessInfo,
							  IN PWCHAR pszFileType)
{
	PFILETYPE pFileType = NULL;
	BOOLEAN     bFound = FALSE;
	if(pProcessInfo == NULL || pszFileType == NULL)
		return	NULL;
	
	
	if(pProcessInfo== NULL || pszFileType == NULL)
		return NULL;

	ASSERT( wcslen(pszFileType) <= (FILETYPELEN-1));

	ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);

	if(!IsListEmpty(&pProcessInfo->FileTypes))
	{
		PLIST_ENTRY plistTemp = NULL;

		for(plistTemp = pProcessInfo->FileTypes.Blink;  plistTemp !=&pProcessInfo->FileTypes;plistTemp = plistTemp->Blink )
		{
			pFileType = CONTAINING_RECORD(plistTemp,FILETYPE,list);
			if(pFileType != NULL)
			{
				if(_wcsicmp(pFileType->FileExt ,pszFileType)==0)
				{
					bFound = TRUE;
					
					break;
				}
			}
		}
	}
	
	ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);

	return (bFound?pFileType:NULL);
	
}

VOID
PfpAddFileTypesToProcessInfoByFileTypeArray(IN PPROCESSINFO pProcessInfo,
							 IN PFILETYPE_INFO pFileTypes,
							 IN ULONG nNum)
{
	ULONG nIndex =0;
	PFILETYPE   FileType  = NULL;
	if(pProcessInfo== NULL ||pFileTypes == NULL ||nNum==0) return ;

	ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
	PfpDeleteAllFileTypesOfProcessInfo(pProcessInfo);
	ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
	for(;nIndex <nNum;nIndex++)
	{
		FileType = ExAllocatePoolWithTag(NonPagedPool,sizeof(FILETYPE),'E101');
		if(FileType != NULL)
		{
			memset(FileType,0,sizeof(FILETYPE));
			memcpy(FileType->FileExt,pFileTypes[nIndex].psztype,50*sizeof(WCHAR));
			InitializeListHead(&FileType->list);
			FileType->bSelected = pFileTypes[nIndex].bEncrypt?TRUE:FALSE;
			FileType->bBackUp	= pFileTypes[nIndex].bBackUp?TRUE:FALSE;

			ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
			InsertHeadList(&pProcessInfo->FileTypes,&FileType->list);
			ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
		}
	}
}

VOID
PfpAddFileTypesForBrowserInfoByFileTypeArray(IN PPROCESSINFO   pProcessInfo,
											 IN ULONG		  nEncryptionType,
											 IN PFILETYPE_INFO pFileTypes,
											 IN ULONG nNum)
{
	ULONG		nIndex		= 0;
	PFILETYPE   FileType	= NULL;
	LONG		nIndexofArray		= -1;
	if(pProcessInfo== NULL ||pFileTypes == NULL ||nNum==0) return ;

	ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
	PfpDeleteAllFileTypesOfBrowser(pProcessInfo,nEncryptionType);
	ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
	nIndexofArray = Type2ArrayIndex(nEncryptionType);
	
	if(nIndexofArray ==-1) return ;

	for(;nIndex <nNum;nIndex++)
	{
		FileType = ExAllocatePoolWithTag(NonPagedPool,sizeof(FILETYPE),'E201');
		if(FileType != NULL)
		{
			memset(FileType,0,sizeof(FILETYPE));
			memcpy(FileType->FileExt,pFileTypes[nIndex].psztype,50*sizeof(WCHAR));
			InitializeListHead(&FileType->list);
			 

			ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
			InsertHeadList(&pProcessInfo->FileTypesForBrowser[nIndexofArray],&FileType->list);
			ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
		}
	}
}
VOID
PfpAddFileTypesToProcessInfo(IN PPROCESSINFO pProcessInfo,
							 IN PWCHAR pszFileTypes)
{
	BOOLEAN     bFound    = FALSE;
	PFILETYPE   FileType  = NULL;
	PWCHAR		psztemp	  = NULL;
	PWCHAR		pszTemp1  = NULL;
	LONG		nIndex = 0;
	if(pProcessInfo== NULL || pszFileTypes == NULL)
		return ;

	
	if(!pProcessInfo->bBowser)
	{

	
		psztemp	   = pszFileTypes;
		
		while(psztemp[nIndex]!=L';' && psztemp[nIndex]!=L'\0')
		{
			if( psztemp[nIndex]!=L'|')
			{
				nIndex++;
				continue;
			}

			FileType = ExAllocatePoolWithTag(NonPagedPool,sizeof(FILETYPE),'E301');
			if(FileType != NULL)
			{
				memset(FileType,0,sizeof(FILETYPE));
				memcpy(FileType->FileExt,psztemp,min(nIndex,FILETYPELEN-1)*sizeof(WCHAR));
				
				FileType->FileExt[min(nIndex,FILETYPELEN-1)] =0;
				psztemp =&psztemp[nIndex+1];
				nIndex=0;

				InitializeListHead(&FileType->list);
				FileType->bSelected = TRUE;
				FileType->bBackUp	= FALSE;
				ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
				InsertHeadList(&pProcessInfo->FileTypes,&FileType->list);
				ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
			}

		};
		if( psztemp[nIndex]==L'\0')
			return ;
		nIndex++;
		psztemp = &psztemp[nIndex];
		nIndex=0;
		while(psztemp[nIndex]!=L'\0')
		{
			if( psztemp[nIndex]!=L'|')
			{
				nIndex++;
				continue;
			}

			FileType = ExAllocatePoolWithTag(NonPagedPool,sizeof(FILETYPE),'E401');
			if(FileType != NULL)
			{
				memset(FileType,0,sizeof(FILETYPE));
				memcpy(FileType->FileExt,psztemp,min(nIndex, FILETYPELEN-1)*sizeof(WCHAR));

				FileType->FileExt[min(nIndex, FILETYPELEN-1 )] =0;
				psztemp =&psztemp[nIndex+1];
				nIndex=0;

				InitializeListHead(&FileType->list);
				FileType->bSelected = FALSE;
				FileType->bBackUp	= FALSE;
				ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
				InsertHeadList(&pProcessInfo->FileTypes,&FileType->list);
				ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
			}
		};	

	}else
	{
		LONG nencryptNum=0;
		LONG nIndexArray  =0;
		LONG nencryptIndexArray[5]={0};
		if(pProcessInfo->nEncryptTypes!=0)
		{
			if(pProcessInfo->nEncryptTypes&PIC_TYPE)
			{
				nencryptIndexArray[nencryptNum]=Type2ArrayIndex(PIC_TYPE);
				nencryptNum++;
			}
			if(pProcessInfo->nEncryptTypes&COOKIE_TYPE)
			{
				nencryptIndexArray[nencryptNum]=Type2ArrayIndex(COOKIE_TYPE);
				nencryptNum++;
			}
			if(pProcessInfo->nEncryptTypes&VEDIO_TYPE)
			{
				nencryptIndexArray[nencryptNum]=Type2ArrayIndex(VEDIO_TYPE);
				nencryptNum++;
			}
			if(pProcessInfo->nEncryptTypes&TEXT_TYPE)
			{
				nencryptIndexArray[nencryptNum]=Type2ArrayIndex(TEXT_TYPE);
				nencryptNum++;
			}
			if(pProcessInfo->nEncryptTypes&SCRIPT_TYPE)
			{
				nencryptIndexArray[nencryptNum]=Type2ArrayIndex(SCRIPT_TYPE);
				nencryptNum++;
			}
		}
		

		psztemp	   = pszFileTypes;
		nIndexArray   =0;
DORead:
		while(psztemp[nIndex]!=L';' && psztemp[nIndex]!=L'\0')
		{
			if( psztemp[nIndex]!=L'|')
			{
				nIndex++;
				continue;
			}

			FileType = ExAllocatePoolWithTag(NonPagedPool,sizeof(FILETYPE),'E501');
			if(FileType != NULL)
			{
				memset(FileType,0,sizeof(FILETYPE));
				memcpy(FileType->FileExt,psztemp,min(nIndex,FILETYPELEN-1)*sizeof(WCHAR));

				FileType->FileExt[min(nIndex,FILETYPELEN-1)] =0;
				psztemp =&psztemp[nIndex+1];
				nIndex=0;

				InitializeListHead(&FileType->list);
				FileType->bSelected = FALSE;
				FileType->bBackUp	= FALSE;
				ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);
				InsertHeadList(&pProcessInfo->FileTypesForBrowser[nencryptIndexArray[nIndexArray]],&FileType->list);
				ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);
			}

		};
		nIndexArray++;
		if( psztemp[nIndex]!=L'\0' && nIndexArray<nencryptNum)
		{
			nIndex=0;
			psztemp++;
			goto DORead;
		}


	}
}

VOID 
PfpDeleteFileTypeFromProcessInfo(IN PPROCESSINFO pProcessInfo,
								 IN PWCHAR       pszFileType)
{

	BOOLEAN     bFound = FALSE;
	PFILETYPE   FileType  = NULL;
	if(pProcessInfo== NULL || pszFileType == NULL)
		return ;

	ASSERT( wcslen(pszFileType) <=  (FILETYPELEN-1));

	ExAcquireFastMutex(&pProcessInfo->FileTypesMutex);

	if(!IsListEmpty(&pProcessInfo->FileTypes))
	{
		PLIST_ENTRY plistTemp = NULL;

		for(plistTemp = pProcessInfo->FileTypes.Blink;  plistTemp !=&pProcessInfo->FileTypes;plistTemp = plistTemp->Blink )
		{
			FileType = CONTAINING_RECORD(plistTemp,FILETYPE,list);
			if(FileType != NULL)
			{
				if(_wcsicmp(FileType->FileExt ,pszFileType)==0)
				{
					RemoveEntryList(plistTemp);
					break;
				}
			}
		}
	}

	ExReleaseFastMutex(&pProcessInfo->FileTypesMutex);

}

VOID 
PfpDeleteAllFileTypesOfProcessInfo(
								   IN PPROCESSINFO pProcessInfo)
{
	ASSERT(pProcessInfo);

	while(!IsListEmpty(&pProcessInfo->FileTypes))
	{
		PLIST_ENTRY plist = RemoveHeadList(&pProcessInfo->FileTypes);
		if(plist )
		{
			PFILETYPE pHInfo = CONTAINING_RECORD(plist,FILETYPE,list);
			if( pHInfo )
			{
				ExFreePool(pHInfo);
			}
		}
	}
}

VOID 
PfpDeleteAllFileTypesOfBrowser(
								   IN PPROCESSINFO pProcessInfo,
								   IN ULONG			nEncryptType)
{
	LIST_ENTRY* pHeadList = NULL;
	LONG nIndex = -1;

	ASSERT(pProcessInfo);
	
	nIndex = Type2ArrayIndex(nEncryptType);
	
	if(nIndex ==-1) return ;
	
	pHeadList = &pProcessInfo->FileTypesForBrowser[nIndex];
	

	while(!IsListEmpty(pHeadList))
	{
		PLIST_ENTRY plist = RemoveHeadList(pHeadList);
		if(plist )
		{
			PFILETYPE pHInfo = CONTAINING_RECORD(plist,FILETYPE,list);
			if( pHInfo )
			{
				ExFreePool(pHInfo);
			}
		}
	}
}

/*VOID 
PfpAddHandleIntoProceInfo(
						  IN OUT PPROCESSINFO	pProcInfo,
						  IN HANDLE				Handle
						  )
{
	PLIST_ENTRY  pList = NULL;
	PHandleOfExe pHandle = NULL;
	if(pProcInfo == NULL)
		return ;


	if(!IsListEmpty(&pProcInfo->hProcessList))
	{
		for(pList = pProcInfo->hProcessList.Blink; pList != &pProcInfo->hProcessList ; pList=pList->Blink)
		{
			pHandle = CONTAINING_RECORD(pList,HandleOfExe,list);
			if(pHandle == Handle)
				return ;
		}
	}

	pHandle = ExAllocatePool_A(PagedPool,sizeof(HandleOfExe));

	if(pHandle == NULL)
		return ;

	RtlZeroMemory(pHandle,sizeof(HandleOfExe));
	pHandle->Handle = Handle;

	InitializeListHead(&pHandle->list);

	InsertHeadList(&pProcInfo->hProcessList,&pHandle->list);

}
*/
VOID 
PfpDeleteHandle(
				IN OUT PPROCESSINFO	pProcInfo,
				IN HANDLE			Handle
				)
{
	PLIST_ENTRY  pList = NULL;
	if(pProcInfo == NULL)
		return ;
	if( IsListEmpty(&pProcInfo->hProcessList)) return ;

	for(pList = pProcInfo->hProcessList.Blink; pList != &pProcInfo->hProcessList ; pList=pList->Blink)
	{
		PHandleOfExe pHandle = CONTAINING_RECORD(pList,HandleOfExe,list);
		if(pHandle->Handle == Handle)
		{
			PfpRemoveAllCreatedFile(pHandle);
			RemoveEntryList(&pHandle->list);
			ExFreePool	(pHandle);
			return ;
		}
	}
}
PHandleOfExe	
PfpAddHanldeIntoProcessInfo(
							IN HANDLE hHandle,
							IN PPROCESSINFO	pProcInfo
							)
{
	PHandleOfExe pHandleInfo = NULL;

	if(hHandle != INVALID_HANDLE_VALUE)
	{
		pHandleInfo  = ExAllocatePoolWithTag(PagedPool,sizeof(HandleOfExe ),'0008');
		if(pHandleInfo== NULL)
		{
			KdPrint (("Allocate Pool failed in Function PfpAddHanldeIntoProcessInfo \n"));
			return NULL;
		}

		pHandleInfo ->Handle = hHandle;
		InitializeListHead(&pHandleInfo->listForDiskFile);
		InitializeListHead(&pHandleInfo->ListForUsermodeFile);
		InsertHeadList(&pProcInfo->hProcessList,&pHandleInfo->list);
		return pHandleInfo;
	}else
		return NULL;
	
}

VOID 
PfpDeleteAllHandle(
				   IN OUT PPROCESSINFO	pProcInfo				
				   )
{
	if(pProcInfo == NULL)
		return ;

	ASSERT(pProcInfo);

	while(!IsListEmpty(&pProcInfo->hProcessList))
	{
		PLIST_ENTRY plist = RemoveHeadList(&pProcInfo->hProcessList);
		if(plist )
		{
			PHandleOfExe pHandle = CONTAINING_RECORD(plist,HandleOfExe,list);
			if( pHandle )
			{
				PfpRemoveAllCreatedFile(pHandle);
				ExFreePool(pHandle);
			}
		}
	}
}

VOID		
ClearAllRecycleList()
{
	PRecyclePath pRecycleInfo = NULL;
	PLIST_ENTRY  plistTemp = NULL;
	

	for(plistTemp = g_RecyclePaths.Blink;  plistTemp !=&g_RecyclePaths;)
	{
		pRecycleInfo = CONTAINING_RECORD(plistTemp,RecyclePath,list);
		plistTemp = plistTemp->Blink;

		if(pRecycleInfo != NULL)
		{
			RemoveEntryList(&pRecycleInfo->list);
			if(pRecycleInfo->pPath)
			{
				ExFreePool(pRecycleInfo->pPath);			
			}
			ExFreePool(pRecycleInfo);		
		}
	}
}

VOID 
AddIntoRecycleList(PWCHAR pPath)
{
	PRecyclePath pRecycleInfo = NULL;
	pRecycleInfo = ExAllocatePool_A(PagedPool,sizeof(RecyclePath));
	if(pRecycleInfo )
	{
		pRecycleInfo->pPath = ExAllocatePool_A(PagedPool,sizeof(WCHAR)*(wcslen(pPath)+1));
		if(pRecycleInfo->pPath)
		{
			wcscpy(pRecycleInfo->pPath ,pPath);
			InsertTailList(&g_RecyclePaths,&pRecycleInfo->list);
		}else
		{
			ExFreePool(pRecycleInfo);
		}
	}
}
BOOLEAN		
IsRecyclePath(PWCHAR pPath)
{
	PRecyclePath pRecycleInfo = NULL; 
	PLIST_ENTRY  plistTemp = NULL;
	pPath = _wcslwr(pPath);

	if( IsListEmpty(&g_RecyclePaths)) return FALSE;

	for(plistTemp = g_RecyclePaths.Blink;  plistTemp !=&g_RecyclePaths;)
	{
		pRecycleInfo = CONTAINING_RECORD(plistTemp,RecyclePath,list);
		plistTemp = plistTemp->Blink;

		if(pRecycleInfo != NULL)
		{
			if(wcsstr(pPath,pRecycleInfo->pPath)!= NULL)
				return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN 
PfpDelProcessInfo(UCHAR* pszHashValue,ULONG nLength)
{
	PPROCESSINFO pProcInfo = NULL;

	if(pszHashValue==NULL ||nLength!= PROCESSHASHVALULENGTH) return TRUE;
		
	pProcInfo = PfpGetProcessInfoUsingHashValue(pszHashValue,nLength,NULL);
	
	if(pProcInfo == NULL) return TRUE;
	
	if(pProcInfo->nRef>1)
	{
		InterlockedDecrement(&pProcInfo->nRef);
		return FALSE;
	}
	
	RemoveEntryList(&pProcInfo->list);
	
	PfpDeleteAllFileTypesOfProcessInfo(pProcInfo);
	PfpDeleteAllHandle(pProcInfo);

	if((pProcInfo )->ProcessName.Buffer)
	{	
		ExFreePool((pProcInfo)->ProcessName.Buffer);
	}

	ExFreePool(pProcInfo);	
	return TRUE;
}
BOOLEAN 
PfpClearAllProcInfos()
{
	PPROCESSINFO pProcInfo = NULL;
	PLIST_ENTRY  plistTemp = NULL;

	for(plistTemp = g_ProcessInofs.Blink;  plistTemp !=&g_ProcessInofs;)
	{
		pProcInfo = CONTAINING_RECORD(plistTemp,PROCESSINFO,list);
		plistTemp = plistTemp->Blink;

		if(pProcInfo != NULL && pProcInfo->nRef>0)
			return FALSE;

	}

	for(plistTemp = g_ProcessInofs.Blink;  plistTemp !=&g_ProcessInofs;)
	{
		pProcInfo = CONTAINING_RECORD(plistTemp,PROCESSINFO,list);
		plistTemp = plistTemp->Blink;

		if(pProcInfo != NULL)
		{
// 			LARGE_INTEGER   Interval;
// 			Interval.QuadPart = 100;
// 			while(pProcInfo->nRef > 0)
// 			{
// 				KeDelayExecutionThread(KernelMode,FALSE,&Interval);
// 			};

			RemoveEntryList(&pProcInfo->list);

			PfpDeleteAllFileTypesOfProcessInfo(pProcInfo);
			PfpDeleteAllHandle(pProcInfo);
			
			if((pProcInfo )->ProcessName.Buffer)
			{	
				ExFreePool((pProcInfo)->ProcessName.Buffer);
			}

			ExFreePool(pProcInfo);		
		}
	}
	return TRUE;
}


BOOLEAN 
PfpFindExcludProcess(HANDLE hHandle)
{
	ProcessExclud* pProcExclud= NULL;
	PLIST_ENTRY  plistTemp = NULL;
	
	if(IsListEmpty(&g_ProcessExclude))
	{
		return FALSE;
	}
	ExAcquireResourceSharedLite(&g_ProcessExcludeResource,TRUE);
	
	for(plistTemp = g_ProcessExclude.Blink;  plistTemp !=&g_ProcessExclude;  )
	{
		pProcExclud = CONTAINING_RECORD(plistTemp,ProcessExclud,list);
		plistTemp = plistTemp->Blink;

		if(pProcExclud != NULL && pProcExclud->Handle == hHandle)
		{
			ExReleaseResourceLite(&g_ProcessExcludeResource);
			
			return TRUE;
		}
	}
	ExReleaseResourceLite(&g_ProcessExcludeResource);
	return FALSE;
}

BOOLEAN 
PfpAddExcludProcess(HANDLE hHandle)
{
	ProcessExclud* pProcExclud= NULL;
	PLIST_ENTRY  plistTemp = NULL;
	PProcessExclud pProcessExclu = NULL;
	
	ExAcquireResourceExclusiveLite(&g_ProcessExcludeResource,TRUE);
	for(plistTemp = g_ProcessExclude.Blink;  plistTemp !=&g_ProcessExclude;  )
	{
		pProcExclud = CONTAINING_RECORD(plistTemp,ProcessExclud,list);
		plistTemp = plistTemp->Blink;

		if(pProcExclud != NULL && pProcExclud->Handle == hHandle)
		{
			break;
		}
	}
	if(plistTemp==&g_ProcessExclude)
	{
		pProcessExclu =ExAllocatePoolWithTag(PagedPool,sizeof(ProcessExclud),'1008');
	
		if(pProcessExclu != NULL)
		{
			pProcessExclu ->Handle = hHandle;
			InitializeListHead(&pProcessExclu->list);
			InsertHeadList(&g_ProcessExclude,&pProcessExclu->list);
	
		}
		
	}
	
	ExReleaseResourceLite(&g_ProcessExcludeResource);
	return TRUE;
}

BOOLEAN 
PfpDelExcludProcess(HANDLE hHandle)
{
	ProcessExclud* pProcExclud= NULL;
	PLIST_ENTRY  plistTemp = NULL;

	if(IsListEmpty(&g_ProcessExclude))
	{
		return FALSE;
	}

	ExAcquireResourceExclusiveLite(&g_ProcessExcludeResource,TRUE);

	for(plistTemp = g_ProcessExclude.Blink;  plistTemp !=&g_ProcessExclude;  )
	{
		pProcExclud = CONTAINING_RECORD(plistTemp,ProcessExclud,list);
		plistTemp = plistTemp->Blink;

		if(pProcExclud != NULL && pProcExclud->Handle == hHandle)
		{
			RemoveEntryList(&pProcExclud->list);
			ExFreePool(pProcExclud);
			break;
		}
	}
	ExReleaseResourceLite(&g_ProcessExcludeResource);
	return TRUE;
}

VOID 
PfpAddCreatedFileIntoProcess(IN PPROCESSINFO pProcessInfo,
							 IN HANDLE HandleOfProcess,
							 IN WCHAR* Driver,
							 IN WCHAR* szFullPath)
{
	PLIST_ENTRY  pList = NULL;
	if(pProcessInfo == NULL)
		return ;

	for(pList = pProcessInfo->hProcessList.Blink; pList != &pProcessInfo->hProcessList ; pList=pList->Blink)
	{
		PHandleOfExe pHandle = CONTAINING_RECORD(pList,HandleOfExe,list);
		if(pHandle->Handle == HandleOfProcess)
		{
			if(!PfpIsFileInProcessCreated_Internal(pHandle,Driver,szFullPath))
			{	
				PPROCESSCREATEDFILE pCreatedFile = ExAllocatePoolWithTag(PagedPool,sizeof(PROCESSCREATEDFILE),'2008');
				LONG nLen = wcslen(szFullPath)*sizeof(WCHAR);
				if(pCreatedFile)
				{
					memcpy(pCreatedFile->szDriverLetter,Driver,4);
					pCreatedFile->szDriverLetter[2]=L'\0';

					pCreatedFile->szFullPathWithOutDriverLetter = ExAllocatePoolWithTag(PagedPool,nLen+sizeof(WCHAR),'3008');
					if(!pCreatedFile->szFullPathWithOutDriverLetter )
					{
						ExFreePool(pCreatedFile);
						return ;
					}
					memcpy(pCreatedFile->szFullPathWithOutDriverLetter ,szFullPath,nLen);
					pCreatedFile->szFullPathWithOutDriverLetter [nLen/sizeof(WCHAR)]=0;
					InsertHeadList(&pHandle->listForDiskFile,&pCreatedFile->list);	
				}
				return ;
			}
			
			return ;
		}
	}
}

BOOLEAN 
PfpIsFileInProcessCreated(IN PPROCESSINFO pProcessInfo,
						  IN HANDLE HandleOfProcess,
						  IN WCHAR* Driver,
						  IN WCHAR* szFullPath)
{
	PLIST_ENTRY  pList = NULL;
	if(pProcessInfo == NULL)
		return FALSE;

	if(IsListEmpty(&pProcessInfo->hProcessList))
	{
		return FALSE;
	}

	for(pList = pProcessInfo->hProcessList.Blink; pList != &pProcessInfo->hProcessList ; pList=pList->Blink)
	{
		PHandleOfExe pHandle = CONTAINING_RECORD(pList,HandleOfExe,list);
		if(pHandle->Handle == HandleOfProcess)
		{
			return PfpIsFileInProcessCreated_Internal(pHandle,Driver,szFullPath);			
		}
	}
	return FALSE;
}

VOID
PfpRemoveAllCreatedFile(IN PHandleOfExe pHandleInfo)
{
	PLIST_ENTRY	  pList		= NULL;
	PLIST_ENTRY   plistTemp = NULL;
	PPROCESSCREATEDFILE pCreatedFile = NULL;
	PPROCESSCREATEDFILEWithCCBs pCreatedFileWithCCb = NULL;
	if(pHandleInfo == NULL)
		return ;
	
	if(IsListEmpty(&pHandleInfo->listForDiskFile))
	{
		return ;
	}


	for(plistTemp = pHandleInfo->listForDiskFile.Blink;  plistTemp !=&pHandleInfo->listForDiskFile;  )
	{
		pCreatedFile = CONTAINING_RECORD(plistTemp,PROCESSCREATEDFILE,list);
		plistTemp = plistTemp->Blink;

		if(pCreatedFile != NULL )
		{
			ExFreePool(pCreatedFile->szFullPathWithOutDriverLetter);

			RemoveEntryList(&pCreatedFile->list);
			ExFreePool(pCreatedFile);
			
		}
	}	

	for(plistTemp = pHandleInfo->ListForUsermodeFile.Flink;  plistTemp !=&pHandleInfo->ListForUsermodeFile;  )
	{
		pCreatedFileWithCCb  = CONTAINING_RECORD(plistTemp,PROCESSCREATEDFILEWithCCBs,list);
		plistTemp = plistTemp->Flink;

		if(pCreatedFileWithCCb  != NULL )
		{
			RemoveEntryList(&pCreatedFileWithCCb ->list);
			PfpDeleteProcessCreatedFileWithCCB(&pCreatedFileWithCCb );
		}
	}	
}

BOOLEAN 
PfpIsFileInProcessCreated_Internal(IN PHandleOfExe pHandleOfProcess,
								   IN WCHAR* Driver,
								   IN WCHAR* szFullPath)
{

	PLIST_ENTRY  pList = NULL;
	if(pHandleOfProcess == NULL)
		return FALSE;
	if(IsListEmpty(&pHandleOfProcess->listForDiskFile)) return FALSE;
	for(pList = pHandleOfProcess->listForDiskFile.Blink; pList != &pHandleOfProcess->listForDiskFile ; pList=pList->Blink)
	{
		PPROCESSCREATEDFILE pCreatedFile = CONTAINING_RECORD(pList,PROCESSCREATEDFILE,list);
		if(pCreatedFile)
		{
			if(_wcsicmp(pCreatedFile->szDriverLetter,Driver)==0 && 	_wcsicmp(pCreatedFile->szFullPathWithOutDriverLetter,szFullPath)==0)
				return TRUE;
		}
	}
	
	return FALSE;
}
PHandleOfExe
PfpGetHandleInfoUsingHanlde(IN PPROCESSINFO pProcessInfo,
							IN HANDLE hProcess)
{
	PLIST_ENTRY  pList = NULL;
	if(pProcessInfo == NULL)
		return NULL;

	for(pList = pProcessInfo->hProcessList.Blink; pList != &pProcessInfo->hProcessList ; pList=pList->Blink)
	{
		PHandleOfExe pHandle = CONTAINING_RECORD(pList,HandleOfExe,list);
		if(pHandle->Handle == hProcess)
		{ return pHandle;}
	}
	return NULL;
}

VOID
PfpDeleteCCBFromHandleOfExe(HandleOfExe *pHandleOfexe,
							PPfpCCB pCCB,
							BOOLEAN *bEmpty,
							PPROCESSCREATEDFILEWithCCBs* pProcessCreatedFileWithCCB)
{
	PPROCESSCREATEDFILEWithCCBs pCreateedFileWithCCB= NULL;
	LIST_ENTRY * pListHead = NULL;
	LIST_ENTRY * pListtemp = NULL;
	ASSERT(pHandleOfexe!= NULL&& pCCB!=  NULL);
	if(IsListEmpty(&pHandleOfexe->ListForUsermodeFile)) 
	{
		*bEmpty = TRUE;
		*pProcessCreatedFileWithCCB = NULL;
		return ;
	}
	pListHead	= &pHandleOfexe->ListForUsermodeFile;
	pListtemp	= pListHead->Flink;
	while(pListtemp!= pListHead	)
	{
		 pCreateedFileWithCCB = CONTAINING_RECORD(pListtemp,PROCESSCREATEDFILEWithCCBs,list);
		 pListtemp = pListtemp->Flink;
		 if(pCreateedFileWithCCB )
		 {
			 LIST_ENTRY * pListHead1	= NULL;
			 LIST_ENTRY * pListtemp1	= NULL;
			 PCCBRECORD pCCRecord		= NULL;
			 if(IsListEmpty(&pCreateedFileWithCCB ->ListHeadForCCofFileObject))
				 continue;
			 pListHead1	 = &pCreateedFileWithCCB ->ListHeadForCCofFileObject;
			 pListtemp1  = pListHead1	 ->Flink;
			 while(pListtemp1  != pListHead1)
			 {
				pCCRecord		= CONTAINING_RECORD(pListtemp1,CCBRECORD,list);
				pListtemp1		= pListtemp1->Flink;
				if(pCCRecord && pCCRecord->pCCB== pCCB)
				{
					RemoveEntryList(&pCCRecord->list);
					ExFreePool_A(pCCRecord);
					if(bEmpty)
						*bEmpty = IsListEmpty(pListHead1);
					if(pProcessCreatedFileWithCCB)
					{
						*pProcessCreatedFileWithCCB= pCreateedFileWithCCB;
						if(bEmpty)
						{
							RemoveEntryList(&pCreateedFileWithCCB->list);
						}
					}
					return ;
				}
			 };

		 }
	};
	*pProcessCreatedFileWithCCB = NULL;
	*bEmpty = TRUE;
	return ;
}

PPROCESSCREATEDFILEWithCCBs
PfpGetCreatedFileWithCCBFromHandleOfexe(HandleOfExe *pHandleOfexe,
										WCHAR* pszDriverLetter,
										PWCHAR pszFilePathWithoutDriver)
{
	PPROCESSCREATEDFILEWithCCBs pCreateedFileWithCCB= NULL;
	LIST_ENTRY * pListHead = NULL;
	LIST_ENTRY * pListtemp = NULL;
	ASSERT(pHandleOfexe!= NULL&& pszDriverLetter!=  NULL && pszFilePathWithoutDriver);

	if(IsListEmpty(&pHandleOfexe->ListForUsermodeFile)) return NULL;
	pListHead	= &pHandleOfexe->ListForUsermodeFile;
	pListtemp	= pListHead->Flink;
	while( pListtemp!= pListHead )
	{
		pCreateedFileWithCCB = CONTAINING_RECORD(pListtemp,PROCESSCREATEDFILEWithCCBs,list);
		pListtemp = pListtemp->Flink;
		if(pCreateedFileWithCCB )
		{
			if(_wcsicmp(pCreateedFileWithCCB ->szDriverLetter,pszDriverLetter)==0 && 
				_wcsicmp(pCreateedFileWithCCB ->szFullPathWithOutDriverLetter,pszFilePathWithoutDriver)==0 )
				return pCreateedFileWithCCB;
		}
	}
	return NULL;
}

VOID
PfpAddCCBIntoProcessCreatedFilesWithCCBs(PPROCESSCREATEDFILEWithCCBs pCreatesFilesWithCCB,
										 PCCBRECORD pCcbRecord)
{
	ASSERT(pCreatesFilesWithCCB!= NULL && pCcbRecord!= NULL);
	InsertHeadList(&pCreatesFilesWithCCB->ListHeadForCCofFileObject,&pCcbRecord->list);
}

VOID 
PfpAddCreateFilesWithCCBsIntoHandleOfExe(HandleOfExe *pHandleOfexe,
										 PPROCESSCREATEDFILEWithCCBs pCreatesFilesWithCCB)
{
	ASSERT(pHandleOfexe!= NULL && pCreatesFilesWithCCB!= NULL);
	InsertHeadList(&pHandleOfexe->ListForUsermodeFile,&pCreatesFilesWithCCB->list);
}
BOOLEAN 
PfpCanProcessbeStoped(PCHAR pHashValue,ULONG nHashLen)
{
	LIST_ENTRY * pHead  = NULL;
	LIST_ENTRY * ptemp  = NULL;
	LIST_ENTRY * pHead1 = NULL;
	LIST_ENTRY * ptemp1 = NULL;
	PHandleOfExe pHandleOfExe =  NULL;
	PPROCESSINFO pProcessInfo = NULL;
	BOOLEAN		 bResult = FALSE;
	PPROCESSCREATEDFILEWithCCBs pCreateFilesWithCCB = NULL;

	pProcessInfo  = PfpGetProcessInfoUsingHashValue(pHashValue,nHashLen,NULL);
	
	if(pProcessInfo == NULL) return FALSE;
	
	if(IsListEmpty(&pProcessInfo->hProcessList))
	{
		InterlockedDecrement(&pProcessInfo->nRef);
		return TRUE;
	}
	
	pHead = &pProcessInfo->hProcessList;
	ptemp = pHead ->Flink;
	while(ptemp != pHead )
	{
		pHandleOfExe = CONTAINING_RECORD(ptemp,HandleOfExe,list);
		ptemp = ptemp ->Flink;
		if(IsListEmpty(&pHandleOfExe->ListForUsermodeFile))
			continue;
		pHead1 = &pHandleOfExe->ListForUsermodeFile;
		ptemp1 = pHead1->Flink;
		while(ptemp1 != pHead1 )
		{
			pCreateFilesWithCCB = CONTAINING_RECORD(ptemp1,PROCESSCREATEDFILEWithCCBs,list);
			ptemp1 = ptemp1->Blink;
			if(pCreateFilesWithCCB && !IsListEmpty(&pCreateFilesWithCCB ->ListHeadForCCofFileObject))
			{
				InterlockedDecrement(&pProcessInfo->nRef);
				return FALSE;
			}
		}
	}
	InterlockedDecrement(&pProcessInfo->nRef);
	return TRUE;

}

PPROCESSCREATEDFILEWithCCBs
PfpCreateProcessCreatedFileWithCCB(PWCHAR szDriver,PWCHAR pszFilePath)
{
	PPROCESSCREATEDFILEWithCCBs pCreatedFileWithCCB = NULL;
	ASSERT(szDriver!= NULL && pszFilePath!= NULL);

	pCreatedFileWithCCB = ExAllocatePoolWithTag(PagedPool,sizeof(PROCESSCREATEDFILEWithCCBs),'4008');
	
	if(pCreatedFileWithCCB == NULL) return NULL;
	
	memcpy(pCreatedFileWithCCB ->szDriverLetter,szDriver,2*sizeof(WCHAR));
	pCreatedFileWithCCB ->szDriverLetter[2]=0;
	pCreatedFileWithCCB ->szFullPathWithOutDriverLetter= ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pszFilePath)+1),'5008');
	if(pCreatedFileWithCCB ->szFullPathWithOutDriverLetter== NULL)
	{
		ExFreePool_A(pCreatedFileWithCCB);
		return NULL;
	}
	wcscpy(pCreatedFileWithCCB ->szFullPathWithOutDriverLetter,pszFilePath);
	InitializeListHead(&pCreatedFileWithCCB ->ListHeadForCCofFileObject);
	return pCreatedFileWithCCB ;
}

VOID
PfpDeleteProcessCreatedFileWithCCB(PPROCESSCREATEDFILEWithCCBs* ppFileWithCCB)
{
	
	LIST_ENTRY *pListHead = NULL;
	LIST_ENTRY *pTemp     = NULL;
	PCCBRECORD pCCbRecord = NULL;
	ASSERT(ppFileWithCCB);
	if((*ppFileWithCCB)->szFullPathWithOutDriverLetter)
		ExFreePool_A((*ppFileWithCCB)->szFullPathWithOutDriverLetter);
	pListHead  =& (*ppFileWithCCB)->ListHeadForCCofFileObject;
	pTemp     = pListHead  ->Flink;
	if(!IsListEmpty(pListHead  ))
	{
		while(pTemp != pListHead )
		{
			pCCbRecord  = CONTAINING_RECORD(pTemp,CCBRECORD,list);
			pTemp = pTemp ->Flink;	
			if(pCCbRecord  )
			{
				ExFreePool_A(pCCbRecord);
			}
		}
	}
	ExFreePool_A(*ppFileWithCCB);
	*ppFileWithCCB= NULL;
}