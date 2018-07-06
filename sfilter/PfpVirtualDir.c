
#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#include <strsafe.h>
#include "ntifs.h"
#include "ntdddisk.h"

#include <stdlib.h>
#include <suppress.h>
#include "fspyKern.h"


PAGED_LOOKASIDE_LIST g_VirualDirLookasideList;
PAGED_LOOKASIDE_LIST g_VirualDiskFileLookasideList;


PDISKDIROBEJECT
PfpGetVirtualRootDirFromSpyDevice(PDEVICE_OBJECT  pSpyDevice )
{
	PFILESPY_DEVICE_EXTENSION	pDeviceExt = pSpyDevice->DeviceExtension;
	if(pDeviceExt == NULL)
		return NULL;

	return (PDISKDIROBEJECT)pDeviceExt->pVirtualRootDir;
}


PDISKDIROBEJECT PfpCreateVirtualDirObject(PWCHAR pDirName,PDISKDIROBEJECT pParent)
{
	PDISKDIROBEJECT pDir = NULL;
	ULONG nLenInbytes = 0;
	if(pDirName== NULL) return NULL;
	 
	pDir = (PDISKDIROBEJECT)ExAllocateFromPagedLookasideList(&g_VirualDirLookasideList)	;
	
	if(pDir == NULL) return NULL;
	
	pDir->pParent			= pParent;
	pDir->AccssLocker		=(ERESOURCE* )ExAllocateFromNPagedLookasideList(&g_EresourceLookasideList)	;
	pDir->DirName.Buffer	= ExAllocatePoolWithTag(PagedPool,nLenInbytes=((wcslen(pDirName)+1)<<1),'1004')	;
	pDir->DirName.Length	= (USHORT)nLenInbytes-2;
	pDir->DirName.MaximumLength =(USHORT) nLenInbytes;
	StringCbCopyW(pDir->DirName.Buffer, pDir->DirName.MaximumLength, pDirName);
 	ExInitializeResourceLite(pDir->AccssLocker	);
	InitializeListHead( &pDir->VirtualDiskFileLists );
	InitializeListHead( &pDir->ChildVirtualDirLists);
	if(pDir->DirName.Length ==2 && pDir->DirName.Buffer[0]==L'\\')
	{
		pDir->bRoot = TRUE;
	}
	else
	{
		pDir->bRoot = FALSE;
	}
	return pDir;
}

PVIRTUALDISKFILE CreateVirDiskFileAndInsertIntoParentVirtual(PDISKDIROBEJECT pParent,PWCHAR szFileName)
{
	PVIRTUALDISKFILE pVirtualDiskFile = NULL;
	
	if(pParent== NULL ||szFileName == NULL) return NULL;

	pVirtualDiskFile = (PVIRTUALDISKFILE)ExAllocateFromPagedLookasideList(&g_VirualDiskFileLookasideList);
	if(pVirtualDiskFile == NULL)  return NULL;
	
	memset(pVirtualDiskFile ,0,sizeof(VIRTUALDISKFILE));

	pVirtualDiskFile->pVirtualDiskLocker = (ERESOURCE*)ExAllocateFromNPagedLookasideList(&g_EresourceLookasideList)	;
	if(pVirtualDiskFile->pVirtualDiskLocker == NULL)
	{
		ExFreeToPagedLookasideList(&g_VirualDiskFileLookasideList,pVirtualDiskFile);
		return NULL;
	}

	pVirtualDiskFile->pParentDir = pParent;
	pVirtualDiskFile->FileName.Length= wcslen(szFileName)<<1;
	pVirtualDiskFile->FileName.Buffer = ExAllocatePoolWithTag(PagedPool,(pVirtualDiskFile->FileName.Length+2),'1005');
	pVirtualDiskFile->FileName. MaximumLength = pVirtualDiskFile->FileName.Length+2;
	if(	pVirtualDiskFile->FileName.Buffer == NULL)
	{
		ExFreeToNPagedLookasideList(&g_EresourceLookasideList,pVirtualDiskFile  ->pVirtualDiskLocker);
		ExFreeToPagedLookasideList(&g_VirualDiskFileLookasideList,pVirtualDiskFile);
		return NULL;
	}
	memcpy(pVirtualDiskFile->FileName.Buffer ,szFileName,pVirtualDiskFile->FileName.Length);
	pVirtualDiskFile->FileName.Buffer [pVirtualDiskFile->FileName.Length>>1]=L'\0';
	ExInitializeResourceLite(pVirtualDiskFile->pVirtualDiskLocker);
	InitializeListHead(&pVirtualDiskFile->listForDiskFileObject);
	InsertHeadList(&pParent->VirtualDiskFileLists,&pVirtualDiskFile->list);
	return pVirtualDiskFile;
}

BOOLEAN 
PfpDeleteVirtualDiskFile(PVIRTUALDISKFILE pVirtualDiskFile,PDISKFILEOBJECT pDiskFileObject)
{
	if(pVirtualDiskFile==NULL)
		return TRUE;
	
	if(pDiskFileObject)
	{
		RemoveEntryList(&pDiskFileObject->list);
		PfpDeleteDiskFileObject(&pDiskFileObject);
	}
	
	if(!IsListEmpty(&pVirtualDiskFile->listForDiskFileObject))
	{
		LIST_ENTRY*pListHead  = &(pVirtualDiskFile->listForDiskFileObject);
		PLIST_ENTRY pListTemp = pListHead  ->Blink;
		PDISKFILEOBJECT  pDiskFileObject = NULL;
		while(pListTemp!=pListHead)
		{
			pDiskFileObject = CONTAINING_RECORD(pListTemp,DISKFILEOBJECT,list);
			pListTemp = pListTemp->Blink;
			if(pDiskFileObject)
			{
				if(FlagOn(((PfpFCB*)(pDiskFileObject->pFCB))->FcbState,FCB_STATE_FILE_DELETED ) &&pDiskFileObject->pDiskFileObjectWriteThrough== NULL)
				{
					RemoveEntryList(&pDiskFileObject->list);	
					pDiskFileObject->pVirtualDiskFile =  NULL;
				}				
			}
		};
		if(!IsListEmpty(&pVirtualDiskFile->listForDiskFileObject))
			return FALSE;
	}

	RemoveEntryList(&pVirtualDiskFile->list);
	if(pVirtualDiskFile->FileName.Buffer)
		ExFreePool_A(pVirtualDiskFile->FileName.Buffer);
	if(pVirtualDiskFile->pVirtualDiskLocker)
	{
		ExDeleteResourceLite(pVirtualDiskFile->pVirtualDiskLocker);
		ExFreeToNPagedLookasideList(&g_EresourceLookasideList,pVirtualDiskFile->pVirtualDiskLocker);
	}
	ExFreeToPagedLookasideList(&g_VirualDiskFileLookasideList,pVirtualDiskFile);
	
	return TRUE;
}
VOID PfpDeleteVirtualDir(PDISKDIROBEJECT* pVirtualDir)
{
	if(pVirtualDir== NULL ||*pVirtualDir== NULL) return ;
	if(!IsListEmpty(&(*pVirtualDir)->VirtualDiskFileLists))
	{
		LIST_ENTRY*pListHead  = &((*pVirtualDir)->VirtualDiskFileLists);
		PLIST_ENTRY pListTemp = pListHead  ->Blink;
		PVIRTUALDISKFILE pVirtualDiskFileObejct = NULL;
		while(pListTemp!=pListHead)
		{
			pVirtualDiskFileObejct = CONTAINING_RECORD(pListTemp,VIRTUALDISKFILE,list);
			pListTemp = pListTemp->Blink;
			if(pVirtualDiskFileObejct)
			{
				//RemoveEntryList(&pVirtualDiskFileObejct->list);
				PfpDeleteVirtualDiskFile(pVirtualDiskFileObejct,NULL);
			}
		};
		
	}

	if(!IsListEmpty(&(*pVirtualDir)->VirtualDiskFileLists))
	{
		LIST_ENTRY*pListHead  = &((*pVirtualDir)->VirtualDiskFileLists);
		PLIST_ENTRY pListTemp = pListHead  ->Blink;
		PDISKDIROBEJECT pDiskFileObejct = NULL;
		while(pListTemp!=pListHead)
		{
			pDiskFileObejct = CONTAINING_RECORD(pListTemp,DISKDIROBEJECT,list);
			pListTemp = pListTemp->Blink;
			if(pDiskFileObejct)
			{				
				PfpDeleteVirtualDir(&pDiskFileObejct);
			}
		};

	}
	if((*pVirtualDir)->pParent!= NULL)
	{
		RemoveEntryList(&(*pVirtualDir)->list);
	}
	if((*pVirtualDir)->DirName.Buffer)
	{
		ExFreePool((*pVirtualDir)->DirName.Buffer);
	}
	ExDeleteResourceLite ( (*pVirtualDir)->AccssLocker);
	ExFreeToNPagedLookasideList(&g_EresourceLookasideList,(*pVirtualDir)->AccssLocker);
	ExFreeToPagedLookasideList(&g_VirualDirLookasideList,(*pVirtualDir));
	*pVirtualDir =  NULL;

}

 
PDISKDIROBEJECT 
PfpPareseToDirObject(PDISKDIROBEJECT pParentDir,PWCHAR szFullFileName,PWCHAR* pRemainer,BOOLEAN* bComplete)
{
	PDISKDIROBEJECT pTempParentDir = NULL;
	PLIST_ENTRY     pListHead = NULL;
	PLIST_ENTRY     pTempList = NULL;
	PWCHAR			pSeperator = NULL;
	ASSERT(pParentDir!=  NULL );
	ASSERT(szFullFileName!=  NULL );
	ASSERT(pRemainer!= NULL);
 
	*bComplete = FALSE;
	*pRemainer= szFullFileName;
	if(pParentDir->bRoot)
	{
		ASSERT(szFullFileName[0]==L'\\');
		*pRemainer = &szFullFileName[1];		
	}
	
	pSeperator = wcschr(*pRemainer,L'\\');
	if(pSeperator == NULL)
	{
		*bComplete = TRUE;
		return pParentDir;
	}
	if(IsListEmpty(&pParentDir->ChildVirtualDirLists))
	{	
		return pParentDir;
	}
	pListHead = &pParentDir->ChildVirtualDirLists;
	for(pTempList = pListHead ->Blink;pTempList != pListHead;pTempList = pTempList ->Blink )
	{
		pTempParentDir = CONTAINING_RECORD(pTempList,DISKDIROBEJECT,list);
		if(pTempParentDir )
		{
			if(pTempParentDir ->DirName.Length ==((pSeperator-*pRemainer)<<1) && _wcsnicmp(pTempParentDir ->DirName.Buffer,*pRemainer,pSeperator-*pRemainer)==0 )
			{				
				//ExAcquireResourceExclusiveLite(pTempParentDir->AccssLocker,TRUE);
				//ExReleaseResourceLite(pParentDir->AccssLocker);
				pParentDir= PfpPareseToDirObject(pTempParentDir,++pSeperator,pRemainer,bComplete);
				 break;
			}
		}
	}
	return pParentDir;
	
}

PDISKDIROBEJECT PfpMakeVirtualChildDirForFile(PDISKDIROBEJECT pTopVirtualDir,PWCHAR* pRemainFilePath)
{
	PWCHAR pSeperator = NULL;
	PDISKDIROBEJECT pTempDir = NULL;
	ASSERT(pTopVirtualDir!=  NULL);
	ASSERT(pRemainFilePath!=  NULL);
	
	if( (pSeperator =wcschr(*pRemainFilePath,L'\\'))== NULL) return pTopVirtualDir;
	*pSeperator = L'\0';
	pTempDir = PfpCreateVirtualDirObject(*pRemainFilePath,pTopVirtualDir);
	*pSeperator =L'\\';
	if(pTempDir == NULL)
	{	
		return pTopVirtualDir;
	}
	InsertHeadList(&pTopVirtualDir->ChildVirtualDirLists,&pTempDir->list);
	*pRemainFilePath=++pSeperator;

	//ExAcquireResourceExclusiveLite(pTempDir->AccssLocker,TRUE);
	//ExReleaseResourceLite(pTopVirtualDir->AccssLocker);
	
	return PfpMakeVirtualChildDirForFile(pTempDir,pRemainFilePath);
}

VOID
PfpAddDiskFileObjectIntoItsVirtualDiskFile(PVIRTUALDISKFILE pVirtualDiskFile,PDISKFILEOBJECT pDiskFile)
{
	ASSERT(pVirtualDiskFile);
	ASSERT(pDiskFile);
	pDiskFile->pVirtualDiskFile = pVirtualDiskFile;
	//ASSERT(IsListEmpty(&pVirtualDiskFile->listForDiskFileObject));
	 
	InsertHeadList(&pVirtualDiskFile->listForDiskFileObject,&pDiskFile->list);
}


PDISKFILEOBJECT 
PfpFindDiskFileObjectInParent(PDISKDIROBEJECT pParent ,UNICODE_STRING* FileFullPath)
{
	//UNICODE_STRING TempString;
	PLIST_ENTRY pTempList = NULL;
	PDISKFILEOBJECT pDiskFileObject = NULL;
// 	
// 	LONG   nIndexofLastSep = ((FileFullPath->Length>>1)-1);
// 	
// 	ASSERT(pParent);
// 	ASSERT(FileFullPath);
// 	
// 	if(IsListEmpty(&pParent->ChildDiskFilesLists))return NULL; 
// 
// 	for(pTempList  = pParent->ChildDiskFilesLists.Blink;pTempList  !=&pParent->ChildDiskFilesLists; pTempList=pTempList->Blink)
// 	{
// 		pDiskFileObject = CONTAINING_RECORD(pTempList,DISKFILEOBJECT,list );
// 		if(pDiskFileObject )
// 		{
// 			if(0==RtlCompareUnicodeString(&pDiskFileObject->FileName,FileFullPath,TRUE) && 
// 				pDiskFileObject->pFCB&&
// 				(pDiskFileObject->pDiskFileObjectWriteThrough!= NULL&&
// 				(((PPfpFCB)pDiskFileObject->pFCB)->bModifiedByOther != TRUE)))
// 			{
// 				return pDiskFileObject;
// 			}
// 		}
// 	}
	
	return NULL;
}

PDISKFILEOBJECT
PpfGetDiskFileObjectFromVirtualDisk(PVIRTUALDISKFILE pVirtualDiskFile)
{	
	PLIST_ENTRY pTempList = NULL;
	PDISKFILEOBJECT pDiskFileObject = NULL;
	BOOLEAN		bPrint= FALSE;
	LONG nNum = 0;
	if(pVirtualDiskFile== NULL || IsListEmpty(&pVirtualDiskFile->listForDiskFileObject))return NULL;

	for(pTempList  = pVirtualDiskFile->listForDiskFileObject.Blink;pTempList  !=&pVirtualDiskFile->listForDiskFileObject; pTempList=pTempList->Blink)
	{
		pDiskFileObject = CONTAINING_RECORD(pTempList,DISKFILEOBJECT,list );
		if(pDiskFileObject )
		{
			if( pDiskFileObject->pFCB&&
				(pDiskFileObject->pDiskFileObjectWriteThrough!= NULL&&
				(((PPfpFCB)pDiskFileObject->pFCB)->bModifiedByOther != TRUE)))
			{
				return pDiskFileObject;
			}else
			{
				KdPrint(("Virtual DIsk File has other files ,so return NULL %wZ\r\n",&pVirtualDiskFile->FileName));
				bPrint = TRUE;
			}
		}
	}
	if(bPrint )
	{
		for(pTempList  = pVirtualDiskFile->listForDiskFileObject.Blink;pTempList  !=&pVirtualDiskFile->listForDiskFileObject; pTempList=pTempList->Blink)
		{
			nNum ++;
		}
		KdPrint(("Virtual DIsk File has %d files \r\n",nNum));
	}
	return NULL;

}

PVIRTUALDISKFILE 
PfpFindVirtualDiskFileObjectInParent(PDISKDIROBEJECT pParent ,UNICODE_STRING* FileFullPath)
{	
	PLIST_ENTRY pTempList = NULL;
	PVIRTUALDISKFILE pVirtualDiskFileObject = NULL;

	LONG   nIndexofLastSep = ((FileFullPath->Length>>1)-1);

	ASSERT(pParent);
	ASSERT(FileFullPath);

	if(IsListEmpty(&pParent->VirtualDiskFileLists))return NULL;
	 
	for(pTempList  = pParent->VirtualDiskFileLists.Blink;pTempList  !=&pParent->VirtualDiskFileLists; pTempList=pTempList->Blink)
	{
		pVirtualDiskFileObject  = CONTAINING_RECORD(pTempList,VIRTUALDISKFILE,list );
		if(pVirtualDiskFileObject  )
		{
			if(0==RtlCompareUnicodeString(&pVirtualDiskFileObject->FileName,FileFullPath,TRUE) )//&& 
// 				pVirtualDiskFileObject ->pFCB&&
// 				(pDiskFileObject->pDiskFileObjectWriteThrough!= NULL&&
// 				(((PPfpFCB)pDiskFileObject->pFCB)->bModifiedByOther != TRUE)))
			{
				return pVirtualDiskFileObject;
			}
		}
	}

	return NULL;
}


PDISKDIROBEJECT
PfpGetDiskDirObject(PDISKDIROBEJECT pParentDir,PWCHAR szFullFileDir,ULONG nLeninBytes)
{
	BOOLEAN bEndIsSperator= FALSE;
	PWCHAR pszRemainer = NULL;
	PLIST_ENTRY pListTemp = NULL;
	PDISKDIROBEJECT pParent  = NULL;
	PDISKDIROBEJECT pTempDir  = NULL;
	BOOLEAN			bComplete  = FALSE;
	ULONG nLen =0;
	if(szFullFileDir[(nLeninBytes>>1) -1]== L'\\')
	{
		bEndIsSperator= TRUE;
		szFullFileDir[(nLeninBytes>>1)-1]=L'\0';
	}
	if(szFullFileDir[0]==L'\0')
	{
		if(bEndIsSperator)
		{
			szFullFileDir[(nLeninBytes>>1)-1]=L'\\';
			szFullFileDir[nLeninBytes>>1]=L'\0';
		}
		//ExReleaseResourceLite(pParentDir->AccssLocker);
		return NULL;
	}
	
	pParent  = PfpPareseToDirObject(pParentDir,szFullFileDir,&pszRemainer ,&bComplete);
	
	if(!bComplete||IsListEmpty(&pParent->ChildVirtualDirLists))
	{
		if(bEndIsSperator)
		{
			szFullFileDir[(nLeninBytes>>1)-1]=L'\\';
			szFullFileDir[nLeninBytes>>1]=L'\0';
		}
		//ExReleaseResourceLite(pParent->AccssLocker);
		return NULL;
	}
	
	nLen  = wcslen(pszRemainer);
	if(bEndIsSperator)
	{
		szFullFileDir[(nLeninBytes>>1)-1]=L'\\';
		szFullFileDir[nLeninBytes>>1]=L'\0';
	}
	for(pListTemp = pParent->ChildVirtualDirLists.Blink;pListTemp != &pParent->ChildVirtualDirLists;pListTemp= pListTemp->Blink)
	{
		pTempDir = CONTAINING_RECORD(pListTemp,DISKDIROBEJECT,list);
		if(pTempDir )
		{
			if(pTempDir->DirName.Length== (nLen<<1) && _wcsnicmp(pTempDir->DirName.Buffer,pszRemainer,nLen)==0)
			{
				//ExAcquireResourceExclusiveLite(pTempDir->AccssLocker,TRUE);
				//ExReleaseResourceLite(pParent->AccssLocker);;
				return pTempDir;
			}
		}
	}
	//ExReleaseResourceLite(pParent->AccssLocker);
	return NULL;
}


PERESOURCE
PfpCloseDiskFilesUnderVirtualDirHasGoneThroughCleanUp(PDISKDIROBEJECT pVirtualParent,PDISKDIROBEJECT pVirtualDir)
{
	PLIST_ENTRY pListTemp= NULL;
	PDISKDIROBEJECT  pTempDir= NULL;
	PVIRTUALDISKFILE  pVirtualTempDiskFile= NULL;

	 
	if(!IsListEmpty(&pVirtualDir->VirtualDiskFileLists))
	{
		for(pListTemp= pVirtualDir->VirtualDiskFileLists.Blink;pListTemp!= &pVirtualDir->VirtualDiskFileLists;pListTemp= pListTemp->Blink)
		{
			pVirtualTempDiskFile = CONTAINING_RECORD(pListTemp,VIRTUALDISKFILE,list);
			PfpCloseDiskFileObjectHasGoneThroughCleanUpInVirtualDiskFile(pVirtualTempDiskFile);
		}
	}
	
   
  	if(!IsListEmpty(&pVirtualDir->ChildVirtualDirLists))
  	{
  		for(pListTemp= pVirtualDir->ChildVirtualDirLists.Blink;pListTemp!= &pVirtualDir->ChildVirtualDirLists;pListTemp= pListTemp->Blink)
  		{
  			pTempDir = CONTAINING_RECORD(pListTemp,DISKDIROBEJECT,list);
			//ExAcquireResourceExclusiveLite(pTempDir->AccssLocker,TRUE);
  			PfpCloseDiskFilesUnderVirtualDirHasGoneThroughCleanUp(NULL,pTempDir );
			//ExReleaseResourceLite(pTempDir->AccssLocker);
  		}
  	}
	return pVirtualDir->AccssLocker;
	 
}

VOID
PfpCloseDiskFileObjectHasGoneThroughCleanUp(PDISKFILEOBJECT pDiskFileObject)
{
	if(PfpIsAllFileObjectThroughCleanup(pDiskFileObject))
	{

		PfpCloseRealDiskFile(&(pDiskFileObject->hFileWriteThrough),&(pDiskFileObject->pDiskFileObjectWriteThrough));

		SetFlag(((PPfpFCB)pDiskFileObject->pFCB)->FcbState, FCB_STATE_FILE_DELETED);

		if(pDiskFileObject->bNeedBackUp)
		{//这个磁盘上的文件也关闭了！，那么发送消息给那个备份的Thread，去关闭备份的文件，

			PfpCloseRealDiskFile(&pDiskFileObject->hBackUpFileHandle,&pDiskFileObject->hBackUpFileObject);
		}
	}
	
}
VOID
PfpCloseDiskFileObjectHasGoneThroughCleanUpInVirtualDiskFile(PVIRTUALDISKFILE pVirtualDiskFileObject)
{
	PLIST_ENTRY pListHead = NULL;
	PLIST_ENTRY pTempList = NULL;
	PDISKFILEOBJECT pDiskFileObeject = NULL;
	ExAcquireResourceExclusiveLite( pVirtualDiskFileObject->pVirtualDiskLocker,TRUE);
	KdPrint(("VirtualDiskFile function accquire file resource %Xh\r\n",pVirtualDiskFileObject->pVirtualDiskLocker));
	if(IsListEmpty(&pVirtualDiskFileObject->listForDiskFileObject)) 
	{
		KdPrint(("VirtualDiskFile function release file resource %Xh\r\n",pVirtualDiskFileObject->pVirtualDiskLocker));
		ExReleaseResourceLite(pVirtualDiskFileObject->pVirtualDiskLocker);
		return  ;
	}
	pListHead = &pVirtualDiskFileObject->listForDiskFileObject;
	
	for(pTempList = pListHead ->Blink;pTempList != pListHead;pTempList = pTempList ->Blink )
	{
		pDiskFileObeject  = CONTAINING_RECORD(pTempList,DISKFILEOBJECT,list);
		if(pDiskFileObeject  )
		{
			PfpCloseDiskFileObjectHasGoneThroughCleanUp(pDiskFileObeject  );
		}
	}

	ExReleaseResourceLite(pVirtualDiskFileObject->pVirtualDiskLocker);
	KdPrint(("VirtualDiskFile function release file resource %Xh\r\n",pVirtualDiskFileObject->pVirtualDiskLocker));
}

VOID 
PfpCloseDiskFileObjectsUnderDir(PWCHAR pszFolderPath)
{
	PDEVICE_OBJECT pSpyDevice = NULL;
	WCHAR szDeviceLetter[3]={0};
	PDISKDIROBEJECT pVirtualRootDir= NULL;
	PDISKDIROBEJECT pVirtualDir =NULL;
	PWCHAR			pPathWithoutDevice= NULL;
	unsigned int nSize = 0;
	 
	 
	szDeviceLetter[0]=((PWCHAR)pszFolderPath)[0];
	szDeviceLetter[1]=((PWCHAR)pszFolderPath)[1];

	pSpyDevice = PfpGetSpyDeviceFromName(szDeviceLetter);
	if(!pSpyDevice )
		goto DirectExit;

	pVirtualRootDir = PfpGetVirtualRootDirFromSpyDevice(pSpyDevice);
	if( pVirtualRootDir== NULL )
	{					
		goto DirectExit;
	}
	nSize = wcslen((PWCHAR)pszFolderPath)*sizeof(WCHAR);
	pPathWithoutDevice = ExAllocatePoolWithTag(PagedPool,nSize,'1111');
	if(!pPathWithoutDevice )
	{
		goto DirectExit;
	}
	StringCbCopyW(pPathWithoutDevice, nSize, &((PWCHAR)pszFolderPath)[2]);
	ExAcquireResourceSharedLite( pVirtualRootDir->AccssLocker,TRUE);

	pVirtualDir = PfpGetDiskDirObject(pVirtualRootDir,pPathWithoutDevice,wcslen(pPathWithoutDevice)*sizeof(WCHAR));

	if(pVirtualDir )
	{
		PfpCloseDiskFilesUnderVirtualDirHasGoneThroughCleanUp(pVirtualRootDir,pVirtualDir);	
	}

	ExReleaseResourceLite(pVirtualRootDir->AccssLocker);
	ExFreePool_A(pPathWithoutDevice);

DirectExit:
	;
	 
}