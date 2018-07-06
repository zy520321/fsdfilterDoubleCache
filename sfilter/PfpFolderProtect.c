 /*++

Copyright (c) 1998-1999 Microsoft Corporation

Module Name:

    fspyTx.c

Abstract:

    This module contains the support routines for the KTM transactions.
    This feature is only available in windows VISTA and later.

Environment:

    Kernel mode

--*/

#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#include <ntifs.h>
#include <stdio.h>
#include "filespy.h"
#include "fspyKern.h"

BOOLEAN IsFolderUnderProtect(WCHAR *pFolderPath,ULONG nsize)
{
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	LONG		HideObjectLength = 0;


	if (IsListEmpty(&g_FolderProtectList))
	{
		return FALSE;
	}
	
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		if((tmpHideFile->szFullPathSize==nsize)&& _wcsnicmp(tmpHideFile ->szFullPath,pFolderPath,nsize)==0)
			return TRUE;
	};
	return FALSE;
}


BOOLEAN IsFileOrFolderUnderProtect(WCHAR *pFolderPath,LONG nLen,BOOLEAN *bEncrypt,BOOLEAN *bBackup,BOOLEAN* bLocked)
{
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	ULONG		HideObjectLength = 0;


	if (IsListEmpty(&g_FolderProtectList))
	{
		return FALSE;
	}

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile  = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		HideObjectLength = tmpHideFile->szFullPathSize;
		
		if( HideObjectLength>((ULONG)nLen>>1))
			continue;

		if(_wcsnicmp(tmpHideFile->szFullPath,pFolderPath,HideObjectLength)==0)
		{
			if(bEncrypt)
			{
				*bEncrypt = tmpHideFile->bEncryptRealTime;
			}
			if(bBackup)
			{
				*bBackup  = tmpHideFile->bBackup;
			}
			return TRUE;
		}
	};
	return FALSE;
}



BOOLEAN	AddNewFolderUnderProtection(PFOLDERPROTECT pProtectFolder)
{ 
	return TRUE;
}
BOOLEAN DeleteFolderFromProtection(WCHAR *pFullPath)
{ 
	return FALSE;
}
BOOLEAN QueryFolerProtection(PFOLDERPROTECT pProtectFolder)
{ 
	return FALSE;
}
BOOLEAN ModifyFolerProtection(PFOLDERPROTECT pProtectFolder)
{ 
	return FALSE;
}

ULONG CalcFolderProctectionLen()
{
	ULONG		nLen = 0;
	PLIST_ENTRY headListEntry			= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry			= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	

	if (IsListEmpty(&g_FolderProtectList))
	{
		return 0;
	}
	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		nLen+=  (sizeof(FOLDERPROTECT)+sizeof(WCHAR)*(1+tmpHideFile ->szFullPathSize)+7)&~((ULONG)7);
		
	};
	ExReleaseResourceLite(&g_FolderResource);
	FsRtlExitFileSystem();
	return nLen;
}

ULONG   CopyFolderItemsIntoUserBuffer(PVOID pBuffer,ULONG nLen)
{
	ULONG		nLenAll = 0;
	PLIST_ENTRY headListEntry			= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry			= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	PFOLDERPROTECT pFolderItem			= (PFOLDERPROTECT) pBuffer;
	ULONG nLenItem=0;

	if(pBuffer ==0||nLen ==0) 
		return 0;

	if (IsListEmpty(&g_FolderProtectList))
	{
		return 0;
	}
	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry	= tmpListEntry->Flink;
		tmpHideFile		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		nLenItem		= (sizeof(FOLDERPROTECT)+sizeof(WCHAR)*(1+tmpHideFile ->szFullPathSize)+7)&~((ULONG)7);
		
		nLenAll			+=  nLenItem		;
		if(nLenAll> nLen)
		{
			nLenAll-=  nLenItem	;
			break;
		}
		pFolderItem ->Type				= tmpHideFile->Type ;
		pFolderItem ->bEncryptRealTime	= tmpHideFile->bEncryptRealTime ;
		pFolderItem ->bBackup			= tmpHideFile->bBackup ;
		pFolderItem ->State				= tmpHideFile->State;
		pFolderItem ->EncryptForFileTypes	= (ULONG)tmpHideFile->bEncryptForFileType;
		pFolderItem->FileTypesNum = 0;

		pFolderItem->FileTypesNum = PfpCopyFileTypesIntoBufferForFolder(pFolderItem->FileTypes,100,&tmpHideFile->pListHeadOfFileTypes);
 
		memcpy(pFolderItem ->szDisplayName,tmpHideFile->szDisplayName,50*sizeof(WCHAR));
		if(tmpHideFile ->szFullPathSize!=0)
		{
			wcscpy(pFolderItem ->szFullPath,tmpHideFile->szFullPath);
		}else
		{
			pFolderItem ->szFullPath[0]=L'\0';
		}
		pFolderItem =(PFOLDERPROTECT)((UCHAR*)pFolderItem +nLenItem);

	};
	ExReleaseResourceLite(&g_FolderResource);
	FsRtlExitFileSystem();
	return nLenAll;
}

BOOLEAN QueryFileTypesLenForFolderEncryption(IN WCHAR *pFolderPath,ULONG *pnLen)
{ 
	return FALSE;
}
BOOLEAN SetFileTypesForFolderEncryption(IN WCHAR *pFolderPath,IN WCHAR* szFileTypes)
{ 
	return FALSE;
}

BOOLEAN QueryFileTypesForFolderEncryption(IN WCHAR *pFolderPath,OUT WCHAR* szFileTypes,ULONG nLen)
{ 
	return FALSE;
}

BOOLEAN IsFileTypeEncryptForFolder(IN		WCHAR* szDriver,
								   IN		WCHAR* szFolderWithoutDriverLetter,
								   IN		LONG   FolderLen,
								   IN		WCHAR* szFileType)
{
	PLIST_ENTRY headListEntry			= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry			= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	ULONG		FolderProtectLen	    = 0;
	PWCHAR		pTemp					= NULL;
	LONG		nIndex					= 0;
	if(	szDriver == NULL|| szFolderWithoutDriverLetter== NULL ||FolderLen==0)
		return FALSE;

	 
	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	if (IsListEmpty(&g_FolderProtectList))
	{
		ExReleaseResourceLite(&g_FolderResource);
		 
		return FALSE;
	}

	
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry	= tmpListEntry->Flink;
		tmpHideFile		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		if(_wcsnicmp(szDriver,tmpHideFile->szFullPath,2)!=0)
			continue;

		if( (FolderProtectLen=tmpHideFile->szFullPathSize) > (2+(ULONG)FolderLen) )
			continue;

		FolderProtectLen-=2;
		if(_wcsnicmp(szFolderWithoutDriverLetter,tmpHideFile->szFullPath+2,FolderProtectLen) ==0)
		{
			if(tmpHideFile->bEncryptForFileType!= ENCRYPT_TYPES)
			{
				ExReleaseResourceLite(&g_FolderResource);
				return TRUE;
			}

			if((ULONG)FolderLen>FolderProtectLen)
			{
				if(szFolderWithoutDriverLetter[FolderProtectLen]!=L'\\')
					continue;
			}
			if(IsListEmpty(&tmpHideFile->pListHeadOfFileTypes))
			{
				ExReleaseResourceLite(&g_FolderResource);
				return FALSE;
			}

			{
				PLIST_ENTRY headListEntryType			= &tmpHideFile->pListHeadOfFileTypes;
				PLIST_ENTRY tmpListEntryType			= headListEntryType			;
				PFILETYPEOFFOLDERITEM pFileType				= NULL;
				while(tmpListEntryType->Blink!= headListEntryType)
				{	
					tmpListEntryType = tmpListEntryType->Blink;
					pFileType		 = (PFILETYPEOFFOLDERITEM )CONTAINING_RECORD(tmpListEntryType,FILETYPEOFFOLDERITEM,list);
					if(pFileType)
					{
						WCHAR *sztemp = pFileType->szFileType;
						while(*sztemp == L'.' && *sztemp != L'\0')sztemp ++;//删除前面的‘.’符号
						while(*szFileType == L'.' && *szFileType != L'\0')szFileType ++;//删除前面的‘.’符号

						if(0==_wcsicmp(sztemp,szFileType))
						{
							ExReleaseResourceLite(&g_FolderResource);
							return TRUE;
						}
					}
				}
			} 
		}else
		{
			continue;
		}
	};

	ExReleaseResourceLite(&g_FolderResource);

	return  FALSE;
}


BOOLEAN IsFileNeedBackupForFolder(IN		WCHAR* szDriver,
								   IN		WCHAR* szFolderWithoutDriverLetter,
								   IN		LONG   FolderLen,
								   IN		WCHAR* pszFiletype)
{
	PLIST_ENTRY headListEntry			= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry			= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	ULONG		FolderProtectLen	    = 0;
	PWCHAR		pTemp					= NULL;
	LONG		nIndex					= 0;
	BOOLEAN		bNeedBackup				= FALSE;
	return FALSE;
	if(	szDriver == NULL|| szFolderWithoutDriverLetter== NULL ||FolderLen==0 || pszFiletype== NULL ||wcslen(pszFiletype)==0)
		return FALSE;


 
	if (IsListEmpty(&g_FolderProtectList))
	{
		 return FALSE;
	}

	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry	= tmpListEntry->Flink;
		tmpHideFile		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		if(_wcsnicmp(szDriver,tmpHideFile->szFullPath,2)!=0)
			continue;

		if( (FolderProtectLen=tmpHideFile->szFullPathSize) > (2+(ULONG)FolderLen) )
			continue;

		FolderProtectLen-=2;
		if(_wcsnicmp(szFolderWithoutDriverLetter,tmpHideFile->szFullPath+2,FolderProtectLen) ==0)
		{
			if((ULONG)FolderLen>FolderProtectLen)
			{
				if(szFolderWithoutDriverLetter[FolderProtectLen]!=L'\\')
					continue;
			}

			{
				PLIST_ENTRY headListEntryType			= &tmpHideFile->pListHeadOfFileTypes;
				PLIST_ENTRY tmpListEntryType			= headListEntryType			;
				PFILETYPEOFFOLDERITEM pFileType				= NULL;
				while(tmpListEntryType->Blink!= headListEntryType)
				{	
					tmpListEntryType = tmpListEntryType->Blink;
					pFileType		 = (PFILETYPEOFFOLDERITEM )CONTAINING_RECORD(tmpListEntryType,FILETYPEOFFOLDERITEM,list);
					if(pFileType)
					{
						WCHAR *sztemp = pFileType->szFileType;
						while(*sztemp == L'.' && *sztemp != L'\0')sztemp ++;//删除前面的‘.’符号
						while(*pszFiletype == L'.' && *pszFiletype != L'\0')pszFiletype ++;//删除前面的‘.’符号

						if(0==_wcsicmp(sztemp,pszFiletype))
						{
							bNeedBackup = (pFileType->bBackup!=0);
							break;
						}
					}
				}
			} 
			 
			break;

		}else
		{
			continue;
		}
	};

	ExReleaseResourceLite(&g_FolderResource);

	return  bNeedBackup;
}
BOOLEAN IsPathUnderVirtualFolder(
								 IN		WCHAR* szDriver,
								 IN		WCHAR* szFolderWithoutDriverLetter,
								 IN		LONG   FolderLen
								 )
								
{

	PLIST_ENTRY headListEntry			= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry			= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	ULONG		FolderProtectLen	    = 0;
	BOOLEAN		bFound					= FALSE;
	if(	szDriver == NULL|| 
		szFolderWithoutDriverLetter== NULL ||
		 
		FolderLen==0)
		return FALSE;
	
	 
	if (IsListEmpty(&g_FolderProtectList))
	{
		 
		return FALSE;
	}
	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry	= tmpListEntry->Flink;
		tmpHideFile		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		if(_wcsnicmp(szDriver,tmpHideFile->szFullPath,2)!=0)
			continue;

		if( (FolderProtectLen=tmpHideFile->szFullPathSize) > (2+(ULONG)FolderLen) )
			continue;
		
		FolderProtectLen-=2;
		if(_wcsnicmp(szFolderWithoutDriverLetter,tmpHideFile->szFullPath+2,FolderProtectLen) ==0)
		{
			if((ULONG)FolderLen>FolderProtectLen)
			{
				if(szFolderWithoutDriverLetter[FolderProtectLen]!=L'\\')
					continue;
			}
		 
			 
			bFound = TRUE;
			break;
		}else
		{
			continue;
		}
	};
	
	ExReleaseResourceLite(&g_FolderResource);

	return  bFound;
}
BOOLEAN GetFolderProtectProperty(
								 IN		WCHAR* szDriver,
								 IN		WCHAR* szFolderWithoutDriverLetter,
								 IN		LONG   FolderLen,
								 OUT	PROTECTTYPE* ProtectType,
								 OUT	BOOLEAN* bEncrypt,
								 OUT	BOOLEAN *bBackup,
								 OUT	BOOLEAN* bLocked,
								 OUT	ULONG* EncryptMode)

{

	PLIST_ENTRY headListEntry			= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry			= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	ULONG		FolderProtectLen	    = 0;
	BOOLEAN		bFound					= FALSE;
	if(	szDriver == NULL|| 
		szFolderWithoutDriverLetter== NULL ||
		ProtectType== NULL || 
		bEncrypt == NULL|| 
		bBackup== NULL||
		FolderLen==0)
		return FALSE;


	if (IsListEmpty(&g_FolderProtectList))
	{

		return FALSE;
	}
	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry	= tmpListEntry->Flink;
		tmpHideFile		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		if(_wcsnicmp(szDriver,tmpHideFile->szFullPath,2)!=0)
			continue;

		if( (FolderProtectLen=tmpHideFile->szFullPathSize) > (2+(ULONG)FolderLen) )
			continue;

		FolderProtectLen-=2;
		if(_wcsnicmp(szFolderWithoutDriverLetter,tmpHideFile->szFullPath+2,FolderProtectLen) ==0)
		{
			if((ULONG)FolderLen>FolderProtectLen)
			{
				if(szFolderWithoutDriverLetter[FolderProtectLen]!=L'\\')
					continue;
			}
			*ProtectType = tmpHideFile->Type;
			*bEncrypt	 = tmpHideFile->bEncryptRealTime;
			*bBackup     = tmpHideFile->bBackup;
			*bLocked	 = (tmpHideFile->State==LOCKED); 
			*EncryptMode = tmpHideFile->bEncryptForFileType;

			bFound = TRUE;
			break;
		}else
		{
			continue;
		}
	};

	ExReleaseResourceLite(&g_FolderResource);

	return  bFound;
}
VOID	InitFolerdProtectorFromBuffer (PVOID pBuffer,ULONG nLen)
{
	PFOLDERPROTECTITEM  pItem = NULL;
	PFOLDERPROTECT tmpFolder = NULL;
	ULONG nFilePathLen = 0;
	PUCHAR pBufferEnd = (PUCHAR)pBuffer +nLen;
	ULONG nIndex = 0;
	ASSERT(pBuffer && nLen!=0);
	
	
	
	while(nLen>=sizeof(FOLDERPROTECT))
	{
		tmpFolder	= (PFOLDERPROTECT)pBuffer;
		nFilePathLen= (sizeof(WCHAR)*(1+wcslen(tmpFolder ->szFullPath))+7)&~((ULONG)7);
		
		pItem		= ExAllocatePool_A(PagedPool,nFilePathLen+sizeof(FOLDERPROTECTITEM));
		
		pItem ->Type				= tmpFolder->Type ;
		pItem ->bEncryptRealTime	= (BOOLEAN) tmpFolder->bEncryptRealTime ;
		pItem ->bBackup				= (BOOLEAN) tmpFolder->bBackup ;
		pItem ->State				= tmpFolder->State;
		pItem->bEncryptForFileType	= tmpFolder->EncryptForFileTypes;
		memcpy(pItem ->szDisplayName,tmpFolder->szDisplayName,50*sizeof(WCHAR));
		pItem->pFileTypesForEncryption = NULL;
		
		wcscpy(pItem ->szFullPath,tmpFolder->szFullPath);
		pItem ->szFullPathSize = wcslen(pItem ->szFullPath);
		InitializeListHead(&pItem->pListHeadOfFileTypes);
		for(nIndex=0;nIndex<tmpFolder->FileTypesNum;++nIndex)
		{
			PFILETYPEOFFOLDERITEM pFiletype= ExAllocatePool_A(PagedPool,sizeof(FILETYPEOFFOLDERITEM ));
			if(pFiletype)
			{
				memcpy(pFiletype->szFileType,tmpFolder->FileTypes[nIndex].szFileType,50*sizeof(WCHAR));
				pFiletype->bBackup = tmpFolder->FileTypes[nIndex].bBackup;
				InsertHeadList(&pItem->pListHeadOfFileTypes,&pFiletype->list);
			}
		}
		InsertHeadList(&g_FolderProtectList, &pItem->list);

		pBuffer		= (PUCHAR)pBuffer+((sizeof(FOLDERPROTECT)+sizeof(WCHAR)*(1+wcslen(tmpFolder ->szFullPath))+7)&~((ULONG)7));
		nLen-=sizeof(FOLDERPROTECT);
	};

	
 
}

ULONG 
PfpCopyFileTypesIntoBufferForFolder(IN OUT PFOLDERFILETYPE pFolderTypes,IN OUT ULONG nNum,IN PLIST_ENTRY  pFileTypeHead)
{
	
	
	PFILETYPEOFFOLDERITEM pFileTypeitem = NULL;
	PLIST_ENTRY headListEntry	= pFileTypeHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	ULONG						nIndex = 0;
	if( pFileTypeHead== NULL )
		return 0 ;
	
	if(IsListEmpty(pFileTypeHead))
	{
	 
		return 0;
	}
	 
	
	while (tmpListEntry->Flink != headListEntry && nIndex<nNum)
	{
		
		tmpListEntry  = tmpListEntry->Flink;
		pFileTypeitem = (PFILETYPEOFFOLDERITEM)CONTAINING_RECORD(tmpListEntry, FILETYPEOFFOLDERITEM, list);
		if(pFileTypeitem )
		{	 
			memcpy(pFolderTypes[nIndex].szFileType,pFileTypeitem->szFileType,50*sizeof(WCHAR));
			pFolderTypes[nIndex].bBackup = pFileTypeitem->bBackup;
			nIndex++;
		}
	};
	
	return nIndex;
}
BOOLEAN SetLockFolderState(PWCHAR pStrFolderPath,ULONG nLen,FOLDERSTATE state)
{	
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	LONG		HideObjectLength = 0;


	if (IsListEmpty(&g_FolderProtectList))
	{
		return FALSE;
	}

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		
		if(tmpHideFile ->szFullPathSize*sizeof(WCHAR) !=nLen )continue;

		if(_wcsnicmp(tmpHideFile ->szFullPath,pStrFolderPath,nLen/sizeof(WCHAR))==0)
		{
			tmpHideFile->State = state;
			break;
		}
	};

	return TRUE;
}


BOOLEAN LockAllFolders()
{
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	LONG		HideObjectLength = 0;
	BOOLEAN		bChanged = FALSE;

	if (IsListEmpty(&g_FolderProtectList))
	{
		return FALSE;
	}

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);

		//if(wcslen(tmpHideFile ->szFullPath)*sizeof(WCHAR) !=nLen )continue;

		if(tmpHideFile->State != LOCKED)
		{
			tmpHideFile->State = LOCKED;			
			bChanged = TRUE;
		}
	};
	return bChanged;
}

PFOLDERPROTECTITEM
PfpGetFolderItem(PWCHAR szFolderPath,ULONG nSize)
{
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	LONG		HideObjectLength = 0;


	if (IsListEmpty(&g_FolderProtectList))
	{
		return NULL;
	}

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);

		//if(wcslen(tmpHideFile ->szFullPath)*sizeof(WCHAR) !=nLen )continue;

		if((nSize ==tmpHideFile ->szFullPathSize) &&_wcsnicmp(tmpHideFile ->szFullPath,szFolderPath ,nSize)==0)
		{
			return tmpHideFile;
		}
	};

	return NULL;
}


NTSTATUS
PfpEnableFolderRealTimeEncrypt(IN PFOLDERPROTECTSETTING pFolderEnable)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(pFolderEnable->szFolderPath,wcslen(pFolderEnable->szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	tmpFolderItem->bEncryptRealTime  = (BOOLEAN)(pFolderEnable->nEnabler!=0);
	return 0;
}

NTSTATUS
PfpChangeFolderProtectType(IN PFOLDERPROTECTSETTING pFolderEnable)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(pFolderEnable->szFolderPath,wcslen(pFolderEnable->szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	tmpFolderItem->Type  = (PROTECTTYPE)pFolderEnable->nEnabler;
	return 0;
}

NTSTATUS
PfpChangeFolderState(IN PFOLDERPROTECTSETTING pFolderEnable)//lock or unlock
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(pFolderEnable->szFolderPath,wcslen(pFolderEnable->szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	tmpFolderItem->State  = (ULONG)pFolderEnable->nEnabler;
	return 0;
}


NTSTATUS
PfpEnableFolderBackup(IN PFOLDERPROTECTSETTING pFolderEnable)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(pFolderEnable->szFolderPath,wcslen(pFolderEnable->szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	tmpFolderItem->bBackup  = (BOOLEAN)(pFolderEnable->nEnabler!=0);
	return 0;
}


NTSTATUS
PfpChangeEncryptionTypeForFolder(IN PFOLDERPROTECTSETTING pFolderEnable)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(pFolderEnable->szFolderPath,wcslen(pFolderEnable->szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	tmpFolderItem->bEncryptForFileType  = (BOOLEAN)(pFolderEnable->nEnabler==0);//这个地方要注意 是想对于 forceencrypt的 反值
	return 0;
}

NTSTATUS
PfpIsFolderLocked(PWCHAR szFolderPath,BOOLEAN* pbLocked)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(szFolderPath,wcslen(szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	*pbLocked = (tmpFolderItem->State==LOCKED);
	return 0;
}

NTSTATUS
PfpSetDisplayNameForFolder(PWCHAR szFolderPath,PWCHAR szDisplayName)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	tmpFolderItem  = PfpGetFolderItem(szFolderPath,wcslen(szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;
	}
	memcpy(tmpFolderItem->szDisplayName,szDisplayName,50*sizeof(WCHAR));
	return 0;
}


NTSTATUS
PfpGetDisplayNameForFolder(PWCHAR szFolderPath,PWCHAR szDisplayName,ULONG nLen)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	
	if(nLen<sizeof(WCHAR)*50) return STATUS_INVALID_PARAMETER;

	tmpFolderItem  = PfpGetFolderItem(szFolderPath,wcslen(szFolderPath));
	if(tmpFolderItem == NULL)
	{
		return -2;//次项目不存在
	}
	memcpy(szDisplayName,tmpFolderItem->szDisplayName,sizeof(WCHAR)*50);
	
	return 0;
}


NTSTATUS 
PfpAddProtectedFolder(PWCHAR szFolderPath,PFODLERPROTECTORINFO pProtectioInfo)
{
	PFOLDERPROTECTITEM	tmpFolderItem = NULL;
	 
	ULONG nFolderPathLenOfChar = 0;
	if(szFolderPath== NULL||pProtectioInfo== NULL)
		return STATUS_INVALID_PARAMETER;

	if((nFolderPathLenOfChar =wcslen(szFolderPath))>1023)
		return STATUS_INVALID_PARAMETER;

	
	 
	tmpFolderItem  = PfpGetFolderItem(szFolderPath,nFolderPathLenOfChar);
	if(tmpFolderItem != NULL)
	{
		 
		return -3;//次项目已经存在
	}
	 
 
	tmpFolderItem = ExAllocatePool_A(PagedPool,sizeof(FOLDERPROTECTITEM)+(1+nFolderPathLenOfChar)*sizeof(WCHAR));
	if(tmpFolderItem  == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	wcscpy(tmpFolderItem->szFullPath,szFolderPath);
	tmpFolderItem->szFullPathSize = nFolderPathLenOfChar;
	 
	tmpFolderItem->bEncryptRealTime = (pProtectioInfo->bEncryptRealTime!=0);
	tmpFolderItem->bBackup			= (pProtectioInfo->bBackup!=0);
	tmpFolderItem->bEncryptForFileType =  pProtectioInfo->EncryptForFileTypes;
	tmpFolderItem->State			= (ULONG)pProtectioInfo->State;
	tmpFolderItem->Type				= pProtectioInfo->Type;
	wcscpy(tmpFolderItem->szDisplayName,pProtectioInfo->szDisplayName);
	tmpFolderItem->pFileTypesForEncryption = NULL;
	InitializeListHead(&tmpFolderItem->pListHeadOfFileTypes);

	 
	InsertTailList(&g_FolderProtectList,&tmpFolderItem->list);
	 
	return 0;
}

NTSTATUS 
PfpGetProtectedFolderNum(ULONG *pNum)
{
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	
	*pNum = 0;
	
	if (IsListEmpty(&g_FolderProtectList))
	{
	 
		return STATUS_SUCCESS;
	}

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		(*pNum) ++;
	};

	return STATUS_SUCCESS;
}
NTSTATUS 
PfpGetFolderPathIntoArray(PFOLDERPATH pFolderPathArray,ULONG* pnNum)
{
	
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY		tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM	tmpHideFile		= NULL;
	LONG			HideObjectLength = 0;
	ULONG			nIndex = 0;
	if(pFolderPathArray== NULL||*pnNum == 0)
		return STATUS_INVALID_PARAMETER;
	
	
	 
	if (IsListEmpty(&g_FolderProtectList))
	{
		*pnNum= 0;
		 
		return STATUS_SUCCESS;
	}

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile  = (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);

		if(tmpHideFile->szFullPathSize>1023)
		{
			wcsncpy(pFolderPathArray[nIndex ].szFolderPath,tmpHideFile->szFullPath,1023);
			pFolderPathArray[nIndex ].szFolderPath[1023] =0;
		}else
		{
			wcscpy(pFolderPathArray[nIndex ].szFolderPath,tmpHideFile->szFullPath );
		}	
		nIndex++;
		if(nIndex == *pnNum)break;
	};
	*pnNum = nIndex ;
	 
	return STATUS_SUCCESS;
}


NTSTATUS
PfpGetNumofFiletypsForProtectedFolder(PWCHAR lpszFolderPath,ULONG* pnNum)
{	
	PFOLDERPROTECTITEM	tmpFolderItem		= NULL;
	*pnNum = 0;
	if(lpszFolderPath== NULL ||pnNum== NULL)
		return STATUS_INVALID_PARAMETER;
	
	
	 
	tmpFolderItem  = PfpGetFolderItem(lpszFolderPath,wcslen(lpszFolderPath));
	if(tmpFolderItem == NULL)
	{
		 
		return -2;//次项目已经存在
	}

	*pnNum =PfpGetNumofFileTypes(tmpFolderItem);
	 
	return STATUS_SUCCESS;
}

ULONG
PfpGetNumofFileTypes(PFOLDERPROTECTITEM pFolderItem)
{
	ULONG nNum = 0;
	PLIST_ENTRY		headListEntry	= &pFolderItem->pListHeadOfFileTypes;
	PLIST_ENTRY		tmpListEntry	= headListEntry;

	if(pFolderItem== NULL)
		return 0;
	if(IsListEmpty(&pFolderItem->pListHeadOfFileTypes))
		return 0;
	

	while (tmpListEntry->Flink != headListEntry)
	{
		nNum ++;
		tmpListEntry = tmpListEntry->Flink;
	};
	return nNum;
}

NTSTATUS
PfpGetFileTypesForProtectedFolder(IN PWCHAR pszFolderPath,
								  IN PFOLDERFILETYPE pFiletypesArray,
								  IN OUT ULONG* pnLen)
{
	ULONG nLen								= 0;
	PFOLDERPROTECTITEM	tmpFolderItem		= NULL;
	PLIST_ENTRY		headListEntry			= NULL;
	PLIST_ENTRY		tmpListEntry			= NULL;
	PFILETYPEOFFOLDERITEM  pFileTypeItem			= NULL;
	ULONG			nIndex					= 0;

	if(pszFolderPath== NULL||pFiletypesArray== NULL||pnLen== NULL||*pnLen==0)
		return STATUS_INVALID_PARAMETER;

	if((nLen = wcslen(pszFolderPath))>1023)
	{
		return STATUS_INVALID_PARAMETER;
	}
	
	 
	tmpFolderItem  = PfpGetFolderItem(pszFolderPath,nLen);
	
	if(tmpFolderItem == NULL)
	{
		 
		return -3;//次项目已经存在
	}
	
	headListEntry	 = &tmpFolderItem->pListHeadOfFileTypes;
	tmpListEntry	 = headListEntry->Flink	 ;
	if(IsListEmpty(&tmpFolderItem->pListHeadOfFileTypes))
	{
		 
		*pnLen  = 0;
		return 0;
	}

	while (tmpListEntry!= headListEntry)
	{
		
		pFileTypeItem  = (PFILETYPEOFFOLDERITEM)CONTAINING_RECORD(tmpListEntry, FILETYPEOFFOLDERITEM, list);
		tmpListEntry = tmpListEntry->Flink;

		memcpy(pFiletypesArray[nIndex].szFileType,pFileTypeItem->szFileType,50*sizeof(WCHAR));
		pFiletypesArray[nIndex].bBackup = pFileTypeItem->bBackup;
		nIndex++;
		
		if(nIndex==*pnLen)
			break;

	};
	*pnLen=nIndex;
	 
	return 0;

}

NTSTATUS
PfpGetFolderProtectInfo(IN PWCHAR lpszFolderPath,
						IN PFODLERPROTECTORINFO pFolderProtectorInfo)
{
	PFOLDERPROTECTITEM	tmpFolderItem		= NULL;
	ULONG nPathSize = 0;
	if(lpszFolderPath== NULL ||pFolderProtectorInfo== NULL)
		return STATUS_INVALID_PARAMETER;
	if((nPathSize =wcslen(lpszFolderPath))>1023) return STATUS_INVALID_PARAMETER;

 
	tmpFolderItem  = PfpGetFolderItem(lpszFolderPath,nPathSize);

	if(tmpFolderItem == NULL)
	{
	 
		return -2;//次项目已经存在
	}
	pFolderProtectorInfo->bBackup				= (tmpFolderItem->bBackup?1:0);
	pFolderProtectorInfo->bEncryptRealTime		=  (tmpFolderItem->bEncryptRealTime?1:0);
	pFolderProtectorInfo->EncryptForFileTypes	= tmpFolderItem->bEncryptForFileType;
	pFolderProtectorInfo->State					= (tmpFolderItem->State);
	memcpy(pFolderProtectorInfo->szDisplayName,tmpFolderItem->szDisplayName,50*sizeof(WCHAR));
	pFolderProtectorInfo->Type					= tmpFolderItem->Type;
	 
	return STATUS_SUCCESS;
}

NTSTATUS 
PfpSetFileTypesForFolder(PSETFILETYPESFORFOLDER  pFiletypesForFolder)

{
	PFOLDERPROTECTITEM	tmpFolderItem		= NULL;
	ULONG				nIndex				= 0;
	FILETYPEOFFOLDERITEM* pFileTypeItem		= NULL;

	if(pFiletypesForFolder== NULL) return STATUS_INVALID_PARAMETER;
	

	 
	tmpFolderItem  = PfpGetFolderItem(pFiletypesForFolder->folderPath.szFolderPath,wcslen(pFiletypesForFolder->folderPath.szFolderPath));

	if(tmpFolderItem == NULL)
	{
		 
		return -2;//次项目已经存在
	}
	PfpDeleteAllFileTypesOfFolder(tmpFolderItem);
	
	for(nIndex = 0;nIndex<pFiletypesForFolder->nNumofFileTypes;++nIndex)
	{
		pFileTypeItem= ExAllocatePool_A(PagedPool,sizeof(FILETYPEOFFOLDERITEM));
		if(pFileTypeItem)
		{
			pFileTypeItem->bBackup = pFiletypesForFolder->FileTyps[nIndex].bBackup;
			memcpy(pFileTypeItem->szFileType,pFiletypesForFolder->FileTyps[nIndex].szFileType,50*sizeof(WCHAR));
			InsertTailList(&tmpFolderItem->pListHeadOfFileTypes,&pFileTypeItem->list);
		}
	}
	 
	return STATUS_SUCCESS;
}


NTSTATUS 
PfpDelProtectedFolder(PWCHAR szFolderPath)
{
	PFOLDERPROTECTITEM	tmpFolderItem	= NULL;

	if(szFolderPath== NULL)return STATUS_INVALID_PARAMETER;
	 
	tmpFolderItem  = PfpGetFolderItem(szFolderPath,wcslen(szFolderPath));

	if(tmpFolderItem == NULL)
	{
		 
		return -3;//此项目不存在
	}

	PfpDeleteAllFileTypesOfFolder(tmpFolderItem);
	RemoveEntryList(&tmpFolderItem->list);
	 
	return STATUS_SUCCESS;
	
}
VOID
PfpDeleteAllFileTypesOfFolder(PFOLDERPROTECTITEM FolderItem)
{
	LIST_ENTRY* tmpListEntry = NULL;
	LIST_ENTRY* headListEntry = NULL;
	PFILETYPEOFFOLDERITEM pFileTypeItem = NULL;
	
	if(FolderItem == NULL) return ;
	
	if(IsListEmpty(&FolderItem->pListHeadOfFileTypes)) return ;

	headListEntry  = &FolderItem->pListHeadOfFileTypes;
	tmpListEntry = headListEntry  ->Flink;
	while (tmpListEntry!= headListEntry)
	{
		
		pFileTypeItem  = CONTAINING_RECORD(tmpListEntry,FILETYPEOFFOLDERITEM,list);
		tmpListEntry	= tmpListEntry->Flink;
				
		RemoveEntryList(&pFileTypeItem->list);
		ExFreePool_A(pFileTypeItem);
	};
}

NTSTATUS 
PfpSetProtectedFolder(PWCHAR szFolderPath,PFODLERPROTECTORINFO pProtectioInfo)
{
	PFOLDERPROTECTITEM	tmpFolderItem		= NULL;
	LONG				nIndex				= 0;
	FILETYPEOFFOLDERITEM* pFileTypeItem		= NULL;

	if(szFolderPath== NULL ||pProtectioInfo== NULL) return STATUS_INVALID_PARAMETER;
	
	 
	tmpFolderItem  = PfpGetFolderItem(szFolderPath,wcslen(szFolderPath));

	if(tmpFolderItem == NULL)
	{
		 
		return -3;//次项目does not exist;
	}
	
	tmpFolderItem->bBackup = (pProtectioInfo->bBackup!=0?1:0);
	tmpFolderItem->bEncryptForFileType = pProtectioInfo->EncryptForFileTypes;
	tmpFolderItem->bEncryptRealTime = (pProtectioInfo->bEncryptRealTime!=0?1:0);
	tmpFolderItem->State   = pProtectioInfo->State;
	memcpy(tmpFolderItem->szDisplayName,pProtectioInfo->szDisplayName,50*sizeof(WCHAR));
	tmpFolderItem->Type = pProtectioInfo->Type;

	 
	return STATUS_SUCCESS;

}