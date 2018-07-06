
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
  

NTSTATUS
PfpCopyOneDataIntoUserBuffer(IN OUT PVOID		pUserBuffer,
							 IN OUT ULONG *		Len,
							 IN PPROCESSINFO	pProcInfo)
{
	ULONG		nOneDataLen = 0;
	PConfigData pData		= NULL;
	BOOLEAN		bHasFileTypes = FALSE;
	ASSERT(pProcInfo && Len);

	if(!pProcInfo->bBowser)
	{
		bHasFileTypes  = !IsListEmpty(&pProcInfo->FileTypes);
	}else
	{
		bHasFileTypes  = (pProcInfo->nEncryptTypes!=0);
	}
	
	if(bHasFileTypes  )
	{
		nOneDataLen  = (PfpCalcFileTypesLen(pProcInfo)+sizeof(ConfigData)+7)&~7;
	}else
	{	
		nOneDataLen  = (sizeof(ConfigData)+7)&~7;
	}

	if(*Len<nOneDataLen )
		return STATUS_BUFFER_OVERFLOW;

	pData = (PConfigData)pUserBuffer;
	pData ->bAllowInherent = pProcInfo->bAllowInherent;
	pData ->bBackup        = pProcInfo->bNeedBackUp;
	pData ->bEnableEncrypt = pProcInfo->bEnableEncrypt;
	pData ->bForceEncryption= pProcInfo->bForceEncryption;
	pData ->bAbone			= pProcInfo->bAlone;
	pData->bCreateExeFile	= pProcInfo->bAllCreateExeFile;
	pData->bBrowser			= pProcInfo->bBowser;
	pData->BrowserEncryptTypeValue = pProcInfo->nEncryptTypes;

	memcpy(pData->EXEHashValue,pProcInfo->ProcessHashValue,PROCESSHASHVALULENGTH);

	
	memcpy(pData->szEXEPath,pProcInfo->ProcessName.Buffer,min(sizeof(WCHAR)*(MAX_PATH-1),pProcInfo->ProcessName.Length));

	pData->szEXEPath[min((MAX_PATH-1),pProcInfo->ProcessName.Length/sizeof(WCHAR))]=0;

	if(bHasFileTypes)
	{
		PfpCopyFileTypesIntoBuffer(pData->szFileTypes,pProcInfo);
	}else
	{
		pData->szFileTypes[0]=0;
	}

	*Len-=nOneDataLen;

	return STATUS_SUCCESS;
}

VOID 
PfpCopyFileTypesIntoBuffer(
						   IN PVOID pBuffer,
						   IN PPROCESSINFO pProcInfo)
{

	PLIST_ENTRY pList		;
	PFILETYPE	pFileType	;
	ULONG		FileTypesLen;
	ULONG		nszLen		;
	PUCHAR		pTemp		= (PUCHAR) pBuffer;
	ASSERT(pProcInfo && pBuffer);

	nszLen = 0;
	FileTypesLen = 0;
	pFileType	 = NULL;
	pList	 = NULL;
	if(pProcInfo == NULL)
		return  ;

	if(!pProcInfo ->bBowser)
	{
		for(pList = pProcInfo->FileTypes.Blink; pList!= &pProcInfo->FileTypes; pList = pList->Blink )
		{
			pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
			if(pFileType && pFileType ->bSelected )
			{ 
				nszLen	= wcslen(pFileType->FileExt);
				memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
				((PWCHAR)pTemp) [nszLen] =L'|';
				pTemp += (nszLen+1)*sizeof(WCHAR);
			}
		}
		*((PWCHAR)pTemp) =L';';
		pTemp+=2;

		for(pList = pProcInfo->FileTypes.Blink; pList!= &pProcInfo->FileTypes; pList = pList->Blink )
		{
			pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
			if(pFileType && !pFileType ->bSelected  )
			{
				nszLen	= wcslen(pFileType->FileExt);
				memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
				((PWCHAR)pTemp) [nszLen] =L'|';
				pTemp += (nszLen+1)*sizeof(WCHAR);
			}
		}
	}else
	{
		if(pProcInfo->nEncryptTypes &PIC_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(PIC_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType)
					{ 
						nszLen	= wcslen(pFileType->FileExt);
						memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
						((PWCHAR)pTemp) [nszLen] =L'|';
						pTemp += (nszLen+1)*sizeof(WCHAR);
					}
				}
			}
			*((PWCHAR)pTemp) =L';';
			pTemp+=2;

		}
		if(pProcInfo->nEncryptTypes &COOKIE_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(COOKIE_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType)
					{ 
						nszLen	= wcslen(pFileType->FileExt);
						memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
						((PWCHAR)pTemp) [nszLen] =L'|';
						pTemp += (nszLen+1)*sizeof(WCHAR);
					}
				}
			}
			*((PWCHAR)pTemp) =L';';
			pTemp+=2;

		}

		if(pProcInfo->nEncryptTypes &VEDIO_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(VEDIO_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType)
					{ 
						nszLen	= wcslen(pFileType->FileExt);
						memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
						((PWCHAR)pTemp) [nszLen] =L'|';
						pTemp += (nszLen+1)*sizeof(WCHAR);
					}
				}
			}
			*((PWCHAR)pTemp) =L';';
			pTemp+=2;

		}

		if(pProcInfo->nEncryptTypes &TEXT_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(TEXT_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType )
					{ 
						nszLen	= wcslen(pFileType->FileExt);
						memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
						((PWCHAR)pTemp) [nszLen] =L'|';
						pTemp += (nszLen+1)*sizeof(WCHAR);
					}
				}
			}
			*((PWCHAR)pTemp) =L';';
			pTemp+=2;

		}

		if(pProcInfo->nEncryptTypes &SCRIPT_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(SCRIPT_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{	
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType )
					{ 
						nszLen	= wcslen(pFileType->FileExt);
						memcpy(pTemp,pFileType->FileExt,nszLen*sizeof(WCHAR));
						((PWCHAR)pTemp) [nszLen] =L'|';
						pTemp += (nszLen+1)*sizeof(WCHAR);
					}
				}
			}
			*((PWCHAR)pTemp) =L';';
			pTemp+=2;

		}
	}
	*((PWCHAR)pTemp) =0;
}

ULONG 
PfpCalcProgramLen()
{
	PLIST_ENTRY  pList			 = NULL;
	PPROCESSINFO pProcInfo		 =  NULL;
	ULONG		 AllPramDataSize = 0;

	for(pList = g_ProcessInofs.Blink; pList !=&g_ProcessInofs;pList= pList->Blink)
	{
		pProcInfo  = CONTAINING_RECORD(pList,PROCESSINFO,list);

		if(pProcInfo  )
		{				
			AllPramDataSize += ((PfpCalcFileTypesLen(pProcInfo)+sizeof(ConfigData))+7)&~7;
		}
	}
	return AllPramDataSize;
}

ULONG 
PfpCalcFileTypesLen(IN PPROCESSINFO pProcInfo)
{
	PLIST_ENTRY pList = NULL;
	PFILETYPE	pFileType = NULL;
	ULONG		FileTypesLen = 0;
	if(pProcInfo == NULL )
		return  0;
	
	if(pProcInfo->bBowser)
	{
		if(pProcInfo->nEncryptTypes ==0) return 0;
		
		if(pProcInfo->nEncryptTypes &PIC_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(PIC_TYPE)];
			
			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType  )
					{
						FileTypesLen +=sizeof(WCHAR)*(1+wcslen(pFileType->FileExt));			
					}
				}
				FileTypesLen+=sizeof(WCHAR);
			}
		}

		if(pProcInfo->nEncryptTypes &COOKIE_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(COOKIE_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType  )
					{
						FileTypesLen +=sizeof(WCHAR)*(1+wcslen(pFileType->FileExt));			
					}
				}
				FileTypesLen+=sizeof(WCHAR);
			}
		}
		if(pProcInfo->nEncryptTypes &VEDIO_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(VEDIO_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType  )
					{
						FileTypesLen +=sizeof(WCHAR)*(1+wcslen(pFileType->FileExt));			
					}
				}
				FileTypesLen+=sizeof(WCHAR);
			}
		}
		if(pProcInfo->nEncryptTypes &TEXT_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(TEXT_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType  )
					{
						FileTypesLen +=sizeof(WCHAR)*(1+wcslen(pFileType->FileExt));			
					}
				}
				FileTypesLen+=sizeof(WCHAR);
			}
		}
		if(pProcInfo->nEncryptTypes &SCRIPT_TYPE)
		{
			PLIST_ENTRY pListHead = &pProcInfo->FileTypesForBrowser[Type2ArrayIndex(SCRIPT_TYPE)];

			if(!IsListEmpty(pListHead))
			{
				for(pList = pListHead->Blink; pList!= pListHead; pList = pList->Blink )
				{
					pFileType  = CONTAINING_RECORD(pList,FILETYPE,list);
					if(pFileType  )
					{
						FileTypesLen +=sizeof(WCHAR)*(1+wcslen(pFileType->FileExt));			
					}
				}
				FileTypesLen+=sizeof(WCHAR);
			}
		}

	}else
	{
		if(IsListEmpty(&pProcInfo->FileTypes))
			return 0;
		for(pList = pProcInfo->FileTypes.Blink; pList!= &pProcInfo->FileTypes; pList = pList->Blink )
		{
			pFileType = CONTAINING_RECORD(pList,FILETYPE,list);
			if(pFileType)
			{
				FileTypesLen +=sizeof(WCHAR)*(1+wcslen(pFileType->FileExt));			
			}
		}
	}
	


	FileTypesLen+=2*sizeof(WCHAR);
	return FileTypesLen;
}


PVOID 
PfpGetAllPrograms(ULONG* szLen )
{
	PVOID pBuffer = NULL;
	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
	*szLen  = PfpCalcProgramLen();
	if(*szLen== 0)
	{
		goto EXITGO;
	}
	pBuffer = ExAllocatePool_A(PagedPool,*szLen);

	if(pBuffer  == NULL)
	{
		goto EXITGO;
	}

	PfpCopyAllProgramsIntoBuffer(pBuffer,szLen);
EXITGO:	
	ExReleaseResourceLite(&g_ProcessInfoResource);
	FsRtlExitFileSystem();
	return pBuffer;
}


BOOLEAN 
PfpCopyAllProgramsIntoBuffer(IN PVOID pBuffer,
							 IN ULONG* Len)
{
	PLIST_ENTRY		pList		 = NULL;
	PPROCESSINFO	pTempPro	 = NULL;
	PVOID			pTempRecord  = pBuffer;
	PVOID			pPreRecord	 = pBuffer;
	ULONG			nOutPutLen	 = *Len;
	ULONG			nLastCount	 = *Len;
	__try
	{
		for(pList  = g_ProcessInofs.Blink; pList!= &g_ProcessInofs ;pList= pList->Blink)
		{
			pTempPro = CONTAINING_RECORD(pList,PROCESSINFO,list);
			if(pTempPro )
			{
				if( STATUS_BUFFER_OVERFLOW == PfpCopyOneDataIntoUserBuffer(pTempRecord,&nOutPutLen,pTempPro)|| nOutPutLen==0)
				{
					if(nOutPutLen==0)
					{
						if(pPreRecord != pTempRecord)
						{
							((PConfigData)pPreRecord)->nNextOffset = (ULONG)((ULONG64)(PUCHAR)pTempRecord-(ULONG64)(PUCHAR)pPreRecord);
						}
						((PConfigData)pTempRecord)->nNextOffset = 0;
					}else if( pPreRecord != pTempRecord )
					{
						((PConfigData)pPreRecord)->nNextOffset = 0;
					}
					
					break;
				}

				if(pPreRecord != pTempRecord)
				{
					((PConfigData)pPreRecord)->nNextOffset =(ULONG)((ULONG64)(PUCHAR)pTempRecord-(ULONG64)(PUCHAR)pPreRecord);
					pPreRecord	= pTempRecord;
					(PUCHAR)pTempRecord += nLastCount-nOutPutLen;
				}else
				{
					((PConfigData)pTempRecord)->nNextOffset = nLastCount-nOutPutLen;
					(PUCHAR)pTempRecord += nLastCount-nOutPutLen;
				}
				//移动数据的指针，

				nLastCount = nOutPutLen;
			}
		}
		*Len -= nOutPutLen;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		
	}
	return TRUE;
}


VOID AddProcessInfoIntoGlobal(PConfigData		pData)
{
	__try
	{		
		PPROCESSINFO	pProcInfo	= NULL;
		
		UNICODE_STRING  szEXEPath;
		do 
		{		
			RtlInitUnicodeString(&szEXEPath,pData->szEXEPath);		

			pProcInfo = PfpCreateAndInitProcessInfo(szEXEPath,
													pData->EXEHashValue,
													PROCESSHASHVALULENGTH,
													INVALID_HANDLE_VALUE,
													(pData->bAllowInherent>0?TRUE:FALSE),
													pData->szFileTypes,
													(BOOLEAN)pData->bBackup,
													(BOOLEAN)pData->bEnableEncrypt,
													(BOOLEAN)pData->bForceEncryption,
													(BOOLEAN)pData->bAbone,
													(BOOLEAN)pData->bBrowser,
													(BOOLEAN)pData->bCreateExeFile,
													pData->BrowserEncryptTypeValue);

			if(pProcInfo == NULL)
			{
				break;
			}

			if(pProcInfo)
			{
				PfpAddProcessIntoGlobal(pProcInfo);
			}		

		} while(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{	
	}
}

VOID 
PfpInitProcessInfosFromBuffer(PUCHAR pBuffer,ULONG nLen ,IO_STATUS_BLOCK *IoStatus)
{
	__try
	{
		PConfigData		pData		= NULL;
		ULONG			Offset		= 0;		
		pData  = (PConfigData)pBuffer;

		do 
		{
			pData =(PConfigData) ((PUCHAR)pData +Offset);
			if( (PUCHAR)pData > (PUCHAR)pBuffer+nLen)
				break;

			AddProcessInfoIntoGlobal(pData);

			Offset = pData->nNextOffset;

		} while(Offset!=0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoStatus->Status = GetExceptionCode();
		IoStatus->Information = 0;
	}
}


//////////////////////////////////////////////////////////////////////////



ULONG PfpGetProgNum()
{
	PLIST_ENTRY  pList = NULL;
	ULONG		nNum = 0;
	PPROCESSINFO pTempProc	=  NULL;
	if( IsListEmpty(&g_ProcessInofs)) return 0;
	
	 ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
	
	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc && !pTempProc->bBowser)
		{
			nNum++;	
		}
		
	}
	ExReleaseResourceLite(&g_ProcessInfoResource);

	return nNum;
}
ULONG PfpGetBrowserCount()
{
	PLIST_ENTRY  pList = NULL;
	ULONG		nNum = 0;
	PPROCESSINFO pTempProc	=  NULL;
	if( IsListEmpty(&g_ProcessInofs)) return 0;

	ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc && pTempProc->bBowser)
		{
			nNum++;	
		}

	}
	ExReleaseResourceLite(&g_ProcessInfoResource);

	return nNum;
}

NTSTATUS 
PfpGetHashValueIntoArray(PPROGHASHVALUEITEM pHashValueArray,ULONG nSize)
{
	PPROCESSINFO pTempProc	=  NULL;
	PLIST_ENTRY  pList		= NULL;
	ULONG		 nIndex = 0;
	if(pHashValueArray== NULL || nSize==0)
		return STATUS_INVALID_PARAMETER;
	
	

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc &&  !pTempProc ->bBowser)
		{
			memcpy(pHashValueArray[nIndex].HashValue,pTempProc->ProcessHashValue,PROCESSHASHVALULENGTH);
			nIndex++;
		}
		
		if(nIndex==nSize)
			break;
	}
	

	return STATUS_SUCCESS;
	
}
NTSTATUS 
PfpGetBrowserHashValueIntoArray(PPROGHASHVALUEITEM pHashValueArray,ULONG nSize)
{
	PPROCESSINFO pTempProc	=  NULL;
	PLIST_ENTRY  pList		= NULL;
	ULONG		 nIndex = 0;
	if(pHashValueArray== NULL || nSize==0)
		return STATUS_INVALID_PARAMETER;
 

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc &&  pTempProc ->bBowser)
		{
			memcpy(pHashValueArray[nIndex].HashValue,pTempProc->ProcessHashValue,PROCESSHASHVALULENGTH);
			nIndex++;
		}

		if(nIndex==nSize)
			break;
	}
	return STATUS_SUCCESS;
}

NTSTATUS 
PfpGetBrowserEncryptFileTypes(UCHAR* pHashValue,
							  ULONG  nEncrytType,
							  IN OUT PFILETYPE_INFO pFileTypeArray,
							  IN ULONG nSizeType)
{
	PPROCESSINFO pTempProc	=  NULL;
	PLIST_ENTRY  pList		= NULL;
	ULONG		 nIndex = 0;
	

	if(pHashValue == NULL ||pFileTypeArray== NULL||nSizeType==0)
		return STATUS_INVALID_PARAMETER;

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc && memcmp(pHashValue,pTempProc->ProcessHashValue,PROCESSHASHVALULENGTH)==0 )
		{
			PLIST_ENTRY  pListFileType		= NULL;
			PLIST_ENTRY	 pFileTypeHead		= NULL;
			PFILETYPE    pFileType			= NULL;
			LONG		 nIndexofArray      = -1;
			if((nIndexofArray = Type2ArrayIndex(nEncrytType))==-1)
			{
				return STATUS_INVALID_PARAMETER;
			}

			pFileTypeHead = &pTempProc->FileTypesForBrowser[nIndexofArray];

			if(!IsListEmpty(pFileTypeHead))
			{

				for(pListFileType =pFileTypeHead->Blink; pListFileType != pFileTypeHead ; pListFileType=pListFileType->Blink)
				{
					pFileType = CONTAINING_RECORD(pListFileType,FILETYPE,list);
					if(pFileType)
					{
						
						memcpy(pFileTypeArray[nIndex].psztype,pFileType->FileExt,50*sizeof(WCHAR));
						nIndex++;
						if(nIndex==nSizeType)
							break;
					}

				}
			}
			break;
		}
	}
	return STATUS_SUCCESS;
}
NTSTATUS 
PfpGetFileTypesForProg(IN PUCHAR pHashValue,
					   IN ULONG nSize,
					   IN OUT PFILETYPE_INFO pFileTypeArray,
					   IN ULONG nSizeType)
{
	PPROCESSINFO pTempProc	=  NULL;
	PLIST_ENTRY  pList		= NULL;
	ULONG		 nIndex = 0;
	if(pHashValue == NULL || nSize!=PROCESSHASHVALULENGTH ||pFileTypeArray== NULL||nSize==0)
		return STATUS_INVALID_PARAMETER;

	  

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc && memcmp(pHashValue,pTempProc->ProcessHashValue,PROCESSHASHVALULENGTH)==0 )
		{
			PLIST_ENTRY  pListFileType		= NULL;
			PFILETYPE    pFileType			= NULL;
			if(!IsListEmpty(&pTempProc->FileTypes))
			{
				for(pListFileType = pTempProc->FileTypes.Blink; pListFileType != &pTempProc->FileTypes ; pListFileType=pListFileType->Blink)
				{
					pFileType = CONTAINING_RECORD(pListFileType,FILETYPE,list);
					if(pFileType)
					{
						pFileTypeArray[nIndex].bBackUp = pFileType->bBackUp;
						pFileTypeArray[nIndex].bEncrypt= pFileType->bSelected;
						memcpy(pFileTypeArray[nIndex].psztype,pFileType->FileExt,50*sizeof(WCHAR));
						nIndex++;
						if(nIndex==nSizeType)
							break;
					}
					
				}
			}
			break;
		}
	}
 

	return STATUS_SUCCESS;

}

NTSTATUS
PfpGetFileFileTypeNumForProg(IN PUCHAR pHashValue,
							 IN ULONG nSize,
							 IN OUT ULONG *nNUM)

{
	

	PPROCESSINFO pTempProc	=  NULL;
	PLIST_ENTRY  pList		= NULL;
	*nNUM = 0;
	
	if(pHashValue== NULL ||nSize != PROCESSHASHVALULENGTH||nNUM== NULL)
		return STATUS_INVALID_PARAMETER;

	 

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc && memcmp(pHashValue,pTempProc->ProcessHashValue,PROCESSHASHVALULENGTH)==0 )
		{
			PLIST_ENTRY  pListFileType		= NULL;
			PFILETYPE    pFileType			= NULL;
			if(!IsListEmpty(&pTempProc->FileTypes))
			{
				for(pListFileType = pTempProc->FileTypes.Blink; pListFileType != &pTempProc->FileTypes ; pListFileType=pListFileType->Blink)
				{
					pFileType = CONTAINING_RECORD(pListFileType,FILETYPE,list);
					if(pFileType)
					{
						(*nNUM)++;
					}

				}
			}
			break;
		}
	}
	 
	return STATUS_SUCCESS;
}


NTSTATUS
PfpGetProtectionInfoForProg(IN PUCHAR pHashValue,
							IN ULONG nSize,
							IN OUT PPROGPROTECTION pProtection)
{
	
	PPROCESSINFO pTempProc	=  NULL;
	PLIST_ENTRY  pList		= NULL;
	BOOLEAN		 bFound		= FALSE;
	if(pHashValue== NULL||nSize != PROCESSHASHVALULENGTH||pProtection== NULL)
		return STATUS_INVALID_PARAMETER;

	for(pList = g_ProcessInofs.Blink; pList != &g_ProcessInofs ; pList=pList->Blink)
	{
		pTempProc = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(pTempProc && memcmp(pHashValue,pTempProc->ProcessHashValue,PROCESSHASHVALULENGTH)==0 )
		{
			pProtection->bEncrypt		=(ULONG)pTempProc->bEnableEncrypt ; 
			pProtection->bForceEncrypt	= (ULONG)pTempProc->bForceEncryption; 
			pProtection->bEnableBackupForProg =(ULONG)pTempProc->bNeedBackUp; 
			pProtection->bAllowInherent = (ULONG)pTempProc->bAllowInherent; 
			pProtection->bAlone			= (ULONG)pTempProc->bAlone;
			bFound		 = TRUE;
			break;
		}
	}
	return bFound?STATUS_SUCCESS:STATUS_INVALID_PARAMETER;	 
}

NTSTATUS
PfpAddProtectionFroProg(IN PADDPROTECTIONFORPROG pProtecForAdding)
{
	PPROCESSINFO	pProcessInfo  = NULL;
	UNICODE_STRING  szEXEPath;
	if(pProtecForAdding == NULL) return STATUS_INVALID_PARAMETER;

	 

	if(NULL!=(pProcessInfo  =PfpGetProcessInfoUsingHashValue(pProtecForAdding->hashValue.HashValue,PROCESSHASHVALULENGTH,NULL)))
	{
		InterlockedDecrement(&pProcessInfo->nRef);
		 
		return STATUS_OBJECT_NAME_EXISTS;
	}
	 

	
	
	
	do 
	{		
		RtlInitUnicodeString(&szEXEPath,pProtecForAdding->szExeFullPath);		

		pProcessInfo = PfpCreateAndInitProcessInfo(szEXEPath,
												pProtecForAdding->hashValue.HashValue,
												PROCESSHASHVALULENGTH,
												INVALID_HANDLE_VALUE,
												(pProtecForAdding->protectInfo.bAllowInherent>0?TRUE:FALSE),
												NULL,
												(BOOLEAN)pProtecForAdding->protectInfo.bEnableBackupForProg,
												(BOOLEAN)pProtecForAdding->protectInfo.bEncrypt,
												(BOOLEAN)pProtecForAdding->protectInfo.bForceEncrypt,
												(BOOLEAN)pProtecForAdding->protectInfo.bAlone,
												FALSE,FALSE,0);

		if(pProcessInfo == NULL)
		{
			break;
		}
	 
		if(pProcessInfo)
		{
			PfpAddFileTypesToProcessInfoByFileTypeArray(pProcessInfo,pProtecForAdding->FileTypes,pProtecForAdding->nNumFileTypes);
			
			 
			PfpAddProcessIntoGlobal(pProcessInfo);
		 
		}		
		
	} while(0);
	 
	return STATUS_SUCCESS;
}


NTSTATUS
PfpAddBrowserProtection(PBROWSERPROTECTION pBrowser)
{
	PPROCESSINFO	pProcessInfo  = NULL;
	UNICODE_STRING  szEXEPath;
	if(pBrowser == NULL) return STATUS_INVALID_PARAMETER;

	 

	if(NULL!=(pProcessInfo  =PfpGetProcessInfoUsingHashValue(pBrowser->hashValue.HashValue,PROCESSHASHVALULENGTH,NULL)))
	{
		InterlockedDecrement(&pProcessInfo->nRef);
		 
		return STATUS_INVALID_PARAMETER;
	}
	 




	do 
	{		
		RtlInitUnicodeString(&szEXEPath,pBrowser->szExeFullPath);		

		pProcessInfo = PfpCreateAndInitProcessInfo(szEXEPath,
			pBrowser->hashValue.HashValue,
			PROCESSHASHVALULENGTH,
			INVALID_HANDLE_VALUE,
			FALSE,
			NULL,
			FALSE,
			(BOOLEAN)pBrowser->ProgProtection.bEncrypt,
			(BOOLEAN)pBrowser->ProgProtection.bForceEncrypt,
			FALSE,
			TRUE,
			(pBrowser->bAllowCreateExeFile!=0),
			0);
			

		if(pProcessInfo == NULL)
		{
			break;
		}
	
		if(pProcessInfo)
		{
			//PfpAddFileTypesToProcessInfoByFileTypeArray(pProcessInfo,pProtecForAdding->FileTypes,pProtecForAdding->nNumFileTypes);
			 
			PfpAddProcessIntoGlobal(pProcessInfo);
		 
		}		

	} while(0);
	 
	return STATUS_SUCCESS;
}

NTSTATUS
PfpGetBrowserProtection(PPROGHASHVALUEITEM phashValue,PBROWSERPROTECTION pBrowser)
{
	PPROCESSINFO pProcessInfo	=  NULL;
	PLIST_ENTRY  pList		= NULL;

	if(phashValue== NULL|| pBrowser== NULL)
		return STATUS_INVALID_PARAMETER;

	 

	if(NULL==(pProcessInfo  = PfpGetProcessInfoUsingHashValue(phashValue->HashValue,PROCESSHASHVALULENGTH,NULL)))
	{		 
		  
		return STATUS_OBJECT_NAME_EXISTS;
	}
	 

	pBrowser->ProgProtection.bEncrypt		=(ULONG)pProcessInfo->bEnableEncrypt ; 
	pBrowser->ProgProtection.bForceEncrypt	=(ULONG)pProcessInfo->bForceEncryption; 
	pBrowser->bAllowCreateExeFile			=(ULONG)pProcessInfo->bAllCreateExeFile;
	wcsncpy(pBrowser->szExeFullPath,pProcessInfo->ProcessName.Buffer,min(1023,pProcessInfo->ProcessName.Length/sizeof(WCHAR)));
	pBrowser->szExeFullPath[min(1023,pProcessInfo->ProcessName.Length/sizeof(WCHAR))]=0;


	InterlockedDecrement(&pProcessInfo->nRef);
	
	return STATUS_SUCCESS;
	 
}