#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "fspyKern.h"

#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif


BOOLEAN		 PfpGetHashValueForEXE(PWCHAR	szFullPath, 
								   ULONG	nFullPathSizeInBytes,
								   UCHAR*	HashValue,
									ULONG	nLegnth)
{
	WCHAR						DeviceChar[20];
	LONG						NumOfBytes =0;
	WCHAR						*szEXEOndevice = NULL;
	PDEVICE_OBJECT				pDeviceConEXE = NULL;
	UNICODE_STRING				FilePath_U ;
	PFILESPY_DEVICE_EXTENSION	pDeviceExt = NULL;
	OBJECT_ATTRIBUTES			object;
	NTSTATUS					ntstatus;
	IO_STATUS_BLOCK				iostatus;
	HANDLE						FileHandle = INVALID_HANDLE_VALUE;
	LARGE_INTEGER				Offset;
	BOOLEAN						bAttached = FALSE;
	LONG						Num	=0;
	LONG						Num1=0;
	LONG						Num2=0;
	KEVENT						event;
	PIRP						pIrp = NULL;
	PFILE_OBJECT				pExeFileObject = NULL;
	PDEVICE_OBJECT				pNextDevice;
	Offset.QuadPart  = HASHVALUEOFFSET	;

	 

	if(szFullPath == NULL)
		return FALSE;

	if(HashValue == NULL || nLegnth==0)
		return FALSE;

	//Get the device DOS letter for this Exe
	if(!PfpCopyDeviceChar(DeviceChar,szFullPath,&NumOfBytes) ||
		0 == NumOfBytes )
	{
		 
		return FALSE;
	}
	
	// Get the deviceobject on which the EXE file exists;
	pDeviceConEXE = PfpGetSpyDeviceFromName(DeviceChar);
	if(!pDeviceConEXE)
	{
		//这个地方说明 这个exe所在的磁盘分区没有 attach 我们的device ，所以我们就不管了
		bAttached  = FALSE;
	
	}else
	{
		bAttached  = TRUE;
	}
	
	// check to see if this device has extension and if this device has a SHADOW device associated
	if(bAttached)	
	{
		if(pDeviceConEXE->DeviceExtension == NULL || 
			!(pDeviceExt=((PFILESPY_DEVICE_EXTENSION)pDeviceConEXE->DeviceExtension))->pShadowDevice)
		{
			 
			return FALSE;
		}

		// if this device has a shadow device , get the shadow device's extension

		pDeviceExt = (PFILESPY_DEVICE_EXTENSION)pDeviceExt->pShadowDevice->DeviceExtension;
		
		ASSERT(pDeviceExt);

		// get the name for exe for on deviceobject with device name
		
		
		Num1	= nFullPathSizeInBytes>>1;//wcslen(szFullPath);
		Num		= wcslen(pDeviceExt->DeviceNames);
		Num2	= NumOfBytes/sizeof(WCHAR);
		szEXEOndevice = ExAllocatePoolWithTag(PagedPool,nFullPathSizeInBytes+(Num<<1)+2,'1009');
		if(szEXEOndevice == NULL)
			return FALSE;

		memcpy(szEXEOndevice,pDeviceExt->DeviceNames,(Num<<1));
		memcpy(&szEXEOndevice[Num],&szFullPath[Num2],(Num1 -Num2)<<1);
		
		szEXEOndevice[Num+Num1-Num2]=0;

	}else
	{
		szEXEOndevice = ExAllocatePoolWithTag(PagedPool,nFullPathSizeInBytes+30+2,'2009');
		if(szEXEOndevice== NULL)
			return FALSE;

		memcpy(szEXEOndevice,L"\\DosDevices\\",24);
		memcpy(&szEXEOndevice[12],szFullPath,nFullPathSizeInBytes);
		szEXEOndevice[12+(nFullPathSizeInBytes>>1)]=L'\0';
	}

	RtlInitUnicodeString(&FilePath_U,szEXEOndevice);
	
	//open the exe file

	InitializeObjectAttributes(&object,&FilePath_U,OBJ_CASE_INSENSITIVE |OBJ_KERNEL_HANDLE,NULL,NULL);

	
	NumOfBytes = 0; 
	ntstatus = ZwCreateFile(&FileHandle,
							FILE_READ_DATA|SYNCHRONIZE,
							&object,
							&iostatus,
							NULL,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
							FILE_OPEN,
							FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0);
	if(!NT_SUCCESS(ntstatus))
	{
		goto EXIT;		
	}

	//from the offset of 60 to read some data;
	ntstatus = ObReferenceObjectByHandle(FileHandle,
										0,
										*IoFileObjectType,
										KernelMode,
										&pExeFileObject ,
										NULL);
	if(!NT_SUCCESS(ntstatus))
	{
		goto EXIT;
	}

	pNextDevice = IoGetRelatedDeviceObject(pExeFileObject);
	if(pNextDevice == NULL)
	{
		ntstatus = STATUS_INVALID_PARAMETER;
		goto EXIT;
	}
	KeInitializeEvent(&event,NotificationEvent ,FALSE);

	pIrp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,pNextDevice,HashValue,nLegnth,&Offset,&event,&iostatus);

	if(pIrp== NULL)
	{
		ntstatus = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}
	IoGetNextIrpStackLocation(pIrp)->FileObject = pExeFileObject;
	ntstatus = IoCallDriver(pNextDevice,pIrp);

	if(ntstatus == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event,
								Executive,
								KernelMode,
								FALSE,
								NULL);
	}
	//IoCompleteRequest( pIrp, IO_DISK_INCREMENT );
	ntstatus = iostatus.Status;

	if(!NT_SUCCESS(ntstatus))
	{
		goto EXIT;
	}
	if(iostatus.Information!=nLegnth)
	{
		ntstatus = STATUS_UNSUCCESSFUL;
		ASSERT(0);
	}

EXIT:
	if(szEXEOndevice)
		ExFreePool(szEXEOndevice);
	if(pExeFileObject)
	{
		ObDereferenceObject(pExeFileObject);
	}
	if(FileHandle!= INVALID_HANDLE_VALUE)
		ZwClose(FileHandle);

	return NT_SUCCESS(ntstatus);
}


VOID	PfpUpperCase(WCHAR* pszBuffer)
{
	LONG nIndex= 0;

	ASSERT(pszBuffer);
	
	while(pszBuffer[nIndex] != L'\0')
	{
		if((pszBuffer[nIndex] >= L'a') &&  (pszBuffer[nIndex] <=L'z'))
		{	
			pszBuffer[nIndex] = pszBuffer[nIndex]-L'a'+L'A';
		}
		nIndex++;
	}	
}



BOOLEAN			
PfpGetFileExtFromFileName(
						  PUNICODE_STRING pFilePath,
						  WCHAR * FileExt,
						  LONG* nLength
						  )
{
	PWCHAR pFileName ;
	LONG   nIndex	 ;

	PWCHAR pTemp	= FileExt;

	pFileName = NULL;
	nIndex	  = 0;

	if(pFilePath == NULL)
		return FALSE;

	if(!pFilePath->Buffer || pFilePath->Length ==0 )
		return FALSE;

	if(pFilePath->Length == sizeof(WCHAR) && pFilePath->Buffer[0] ==L'\\')
		return FALSE;

	pFileName	= pFilePath->Buffer;
	nIndex		= pFilePath->Length/sizeof(WCHAR) -1 ;

	while( nIndex >= 0 )
	{
		if( pFileName[nIndex] ==L'.'|| pFileName[nIndex] ==L'\\')
		{
			break;
		}
		nIndex--;

	};

	if( nIndex <0)
		return FALSE;

	if(pFileName[nIndex] == L'\\')
		return FALSE;
	if(pFileName[nIndex] == L'.' && nIndex>0 && pFileName[nIndex-1] == L'*')
		return FALSE;
	nIndex++;

	if(pFilePath->Length/sizeof(WCHAR) -nIndex>49)
		return FALSE;

	while(  (USHORT)nIndex <pFilePath->Length/sizeof(WCHAR) &&pFileName[nIndex] != 0 )
	{
		//	if( (pFileName[nIndex] >=L'a' && pFileName[nIndex]<=L'z') ||
		//		(pFileName[nIndex] >=L'A' && pFileName[nIndex]<=L'Z') )
		{
			*pTemp = pFileName[nIndex++];
			pTemp++;
		}
	};
	*pTemp =0;

	*nLength = (pTemp-FileExt)*sizeof(WCHAR);
	//make the chars Uppercase
	PfpUpperCase(FileExt);

	return TRUE;
}

BOOLEAN		PfpGetFileExtFromFileObject(PFILE_OBJECT pObject,WCHAR * FileExt,LONG* nLength)
/*
pObject : fileobject
FileExt : buffer for this has been allocated outside this function
nLength : the Length for Ext ; is num of bytes
*/
{
	return PfpGetFileExtFromFileName(&pObject->FileName,FileExt,nLength);

}




typedef NTSTATUS( * QUERY_INFO_PROCESS)(HANDLE ,
										PROCESSINFOCLASS ,
										PVOID ,
										ULONG ,
										PULONG
										);

//after call this function we must call function to free this UNICODE string.
NTSTATUS GetProcessImageName(HANDLE hProcess,PUNICODE_STRING ProcessImageName)
/*
this routine will allocate memory in ProcessImageName;
and at the same time , it will make the Chars Upper.
*/

{
	NTSTATUS status;
	ULONG returnedLength;	
	UNICODE_STRING	*UniFilePath;
		
	QUERY_INFO_PROCESS ZwQueryInformationProcess =NULL;

	//PROCESS_BASIC_INFORMATION  ProcessBasic;
	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process
	
	if(PASSIVE_LEVEL != KeGetCurrentIrql())
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == ZwQueryInformationProcess) 
	{

		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		ZwQueryInformationProcess = (QUERY_INFO_PROCESS) MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess) 
		{
			return STATUS_INVALID_PARAMETER;
		}
	}
	//
	// Step one - get the size we need
	//
	
	UniFilePath= ExAllocatePoolWithTag(PagedPool,1024,'3009');
	if(UniFilePath== NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	
	status = ZwQueryInformationProcess( hProcess, 
										ProcessImageFileName,
										UniFilePath, // buffer
										1024, // buffer size
										&returnedLength);
	if(NT_SUCCESS(status) && returnedLength>0)
	{
		RtlUpcaseUnicodeString(ProcessImageName,UniFilePath,TRUE);
		ReplaceHardDeviceNameWithDos(ProcessImageName);
	}else if( status== STATUS_BUFFER_OVERFLOW|| status== STATUS_BUFFER_TOO_SMALL|| STATUS_INFO_LENGTH_MISMATCH ==status)
	{
		
		ExFreePool_A(UniFilePath);
		UniFilePath= ExAllocatePoolWithTag(PagedPool,returnedLength+2*sizeof(WCHAR),'4009');
		if(UniFilePath!= NULL)
		{
			status = ZwQueryInformationProcess( hProcess, 
				ProcessImageFileName,
				UniFilePath, // buffer
				returnedLength, // buffer size
				&returnedLength);
			if(NT_SUCCESS(status) && returnedLength>0)
			{
				RtlUpcaseUnicodeString(ProcessImageName,UniFilePath,TRUE);
				ReplaceHardDeviceNameWithDos(ProcessImageName);
			}
		}else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
	}else
	{
		status = STATUS_INVALID_PARAMETER;
	}
	if(UniFilePath)
	{
		ExFreePool(UniFilePath);
	}
	return status;

} 


BOOLEAN
QuerySymbolicLink(PUNICODE_STRING SymbolicLinkName,WCHAR* pBuffer,USHORT BufferLen)
{
	OBJECT_ATTRIBUTES SymbolickLinkObject; 
	UNICODE_STRING UnicodeLinkTarget;
	HANDLE SymbolicLinkHandle; 

	InitializeObjectAttributes(&SymbolickLinkObject,SymbolicLinkName,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE ,0,0); 
	if(!NT_SUCCESS(ZwOpenSymbolicLinkObject(&SymbolicLinkHandle,GENERIC_READ,&SymbolickLinkObject))) 
		return FALSE; 

	
	UnicodeLinkTarget.Buffer=pBuffer;
	UnicodeLinkTarget.MaximumLength=BufferLen;
	UnicodeLinkTarget.Length=0;
	if(!NT_SUCCESS(ZwQuerySymbolicLinkObject(SymbolicLinkHandle,&UnicodeLinkTarget,NULL)))
	{
		ZwClose(SymbolicLinkHandle);
		return FALSE;
	}

	pBuffer[UnicodeLinkTarget.Length/2]=0; 
	ZwClose(SymbolicLinkHandle);
	return TRUE;
}

VOID 
ReplaceHardDeviceNameWithDos(PUNICODE_STRING ProcessImageName)
{
	LONG	nCount =0;
	WCHAR * pszHardPart = NULL;
	USHORT	n= 0;
	if(ProcessImageName== NULL ||ProcessImageName->Buffer== NULL ||ProcessImageName->Length==0)
		return ;

	if(ProcessImageName->Buffer[0]!= L'\\')
		return;

	KdPrint(("Process path convert before %wZ\r\n",ProcessImageName));
// 	for(;n<ProcessImageName->Length/sizeof(WCHAR);n++)
// 	{
// 		if(ProcessImageName->Buffer[n]==L'\\')
// 		{
// 			nCount++;
// 			if(nCount==3)
// 				break;
// 		}
// 	}
// 	
// 	if(nCount==3 && n<ProcessImageName->Length/sizeof(WCHAR))
// 	{
// 		UNICODE_STRING  DeviceHardLink;
// 		WCHAR			szLetter;
// 		pszHardPart  = ExAllocatePoolWithTag(PagedPool,ProcessImageName->Length,'5009');
// 		if(pszHardPart == NULL)
// 		{
// 			return ;
// 		}
// 
// 		memcpy(pszHardPart,ProcessImageName->Buffer,n*sizeof(WCHAR));
// 		pszHardPart[n]=L'\0';
// 		RtlInitUnicodeString(&DeviceHardLink,pszHardPart);
	{
		WCHAR			szLetter;
		long			IndexHardLink=0;
		if(VFSVolumeDeviceToDosNameEx(*ProcessImageName,&szLetter,&IndexHardLink))
		{
			ProcessImageName->Buffer[0] = szLetter;
			ProcessImageName->Buffer[1] = L':';
			memmove(&ProcessImageName->Buffer[2],&ProcessImageName->Buffer[IndexHardLink],ProcessImageName->Length-sizeof(WCHAR)*IndexHardLink);
			ProcessImageName->Length =(USHORT) (ProcessImageName->Length-sizeof(WCHAR)*IndexHardLink+sizeof(WCHAR)*2);
		}
	}
	KdPrint(("Process path convert After %wZ\r\n",ProcessImageName));
	//	ExFreePool(pszHardPart);
/*	}*/
}

BOOLEAN	VFSVolumeDeviceToDosNameEx(UNICODE_STRING DeviceHardLinkPath,WCHAR* DriveLetter,long *HardDiskLeninchars)
{
	UNICODE_STRING DriveLetterName; 
	UNICODE_STRING LinkTarget; 
	UNICODE_STRING LinkTargetTemp; 
	WCHAR			DISK_CH;
	WCHAR			TempLetterName[]=L"\\??\\X:";   //Х Ап·ЦЕд   ЙТФРЮёД
	WCHAR			Buffer[128];

	RtlInitUnicodeString(&DriveLetterName,TempLetterName);

	for (DISK_CH= 'A';DISK_CH<= 'Z';DISK_CH++) 
	{ 
		DriveLetterName.Buffer[4] =DISK_CH; 

		if(!QuerySymbolicLink(&DriveLetterName,Buffer,128*2))
			continue;

		LinkTarget.Buffer=Buffer;
		LinkTarget.MaximumLength=128;
		LinkTarget.Length=wcslen(LinkTarget.Buffer)*sizeof(WCHAR);
		//KdPrint(("VFSVolumeDeviceToDosName:LinkName=%wZ,QuerySymNmae=%wZ\n",&LinkTarget,&DeviceObjectName.UnicodeName));
		if(DeviceHardLinkPath.Length>=LinkTarget.Length)
		{
			LinkTargetTemp.Buffer = DeviceHardLinkPath.Buffer;
			LinkTargetTemp.MaximumLength= DeviceHardLinkPath.MaximumLength;
			LinkTargetTemp.Length =LinkTarget.Length;
			if(RtlEqualUnicodeString(&LinkTargetTemp,&LinkTarget,TRUE))
			{
				*HardDiskLeninchars = (LinkTarget.Length>>1);
				break;
			}
		}
// 		if(RtlEqualUnicodeString(&LinkTarget,&DeviceHardLink,TRUE)) 
// 			break; 
	} 

	if(DISK_CH<= L'Z') 
	{	
		*DriveLetter=DISK_CH;
		return TRUE; 
	}

	return FALSE;
}

BOOLEAN	VFSVolumeDeviceToDosName(UNICODE_STRING DeviceHardLink,WCHAR* DriveLetter)
{
	UNICODE_STRING DriveLetterName; 
	UNICODE_STRING LinkTarget; 
	WCHAR			DISK_CH;
	WCHAR			TempLetterName[]=L"\\??\\X:";   //Х Ап·ЦЕд   ЙТФРЮёД
	WCHAR			Buffer[128];
	RtlInitUnicodeString(&DriveLetterName,TempLetterName);

	for (DISK_CH= 'A';DISK_CH<= 'Z';DISK_CH++) 
	{ 
		DriveLetterName.Buffer[4] =DISK_CH; 

		if(!QuerySymbolicLink(&DriveLetterName,Buffer,128*2))
			continue;

		LinkTarget.Buffer=Buffer;
		LinkTarget.MaximumLength=128;
		LinkTarget.Length=wcslen(LinkTarget.Buffer)*sizeof(WCHAR);
		//KdPrint(("VFSVolumeDeviceToDosName:LinkName=%wZ,QuerySymNmae=%wZ\n",&LinkTarget,&DeviceObjectName.UnicodeName));
		if(RtlEqualUnicodeString(&LinkTarget,&DeviceHardLink,TRUE)) 
			break; 
	} 

	if(DISK_CH<= L'Z') 
	{	
		*DriveLetter=DISK_CH;
		return TRUE; 
	}

	return FALSE;
}

VOID
PfpGetProcessHandleFromID(HANDLE ProcessID,HANDLE* ProcessHandle)
{ 
	//KAPC_STATE state;
	//PEPROCESS eprocess;
	OBJECT_ATTRIBUTES objattri;
	InitializeObjectAttributes(&objattri,NULL ,OBJ_KERNEL_HANDLE ,NULL,NULL);
	__try
	{
		NtOpenProcess(ProcessHandle,GENERIC_READ,&objattri,ProcessID);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		*ProcessHandle = 0;
	}
// 	if(NT_SUCCESS(PsLookupProcessByProcessId(ProcessID,&eprocess)))
// 	{
// 		KeStackAttachProcess (eprocess,&state);
// 		if(!NT_SUCCESS(ObOpenObjectByPointer(eprocess,0, NULL, 0,0,KernelMode,ProcessHandle)))
// 		{
// 			*ProcessHandle = INVALID_HANDLE_VALUE;
// 		}
// 		KeUnstackDetachProcess (&state);
// 
// 	}
}

BOOLEAN
PfpGetDeviceDosNameFromFileHandle(HANDLE  hFile,WCHAR * szDosName)
{
	PFILE_OBJECT pFileObject = NULL;
	NTSTATUS	 ntstatus;
	 POBJECT_NAME_INFORMATION   pObjectName = NULL;
	ntstatus = ObReferenceObjectByHandle(hFile,
		0,
		*IoFileObjectType,
		KernelMode,
		&pFileObject,
		NULL);
	if(NT_SUCCESS(ntstatus))
	{
		if(NT_SUCCESS(ntstatus= IoQueryFileDosDeviceName(pFileObject,&pObjectName )))
		{
			memcpy(szDosName,pObjectName->Name.Buffer,min(4,pObjectName->Name.Length));
			ExFreePool(pObjectName);
		}
		ObDereferenceObject(pFileObject);
	}
	return NT_SUCCESS(ntstatus);
}
PDEVICE_OBJECT PfpGetSpyDeviceFromName(PWCHAR pName)
{
	PLIST_ENTRY pList ;
	WCHAR szDosName[20] = {0} ;

	for( pList = gSpyDeviceExtensionList.Blink ; pList != &gSpyDeviceExtensionList ; pList=pList->Blink)
	{
		PFILESPY_DEVICE_EXTENSION pExt = CONTAINING_RECORD(pList,FILESPY_DEVICE_EXTENSION,NextFileSpyDeviceLink);

		if(pExt->NLExtHeader.DosName.Length != 0  )
		{
			wcsncpy(szDosName,pExt->NLExtHeader.DosName.Buffer,min(19,pExt->NLExtHeader.DosName.Length ));
			szDosName[min(19,pExt->NLExtHeader.DosName.Length )]=0;

			if(wcsstr(pExt->NLExtHeader.DosName.Buffer,pName) != NULL)
			{
				return pExt->NLExtHeader.ThisDeviceObject;
			}
		}
	}

	return NULL;
}

BOOLEAN	PfpCopyDeviceChar(PWCHAR pChar ,PWCHAR pProcessImagePath,__out LONG * Length)
/*
pChar :				buffer for the devicechar
pProcessImagePth:	fullpath for exe
Length			:   num of bytes copied to pChar
*/
{
	LONG nIndex = 0;

	while(pProcessImagePath[nIndex] != 0  && pProcessImagePath[nIndex] != L'\\') nIndex++;

	if( pProcessImagePath[nIndex]== L'\\' && nIndex < 19 )
	{
		wcsncpy(pChar,pProcessImagePath,nIndex);
		pChar[nIndex] =0 ;
		*Length = nIndex*sizeof(WCHAR);
		return TRUE;
	}
	return FALSE;

}

BOOLEAN IncreaseNum(PWCHAR pNum ,LONG nIndex)
{
	if((pNum[nIndex] <L'0' || pNum[nIndex] >L'9'))
		return FALSE;

	if(pNum[nIndex] <L'9')
	{
		pNum[nIndex]++;
		return TRUE;
	}

	if(nIndex ==0) return FALSE;

	if(IncreaseNum(pNum,nIndex-1))
	{
		pNum[nIndex]=L'0';
		return TRUE;
	}else
		return FALSE;

}

BOOLEAN			
PfpFileExtentionExistInProcInfoNotSelete(PPROCESSINFO  ProcInof,PWCHAR ext)
{
	PLIST_ENTRY plist		= NULL;
	PFILETYPE	FileType	= NULL;
	BOOLEAN		bFound		= FALSE;
	PWCHAR		pszTemp		= NULL;
	
	WCHAR			p2[]=L"DLL";
	WCHAR			p3[]=L"OCX";
	WCHAR			p4[]=L"EXE";
	WCHAR			p5[]=L"SYS";
	WCHAR			p6[]=L"COM";
	WCHAR			p7[]=L"BAT";

	if(ProcInof == NULL ||ext == NULL)
		return bFound;

	
	if(!ProcInof->bBowser)
	{	
		if(_wcsicmp(ext,p2)==0||_wcsicmp(ext,p3)==0||_wcsicmp(ext,p4)==0||_wcsicmp(ext,p5)==0||_wcsicmp(ext,p7)==0||_wcsicmp(ext,p6)==0)
		{
			return TRUE;
		}

		if(IsListEmpty(&ProcInof->FileTypes))
			return bFound;
	
		ExAcquireFastMutex(&ProcInof->FileTypesMutex);

	
		for(plist = ProcInof->FileTypes.Blink; plist != &ProcInof->FileTypes; plist =plist->Blink)
		{
			FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
			if(FileType ->bSelected)
				continue;
			// skip the . char
			pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];

			if(_wcsicmp(ext,pszTemp )==0)
			{
				bFound= TRUE;
				break;
			}
		}
	
		ExReleaseFastMutex(&ProcInof->FileTypesMutex);
	}
	return bFound;
}

BOOLEAN		PfpFileExtentionExistInProcInfo(PPROCESSINFO  ProcInof,PWCHAR ext)
{
	PLIST_ENTRY plist		= NULL;
	PFILETYPE	FileType	= NULL;
	BOOLEAN		bFound		= FALSE;
	PWCHAR		pszTemp		= NULL;
	
	if(ProcInof == NULL ||ext == NULL)
		return bFound;
	
	if(!ProcInof->bBowser)
	{
		if(IsListEmpty(&ProcInof->FileTypes))
			return bFound;
		
		ExAcquireFastMutex(&ProcInof->FileTypesMutex);

		for(plist = ProcInof->FileTypes.Blink; plist != &ProcInof->FileTypes; plist =plist->Blink)
		{
			FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
			if(!FileType->bSelected)
				continue;
			// skip the . char
			pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];
			
			if(_wcsicmp(ext,pszTemp )==0)
			{
				bFound= TRUE;
				break;
			}
		}

		ExReleaseFastMutex(&ProcInof->FileTypesMutex);
	}else
	{
		ExAcquireFastMutex(&ProcInof->FileTypesMutex);
		if(ProcInof->bForceEncryption )	
		{
			bFound= TRUE;
		}
		else
		{
			if(ProcInof->nEncryptTypes &PIC_TYPE)
			{
				PLIST_ENTRY pListHead = &ProcInof->FileTypesForBrowser[Type2ArrayIndex(PIC_TYPE)];

				if(!IsListEmpty(pListHead))
				{
					for(plist = pListHead->Blink; plist!= pListHead; plist = plist->Blink )
					{
						FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
						pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];

						if(_wcsicmp(ext,pszTemp )==0)
						{
							bFound= TRUE;
							break;
						}
					}
					
				}
			}

			if(  !bFound && ProcInof->nEncryptTypes &COOKIE_TYPE)
			{
				PLIST_ENTRY pListHead = &ProcInof->FileTypesForBrowser[Type2ArrayIndex(COOKIE_TYPE)];

				if(!IsListEmpty(pListHead))
				{
					for(plist = pListHead->Blink; plist!= pListHead; plist = plist->Blink )
					{
						FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
						pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];

						if(_wcsicmp(ext,pszTemp )==0)
						{
							bFound= TRUE;
							break;
						}
					}

				}
			}

			if( !bFound && ProcInof->nEncryptTypes &VEDIO_TYPE)
			{
				PLIST_ENTRY pListHead = &ProcInof->FileTypesForBrowser[Type2ArrayIndex(VEDIO_TYPE)];

				if(!IsListEmpty(pListHead))
				{
					for(plist = pListHead->Blink; plist!= pListHead; plist = plist->Blink )
					{
						FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
						pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];

						if(_wcsicmp(ext,pszTemp )==0)
						{
							bFound= TRUE;
							break;
						}
					}

				}
			}

			if( !bFound &&  ProcInof->nEncryptTypes &TEXT_TYPE)
			{
				PLIST_ENTRY pListHead = &ProcInof->FileTypesForBrowser[Type2ArrayIndex(TEXT_TYPE)];

				if(!IsListEmpty(pListHead))
				{
					for(plist = pListHead->Blink; plist!= pListHead; plist = plist->Blink )
					{
						FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
						pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];

						if(_wcsicmp(ext,pszTemp )==0)
						{
							bFound= TRUE;
							break;
						}
					}

				}
			}

			if( !bFound && ProcInof->nEncryptTypes &SCRIPT_TYPE)
			{
				PLIST_ENTRY pListHead = &ProcInof->FileTypesForBrowser[Type2ArrayIndex(SCRIPT_TYPE)];

				if(!IsListEmpty(pListHead))
				{
					for(plist = pListHead->Blink; plist!= pListHead; plist = plist->Blink )
					{
						FileType  = CONTAINING_RECORD(plist,FILETYPE,list);
						pszTemp  = (FileType->FileExt[0]==L'.')?&FileType->FileExt[1]:&FileType->FileExt[0];

						if(_wcsicmp(ext,pszTemp )==0)
						{
							bFound= TRUE;
							break;
						}
					}

				}
			}
		}

		ExReleaseFastMutex(&ProcInof->FileTypesMutex);
	}


	return bFound;
}

PDISKFILEOBJECT 
PfpGetDiskFileObject(
					 UNICODE_STRING*  FullPath_U,					 
					 PLIST_ENTRY     pListHead	 )
{
	PLIST_ENTRY  plist = NULL;
	PDISKFILEOBJECT pDiskFileobj = NULL;
	PPfpFCB      pFcb= NULL;

	if(IsListEmpty(pListHead))
		return NULL;

	for(plist = pListHead->Blink; plist != pListHead; plist = plist->Blink)
	{
		pDiskFileobj  = CONTAINING_RECORD(plist,DISKFILEOBJECT,list);
		
		if((FullPath_U->Length == pDiskFileobj->FullFilePath.Length ) && RtlEqualUnicodeString(FullPath_U,&pDiskFileobj->FullFilePath,TRUE))		
		{
			pFcb=pDiskFileobj->pFCB;
			
			if(  pFcb&& ((pDiskFileobj->pDiskFileObjectWriteThrough== NULL)||/*FlagOn( pFcb->FcbState, FCB_STATE_FILE_DELETED )||*/(pFcb->bModifiedByOther == TRUE)))
			{
				continue;
			}else
			{
				break;
			}
		}
	}
	
	return (plist== pListHead)?NULL:pDiskFileobj ;
}

PDISKFILEOBJECT 
PfpGetDiskFileObjectByUsingFCBONDisk(
					 PVOID FileObjectContext,					 
					 PLIST_ENTRY     pListHead	 )
{
	PLIST_ENTRY  plist = NULL;
	PDISKFILEOBJECT pDiskFileobj = NULL;
	PPfpFCB      pFcb= NULL;

	if(IsListEmpty(pListHead))
		return NULL;

	for(plist = pListHead->Blink; plist != pListHead; plist = plist->Blink)
	{
		pDiskFileobj  = CONTAINING_RECORD(plist,DISKFILEOBJECT,list);

		if( pDiskFileobj->pDiskFileObjectWriteThrough&& pDiskFileobj->pDiskFileObjectWriteThrough->FsContext )		
		{
			pFcb = pDiskFileobj->pFCB;
			if(pFcb->UncleanCount == 0 && pDiskFileobj->pDiskFileObjectWriteThrough->FsContext == FileObjectContext )
				break;
		}
	}

	return (plist== pListHead)?NULL:pDiskFileobj ;
}


FAST_MUTEX*
PfpGetDiskFileObjectMutex(PDEVICE_OBJECT  pSpyDevice )
{
	PFILESPY_DEVICE_EXTENSION	pDeviceExt = pSpyDevice->DeviceExtension;
	if(pDeviceExt == NULL)
		return NULL;
	return NULL;	 
}
PERESOURCE
PfpGetDeviceResource(PDEVICE_OBJECT  pSpyDevice )
{
	PFILESPY_DEVICE_EXTENSION	pDeviceExt = pSpyDevice->DeviceExtension;
	if(pDeviceExt == NULL)
		return NULL;
	return NULL;	 
}


PUSERFILEOBJECT
PfpGetUserFileobjects(PLIST_ENTRY pUserFileobjects,PFILE_OBJECT pUserObject)
{
	PLIST_ENTRY		pList			= NULL;
	PUSERFILEOBJECT pUserFileobject = NULL;

	if(pUserFileobjects == NULL|| IsListEmpty(pUserFileobjects) ||pUserObject == NULL)
		return NULL;
	
	for(pList = pUserFileobjects->Blink;pList!= pUserFileobjects;pList = pList->Blink)
	{
		pUserFileobject  = CONTAINING_RECORD(pList ,USERFILEOBJECT,list)	;
		if(pUserFileobject->UserFileObj == pUserObject)
			break;
	}

	return (pList ==pUserFileobjects)? NULL:pUserFileobject ;
}


BOOLEAN
PfpAreAllFileOBJECTEnterCleanup(PLIST_ENTRY pUserFileobjects)
{
	PLIST_ENTRY		pList			= NULL;
	PUSERFILEOBJECT pUserFileobject = NULL;

	if(pUserFileobjects == NULL|| IsListEmpty(pUserFileobjects) )
		return TRUE;

	for(pList = pUserFileobjects->Blink;pList!= pUserFileobjects;pList = pList->Blink)
	{
		pUserFileobject  = CONTAINING_RECORD(pList ,USERFILEOBJECT,list)	;
		if(!FlagOn(pUserFileobject->UserFileObj->Flags,FO_CLEANUP_COMPLETE))
			return FALSE;
	}
	return TRUE;
}


BOOLEAN	
PfpCheckCreateFileResult(NTSTATUS ntstatus, IO_STATUS_BLOCK * iostatus)
{
	return (NT_SUCCESS(ntstatus) && (iostatus->Information ==FILE_CREATED||
									 iostatus->Information ==FILE_SUPERSEDED||
									 iostatus->Information ==FILE_OVERWRITTEN||
									 iostatus->Information ==FILE_OPENED) );
}


NTSTATUS
PfpCloseRealDiskFile( 
					HANDLE *		FileHandle,
					PFILE_OBJECT *	pFileObject
					)
{
	ASSERT(FileHandle);
	ASSERT(pFileObject);
	if(*pFileObject)
		ObDereferenceObject(*pFileObject);
	*pFileObject = NULL;

	if(*FileHandle != INVALID_HANDLE_VALUE)
 		ZwClose(*FileHandle);
 	*FileHandle = INVALID_HANDLE_VALUE;
	return STATUS_SUCCESS;
}

PPROCESSINFO	
PfpGetProcessInfoUsingFullPath(
							   PWCHAR pszProcessImageFullPath
							   )
{
	PLIST_ENTRY		pList = NULL;
	PPROCESSINFO	ProcessInfo = NULL;
	UNICODE_STRING  szFullPath ;
	
	ASSERT(pszProcessImageFullPath);

	RtlInitUnicodeString(&szFullPath,pszProcessImageFullPath);
	for(pList = g_ProcessInofs.Blink;pList != &g_ProcessInofs; pList= pList->Blink)
	{
		ProcessInfo  = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(RtlCompareUnicodeString(&szFullPath,&ProcessInfo->ProcessName,TRUE) ==0)
		{
			InterlockedIncrement(&ProcessInfo->nRef);
			return ProcessInfo;
		}
	}

	return NULL;
}
PPROCESSINFO	PfpGetProcessInfoUsingHashValue(UCHAR * pHash,LONG Length,PWCHAR pszProcessImageFullPath)
{
	PLIST_ENTRY		pList = NULL;
	PPROCESSINFO	ProcessInfo = NULL;
	pszProcessImageFullPath;
	
	if(pHash == NULL||Length ==0)
		return NULL;
	
	if(PROCESSHASHVALULENGTH  != Length)
		return NULL;

	for(pList = g_ProcessInofs.Blink;pList != &g_ProcessInofs; pList= pList->Blink)
	{
		ProcessInfo  = CONTAINING_RECORD(pList,PROCESSINFO,list);
		if(PROCESSHASHVALULENGTH == RtlCompareMemory(ProcessInfo->ProcessHashValue,pHash,PROCESSHASHVALULENGTH)/*&&
			RtlCompareUnicodeString(&szFullPath,&ProcessInfo->ProcessName,TRUE) ==0*/)
		{
			InterlockedIncrement(&ProcessInfo->nRef);
			return ProcessInfo;
		}
	}

	return NULL;
}


PVOID	PfpCreateFCB()
{
	
	PfpFCB * pFCB;
	//VirtualizerStart();
	pFCB = ExAllocateFromNPagedLookasideList( &g_PfpFCBLookasideList);

	if ( pFCB == NULL)
	{
		goto RETURN;
	}

	
	RtlZeroMemory(pFCB,sizeof(PfpFCB ));
	
	pFCB->Header.NodeTypeCode  = 0x8000; // for 3rd party file systems
	pFCB->Header.NodeByteSize  = sizeof(PfpFCB);

	pFCB->NtFsFCB = ExAllocateFromNPagedLookasideList( &g_NTFSFCBLookasideList);

	if(pFCB->NtFsFCB == NULL)
	{
		goto exit;
	}
	
	RtlZeroMemory(pFCB->NtFsFCB,sizeof(NTFSFCB ));

	pFCB->Header.FastMutex = ExAllocateFromNPagedLookasideList( &g_FaseMutexInFCBLookasideList);
	if (pFCB->Header.FastMutex == NULL)
	{
		goto exit;	
	}
	
	pFCB->NtFsFCB->Resource =  pFCB->Resource	= (ERESOURCE* )ExAllocateFromNPagedLookasideList(&g_EresourceLookasideList)	;
	if (pFCB->Resource== NULL)
	{
		goto exit;
	}


/*	pFCB->NtFsFCB->PageioResource =*/ pFCB->Header.Resource = (ERESOURCE* )ExAllocateFromNPagedLookasideList(&g_EresourceLookasideList)	;
	if (pFCB->Header.Resource  == NULL)
		goto exit;
	
	pFCB->PendingEofAdvances = ExAllocateFromNPagedLookasideList( &g_ListEntryInFCBLookasideList);
	if(pFCB->PendingEofAdvances == NULL)
	{
		goto exit;
	}

	pFCB->Other_Mutex=  ExAllocateFromNPagedLookasideList( &g_FaseMutexInFCBLookasideList);
	if(pFCB->Other_Mutex == NULL)
	{
		goto exit;
	}
	
	ExInitializeResourceLite(pFCB->Resource);

	ExInitializeFastMutex(pFCB->Header.FastMutex);

	ExInitializeFastMutex(pFCB->Other_Mutex);

	ExInitializeResourceLite(pFCB->Header.Resource);
	
	InitializeListHead(pFCB->PendingEofAdvances);

	FsRtlInitializeOplock(&pFCB->Oplock);

	FsRtlSetupAdvancedHeader(&pFCB->Header,NULL);
	ClearFlag(pFCB->Header.Flags2,FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS );
	pFCB->Header.IsFastIoPossible			= FastIoIsNotPossible;
	pFCB->Header.AllocationSize.QuadPart	= -1;
	pFCB->Header.FileSize.QuadPart			= 0;
	pFCB->Header.ValidDataLength.QuadPart	= 0;
	pFCB->Vcb								= szVcbPlacer;
	pFCB->NoPagedFCB						= pFCB;
	
	goto RETURN;

exit:

	if (pFCB->Header.FastMutex)
		ExFreePool(pFCB->Header.FastMutex);

	if (pFCB->Resource	)
		ExFreePool(pFCB->Resource);

	if (pFCB->Header.Resource)
		ExFreePool(pFCB->Header.Resource );
	
	if(pFCB->PendingEofAdvances)
		ExFreePool(pFCB->PendingEofAdvances);

	if(pFCB->Other_Mutex)
	{
		ExFreePool(pFCB->Other_Mutex);

	}
	if(pFCB->NtFsFCB)
	{		
		ExFreePool(pFCB->NtFsFCB);
	}

	if(pFCB->FileLock)
	{
		ExFreePool(pFCB->FileLock);
	}
	ExFreePool(pFCB);
	pFCB = NULL;
RETURN:
	//VirtualizerEnd();
	return pFCB;
	
}

VOID 	
PfpDeleteFCB(
			 PPfpFCB* ppFcb
			 )
{
	////VirtualizerStart();
	if ((*ppFcb)->Header.FastMutex)
	{
		
		ExFreePool((*ppFcb)->Header.FastMutex);
		(*ppFcb)->Header.FastMutex = NULL;
	}else
	{
		ASSERT(0);
	}

	if ((*ppFcb)->Resource	)
	{
		
		ExDeleteResourceLite((*ppFcb)->Resource);
		ExFreeToNPagedLookasideList(&g_EresourceLookasideList,(*ppFcb)->Resource);
		 
		(*ppFcb)->Resource = NULL;
	}else
	{
		ASSERT(0);
	}

	if ((*ppFcb)->Header.Resource)
	{
		ExDeleteResourceLite((*ppFcb)->Header.Resource );
		ExFreeToNPagedLookasideList(&g_EresourceLookasideList,(*ppFcb)->Header.Resource);
		
		(*ppFcb)->Header.Resource = NULL;
	}else
	{
		ASSERT(0);
	}
	
	if((*ppFcb)->PendingEofAdvances)
	{
		ExFreeToNPagedLookasideList(&g_ListEntryInFCBLookasideList,(*ppFcb)->PendingEofAdvances);
		
		(*ppFcb)->PendingEofAdvances= NULL;
	}else
	{
		ASSERT(0);
	}

	if((*ppFcb)->Other_Mutex)
	{
		ExFreeToNPagedLookasideList(&g_FaseMutexInFCBLookasideList,(*ppFcb)->Other_Mutex);
		
		(*ppFcb)->Other_Mutex = NULL;
	}else
	{
		ASSERT(0);
	}
	if((*ppFcb)->NtFsFCB)
	{
		ExFreeToNPagedLookasideList(&g_NTFSFCBLookasideList,(*ppFcb)->NtFsFCB);
		
	}

	if((*ppFcb)->Oplock)
	{
		FsRtlUninitializeOplock(&(*ppFcb)->Oplock);
	}

	if((*ppFcb)->FileLock)
	{
		FsRtlUninitializeFileLock((*ppFcb)->FileLock);
		ExFreePool((*ppFcb)->FileLock);
	}
	ExFreeToNPagedLookasideList(&g_PfpFCBLookasideList,*ppFcb);
	*ppFcb = NULL; 
	////VirtualizerEnd();
	return ;
	//

}

PVOID	
PfpCreateCCB()
{
	PfpCCB * pCCB;
	pCCB = ExAllocatePoolWithTag( NonPagedPool,sizeof(PfpCCB),'N411');
	RtlZeroMemory(pCCB,sizeof(PfpCCB));
	return pCCB;
}

VOID	
PfpDeleteCCB(
			 PPfpCCB ppCcb
			 )
{
	ExFreePool(ppCcb);
}
BOOLEAN		PfpCheckEncryptInfo(PVOID szBuffer,ULONG Length)
{
	if(szBuffer == NULL ||Length < sizeof(LONGLONG))
		return FALSE;	

	return (*(LONGLONG*)szBuffer == 0xA1F0B4CF378EB4C8);
		
}

PUSERFILEOBJECT PfpCreateUserFileObject( PFILE_OBJECT userfileobject , 
								 PFILE_OBJECT diskfileobject,
								 HANDLE diskfilehandle
							 )
{
	PUSERFILEOBJECT pUserFileobject =(PUSERFILEOBJECT) ExAllocateFromNPagedLookasideList(&g_UserFileObejctLookasideList);
	if(pUserFileobject== NULL)
		return NULL;

	pUserFileobject->DiskFileHandle = diskfilehandle;
	pUserFileobject->DiskFileobj    = diskfileobject;
	pUserFileobject->UserFileObj    = userfileobject;
	InitializeListHead(&pUserFileobject->list);
	return pUserFileobject;
}

VOID	
PfpAddUserFileObjectIntoDiskFileObject(PDISKFILEOBJECT pDiskFileObject,
									   PUSERFILEOBJECT pUserFileObject)
{

	if(pDiskFileObject == NULL ||pUserFileObject == NULL)
		return ;
	
	InsertTailList(&pDiskFileObject->UserFileObjList,&pUserFileObject->list);
}

VOID
PfpAddDiskFileObjectIntoList(
							 PDISKFILEOBJECT pDiskFileObject,
							 PLIST_ENTRY     pListHead )
{
	InsertTailList(pListHead,&pDiskFileObject->list);
}

// remove the entry from diskfileobject,and delete the pUserFileobject's memory
VOID
PfpRemoveUserFileObejctFromDiskFileObject(PLIST_ENTRY pListHead,PUSERFILEOBJECT pUserFileObejct)
{
	PLIST_ENTRY		pList=  NULL;
	PUSERFILEOBJECT pTemp= NULL;
	for(pList = pListHead->Blink; pList != pListHead;pList= pList->Blink)
	{
		pTemp = (PUSERFILEOBJECT)CONTAINING_RECORD(pList,USERFILEOBJECT,list);
		if(pUserFileObejct ==  pTemp)
		{
			RemoveEntryList (&(pUserFileObejct)->list);
			break;
		}
	}
}

VOID
PfpDeleteUserFileObject(
						PUSERFILEOBJECT* pUserFileObejct
						)
{
	ASSERT(pUserFileObejct);
	if( *pUserFileObejct != NULL)
	{
		ExFreeToNPagedLookasideList(&g_UserFileObejctLookasideList, *pUserFileObejct);
		
		*pUserFileObejct = NULL;
	}
}

VOID
PfpRemoveDiskFileObjectFromListEntry(
								  PDISKFILEOBJECT pDiskFileObject										
								  )
{
	ASSERT(pDiskFileObject);	
	RemoveEntryList(&pDiskFileObject->list);
}

PDISKFILEOBJECT	
PfpCreateDiskFileObject(
						UNICODE_STRING* pFullPath,
						PDEVICE_OBJECT  pDevice
						)
{	
	PDISKFILEOBJECT pDiskFileObject =  NULL;
	LONG			nIndexofLastSep = -1;
	ASSERT(pFullPath && pDevice);
	nIndexofLastSep   = ((pFullPath->Length>>1)-1);
	pDiskFileObject   = (PDISKFILEOBJECT)ExAllocateFromNPagedLookasideList(&g_DiskFileObejctLookasideList);
	if(pDiskFileObject == NULL)
	{
			return NULL;
	}
	
	RtlZeroMemory(pDiskFileObject ,sizeof(DISKFILEOBJECT));

	while(nIndexofLastSep>=0 && pFullPath->Buffer[nIndexofLastSep]!= L'\\') nIndexofLastSep--;
	ASSERT(nIndexofLastSep>=0);
	
	
	nIndexofLastSep++;

	pDiskFileObject->FileNameOnDisk.Length = (USHORT)(pFullPath->Length- (nIndexofLastSep<<1));
	pDiskFileObject->FileNameOnDisk.MaximumLength = (pDiskFileObject->FileNameOnDisk.Length +(2<<1));
	pDiskFileObject->FileNameOnDisk.Buffer = ExAllocatePoolWithTag( NonPagedPool,pDiskFileObject->FileNameOnDisk.MaximumLength,'N511');
	if(pDiskFileObject->FileNameOnDisk.Buffer == NULL)
	{
		ExFreeToNPagedLookasideList(&g_DiskFileObejctLookasideList,pDiskFileObject);
		return NULL;
	}

	memcpy(pDiskFileObject->FileNameOnDisk.Buffer ,&pFullPath->Buffer[nIndexofLastSep],pDiskFileObject->FileNameOnDisk.Length);
	pDiskFileObject->FileNameOnDisk.Buffer[pDiskFileObject->FileNameOnDisk.Length>>1]=L'\0';
	
	pDiskFileObject->FullFilePath.Buffer = ExAllocatePoolWithTag( NonPagedPool,pFullPath->MaximumLength+2*sizeof(WCHAR),'N611');
	if(pDiskFileObject->FullFilePath.Buffer == NULL)
	{
		ExFreePool_A(pDiskFileObject->FileNameOnDisk.Buffer);
		ExFreeToNPagedLookasideList(&g_DiskFileObejctLookasideList,pDiskFileObject);
		return NULL;
	}
	memcpy(pDiskFileObject->FullFilePath.Buffer ,pFullPath->Buffer,pFullPath->Length);

	pDiskFileObject->FullFilePath.Length			= pFullPath->Length;
	pDiskFileObject->FullFilePath.MaximumLength		= pFullPath->MaximumLength+2*sizeof(WCHAR);

	ExInitializeResourceLite(&pDiskFileObject->UserObjectResource);
	InitializeListHead(&pDiskFileObject->UserFileObjList);
	 
	pDiskFileObject->pOurSpyDevice = pDevice;
	pDiskFileObject->bAllHandleClosed = FALSE;


	return pDiskFileObject;
}

VOID 
PfpDeleteDiskFileObject(
						PDISKFILEOBJECT *pDiskFileObject
						)
{
	ASSERT(pDiskFileObject && *pDiskFileObject);
	if((*pDiskFileObject)->FullFilePath.Buffer)
	{
		ExFreePool((*pDiskFileObject)->FullFilePath.Buffer);
		(*pDiskFileObject)->FullFilePath.Buffer = NULL;
	}

	if((*pDiskFileObject)->FileNameOnDisk.Buffer)
	{
		ExFreePool((*pDiskFileObject)->FileNameOnDisk.Buffer);
		(*pDiskFileObject)->FileNameOnDisk.Buffer = NULL;
	}

	ExDeleteResourceLite(&(*pDiskFileObject)->UserObjectResource);

	ExFreeToNPagedLookasideList(&g_DiskFileObejctLookasideList,*pDiskFileObject);
	*pDiskFileObject = NULL;
}

BOOLEAN 
IsEmptyDiskFileObject(
					  PDISKFILEOBJECT pDiskFileObject
					  )
{
	ASSERT(pDiskFileObject);

	return IsListEmpty(&pDiskFileObject->UserFileObjList);
}

BOOLEAN
PfpIsThereValidProcessInfo()
{
	PPROCESSINFO pProcInfo = NULL;
	PLIST_ENTRY  plistTemp = NULL;
	PLIST_ENTRY	 pHandleTemp = NULL;
	PHandleOfExe pHandleInfo = NULL;
	ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
	if(!IsListEmpty(&g_ProcessInofs))
	{
		for(plistTemp = g_ProcessInofs.Blink;  plistTemp !=&g_ProcessInofs;plistTemp = plistTemp->Blink )
		{
			pProcInfo = CONTAINING_RECORD(plistTemp,PROCESSINFO,list);

			if(pProcInfo != NULL && pProcInfo ->bEnableEncrypt == TRUE)
			{
				ExReleaseResourceLite(&g_ProcessInfoResource);
				return TRUE;
			}
		}
	}
	ExReleaseResourceLite(&g_ProcessInfoResource);
	return FALSE;
	
}
PPROCESSINFO	PfpGetProcessInfoUsingProcessId(HANDLE hProcess)
{
	PPROCESSINFO pProcInfo = NULL;
	PLIST_ENTRY  plistTemp = NULL;
	PLIST_ENTRY	 pHandleTemp = NULL;
	PHandleOfExe pHandleInfo = NULL;

	if(IsListEmpty(&g_ProcessInofs))
		return NULL;

	for(plistTemp = g_ProcessInofs.Blink;  plistTemp !=&g_ProcessInofs;plistTemp = plistTemp->Blink )
	{
		pProcInfo = CONTAINING_RECORD(plistTemp,PROCESSINFO,list);

		if(pProcInfo != NULL)
		{
			for(pHandleTemp = pProcInfo->hProcessList.Blink ;pHandleTemp != &pProcInfo->hProcessList;pHandleTemp= pHandleTemp->Blink )
			{
				pHandleInfo = CONTAINING_RECORD(pHandleTemp,HandleOfExe,list);

				if(pHandleInfo  && pHandleInfo ->Handle == hProcess)
					break;
			}
			if(pHandleTemp != &pProcInfo->hProcessList)
			{
				break;
			}
			else
			{
				pProcInfo = NULL;
			}
			
		}
	}
	if(pProcInfo)
	{
		InterlockedIncrement(&pProcInfo->nRef);
	}
	
	return pProcInfo;
}

PUSERFILEOBJECT 
PfpRemoveUFOFromDFOByHandle(
							PDISKFILEOBJECT pDiskFileObject,
							PFILE_OBJECT    pFileObject)
{
	PUSERFILEOBJECT pUserFileObject;
	ASSERT(pDiskFileObject != NULL);
	
	pUserFileObject = PfpGetUserFileobjects(&pDiskFileObject->UserFileObjList,pFileObject);
	
	if(pUserFileObject )
	{
		RemoveEntryList (&(pUserFileObject)->list);
	}
	
	return pUserFileObject;

}


BOOLEAN
PfpGetDeviceLetter(IN PDEVICE_OBJECT pDevice,WCHAR* szLetter)
{
	PFILESPY_DEVICE_EXTENSION	pExt				= NULL;
	pExt  = pDevice->DeviceExtension;

	if(pExt->NLExtHeader.DosName.Length==0)
	{
		return FALSE;
	}

	ASSERT(pExt->NLExtHeader.DosName.Length>=2);
	//得到当前这个分区的设备的盘符 例如: C:
	memcpy(szLetter ,pExt->NLExtHeader.DosName.Buffer,2*sizeof(WCHAR));

	return TRUE;

}



BOOLEAN	
PfpGetDosNameFromFullPath (IN WCHAR *pszFullPath, 
						   IN LONG Len,
						   OUT WCHAR* szDosName)
{
	WCHAR szNameSpace[]    =L"\\??\\";
	WCHAR szNameSpace1[]   =L"\\DosDevices\\";

	LONG  nIndex = 0;
	if(Len/sizeof(WCHAR)>wcslen(szNameSpace)||
		Len/sizeof(WCHAR)>wcslen(szNameSpace1))
	{
		if(_wcsnicmp(pszFullPath,szNameSpace,wcslen(szNameSpace))==0)
		{
			memcpy(szDosName,&pszFullPath[wcslen(szNameSpace)],2*sizeof(WCHAR));
			szDosName[2] =L'\0';
			return TRUE;
		}else if(_wcsnicmp(pszFullPath,szNameSpace1,wcslen(szNameSpace1))==0)
		{
			memcpy(szDosName,&pszFullPath[wcslen(szNameSpace1)],2*sizeof(WCHAR));
			szDosName[2] =L'\0';
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}

BOOLEAN
PfpIsDeviceOfUSBType(PDEVICE_OBJECT pOurDeviceObject)
{
	PFILESPY_DEVICE_EXTENSION	pExt				= NULL;
	
	if(pOurDeviceObject== NULL)
	{
		return FALSE;
	}

	pExt = (PFILESPY_DEVICE_EXTENSION	)pOurDeviceObject->DeviceExtension;

	return pExt ->bUsbDevice;

}


NTSTATUS
PfpGetFileSizofEncryptedByShadowDevice(IN WCHAR *			pDirPath,
									   IN WCHAR*			pFileName,
									   IN LONG				NameLenInBytes,	
									   IN PDEVICE_OBJECT	pDevice,
									   LARGE_INTEGER	*	pFileSize,
									   LARGE_INTEGER	*	pAllocation)
{
	//HANDLE hFileParent				= INVALID_HANDLE_VALUE;
	
	HANDLE hFile					= INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES			Objattri;
	UNICODE_STRING				ObjectAttri_U;
	//WCHAR *szFileName			= NULL;
	IO_STATUS_BLOCK				iostatus;
	NTSTATUS					ntstatus;
	

	PDEVICE_OBJECT  pShadowDevice;
	PWCHAR			pDirWithDeviceName;
	PFILESPY_DEVICE_EXTENSION	pExt;
	PFILESPY_DEVICE_EXTENSION	pExtReal;
	LONG			lDirPathLen;
	LONG			lShadowNameLen;
	BOOLEAN			bNetWorkDevice;
	PUCHAR 			pTemp;

	return STATUS_UNSUCCESSFUL;


	pExtReal = (PFILESPY_DEVICE_EXTENSION)pDevice->DeviceExtension;

	ASSERT(!pExtReal ->bShadow);
	ASSERT(pDirPath!= NULL &&pDirPath[0]!=0);

	pShadowDevice = pExtReal ->pShadowDevice;

	ASSERT(pShadowDevice);

	bNetWorkDevice = (pDevice->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM);

	lDirPathLen = wcslen(pDirPath)*sizeof(WCHAR);

	pExt = (PFILESPY_DEVICE_EXTENSION)pShadowDevice ->DeviceExtension;

	lShadowNameLen = bNetWorkDevice?pExt ->UserNames.Length:wcslen(pExt->DeviceNames)*sizeof(WCHAR);

	pDirWithDeviceName = ExAllocatePoolWithTag(PagedPool,lShadowNameLen+lDirPathLen+NameLenInBytes+2*sizeof(WCHAR),'6009');

	if(!pDirWithDeviceName)
		return STATUS_INSUFFICIENT_RESOURCES;

	pTemp = (PUCHAR)pDirWithDeviceName;

	memcpy(pTemp ,bNetWorkDevice?pExt->UserNames.Buffer:pExt->DeviceNames,lShadowNameLen);

	pTemp += lShadowNameLen;	

	memcpy(pTemp ,pDirPath,lDirPathLen);

	if(pDirPath[lDirPathLen/sizeof(WCHAR)-1]!=L'\\')
	{
		pDirWithDeviceName[(lDirPathLen+lShadowNameLen)/sizeof(WCHAR)]=L'\\';
		lShadowNameLen+=2;
	}
	pTemp =(PUCHAR) &pDirWithDeviceName[(lDirPathLen+lShadowNameLen)/sizeof(WCHAR)];
	
	memcpy(pTemp ,pFileName,NameLenInBytes);
	pDirWithDeviceName[(lDirPathLen+lShadowNameLen+NameLenInBytes)/sizeof(WCHAR)] = 0;
	

	 
	RtlInitUnicodeString(&ObjectAttri_U,pDirWithDeviceName);


	InitializeObjectAttributes(&Objattri,
								&ObjectAttri_U,
								OBJ_CASE_INSENSITIVE |OBJ_KERNEL_HANDLE,
								NULL,
								NULL
								);


	ntstatus  = ZwCreateFile(&hFile,
								FILE_READ_DATA| SYNCHRONIZE ,
								&Objattri,
								&iostatus,									
								NULL,
								FILE_ATTRIBUTE_NORMAL ,
								FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
								FILE_OPEN,
								FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
								NULL,
								0);
	if(NT_SUCCESS(ntstatus))
	{
		PFILE_OBJECT pFileObject = NULL;
		ntstatus = ObReferenceObjectByHandle(hFile,
											0,
											*IoFileObjectType,
											KernelMode,
											&pFileObject,
											NULL);
		if(NT_SUCCESS(ntstatus))
		{
			LARGE_INTEGER				ByteOffset = {0};
			PUCHAR						szBuffer	= ExAllocatePoolWithTag(NonPagedPool,512,'N301');
			if(szBuffer!= NULL)
			{
				ntstatus = PfpReadFileByAllocatedIrp(szBuffer,512,ByteOffset,pFileObject,pExtReal->NLExtHeader.AttachedToDeviceObject,&iostatus);
				if(NT_SUCCESS(ntstatus))
				{
					if(iostatus.Information==512)
					{
						if(PfpCheckEncryptInfo((PVOID)szBuffer,(ULONG)iostatus.Information))
						{
							pFileSize->QuadPart = *(LONGLONG*)(szBuffer+sizeof(LONGLONG));
							
							pAllocation->QuadPart = *(LONGLONG*)(szBuffer+3*sizeof(LONGLONG));
						}else
						{
							ntstatus = STATUS_NO_MORE_FILES;
						}
					}
				}
				ExFreePool(szBuffer);
				szBuffer = NULL;
			}
			ObDereferenceObject(pFileObject);	
		}
	}
	 
	if(hFile!= INVALID_HANDLE_VALUE)
	{
		ZwClose(hFile);
	}
	if(pDirWithDeviceName)
	{
		ExFreePool(pDirWithDeviceName);
	}

	return ntstatus;
	
}


BOOLEAN
PfpFileIsPe(PUCHAR pBuffer,ULONG nlen,ULONG* nlenNeed)
{
	if(nlen<sizeof(IMAGE_DOS_HEADER))
	{
		*nlenNeed = sizeof(IMAGE_DOS_HEADER);
		return FALSE;
	}

	if(((PIMAGE_DOS_HEADER)pBuffer)->e_magic!=IMAGE_DOS_SIGNATURE)return FALSE;
	if(nlen< (ULONG)((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew) 
	{
		*nlenNeed = ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew;
		return FALSE;
	}
	
	return (*((ULONG*)(pBuffer+((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew)) == IMAGE_NT_SIGNATURE);
}