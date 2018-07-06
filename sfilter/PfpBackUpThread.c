#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "log.h"
#include "UsbSecure.h"
HANDLE 
PfpCreateBackUpThread()
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	KeInitializeEvent(&g_ThreadEvent,NotificationEvent,
						FALSE);
	PsCreateSystemThread(&handle ,
						THREAD_ALL_ACCESS ,
						NULL,
						NULL,
						NULL,
						PfpBackupThread,
						&g_ThreadEvent 
						);
	return handle;
}
HANDLE 
PfpCreateMonitorThreadForUserModeExe()
{
	HANDLE handle = INVALID_HANDLE_VALUE;
	KeInitializeEvent(&g_ThreadEvent,NotificationEvent,
		FALSE);
	PsCreateSystemThread(&handle ,
		THREAD_ALL_ACCESS ,
		NULL,
		NULL,
		NULL,
		PfpMonitorThread,
		PsGetCurrentProcess() 
		);
	return handle;
};
VOID 
PfpMonitorThread(IN PVOID pContext)
{
	
	BOOLEAN bNeedToSave = FALSE;

	KeWaitForSingleObject(pContext,Executive,KernelMode ,FALSE,NULL);
	ExeHasLoggon = 0;
	g_ourProcessHandle= INVALID_HANDLE_VALUE;
	if(g_LogEvent)
	{
		ObDereferenceObject(g_LogEvent);
		g_LogEvent = NULL;
	}
	if(g_UsbDeviceSignal)
	{
		ObDereferenceObject(g_UsbDeviceSignal);
		g_UsbDeviceSignal = NULL;
	}


	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);

	bNeedToSave = LockAllFolders();
	
	ExReleaseResourceLite(&g_FolderResource);
	FsRtlExitFileSystem();
	
	if(bNeedToSave)
	{
		PfpSaveSystemSettings();
	}
}
VOID 
PfpBackupThread(IN PVOID pContext)
{
	

	PBackUpInfo			pbackup;
	PBackUpFileInfo		pBackUpFile ;
	BOOLEAN				bNeedCopy = FALSE;
	LARGE_INTEGER		timeout;
	timeout.QuadPart = 0;
	UNREFERENCED_PARAMETER(pContext);
	while(TRUE)
	{

		if(STATUS_SUCCESS ==KeWaitForSingleObject(
								(PKEVENT)pContext,
								Executive,
								KernelMode,
								FALSE,
								&timeout
								))
		{
			break;

		}

		
		ExAcquireFastMutex(&g_BackUpMetux);
	
		pbackup = PfpRemoveBackUpInfoFromGlobal();

		ExReleaseFastMutex(&g_BackUpMetux);

		if( !pbackup )
		{
			Sleep();	
		}
		else
		{
			
			pBackUpFile = PfpGetBackFileInfo(pbackup);

			switch(pbackup->Request_Place )
			{
			case REQUEST_FROM_CLOSE :
				{
					if(pBackUpFile )
					{
						RemoveEntryList(&pBackUpFile->list);
						PfpCloseBackUpFile(pBackUpFile);
						PfpDeleteBackUpFileStuct (pBackUpFile);
					}
				}
				break;
			case REQUEST_FROM_WRITE:
				{
					if(pBackUpFile )
					{
						PfpWriteBackupFile(pBackUpFile,pbackup);
					}
				}
				break;

			case REQUEST_FROM_DELETE:
				{
					if(pBackUpFile )
					{
						PfpDeleteFile(pBackUpFile,pbackup);
					}
				}
				break;
			case REQUEST_FROM_RENAME:
				{					
					if(pBackUpFile )
					{
						PfpRenameFile(pBackUpFile,pbackup);
					}
				}
				break;
			case REQUEST_FROM_CREATE:
				{
					if(pBackUpFile== NULL)
					{	//1：检查时不是有定期的备份文件（定期备份是针对 应用程序和应用程序的 文件类型）
						//检查是不是可以创建备份文件。
						//here检查是不是可以创建 这个文件
						//再看要不要copy file
						IO_STATUS_BLOCK		iostatus;
						NTSTATUS			ntstatus;
						HANDLE				hOrginalFile = INVALID_HANDLE_VALUE;

						pBackUpFile =  PfpCreateBackUpFile(pbackup,&bNeedCopy );
						if(pBackUpFile )
						{							
							if(bNeedCopy)
							{
								ntstatus = PfpOpenOriganlFileForBackup(pbackup->pOrginalFileFullPath,&hOrginalFile,&iostatus);
								if(ntstatus == STATUS_OBJECT_PATH_NOT_FOUND ||iostatus.Information ==FILE_OPENED)
								{
									if(iostatus.Information ==FILE_OPENED)
									{
										PfpCopyFile(pBackUpFile->hBackUpFile,hOrginalFile);
									}
									InsertTailList(&g_BackUp_FileInfoLists,&pBackUpFile->list);
								}else
								{
									PfpDeleteBackUpFileStuct(pBackUpFile);
									pBackUpFile = NULL;
								}
							}else
							{
								InsertTailList(&g_BackUp_FileInfoLists,&pBackUpFile->list);
							}
						}
								
					}

					KeSetEvent(pbackup->Event, IO_NO_INCREMENT,FALSE);
					pbackup = NULL;//这里我们要清空这个数据，让create的函数来删除这个内存

				}
				break;
			default:
				break;
			}
			if(pBackUpFile)
			{	

			}
			if(pbackup)
				PfpDeleteBackUpInfo(pbackup);
		}
	};
}

VOID 
PfpDeleteBackUpFileStuct(PBackUpFileInfo pBackUpFile)
{
	if(pBackUpFile->pExeName)
	{
		ExFreePool(pBackUpFile->pExeName);
	}
	if(pBackUpFile->pFileName)
	{
		ExFreePool(pBackUpFile->pFileName);
	}
	ExFreePool(pBackUpFile);
}
VOID 
PfpCloseBackUpFile(PBackUpFileInfo pBackUpFile)
{
	if(pBackUpFile)
	{
		ObDereferenceObject(pBackUpFile->pFileObject_BackUp);
		ZwClose(pBackUpFile->hBackUpFile);
	}
}
VOID 
PfpWriteBackupFile(PBackUpFileInfo pBackupFile,PBackUpInfo pBackUpInfo)
{
	IO_STATUS_BLOCK Iosb;
	
	ZwWriteFile(pBackupFile->hBackUpFile,
				NULL,
				NULL,
				NULL,
				&Iosb,
				pBackUpInfo->pBuffer ,
				pBackUpInfo->nLength,
				&pBackUpInfo->Offset,
				NULL
				);
	//ZwFlushBuffersFile (pBackupFile->hBackUpFile,&Iosb);

}

VOID 
PfpDeleteFile(PBackUpFileInfo pBackupFile,PBackUpInfo pBackUpInfo)
{
	
	IO_STATUS_BLOCK Iosb;
	NTSTATUS		ntstatus;
	FILE_DISPOSITION_INFORMATION DispInfo;
	DispInfo.DeleteFile = TRUE;
	pBackUpInfo;
	ntstatus = ZwSetInformationFile(pBackupFile->hBackUpFile,
						&Iosb,
						&DispInfo,
						sizeof(FILE_DISPOSITION_INFORMATION),
						FileDispositionInformation);

	if(NT_SUCCESS(ntstatus ))
	{
		;
	}
}

VOID 
PfpRenameFile(PBackUpFileInfo pBackupFile,PBackUpInfo pBackUpInfo)
{
	
	PDEVICE_OBJECT			pDevice;
	//IO_STATUS_BLOCK			Iosb;
	NTSTATUS				ntstatus;
	FILE_RENAME_INFORMATION	*pRenameInfo;
	LONG					nExeNameLength;
	PIRP					Irp;
	PIO_STACK_LOCATION		pSp;
	long					nIndex	= 0;
	KEVENT					event;
	PWCHAR					pTemp	= pBackUpInfo->pszExeName;

	pBackUpInfo;
	nExeNameLength = wcslen(pBackUpInfo->pszExeName);
	
	nIndex =  nExeNameLength-1;
//下面过滤掉相对路径中的\\这个分割户
//因为我只处理这个同一个目录下面的rename 操作
	if(nIndex <0)return ;

	while(nIndex >=0 && pBackUpInfo->pszExeName[nIndex]!=L'\\')
		nIndex--;

	if(nIndex>=0 && sizeof(WCHAR)*(nIndex+1) ==nExeNameLength)
		return ;
	
	if(nIndex>=0)
	{
		nIndex++;
		nExeNameLength-=nIndex;
		pTemp = &pBackUpInfo->pszExeName[nIndex];
	}

	pRenameInfo= ExAllocatePool_A(PagedPool,sizeof(FILE_NAME_INFORMATION)+sizeof(WCHAR)*(nExeNameLength+2));

	if(pRenameInfo== NULL)
	{
		return ;
	}
	pRenameInfo->ReplaceIfExists	= TRUE;
	pRenameInfo->RootDirectory		= NULL;
	pRenameInfo->FileNameLength		= sizeof(WCHAR)*nExeNameLength;
	memcpy(pRenameInfo->FileName,pTemp,pRenameInfo->FileNameLength);

	pDevice = IoGetRelatedDeviceObject(pBackupFile->pFileObject_BackUp);
	if(pDevice== NULL)
		return ;

	Irp = IoAllocateIrp(pDevice->StackSize,FALSE );

	if(Irp  == NULL)
	{	
		return ;
	}

	//IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.AdvanceOnly;
	Irp->AssociatedIrp.SystemBuffer = pRenameInfo ;
	Irp->Flags						= IRP_SYNCHRONOUS_API;
	Irp->RequestorMode				= KernelMode;
	Irp->UserIosb					= NULL;
	Irp->UserEvent					= NULL;
	Irp->Tail.Overlay.Thread		= PsGetCurrentThread();

	pSp = IoGetNextIrpStackLocation(Irp);

	pSp->MajorFunction								= IRP_MJ_SET_INFORMATION;	
	pSp->Parameters.SetFile.Length					= sizeof(FILE_NAME_INFORMATION)+sizeof(WCHAR)*(nExeNameLength+2);
	pSp->Parameters.SetFile.FileInformationClass	= FileRenameInformation;
	pSp->Parameters.SetFile.ReplaceIfExists			= TRUE  ;	
	pSp->FileObject									= pBackupFile->pFileObject_BackUp;	
	pSp->DeviceObject								= pDevice;

	KeInitializeEvent(&event,NotificationEvent ,FALSE);

	IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,&event,TRUE,TRUE,TRUE);

	if( STATUS_PENDING == IoCallDriver(pDevice,Irp) )
	{
		KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);
		ntstatus = STATUS_SUCCESS;
	}

	ntstatus = Irp->IoStatus.Status;
	

	IoFreeIrp(Irp);

	ExFreePool(pRenameInfo );
}



VOID 
PfpRenameFileUsingFileobeject(PFILE_OBJECT pBackFileObject, PWCHAR szTargetFileName)
{

	PDEVICE_OBJECT			pDevice;
	//IO_STATUS_BLOCK			Iosb;
	NTSTATUS				ntstatus;
	FILE_RENAME_INFORMATION	*pRenameInfo;
	LONG					nExeNameLength;
	PIRP					Irp;
	PIO_STACK_LOCATION		pSp;
	long					nIndex	= 0;
	KEVENT					event;
	
	
	nExeNameLength = wcslen(szTargetFileName);

	pRenameInfo= ExAllocatePool_A(PagedPool,sizeof(FILE_NAME_INFORMATION)+sizeof(WCHAR)*(nExeNameLength+2));

	if(pRenameInfo== NULL)
	{
		return ;
	}
	pRenameInfo->ReplaceIfExists	= TRUE;
	pRenameInfo->RootDirectory		= NULL;
	pRenameInfo->FileNameLength		= sizeof(WCHAR)*nExeNameLength;
	memcpy(pRenameInfo->FileName,szTargetFileName,nExeNameLength*sizeof(WCHAR));

	pDevice = IoGetRelatedDeviceObject(pBackFileObject);
	if(pDevice== NULL)
		return ;

	Irp = IoAllocateIrp(pDevice->StackSize,FALSE );

	if(Irp  == NULL)
	{	
		return ;
	}

	//IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.AdvanceOnly;
	Irp->AssociatedIrp.SystemBuffer = pRenameInfo ;
	Irp->Flags						= IRP_SYNCHRONOUS_API;
	Irp->RequestorMode				= KernelMode;
	Irp->UserIosb					= NULL;
	Irp->UserEvent					= NULL;
	Irp->Tail.Overlay.Thread		= PsGetCurrentThread();

	pSp = IoGetNextIrpStackLocation(Irp);

	pSp->MajorFunction								= IRP_MJ_SET_INFORMATION;	
	pSp->Parameters.SetFile.Length					= sizeof(FILE_NAME_INFORMATION)+sizeof(WCHAR)*(nExeNameLength+2);
	pSp->Parameters.SetFile.FileInformationClass	= FileRenameInformation;
	pSp->Parameters.SetFile.ReplaceIfExists			= TRUE  ;	
	pSp->FileObject									= pBackFileObject;	
	pSp->DeviceObject								= pDevice;

	KeInitializeEvent(&event,NotificationEvent ,FALSE);

	IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,&event,TRUE,TRUE,TRUE);

	if( STATUS_PENDING == IoCallDriver(pDevice,Irp) )
	{
		KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);
		ntstatus = STATUS_SUCCESS;
	}

	ntstatus = Irp->IoStatus.Status;


	IoFreeIrp(Irp);

	ExFreePool(pRenameInfo );
}

PBackUpFileInfo
PfpGetBackFileInfo(PBackUpInfo pBackUpInfo)
{
	PLIST_ENTRY			plist ;
	PBackUpFileInfo		pBackupFileInfo;

	ASSERT(pBackUpInfo);
	for(plist = g_BackUp_FileInfoLists.Blink;plist!= &g_BackUp_FileInfoLists;plist = plist->Blink)
	{
		pBackupFileInfo  =(PBackUpFileInfo) CONTAINING_RECORD(plist,BackUpFileInfo,list);
		if(pBackupFileInfo  )
		{
			if(_wcsicmp(pBackUpInfo->pFileName,pBackupFileInfo->pFileName)==0 )
			{
				return pBackupFileInfo;
			}
		}
	}

	return NULL;
}

NTSTATUS
PfpCreateBackUpFile_Real(PFILE_OBJECT*pFileObject,HANDLE * hReturn,PWCHAR pszFullPath)
{
	NTSTATUS			status;
	UNICODE_STRING		unFullPath;
	OBJECT_ATTRIBUTES	objectAttributes;
	IO_STATUS_BLOCK     openStatus;
	WCHAR*				pszDirFullPath=NULL;
	LONG				nIndex =0;
	BOOLEAN				bDirMakeSuc = FALSE;
	status = STATUS_SUCCESS;
	
	RtlInitUnicodeString(&unFullPath,pszFullPath);

	InitializeObjectAttributes( &objectAttributes,
								&unFullPath,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL );

	//
	//  Open the file object for the given device.
	//

	status = ZwCreateFile( hReturn,
							SYNCHRONIZE|FILE_WRITE_DATA,
							&objectAttributes,
							&openStatus,
							NULL,
							0,
							FILE_SHARE_READ,
							FILE_OPEN_IF,
							FILE_SYNCHRONOUS_IO_NONALERT|FILE_WRITE_THROUGH,
							NULL,
							0 );

	if(!NT_SUCCESS(status))
	{
		*pFileObject= NULL;
		*hReturn = INVALID_HANDLE_VALUE;
		return status;
	}

	status = ObReferenceObjectByHandle(*hReturn,
										0,
										*IoFileObjectType,
										KernelMode,
										pFileObject,
										NULL);

	if(!NT_SUCCESS(status))
	{
		if(*hReturn!= INVALID_HANDLE_VALUE)
			ZwClose(*hReturn);
		*pFileObject= NULL;
		*hReturn = INVALID_HANDLE_VALUE;
		return status;
	}
	
	return (NTSTATUS)openStatus.Information;
}

VOID 
PfpDeleteBackUpInfo(PBackUpInfo pBackUpInfo)
{
	ASSERT(pBackUpInfo);
	if(pBackUpInfo->pBuffer)
		ExFreePool(pBackUpInfo->pBuffer);
	
	if(pBackUpInfo->pszExeName)
		ExFreePool(pBackUpInfo->pszExeName);
	
	if(pBackUpInfo->pFileName)
		ExFreePool(pBackUpInfo->pFileName);

	if(pBackUpInfo->pOrginalFileFullPath)
		ExFreePool(pBackUpInfo->pOrginalFileFullPath);
	
	if(pBackUpInfo->Event)
	{
		ExFreePool(pBackUpInfo->Event);
	}
	ExFreePool(pBackUpInfo);

}

VOID 
Sleep()
{
	LARGE_INTEGER interval;
	interval.QuadPart = -1000*10000*3;
	KeDelayExecutionThread(KernelMode,FALSE,&interval);
}



PBackUpInfo
PfpRemoveBackUpInfoFromGlobal()
{
	PBackUpInfo pbackUp = NULL;
	PLIST_ENTRY	pList = NULL;

	if(!IsListEmpty(&g_BackUpList))
	{
		pList =RemoveHeadList(&g_BackUpList);	
		pbackUp  = CONTAINING_RECORD(pList,BackUpInfo,List);
	}

	return pbackUp;
}


VOID 
PfpSetProcessNameInFileContext2(PPfpCCB pCcb,PPROCESSINFO pProcInfo)
{
	LONG nIndex =0;
	ASSERT(pCcb && pProcInfo);

	nIndex = pProcInfo->ProcessName.Length/sizeof(WCHAR)-1;
	if(nIndex <=0)
	{
		pCcb->szExeName[0]=0;
		return ;
	}
	
	while(nIndex!=0 && pProcInfo->ProcessName.Buffer[nIndex]!= L'\\')
	{
		nIndex--;
	};

	nIndex++;
	
    memcpy(pCcb->szExeName,&pProcInfo->ProcessName.Buffer[nIndex], min(49*sizeof(WCHAR),pProcInfo->ProcessName.Length-nIndex*sizeof(WCHAR)));
}



PBackUpInfo 
PfpCreateBackUpInfoAndInsertIntoGlobalList(PWCHAR			szExeName,
										   UNICODE_STRING	FullFilePath,
										   PVOID			pBuffer,
										   LONGLONG			offset,
										   LONG				len,
										   ULONG			nRequestFlag)

{
	PBackUpInfo pBackUp ;
	LONG		nIndex =0;
	if(g_szBackupDir == NULL)
	{
		if(pBuffer)
			ExFreePool(pBuffer);
		
		return NULL;
	}

	pBackUp  = (PBackUpInfo)ExAllocatePoolWithTag(PagedPool,sizeof(BackUpInfo),(ULONG  )'ucb');
	if(pBackUp  == NULL)
	{
		goto RETURN;
	}
	
	RtlZeroMemory(pBackUp,sizeof(BackUpInfo));
	pBackUp ->Event= ExAllocatePool_A(NonPagedPool,sizeof(KEVENT));

	if(pBackUp ->Event== NULL)
	{
		goto RETURN;
	}	

	nIndex = FullFilePath.Length/sizeof(WCHAR)-1;
	pBackUp->pOrginalFileFullPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool, FullFilePath.Length+sizeof(WCHAR),(ULONG  )'ucb');
	pBackUp->pFileName = (WCHAR*)ExAllocatePoolWithTag(PagedPool, FullFilePath.Length+sizeof(WCHAR),(ULONG  )'ucb');
	if(pBackUp->pFileName == NULL||pBackUp->pOrginalFileFullPath== NULL)
	{
		goto RETURN;
	}

	memcpy(pBackUp->pOrginalFileFullPath,FullFilePath.Buffer,FullFilePath.Length);
	pBackUp->pOrginalFileFullPath[FullFilePath.Length/sizeof(WCHAR)] =0;

	while( nIndex>=0 && FullFilePath.Buffer[nIndex]!=L'\\')
	{	
		nIndex--;
	};

	if( FullFilePath.Length!=0)
	{
		if(nIndex<0 )
		{			
			memcpy(pBackUp->pFileName, 	 FullFilePath.Buffer, FullFilePath.Length);
			pBackUp->pFileName[ FullFilePath.Length/sizeof(WCHAR)] =0;
		}
		else
		{			
			nIndex++;
			memcpy( pBackUp->pFileName, & FullFilePath.Buffer[nIndex], FullFilePath.Length-nIndex*sizeof(WCHAR));
			pBackUp->pFileName[ FullFilePath.Length/sizeof(WCHAR)-nIndex]=0;
		}
	}
	//pBackUp->pFileName = ExAllocatePool(PagedPool,);
	if(szExeName)
	{
		pBackUp->pszExeName = (WCHAR*)ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(szExeName)+1),(ULONG  )'ucb');
		if(pBackUp->pszExeName== NULL)
		{
			goto RETURN;
		}
		wcscpy(pBackUp->pszExeName ,szExeName);
	}else
	{
		pBackUp->pszExeName = NULL;
	}

	
	pBackUp->nLength		 = len;
	pBackUp->pBuffer		 = pBuffer;
	pBackUp->Offset.QuadPart = offset;
	pBackUp->Request_Place	 = nRequestFlag;
	
	KeInitializeEvent(pBackUp->Event,NotificationEvent ,FALSE);

	ExAcquireFastMutex(&g_BackUpMetux);
	InsertTailList(&g_BackUpList,&pBackUp->List);
	ExReleaseFastMutex(&g_BackUpMetux);

	return pBackUp;
RETURN:
	if(pBuffer)
		ExFreePool(pBuffer);
	if(pBackUp)
	{
		if(pBackUp->Event)
		{ExFreePool(pBackUp->Event);}

		if(pBackUp->pFileName )
		{	ExFreePool(pBackUp->pFileName );}

		if(pBackUp->pOrginalFileFullPath)
		{	ExFreePool(pBackUp->pOrginalFileFullPath);}

		ExFreePool(pBackUp);
	}

	return NULL;
}

BOOLEAN 
PfpMakeBackUpDirExist(PWCHAR szDirFullPaht)
{
	HANDLE			hDir;
	IO_STATUS_BLOCK	iostatus;
	NTSTATUS		ntstatus;
	OBJECT_ATTRIBUTES ObjectAttributes ;
	UNICODE_STRING  DirPath ;
	if(szDirFullPaht == NULL)
		return FALSE;
	hDir = INVALID_HANDLE_VALUE;
	
	RtlInitUnicodeString(&DirPath ,szDirFullPaht);

	InitializeObjectAttributes(&ObjectAttributes,&DirPath ,OBJ_OPENIF|OBJ_KERNEL_HANDLE ,
								NULL,NULL);


//	ntstatus = ZwCreateDirectoryObject(&hDir,DIRECTORY_ALL_ACCESS,&ObjectAttributes);
  	ntstatus=ZwCreateFile(&hDir,
  				  FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES,
  				  &ObjectAttributes,
  				  &iostatus,
  				  NULL,FILE_ATTRIBUTE_DIRECTORY,
  				  FILE_SHARE_READ,
  				  FILE_OPEN_IF,
  				  FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
  				  NULL,
  				  0);
	if(hDir!= INVALID_HANDLE_VALUE)
	{
		ZwClose(hDir);
	}

	return NT_SUCCESS(ntstatus);
}
//这个函数判断是不是周期性的备份文件
BOOLEAN PfpIsBackUpPeriodic(PWCHAR szProcessName,PWCHAR szFileType,OUT ULONG* nPeriodType,OUT ULONG* nCout)	
{
	PLIST_ENTRY			plist		= NULL;
	PLIST_ENTRY			plistTemp	= NULL;
	PPeriodicBackUpInfo pPeriInfo	= NULL;
	PFileTypePeriod     pPeriodType = NULL;
	UNICODE_STRING		UnicodeProcessName;
	UNICODE_STRING		UnicodeFileType;
	UNICODE_STRING		strTemp1;
	UNICODE_STRING		strTemp2;

	if(IsListEmpty(&g_PeriodicBackUpInfo_ListHead))
		return FALSE;

	ASSERT(szProcessName && szFileType);
	RtlInitUnicodeString(&UnicodeProcessName,szProcessName);
	RtlInitUnicodeString(&UnicodeFileType,szFileType)	;

	for(plist  = g_PeriodicBackUpInfo_ListHead.Blink;plist!= &g_PeriodicBackUpInfo_ListHead; plist = plist->Blink)
	{
		pPeriInfo = CONTAINING_RECORD(plist,PeriodicBackUpInfo,list);
		if(pPeriInfo != NULL)
		{
			for(plistTemp = pPeriInfo->FileTypes.Blink; plistTemp != &pPeriInfo->FileTypes;plistTemp= plistTemp->Blink)
			{
				pPeriodType  = CONTAINING_RECORD(plistTemp,FileTypePeriod,list);
				if(pPeriodType) 
				{
					RtlInitUnicodeString(&strTemp1,pPeriInfo->szProcessName);
					RtlInitUnicodeString(&strTemp2,pPeriodType->szFileType);
					if(RtlCompareUnicodeString(&UnicodeProcessName,&strTemp1,FALSE)==0 && RtlCompareUnicodeString(&UnicodeFileType,&strTemp2,FALSE)==0 )
					{
						*nPeriodType = pPeriodType->nPeriodeType;
						*nCout		 = pPeriodType->nCout;	
						return TRUE;
					}

				}
			}
		}
	}
	return FALSE;
}
PBackUpFileInfo
PfpCreateBackUpFile(PBackUpInfo pBackUpInfo,BOOLEAN* bNeedCopy)
{
	ULONG				nPeriodType = 0;
	ULONG				nCount =0;
	LONG				nIndex = 0;
	BOOLEAN				IsPeriodic = FALSE;
	PBackUpFileInfo		pBackupFileInfo;
	WCHAR*				FileFullPath= NULL;
	WCHAR				szDeviceName[20]={0};	
	LONG				nIndex1 =0;
	PDEVICE_OBJECT		pSpyDevice = NULL;
	PFILESPY_DEVICE_EXTENSION devExt;
	NTSTATUS			ntstatus;
	WCHAR*				szDateFoleder= NULL;
	//WCHAR				szDas[1];;
	BOOLEAN				DataFolderExist = FALSE;
	
devExt;
	//szDas[0]=L'\\';
	
	if(g_szBackupDir == NULL)
		return NULL;
	
	FileFullPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*MAX_PATH,(ULONG  )'ucb');
	szDateFoleder =(WCHAR*) ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*MAX_PATH,(ULONG  )'ucb');

	if(FileFullPath == NULL||szDateFoleder == NULL)
	{
		goto exit;
	}
	while(g_szBackupDir[nIndex]==L'\\' && g_szBackupDir[nIndex]!= L'\0' )nIndex++;
	if(g_szBackupDir[nIndex]== L'\0' ) return NULL;

	while(g_szBackupDir[nIndex]!=L'\\'&& g_szBackupDir[nIndex]!= L'\0')
	{
		szDeviceName[nIndex1] =g_szBackupDir[nIndex];
		nIndex1++;
		nIndex++;
	}
	
	pSpyDevice = PfpGetSpyDeviceFromName(szDeviceName);
	//if(pSpyDevice == NULL)
	{
		wcscpy(FileFullPath,L"\\DosDevices\\");
		wcscat(FileFullPath,g_szBackupDir);
		wcscat(FileFullPath,L"\\");
	}
// 	}else
// 	{
// 		nIndex++;
// 		devExt = pSpyDevice->DeviceExtension;
// 		ASSERT(devExt->pShadowDevice);
// 		devExt = devExt->pShadowDevice->DeviceExtension;
// 		wcscpy(FileFullPath,devExt->DeviceNames);
// 		wcscat(FileFullPath,L"\\");
// 		wcscat(FileFullPath,&g_szBackupDir[nIndex]);
// 		wcscat(FileFullPath,L"\\");
// 	}
	
	ASSERT(pBackUpInfo->pFileName);
/*	nIndex  = wcslen(pBackUpInfo->pFileName)-1;
	if(nIndex  <=0)
	{
		if(FileFullPath )
			ExFreePool(FileFullPath );
		if(szDateFoleder )
			ExFreePool(szDateFoleder );
		return NULL;
	}
*/
	ASSERT(pBackUpInfo &&bNeedCopy );
	/*while(pBackUpInfo->pFileName[nIndex]!=L'\\' &&  nIndex>=0)
	{
		nIndex--;
	};

	if(nIndex<0)
	{
		if(FileFullPath )
			ExFreePool(FileFullPath );
		if(szDateFoleder )
			ExFreePool(szDateFoleder );
		return NULL;
	}
	nIndex++;
*/

	//wcscpy(FileFullPath,g_szBackupDir);
	
	//wcscat(FileFullPath,&pBackUpInfo->pszExeName);
	//if(!PfpMakeBackUpDirExist(FileFullPath))
	{
	//	goto exit;
	}

	if(wcslen(FileFullPath)+2+wcslen(pBackUpInfo->pFileName)>MAX_PATH)
	{
		goto exit;
	}
	if(FileFullPath[wcslen(FileFullPath)-1]!=L'\\')
	{
		wcscat(FileFullPath,L"\\");
	}
	
	wcscat(FileFullPath,pBackUpInfo->pFileName);

	
	
	pBackupFileInfo = ExAllocatePool_A(PagedPool,sizeof(BackUpFileInfo));
	if(pBackupFileInfo  == NULL)
	{	
		goto exit;
	}
	
	RtlZeroMemory(pBackupFileInfo  ,sizeof(BackUpFileInfo));
	if(pBackUpInfo->pszExeName)
	{
		pBackupFileInfo->pExeName = ExAllocatePool_A(PagedPool,(wcslen(pBackUpInfo->pszExeName)+1)*sizeof(WCHAR));
		if(pBackupFileInfo->pExeName== NULL)
		{
			goto exit;
		}
		wcscpy(pBackupFileInfo->pExeName ,pBackUpInfo->pszExeName);
	}
	
	if(pBackUpInfo->pFileName)
	{
		pBackupFileInfo->pFileName= ExAllocatePool_A(PagedPool,(wcslen(pBackUpInfo->pFileName)+1)*sizeof(WCHAR));
		if(pBackupFileInfo->pFileName== NULL)
		{
			goto exit;
		}
		wcscpy(pBackupFileInfo->pFileName ,pBackUpInfo->pFileName);
	}
	
	
	ntstatus  = PfpCreateBackUpFile_Real(&pBackupFileInfo->pFileObject_BackUp,&pBackupFileInfo->hBackUpFile,FileFullPath);
	
	if(!NT_SUCCESS(ntstatus ) )
	{
		if(pBackupFileInfo)
		{
			if(pBackupFileInfo->pExeName)
			{
				ExFreePool(pBackupFileInfo->pExeName);
			}
			if(pBackupFileInfo->pFileName)
			{
				ExFreePool(pBackupFileInfo->pFileName);

			}
			ExFreePool(pBackupFileInfo);
		}
		pBackupFileInfo = NULL;
	}else
	{
		*bNeedCopy  = (ntstatus==FILE_CREATED);
	}


	if(FileFullPath )
	{
		ExFreePool(FileFullPath );
	}

	if(szDateFoleder )
	{
		ExFreePool(szDateFoleder );
	}


	return pBackupFileInfo;

exit:
	if(pBackupFileInfo)
	{
		if(pBackupFileInfo->pExeName)
		{
			ExFreePool(pBackupFileInfo->pExeName);
		}
		if(pBackupFileInfo->pFileName)
		{
			ExFreePool(pBackupFileInfo->pFileName);

		}
		ExFreePool(pBackupFileInfo);
	}
	if(FileFullPath )
		ExFreePool(FileFullPath );
	if(szDateFoleder )
		ExFreePool(szDateFoleder );

	return NULL;
	
}



BOOLEAN	
PfpGetLastCreateDateofSubDir(PWCHAR szParent,LARGE_INTEGER * CreateTime,PWCHAR szSubFolder)
{
	UNICODE_STRING	ObjectAttr;
	OBJECT_ATTRIBUTES Obj;
	NTSTATUS		ntStatus;
	IO_STATUS_BLOCK iostatus; 
	HANDLE			pHandleReturned = INVALID_HANDLE_VALUE;
	
	PVOID			  pBuffer = NULL;
	ULONG			  lBufferLen;
	UNICODE_STRING	  FileName;
	NTSTATUS		  ntstatus;
	ULONG			  nIndex =0;
	WCHAR*			  szFileName= NULL;
	BOOLEAN			  bFound;	
	FILE_DIRECTORY_INFORMATION* FileDirectoryEntry = NULL;
	    
	if( (szFileName = (WCHAR*)ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*MAX_PATH,(ULONG)'dlf'))== NULL)
		return FALSE;

	RtlInitUnicodeString(&ObjectAttr,szParent);
	InitializeObjectAttributes(&Obj,&ObjectAttr,OBJ_KERNEL_HANDLE,NULL,NULL);
	

	ntStatus = ZwCreateFile(pHandleReturned,
							FILE_TRAVERSE|SYNCHRONIZE ,
							&Obj,
							&iostatus,									
							NULL,
							0 ,
							FILE_SHARE_READ,
							FILE_OPEN,
							FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0);
	if(!NT_SUCCESS(ntStatus))
	{
		if(szFileName)
			ExFreePool(szFileName);
		return FALSE;
	}

	FileDirectoryEntry = ExAllocatePool_A(PagedPool,sizeof(FILE_DIRECTORY_INFORMATION)+512);
	if(FileDirectoryEntry== NULL)
	{
		if(szFileName)
			ExFreePool(szFileName);
		return FALSE;
	}
	lBufferLen = sizeof(FileDirectoryEntry)+512;	


	ntstatus = ZwQueryDirectoryFile(pHandleReturned,
									NULL,
									NULL,
									NULL,
									&iostatus,
									FileDirectoryEntry,
									lBufferLen,
									FileDirectoryInformation,
									TRUE,
									&FileName,
									TRUE);

	if(!NT_SUCCESS(ntstatus))
	{
		if(szFileName)
			ExFreePool(szFileName);
		return FALSE;
	}

	do 
	{
		if((FileDirectoryEntry->FileAttributes&FILE_ATTRIBUTE_DIRECTORY) ==FILE_ATTRIBUTE_DIRECTORY )
		{
			if(!( (FileDirectoryEntry->FileNameLength==1&&  FileDirectoryEntry->FileName[0]==L'.') ||
				 FileDirectoryEntry->FileName[1]==L'.' ))
			{
				if(CreateTime->QuadPart <FileDirectoryEntry->CreationTime.QuadPart)
				{
					CreateTime->QuadPart = FileDirectoryEntry->CreationTime.QuadPart;
					memcpy(szSubFolder,FileDirectoryEntry->FileName,min(FileDirectoryEntry->FileNameLength,254*sizeof(WCHAR)));
					szSubFolder[min(FileDirectoryEntry->FileNameLength/sizeof(WCHAR),254)]=0;	
				}
				bFound = TRUE;
			}
		}

		ntstatus = ZwQueryDirectoryFile(pHandleReturned,
										NULL,
										NULL,
										NULL,
										&iostatus,
										FileDirectoryEntry,
										lBufferLen,
										FileDirectoryInformation,										
										TRUE,
										NULL,
										FALSE);

	} while( ntstatus!= STATUS_NO_MORE_FILES && NT_SUCCESS(ntstatus));
	
	ZwClose(pHandleReturned);
	if(FileDirectoryEntry)
	{
		ExFreePool(FileDirectoryEntry);
	}

	if(szFileName)
		ExFreePool(szFileName);
	return bFound;
}



BOOLEAN
PfpIsDateLessThandPeriodDate(LARGE_INTEGER CurrentDate ,LARGE_INTEGER FolderDate,ULONG nPeriodType, ULONG nCout)
{
	LARGE_INTEGER  CurrentLocalDate, CurrentLocalFolderDate;
	TIME_FIELDS    CurretDate1,FolderDate1;
	int			   nPeriod;
	UNREFERENCED_PARAMETER(nCout);
	ExSystemTimeToLocalTime(&CurrentDate,&CurrentLocalDate);

	ExSystemTimeToLocalTime(&FolderDate,&CurrentLocalFolderDate);

	RtlTimeToTimeFields(&CurrentLocalDate,&CurretDate1);
	RtlTimeToTimeFields(&CurrentLocalFolderDate,&FolderDate1);

	switch(nPeriodType)
	{
	case 1://每天
		nPeriod = 1;
		return (CurretDate1.Year>=FolderDate1.Year && CurretDate1.Month>=FolderDate1.Month &&CurretDate1.Day>FolderDate1.Day);
		
		break;
	case 2://周几
		nPeriod = 7;
		return (CurretDate1.Year>=FolderDate1.Year && CurretDate1.Month>=FolderDate1.Month &&CurretDate1.Day>FolderDate1.Day);
		break;
	case 3://每月 几号？
		break;
	default:
		break;
	}

	return FALSE;
}

VOID
PfpGetBackUpFolderNameForPeriod(LARGE_INTEGER CurrentDate,ULONG nPeriodType, ULONG nCout,PWCHAR szFolderName)
{
	LARGE_INTEGER  CurrentLocalDate;
	TIME_FIELDS    CurretDateTime;
	
	UNREFERENCED_PARAMETER(nCout);
	UNREFERENCED_PARAMETER(nPeriodType);
	UNREFERENCED_PARAMETER(szFolderName);
	ExSystemTimeToLocalTime(&CurrentDate,&CurrentLocalDate);

	RtlTimeToTimeFields(&CurrentLocalDate,&CurretDateTime);
	

}

NTSTATUS
PfpOpenOriganlFileForBackup(WCHAR* szFullPath,HANDLE * FileHandle, IO_STATUS_BLOCK* iostatus)
{
	OBJECT_ATTRIBUTES	objectAttributes;
	UNICODE_STRING		szUncidoeFullPath;
	

	ASSERT(szFullPath && FileHandle);

	if(szFullPath== NULL||FileHandle==  NULL)
		return FALSE;

	RtlInitUnicodeString(&szUncidoeFullPath,szFullPath);

	InitializeObjectAttributes( &objectAttributes,
								&szUncidoeFullPath,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL );

	return ZwCreateFile( FileHandle,
							SYNCHRONIZE|FILE_READ_DATA,
							&objectAttributes,
							iostatus,
							NULL,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ|FILE_SHARE_WRITE,
							FILE_OPEN,
							FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0 );
	
}

BOOLEAN
PfpGenerateFullFilePathWithShadowDeviceName(IN PDEVICE_OBJECT pSpyDevice,
											IN WCHAR*szFullPathWithoutDeviceName,
											OUT WCHAR** FullPathWithDeviceName)
{
	ULONG								nFullNameLen ;
	PFILESPY_DEVICE_EXTENSION			deviceExt = NULL;
	PWCHAR								pszFullName = NULL;
	ULONG								nDeviceNames;
	ASSERT(pSpyDevice && szFullPathWithoutDeviceName);
	deviceExt  =(PFILESPY_DEVICE_EXTENSION)pSpyDevice ->DeviceExtension;
	ASSERT(deviceExt);

	ASSERT(!deviceExt  ->bShadow);
	
	
	deviceExt  = (PFILESPY_DEVICE_EXTENSION)deviceExt  ->pShadowDevice->DeviceExtension;
	ASSERT(deviceExt  ->bShadow);

	nDeviceNames = wcslen(deviceExt->DeviceNames);
	nFullNameLen  = sizeof(WCHAR)*(2+nDeviceNames+wcslen(szFullPathWithoutDeviceName));
	
	pszFullName  = ExAllocatePool_A(PagedPool,nFullNameLen);
	
	if(pszFullName  == NULL)
		return FALSE;
	
	wcscpy(pszFullName,deviceExt->DeviceNames);
	if(pszFullName[nDeviceNames-1]==L'\\' && szFullPathWithoutDeviceName[0]==L'\\')
	{
		pszFullName[nDeviceNames-1]=0;
	}else if(pszFullName[nDeviceNames-1]!=L'\\' &&szFullPathWithoutDeviceName[0]!=L'\\')
	{
		pszFullName[nDeviceNames]=L'\\';
		pszFullName[nDeviceNames+1] =0;
	}
	wcscat(pszFullName,szFullPathWithoutDeviceName);
	*FullPathWithDeviceName =pszFullName ;

	return TRUE;
}


VOID 
PfpCopyFile(HANDLE hDestination,HANDLE hSource)
{
	IO_STATUS_BLOCK		iostatus;
	PVOID				pBuffer = NULL;	
	NTSTATUS			ntstatus;
	LARGE_INTEGER		Offset;
	ULONG				Length=0;

	Offset.QuadPart =0;
	
	pBuffer  = ExAllocatePool_A(PagedPool ,1024*4);
	if(pBuffer  == NULL)
		return ;

	while(1) 
	{					
		Length = 4*1024;		// 每次读取4k。
		// 读取旧文件。注意status。	
		ntstatus = ZwReadFile(hSource,
								NULL,
								NULL,
								NULL,
								&iostatus,
								pBuffer,
								Length,
								&Offset,	
								NULL);

		if(!NT_SUCCESS(ntstatus))
		{
			// 如果状态为STATUS_END_OF_FILE，则说明文件
			// 的拷贝已经成功的结束了。
			if(ntstatus == STATUS_END_OF_FILE)
				ntstatus = STATUS_SUCCESS;			
			break;			
		}			

		// 获得实际读取到的长度。
		Length =(ULONG)iostatus.Information;		
		// 现在读取了内容。读出的长度为length.那么我写入的长度也应该是length。	
		ntstatus = ZwWriteFile(hDestination,
								NULL,
								NULL,
								NULL,
								&iostatus,
								pBuffer,
								Length,
								&Offset,			
								NULL);


		if(!NT_SUCCESS(ntstatus))		
		{
			DbgPrint("Write  to target file fail \n");
			break;
		}	
		// offset移动，然后继续。直到出现STATUS_END_OF_FILE		
		// 的时候才结束。
		Offset.QuadPart += Length;
	};

	if(pBuffer)
	{
		ExFreePool(pBuffer);
	}
}


ULONG 
PfpGetFileSize(HANDLE hFile)
{	
	FILE_STANDARD_INFORMATION Filestard;
	IO_STATUS_BLOCK  iostatus;
	memset(&Filestard,0,sizeof(Filestard));
	ZwQueryInformationFile(hFile,&iostatus,&Filestard,sizeof(FILE_STANDARD_INFORMATION ),FileStandardInformation);
	if(NT_SUCCESS(iostatus.Status))
	{
		return (ULONG)Filestard.EndOfFile.QuadPart;
	}
	return  0;

}	