
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "UsbSecure.h"


NTSTATUS
FsDirectoryControl(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp)
{
	NTSTATUS					 status;
	PERESOURCE					 pDeviceResouce = NULL;
	PIO_STACK_LOCATION			 irpSp		= IoGetCurrentIrpStackLocation(Irp);	//当前Irp(IO_STACK_LOCATION)的参数
	PFILESPY_DEVICE_EXTENSION	 devExt		= DeviceObject->DeviceExtension;
	
	
	BOOLEAN			bSingle			= (irpSp->Flags &SL_RETURN_SINGLE_ENTRY);
	PVOID			pUserBuffer		= Irp->UserBuffer;
	PVOID			pPreUserBuffer  = NULL;
	ULONG			UserBufferLen	= irpSp->Parameters.QueryDirectory.Length;
	PVOID			pBuffer			= NULL;
	ULONG			nCurrentIndex   = 0;
	LONG			nLenLeft		= 0;
	PVOID			pTempBuffer		= NULL;
	ULONG			nOffset			= 0;
	//WCHAR		   * szParentPath	=NULL;
	//WCHAR*			pTempPath		= NULL;
	ULONG			nTempLen		=0;
	PPROCESSINFO	ProcessInfo		= NULL;
	
	BOOLEAN						bEncryptForFolder = FALSE;
	BOOLEAN						bBackupForFolder = FALSE;
	BOOLEAN						bFolderUnderProtect = FALSE;
	BOOLEAN						bFolderLocked = FALSE;
	ULONG						bEncryptFileTypeForFolder = ENCRYPT_NONE;
	WCHAR						DeviceLetter [3]={0};
	PROTECTTYPE					ProtectTypeForFolder;
	WCHAR					*	FullPathName		= NULL;	 
	WCHAR *						szFullPathofParent  = NULL;
	BOOLEAN						bUsbdeviceNeedEncrypted = FALSE;
	IO_STATUS_BLOCK				ioStatus;
	//PDISKDIROBEJECT				pVirtualRootDir = NULL;
	//PDISKDIROBEJECT				pVirtualDir = NULL;
	ULONG						lParentLen		   = 0;
	 

	FsRtlEnterFileSystem();

	ASSERT(IS_FILESPY_DEVICE_OBJECT( DeviceObject ));
	
	if ( (IRP_MN_QUERY_DIRECTORY != irpSp->MinorFunction))
	{
		goto PASSTHROUGH;
	}

	//if (Irp->RequestorMode == KernelMode)
	{
		goto PASSTHROUGH;
	}
	
	//KdPrint(("PASSTHROUGH compare %ws %d \n",irpSp->FileObject->FileName.Buffer,irpSp->Parameters.QueryDirectory.FileInformationClass));
	
	if (FileBothDirectoryInformation != irpSp->Parameters.QueryDirectory.FileInformationClass && 
		FileIdBothDirectoryInformation!=irpSp->Parameters.QueryDirectory.FileInformationClass&& 
		FileFullDirectoryInformation!= irpSp->Parameters.QueryDirectory.FileInformationClass&&
		FileIdFullDirectoryInformation!= irpSp->Parameters.QueryDirectory.FileInformationClass&&
		FileDirectoryInformation!= irpSp->Parameters.QueryDirectory.FileInformationClass) 
	{			
		goto PASSTHROUGH;
	}

	
 
	
	bUsbdeviceNeedEncrypted = (devExt->bUsbDevice && IsUsbDeviceNeedEncryption(DeviceObject));
	//ExAcquireResourceSharedLite(pDeviceResouce,TRUE);
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
	if(g_ourProcessHandle == PsGetCurrentProcessId())
	{
		goto PASSTHROUGH;//如果是我们的控制台的程序 ，那么就直接pass ，让我们的控制程序能看到任何被隐藏的文件或者文件夹
	}
	
	if(irpSp->FileObject->FileName.Buffer== NULL)
	{
		goto PASSTHROUGH;
	}

	PfpGetDeviceLetter(DeviceObject,DeviceLetter);
	if(irpSp->FileObject->FileName.Buffer!= NULL && irpSp->FileObject->FileName.Length!= 0)
	{
		if(irpSp->Parameters.QueryDirectory.FileName!= NULL&& irpSp->Parameters.QueryDirectory.FileName->Length!=0)
		{
			lParentLen= irpSp->Parameters.QueryDirectory.FileName->Length;
		}
		szFullPathofParent=ExAllocatePool_A(PagedPool,
											(lParentLen+=irpSp->FileObject->FileName.Length)+4*sizeof(WCHAR)+devExt->NLExtHeader.DosName.Length);
		
		if(szFullPathofParent )
		{
			BOOLEAN bFilterValid = (lParentLen!= irpSp->FileObject->FileName.Length);
			PWCHAR pTempParent = szFullPathofParent;
			memcpy(szFullPathofParent,devExt->NLExtHeader.DosName.Buffer,devExt->NLExtHeader.DosName.Length);
			pTempParent +=(devExt->NLExtHeader.DosName.Length>>1);
			szFullPathofParent+=(devExt->NLExtHeader.DosName.Length>>1);
			memcpy(pTempParent,irpSp->FileObject->FileName.Buffer,irpSp->FileObject->FileName.Length);
			if(pTempParent[irpSp->FileObject->FileName.Length/sizeof(WCHAR)-1]!= L'\\')
			{
				pTempParent[irpSp->FileObject->FileName.Length/sizeof(WCHAR)]= L'\\';				
				lParentLen+=sizeof(WCHAR);
				pTempParent = &pTempParent[irpSp->FileObject->FileName.Length/sizeof(WCHAR)+1];
			}else
			{
				pTempParent = &pTempParent[irpSp->FileObject->FileName.Length/sizeof(WCHAR)];
			}
			if(bFilterValid)
			{
				if(irpSp->Parameters.QueryDirectory.FileName->Buffer[0]==L'\\')
				{
					lParentLen-=sizeof(WCHAR);
					memcpy(pTempParent,
						&irpSp->Parameters.QueryDirectory.FileName->Buffer[1],
						irpSp->Parameters.QueryDirectory.FileName->Length-2);
				}else
				{
					memcpy(pTempParent,
						irpSp->Parameters.QueryDirectory.FileName->Buffer,
						irpSp->Parameters.QueryDirectory.FileName->Length);
				}
				
			}
			
			szFullPathofParent[lParentLen/sizeof(WCHAR)]=0;//下面就是找到最后一个 //代表着前面的内容就是一个目录
			pTempParent = &szFullPathofParent[lParentLen/sizeof(WCHAR)-1];
			while( (pTempParent >=szFullPathofParent) && (*pTempParent != L'\\'))pTempParent --;
			pTempParent++;
			*pTempParent=L'\0';
			lParentLen =(ULONG) ((PUCHAR) pTempParent-(PUCHAR)szFullPathofParent);

			szFullPathofParent-=(devExt->NLExtHeader.DosName.Length>>1);
			lParentLen+= devExt->NLExtHeader.DosName.Length;
		}
	}
	
	if(ExeHasLoggon)
	{
		ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
		ProcessInfo = PfpGetProcessInfoUsingProcessId(PsGetProcessId(IoGetCurrentProcess()));
		ExReleaseResourceLite(&g_ProcessInfoResource);
		
		if( (ProcessInfo== NULL|| !ProcessInfo->bEnableEncrypt) &&//没有可信的进程，或者 如果有但是这个进程是暂停加密了
			!bUsbdeviceNeedEncrypted&& szFullPathofParent&& //没有usb 设备或者有但是没有要求 实施加密
			!(bFolderUnderProtect =GetFolderProtectProperty(DeviceLetter ,&szFullPathofParent[devExt->NLExtHeader.DosName.Length>>1],
															(lParentLen-devExt->NLExtHeader.DosName.Length)>>1,
															&ProtectTypeForFolder,
															&bEncryptForFolder,
															&bBackupForFolder,
															&bFolderLocked,
															&bEncryptFileTypeForFolder))//访问的文件也不是在个人安全文件夹里面
			/*(!g_nHIDEState || */
			)
		{
			if(IsListEmpty(&g_HideObjHead)&& IsListEmpty(&g_FolderProtectList)||
				(!IsThereHideItmesInFolder(szFullPathofParent,lParentLen) && !IsThereSecureFolderNeedHide(szFullPathofParent,lParentLen)))
			goto PASSTHROUGH;
		}
		
	}else
	{
		if(IsListEmpty(&g_HideObjHead) && IsListEmpty(&g_FolderProtectList))
			goto PASSTHROUGH;
		else if(szFullPathofParent && lParentLen!=0)
		{			
			if(!IsThereHideItmesInFolder(szFullPathofParent,lParentLen) && !IsThereSecureFolderNeedHide(szFullPathofParent,lParentLen))
				goto PASSTHROUGH;
		}
	}

	pUserBuffer		= Irp->UserBuffer;
	nCurrentIndex	= 0;

	pBuffer			= ExAllocatePoolWithTag(NonPagedPool,irpSp->Parameters.QueryDirectory.Length,'N801');

	if(pBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = status;
		goto RETURN;
	}

 
	nLenLeft    = UserBufferLen;
	pTempBuffer = pBuffer;
 
	
	ExAcquireResourceSharedLite(&g_HideEresource,TRUE);
	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	switch(irpSp->Parameters.QueryDirectory.FileInformationClass )
	{
	case FileBothDirectoryInformation:
		{
			PFILE_BOTH_DIR_INFORMATION	 dirInfo	= NULL;
			if(irpSp->Parameters.QueryDirectory.FileName!= NULL)
			{
				PWCHAR pszFilter	= irpSp->Parameters.QueryDirectory.FileName->Buffer;
				ULONG  FilterLen	= irpSp->Parameters.QueryDirectory.FileName->Length;
 
				if(!(FilterLen==2 && pszFilter[0]==L'*'))
				{
					if(bSingle&& (IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_DIRECTORY)||
					IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_NORMAL)))
					{
						status = STATUS_NO_MORE_FILES;
						goto FilterExit5;
					}
				}
			}
			do 
			{
				if(nLenLeft<(LONG)sizeof(FILE_BOTH_DIR_INFORMATION))
				{
					break;
				}
				status = PfpQueryDirectory(Irp,devExt->NLExtHeader.AttachedToDeviceObject,pBuffer,nLenLeft,&ioStatus);
				if(NT_SUCCESS(status))
				{

					dirInfo =(PFILE_BOTH_DIR_INFORMATION)pBuffer;
					do
					{
 						if(!IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen, 
							dirInfo->FileName,dirInfo->FileNameLength,
							dirInfo->FileAttributes))
						{	
							__try
							{
								LONG nsize =((sizeof(FILE_BOTH_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR)+7)&~7);
								if(nLenLeft>=nsize)
								{

									memcpy(pUserBuffer,dirInfo,sizeof(FILE_BOTH_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR));
									
									if(!(dirInfo->FileAttributes&FILE_ATTRIBUTE_DIRECTORY))
									{

										if(((ProcessInfo&& ProcessInfo->bEnableEncrypt) || ( bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))||bUsbdeviceNeedEncrypted) &&
											(dirInfo->EndOfFile.QuadPart>=ENCRYPTIONHEADLENGTH && 0==(dirInfo->EndOfFile.QuadPart&(LONGLONG)511)) && 
											szFullPathofParent!= NULL)
										{

											LARGE_INTEGER filesize={0};
											LARGE_INTEGER allocation={0};
											
											if(NT_SUCCESS (PfpGetFileSizofEncryptedByShadowDevice(&szFullPathofParent[2],//!!!!!注意是硬编码的2个字符的 deviceletter
															dirInfo->FileName,
															dirInfo->FileNameLength,	
															DeviceObject,
															&filesize,&allocation)))
											{
												((FILE_BOTH_DIR_INFORMATION*)pUserBuffer)->EndOfFile.QuadPart = filesize.QuadPart;
												((FILE_BOTH_DIR_INFORMATION*)pUserBuffer)->AllocationSize.QuadPart = allocation.QuadPart;
											}
											
										}
									}
									pPreUserBuffer = pUserBuffer;

									(PUCHAR)pUserBuffer += nsize;
									nLenLeft-=nsize;

									(*(PFILE_BOTH_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset = (ULONG)((ULONG64)(PUCHAR)pUserBuffer-(ULONG64)(PUCHAR)pPreUserBuffer);
								}else
								{
									goto FilterExit5;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								status = Irp->IoStatus.Status = GetExceptionCode();
							}
						}

						nOffset =  dirInfo->NextEntryOffset;
						dirInfo =(PFILE_BOTH_DIR_INFORMATION)((PUCHAR)dirInfo +nOffset);

					}
					while(nOffset!=0);

					if(pPreUserBuffer!= NULL && bSingle)//上次查询 没有找到
					{
						break;				
					}
					memset(pBuffer,0,UserBufferLen);
				}
				if(!bSingle)
				{
					IoGetCurrentIrpStackLocation(Irp)->Flags&=~SL_RESTART_SCAN; 
				}
			} while(NT_SUCCESS(status));
FilterExit5:
			if(pPreUserBuffer)
			{
				(*(PFILE_BOTH_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset  =0;
				Irp->IoStatus.Information = (UserBufferLen-nLenLeft);
				status = Irp->IoStatus.Status = STATUS_SUCCESS;
			}else
			{
				Irp->IoStatus.Status =status;
			}
		}
		break;
	case FileIdBothDirectoryInformation:
		{
			PFILE_ID_BOTH_DIR_INFORMATION	 dirInfo	= NULL;

			if(irpSp->Parameters.QueryDirectory.FileName!= NULL)
			{
				PWCHAR pszFilter	= irpSp->Parameters.QueryDirectory.FileName->Buffer;
				ULONG  FilterLen	= irpSp->Parameters.QueryDirectory.FileName->Length;
				if(!(FilterLen==2 && pszFilter[0]==L'*'))
				{
					if(bSingle&& (IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_DIRECTORY)||
						IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_NORMAL)))
					{
						status = STATUS_NO_MORE_FILES;
						goto FilterExit5;
					}
				}
			}
			do 
			{

				if(nLenLeft<(LONG)sizeof(FILE_ID_BOTH_DIR_INFORMATION))
				{
					break;
				}
				status = PfpQueryDirectory(Irp,devExt->NLExtHeader.AttachedToDeviceObject,pBuffer,nLenLeft,&ioStatus);
				if(NT_SUCCESS(status))
				{

					dirInfo =(PFILE_ID_BOTH_DIR_INFORMATION)pBuffer;
					do
					{
						if(!IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen, 
							dirInfo->FileName,dirInfo->FileNameLength,
							dirInfo->FileAttributes))
						{	
							__try
							{
								LONG nsize =((sizeof(FILE_ID_BOTH_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR)+7)&~7);
								if(nLenLeft>=nsize)
								{

									memcpy(pUserBuffer,dirInfo,sizeof(FILE_ID_BOTH_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR));
									if(!(dirInfo->FileAttributes&FILE_ATTRIBUTE_DIRECTORY))
									{

										if(((ProcessInfo&& ProcessInfo->bEnableEncrypt) || ( bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))||bUsbdeviceNeedEncrypted) &&
											(dirInfo->EndOfFile.QuadPart>=ENCRYPTIONHEADLENGTH&& 0==(dirInfo->EndOfFile.QuadPart&(LONGLONG)511)) && 
											szFullPathofParent!= NULL)
										{

											LARGE_INTEGER filesize={0};
											LARGE_INTEGER allocation={0};

											if(NT_SUCCESS (PfpGetFileSizofEncryptedByShadowDevice(&szFullPathofParent[2],//!!!!!注意是硬编码的2个字符的 deviceletter
												dirInfo->FileName,
												dirInfo->FileNameLength,	
												DeviceObject,
												&filesize,&allocation)))
											{
												((FILE_ID_BOTH_DIR_INFORMATION*)pUserBuffer)->EndOfFile.QuadPart = filesize.QuadPart;
												((FILE_ID_BOTH_DIR_INFORMATION*)pUserBuffer)->AllocationSize.QuadPart = allocation.QuadPart;
											}

										}
									}
									pPreUserBuffer = pUserBuffer;

									(PUCHAR)pUserBuffer += nsize;
									nLenLeft-=nsize;

									(*(PFILE_ID_BOTH_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset = (ULONG)((ULONG64)(PUCHAR)pUserBuffer-(ULONG64)(PUCHAR)pPreUserBuffer);
								}else
								{
									goto FilterExit4;
								}

							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								status = Irp->IoStatus.Status = GetExceptionCode();
							}
						}

						nOffset =  dirInfo->NextEntryOffset;
						dirInfo =(PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)dirInfo +nOffset);

					}
					while(nOffset!=0);

					if(pPreUserBuffer!= NULL && bSingle)//上次查询 没有找到
					{
						break;				
					}
					memset(pBuffer,0,UserBufferLen);
				}
				if(!bSingle)
				{
					IoGetCurrentIrpStackLocation(Irp)->Flags&=~SL_RESTART_SCAN; 
				}
			} while(NT_SUCCESS(status));
FilterExit4:
			if(pPreUserBuffer)
			{
				(*(PFILE_ID_BOTH_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset  =0;
				Irp->IoStatus.Information = (UserBufferLen-nLenLeft);
				status = Irp->IoStatus.Status = STATUS_SUCCESS;
			}else
			{
				Irp->IoStatus.Status = status;
			}
		}
		break;
	case FileFullDirectoryInformation:
		{
			PFILE_FULL_DIR_INFORMATION	 dirInfo	= NULL;
			if(irpSp->Parameters.QueryDirectory.FileName!= NULL)
			{
				PWCHAR pszFilter	= irpSp->Parameters.QueryDirectory.FileName->Buffer;
				ULONG  FilterLen	= irpSp->Parameters.QueryDirectory.FileName->Length;
				if(!(FilterLen==2 && pszFilter[0]==L'*'))
				{
					if(bSingle&& (IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_DIRECTORY)||
						IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_NORMAL)))
					{
						status = STATUS_NO_MORE_FILES;
						goto FilterExit5;
					}
				}
			}
			do 
			{

				if(nLenLeft<(LONG)sizeof(FILE_FULL_DIR_INFORMATION))
				{
					break;
				}
				status = PfpQueryDirectory(Irp,devExt->NLExtHeader.AttachedToDeviceObject,pBuffer,nLenLeft,&ioStatus);
				if(NT_SUCCESS(status))
				{

					dirInfo =(PFILE_FULL_DIR_INFORMATION)pBuffer;
					do
					{
						if(!IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen, 
							dirInfo->FileName,dirInfo->FileNameLength,
							dirInfo->FileAttributes))
						{	
							__try
							{

								LONG nsize =((sizeof(FILE_FULL_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR)+7)&~7);
								if(nLenLeft>=nsize)
								{

									memcpy(pUserBuffer,dirInfo,sizeof(FILE_FULL_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR));
									if(!(dirInfo->FileAttributes&FILE_ATTRIBUTE_DIRECTORY))
									{

										if(((ProcessInfo&& ProcessInfo->bEnableEncrypt) ||( bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))||bUsbdeviceNeedEncrypted) &&
											(dirInfo->EndOfFile.QuadPart>=ENCRYPTIONHEADLENGTH&& 0==(dirInfo->EndOfFile.QuadPart&(LONGLONG)511)) && 
											szFullPathofParent!= NULL)
										{

											LARGE_INTEGER filesize={0};
											LARGE_INTEGER allocation={0};

											if(NT_SUCCESS (PfpGetFileSizofEncryptedByShadowDevice(&szFullPathofParent[2],//!!!!!注意是硬编码的2个字符的 deviceletter
												dirInfo->FileName,
												dirInfo->FileNameLength,	
												DeviceObject,
												&filesize,&allocation)))
											{
												((FILE_FULL_DIR_INFORMATION*)pUserBuffer)->EndOfFile.QuadPart = filesize.QuadPart;
												((FILE_FULL_DIR_INFORMATION*)pUserBuffer)->AllocationSize.QuadPart = allocation.QuadPart;
											}


										}
									}
									pPreUserBuffer = pUserBuffer;

									(PUCHAR)pUserBuffer += nsize;
									nLenLeft-=nsize;

									(*(PFILE_FULL_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset = (ULONG)((ULONG64)(PUCHAR)pUserBuffer-(ULONG64)(PUCHAR)pPreUserBuffer);
								}else
								{
									goto FilterExit3;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								status = Irp->IoStatus.Status = GetExceptionCode();
							}
						}

						nOffset =  dirInfo->NextEntryOffset;
						dirInfo =(PFILE_FULL_DIR_INFORMATION)((PUCHAR)dirInfo +nOffset);

					}
					while(nOffset!=0);

					if(pPreUserBuffer!= NULL && bSingle)//上次查询 没有找到
					{
						break;				
					}
					memset(pBuffer,0,UserBufferLen);
				}
				if(!bSingle)
				{
					IoGetCurrentIrpStackLocation(Irp)->Flags&=~SL_RESTART_SCAN; 
				}
			} while(NT_SUCCESS(status));
FilterExit3:
			if(pPreUserBuffer)
			{
				(*(PFILE_FULL_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset  =0;
				Irp->IoStatus.Information = (UserBufferLen-nLenLeft);
				status = Irp->IoStatus.Status = STATUS_SUCCESS;
			}else
			{
				Irp->IoStatus.Status =status;
			}
		}
		break;
	case FileDirectoryInformation:
		{
			PFILE_DIRECTORY_INFORMATION	 dirInfo	= NULL;
			if(irpSp->Parameters.QueryDirectory.FileName!= NULL)
			{
				PWCHAR pszFilter	= irpSp->Parameters.QueryDirectory.FileName->Buffer;
				ULONG  FilterLen	= irpSp->Parameters.QueryDirectory.FileName->Length;
				if(!(FilterLen==2 && pszFilter[0]==L'*'))
				{
					if(bSingle&& (IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_DIRECTORY)||
						IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_NORMAL)))
					{
						status = STATUS_NO_MORE_FILES;
						goto FilterExit5;
					}
				}
			}
			do 
			{

				if(nLenLeft<(LONG)sizeof(FILE_DIRECTORY_INFORMATION))
				{
					break;
				}
				status = PfpQueryDirectory(Irp,devExt->NLExtHeader.AttachedToDeviceObject,pBuffer,nLenLeft,&ioStatus);
				if(NT_SUCCESS(status))
				{

					dirInfo =(PFILE_DIRECTORY_INFORMATION)pBuffer;
					do
					{
						if(!IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen, 
							dirInfo->FileName,dirInfo->FileNameLength,
							dirInfo->FileAttributes))
						{	
							__try
							{
								LONG nsize =((sizeof(FILE_DIRECTORY_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR)+7)&~7);
								if(nLenLeft>=nsize)
								{

									memcpy(pUserBuffer,dirInfo,sizeof(FILE_DIRECTORY_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR));
									if(!(dirInfo->FileAttributes&FILE_ATTRIBUTE_DIRECTORY))
									{

										if(((ProcessInfo&& ProcessInfo->bEnableEncrypt) || ( bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))||bUsbdeviceNeedEncrypted) &&
											(dirInfo->EndOfFile.QuadPart>=ENCRYPTIONHEADLENGTH&& 0==(dirInfo->EndOfFile.QuadPart&(LONGLONG)511)) && 
											szFullPathofParent!= NULL)
										{
											LARGE_INTEGER filesize={0};
											LARGE_INTEGER allocation={0};

											if(NT_SUCCESS (PfpGetFileSizofEncryptedByShadowDevice(&szFullPathofParent[2],//!!!!!注意是硬编码的2个字符的 deviceletter
												dirInfo->FileName,
												dirInfo->FileNameLength,	
												DeviceObject,
												&filesize,&allocation)))
											{
												((FILE_DIRECTORY_INFORMATION*)pUserBuffer)->EndOfFile.QuadPart = filesize.QuadPart;
												((FILE_DIRECTORY_INFORMATION*)pUserBuffer)->AllocationSize.QuadPart = allocation.QuadPart;
											}


										}
									}
									pPreUserBuffer = pUserBuffer;

									(PUCHAR)pUserBuffer += nsize;
									nLenLeft-=nsize;

									(*(PFILE_DIRECTORY_INFORMATION)pPreUserBuffer).NextEntryOffset = (ULONG)((ULONG64)(PUCHAR)pUserBuffer-(ULONG64)(PUCHAR)pPreUserBuffer);
								}else
								{
									goto FilterExit2;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								status = Irp->IoStatus.Status = GetExceptionCode();
							}
						}

						nOffset =  dirInfo->NextEntryOffset;
						dirInfo =(PFILE_DIRECTORY_INFORMATION)((PUCHAR)dirInfo +nOffset);

					}
					while(nOffset!=0);

					if(pPreUserBuffer!= NULL && bSingle)//上次查询 没有找到
					{
						break;				
					}
					memset(pBuffer,0,UserBufferLen);
				}
				if(!bSingle)
				{
					IoGetCurrentIrpStackLocation(Irp)->Flags&=~SL_RESTART_SCAN; 
				}
			} while(NT_SUCCESS(status));
FilterExit2:
			if(pPreUserBuffer)
			{
				(*(PFILE_DIRECTORY_INFORMATION)pPreUserBuffer).NextEntryOffset  =0;
				Irp->IoStatus.Information = (UserBufferLen-nLenLeft);
				status = Irp->IoStatus.Status = STATUS_SUCCESS;
			}else
			{
				Irp->IoStatus.Status =status;
			}
		}
		break;
	case FileIdFullDirectoryInformation:
		{
			PFILE_ID_FULL_DIR_INFORMATION	 dirInfo	= NULL;
			if(irpSp->Parameters.QueryDirectory.FileName!= NULL)
			{
				PWCHAR pszFilter	= irpSp->Parameters.QueryDirectory.FileName->Buffer;
				ULONG  FilterLen	= irpSp->Parameters.QueryDirectory.FileName->Length;
				if(!(FilterLen==2 && pszFilter[0]==L'*'))
				{
					if(bSingle&& (IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_DIRECTORY)||
						IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen,pszFilter,FilterLen,FILE_ATTRIBUTE_NORMAL)))
					{
						status = STATUS_NO_MORE_FILES;
						goto FilterExit5;
					}
				}
			}
			do 
			{

				if(nLenLeft<(LONG)sizeof(FILE_ID_FULL_DIR_INFORMATION))
				{
					break;
				}
				status = PfpQueryDirectory(Irp,devExt->NLExtHeader.AttachedToDeviceObject,pBuffer,nLenLeft,&ioStatus);
				if(NT_SUCCESS(status))
				{

					dirInfo =(PFILE_ID_FULL_DIR_INFORMATION)pBuffer;
					do
					{
						if(!IS_MY_HIDE_OBJECT_EX(szFullPathofParent,lParentLen, 
							dirInfo->FileName,dirInfo->FileNameLength,
							dirInfo->FileAttributes))
						{	
							__try
							{

								LONG nsize =((sizeof(FILE_ID_FULL_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR)+7)&~7);
								if(nLenLeft>=nsize)
								{

									memcpy(pUserBuffer,dirInfo,sizeof(FILE_ID_FULL_DIR_INFORMATION)+dirInfo->FileNameLength-sizeof(WCHAR));
									if(!(dirInfo->FileAttributes&FILE_ATTRIBUTE_DIRECTORY))
									{

										if(((ProcessInfo&& ProcessInfo->bEnableEncrypt) || ( bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))||bUsbdeviceNeedEncrypted) &&
											(dirInfo->EndOfFile.QuadPart>=ENCRYPTIONHEADLENGTH&& 0==(dirInfo->EndOfFile.QuadPart&(LONGLONG)511)) && 
											szFullPathofParent!= NULL)
										{

											LARGE_INTEGER filesize={0};
											LARGE_INTEGER allocation={0};

											if(NT_SUCCESS (PfpGetFileSizofEncryptedByShadowDevice(&szFullPathofParent[2],//!!!!!注意是硬编码的2个字符的 deviceletter
												dirInfo->FileName,
												dirInfo->FileNameLength,	
												DeviceObject,
												&filesize,&allocation)))
											{
												((FILE_ID_FULL_DIR_INFORMATION*)pUserBuffer)->EndOfFile.QuadPart = filesize.QuadPart;
												((FILE_ID_FULL_DIR_INFORMATION*)pUserBuffer)->AllocationSize.QuadPart = allocation.QuadPart;
											}
										}
									}
									pPreUserBuffer = pUserBuffer;

									(PUCHAR)pUserBuffer += nsize;
									nLenLeft-=nsize;

									(*(PFILE_ID_FULL_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset =(ULONG)((ULONG64)(PUCHAR)pUserBuffer-(ULONG64)(PUCHAR)pPreUserBuffer);
								}else
								{
									goto FilterExit1;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								status = Irp->IoStatus.Status = GetExceptionCode();
							}
						}

						nOffset =  dirInfo->NextEntryOffset;
						dirInfo =(PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)dirInfo +nOffset);

					}
					while(nOffset!=0);

					if(pPreUserBuffer!= NULL && bSingle)//上次查询 没有找到
					{
						break;				
					}
					memset(pBuffer,0,UserBufferLen);
				}
				if(!bSingle)
				{
					IoGetCurrentIrpStackLocation(Irp)->Flags&=~SL_RESTART_SCAN; 
				}
			} while(NT_SUCCESS(status));
FilterExit1:
			if(pPreUserBuffer)
			{
				(*(PFILE_ID_FULL_DIR_INFORMATION)pPreUserBuffer).NextEntryOffset  =0;
				Irp->IoStatus.Information = (UserBufferLen-nLenLeft);
				status = Irp->IoStatus.Status = STATUS_SUCCESS;
			}else
			{
				Irp->IoStatus.Status =status;
			}
		}
		break;
	default:
		break;
	}
	ExReleaseResourceLite(&g_FolderResource);
	ExReleaseResourceLite(&g_HideEresource);
	
RETURN:
 
	if(ProcessInfo)
	{
		InterlockedDecrement(&ProcessInfo->nRef);
	}
	if(szFullPathofParent)
	{
		ExFreePool(szFullPathofParent);
	}
	
	if(pBuffer)
	{
		ExFreePool(pBuffer);
	}
	FsRtlExitFileSystem();
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;

PASSTHROUGH:
	if(ProcessInfo)
	{
		InterlockedDecrement(&ProcessInfo->nRef);
	}
	if(szFullPathofParent)
	{
		ExFreePool(szFullPathofParent);
	}

	if(pBuffer)
	{
		ExFreePool(pBuffer);
	}
	FsRtlExitFileSystem();
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(devExt->NLExtHeader.AttachedToDeviceObject, Irp);
}

ULONG
PfpGetParentPathFromFileObject(PFILE_OBJECT pParentObject,PWCHAR szParentPath)
{
	
	NTSTATUS				ntstatus = STATUS_SUCCESS ; 
	LONG					nLeninBytes = 0;

	if(pParentObject->FileName.Length ==2 && pParentObject->FileName.Buffer[0]==L'\\')
	{
		szParentPath[0]=L'\\';
		szParentPath[1]=L'\0';
		nLeninBytes =2;
		return nLeninBytes;
	}
	 
	ASSERT(pParentObject->FileName.Length<=(MAX_PATH-3)*sizeof(WCHAR));
	if(pParentObject->FileName.Buffer[0]!=L'\\')
	{
		szParentPath[0] =L'\\';
		szParentPath++;
		nLeninBytes =2;
	}
	memcpy(szParentPath,pParentObject->FileName.Buffer,pParentObject->FileName.Length);
	if(szParentPath[pParentObject->FileName.Length/sizeof(WCHAR)-1]!=L'\\')
	{
		szParentPath[pParentObject->FileName.Length/sizeof(WCHAR)]='\\';
		szParentPath[pParentObject->FileName.Length/sizeof(WCHAR)+1]=L'\0';
		nLeninBytes +=2;
	}
	else
	{
		szParentPath[pParentObject->FileName.Length/sizeof(WCHAR)]=L'\0';
	}
	nLeninBytes +=pParentObject->FileName.Length;

	return nLeninBytes;
}

NTSTATUS 
PfpQueryDirectory(IN PIRP			pOrignalIrp,
				  IN PDEVICE_OBJECT pNextDevice,
				  IN PVOID			pBuffer, //新申请的buffer
				  IN ULONG			Len,//userbuffer中剩余的 字节
				  PIO_STATUS_BLOCK  pIostatus)
{
	PIRP				pnewIrp;
	PIO_STACK_LOCATION  pIostack;
	PIO_STACK_LOCATION  pPreIoStack;	
	KEVENT				waitEvent;
	NTSTATUS			ntstatus;
	pnewIrp = IoAllocateIrp(pNextDevice->StackSize,TRUE);

	if(pnewIrp == NULL)
	{
		pIostatus->Information =0;
		pIostatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		return pIostatus->Status ;

	}	

	pIostack	= IoGetNextIrpStackLocation(pnewIrp);
	
	pPreIoStack = IoGetCurrentIrpStackLocation(pOrignalIrp);

	*pIostack	=* IoGetCurrentIrpStackLocation(pOrignalIrp);
	
	pIostack->FileObject	= pPreIoStack->FileObject;
	pIostack->Flags			= pPreIoStack->Flags;
	pIostack->MajorFunction = pPreIoStack->MajorFunction;
	pIostack->MinorFunction = pPreIoStack->MinorFunction;
	pIostack->Parameters.QueryDirectory.FileIndex			= pPreIoStack->Parameters.QueryDirectory.FileIndex  ;
	pIostack->Parameters.QueryDirectory.FileInformationClass= pPreIoStack->Parameters.QueryDirectory.FileInformationClass  ;

	pnewIrp->MdlAddress = IoAllocateMdl(pBuffer, Len, FALSE, TRUE, NULL);
	if (!pnewIrp->MdlAddress)
	{
		IoFreeIrp(pnewIrp);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	MmBuildMdlForNonPagedPool(pnewIrp->MdlAddress);

	pnewIrp->UserBuffer		= MmGetMdlVirtualAddress(pnewIrp->MdlAddress);
	pnewIrp->UserIosb		= pIostatus;
	pnewIrp->Flags			= pOrignalIrp->Flags;
	pnewIrp->RequestorMode	= KernelMode;

	pnewIrp->Tail.Overlay.Thread = PsGetCurrentThread();
	pnewIrp->UserEvent		= NULL;

	pIostack->Parameters.QueryDirectory.Length = Len;

	KeInitializeEvent(&waitEvent,NotificationEvent ,FALSE);
	IoSetCompletionRoutine(	pnewIrp,
		DirControlCompletion,		//CompletionRoutine
		&waitEvent,					//context parameter
		TRUE,
		TRUE,
		TRUE
		);

	ntstatus =  IoCallDriver(pNextDevice,pnewIrp);

	if (STATUS_PENDING == ntstatus)
	{

		KeWaitForSingleObject( &waitEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL );
	}

	//
	//  Verify the completion has actually been run
	//

	ASSERT(KeReadStateEvent(&waitEvent) || !NT_SUCCESS(pIostatus->Status));

	return pIostatus->Status;
}
/*
*	测试是否是要隐藏的对象
*/

BOOLEAN  IsThereSecureFolderNeedHide(WCHAR* pszFolder,ULONG nLeninBytes)
{
	PLIST_ENTRY headListEntry	= &g_FolderProtectList;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM			tmpFolderItem		= NULL;	
	ULONG					HideObjectLength		= 0;
	PWCHAR					pLeftOfHideItem			= NULL;
	
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpFolderItem		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		HideObjectLength	= tmpFolderItem->szFullPathSize;

		if( tmpFolderItem->Type == NOACCESS_VISABLE|| tmpFolderItem->State!= LOCKED)
			continue;

		if((ULONG)HideObjectLength >= (nLeninBytes>>1) )
		{
			if(0==_wcsnicmp(pszFolder, tmpFolderItem->szFullPath,(nLeninBytes>>1) ))
			{
				if((ULONG)HideObjectLength == (nLeninBytes>>1))
					return TRUE;
				pLeftOfHideItem   = &tmpFolderItem->szFullPath[nLeninBytes>>1];
				while(pLeftOfHideItem < &tmpFolderItem->szFullPath[HideObjectLength])
				{
					if(*pLeftOfHideItem==L'\\' )
						break;
					pLeftOfHideItem ++;
				};
				if(pLeftOfHideItem ==&tmpFolderItem->szFullPath[HideObjectLength])
					return TRUE;
			}
		}
		
	}
	return FALSE;
}
BOOLEAN IsThereHideItmesInFolder(WCHAR* pszFolder,ULONG nLeninBytes)
{
	PLIST_ENTRY headListEntry	= &g_HideObjHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PHIDE_FILE	tmpHideFile		= NULL;
	LONG		HideObjectLength = 0;
	PWCHAR		pLeftOfHideItem  = NULL;
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpHideFile			= (PHIDE_FILE)CONTAINING_RECORD(tmpListEntry, HIDE_FILE, linkfield);
		HideObjectLength	= tmpHideFile->Namesize;
		if(tmpHideFile->nHide==2)
			continue;
		if((ULONG)HideObjectLength >= (nLeninBytes>>1) )
		{
			if(0==_wcsnicmp(pszFolder, tmpHideFile->Name,nLeninBytes>>1))
			{
				if((ULONG)HideObjectLength == (nLeninBytes>>1))
					return TRUE;

				pLeftOfHideItem   = &tmpHideFile->Name[nLeninBytes>>1];
				while(pLeftOfHideItem < &tmpHideFile->Name[HideObjectLength])
				{
					if(*pLeftOfHideItem==L'\\' )
						break;
					pLeftOfHideItem ++;
				};
				if(pLeftOfHideItem ==&tmpHideFile->Name[HideObjectLength])
					return TRUE;
			}
		}
		 
	}
	return FALSE;
}

BOOLEAN
IS_MY_HIDE_OBJECT_EX(const WCHAR *pFolerPathWithBackSplash, ULONG FolderLenth,const WCHAR *pItemName,ULONG NameLenth, ULONG Flag)
{
	PLIST_ENTRY headListEntry	= &g_HideObjHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PHIDE_FILE	tmpHideFile		= NULL;
	PFOLDERPROTECTITEM tmpFolderItem = NULL;
	LONG		HideObjectLength = 0;
	ULONG ObjFlag = (FILE_ATTRIBUTE_DIRECTORY & Flag)?CDO_FLAG_DIRECTORY:CDO_FLAG_FILE;


	if((NameLenth==2&& pItemName[0]==L'.')||(NameLenth==4&& pItemName[0]==L'.' && pItemName[1]==L'.'))
		return FALSE;
	//KdPrint(("compare %ws \n",Name));
	if (IsListEmpty(&g_HideObjHead)&&IsListEmpty(&g_FolderProtectList))
	{
		return FALSE;
	}

	if(!g_nHIDEState && ExeHasLoggon!=0) //如果 用户把安全文件是在解锁的状态
	{
		goto FOLDERPROTECTPROCESS;
	}
	//判断 隐藏的设置

	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpHideFile			= (PHIDE_FILE)CONTAINING_RECORD(tmpListEntry, HIDE_FILE, linkfield);
		HideObjectLength	= tmpHideFile->Namesize;
		
		if(tmpHideFile->nHide==2 )
			continue;
		if(ObjFlag ==  CDO_FLAG_DIRECTORY)
		{
			if(tmpHideFile->Flag== CDO_FLAG_DIRECTORY)
			{
				if((ULONG)HideObjectLength == ((FolderLenth+NameLenth)>>1))
				{
					if(0==_wcsnicmp(tmpHideFile->Name,pFolerPathWithBackSplash,(FolderLenth>>1) )&& 
						0==_wcsnicmp(&tmpHideFile->Name[FolderLenth>>1],pItemName,(NameLenth>>1) )
						)
						return TRUE;
				}
			}
		}else
		{
			if(tmpHideFile->Flag == CDO_FLAG_DIRECTORY)
			{
				if(((ULONG)HideObjectLength+1)==(FolderLenth>>1))
				{
					if(0==_wcsnicmp(tmpHideFile->Name,pFolerPathWithBackSplash,HideObjectLength ))
						return TRUE;
				}
			}else
			{
				if((ULONG)HideObjectLength == ((FolderLenth+NameLenth)>>1))
				{
					if(0==_wcsnicmp(tmpHideFile->Name,pFolerPathWithBackSplash,(FolderLenth>>1) )&& 
						0==_wcsnicmp(&tmpHideFile->Name[FolderLenth>>1],pItemName,(NameLenth>>1) )
						)
						return TRUE;
				}
			}
		}
	}


	// 下面是判断是不是 个人安全文件夹的设置
FOLDERPROTECTPROCESS:

	// 	if(!g_nFolderLock) //如果 用户把安全文件是在解锁的状态
	// 	{
	// 		return FALSE;
	// 	}
	headListEntry= &g_FolderProtectList;
	tmpListEntry = headListEntry;


	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpFolderItem		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		HideObjectLength	= tmpFolderItem->szFullPathSize;

		if(tmpFolderItem->Type != NOACCESS_INVISIBLE|| tmpFolderItem->State!= LOCKED )
			continue;

// 		if((ULONG)HideObjectLength > (NameLenth>>1) )
// 		{
// 			continue;			
// 		}

		if(ObjFlag == CDO_FLAG_DIRECTORY)
		{
			if((ULONG)HideObjectLength == ((FolderLenth+NameLenth)>>1))
			{
				if(0==_wcsnicmp(tmpFolderItem->szFullPath,pFolerPathWithBackSplash,(FolderLenth>>1) )&& 
					0==_wcsnicmp(&tmpFolderItem->szFullPath[FolderLenth>>1],pItemName,(NameLenth>>1) )
					)
				return TRUE;
			}		
		}else
		{
			if(((ULONG)HideObjectLength+1)==(FolderLenth>>1))
			{
				if(0==_wcsnicmp(tmpFolderItem->szFullPath,pItemName,HideObjectLength ))
					return TRUE;
			}			
		}		
	}
	return FALSE;
}
NTSTATUS
DirControlCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	
	//PIO_STACK_LOCATION sp;
	UNREFERENCED_PARAMETER(DeviceObject);
	
	ASSERT( NULL != Irp->UserIosb );

	*Irp->UserIosb = Irp->IoStatus;

	KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);

	//
	//  We are now done, so clean up the IRP that we allocated.
	//
	if(Irp->MdlAddress)
		IoFreeMdl(Irp->MdlAddress);
	IoFreeIrp( Irp );

	return STATUS_MORE_PROCESSING_REQUIRED;	//注：必须返回这个值
}



/*
*	添加一个隐藏对象
*/
VOID
AddHideObject(PWCHAR Name, ULONG Flag)
{
	//添加一个隐藏
	
	PLIST_ENTRY pList = NULL;
	ULONG		nNamesize = 0;
	PHIDE_FILE	newHideObj = NULL;
	PHIDE_FILE	TempHideObj = NULL;
	nNamesize  = wcslen(Name);
	newHideObj= ExAllocatePoolWithTag(PagedPool, sizeof(HIDE_FILE), 'NHFO');
	 
	if(newHideObj== NULL)
	{
		ASSERT(0);
		return ;
	} 
	
	ExAcquireResourceExclusiveLite(&g_HideEresource,TRUE);
	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		TempHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(TempHideObj )
		{
			if( (Flag == TempHideObj->Flag) && (nNamesize  == TempHideObj->Namesize)&&_wcsnicmp(Name,TempHideObj->Name,nNamesize)==0)
			{				 
				break;
			}
		}
	}
	if(pList ==&g_HideObjHead)
	{
		newHideObj->Flag = Flag;
		newHideObj->nHide = 1;
		wcscpy(newHideObj->Name, Name);
		newHideObj->Namesize = nNamesize;
		InsertTailList(&g_HideObjHead, &newHideObj->linkfield);//
		newHideObj = NULL;
	}
	
	ExReleaseResourceLite(&g_HideEresource);
	if(newHideObj != NULL)
	{
		ExFreePoolWithTag(newHideObj, 'NHFO');
	}
	 
	 
	//sKdPrint(("Add Hide Obj:%ws", Name));
}

ULONG 
CalcHidderLen()
{
	PHIDE_FILE newHideObj;
	PLIST_ENTRY pList = NULL;
	ULONG nLen = 0;
	

	if(IsListEmpty(&g_HideObjHead))
		return nLen;


	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			nLen +=	sizeof(WCHAR)*(newHideObj->Namesize+1);			
		}
	}

	return nLen;
}

ULONG 
CopyHidderIntoBuffer(PVOID pOutBufer, ULONG nBufLen)
{
	PHIDE_FILE	newHideObj;
	PLIST_ENTRY pList = NULL;
	ULONG		nLen = 0;
	ULONG		nOneHidderLen = 0;
	PUCHAR		pTemp = (PUCHAR)pOutBufer;
	if(IsListEmpty(&g_HideObjHead))
		return nLen;


	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			nOneHidderLen = sizeof(WCHAR)*(newHideObj->Namesize+1);			
			if((nLen+nOneHidderLen )>nBufLen)
				break;
			memcpy(pTemp,newHideObj->Name,nOneHidderLen-sizeof(WCHAR));
			((PWCHAR)pTemp)[nOneHidderLen/sizeof(WCHAR)-1] = L'|';
			pTemp+= nOneHidderLen;
			nLen +=	nOneHidderLen;
		}
	}

	return nLen;
}
VOID
DelHideObject(PWCHAR Name, ULONG Flag)
{
	//添加一个隐藏
	PHIDE_FILE newHideObj;
	PLIST_ENTRY pList = NULL;
	ULONG nNamesize = 0;
	nNamesize  = wcslen(Name);

	if(IsListEmpty(&g_HideObjHead))
		return ;

 
	ExAcquireResourceExclusiveLite(&g_HideEresource,TRUE);
	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			if( (Flag == newHideObj->Flag) && (nNamesize  == newHideObj->Namesize)&&_wcsnicmp(Name,newHideObj->Name,nNamesize)==0)
			{
				RemoveEntryList(pList);
				ExFreePool(newHideObj);
				break;
			}
		}
	}
	ExReleaseResourceLite(&g_HideEresource);
 
	return ;
}

VOID 
PfpSetBackUpDir(PWCHAR Path,ULONG InputLen)
{
	
	if(g_szBackupDir != NULL)
	{
		ExFreePool(g_szBackupDir);
		g_szBackupDir = NULL;
	}

	g_szBackupDir = ExAllocatePool_A(PagedPool,sizeof(WCHAR)+InputLen);

	memcpy(g_szBackupDir,Path,InputLen);
	g_szBackupDir[InputLen/sizeof(WCHAR)]=0;
	
}

VOID 
PfpGetBackUpDir(PWCHAR OutPutBuffer,ULONG OutputLen,IO_STATUS_BLOCK*IoStatus )
{
	ULONG nDirLen ;
	ULONG nIndex ;
	if(g_szBackupDir==NULL)
	{
		IoStatus->Information =0;
		IoStatus->Status = STATUS_SUCCESS;
		return ;
	}else
	{
		nIndex=1;
		nDirLen = wcslen(g_szBackupDir)*sizeof(WCHAR);
		while(g_szBackupDir[nIndex]!=L'\\' && g_szBackupDir[nIndex]!=L'\0')
		{
			nIndex++;
		}
		if(g_szBackupDir[nIndex]==L'\0')
		{
			IoStatus->Information = 0;
			IoStatus->Status = STATUS_SUCCESS;
			return ;
		}
		nIndex++;
		if(OutputLen<(nDirLen-nIndex*sizeof(WCHAR)) +sizeof(WCHAR))
		{
			nDirLen =	OutputLen-sizeof(WCHAR);
		}else
		{
			nDirLen -=nIndex*sizeof(WCHAR);
		}
		memcpy(OutPutBuffer,&g_szBackupDir[nIndex],nDirLen);
		((PWCHAR)OutPutBuffer)[nDirLen]=0;
		IoStatus->Information =nDirLen+sizeof(WCHAR);
		IoStatus->Status = STATUS_SUCCESS;
	}
}

VOID 
PfpGetRunState(PVOID OutPutBuffer,IO_STATUS_BLOCK*IoStatus )
{
	__try 
	{
		IoStatus->Information = sizeof(ULONG);
		RtlCopyMemory(OutPutBuffer, &g_nRunningState, sizeof(ULONG ));

	} 
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

		IoStatus->Status = GetExceptionCode();
		IoStatus->Information = 0;
	}
}


VOID
PfpGetHideLen(PVOID OutPutBuffer,IO_STATUS_BLOCK*IoStatus,ULONG Flag)
{
	PHIDE_FILE	newHideObj;
	PLIST_ENTRY pList = NULL;
	ULONG		Len=0;
	//KdPrint(("Delete Hide Obj:%ws", Name));

	if(IsListEmpty(&g_HideObjHead))
		return ;
	
	IoStatus->Information = sizeof(ULONG);


	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			if( (Flag == newHideObj->Flag))
			{	
				Len+=(newHideObj->Namesize+1)*sizeof(WCHAR);//每个字符串要加上一个间隔符
			}
		}
	}
	Len+=sizeof(WCHAR);//加上字符串结尾的一个空间。
	*(ULONG*)OutPutBuffer =Len;
}

VOID
PfpGetHides(PVOID OutPutBuffer,ULONG inuputLen,IO_STATUS_BLOCK*IoStatus,ULONG Flag)
{
	PHIDE_FILE	newHideObj;
	PLIST_ENTRY pList = NULL;
	ULONG		Len=0;
	PWCHAR		pTemp = NULL;
	//KdPrint(("Delete Hide Obj:%ws", Name));
	WCHAR		szMark[1]={L'|'};

	UNREFERENCED_PARAMETER(inuputLen);
	if(IsListEmpty(&g_HideObjHead))
		return ;

	//IoStatus->Information = sizeof(ULONG);

	pTemp = (PWCHAR)OutPutBuffer;
	pTemp[0]=0;
	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			if( (Flag == newHideObj->Flag))
			{	
				if(pTemp[0]==0)
				{
					wcscpy(pTemp,newHideObj->Name);
				}else
				{
					wcscat(pTemp,newHideObj->Name);
				}
				wcscat(pTemp,szMark);
			}
		}
	}
	IoStatus->Information = (wcslen(pTemp)+1)*sizeof(WCHAR);
	
}

ULONG CalcHideObjectSizeForWritingFile()
{
	ULONG nsize = 0;
	PLIST_ENTRY headListEntry	= &g_HideObjHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;

	FsRtlEnterFileSystem();

	ExAcquireResourceSharedLite(&g_HideEresource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		nsize		 += sizeof(HIDE_FILE);
	};
	
	ExReleaseResourceLite(&g_HideEresource);
	FsRtlExitFileSystem();
	return nsize;

}
VOID InitHidderFromBufferReadFromFile (PVOID pBuffer, ULONG nLen)
{
	ULONG HidderSize = sizeof(HIDE_FILE);
	PUCHAR pBufferEnd = (PUCHAR)pBuffer+ nLen;
	PHIDE_FILE	newHideObj;
	ULONG MaxNameSize = 1023*sizeof(WCHAR);
	
	while( nLen>=sizeof(HIDE_FILE) )
	{
		newHideObj = ExAllocatePoolWithTag(PagedPool, sizeof(HIDE_FILE), 'NHFO');
		
		if(newHideObj == NULL)
			break;
		
		newHideObj ->Flag = ((PHIDE_FILE)pBuffer)->Flag;
		newHideObj->nHide = ((PHIDE_FILE)pBuffer)->nHide;
		memcpy(newHideObj ->Name ,((PHIDE_FILE)pBuffer)->Name,min((((PHIDE_FILE)pBuffer)->Namesize+1),MaxNameSize)<<1);
		
		newHideObj ->Namesize = ((PHIDE_FILE)pBuffer)->Namesize;
		newHideObj ->Name[newHideObj ->Namesize ]=L'\0';
		InsertTailList(&g_HideObjHead, &newHideObj->linkfield);

		pBuffer = (PUCHAR)pBuffer+sizeof(HIDE_FILE);
		nLen-=sizeof(HIDE_FILE);
	};
}

VOID WriteHidderObjectsIntoBufferForWrittingFile (IN OUT PVOID pBuffer, IN OUT ULONG* nLen)
{
	ULONG HidderSize = sizeof(HIDE_FILE);
	PHIDE_FILE	newHideObj;
	PLIST_ENTRY pList = NULL;	
	ULONG MaxNameSize = 1024*sizeof(WCHAR);
	*nLen = 0;
	if(IsListEmpty(&g_HideObjHead))
	{		
		return ;
	}
	
	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&g_HideEresource,TRUE);

	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			((PHIDE_FILE)pBuffer)->Flag = newHideObj->Flag;
			((PHIDE_FILE)pBuffer)->nHide = newHideObj->nHide;
			memcpy(((PHIDE_FILE)pBuffer)->Name,newHideObj->Name,min((newHideObj ->Namesize+1),MaxNameSize)<<1);
			((PHIDE_FILE)pBuffer)->Namesize = min(MaxNameSize-1,newHideObj ->Namesize);
			((PHIDE_FILE)pBuffer)->Name[((PHIDE_FILE)pBuffer)->Namesize]=L'\0';
			pBuffer = (PUCHAR)pBuffer+HidderSize;
			*nLen+=HidderSize;
		}
	}
	ExReleaseResourceLite(&g_HideEresource);
	FsRtlExitFileSystem();
	
}
VOID
FsShutDown(IN PDEVICE_OBJECT DeviceObject)
{
	UNREFERENCED_PARAMETER(DeviceObject);	
	KeSetEvent(&g_ThreadEvent,IO_NO_INCREMENT, FALSE);
}





ULONG 
PfpGetNumOfHidder()
{

	PHIDE_FILE	newHideObj;
	PLIST_ENTRY pList = NULL;
	ULONG		Num=0;
	

	if(IsListEmpty(&g_HideObjHead))
		return 0;

	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			Num++;
		}
	}		
	
	return Num;

}



NTSTATUS
PfpGetHidderItemsByArray(IN PHIDDERITEM pItemArray,
						 IN OUT ULONG* pNums)
{
	PHIDE_FILE	newHideObj;
	PLIST_ENTRY pList	= NULL;
	ULONG		nIndex	= 0;
	ULONG		MaxNameSize = sizeof(WCHAR)*1024;
	if(pItemArray==  NULL ||pNums== NULL ||*pNums==0)
		return STATUS_INVALID_PARAMETER;
	
	for(pList = g_HideObjHead.Blink ; pList !=&g_HideObjHead;pList= pList->Blink)
	{
		newHideObj = CONTAINING_RECORD(pList,HIDE_FILE,linkfield) ;
		if(newHideObj )
		{
			pItemArray[nIndex].bDir = ((newHideObj->Flag==CDO_FLAG_DIRECTORY)?1:0);
			pItemArray[nIndex].nHide =newHideObj->nHide; 
			memcpy(pItemArray[nIndex].szFullPath,newHideObj->Name,MaxNameSize);
			nIndex++;
			if(nIndex== *pNums)
				break;						
		}
	}
	*pNums = nIndex;
	return STATUS_SUCCESS;
}


NTSTATUS 
PfpSetHideItemState(IN PHIDDERITEM pItem)
{
	PLIST_ENTRY headListEntry	= &g_HideObjHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PHIDE_FILE	tmpHideFile		= NULL;
	PFOLDERPROTECTITEM tmpFolderItem = NULL;
	LONG		HideObjectLength = 0;
	ULONG ObjFlag = pItem->bDir?CDO_FLAG_DIRECTORY:CDO_FLAG_FILE;
	ULONG		nLen = wcslen(pItem->szFullPath);
	NTSTATUS	nStatus = STATUS_INVALID_PARAMETER;
	//KdPrint(("compare %ws \n",Name));
	if (IsListEmpty(&g_HideObjHead))
	{
		return STATUS_SUCCESS;
	}
 
	//判断 隐藏的设置
	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&g_HideEresource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpHideFile			= (PHIDE_FILE)CONTAINING_RECORD(tmpListEntry, HIDE_FILE, linkfield);
		HideObjectLength	= tmpHideFile->Namesize;

		if(tmpHideFile->Flag== CDO_FLAG_DIRECTORY)
		{
			if((ULONG)HideObjectLength ==nLen  && _wcsnicmp(tmpHideFile->Name,pItem->szFullPath,nLen)==0)
			{
				tmpHideFile->nHide = pItem->nHide;
				nStatus = STATUS_SUCCESS;
				break;
			}
		}else
		{
			if(ObjFlag==CDO_FLAG_FILE &&  HideObjectLength ==nLen &&_wcsnicmp(tmpHideFile->Name,pItem->szFullPath,nLen)==0)
			{
				
				tmpHideFile->nHide = pItem->nHide;
				nStatus = STATUS_SUCCESS;
				break;
			}
		}
	}
	ExReleaseResourceLite(&g_HideEresource);
	FsRtlExitFileSystem();
	
	return nStatus;
}
NTSTATUS
PfpAddHidderItem(IN PHIDDERITEM pItemArray,
				 IN OUT ULONG*  pNums)
{
	ULONG nIndex = 0;
	PHIDE_FILE	newHideObj = NULL;  
	if(pItemArray== NULL ||pNums == NULL||*pNums == 0)
		return STATUS_INVALID_PARAMETER;


	 
	ExAcquireResourceExclusiveLite(&g_HideEresource,TRUE);
	for(nIndex =0;nIndex<*pNums;++nIndex)
	{
		newHideObj  = ExAllocatePool_A(PagedPool,sizeof(HIDE_FILE));
		newHideObj->Flag = pItemArray[nIndex].bDir;
		newHideObj->nHide = pItemArray[nIndex].nHide;
		memcpy(newHideObj->Name, pItemArray[nIndex].szFullPath,1024*sizeof(WCHAR));	
		newHideObj->Namesize = wcslen(newHideObj->Name);
		InsertTailList(&g_HideObjHead, &newHideObj->linkfield);		
	}
	ExReleaseResourceLite(&g_HideEresource);
	 
	return STATUS_SUCCESS;
}



BOOLEAN 
PfpIsDirParentOfHide(PWCHAR szDirFullPath,ULONG nLen)
{

	PLIST_ENTRY headListEntry	= &g_HideObjHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PHIDE_FILE	tmpHideFile		= NULL;

	LONG		HideObjectLength = 0;
	BOOLEAN		bItIs	= FALSE;

	ASSERT(szDirFullPath!= NULL && nLen!= 0);

	if (IsListEmpty(&g_HideObjHead))
	{
		return FALSE;
	}


	//判断 隐藏的设置
 
	ExAcquireResourceSharedLite(&g_HideEresource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpHideFile			= (PHIDE_FILE)CONTAINING_RECORD(tmpListEntry, HIDE_FILE, linkfield);
		HideObjectLength	= wcslen(tmpHideFile->Name);

		if((ULONG)HideObjectLength >= (nLen>>1) )
		{
			if(0==_wcsnicmp(szDirFullPath, tmpHideFile->Name,nLen>>1))
			{
				bItIs = TRUE;
				break;
			}
		}
	}
	ExReleaseResourceLite(&g_HideEresource);
 
	return bItIs;
}
BOOLEAN 
PfpIsDirParentOfSecureFolder(PWCHAR szDirFullPath,ULONG nLen)
{
	PLIST_ENTRY headListEntry	= &g_HideObjHead;
	PLIST_ENTRY tmpListEntry	= headListEntry;
	PFOLDERPROTECTITEM		tmpFolderItem = NULL;
	LONG		HideObjectLength = 0;
	BOOLEAN		bItIs			= FALSE;

	ASSERT(szDirFullPath!= NULL && nLen!= 0);

	headListEntry= &g_FolderProtectList;
	tmpListEntry = headListEntry;

	ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry		= tmpListEntry->Flink;
		tmpFolderItem		= (PFOLDERPROTECTITEM)CONTAINING_RECORD(tmpListEntry, FOLDERPROTECTITEM, list);
		HideObjectLength	= tmpFolderItem->szFullPathSize;


		if((ULONG)HideObjectLength < (nLen>>1) )
		{
			continue;			
		}
		if(0==_wcsnicmp(szDirFullPath, tmpFolderItem->szFullPath,(nLen>>1)))
		{
			bItIs = TRUE;
			break;
		}
	}
	ExReleaseResourceLite(&g_FolderResource);
	return bItIs;
}