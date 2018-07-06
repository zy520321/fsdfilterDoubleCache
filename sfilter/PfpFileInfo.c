#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "UsbSecure.h"
NTSTATUS
PfpQueryInformation (               //  implemented in FileInfo.c
					 IN PDEVICE_OBJECT VolumeDeviceObject,
					 IN PIRP Irp
					 )
{
	TOP_LEVEL_CONTEXT	TopLevelContext;
	PTOP_LEVEL_CONTEXT	ThreadTopLevelContext;	
	PDEVICE_OBJECT		pNextDevice;
	PDISKFILEOBJECT     pDiskFileObjs;

	PFILESPY_DEVICE_EXTENSION pDeviceExt;
	NTSTATUS			Status				= STATUS_SUCCESS;
	PIRP_CONTEXT		IrpContext			= NULL;	
	PFILE_OBJECT		pFileObject_Disk	= NULL;
	PFILE_OBJECT		pFileObject;
	PPfpFCB				pFcb;

	//
	//  Call the common query Information routine
	//
	if ( VolumeDeviceObject == gControlDeviceObject ) 
	{
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_DISK_INCREMENT );

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	pDeviceExt	= ((PDEVICE_OBJECT)VolumeDeviceObject)->DeviceExtension;
	pNextDevice = pDeviceExt ->NLExtHeader.AttachedToDeviceObject;
	pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	 

	FsRtlEnterFileSystem();

	//
	//Check to see if the irp is coming form shadowdevice.
	//
	if( pDeviceExt->bShadow )
	{
		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)(pDeviceExt->pRealDevice->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
		goto BYPASS;
	}
	
	//
	// Check to see if the fileobject of current irp is recorded by us
	//

	
	
	if(!PfpFileObjectHasOurFCB(pFileObject))
		goto BYPASS;
	
	pFcb = (PPfpFCB)pFileObject->FsContext;

	ASSERT(pFcb->pDiskFileObject);
	pDiskFileObjs = pFcb->pDiskFileObject;
	
	if(pDiskFileObjs->pDiskFileObjectWriteThrough== NULL)
	{
		FsRtlExitFileSystem();
		PfpCompleteRequest( NULL, &Irp, STATUS_INVALID_HANDLE );
		return STATUS_INVALID_HANDLE;
	}

	
	ThreadTopLevelContext = PfpSetTopLevelIrp( &TopLevelContext, FALSE, FALSE );

	__try 
	{

		//
		//  We are either initiating this request or retrying it.
		//

		if (IrpContext == NULL) 
		{
			IrpContext = PfpCreateIrpContext( Irp, CanFsdWait( Irp ) );
			PfpUpdateIrpContextWithTopLevel( IrpContext, ThreadTopLevelContext );
		}
		
		//
		//Fill these fields to be used in subroutine.
		//

		IrpContext->pNextDevice			= pNextDevice;
		IrpContext->Fileobject_onDisk	= pDiskFileObjs->pDiskFileObjectWriteThrough;//在IrpContext里面设置真正的磁盘文件的Fileobject 
		IrpContext->OriginatingIrp		= Irp;

		VirtualizerStart();
		Status = PfpCommonQueryInformation( IrpContext, Irp );
		VirtualizerEnd();

	}
	__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() )) 
	{

		//
		//  We had some trouble trying to perform the requested
		//  operation, so we'll abort the I/O request with
		//  the error status that we get back from the
		//  execption code
		//

		Status = PfpProcessException( IrpContext, Irp, GetExceptionCode() );
	}

	if (ThreadTopLevelContext == &TopLevelContext) 
	{
		PfpRestoreTopLevelIrp( ThreadTopLevelContext );
	}

	FsRtlExitFileSystem();
	
	return Status;

BYPASS:
 
	FsRtlExitFileSystem();

	IoSkipCurrentIrpStackLocation(Irp);
	Status = IoCallDriver(pNextDevice,Irp);
	
	return Status;
}

NTSTATUS
PfpSetInformation (                 //  implemented in FileInfo.c
				   IN PDEVICE_OBJECT VolumeDeviceObject,
				   IN PIRP Irp
				   )
{
	TOP_LEVEL_CONTEXT	TopLevelContext;
	PTOP_LEVEL_CONTEXT	ThreadTopLevelContext;
	NTSTATUS			ExceptionCode;
	PIO_STACK_LOCATION	IrpSpExcept;
	PDEVICE_OBJECT		pNextDevice;
	PDISKFILEOBJECT     pDiskFileObjs;
	NTSTATUS			Status = STATUS_SUCCESS;
	PIRP_CONTEXT		IrpContext = NULL;
	ULONG				LogFileFullCount = 0;
	PIO_STACK_LOCATION	psp;	
	PFILESPY_DEVICE_EXTENSION pDeviceExt;
	
	PFILE_OBJECT		pFileObject_Disk	= NULL;
	PFILE_OBJECT		pFileObject;
	PPfpFCB				pFcb;
	

	PDISKDIROBEJECT		pVirtualParentDir = NULL;
	PDISKDIROBEJECT		pRootVirtualDir   = NULL;

	BOOLEAN				bFileRename = FALSE;
	BOOLEAN				bDirReanme  = FALSE;
	BOOLEAN				bReNameSourceInSecureFolder = FALSE;
	PWCHAR				bFullPathWithDeviceLetterofSourceDirInRename= NULL;
	//
	//  Call the common set Information routine
	//
//
	// Check to see if the fileobject of current irp is recorded by us
	//
	pDeviceExt	= ((PDEVICE_OBJECT)VolumeDeviceObject)->DeviceExtension;
	pNextDevice = pDeviceExt ->NLExtHeader.AttachedToDeviceObject;
	pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	psp			= IoGetCurrentIrpStackLocation(Irp);
 
	FsRtlEnterFileSystem();
	
	//
	//Check to see if the irp is coming form shadowdevice.
	//
	if( pDeviceExt->bShadow )
	{
		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)(pDeviceExt->pRealDevice->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
		goto BYPASS;
	}
	//保护程序本身不被 恶意的删除掉
	if(g_bProtectSySself && (psp->Parameters.SetFile.FileInformationClass == FileDispositionInformation||
		psp->Parameters.SetFile.FileInformationClass ==FileRenameInformation))
	{
		if(PfpIsFileSysProtected(&pFileObject->FileName))
		{
			FsRtlExitFileSystem();
			PfpCompleteRequest( NULL, &Irp, STATUS_ACCESS_DENIED );
			return STATUS_ACCESS_DENIED;
		}
		
	}
	if(!PfpFileObjectHasOurFCB(pFileObject))
	{	
		WCHAR						szDeviceLetter[3] ={0};
		
		if(IoGetTopLevelIrp()!= NULL)
			goto SUBEXIT;
		
		PfpGetDeviceLetter(VolumeDeviceObject,szDeviceLetter);
		if(psp->Parameters.SetFile.FileInformationClass == FileDispositionInformation)
		{
			PWCHAR						pDirFullPath   = NULL;
			ULONG						nLenDirFull		= 0;
			
			if(((PFILE_DISPOSITION_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->DeleteFile )
			{ 
				PDISKDIROBEJECT				pVirtualRootDir= NULL;
				PERESOURCE					pDeviceResouce = NULL;
				UNICODE_STRING				FileFullPathDelete;
				LONG						nFolder_File_UnknowYet =0;//1 文件夹 2 文件！0就是没有设置
				pVirtualRootDir = PfpGetVirtualRootDirFromSpyDevice(VolumeDeviceObject);
				if( pFileObject->FsContext== NULL )
				{					
					goto DELEXIT;
				}
				if(NT_SUCCESS(PfpQueryForLongName(pFileObject->FileName.Buffer,pFileObject->FileName.Length/sizeof(WCHAR),(PDEVICE_OBJECT)VolumeDeviceObject,&pDirFullPath)))
				{
					nLenDirFull = wcslen(pDirFullPath)*sizeof(WCHAR);
				}else
				{
					if(pFileObject->FileName.Length==pFileObject->FileName.MaximumLength)
					{
						pDirFullPath = ExAllocatePoolWithTag(PagedPool,(nLenDirFull=pFileObject->FileName.Length)+2,'0007');
						memcpy(pDirFullPath,pFileObject->FileName.Buffer,pFileObject->FileName.Length);
						pDirFullPath[pFileObject->FileName.Length>>1]=L'\0';
					}else
					{
						nLenDirFull = pFileObject->FileName.Length;
						pDirFullPath = pFileObject->FileName.Buffer;
						pDirFullPath [nLenDirFull>>1]=L'\0';
					}	
				}
				 
				FileFullPathDelete.Buffer = pDirFullPath;
				FileFullPathDelete.Length = (USHORT)nLenDirFull;
				FileFullPathDelete.MaximumLength = (USHORT)nLenDirFull+2;

				if(IsFileDirectroy(pFileObject->FileName.Buffer,pFileObject->FileName.Length/sizeof(WCHAR),(PDEVICE_OBJECT)VolumeDeviceObject))
				{
					PDISKDIROBEJECT				pVirtualDir= NULL;
					ULONG						nLenDirFullWithLetter = nLenDirFull+(2<<1) ;
					PWCHAR						pDirPathWithDeviceLetter = ExAllocatePoolWithTag(PagedPool, nLenDirFullWithLetter+2,'1007');
					if(pDirPathWithDeviceLetter )
					{
						memcpy(pDirPathWithDeviceLetter,szDeviceLetter,4);
						memcpy(&pDirPathWithDeviceLetter[2],pDirFullPath,nLenDirFull);
						pDirPathWithDeviceLetter[(nLenDirFullWithLetter>>1)] =L'\0';
						if(PfpIsDirParentOfSecureFolder(pDirPathWithDeviceLetter,nLenDirFullWithLetter)||PfpIsDirParentOfHide(pDirPathWithDeviceLetter,nLenDirFullWithLetter))
						{
							ExFreePool_A(pDirPathWithDeviceLetter);
							if(pDirFullPath!=  pFileObject->FileName.Buffer)
							{
								ExFreePool_A(pDirFullPath);
							}
							FsRtlExitFileSystem();
							PfpCompleteRequest( NULL, &Irp, STATUS_ACCESS_DENIED );
							return STATUS_ACCESS_DENIED;
						}
						ExFreePool_A(pDirPathWithDeviceLetter);
					}

					//因为这个目录要删除 ，所以要删除 这个目录下面 所有我们已经打开的并且已经全部被usermode app 关闭的 文件
					ASSERT(pVirtualRootDir);
					 
					ExAcquireResourceSharedLite( pVirtualRootDir->AccssLocker,TRUE);
					pVirtualDir = PfpGetDiskDirObject(pVirtualRootDir,pDirFullPath,nLenDirFull);
					
					if(pVirtualDir )
					{
						PfpCloseDiskFilesUnderVirtualDirHasGoneThroughCleanUp(pVirtualRootDir,pVirtualDir);	
					}
					ExReleaseResourceLite(pVirtualRootDir->AccssLocker);

					
				}else //因为这个文件要删除，所以要看我们有没有打开过这个文件，并且这个文件全部被关闭！
				{
					PDISKDIROBEJECT				pVirtualDir= NULL;
					PDISKFILEOBJECT				pDiskFileObject = NULL;
					BOOLEAN						bComplete = FALSE;
					PWCHAR						pszRemainer = NULL;
					PVIRTUALDISKFILE			pVirtualDiskFile = NULL;	
					ASSERT(pVirtualRootDir);
					
					ExAcquireResourceSharedLite( pVirtualRootDir->AccssLocker,TRUE);
					pDeviceResouce  = pVirtualRootDir->AccssLocker;
					pVirtualDir = PfpPareseToDirObject(pVirtualRootDir,pDirFullPath,&pszRemainer ,&bComplete);
					
					 
					if(bComplete)
					{
						UNICODE_STRING TempString;
						TempString.Buffer = pszRemainer;
						TempString.Length = (wcslen(pszRemainer)<<1);
						TempString.MaximumLength  = 2+TempString.Length ;
						
						pVirtualDiskFile =PfpFindVirtualDiskFileObjectInParent(pVirtualDir,&TempString);
						 
						if(pVirtualDiskFile)
						{
							pDiskFileObject= PpfGetDiskFileObjectFromVirtualDisk(pVirtualDiskFile);							 
						}
						if(pDiskFileObject )
						{
							ExAcquireResourceExclusiveLite(pVirtualDiskFile->pVirtualDiskLocker,TRUE);
							PfpCloseDiskFileObjectHasGoneThroughCleanUp(pDiskFileObject );			
							ExReleaseResourceLite(pVirtualDiskFile->pVirtualDiskLocker);
						}
					}
					if(pDeviceResouce)
					{
						ExReleaseResourceLite(pDeviceResouce);
						pDeviceResouce = NULL;
					}
					
				}
				if(pDirFullPath!=  pFileObject->FileName.Buffer)
				{
					ExFreePool_A(pDirFullPath);
				}
DELEXIT:
				;
			}

		}else if(psp->Parameters.SetFile.FileInformationClass == FileRenameInformation)
		{
			//不能让个人文件安全夹外面的文件 通过 rename的方式 放到里面去
			FILE_RENAME_INFORMATION *pRenameInfo = NULL		;
			LONG			nIndex				 =-1;
			WCHAR*			pFileExt			= NULL;
			WCHAR*			pDestFilePath		= NULL;	
			BOOLEAN			bFolderUnderProtect = FALSE;
			PROTECTTYPE		ProtectTypeForFolder= FALSE;
			BOOLEAN			bEncryptForFolder	= FALSE;
			BOOLEAN			bBackupForFolder	= FALSE;
			BOOLEAN			bFolderLocked		= FALSE;
			ULONG			bEncryptFileTypeForFolder	= ENCRYPT_NONE;
			WCHAR *			pFullPathOrigFile	= NULL;
			PWCHAR			pDirFullPath		= NULL;
			ULONG			nLenDirFull			= 0;
			BOOLEAN			bDirOperation		= FALSE;
			ULONG			nLenDirFullWithLetter = 0;
			PWCHAR			pDirPathWithDeviceLetter =  NULL;
			if( bDirOperation=IsFileDirectroy(pFileObject->FileName.Buffer,pFileObject->FileName.Length/sizeof(WCHAR),(PDEVICE_OBJECT)VolumeDeviceObject))
			{
				PDISKDIROBEJECT				pVirtualRootDir= NULL;
				PERESOURCE					pDeviceResouce = NULL;
				PDISKDIROBEJECT				pVirtualDir= NULL;
				PDISKFILEOBJECT				pDiskFileObject =NULL;
				UNICODE_STRING				FileFullPathRename;
				pVirtualRootDir = PfpGetVirtualRootDirFromSpyDevice(VolumeDeviceObject);
				if( pFileObject->FsContext== NULL )
				{					
					goto RENAMEEXIT;
				}
				if(NT_SUCCESS(PfpQueryForLongName(pFileObject->FileName.Buffer,pFileObject->FileName.Length/sizeof(WCHAR),(PDEVICE_OBJECT)VolumeDeviceObject,&pDirFullPath)))
				{
					nLenDirFull = wcslen(pDirFullPath)*sizeof(WCHAR);
				}else
				{
					if(pFileObject->FileName.Length==pFileObject->FileName.MaximumLength)
					{
						pDirFullPath = ExAllocatePoolWithTag(PagedPool,(nLenDirFull=pFileObject->FileName.Length)+2,'2007');
						memcpy(pDirFullPath,pFileObject->FileName.Buffer,pFileObject->FileName.Length);
						pDirFullPath[pFileObject->FileName.Length>>1]=L'\0';
					}else
					{
						nLenDirFull = pFileObject->FileName.Length;
						pDirFullPath = pFileObject->FileName.Buffer;
						pDirFullPath [nLenDirFull>>1]=L'\0';
					}	
				}
				FileFullPathRename.Buffer = pDirFullPath;
				FileFullPathRename.Length = (USHORT)nLenDirFull;
				FileFullPathRename.MaximumLength = (USHORT)nLenDirFull+2;
							
				nLenDirFullWithLetter = nLenDirFull+(2<<1) ;
				pDirPathWithDeviceLetter = ExAllocatePoolWithTag(PagedPool, nLenDirFullWithLetter+2,'3007');
				if(pDirPathWithDeviceLetter )
				{
					memcpy(pDirPathWithDeviceLetter,szDeviceLetter,4);
					memcpy(&pDirPathWithDeviceLetter[2],pDirFullPath,nLenDirFull);
					pDirPathWithDeviceLetter[(nLenDirFullWithLetter>>1)] =L'\0';
					if(PfpIsDirParentOfSecureFolder(pDirPathWithDeviceLetter,nLenDirFullWithLetter)||PfpIsDirParentOfHide(pDirPathWithDeviceLetter,nLenDirFullWithLetter))
					{
						//bDirReanme = TRUE;
						ExFreePool_A(pDirPathWithDeviceLetter);
						if(pDirFullPath!=  pFileObject->FileName.Buffer)
						{
							ExFreePool_A(pDirFullPath);
						}
						FsRtlExitFileSystem();
						PfpCompleteRequest( NULL, &Irp, STATUS_ACCESS_DENIED );
						return STATUS_ACCESS_DENIED;
					}					
				}
				
				ASSERT(pVirtualRootDir);
				
				ExAcquireResourceSharedLite( pVirtualRootDir->AccssLocker,TRUE);
				pVirtualDir = PfpGetDiskDirObject(pVirtualRootDir,pDirFullPath,nLenDirFull);
				
				if(pVirtualDir )
				{
					PfpCloseDiskFilesUnderVirtualDirHasGoneThroughCleanUp(pVirtualRootDir,pVirtualDir);
				} 
				ExReleaseResourceLite(pVirtualRootDir->AccssLocker);
				if(pDirFullPath!=  pFileObject->FileName.Buffer)
				{
					ExFreePool_A(pDirFullPath);
				}
				
			}
							 
			pRenameInfo		= ((FILE_RENAME_INFORMATION*)Irp->AssociatedIrp.SystemBuffer);
			
			if(pRenameInfo->RootDirectory)//有相对文件夹的时候
			{
				WCHAR *szFullPathofParent  = NULL;
				LONG   lParentLen		   = 0;
				WCHAR  szDriverLetter   [3]= {0};
				PFILE_OBJECT			pDirFileObject = NULL;
				NTSTATUS				ntstatus ;		
				if(!NT_SUCCESS(ntstatus = ObReferenceObjectByHandle(pRenameInfo->RootDirectory,
													0,
													*IoFileObjectType,
													KernelMode,
													&pDirFileObject,
													NULL)))
				{
					if(pDirPathWithDeviceLetter)
					{	
						ExFreePool_A(pDirPathWithDeviceLetter);
					}
					FsRtlExitFileSystem();
					PfpCompleteRequest( NULL, &Irp, ntstatus );
					return ntstatus;
				}

				if(NT_SUCCESS(PfpGetFullPathForFileObject(pDirFileObject,&szFullPathofParent,&lParentLen,pNextDevice)))
				{
					if(PfpGetDeviceLetter(VolumeDeviceObject,szDriverLetter))
					{
						bFolderUnderProtect = GetFolderProtectProperty( szDriverLetter ,
																		szFullPathofParent,
																		lParentLen,
																		&ProtectTypeForFolder,
																		&bEncryptForFolder,
																		&bBackupForFolder,
																		&bFolderLocked,
																		&bEncryptFileTypeForFolder);
						
						if(bFolderUnderProtect && (bEncryptFileTypeForFolder!= ENCRYPT_NONE))
						{
							if(bDirOperation)
							{
								bDirReanme = TRUE;
							}else
							{
								if(ENCRYPT_TYPES!=bEncryptFileTypeForFolder)
								{
									bFileRename = TRUE;
								}else
								{
									if(pRenameInfo&& pRenameInfo->FileNameLength!=0)
									{
										PWCHAR pszExt =NULL;
										LONG nIndexExt = (pRenameInfo->FileNameLength>>1)-1;
										BOOLEAN bFoundExt = FALSE;
										while(nIndexExt >=0)
										{
											if(pRenameInfo->FileName[nIndexExt]==L'\\')
											{
												break;
											}
											if(pRenameInfo->FileName[nIndexExt]==L'.')
											{
												bFoundExt = TRUE;
												break;
											}
											nIndexExt--;
										};
										if(bFoundExt)
										{
											pszExt = ExAllocatePoolWithTag(PagedPool,pRenameInfo->FileNameLength-(nIndexExt<<1),'2002');
											if(pszExt )
											{
												nIndexExt++;
												memcpy(pszExt,&pRenameInfo->FileName[nIndexExt],pRenameInfo->FileNameLength-(nIndexExt<<1));
												pszExt[(pRenameInfo->FileNameLength>>1)-nIndexExt]=L'\0';
												bFileRename=IsFileTypeEncryptForFolder(szDeviceLetter ,szFullPathofParent,lParentLen,pszExt);
												ExFreePool(pszExt);
											}
											
										}

									}
								}
							}								
						}
					}					
				}
				if(bDirOperation && pDirPathWithDeviceLetter )
				{
					 
					
					bFolderUnderProtect = GetFolderProtectProperty( szDeviceLetter ,
																	&pDirPathWithDeviceLetter[2],
																	wcslen(&pDirPathWithDeviceLetter[2])<<1,
																	&ProtectTypeForFolder,
																	&bEncryptForFolder,
																	&bBackupForFolder,
																	&bFolderLocked,
																	&bEncryptFileTypeForFolder);
					if(bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))
					{
						bFullPathWithDeviceLetterofSourceDirInRename = pDirPathWithDeviceLetter;// store this value into another varible
						pDirPathWithDeviceLetter = NULL;
						bReNameSourceInSecureFolder = TRUE;
					}
				}
				ObDereferenceObject(pDirFileObject);
				if(szFullPathofParent) ExFreePool(szFullPathofParent);
			}else //绝对路径的情况下
			{
				WCHAR szNameSpace[]    =L"\\??\\";
				WCHAR szNameSpace1[]   =L"\\DosDevices\\";
				WCHAR szDriverLetter[3]={0};
				LONG  nIndex		   = 0;
				ULONG  LenName		   = wcslen(szNameSpace);
				ULONG  LenName1		   = wcslen(szNameSpace1);
				
				pDestFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)+pRenameInfo->FileNameLength,'4007');	
				if(pDestFilePath == NULL)
				{
					goto RENAMEEXIT;
				}
				RtlCopyMemory((PUCHAR)pDestFilePath,(PUCHAR)pRenameInfo->FileName,pRenameInfo->FileNameLength);
				pDestFilePath[pRenameInfo->FileNameLength/sizeof(WCHAR)] =0;

				if(pRenameInfo->FileNameLength/sizeof(WCHAR)>LenName||pRenameInfo->FileNameLength/sizeof(WCHAR)>LenName1)
				{
					if(pRenameInfo->FileNameLength/sizeof(WCHAR)>LenName)
					{
						if(_wcsnicmp(pDestFilePath,szNameSpace,LenName)==0)
						{
							RtlMoveMemory(pDestFilePath,&pDestFilePath[LenName],sizeof(WCHAR)*(pRenameInfo->FileNameLength/sizeof(WCHAR)-LenName));
							pDestFilePath[pRenameInfo->FileNameLength/sizeof(WCHAR)-LenName]=L'\0';									
							goto CHECKEDIR;
						}
						if(pRenameInfo->FileNameLength/sizeof(WCHAR) >LenName1  && _wcsnicmp(pDestFilePath,szNameSpace1,LenName1)==0)
						{
							RtlMoveMemory(pDestFilePath,&pDestFilePath[LenName1],sizeof(WCHAR)*(pRenameInfo->FileNameLength/sizeof(WCHAR)-LenName1));
							pDestFilePath[pRenameInfo->FileNameLength/sizeof(WCHAR)-LenName1]=L'\0';
							// 这里的得到父文件夹的路径		
							goto CHECKEDIR;
						}

						if(pDestFilePath)ExFreePool_A(pDestFilePath);
						goto RENAMEEXIT;
				
CHECKEDIR:
						nIndex =  wcslen(pDestFilePath)-1;
						while(nIndex>=0 && pDestFilePath[nIndex]!=L'\\') nIndex--;

						if(nIndex>0) 
						{
							pDestFilePath[nIndex ]=0;

							memcpy(szDriverLetter,pDestFilePath,2*sizeof(WCHAR));
							nIndex = wcslen(pDestFilePath);
							bFolderUnderProtect = GetFolderProtectProperty(szDriverLetter ,
																			&pDestFilePath[2],
																			nIndex-2,
																			&ProtectTypeForFolder,
																			&bEncryptForFolder,
																			&bBackupForFolder,
																			&bFolderLocked,
																			&bEncryptFileTypeForFolder);
							
							if(bFolderUnderProtect && (bEncryptFileTypeForFolder!= ENCRYPT_NONE) )
							{					
								if(bDirOperation)
								{
									bDirReanme = TRUE;
								}else
								{
									if(ENCRYPT_TYPES!=bEncryptFileTypeForFolder)
									{
										bFileRename = TRUE;
									}else
									{
										if(pRenameInfo&& pRenameInfo->FileNameLength!=0)
										{
											PWCHAR pszExt =NULL;
											LONG nIndexExt = (pRenameInfo->FileNameLength>>1)-1;
											BOOLEAN bFoundExt = FALSE;
											while(nIndexExt >=0)
											{
												if(pRenameInfo->FileName[nIndexExt]==L'\\')
												{
													break;
												}
												if(pRenameInfo->FileName[nIndexExt]==L'.')
												{
													bFoundExt = TRUE;
													break;
												}
												nIndexExt--;
											};
											if(bFoundExt)
											{
												pszExt = ExAllocatePoolWithTag(PagedPool,pRenameInfo->FileNameLength-(nIndexExt<<1),'2002');
												if(pszExt )
												{
													nIndexExt++;
													memcpy(pszExt,&pRenameInfo->FileName[nIndexExt],pRenameInfo->FileNameLength-(nIndexExt<<1));
													pszExt[(pRenameInfo->FileNameLength>>1)-nIndexExt]=L'\0';
													bFileRename=IsFileTypeEncryptForFolder(szDeviceLetter ,&pDestFilePath[2],nIndex-2,pszExt);
													ExFreePool(pszExt);
												}

											}

										}
									}
								}
							}
						}	
						if(bDirOperation && pDirPathWithDeviceLetter )
						{
							 

							bFolderUnderProtect = GetFolderProtectProperty( szDeviceLetter ,
								&pDirPathWithDeviceLetter[2],
								wcslen(&pDirPathWithDeviceLetter[2])<<1,
								&ProtectTypeForFolder,
								&bEncryptForFolder,
								&bBackupForFolder,
								&bFolderLocked,
								&bEncryptFileTypeForFolder);
							if(bFolderUnderProtect&& (bEncryptFileTypeForFolder!= ENCRYPT_NONE))
							{
								bFullPathWithDeviceLetterofSourceDirInRename = pDirPathWithDeviceLetter;// store this value into another varible
								pDirPathWithDeviceLetter = NULL;
								bReNameSourceInSecureFolder = TRUE;
							}
						}
						 
					}					 
				} 
				if(pDestFilePath)ExFreePool_A(pDestFilePath);
			}			
RENAMEEXIT:
			if(pDirPathWithDeviceLetter)
			{
				ExFreePool_A(pDirPathWithDeviceLetter);
			}
		}

SUBEXIT:		
		goto BYPASS;
	}

	pFcb = (PPfpFCB)pFileObject->FsContext;
	ASSERT(pFcb->pDiskFileObject);
 
	if((pDiskFileObjs = pFcb->pDiskFileObject)== NULL|| pDiskFileObjs->pDiskFileObjectWriteThrough== NULL)
	{
		FsRtlExitFileSystem();
		PfpCompleteRequest( NULL, &Irp, STATUS_INVALID_HANDLE );
		return STATUS_INVALID_HANDLE;
	}
	 
	
	ThreadTopLevelContext = PfpSetTopLevelIrp( &TopLevelContext, FALSE, FALSE );

	
	__try {

		//
		//  We are either initiating this request or retrying it.
		//

		if (IrpContext == NULL)
		{
			IrpContext = PfpCreateIrpContext( Irp, CanFsdWait( Irp ) );
			PfpUpdateIrpContextWithTopLevel( IrpContext, ThreadTopLevelContext );
		} 		
	
		IrpContext->pNextDevice			= pNextDevice;
		IrpContext->Fileobject_onDisk	= pDiskFileObjs->pDiskFileObjectWriteThrough;
		IrpContext->OriginatingIrp		= Irp;
		IrpContext->RealDevice			= VolumeDeviceObject;
		VirtualizerStart();
		
		Status = PfpCommonSetInformation( IrpContext, Irp );

		VirtualizerEnd();
		

	} 
	__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() ))
	{

		IrpSpExcept = IoGetCurrentIrpStackLocation( Irp );

		ExceptionCode = GetExceptionCode();

		if ((ExceptionCode == STATUS_FILE_DELETED) &&
			(IrpSpExcept->Parameters.SetFile.FileInformationClass == FileEndOfFileInformation)) 
		{

			IrpContext->ExceptionStatus = ExceptionCode = STATUS_SUCCESS;
		}

		Status = PfpProcessException( IrpContext, Irp, ExceptionCode );
	}

	if (ThreadTopLevelContext == &TopLevelContext) 
	{
		PfpRestoreTopLevelIrp( ThreadTopLevelContext );
	}
	
	FsRtlExitFileSystem();

	return Status;

BYPASS:
 
	
	IoSkipCurrentIrpStackLocation(Irp);	
	Status = IoCallDriver(pNextDevice,Irp);
	
	if( NT_SUCCESS(Status))
	{
		if(bFileRename )
		{
			PfpEncryptFile(pFileObject,pNextDevice);
		}else
		{
			if(bReNameSourceInSecureFolder && !bDirReanme )//dencrypt
			{
				PfpEnOrDecryptDir(pFileObject,pDeviceExt->pShadowDevice,pNextDevice,VolumeDeviceObject,FALSE,bFullPathWithDeviceLetterofSourceDirInRename);
			}
			if(!bReNameSourceInSecureFolder&& bDirReanme )
			{
				PfpEnOrDecryptDir(pFileObject,pDeviceExt->pShadowDevice,pNextDevice,VolumeDeviceObject,TRUE,NULL);
			}
		}
		
	}
	if(bFullPathWithDeviceLetterofSourceDirInRename)
	{
		ExFreePool_A(bFullPathWithDeviceLetterofSourceDirInRename);
	}
	FsRtlExitFileSystem();
	return Status;
}
void PfpDecryptFile(PFILE_OBJECT pFileObject,PDEVICE_OBJECT pTargetDevice)
{
	PUCHAR pBuffer = NULL;
	LONG BufLen	= ENCRYPTIONHEADLENGTH;
	NTSTATUS ntstatus;		
	 
	IO_STATUS_BLOCK iostatusread;
	
	PVOID pEncryptHead = NULL;

	pBuffer  = ExAllocatePoolWithTag(PagedPool,(BufLen= sizeof( FILE_STANDARD_INFORMATION)),'9007');		
	if(pBuffer== NULL)
	{
		goto EXIT;
	}

	ntstatus = PfpQueryFileInforByIrp(pFileObject,(PUCHAR)pBuffer,BufLen,FileStandardInformation,pTargetDevice);

	if(!NT_SUCCESS(ntstatus) && ntstatus!=STATUS_BUFFER_OVERFLOW )
	{		 						
		goto EXIT;
	}
	if(((FILE_STANDARD_INFORMATION*)pBuffer)->EndOfFile.QuadPart<=ENCRYPTIONHEADLENGTH)
	{
		goto EXIT;
	}
	pEncryptHead =(PPfpFCB) ExAllocatePoolWithTag(PagedPool,ENCRYPTIONHEADLENGTH,'NOO4');
	if(pEncryptHead== NULL)
	{
		goto EXIT;		 
	}
	ntstatus = PfpReadHeadForEncryption(pEncryptHead,
										ENCRYPTIONHEADLENGTH,
										pFileObject,
										pTargetDevice,
										&iostatusread
										);
	if(!NT_SUCCESS(ntstatus)||iostatusread.Information!= ENCRYPTIONHEADLENGTH)
	{
		goto EXIT;
	}
	if(!PfpCheckEncryptInfo(pEncryptHead,ENCRYPTIONHEADLENGTH))
	{	
		goto EXIT;
	}
	/*	try
	{
	if(CcIsFileCached(pFileObject))
	{

	CcFlushCache( &pFileObject->, NULL, 0, &iostatusread );		
	}
	}*/

	//except(EXCEPTION_EXECUTE_HANDLER)
	//{				

	//}
	
	if(DoDecryptOnSameFile(INVALID_HANDLE_VALUE,pFileObject,pTargetDevice))
	{
		LARGE_INTEGER FileSize;		
		FileSize.QuadPart = *(LONGLONG*)((PUCHAR)pEncryptHead+sizeof(LONGLONG));
		PfpSetFileNotEncryptSize(pFileObject,FileSize,pTargetDevice);
	}

EXIT:
	if(pBuffer)
	{
		ExFreePoolWithTag(pBuffer,'9007');
	}
	if(pEncryptHead)
	{
		ExFreePoolWithTag(pEncryptHead,'NOO4');			
	}
	 
}

void PfpEncryptFile(PFILE_OBJECT pFileObject,PDEVICE_OBJECT pTargetDevice)
{
	PUCHAR pBuffer;
	LONG BufLen;
	NTSTATUS ntstatus;		
	PPfpFCB pFcbTemp;
	IO_STATUS_BLOCK iostatusread;
	LARGE_INTEGER FileSize;
	PVOID pEncryptHead = NULL;
	PVOID EncryptHead = NULL;

	LARGE_INTEGER	ByteOffset	= {0};
	ULONG			Length		= ENCRYPTIONHEADLENGTH;			
	 

	EncryptHead = ExAllocatePoolWithTag(NonPagedPool ,ENCRYPTIONHEADLENGTH,'N101');
	if(EncryptHead == NULL)
	{
		return ;
	}

	ntstatus = PfpReadHeadForEncryption(	EncryptHead,
		Length,
		pFileObject,
		pTargetDevice,
		&iostatusread
		);

	if(NT_SUCCESS(ntstatus) && iostatusread.Information >= ENCRYPTIONHEADLENGTH && PfpCheckEncryptInfo(EncryptHead,ENCRYPTIONHEADLENGTH))
	{
		ExFreePoolWithTag(EncryptHead,'N101');

		return ;
	}
	
	pBuffer  = ExAllocatePoolWithTag(PagedPool,(BufLen= sizeof( FILE_STANDARD_INFORMATION)),'9007');		
	if(pBuffer== NULL)
	{
		return ;
	}

	ntstatus = PfpQueryFileInforByIrp(pFileObject,(PUCHAR)pBuffer,BufLen,FileStandardInformation,pTargetDevice);

	if(!NT_SUCCESS(ntstatus) && ntstatus!=STATUS_BUFFER_OVERFLOW )
	{
		if(pBuffer)
		{
			ExFreePool(pBuffer);
		}						
		return ;
	}
	/*	try
	{
	if(CcIsFileCached(pFileObject))
	{

	CcFlushCache( &pFileObject->, NULL, 0, &iostatusread );		
	}
	}*/

	//except(EXCEPTION_EXECUTE_HANDLER)
	//{				

	//}
	pFcbTemp =(PPfpFCB) ExAllocatePoolWithTag(PagedPool,sizeof(PfpFCB),'NOO4');
	if(pFcbTemp== NULL)
	{
		if(pBuffer)
		{
			ExFreePool(pBuffer);
		}						
		return ;
	}
	if(DoEncryptOnSameFile(INVALID_HANDLE_VALUE,pFileObject,pTargetDevice))
	{
		pFcbTemp->Header.ValidDataLength .QuadPart= pFcbTemp->Header.FileSize.QuadPart = ((FILE_STANDARD_INFORMATION*)pBuffer)->EndOfFile.QuadPart;
		pFcbTemp->Header.AllocationSize .QuadPart = 	((FILE_STANDARD_INFORMATION*)pBuffer)->AllocationSize.QuadPart;
		pEncryptHead = PfpCreateEncryptHead(pFcbTemp);
		if(pEncryptHead )
		{
			LARGE_INTEGER offset= {0};
			PfpWriteFileByAllocatedIrp(pEncryptHead,ENCRYPTIONHEADLENGTH,offset,pFileObject,pTargetDevice,&iostatusread);
			FileSize .QuadPart = (pFcbTemp->Header.FileSize.QuadPart+ENCRYPTIONHEADLENGTH+g_SectorSize-1)&~((LONGLONG)g_SectorSize-1);
			PfpSetFileNotEncryptSize(pFileObject,FileSize ,pTargetDevice);
		}
	}
	if(pBuffer)
	{
		ExFreePoolWithTag(pBuffer,'9007');
	}
	if(pEncryptHead)
	{
		ExFreePoolWithTag(pEncryptHead,'N001');			
	}
	if(pFcbTemp== NULL)
	{
		ExFreePoolWithTag(pFcbTemp,'NOO4');
	}
	if(EncryptHead)
	{
		ExFreePoolWithTag(EncryptHead,'N101');
	}
}
void PfpEnOrDecryptDir(PFILE_OBJECT pDirObj,PDEVICE_OBJECT  pShadowDevice, PDEVICE_OBJECT pTargetDevice,PDEVICE_OBJECT pCurrentDevice,BOOLEAN bEncrypt,PWCHAR pszSourceDirPath)
{
	//enum all dirs and files
	// if files, create file and get fileobject and encrypt file
	//if dir,call pfpEncryptdir();
	PIRP		pIrp			= NULL;
	PVOID		pUserBuf		= NULL;
	PIO_STACK_LOCATION pStack	= NULL;
	PFILE_DIRECTORY_INFORMATION  pDirectories= NULL;
	HANDLE		hDirObject		= INVALID_HANDLE_VALUE;
	BOOLEAN		bReLoop			= FALSE;
	PPfpFCB		pFcbTemp		= NULL;
	IO_STATUS_BLOCK  iostate;
	NTSTATUS	ntStatus;
	KEVENT		SyncEvent;
	 
	
	PWCHAR		pFileName;
	PWCHAR		pFilePathWithoutDevice;
	LONG		nLenForFilePath;
	PFILE_OBJECT	 pDirObject  ;
	
	pIrp = IoAllocateIrp(pTargetDevice->StackSize,FALSE);
	if(pIrp == NULL)
		return ;

	pUserBuf = ExAllocatePoolWithTag(NonPagedPool,10*1024,'NOO1');
	if(pUserBuf== NULL)
	{
		IoFreeIrp(pIrp);
		return ;
	}
LOOPFind:
	pStack  = IoGetNextIrpStackLocation(pIrp);
	pIrp->UserBuffer = pUserBuf;
	pIrp->UserIosb   = &iostate;
	pIrp->Flags								= IRP_SYNCHRONOUS_API;
	pIrp->UserEvent							= NULL;
	pIrp->RequestorMode						= KernelMode;
	pIrp->Tail.Overlay.Thread				= (PETHREAD) PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject	= pDirObj;
	if(!bReLoop)
	{
		pStack->Flags = SL_RESTART_SCAN;
	}else
	{
		pStack->Flags = 0;
	}
	pStack->MajorFunction   =	IRP_MJ_DIRECTORY_CONTROL;
	pStack->MinorFunction	=	IRP_MN_QUERY_DIRECTORY;
	pStack->Parameters.QueryDirectory.FileInformationClass = FileDirectoryInformation;
	//pStack->Parameters.QueryDirectory.FileName->Buffer= NULL;
	pStack->Parameters.QueryDirectory.Length =10*1024;
	pStack->DeviceObject	= pTargetDevice;
	pStack->FileObject		= pDirObj;
	KeInitializeEvent(&SyncEvent,NotificationEvent,FALSE);
	ntStatus = IoSetCompletionRoutineEx(pTargetDevice,
										pIrp,
										PfpNonCachedReadByIrpCompete,
										&SyncEvent,
										TRUE,
										TRUE,
										TRUE);
	ntStatus = IoCallDriver(pTargetDevice,pIrp);
	if(NT_SUCCESS(ntStatus) )
	{
		if( STATUS_NO_MORE_FILES==ntStatus)
		{
			ExFreePoolWithTag(pUserBuf,'NOO1');
			IoFreeIrp(pIrp);
		}else
		{
			ntStatus = STATUS_SUCCESS;
			IoReuseIrp(pIrp,ntStatus);
			pDirectories = (PFILE_DIRECTORY_INFORMATION)pUserBuf;
			
			do
			{
				if(!(pDirectories->FileAttributes&FILE_ATTRIBUTE_DIRECTORY))
				{
					//create file 
					// encrpti
					//close file
					if( NT_SUCCESS(PfpGetFullPathForFileObject(pDirObj,&pFilePathWithoutDevice,&nLenForFilePath,pTargetDevice)))
					{
						WCHAR szDeviceLetter[3]={0};
						
						BOOLEAN bNeedEncrypt = FALSE;
						if(PfpGetDeviceLetter(pCurrentDevice,szDeviceLetter))
						{
							if(pDirectories&& pDirectories->FileNameLength!=0)
							{
								PWCHAR pszExt =NULL;
								LONG nIndexExt = (pDirectories->FileNameLength>>1)-1;
								BOOLEAN bFoundExt = FALSE;
								while(nIndexExt >=0)
								{
									if(pDirectories->FileName[nIndexExt]==L'\\')
									{
										break;
									}
									if(pDirectories->FileName[nIndexExt]==L'.')
									{
										bFoundExt = TRUE;
										break;
									}
									nIndexExt--;
								};
								if(bFoundExt)
								{
									pszExt = ExAllocatePoolWithTag(PagedPool,pDirectories->FileNameLength-(nIndexExt<<1),'2002');
									if(pszExt )
									{
										nIndexExt++;
										memcpy(pszExt,&pDirectories->FileName[nIndexExt],pDirectories->FileNameLength-(nIndexExt<<1));
										pszExt[(pDirectories->FileNameLength>>1)-nIndexExt]=L'\0';
										if(pszSourceDirPath)
										{
											bNeedEncrypt =IsFileTypeEncryptForFolder(szDeviceLetter ,&pszSourceDirPath[2],wcslen(&pszSourceDirPath[2]),pszExt);	
										}
										else
										{
											bNeedEncrypt =IsFileTypeEncryptForFolder(szDeviceLetter ,pFilePathWithoutDevice,nLenForFilePath>>1,pszExt);	
										}
										
										ExFreePool(pszExt);
									}

								}

							}
						}
						if(bNeedEncrypt)
						{
							pFileName =(PWCHAR) ExAllocatePoolWithTag(PagedPool,pDirectories->FileNameLength+2+nLenForFilePath+2,'NOO2');
							if(pFileName!= NULL)
							{
								memcpy(pFileName,pFilePathWithoutDevice,nLenForFilePath);
								ExFreePoolWithTag(pFilePathWithoutDevice,'9005');
								pFilePathWithoutDevice = pFileName;
								pFileName = &pFileName[(nLenForFilePath>>1)-1];
								if(*pFileName!=L'\\')
								{
									pFileName[1]=L'\\';
									pFileName++; 
								}
								pFileName++;

								memcpy(pFileName,pDirectories->FileName,pDirectories->FileNameLength);
								pFileName[pDirectories->FileNameLength>>1]=L'\0';								 
								ntStatus = PfpOpenFileByShadowDevice(pFilePathWithoutDevice,&hDirObject,pCurrentDevice);
								ExFreePoolWithTag(pFilePathWithoutDevice,	'NOO2');
								if(NT_SUCCESS(ntStatus))
								{
									pDirObject = NULL;
									ntStatus=ObReferenceObjectByHandle(hDirObject,
										FILE_READ_DATA|FILE_WRITE_DATA,
										*IoFileObjectType,
										KernelMode,
										&pDirObject,
										NULL);
									if(NT_SUCCESS(ntStatus) && pDirObject!= NULL)
									{
										if(bEncrypt)
										{
											PfpEncryptFile(pDirObject,pTargetDevice);
										}else
										{
											PfpDecryptFile(pDirObject,pTargetDevice);
										}
										ObDereferenceObject(pDirObject);
									}									
									ZwClose(hDirObject);
								}
							}else
							{
								ExFreePoolWithTag(pFilePathWithoutDevice,'9005');
							}
						}
					}					
				}else
				{
					if( !((pDirectories->FileNameLength==2&&pDirectories->FileName[0]==L'.' )||
						(pDirectories->FileNameLength==4&& memcmp(pDirectories->FileName,L"..",4 )==0)))
					{//directory.

						//zwopendirectory
						//get fileobejct for directory
						//PfpEncryptDir();
								

						if(NT_SUCCESS(PfpGetFullPathForFileObject(pDirObj,&pFilePathWithoutDevice,&nLenForFilePath,pTargetDevice)))
						{
							pFileName =(PWCHAR) ExAllocatePoolWithTag(PagedPool,pDirectories->FileNameLength+2+nLenForFilePath+2,'NOO2');
							if(pFileName!= NULL)
							{
								memcpy(pFileName,pFilePathWithoutDevice,nLenForFilePath);
								ExFreePoolWithTag(pFilePathWithoutDevice,'9005');
								pFilePathWithoutDevice = pFileName;
								pFileName = &pFileName[(nLenForFilePath>>1)-1];
								if(*pFileName!=L'\\')
								{
									pFileName[1]=L'\\';
									pFileName++; 
								}
								pFileName++;
								
								memcpy(pFileName,pDirectories->FileName,pDirectories->FileNameLength);
								pFileName[pDirectories->FileNameLength>>1]=L'\0';								 
								ntStatus = PfpOpenDirByShadowDevice(pFilePathWithoutDevice,&hDirObject,pCurrentDevice);
								ExFreePoolWithTag(pFilePathWithoutDevice,	'NOO2');
								if(NT_SUCCESS(ntStatus))
								{
									pDirObject = NULL;
									ntStatus=ObReferenceObjectByHandle(hDirObject,
																		FILE_LIST_DIRECTORY|FILE_TRAVERSE,
																		*IoFileObjectType,
																		KernelMode,
																		&pDirObject,
																		NULL);
									if(NT_SUCCESS(ntStatus) && pDirObject!= NULL)
									{
										PfpEnOrDecryptDir(pDirObject,pShadowDevice, pTargetDevice,pCurrentDevice,bEncrypt,pszSourceDirPath);
										ObDereferenceObject(pDirObject);
									}									
									ZwClose(hDirObject);
								}
							}else
							{
								ExFreePoolWithTag(pFilePathWithoutDevice,'9005');
							}
						}
					}
				}
				if(pDirectories ->NextEntryOffset!=0)
				{	
					pDirectories  = (PFILE_DIRECTORY_INFORMATION)(pDirectories ->NextEntryOffset+(PUCHAR)pDirectories) ;
				}else
				{
					break;
				}
			}
			while(1);
			bReLoop = TRUE;
			goto LOOPFind;
		}		
	}else
	{
		ExFreePoolWithTag(pUserBuf,'NOO1');
		IoFreeIrp(pIrp);
	}
}

BOOLEAN PfpIsFileSysProtected(PUNICODE_STRING pFileName)
{
	UNICODE_STRING p7;
	WCHAR szFileName[30]= {0};
	LONG nsize = ((pFileName->Length>>1)-1);

	if(pFileName->Buffer== NULL ||pFileName->Length ==0 ) return FALSE;
	
	while(nsize>=0 && pFileName->Buffer[nsize]!= L'\\')
	{
		nsize--;
	}
	if(nsize<0) return FALSE;
	
	nsize++;

	memcpy(szFileName,&pFileName->Buffer[nsize],min(29*sizeof(WCHAR),pFileName->Length-nsize*sizeof(WCHAR)));
	RtlInitUnicodeString(&p7,szFileName);	

	return (RtlCompareUnicodeString(&p7,&g_p1,TRUE)==0 ||
			RtlCompareUnicodeString(&p7,&g_p2,TRUE)==0 ||
			RtlCompareUnicodeString(&p7,&g_p3,TRUE)==0 ||
			RtlCompareUnicodeString(&p7,&g_p4,TRUE)==0 ||
			RtlCompareUnicodeString(&p7,&g_p5,TRUE)==0 ||
			RtlCompareUnicodeString(&p7,&g_p6,TRUE)==0);	

}

NTSTATUS 
PfpCommonQueryInformation ( 
						   IN PIRP_CONTEXT IrpContext, 
						   IN PIRP Irp )
{
	NTSTATUS				Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION		IrpSp;
	PFILE_OBJECT			FileObject;
	PFILE_OBJECT			pUserFileObject;
	PPfpFCB					Fcb;
	ULONG					Length;
	FILE_INFORMATION_CLASS	FileInformationClass;
	PVOID					Buffer;
	PERESOURCE				pRootDirResource = NULL;
	BOOLEAN				OpenById = FALSE;
	BOOLEAN				FcbAcquired = FALSE;
	BOOLEAN				VcbAcquired = FALSE;
	BOOLEAN				FsRtlHeaderLocked = FALSE;
	PFILE_ALL_INFORMATION AllInfo;

	PAGED_CODE();

	//
	//  Get the current Irp stack location
	//

	IrpSp = IoGetCurrentIrpStackLocation( Irp );
	//
	//  Reference our input parameters to make things easier
	//

	Length					= IrpSp->Parameters.QueryFile.Length;
	FileInformationClass	= IrpSp->Parameters.QueryFile.FileInformationClass;
	Buffer					= Irp->AssociatedIrp.SystemBuffer;

	//
	//  Extract and decode the file object
	//

	FileObject = IrpSp->FileObject;
	Fcb		   = (PPfpFCB)FileObject->FsContext;
	
	pUserFileObject = IrpContext->Fileobject_onDisk;

	OpenById   = FlagOn( Fcb->CCBFlags, CCB_FLAG_OPEN_BY_FILE_ID )?TRUE:FALSE;
	__try 
	{
		//
		//  Acquire the Vcb if there is no Ccb.  This is for the
		//  case where the cache manager is querying the name.
		//

	/*	if (Ccb == NULL) 
		{
			NtfsAcquireSharedVcb( IrpContext, Vcb, FALSE );
			VcbAcquired = TRUE;
		}*/
		if((FileInformationClass == FileAllInformation)||FileNameInformation==FileInformationClass)
		{
			ExAcquireResourceExclusiveLite(Fcb->pDiskFileObject->pParentDirResource,TRUE);
			pRootDirResource = Fcb->pDiskFileObject->pParentDirResource;
		}
		if (TRUE/*(Fcb->Header.Resource != NULL) &&
			((FileInformationClass == FileAllInformation) ||
			(FileInformationClass == FileStandardInformation) ||
			(FileInformationClass == FileCompressionInformation))*/)
		{
				ExAcquireResourceSharedLite( Fcb->Header.Resource, TRUE );
				FsRtlLockFsRtlHeader( &Fcb->Header);
				FsRtlHeaderLocked = TRUE;
		}

// 		PfpAcquireSharedFcb( IrpContext, Fcb, FALSE );
// 		FcbAcquired = TRUE;

		//
		//  Make sure the volume is still mounted.  We need to test this
		//  with the Fcb acquired.
		//

		//
		//  Based on the information class we'll do different
		//  actions.  Each of hte procedures that we're calling fills
		//  up the output buffer, if possible.  They will raise the
		//  status STATUS_BUFFER_OVERFLOW for an insufficient buffer.
		//  This is considered a somewhat unusual case and is handled
		//  more cleanly with the exception mechanism rather than
		//  testing a return status value for each call.
		//

		switch (FileInformationClass) 
		{

			case FileAllInformation:

				//
				//  This is illegal for the open by Id case.
				//

				if (OpenById)
				{
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				//
				//  For the all information class we'll typecast a local
				//  pointer to the output buffer and then call the
				//  individual routines to fill in the buffer.
				//

				AllInfo = Buffer;

				Status = PfpQueryFileInfo(IrpContext,
										  pUserFileObject,
										  Fcb,							  
										  FileInformationClass 
										  );				

				AllInfo->StandardInformation.EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;				
				AllInfo->StandardInformation.AllocationSize.QuadPart=Fcb->Header.AllocationSize.QuadPart; 
				
				AllInfo->PositionInformation.CurrentByteOffset = FileObject->CurrentByteOffset;
				
				AllInfo->BasicInformation.CreationTime.QuadPart   = Fcb->CreationTime  ;
				AllInfo->BasicInformation.LastWriteTime.QuadPart  = Fcb->LastModificationTime  ;
				AllInfo->BasicInformation.ChangeTime.QuadPart     = Fcb->LastChangeTime  ;
				AllInfo->BasicInformation.LastAccessTime.QuadPart = Fcb->CurrentLastAccess ;
				AllInfo->BasicInformation.FileAttributes			=  FILE_ATTRIBUTE_NORMAL ;
				if (FlagOn( Fcb->FcbState, FCB_STATE_TEMPORARY )) 
				{
					SetFlag( ((PFILE_BASIC_INFORMATION)Buffer)->FileAttributes, FILE_ATTRIBUTE_TEMPORARY );
				}

				
				break;

			case FileBasicInformation:
			case FileStandardInformation:
			case FileInternalInformation:
			case FileEaInformation:
			case FilePositionInformation:
			case FileStreamInformation:
			case FileCompressionInformation:
			case FileNetworkOpenInformation:	
			
				VirtualizerStart();
				Status = PfpQueryFileInfo(	IrpContext,
											pUserFileObject,
											Fcb,							  
											FileInformationClass );
				VirtualizerEnd();

				if(FileInformationClass == FileStandardInformation)
				{
					((FILE_STANDARD_INFORMATION*)Buffer)->EndOfFile.QuadPart	= Fcb->Header.FileSize.QuadPart;
					((FILE_STANDARD_INFORMATION*)Buffer)->AllocationSize.QuadPart =Fcb->Header.AllocationSize.QuadPart; 
					 

				}
				if(FileInformationClass == FilePositionInformation)
				{
					((FILE_POSITION_INFORMATION*)Buffer)->CurrentByteOffset =FileObject->CurrentByteOffset;
				}
				if(FileNetworkOpenInformation==FileInformationClass )
				{
					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->EndOfFile.QuadPart	= Fcb->Header.FileSize.QuadPart;
					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->AllocationSize.QuadPart  =Fcb->Header.AllocationSize.QuadPart; 
					 
					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->CreationTime.QuadPart	= Fcb->CreationTime				     ;
					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->LastWriteTime.QuadPart  = Fcb->LastModificationTime		  ;
					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->ChangeTime.QuadPart		=Fcb->LastChangeTime				       ;			
					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->LastAccessTime.QuadPart =Fcb->CurrentLastAccess ;

					((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->FileAttributes			= FILE_ATTRIBUTE_NORMAL;
					if (FlagOn( Fcb->FcbState, FCB_STATE_TEMPORARY )) 
					{
						SetFlag( ((PFILE_NETWORK_OPEN_INFORMATION)Buffer)->FileAttributes, FILE_ATTRIBUTE_TEMPORARY );
					}
					
				}
				if(FileBasicInformation ==FileInformationClass)
				{
					((PFILE_BASIC_INFORMATION)Buffer)->CreationTime.QuadPart	= Fcb->CreationTime  ;
					((PFILE_BASIC_INFORMATION)Buffer)->LastWriteTime.QuadPart  = Fcb->LastModificationTime  ;
					((PFILE_BASIC_INFORMATION)Buffer)->ChangeTime.QuadPart     = Fcb->LastChangeTime  ;
					((PFILE_BASIC_INFORMATION)Buffer)->LastAccessTime.QuadPart = Fcb->CurrentLastAccess ;
					((PFILE_BASIC_INFORMATION)Buffer)->FileAttributes			=  FILE_ATTRIBUTE_NORMAL ;
					if (FlagOn( Fcb->FcbState, FCB_STATE_TEMPORARY )) 
					{
						SetFlag( ((PFILE_BASIC_INFORMATION)Buffer)->FileAttributes, FILE_ATTRIBUTE_TEMPORARY );
					}
				}
				
				break;

			case FileNameInformation:
			case FileAlternateNameInformation:
			case FileAttributeTagInformation:
				//
				//  This is illegal for the open by Id case.
				//

				if (OpenById) 
				{

					Status = STATUS_INVALID_PARAMETER;

				} else 
				{

					Status = PfpQueryFileInfo(	IrpContext,
						pUserFileObject,
						Fcb,							  
						FileInformationClass );
				}
				
				break;

			default:

				Status = STATUS_INVALID_PARAMETER;
				break;
		}

		//
		//  Set the information field to the number of bytes actually filled in
		//  and then complete the request
		//

		//Irp->IoStatus.Information = IrpSp->Parameters.QueryFile.Length - Length;

	} 
	__finally 
	{

		//DebugUnwind( NtfsCommonQueryInformation );
		if(pRootDirResource)
		{
			ExReleaseResourceLite(pRootDirResource);
		}
		if (FcbAcquired) { PfpReleaseFcb( IrpContext, Fcb ); }

		if (FsRtlHeaderLocked) 
		{
			FsRtlUnlockFsRtlHeader( &Fcb->Header );
			ExReleaseResourceLite( Fcb->Header.Resource );
		}

		if (!AbnormalTermination()) 
		{
			PfpCompleteRequest( &IrpContext, &Irp, Status );
		}

		//DebugTrace( -1, Dbg, ("NtfsCommonQueryInformation -> %08lx\n", Status) );
	}

	return Status;
}

NTSTATUS 
PfpCommonSetInformation ( 
						 IN PIRP_CONTEXT IrpContext, 
						 IN PIRP Irp )
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpSp;
	PFILE_OBJECT		FileObject;
	PFILE_OBJECT		pUserFileObject;
	PPfpFCB				Fcb;
	FILE_INFORMATION_CLASS	FileInformationClass;
	BOOLEAN					VcbAcquired = FALSE;
	BOOLEAN					ReleaseScbPaging = FALSE;
	BOOLEAN					LazyWriterCallback = FALSE;	
	BOOLEAN					bResource		= FALSE;
	PERESOURCE				pReSourceDir =NULL;
	PAGED_CODE();

	//
	//  Get the current Irp stack location
	//

	IrpSp = IoGetCurrentIrpStackLocation( Irp );

	//
	//  Reference our input parameters to make things easier
	//

	FileInformationClass = IrpSp->Parameters.SetFile.FileInformationClass;

	//
	//  Extract and decode the file object
	//

	FileObject = IrpSp->FileObject;	
	Fcb		   = (PPfpFCB)FileObject->FsContext;

	pUserFileObject = IrpContext->Fileobject_onDisk;
	//
	//  We can reject volume opens immediately.
	//

	__try 
	{

		//
		//  The typical path here is for the lazy writer callback.  Go ahead and
		//  remember this first.
		//

		if (FileInformationClass == FileEndOfFileInformation) 
		{

			LazyWriterCallback = IrpSp->Parameters.SetFile.AdvanceOnly;
			if(pUserFileObject== NULL)// 磁盘上的文件已经被关闭了 是layzewriter在设置文件的大小! 没有办法 lazywrite 一直就是比正常的程序要慢
			{
				Status = STATUS_SUCCESS;
				try_return( NOTHING );
				
			}
		}

		//
		//  Perform the oplock check for changes to allocation or EOF if called
		//  by the user.
		//

		if (!LazyWriterCallback &&
			((FileInformationClass == FileEndOfFileInformation) ||
			(FileInformationClass == FileAllocationInformation)))
		{

				//
				//  We check whether we can proceed based on the state of the file oplocks.
				//  This call might block this request.
				//

				Status = FsRtlCheckOplock( &Fcb->Oplock,
											Irp,
											IrpContext,
											NULL,
											NULL );

				if (Status != STATUS_SUCCESS) 
				{
					try_return( NOTHING );
				}

				//
				//  Update the FastIoField.
				//

				ExAcquireFastMutex( Fcb->Header.FastMutex );
				Fcb->Header.IsFastIoPossible = PfpIsFastIoPossible( Fcb );
				ExReleaseFastMutex( Fcb->Header.FastMutex );
		}

		//
		//  If this call is for EOF then we need to acquire the Vcb if we may
		//  have to perform an update duplicate call.  Don't block waiting for
		//  the Vcb in the Valid data callback case.
		//  We don't want to block the lazy write threads in the clean checkpoint
		//  case.
		//

	

		//
		//  The Lazy Writer must still synchronize with Eof to keep the
		//  stream sizes from changing.  This will be cleaned up when we
		//  complete.
		//

		if (LazyWriterCallback) 
		{

			//
			//  Acquire either the paging io resource shared to serialize with
			//  the flush case where the main resource is acquired before IoAtEOF
			//

			if (Fcb->Header.Resource != NULL)
			{

				ExAcquireResourceSharedLite( Fcb->Header.Resource, TRUE );
				ReleaseScbPaging = TRUE;
			}

			FsRtlLockFsRtlHeader( &Fcb->Header );
			IrpContext->FcbWithPagingExclusive = (PPfpFCB)Fcb;

			//
			//  Anyone potentially shrinking/deleting allocation must get the paging I/O
			//  resource first.  Also acquire this in the rename path to lock the
			//  mapped page writer out of this file.
			//

		} else/* if (((Fcb->Header.Resource != NULL) &&
			((FileInformationClass == FileEndOfFileInformation) ||
			(FileInformationClass == FileAllocationInformation) ||
			(FileInformationClass == FileRenameInformation) ||
			(FileInformationClass == FileLinkInformation))) )*/
		{
 			if(FileInformationClass== FileRenameInformation) 		
			{
				pReSourceDir =  Fcb->pDiskFileObject->pParentDirResource;
 				ExAcquireResourceExclusiveLite(pReSourceDir,TRUE );
 			}
			if (Fcb->Header.Resource != NULL)
			{

				ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
				ReleaseScbPaging = TRUE;
			}

			FsRtlLockFsRtlHeader( &Fcb->Header );
			IrpContext->FcbWithPagingExclusive = (PPfpFCB)Fcb;

		}

// 			//
// 			//  Acquire exclusive access to the Fcb,  We use exclusive
// 			//  because it is probable that one of the subroutines
// 			//  that we call will need to monkey with file allocation,
// 			//  create/delete extra fcbs.  So we're willing to pay the
// 			//  cost of exclusive Fcb access.
// 			//		
// 			PfpAcquireExclusiveFcb (IrpContext,Fcb);
// 			bResource = TRUE;
		//
		//  Based on the information class we'll do different
		//  actions.  We will perform checks, when appropriate
		//  to insure that the requested operation is allowed.
		//

		switch (FileInformationClass) 
		{
			//!!!!need to add code care about rename and allocation and disposition request.
			case FileBasicInformation:
			case FileDispositionInformation:
			case FileRenameInformation:
			case FilePositionInformation:
			case FileAllocationInformation:
			case FileEndOfFileInformation:
			case FileLinkInformation:
			case FileAttributeTagInformation:
				
				VirtualizerStart();
				Status = PfpSetFileInfo (
											IrpContext,
											pUserFileObject,
											Fcb,							  
											FileInformationClass 
											);
				VirtualizerEnd();
			
					
				//if(NT_SUCCESS(Status))
				{
					switch(FileInformationClass)
					{
					case FileEndOfFileInformation:

						////VirtualizerStart();
						Status = PfpSetEndOfFileInfo(FileObject,Irp,Fcb);
						////VirtualizerEnd();
						if(!NT_SUCCESS(Status ))
						{

						}

						break;

					case FileAllocationInformation:

						Status = PfpSetAllocationInfo(FileObject,Irp,Fcb);

						break;

					case FilePositionInformation:

							Status = PfpSetPositionInfo(Irp,FileObject);

						break;
					case FileBasicInformation:
						{
							LONGLONG CurrentTime;
							BOOL bLeveChangeTime = FALSE;
							PFILE_BASIC_INFORMATION pBasic= Irp->AssociatedIrp.SystemBuffer;
							
							KeQuerySystemTime((PLARGE_INTEGER)&CurrentTime);
							if(pBasic->FileAttributes!= 0)
							{
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(pBasic->CreationTime.QuadPart!=0)
							{
								Fcb->CreationTime = 	pBasic->CreationTime.QuadPart;
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(pBasic->LastAccessTime.QuadPart!=0)
							{
								Fcb->LastAccessTime = 	pBasic->LastAccessTime.QuadPart;
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(pBasic->LastWriteTime.QuadPart != 0)
							{
								Fcb->LastModificationTime = pBasic->LastWriteTime.QuadPart;
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(!bLeveChangeTime)
							{
								Fcb->LastChangeTime = CurrentTime;
								
							}
						}
						break;
					case FileAllInformation:
						{
							LONGLONG CurrentTime;
							BOOL bLeveChangeTime = FALSE;
							PFILE_ALL_INFORMATION pBasic= Irp->AssociatedIrp.SystemBuffer;

							KeQuerySystemTime((PLARGE_INTEGER)&CurrentTime);
							if(pBasic->BasicInformation.FileAttributes!= 0)
							{
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(pBasic->BasicInformation.CreationTime.QuadPart!=0)
							{
								Fcb->CreationTime = 	pBasic->BasicInformation.CreationTime.QuadPart;
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(pBasic->BasicInformation.LastAccessTime.QuadPart!=0)
							{
								Fcb->LastAccessTime = 	pBasic->BasicInformation.LastAccessTime.QuadPart;
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(pBasic->BasicInformation.LastWriteTime.QuadPart != 0)
							{
								Fcb->LastModificationTime = pBasic->BasicInformation.LastWriteTime.QuadPart;
								Fcb->LastChangeTime = CurrentTime;
								bLeveChangeTime = TRUE;
							}
							if(!bLeveChangeTime)
							{
								Fcb->LastChangeTime = CurrentTime;

							}
						}
						break;
					default:break;
					}
				}
				break;		

			default:

				Status = STATUS_INVALID_PARAMETER;
				break;
			}

		//
		//  Abort transaction on error by raising.
		//

try_exit:  NOTHING;
	}
	__finally 
	{

		//DebugUnwind( NtfsCommonSetInformation );

		//
		//  Release the paging io resource if acquired shared.
		//

		if(bResource)
		{
			ExReleaseResourceLite(Fcb->Resource);
		}
		if (ReleaseScbPaging) 
		{

			ExReleaseResourceLite( Fcb->Header.Resource );
		}
	
		if(pReSourceDir)
		{
			ExReleaseResourceLite(pReSourceDir);
		}
		if (Status != STATUS_PENDING)
		{
			//
			//  Complete the request unless it is being done in the oplock
			//  package.//
			if (!AbnormalTermination()) 
			{
				PfpCompleteRequest( &IrpContext, &Irp, Status );
			}
		}		
	}

	return Status;
}
NTSTATUS
PfpSetPositionInfo (
					IN PIRP Irp,
					IN PFILE_OBJECT FileObject
					)

					/*++

					Routine Description:

					This routine performs the set position information for fat.  It either
					completes the request or enqueues it off to the fsp.

					Arguments:

					Irp - Supplies the irp being processed

					FileObject - Supplies the file object being processed

					Return Value:

					NTSTATUS - The result of this operation if it completes without
					an exception.

					--*/

{
	NTSTATUS Status;

	PFILE_POSITION_INFORMATION Buffer;	
	PAGED_CODE();
	//
	//  Reference the system buffer containing the user specified position
	//  information record
	//

	Buffer = Irp->AssociatedIrp.SystemBuffer;

	__try {

		//
		//  Check if the file does not use intermediate buffering.  If it does
		//  not use intermediate buffering then the new position we're supplied
		//  must be aligned properly for the device
		//

		if (FlagOn( FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING ))
		{

			PDEVICE_OBJECT DeviceObject;

			DeviceObject = IoGetCurrentIrpStackLocation(Irp)->DeviceObject;

			if ((Buffer->CurrentByteOffset.LowPart & DeviceObject->AlignmentRequirement) != 0) 
			{

				try_return( Status = STATUS_INVALID_PARAMETER );
			}
		}

		//
		//  Set the new current byte offset in the file object
		//

		FileObject->CurrentByteOffset = Buffer->CurrentByteOffset;

		Status = STATUS_SUCCESS;

try_exit: NOTHING;
	} 
	__finally 
	{

	
	}
	return Status;
}
NTSTATUS
PfpSetEndOfFileInfo (
					
					 IN PFILE_OBJECT FileObject,
					 IN PIRP Irp,
					 IN PPfpFCB Fcb
					 )
{
	NTSTATUS Status;
	
	BOOLEAN FileSizeChanged = FALSE;
	LONGLONG NewFileSize;
	LONGLONG NewValidDataLength;

	PAGED_CODE();

	

	
	//
	//  Get the new file size and whether this is coming from the lazy writer.
	//

	NewFileSize = ((PFILE_END_OF_FILE_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->EndOfFile.QuadPart;

	//
	//  If this attribute has been 'deleted' then return immediately.
	//

// 	if (FlagOn( Scb->ScbState, SCB_STATE_ATTRIBUTE_DELETED ))
// 	{
// 
// 		DebugTrace( -1, Dbg, ("NtfsEndOfFileInfo:  No work to do\n") );
// 
// 		return STATUS_SUCCESS;
// 	}

	//
	//  Save the current state of the Scb.
	//

	//
	//  If we are called from the cache manager then we want to update the valid data
	//  length if necessary and also perform an update duplicate call if the Vcb
	//  is held.
	//

	if (IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.AdvanceOnly)
	{

		//
		//  We only have work to do if the file is nonresident.
		//

		
			//
			//  Assume this is the lazy writer and set NewValidDataLength to
			//  NewFileSize (NtfsWriteFileSizes never goes beyond what's in the
			//  Fcb).
			//

			NewValidDataLength = NewFileSize;

			NewFileSize = Fcb->Header.FileSize.QuadPart;

			//
			//  We can always move the valid data length in the Scb up to valid data
			//  on disk for this call back.  Otherwise we may lose data in a mapped
			//  file if a user does a cached write to the middle of a page.
			//  For the typical case, Scb valid data length and file size are
			//  equal so no adjustment is necessary.
			//
			
			if ((Fcb->Header.ValidDataLength.QuadPart < NewFileSize) &&
				(NewValidDataLength > Fcb->Header.ValidDataLength.QuadPart)
				) 
			{

					//
					//  Set the valid data length to the smaller of ValidDataToDisk
					//  or file size.
					//
					if (NewValidDataLength >= Fcb->Header.FileSize.LowPart)
					{

						NewValidDataLength = Fcb->Header.FileSize.LowPart;
					}
					

					ExAcquireFastMutex( Fcb->Header.FastMutex );

					Fcb->Header.ValidDataLength.QuadPart = NewValidDataLength;
					ExReleaseFastMutex( Fcb->Header.FastMutex );
			}			
		
	} else 
	{

		//
		//  Check if we really are changing the file size.
		//

		if (Fcb->Header.FileSize.QuadPart != NewFileSize)
		{

			FileSizeChanged = TRUE;

		}
		
		//
		//  Check if we are shrinking a mapped file in the non-lazywriter case.  MM
		//  will tell us if someone currently has the file mapped.
		//

		if ((NewFileSize < Fcb->Header.FileSize.QuadPart) &&
			!MmCanFileBeTruncated( FileObject->SectionObjectPointer,
			(PLARGE_INTEGER)&NewFileSize )) 
		{

				Status = STATUS_USER_MAPPED_FILE;				

				return Status;
		}

		//
		//  It is extremely expensive to make this call on a file that is not
		//  cached, and Ntfs has suffered stack overflows in addition to massive
		//  time and disk I/O expense (CcZero data on user mapped files!).  Therefore,
		//  if no one has the file cached, we cache it here to make this call cheaper.
		//
		//  Don't create the stream file if called from FsRtlSetFileSize (which sets
		//  IRP_PAGING_IO) because mm is in the process of creating a section.
		//

		//
		//  We now test if we need to modify the non-resident Eof.  We will
		//  do this in two cases.  Either we're converting from resident in
		//  two steps or the attribute was initially non-resident.  We can ignore
		//  this step if not changing the file size.
		//

		
		{

			//
			//  Now determine where the new file size lines up with the
			//  current file layout.  The two cases we need to consider are
			//  where the new file size is less than the current file size and
			//  valid data length, in which case we need to shrink them.
			//  Or we new file size is greater than the current allocation,
			//  in which case we need to extend the allocation to match the
			//  new file size.
			//

			

			NewValidDataLength = Fcb->Header.ValidDataLength.QuadPart;

			
			if (NewFileSize < NewValidDataLength)
			{

				Fcb->Header.ValidDataLength.QuadPart =NewValidDataLength = NewFileSize;
			}

		

			Fcb->Header.FileSize.QuadPart = NewFileSize;

			//
			//  Call our common routine to modify the file sizes.  We are now
			//  done with NewFileSize and NewValidDataLength, and we have
			//  PagingIo + main exclusive (so no one can be working on this Scb).
			//  NtfsWriteFileSizes uses the sizes in the Scb, and this is the
			//  one place where in Ntfs where we wish to use a different value
			//  for ValidDataLength.  Therefore, we save the current ValidData
			//  and plug it with our desired value and restore on return.
			//

			ASSERT( NewFileSize == Fcb->Header.FileSize.QuadPart );
			ASSERT( NewValidDataLength == Fcb->Header.ValidDataLength.QuadPart );
			if(NewFileSize> Fcb->Header.AllocationSize.QuadPart)
			{
				LARGE_INTEGER temp1;
				temp1.QuadPart = NewFileSize+g_SectorSize-1;
				temp1.LowPart &=~((ULONG)g_SectorSize-1);
				Fcb->Header.AllocationSize.QuadPart = temp1.QuadPart;
			}
		
		}

		//
		//  If the file size changed then mark this file object as having changed the size.
		//

		if (FileSizeChanged)
		{

			SetFlag( FileObject->Flags, FO_FILE_SIZE_CHANGED );
		}

		//
		//  Only call if the file is cached now, because the other case
		//  may cause recursion in write!

		if (CcIsFileCached(FileObject)) 
		{
			//
			//  We want to checkpoint the transaction if there is one active.
			//			

			CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );
		}

		//
		//  Now cleanup the stream we created if there are no more user
		//  handles.
		//

		
	}
	Status = STATUS_SUCCESS;

	return Status;
}
NTSTATUS
PfpSetAllocationInfo (
					  IN PFILE_OBJECT FileObject,
					  IN PIRP Irp,
					  IN PPfpFCB Fcb
					  )
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_ALLOCATION_INFORMATION Buffer;
	ULONG NewAllocationSize;

	BOOLEAN FileSizeChanged = FALSE;
	BOOLEAN CacheMapInitialized = FALSE;
	BOOLEAN ResourceAcquired = FALSE;
	ULONG OriginalFileSize;
	ULONG OriginalValidDataLength;
	

	Buffer = Irp->AssociatedIrp.SystemBuffer;

	NewAllocationSize = Buffer->AllocationSize.LowPart;	

	//
	//  Allocation is only allowed on a file and not a directory
	//


	//
	//  This is kinda gross, but if the file is not cached, but there is
	//  a data section, we have to cache the file to avoid a bunch of
	//  extra work.
	//

	if ((FileObject->SectionObjectPointer->DataSectionObject != NULL) &&
		(FileObject->SectionObjectPointer->SharedCacheMap == NULL) &&
		!FlagOn(Irp->Flags, IRP_PAGING_IO))
	{

			ASSERT( !FlagOn( FileObject->Flags, FO_CLEANUP_COMPLETE ) );

			//
			//  Now initialize the cache map.
			//

			CcInitializeCacheMap(	FileObject,
									(PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
									FALSE,
									&CacheManagerCallbacks,
									Fcb );

			CacheMapInitialized = TRUE;
	}

	

	//
	//  Now mark that the time on the dirent needs to be updated on close.
	//

	SetFlag( FileObject->Flags, FO_FILE_MODIFIED );

	__try {

		//
		//  Increase or decrease the allocation size.
		//
		FileSizeChanged = (NewAllocationSize != Fcb->Header.AllocationSize.QuadPart);

		if (NewAllocationSize > Fcb->Header.AllocationSize.QuadPart)
		{
			Fcb->Header.AllocationSize.QuadPart = NewAllocationSize;			
			
		} else 
		{

			//
			//  Check here if we will be decreasing file size and synchonize with
			//  paging IO.
			//

			if ( Fcb->Header.FileSize.QuadPart > NewAllocationSize )
			{

				//
				//  Before we actually truncate, check to see if the purge
				//  is going to fail.
				//

				if (!MmCanFileBeTruncated( FileObject->SectionObjectPointer,
					&Buffer->AllocationSize )) 
				{
						FileSizeChanged = FALSE;
						try_return( Status = STATUS_USER_MAPPED_FILE );
				}

				OriginalFileSize = Fcb->Header.FileSize.LowPart;
				OriginalValidDataLength = Fcb->Header.ValidDataLength.LowPart;		

				(VOID)ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
				ResourceAcquired = TRUE;

				Fcb->Header.FileSize.LowPart = NewAllocationSize;

				//
				//  If we reduced the file size to less than the ValidDataLength,
				//  adjust the VDL.  Likewise ValidDataToDisk.
				//

				if (Fcb->Header.ValidDataLength.LowPart > Fcb->Header.FileSize.LowPart) 
				{
					Fcb->Header.ValidDataLength.LowPart = Fcb->Header.FileSize.LowPart;
				}				

			}
		
			if ( FileSizeChanged ) 
			{
				CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );		

				ASSERT( FileObject->DeleteAccess || FileObject->WriteAccess );

			}
		}

try_exit: NOTHING;

	}
	__finally
 {

		if ( AbnormalTermination() && FileSizeChanged ) 
		{

			Fcb->Header.FileSize.LowPart = OriginalFileSize;
			Fcb->Header.ValidDataLength.LowPart = OriginalValidDataLength;	

			//
			//  Make sure Cc knows the right filesize.
			//

			if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) 
			{
				*CcGetFileSizePointer(FileObject) = Fcb->Header.FileSize;
			}

			ASSERT( Fcb->Header.FileSize.LowPart <= Fcb->Header.AllocationSize.LowPart );
		}

		if (CacheMapInitialized) 
		{
			CcUninitializeCacheMap( FileObject, NULL, NULL );
		}

		if (ResourceAcquired) 		
		{
			ExReleaseResourceLite( Fcb->Header.Resource );
		}

	}
	
	return Status;
}
NTSTATUS
PfpQueryFileInfo (
					IN PIRP_CONTEXT IrpContext,
					IN PFILE_OBJECT FileObject,
					IN PPfpFCB Fcb,							  
					IN FILE_INFORMATION_CLASS InformationClass
					)

					/*++

					Routine Description:

					This routine performs the query basic information function.

					Arguments:

					FileObject - Supplies the file object being processed

					Scb - Supplies the Scb being queried

					Ccb - Supplies the Ccb for this handle

					Buffer - Supplies a pointer to the buffer where the information is to
					be returned

					Length - Supplies the length of the buffer in bytes, and receives the
					remaining bytes free in the buffer upon return.

					Return Value:

					None

					--*/

{
	
	PDEVICE_OBJECT		pTargetDevice;	
	PIO_STACK_LOCATION	pSpOrignal;	
	KEVENT				event;
	NTSTATUS			status;	
	PIRP				IrpOrignal;
	PIRP				Irp;	

	PIO_STACK_LOCATION  pSp;
	UNREFERENCED_PARAMETER(Fcb);
	UNREFERENCED_PARAMETER(InformationClass);
	pTargetDevice	= IrpContext->pNextDevice;
	IrpOrignal		= IrpContext->OriginatingIrp;

	Irp = IoAllocateIrp(pTargetDevice->StackSize,FALSE );

	if(Irp  == NULL)
	{	
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.AdvanceOnly;
	

	Irp->AssociatedIrp.SystemBuffer = IrpOrignal->AssociatedIrp.SystemBuffer ;
	Irp->Flags						= IRP_SYNCHRONOUS_API;
	Irp->RequestorMode				= KernelMode;
	Irp->UserIosb					= NULL;
	Irp->UserEvent					= NULL;
	Irp->Tail.Overlay.Thread		= PsGetCurrentThread();


	pSpOrignal		= IoGetCurrentIrpStackLocation(IrpOrignal);

	pSp				= IoGetNextIrpStackLocation(Irp);
	
	ASSERT(pTargetDevice);

 	KeInitializeEvent(&event,NotificationEvent ,FALSE);
	pSp->FileObject						= FileObject;
	pSp->MajorFunction					= pSpOrignal->MajorFunction;
	pSp->MinorFunction					= pSpOrignal->MinorFunction;
 	pSp->DeviceObject					= pTargetDevice;
	pSp->Parameters.QueryFile.Length	= pSpOrignal->Parameters.QueryFile.Length;
	pSp->Parameters.QueryFile.FileInformationClass = pSpOrignal->Parameters.QueryFile.FileInformationClass;

	IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,
							&event,
							TRUE,
							TRUE,
							TRUE );
	

	if( STATUS_PENDING == IoCallDriver(pTargetDevice,Irp) )
	{
		KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);
		status = STATUS_SUCCESS;
	}

	status = Irp->IoStatus.Status;
	IrpOrignal->IoStatus= Irp->IoStatus;
	IoFreeIrp(Irp);
	return status; 
}


NTSTATUS
PfpQueryAndSetComplete(
					   IN PDEVICE_OBJECT  DeviceObject,
					   IN PIRP  Irp,
					   IN PVOID  Context
					   )
{
	

	PKEVENT event = (PKEVENT )Context;
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	KeSetEvent(event,0,FALSE);
	
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
PfpSetFileInfo (
				  IN PIRP_CONTEXT IrpContext,
				  IN PFILE_OBJECT FileObject,
				  IN PPfpFCB Fcb,							  
				  IN FILE_INFORMATION_CLASS InformationClass 
				  )

				  /*++

				  Routine Description:

				  This routine performs the query basic information function.

				  Arguments:

				  FileObject - Supplies the file object being processed

				  Scb - Supplies the Scb being queried

				  Ccb - Supplies the Ccb for this handle

				  Buffer - Supplies a pointer to the buffer where the information is to
				  be returned

				  Length - Supplies the length of the buffer in bytes, and receives the
				  remaining bytes free in the buffer upon return.

				  Return Value:

				  None

				  --*/

{

	PIRP				Irp		= NULL;
	PDEVICE_OBJECT		pTargetDevice;
	PIO_STACK_LOCATION	pSp;
	PIO_STACK_LOCATION	pSpOrignal;
	
	KEVENT				event;
	NTSTATUS			status;	
	PIRP				IrpOrignal;
	PVOID				pTemp	= NULL;
	BOOLEAN				bDelete = FALSE;
	BOOLEAN				bNewFileNeedBackup = FALSE;
	LARGE_INTEGER		tempAl;

	PDISKFILEOBJECT    pDiskFileObject;
	UNREFERENCED_PARAMETER(Fcb);
	UNREFERENCED_PARAMETER(InformationClass);
	pTemp = NULL;
	tempAl.QuadPart = 0;
	
	pDiskFileObject = Fcb->pDiskFileObject;

	IrpOrignal		= IrpContext->OriginatingIrp;
	pSpOrignal		= IoGetCurrentIrpStackLocation(IrpOrignal);
	pTargetDevice	= IrpContext->pNextDevice;
	
	ASSERT(pTargetDevice);

	Irp = IoAllocateIrp(pTargetDevice->StackSize,FALSE );

	if(Irp  == NULL)
	{	
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto ERROR;
	}
										//IoGetCurrentIrpStackLocation(Irp)->Parameters.SetFile.AdvanceOnly;
	Irp->AssociatedIrp.SystemBuffer = IrpOrignal->AssociatedIrp.SystemBuffer ;
	Irp->Flags						= IrpOrignal->Flags;//IRP_SYNCHRONOUS_API;
	Irp->RequestorMode				= IrpOrignal->RequestorMode;//KernelMode;
	Irp->UserIosb					= IrpOrignal->UserIosb;
	Irp->UserEvent					= IrpOrignal->UserEvent;
	Irp->Tail.Overlay.Thread		= IrpOrignal->Tail.Overlay.Thread;//PsGetCurrentThread();

	pSp = IoGetNextIrpStackLocation(Irp);
	
	if(Fcb->bNeedEncrypt)
	{
		switch(InformationClass)
		{
		case FileAllocationInformation:
		case FileEndOfFileInformation:
			{
				//LARGE_INTEGER tempAl;
				
				pTemp = ExAllocatePoolWithTag(NonPagedPool,pSpOrignal->Parameters.SetFile.Length,'N401');
				if(pTemp == NULL)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					goto ERROR;
				}
				Irp->AssociatedIrp.SystemBuffer = pTemp;
				RtlCopyMemory(pTemp,IrpOrignal->AssociatedIrp.SystemBuffer,pSpOrignal->Parameters.SetFile.Length);
				if(InformationClass== FileAllocationInformation)
				{
					
					tempAl.QuadPart = ((PFILE_ALLOCATION_INFORMATION)pTemp)->AllocationSize.QuadPart;
					tempAl.QuadPart+=(ULONG)g_SectorSize-1;

					tempAl.LowPart = tempAl.LowPart&~((ULONG)g_SectorSize-1);
					
					((PFILE_ALLOCATION_INFORMATION)pTemp)->AllocationSize.QuadPart= tempAl.QuadPart+ENCRYPTIONHEADLENGTH;

				}else
				{				
					tempAl.QuadPart = ((PFILE_END_OF_FILE_INFORMATION)pTemp)->EndOfFile.QuadPart;
					tempAl.QuadPart+=(ULONG)g_SectorSize-1;
					tempAl.LowPart = tempAl.LowPart&~((ULONG)g_SectorSize-1);

					((PFILE_END_OF_FILE_INFORMATION)pTemp)->EndOfFile.QuadPart= tempAl.QuadPart+ENCRYPTIONHEADLENGTH;
				}
			}
			break;
		case FileLinkInformation:
		case FileRenameInformation:
			{
				PPROCESSINFO	ProcessInfo			= NULL;
				HANDLE			hProcess;
				ULONG			FileNameLength		= 0;
				WCHAR			*FileName			= NULL;
				LONG			nIndex				=-1;
				WCHAR*			pFileExt			= NULL;
				IO_STATUS_BLOCK	iostatusread;				
				WCHAR*			pDestFilePath		= NULL;	
				ULONG			DestFileLenInByte   = 0; 
				HANDLE			hFileOnDisk			= INVALID_HANDLE_VALUE;
				WCHAR			FileszExt[50]		= {0};
				LONG			exLenght			= 0;
				PDEVICE_OBJECT	pDeviceForTargetFile = NULL;
				FILE_END_OF_FILE_INFORMATION	FileSize;
				BOOLEAN			bLastBlock				= FALSE;
				UNICODE_STRING	DestiFilePath;
				FILE_RENAME_INFORMATION *pRenameInfo	= NULL;
				BOOLEAN			bTargetFileOnUsbDevice	= FALSE;
				WCHAR			TargetdeviceDosName[3]  = {0};
				PDEVICE_OBJECT	pOurDeviceObject		= NULL; 
				PROTECTTYPE					ProtectTypeForFolder;
				BOOLEAN						bEncryptForFolder			= FALSE;
				BOOLEAN						bBackupForFolder			= FALSE;
				BOOLEAN						bFolderUnderProtect			= FALSE;
				BOOLEAN						bFolderLocked				= FALSE;
				ULONG						bEncryptFileTypeForFolder	= ENCRYPT_NONE;
				pSp->Parameters.SetFile.FileObject	 = pSpOrignal->Parameters.SetFile.FileObject;

				//得到目标文件的全路径
				//////////////////////////////////////////////////////////////////////////

				pRenameInfo		= ((FILE_RENAME_INFORMATION*)IrpOrignal->AssociatedIrp.SystemBuffer);

				if(pRenameInfo->FileNameLength==0)// 如果这个rename的 target的 filename 是没有无效的！那么没有必要给他解密了
				{
					goto PASS;
				}


				pDestFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)+pRenameInfo->FileNameLength,'5007');	
				if(pDestFilePath == NULL)
				{
					goto PASS;
				}
				DestFileLenInByte = pRenameInfo->FileNameLength;
				RtlCopyMemory((PUCHAR)pDestFilePath,(PUCHAR)pRenameInfo->FileName,pRenameInfo->FileNameLength);

				pDestFilePath[pRenameInfo->FileNameLength/sizeof(WCHAR)]=L'\0';
				DestiFilePath.Buffer = pDestFilePath;
				DestiFilePath.Length = (USHORT)pRenameInfo->FileNameLength;
				DestiFilePath.MaximumLength = (USHORT)(pRenameInfo->FileNameLength+2);
				if(!PfpGetFileExtFromFileName(&DestiFilePath,FileszExt,&exLenght))//没有找到后缀
				{
					goto PASS;
				}
				//////////////////////////////////////////////////////////////////////////
				if(pRenameInfo->RootDirectory)
				{
					if(!PfpGetDeviceDosNameFromFileHandle(pRenameInfo->RootDirectory,TargetdeviceDosName))					
					{
						goto PASS;
					}
				}else
				{
					if(!PfpGetDosNameFromFullPath(pRenameInfo->FileName,pRenameInfo->FileNameLength,TargetdeviceDosName))
						goto PASS;
				}
				
				
				bTargetFileOnUsbDevice = PfpIsDeviceOfUSBType((pDeviceForTargetFile=PfpGetSpyDeviceFromName(TargetdeviceDosName)));
				if(bTargetFileOnUsbDevice && ExeHasLoggon!= 0 && IsUsbDeviceNeedEncryption(pDeviceForTargetFile) && IsFileNeedEncryptionForUsb(pDeviceForTargetFile,FileszExt))
				{					
					goto PASS;
					
				}

				if(pDiskFileObject ->bProcessOpened )
				{
					hProcess = PsGetProcessId(IoGetCurrentProcess() );

					ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
					ProcessInfo = PfpGetProcessInfoUsingProcessId(hProcess);
					ExReleaseResourceLite(&g_ProcessInfoResource);

					if(!ProcessInfo || IsListEmpty (&ProcessInfo->FileTypes))//设置了程序，但是没有设置文件类型，那么说明这个软件的所有的文件都要求是加密的。
					{
						goto PASS;
					}

					if(exLenght== 3*sizeof(WCHAR))//当文件后缀是3个字符的时候，进行优先的几个文件类型的判断
					{
						if(IsFileTypeBelongExeType(FileszExt))
						{
							goto DECRYPT;
						}
					}				

					//判断访问的文件类型是不是次程序要排除的。
					//如果是此程序明确排除的，那么 就没有任何疑问了
					//1:只要不是明确要求解密的 那么就直接pass
					if((ProcessInfo->bForceEncryption && PfpFileExtentionExistInProcInfoNotSelete(ProcessInfo,FileszExt) )//如果是强制加密的情况
						|| (!ProcessInfo->bForceEncryption && !PfpFileExtentionExistInProcInfo(ProcessInfo,FileszExt)))		//解密的 不备份
					{
				DECRYPT:

						InterlockedDecrement(&ProcessInfo->nRef);
						ProcessInfo= NULL;	

						hFileOnDisk = Fcb->pDiskFileObject->hFileWriteThrough;//PfpGetHandleFromObject(Fcb->pDiskFileObject->pDiskFileObjectWriteThrough);// Fcb->pDiskFileObject->hFileWriteThrough;
						if(hFileOnDisk == INVALID_HANDLE_VALUE)
						{
							goto PASS;
						}
						__try
						{
							if(CcIsFileCached(FileObject))
							{
								CcFlushCache( &Fcb->SegmentObject, NULL, 0, &iostatusread );		
							}
						}
						__except(EXCEPTION_EXECUTE_HANDLER)
						{				

						}
						DoDecryptOnSameFile(hFileOnDisk,Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,pTargetDevice);

						FileSize.EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
					
						PfpSetFileNotEncryptSize(Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,
												FileSize.EndOfFile,
												pTargetDevice);

						Fcb->bNeedEncrypt = FALSE;					
					}else  //做备份工作了
					{
						bNewFileNeedBackup = PfpIsFileTypeNeedBackup(ProcessInfo,FileszExt);

					}
				}else if(pDiskFileObject ->bUnderSecurFolder)//文件夹下面打开的文件
				{
					if(exLenght== 3*sizeof(WCHAR))//当文件后缀是3个字符的时候，进行优先的几个文件类型的判断
					{
						if(IsFileTypeBelongExeType(FileszExt))
						{
							goto DECRYPTForFolder;
						}
					}

					if(pRenameInfo->RootDirectory)//有相对文件夹的时候
					{
						WCHAR *szFullPathofParent  = NULL;
						LONG   lParentLen		   = 0;
						WCHAR  szDriverLetter   [3]= {0};
						PFILE_OBJECT			pDirFileObject = NULL;
						NTSTATUS				ntstatus ;		
						if(!NT_SUCCESS(ntstatus = ObReferenceObjectByHandle(pRenameInfo->RootDirectory,
							0,
							*IoFileObjectType,
							KernelMode,
							&pDirFileObject,
							NULL)))
						{
							FsRtlExitFileSystem();
							PfpCompleteRequest( NULL, &Irp, ntstatus );
							return ntstatus;
						}
						ntstatus = PfpGetFullPathForFileObject(pDirFileObject,&szFullPathofParent,&lParentLen,pTargetDevice);
						ObDereferenceObject(pDirFileObject);
						pDirFileObject = NULL;
						if(!NT_SUCCESS(ntstatus ))
						{
							goto PASS;
						}			 
							
						if(!PfpGetDeviceLetter(IrpContext->RealDevice,szDriverLetter)) 
						{
							if(szFullPathofParent) ExFreePool(szFullPathofParent);		
							 
							goto PASS;
						}

						bFolderUnderProtect = GetFolderProtectProperty(szDriverLetter ,
																		szFullPathofParent,
																		lParentLen,
																		&ProtectTypeForFolder,
																		&bEncryptForFolder,
																		&bBackupForFolder,
																		&bFolderLocked,
																		&bEncryptFileTypeForFolder);
						
						if(!bFolderUnderProtect || (bEncryptFileTypeForFolder== ENCRYPT_NONE) || ((bEncryptFileTypeForFolder==ENCRYPT_TYPES)?!IsFileTypeEncryptForFolder(szDriverLetter,szFullPathofParent,lParentLen,FileszExt):0))							
						{				
							if(szFullPathofParent) ExFreePool(szFullPathofParent);								
							 
						}else
						{
							bNewFileNeedBackup = IsFileNeedBackupForFolder(szDriverLetter,szFullPathofParent,lParentLen,FileszExt);
							if(szFullPathofParent) ExFreePool(szFullPathofParent);
							goto PASS;
						}
					}else //绝对路径的情况下
					{
						WCHAR szNameSpace[]    =L"\\??\\";
						WCHAR szNameSpace1[]   =L"\\DosDevices\\";
						WCHAR szDriverLetter[3]={0};
						LONG  nIndex		   = 0;
						ULONG  LenName		   = wcslen(szNameSpace);
						ULONG  LenName1		   = wcslen(szNameSpace1);

						if(pRenameInfo->FileNameLength>>1 <=LenName)
						{
							goto PASS;
						}
						
						if(_wcsnicmp(pDestFilePath,szNameSpace,LenName)==0)
						{
							DestFileLenInByte = sizeof(WCHAR)*(pRenameInfo->FileNameLength/sizeof(WCHAR)-LenName);
							RtlMoveMemory(pDestFilePath,&pDestFilePath[LenName],DestFileLenInByte);
							pDestFilePath[DestFileLenInByte>>1]=L'\0'; 
						}else
						{
							if(pRenameInfo->FileNameLength/sizeof(WCHAR) > LenName1 && _wcsnicmp(pDestFilePath,szNameSpace1,LenName1)==0)
							{										 
								DestFileLenInByte = sizeof(WCHAR)*(pRenameInfo->FileNameLength/sizeof(WCHAR)-LenName1);
								RtlMoveMemory(pDestFilePath,&pDestFilePath[LenName1],DestFileLenInByte);
								pDestFilePath[DestFileLenInByte>>1]=L'\0';// 这里的得到父文件夹的路径								 
							}
							else
							{
								goto PASS;
							}
						}
 
						nIndex =  (DestFileLenInByte>>1)-1;
						while(nIndex>=0 && pDestFilePath[nIndex]!=L'\\') nIndex--;

						if(nIndex<0) 
						{
							goto PASS;
						}

						pDestFilePath[nIndex ]=0;
						memcpy(szDriverLetter,pDestFilePath,2*sizeof(WCHAR));
						DestFileLenInByte = (nIndex <<1);
					 
						bFolderUnderProtect = GetFolderProtectProperty(szDriverLetter ,
																		&pDestFilePath[2],
																		(DestFileLenInByte>>1)-2,
																		&ProtectTypeForFolder,
																		&bEncryptForFolder,
																		&bBackupForFolder,
																		&bFolderLocked,
																		&bEncryptFileTypeForFolder);

						if(!bFolderUnderProtect || (bEncryptFileTypeForFolder==ENCRYPT_NONE) || ((bEncryptFileTypeForFolder==ENCRYPT_TYPES)? !IsFileTypeEncryptForFolder(szDriverLetter,&pDestFilePath[2],(DestFileLenInByte>>1)-2,FileszExt):0))							
						{
							goto DECRYPTForFolder;
						}else
						{
							bNewFileNeedBackup = IsFileNeedBackupForFolder(szDriverLetter,&pDestFilePath[2],(DestFileLenInByte>>1)-2,FileszExt);
						
						}
						goto PASS;	
					}
						
					
DECRYPTForFolder:
						
					hFileOnDisk = Fcb->pDiskFileObject->hFileWriteThrough;
					if(hFileOnDisk == INVALID_HANDLE_VALUE)
					{
						goto PASS;
					}
					__try
					{
						if(CcIsFileCached(FileObject))
						{
							CcFlushCache( &Fcb->SegmentObject, NULL, 0, &iostatusread );		
						}
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{				

					}
					DoDecryptOnSameFile(hFileOnDisk,Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,pTargetDevice);

					FileSize.EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
					
					PfpSetFileNotEncryptSize(Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,
											FileSize.EndOfFile,
											pTargetDevice);
					Fcb->bNeedEncrypt = FALSE;					
					
				}
				//这里就是提前使用完毕了，所以对这个processinfo的结构的引用立即释放			
PASS:
				if(pDestFilePath)
				{
					ExFreePool(pDestFilePath);
					pDestFilePath = NULL;
				}				
				if(ProcessInfo)
				{
					InterlockedDecrement(&ProcessInfo->nRef);
				}				
			}
			break;
		default:
			break;
		}
	}else//  下面处理对目标文件 是不是加密的情况下！ 这个时候的文件处于非加密的状态
	{
		switch(InformationClass)
		{
			
		case FileRenameInformation:
			{
				PPROCESSINFO				ProcessInfo			= NULL;
				HANDLE						hProcess			= INVALID_HANDLE_VALUE;
				WCHAR*						pDestFilePath		= NULL;
				ULONG						DestFileLenInByte   = 0; 
				IO_STATUS_BLOCK				iostatusread;				

				HANDLE						hFileOnDisk			= INVALID_HANDLE_VALUE;
				WCHAR						FileszExt[50]		={0};
				LONG						exLenght			=0;

				FILE_END_OF_FILE_INFORMATION	FileSize;
				BOOLEAN						bLastBlock					= FALSE;
				UNICODE_STRING				DestiFilePath;
				PVOID						pEncryptHead				= NULL;
				FILE_RENAME_INFORMATION *	pRenameInfo	= NULL;
				BOOLEAN						bTargetFileOnUsbDevice		= FALSE;
				WCHAR						TargetdeviceDosName[3]		= {0};
				PROTECTTYPE					ProtectTypeForFolder;
				BOOLEAN						bEncryptForFolder			= FALSE;
				BOOLEAN						bBackupForFolder			= FALSE;
				BOOLEAN						bFolderUnderProtect			= FALSE;
				BOOLEAN						bFolderLocked				= FALSE;
				ULONG						bEncryptFileTypeForFolder	= ENCRYPT_NONE;
				PDEVICE_OBJECT				pDeviceForTargetFile		= NULL;
				pSp->Parameters.SetFile.FileObject		= pSpOrignal->Parameters.SetFile.FileObject;

				//得到目标文件的全路径
				//////////////////////////////////////////////////////////////////////////

				pRenameInfo		= ((FILE_RENAME_INFORMATION*)IrpOrignal->AssociatedIrp.SystemBuffer);

				if(pRenameInfo->FileNameLength==0)// 如果这个rename的 target的 filename 是没有无效的！那么没有必要给他解密了
				{
					goto BYPASS_ENCRYPT;
				}

				pDestFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)+pRenameInfo->FileNameLength,'6007');	
				if(pDestFilePath == NULL)
				{
					goto BYPASS_ENCRYPT;
				}
				DestFileLenInByte = pRenameInfo->FileNameLength;
				RtlCopyMemory((PUCHAR)pDestFilePath,(PUCHAR)pRenameInfo->FileName,DestFileLenInByte);

				pDestFilePath[DestFileLenInByte>>1]=L'\0';
				DestiFilePath.Buffer = pDestFilePath;
				DestiFilePath.Length = (USHORT)pRenameInfo->FileNameLength;
				DestiFilePath.MaximumLength = (USHORT)(pRenameInfo->FileNameLength+2);
				if(!PfpGetFileExtFromFileName(&DestiFilePath,FileszExt,&exLenght))//没有找到后缀
				{
					goto BYPASS_ENCRYPT;
				}

				if(pRenameInfo->RootDirectory)
				{
					if(!PfpGetDeviceDosNameFromFileHandle(pRenameInfo->RootDirectory,TargetdeviceDosName))					
					{
						goto BYPASS_ENCRYPT;
					}
				}else
				{
					if(!PfpGetDosNameFromFullPath(pRenameInfo->FileName,pRenameInfo->FileNameLength,TargetdeviceDosName))
						goto BYPASS_ENCRYPT;
				}

				//对usb硬盘的rename 的操作
				bTargetFileOnUsbDevice = PfpIsDeviceOfUSBType((pDeviceForTargetFile=PfpGetSpyDeviceFromName(TargetdeviceDosName)));
				if(bTargetFileOnUsbDevice && ExeHasLoggon!= 0 && IsUsbDeviceNeedEncryption(pDeviceForTargetFile) && IsFileNeedEncryptionForUsb(pDeviceForTargetFile,FileszExt))
				{					
					goto ENCRYPT;

				}	
				if(!(pDiskFileObject ->bProcessOpened ) && !pDiskFileObject->bUnderSecurFolder)
				{
					goto BYPASS_ENCRYPT;
				}
				if(pDiskFileObject ->bProcessOpened )//进程打开的rename的操作
				{
					hProcess = PsGetProcessId(IoGetCurrentProcess() );

					ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
					ProcessInfo = PfpGetProcessInfoUsingProcessId(hProcess);
					ExReleaseResourceLite(&g_ProcessInfoResource);

					if(!ProcessInfo || IsListEmpty (&ProcessInfo->FileTypes))//设置了程序，但是没有设置文件类型，那么说明这个软件的所有的文件都要求是加密的。
					{
						goto BYPASS_ENCRYPT;
					}
	
					if(!PfpFileExtentionExistInProcInfo(ProcessInfo,FileszExt))
					{
						goto BYPASS_ENCRYPT;
					}
					bNewFileNeedBackup = PfpIsFileTypeNeedBackup(ProcessInfo,FileszExt);
				}else  //在文件保险箱里面
				{
					if(pRenameInfo->RootDirectory)//有相对文件夹的时候
					{
						WCHAR *szFullPathofParent  = NULL;
						LONG   lParentLen		   = 0;
						WCHAR  szDriverLetter   [3]= {0};
						PFILE_OBJECT			pDirFileObject = NULL;
						NTSTATUS				ntstatus ;	
						BOOLEAN					bNeedEncrypt = FALSE;
						if(!NT_SUCCESS(ntstatus = ObReferenceObjectByHandle(pRenameInfo->RootDirectory,0,*IoFileObjectType,KernelMode,&pDirFileObject,NULL))
							)
						{
							FsRtlExitFileSystem();
							PfpCompleteRequest( NULL, &Irp, ntstatus );
							return ntstatus;
						}
				
						ntstatus = PfpGetFullPathForFileObject(pDirFileObject,&szFullPathofParent,&lParentLen,pTargetDevice);
						ObDereferenceObject(pDirFileObject);
						pDirFileObject = NULL;

						if(!NT_SUCCESS(ntstatus ))
						{
							goto BYPASS_ENCRYPT;
						}

						if(!PfpGetDeviceLetter(IrpContext->RealDevice,szDriverLetter))
						{
							if(szFullPathofParent) 
							{
								ExFreePool(szFullPathofParent);
							}
							goto BYPASS_ENCRYPT;
						}

						bFolderUnderProtect = GetFolderProtectProperty(szDriverLetter ,
																		szFullPathofParent,
																		lParentLen,
																		&ProtectTypeForFolder,
																		&bEncryptForFolder,
																		&bBackupForFolder,
																		&bFolderLocked,
																		&bEncryptFileTypeForFolder);
						
						if(bFolderUnderProtect && (bEncryptFileTypeForFolder!= ENCRYPT_NONE)&& ((bEncryptFileTypeForFolder==ENCRYPT_TYPES)?IsFileTypeEncryptForFolder(szDriverLetter,szFullPathofParent,lParentLen,FileszExt):1))
						{
							bNewFileNeedBackup = IsFileNeedBackupForFolder(szDriverLetter,szFullPathofParent,lParentLen,FileszExt);
							
							bNeedEncrypt = TRUE;
						}
						if(szFullPathofParent) 
						{
							ExFreePool(szFullPathofParent);
						}
						 if(!bNeedEncrypt )
						 {
							 goto BYPASS_ENCRYPT;
						 }						
						 
					}else //绝对路径的情况下
					{
						WCHAR szNameSpace[]    =L"\\??\\";
						WCHAR szNameSpace1[]   =L"\\DosDevices\\";
						WCHAR szDriverLetter[3]={0};
						LONG  nIndex		   = 0;
						ULONG  LenName		   = wcslen(szNameSpace);
						ULONG  LenName1		   = wcslen(szNameSpace1);
						if(pRenameInfo->FileNameLength<=LenName)
						{
							goto BYPASS_ENCRYPT;
						}
						 
							 
						if(_wcsnicmp(pDestFilePath,szNameSpace,LenName)==0)
						{
							DestFileLenInByte = pRenameInfo->FileNameLength-(LenName<<1);
							RtlMoveMemory(pDestFilePath,&pDestFilePath[LenName],DestFileLenInByte);
							pDestFilePath[DestFileLenInByte>>1]=L'\0';									
							 
						}else
						if((pRenameInfo->FileNameLength>>1) >LenName1  && _wcsnicmp(pDestFilePath,szNameSpace1,LenName1)==0)
						{
							DestFileLenInByte = pRenameInfo->FileNameLength-(LenName1<<1);
							RtlMoveMemory(pDestFilePath,&pDestFilePath[LenName1],DestFileLenInByte);
							pDestFilePath[DestFileLenInByte>>1]=L'\0';	
						}
						else
						{
							goto BYPASS_ENCRYPT;
						}
 
						nIndex =  ((DestFileLenInByte>>1)-1);
						while(nIndex>=0 && pDestFilePath[nIndex]!=L'\\') nIndex--;

						if(nIndex<0) goto BYPASS_ENCRYPT;

						pDestFilePath[nIndex ]=0;
						 
						memcpy(szDriverLetter,pDestFilePath,2*sizeof(WCHAR));
						 

						bFolderUnderProtect = GetFolderProtectProperty(szDriverLetter ,&pDestFilePath[2],nIndex-2,&ProtectTypeForFolder,
							&bEncryptForFolder,&bBackupForFolder,&bFolderLocked,&bEncryptFileTypeForFolder);

						if(bFolderUnderProtect && (bEncryptFileTypeForFolder!= ENCRYPT_NONE)&& 
							((bEncryptFileTypeForFolder==ENCRYPT_TYPES)?IsFileTypeEncryptForFolder(szDriverLetter,&pDestFilePath[2],nIndex-2,FileszExt):1))
						{
							bNewFileNeedBackup = IsFileNeedBackupForFolder(szDriverLetter,&pDestFilePath[2],nIndex-2,FileszExt);							
						}else
						{
							goto BYPASS_ENCRYPT;
						}
					}
				} 
ENCRYPT:
				if(ProcessInfo)
				{
					InterlockedDecrement(&ProcessInfo->nRef);
					ProcessInfo= NULL;	
				}

				hFileOnDisk = Fcb->pDiskFileObject->hFileWriteThrough;//PfpGetHandleFromObject(Fcb->pDiskFileObject->pDiskFileObjectWriteThrough);// Fcb->pDiskFileObject->hFileWriteThrough;
				if(hFileOnDisk == INVALID_HANDLE_VALUE)
				{
					goto PASS;
				}
				__try
				{
					if(CcIsFileCached(FileObject))
					{
						CcFlushCache( &Fcb->SegmentObject, NULL, 0, &iostatusread );		
					}
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{				

				}
				DoEncryptOnSameFile(hFileOnDisk,Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,pTargetDevice);
				pEncryptHead = PfpCreateEncryptHead(Fcb);
				if(pEncryptHead )
				{
					LARGE_INTEGER offset= {0};
					PfpWriteFileByAllocatedIrp(pEncryptHead,ENCRYPTIONHEADLENGTH,offset,Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,pTargetDevice,&iostatusread);
					
				}
				
				FileSize.EndOfFile.QuadPart = (Fcb->Header.FileSize.QuadPart+ENCRYPTIONHEADLENGTH+g_SectorSize-1)&~((LONGLONG)g_SectorSize-1);
				PfpSetFileNotEncryptSize(Fcb->pDiskFileObject->pDiskFileObjectWriteThrough,
										FileSize.EndOfFile,
										pTargetDevice);

				Fcb->bNeedEncrypt = TRUE;	
BYPASS_ENCRYPT:
				if(pEncryptHead)
				{
					ExFreePool(pEncryptHead);
					pEncryptHead = NULL;
				}
				if(pDestFilePath)
				{
					ExFreePool(pDestFilePath);
					pDestFilePath = NULL;
				}				
				if(ProcessInfo)
				{
					InterlockedDecrement(&ProcessInfo->nRef);
				}	
			}

			break;
		default:
			break;
		}
	}

	pSp->MajorFunction						= pSpOrignal->MajorFunction;
	pSp->MinorFunction						= pSpOrignal->MinorFunction;
	pSp->Parameters.SetFile.Length			= pSpOrignal->Parameters.SetFile.Length;
	pSp->Parameters.SetFile.FileInformationClass = pSpOrignal->Parameters.SetFile.FileInformationClass;
	pSp->Parameters.SetFile.AdvanceOnly		= pSpOrignal->Parameters.SetFile.AdvanceOnly;
	pSp->Parameters.SetFile.ReplaceIfExists = pSpOrignal->Parameters.SetFile.ReplaceIfExists  ;
	pSp->Parameters.SetFile.ClusterCount    = pSpOrignal->Parameters.SetFile.ClusterCount ;
	pSp->Parameters.SetFile.DeleteHandle	= pSpOrignal->Parameters.SetFile.DeleteHandle   ;
	
	//
	//Replace fileobject in stack location by using the correct fileobject corresponding to disk.
	//
	pSp->FileObject		= FileObject;	
	pSp->DeviceObject	= pTargetDevice;
	KeInitializeEvent(&event,NotificationEvent ,FALSE);

	IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,&event,TRUE,TRUE,TRUE);


	if( STATUS_PENDING == IoCallDriver(pTargetDevice,Irp) )
	{
		KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);
		status = STATUS_SUCCESS;
	}
	
	status = Irp->IoStatus.Status;
	if(pTemp)
	{
		ExFreePool(pTemp);
		pTemp= NULL;
	}

	IrpOrignal->IoStatus= Irp->IoStatus;
	IoFreeIrp(Irp);
	Irp = NULL;
	

	if(NT_SUCCESS(status)&& (InformationClass == FileDispositionInformation))
	{		
		if(bDelete=((PFILE_DISPOSITION_INFORMATION)IrpOrignal->AssociatedIrp.SystemBuffer)->DeleteFile )
		{
			pSpOrignal->FileObject->DeletePending = TRUE;
			SetFlag( Fcb->FcbState, FCB_STATE_FILE_DELETED );
		}else
		{
			pSpOrignal->FileObject->DeletePending = FALSE;
			ClearFlag( Fcb->FcbState, FCB_STATE_FILE_DELETED );
		}		
	}

	//重命名后，ntfs就会把命名后的文件路径和名字改写到fileobject的name里面去
	//所以，这里我们要做补救工作。但是这个fileobject->context->fcb->diskfileobject->fullpath 还是以前的打开的文件路径

	if(NT_SUCCESS(status) && InformationClass== FileRenameInformation)		
	{
		PERESOURCE pSourceFileParentResource = Fcb->pDiskFileObject->pParentDirResource;
		//ExAcquireResourceExclusiveLite( pSourceFileParentResource,TRUE );
		if(NT_SUCCESS(PfpReBuildFullPathForDiskFileObjectAfterRename(FileObject,(PFILE_RENAME_INFORMATION)IrpOrignal->AssociatedIrp.SystemBuffer,pSpOrignal,Fcb,IrpContext)))
		{
			PWCHAR pszRemainer = NULL;
			BOOLEAN bComplete = FALSE;
			PDISKDIROBEJECT		pTargetParentDir = NULL; 
			PDISKDIROBEJECT		pTempParentDir = NULL;
			PDISKDIROBEJECT		pRootDir = PfpGetVirtualRootDirFromSpyDevice(IrpContext->RealDevice);
			PDISKFILEOBJECT		pTempDisk = NULL;
			PVIRTUALDISKFILE	pVirtualDiskFile = NULL;
			PERESOURCE			pTempResource = NULL;
			
			//ExAcquireResourceExclusiveLite( pRootDir->AccssLocker,TRUE );
			pTargetParentDir   = PfpPareseToDirObject(pRootDir ,Fcb->pDiskFileObject->FullFilePath.Buffer,&pszRemainer,&bComplete );
			if(pTargetParentDir  !=((PVIRTUALDISKFILE)Fcb->pDiskFileObject->pVirtualDiskFile)->pParentDir)
			{
			
				if(!bComplete)
				{				
					pTempParentDir =PfpMakeVirtualChildDirForFile(pTargetParentDir ,&pszRemainer);
				} 
				else
				{
					pTempParentDir =pTargetParentDir  ;
				}

				if(bComplete)
				{
					UNICODE_STRING TempString;
					TempString.Buffer = pszRemainer;
					TempString.Length = (Fcb->pDiskFileObject->FullFilePath.Length-(USHORT)((PUCHAR)pszRemainer-(PUCHAR)Fcb->pDiskFileObject->FullFilePath.Buffer));
					TempString.MaximumLength  = 2+TempString.Length ;
					pVirtualDiskFile = PfpFindVirtualDiskFileObjectInParent(pTempParentDir,&TempString);
				 	ASSERT(NULL==PpfGetDiskFileObjectFromVirtualDisk(pVirtualDiskFile));
				}
				if(pVirtualDiskFile== NULL)
				{
					pVirtualDiskFile = CreateVirDiskFileAndInsertIntoParentVirtual(pTempParentDir,pszRemainer);
				}
				ASSERT(pVirtualDiskFile!= NULL);

				//从原来的目录下面 断下来，并且把原有的 virtualdiskfile 删除掉
				pTempResource = ((PVIRTUALDISKFILE)(Fcb->pDiskFileObject->pVirtualDiskFile))->pVirtualDiskLocker;
				KdPrint(("setinfomation function accquire file resource %Xh",pTempResource));
				ExAcquireResourceExclusiveLite(pTempResource ,TRUE);
				
				PfpRemoveDiskFileObjectFromListEntry(Fcb->pDiskFileObject);					
				PfpAddDiskFileObjectIntoItsVirtualDiskFile(pVirtualDiskFile,Fcb->pDiskFileObject);
				
				ExReleaseResourceLite(pTempResource);
				KdPrint(("setinfomation function release file resource %Xh",pTempResource));
				PfpDeleteVirtualDiskFile((PVIRTUALDISKFILE)(Fcb->pDiskFileObject->pVirtualDiskFile),NULL);
				
				
				 
				//ExReleaseResourceLite( pTempParentDir ->AccssLocker);
				 
			} else
			{
				UNICODE_STRING TempString;
				PVIRTUALDISKFILE pVirtualTargetDiskFile =  NULL;

				TempString.Buffer = pszRemainer;
				TempString.Length = (Fcb->pDiskFileObject->FullFilePath.Length-(USHORT)((PUCHAR)pszRemainer-(PUCHAR)Fcb->pDiskFileObject->FullFilePath.Buffer));
				TempString.MaximumLength  = 2+TempString.Length ;
				pVirtualTargetDiskFile= PfpFindVirtualDiskFileObjectInParent(pTargetParentDir,&TempString);		
				if(pVirtualTargetDiskFile)
				{
					ASSERT(NULL==PpfGetDiskFileObjectFromVirtualDisk(pVirtualDiskFile));					
					//RemoveEntryList(&pVirtualTargetDiskFile->list);
					PfpDeleteVirtualDiskFile(pVirtualTargetDiskFile,NULL);
				}
				pVirtualDiskFile = (PVIRTUALDISKFILE)Fcb->pDiskFileObject->pVirtualDiskFile;
				 
				if(Fcb->pDiskFileObject->FileNameOnDisk.Buffer)
				{
					if(pVirtualDiskFile->FileName.Buffer)
					{
						ExFreePool_A(pVirtualDiskFile->FileName.Buffer);
					}
					pVirtualDiskFile->FileName.Length = Fcb->pDiskFileObject->FileNameOnDisk.Length;
					pVirtualDiskFile->FileName.Buffer = ExAllocatePoolWithTag(PagedPool,pVirtualDiskFile->FileName.Length+2,'7007');
					if(pVirtualDiskFile->FileName.Buffer)
					{
						memcpy(pVirtualDiskFile->FileName.Buffer,Fcb->pDiskFileObject->FileNameOnDisk.Buffer,pVirtualDiskFile->FileName.Length);
						pVirtualDiskFile->FileName.Buffer[pVirtualDiskFile->FileName.Length>>1]=L'\0';
					}

					pVirtualDiskFile->FileName.MaximumLength = pVirtualDiskFile->FileName.Length+2;
				}
				//ExReleaseResourceLite(  pTargetParentDir->AccssLocker);
			}
			//ExReleaseResourceLite(pSourceFileParentResource);
		}
	}

	if(NT_SUCCESS(status) && ((InformationClass== FileEndOfFileInformation)||(InformationClass==FileAllocationInformation ))	)	
	{
		pSpOrignal->FileObject->Flags|=FO_FILE_SIZE_CHANGED;
	}
	//对文件有备份的要求，那么有些操作 要对备份文件上处理 1：文件大小变化！2：重命名 3：删除
	if(NT_SUCCESS(status)&& (bNewFileNeedBackup||Fcb->pDiskFileObject->bNeedBackUp))
	{
		if(!Fcb->pDiskFileObject->bNeedBackUp)
		{
			Fcb->pDiskFileObject->bNeedBackUp = bNewFileNeedBackup;
		}
		switch(InformationClass)
		{
		case FileRenameInformation:
		case FileDispositionInformation:		
			{				

				if((InformationClass==FileRenameInformation) && !PfpIsBackupFileObjectStillValid(Fcb->pDiskFileObject))//备份的文件不存在 或者被删除了！那么就要创建一个新的备份文件了
				{//1:创建新的文件2:拷贝原始的数据到备份中！！
					
					PfpDoBackUpWorkAboutCreate(Fcb->pDiskFileObject,IrpContext->RealDevice,NULL, Fcb->pDiskFileObject->FullFilePath.Buffer);

				}
				else					
				{
					PfpRenameOrDelBackUpFile(Fcb,InformationClass,bDelete);	
					if(FileRenameInformation == InformationClass && !bNewFileNeedBackup)
					{
						PfpRenameOrDelBackUpFile(Fcb,FileDispositionInformation,TRUE);
					}
				}
			}
			break;
		case FileEndOfFileInformation:
			{
				FILE_END_OF_FILE_INFORMATION	FileSize;
				FileSize.EndOfFile.QuadPart = (tempAl.QuadPart+ENCRYPTIONHEADLENGTH+g_SectorSize-1)&~((LONGLONG)(g_SectorSize-1));
		
				PfpSetFileNotEncryptSize(Fcb->pDiskFileObject->hBackUpFileObject,
										FileSize.EndOfFile,
										pTargetDevice);
			}
			break;
		default:break;
		}
	}
ERROR:
	if(Irp)
	{
		IoFreeIrp(Irp);		
	}
	if(pTemp)
	{
		ExFreePool(pTemp);
	}
	return status ; 



}
NTSTATUS
PfpReBuildFullPathForDiskFileObjectAfterRename(PFILE_OBJECT pDiskFile, 
											   PFILE_RENAME_INFORMATION pRenameInfo,
											   PIO_STACK_LOCATION pOrginalSp,
											   PPfpFCB Fcb,
											   PIRP_CONTEXT IrpContext)
{
	FAST_MUTEX	*		pDiskFileMutex			= NULL;
	//PWCHAR				pOrinalFilePath			= NULL;
	PFILE_OBJECT		pUsermodeFileObject		= pOrginalSp->FileObject;
	PFILE_OBJECT		FileObject				= pDiskFile;
	NTSTATUS			ntstatus				= STATUS_SUCCESS;	
	WCHAR				szDeviceName		[]  = L"\\??\\";
	ULONG				lDeviceNameSize			= wcslen(szDeviceName		);
	PWCHAR				pszFullPath				=  NULL;
	ULONG				lPathSize				= 0;
	PWCHAR				pszFilename				= NULL;
	ULONG				lNameSize				= 0;
	if(pRenameInfo->FileNameLength>(lDeviceNameSize<<1) && _wcsnicmp(pRenameInfo->FileName,szDeviceName,lDeviceNameSize)==0)
	{//绝对路径
		WCHAR* pszFullPathStart= &pRenameInfo->FileName[lDeviceNameSize+2];
		ULONG  nFullPathLen    = pRenameInfo->FileNameLength-((lDeviceNameSize+2)<<1);
		
		if(Fcb->pDiskFileObject->FullFilePath.MaximumLength <(nFullPathLen+2))
		{
			if(Fcb->pDiskFileObject->FullFilePath.Buffer)
			{
				ExFreePool(Fcb->pDiskFileObject->FullFilePath.Buffer);
			}
			Fcb->pDiskFileObject->FullFilePath.Buffer= ExAllocatePoolWithTag(NonPagedPool,nFullPathLen+2,'N501');
			if(Fcb->pDiskFileObject->FullFilePath.Buffer== NULL)
			{
				Fcb->pDiskFileObject->FullFilePath.Buffer			= NULL;
				Fcb->pDiskFileObject->FullFilePath.Length			= 0;
				Fcb->pDiskFileObject->FullFilePath.MaximumLength	= 0;
			}else
			{
				Fcb->pDiskFileObject->FullFilePath.MaximumLength		= (USHORT)nFullPathLen+2;
			}
		}
		if(Fcb->pDiskFileObject->FullFilePath.Buffer)
		{
			LONG			nIndexofLastSep = -1;
			RtlCopyMemory(Fcb->pDiskFileObject->FullFilePath.Buffer ,pszFullPathStart,nFullPathLen);
			Fcb->pDiskFileObject->FullFilePath.Length						=(USHORT) nFullPathLen;						
			Fcb->pDiskFileObject->FullFilePath.Buffer[nFullPathLen/sizeof(WCHAR)]	= L'\0';

			nIndexofLastSep = ((Fcb->pDiskFileObject->FullFilePath.Length>>1)-1);
			while(nIndexofLastSep>=0 && Fcb->pDiskFileObject->FullFilePath.Buffer[nIndexofLastSep]!= L'\\') nIndexofLastSep--;
			ASSERT(nIndexofLastSep>=0);
			nIndexofLastSep++;

			Fcb->pDiskFileObject->FileNameOnDisk.Length =(USHORT) (Fcb->pDiskFileObject->FullFilePath.Length- (nIndexofLastSep<<1));
			Fcb->pDiskFileObject->FileNameOnDisk.MaximumLength = (Fcb->pDiskFileObject->FileNameOnDisk.Length +(2<<1));
			if(Fcb->pDiskFileObject->FileNameOnDisk.Buffer)
			{
				ExFreePool(Fcb->pDiskFileObject->FileNameOnDisk.Buffer);
			}
			Fcb->pDiskFileObject->FileNameOnDisk.Buffer = ExAllocatePoolWithTag( NonPagedPool,Fcb->pDiskFileObject->FileNameOnDisk.MaximumLength,'N711');

			if(Fcb->pDiskFileObject->FileNameOnDisk.Buffer != NULL)
			{
				memcpy(Fcb->pDiskFileObject->FileNameOnDisk.Buffer ,&Fcb->pDiskFileObject->FullFilePath.Buffer[nIndexofLastSep],Fcb->pDiskFileObject->FileNameOnDisk.Length);
				Fcb->pDiskFileObject->FileNameOnDisk.Buffer[Fcb->pDiskFileObject->FileNameOnDisk.Length>>1]=L'\0';							 
			}
		}

 
	}else  
	{
		PVOID			pBuffer;
		HANDLE			HFile = INVALID_HANDLE_VALUE;
		USHORT			BufLen;

		pBuffer  = ExAllocatePoolWithTag(PagedPool,BufLen=(sizeof(WCHAR)*(MAX_PATH+1)+sizeof( FILE_NAME_INFORMATION)),'9007');		
		if(pBuffer== NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ntstatus = PfpQueryFileInforByIrp(FileObject,(PUCHAR)pBuffer,BufLen,FileNameInformation,IrpContext->pNextDevice);

		if(!NT_SUCCESS(ntstatus) && ntstatus!=STATUS_BUFFER_OVERFLOW )
		{
			if(pBuffer)
			{
				ExFreePool(pBuffer);
			}						
			goto EXIT1;
		}

		BufLen = (USHORT)((PFILE_NAME_INFORMATION)pBuffer)->FileNameLength;
		if(Fcb->pDiskFileObject->FullFilePath.MaximumLength <(BufLen+2))
		{
			if(Fcb->pDiskFileObject->FullFilePath.Buffer)
			{
				ExFreePool(Fcb->pDiskFileObject->FullFilePath.Buffer);
			}
			Fcb->pDiskFileObject->FullFilePath.Buffer= ExAllocatePoolWithTag(NonPagedPool,BufLen+2,'N501');
			if(Fcb->pDiskFileObject->FullFilePath.Buffer== NULL)
			{
				Fcb->pDiskFileObject->FullFilePath.Buffer			= NULL;
				Fcb->pDiskFileObject->FullFilePath.Length			= 0;
				Fcb->pDiskFileObject->FullFilePath.MaximumLength	= 0;
			}else
			{
				Fcb->pDiskFileObject->FullFilePath.MaximumLength		= BufLen+2;
			}
		}
		if(Fcb->pDiskFileObject->FullFilePath.Buffer)
		{
			LONG			nIndexofLastSep = -1;
			RtlCopyMemory(Fcb->pDiskFileObject->FullFilePath.Buffer ,((PFILE_NAME_INFORMATION)pBuffer)->FileName,BufLen);
			Fcb->pDiskFileObject->FullFilePath.Length						= BufLen;						
			Fcb->pDiskFileObject->FullFilePath.Buffer[BufLen/sizeof(WCHAR)]	= L'\0';

			nIndexofLastSep = ((Fcb->pDiskFileObject->FullFilePath.Length>>1)-1);
			while(nIndexofLastSep>=0 && Fcb->pDiskFileObject->FullFilePath.Buffer[nIndexofLastSep]!= L'\\') nIndexofLastSep--;
			ASSERT(nIndexofLastSep>=0);
			nIndexofLastSep++;

			Fcb->pDiskFileObject->FileNameOnDisk.Length =(USHORT) (Fcb->pDiskFileObject->FullFilePath.Length- (nIndexofLastSep<<1));
			Fcb->pDiskFileObject->FileNameOnDisk.MaximumLength = (Fcb->pDiskFileObject->FileNameOnDisk.Length +(2<<1));
			if(Fcb->pDiskFileObject->FileNameOnDisk.Buffer)
			{
				ExFreePool(Fcb->pDiskFileObject->FileNameOnDisk.Buffer);
			}
			Fcb->pDiskFileObject->FileNameOnDisk.Buffer = ExAllocatePoolWithTag( NonPagedPool,Fcb->pDiskFileObject->FileNameOnDisk.MaximumLength,'N711');

			if(Fcb->pDiskFileObject->FileNameOnDisk.Buffer != NULL)
			{
				memcpy(Fcb->pDiskFileObject->FileNameOnDisk.Buffer ,&Fcb->pDiskFileObject->FullFilePath.Buffer[nIndexofLastSep],Fcb->pDiskFileObject->FileNameOnDisk.Length);
				Fcb->pDiskFileObject->FileNameOnDisk.Buffer[Fcb->pDiskFileObject->FileNameOnDisk.Length>>1]=L'\0';							 
			}
		}
		if(pBuffer)
		{
			ExFreePool(pBuffer);
		}	
EXIT1:;
	} 
	return STATUS_SUCCESS;

	
}

NTSTATUS 
PfpRenameOrDelBackUpFile(IN PPfpFCB Fcb,IN FILE_INFORMATION_CLASS InformationClass , BOOLEAN bDelete )
{
	NTSTATUS  ntstatus = STATUS_SUCCESS;

	if(InformationClass==FileDispositionInformation)
	{
		FILE_DISPOSITION_INFORMATION dispinfo;		
		IO_STATUS_BLOCK iostatusread;		
		dispinfo.DeleteFile = bDelete;	
		
		if(Fcb->pDiskFileObject->hBackUpFileHandle!= INVALID_HANDLE_VALUE)
		{
			ZwSetInformationFile(Fcb->pDiskFileObject->hBackUpFileHandle,&iostatusread,&dispinfo,sizeof(FILE_DISPOSITION_INFORMATION),FileDispositionInformation);			
		}

	}else
	{
		PWCHAR szNewFileName =ExAllocatePoolWithTag(PagedPool,Fcb->pDiskFileObject->FullFilePath.MaximumLength+2,'0107');
		
		if(szNewFileName)
		{			
			BOOLEAN bDeleteToRecycle = FALSE;
			
			memcpy(szNewFileName,Fcb->pDiskFileObject->FullFilePath.Buffer,Fcb->pDiskFileObject->FullFilePath.Length);
			szNewFileName[Fcb->pDiskFileObject->FullFilePath.Length>>1]=L'\0';

			ExAcquireFastMutex(&g_fastRecycle);	
			bDeleteToRecycle = IsRecyclePath(szNewFileName);
			ExReleaseFastMutex(&g_fastRecycle);
			
			if(!bDeleteToRecycle)
			{
				LONG nIndex ;
				nIndex = Fcb->pDiskFileObject->FullFilePath.Length/sizeof(WCHAR)-1;
				while(nIndex>=0  && Fcb->pDiskFileObject->FullFilePath.Buffer[nIndex]!= L'\\')
				{
					nIndex--;
				};
				if(nIndex>=0)
				{
					nIndex++;
					memcpy(szNewFileName,&Fcb->pDiskFileObject->FullFilePath.Buffer[nIndex],Fcb->pDiskFileObject->FullFilePath.Length-nIndex*sizeof(WCHAR));
					szNewFileName[(Fcb->pDiskFileObject->FullFilePath.Length>>1)-nIndex]=L'\0';
				}
				PfpRenameFileUsingFileobeject(Fcb->pDiskFileObject->hBackUpFileObject,szNewFileName);				
			}else
			{
				FILE_DISPOSITION_INFORMATION dispinfo;
				
				IO_STATUS_BLOCK iostatusread;
				dispinfo.DeleteFile = TRUE;

				if(Fcb->pDiskFileObject->hBackUpFileHandle!= INVALID_HANDLE_VALUE)
				{
					ZwSetInformationFile(Fcb->pDiskFileObject->hBackUpFileHandle,&iostatusread,&dispinfo,sizeof(FILE_DISPOSITION_INFORMATION),FileDispositionInformation);					 
				}
			}
			ExFreePool(szNewFileName);			
		}
	}

	return STATUS_SUCCESS;
}
NTSTATUS
PfpFsQueryAndSetSec(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp)
{

	PDEVICE_OBJECT		pTargetDevice;	
	PIO_STACK_LOCATION	pSpOrignal;	
	KEVENT				event;
	NTSTATUS			status;	
	PIRP				IrpOrignal;

	PFILESPY_DEVICE_EXTENSION pDeviceExt;
	PDEVICE_OBJECT		pNextDevice;
	PFILE_OBJECT		FileObject;
	PIO_STACK_LOCATION pSp = IoGetCurrentIrpStackLocation(Irp);
	FileObject = pSp ->FileObject;
	pDeviceExt = ((PDEVICE_OBJECT)DeviceObject)->DeviceExtension;
	pNextDevice = pDeviceExt ->NLExtHeader.AttachedToDeviceObject;

	//
	//Check to see if the irp is coming form shadowdevice.
	//
	// 	if( pDeviceExt->bShadow )
	// 	{
	// 		pNextDevice = ((PFILESPY_DEVICE_EXTENSION)(pDeviceExt->pRealDevice->DeviceExtension))->NLExtHeader.AttachedToDeviceObject;
	// 		goto BYPASS;
	// 	}
	// 	

	if(PfpFileObjectHasOurFCB(FileObject ))
	{

		pTargetDevice	= pNextDevice;
		IrpOrignal		= Irp;

		Irp = IoAllocateIrp(pTargetDevice->StackSize,FALSE );

		if(Irp  == NULL)
		{	
			IrpOrignal->IoStatus.Status= STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest(IrpOrignal,IO_DISK_INCREMENT);
			return STATUS_INSUFFICIENT_RESOURCES; 
			
		}

		//Irp->AssociatedIrp.SystemBuffer = IrpOrignal->AssociatedIrp.SystemBuffer ;
		Irp->Flags						= IRP_SYNCHRONOUS_API;
		Irp->RequestorMode				= KernelMode;
		Irp->UserIosb					= NULL;
		Irp->UserEvent					= NULL;
		Irp->Tail.Overlay.Thread		= PsGetCurrentThread();


		pSpOrignal		= IoGetCurrentIrpStackLocation(IrpOrignal);

		pSp				= IoGetNextIrpStackLocation(Irp);

		ASSERT(pTargetDevice);

		KeInitializeEvent(&event,NotificationEvent ,FALSE);
		pSp->FileObject						= ((PPfpFCB)(FileObject ->FsContext))->pDiskFileObject->pDiskFileObjectWriteThrough;
		pSp->MajorFunction					= pSpOrignal->MajorFunction;

		//	pSp->DeviceObject					= pTargetDevice;
		switch(pSpOrignal->MajorFunction)
		{
		case IRP_MJ_SET_SECURITY:
			pSp->Parameters.SetSecurity.SecurityDescriptor  = pSpOrignal->Parameters.SetSecurity.SecurityDescriptor;
			pSp->Parameters.SetSecurity.SecurityInformation = pSpOrignal->Parameters.SetSecurity.SecurityInformation ;
			break;

		case IRP_MJ_QUERY_SECURITY:
			pSp->Parameters.QuerySecurity.Length	= pSpOrignal->Parameters.QuerySecurity.Length;
			pSp->Parameters.QuerySecurity.SecurityInformation  = pSpOrignal->Parameters.QuerySecurity.SecurityInformation ;
			
			if(IrpOrignal->UserBuffer)
			{
				Irp->UserBuffer							= ExAllocatePoolWithTag(PagedPool,pSpOrignal->Parameters.QuerySecurity.Length,'1107');
				if(Irp->UserBuffer== NULL)
				{
					IrpOrignal->IoStatus.Status= STATUS_INSUFFICIENT_RESOURCES;
					IoFreeIrp(Irp);
					IoCompleteRequest(IrpOrignal,IO_DISK_INCREMENT);
					return STATUS_INSUFFICIENT_RESOURCES; 
				}
			}
			break;
		default:
			ASSERT(0);
			break;

		}


		IoSetCompletionRoutine(Irp,PfpQueryAndSetComplete,
			&event,
			TRUE,
			TRUE,
			TRUE );


		if( STATUS_PENDING == IoCallDriver(pTargetDevice,Irp) )
		{
			KeWaitForSingleObject(&event,Executive,KernelMode ,FALSE,NULL);
			status = STATUS_SUCCESS;
		}

		
		IrpOrignal->IoStatus= Irp->IoStatus;
		status =IrpOrignal->IoStatus.Status;
		if(NT_SUCCESS(IrpOrignal->IoStatus.Status) && pSpOrignal->MajorFunction ==IRP_MJ_QUERY_SECURITY)
		{
			__try 
			{
				if(IrpOrignal->UserBuffer)
				{
					ProbeForWrite( IrpOrignal->UserBuffer, IrpOrignal->IoStatus.Information, sizeof( UCHAR ) );	
					memcpy(IrpOrignal->UserBuffer,Irp->UserBuffer,IrpOrignal->IoStatus.Information);
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				status= IrpOrignal->IoStatus.Status		 = GetExceptionCode();
				IrpOrignal->IoStatus.Information = 0;
			}
			
		}
		if(pSpOrignal->MajorFunction ==IRP_MJ_QUERY_SECURITY && IrpOrignal->UserBuffer)
		{
			ExFreePool_A(Irp->UserBuffer);
		}
		IoFreeIrp(Irp);
		IoCompleteRequest(IrpOrignal,IO_DISK_INCREMENT);
		return status; 
	}else
	{
		return SpyDispatch(DeviceObject,Irp);
	}
}

#define DATA_BLOCK_SIZE 1024*256
BOOLEAN		DoEncryptOnSameFile(HANDLE hFile,PFILE_OBJECT pFileObject,PDEVICE_OBJECT pNextDevice)
{
	NTSTATUS			status;
	IO_STATUS_BLOCK		iostatusread;
	PVOID				pBuffer;
	LARGE_INTEGER		Offset;
	LARGE_INTEGER		OffsetWrite;
	BOOLEAN				bLastBlock	= FALSE;
	LONG				Length		= 0;
	FILE_STANDARD_INFORMATION *pStardInfo=NULL;
	ULONG				nLeft = 0;
	
	
	pStardInfo =(FILE_STANDARD_INFORMATION*) ExAllocatePoolWithTag(PagedPool,sizeof(FILE_STANDARD_INFORMATION),'2107');
	if(pStardInfo == NULL)
		return FALSE;
	memset(pStardInfo,0,sizeof(FILE_STANDARD_INFORMATION));
	if(PfpQueryFileInforByIrp(pFileObject,(PUCHAR)pStardInfo,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation,pNextDevice)== STATUS_SUCCESS)
	{
		if(pStardInfo->EndOfFile.QuadPart==0 ||pStardInfo->Directory)			
		{
			ExFreePoolWithTag(pStardInfo,'2107');
			return FALSE;
		}
	}

	Offset.QuadPart = 0;

	pBuffer  = ExAllocatePoolWithTag(NonPagedPool,DATA_BLOCK_SIZE,'N601');
	if(pBuffer  == NULL)
	{
		ExFreePoolWithTag(pStardInfo,'2107');
		return FALSE;
	}
	nLeft = (ULONG)pStardInfo->EndOfFile.QuadPart&(LONGLONG)(DATA_BLOCK_SIZE-1);
	Offset.QuadPart= pStardInfo->EndOfFile.QuadPart;

	if(nLeft!=0)
	{
		Offset.QuadPart-= nLeft;
		
		nLeft = (nLeft+15)&~((ULONG)15); 
		
		status = PfpReadFileByAllocatedIrp(pBuffer,nLeft,Offset,pFileObject,pNextDevice,&iostatusread);
		
		
		PfpEncryptBuffer(pBuffer,nLeft,&ase_en_context);
		OffsetWrite.QuadPart = (Offset.QuadPart+ENCRYPTIONHEADLENGTH);

		status = PfpWriteFileByAllocatedIrp(pBuffer,nLeft,OffsetWrite,pFileObject,pNextDevice,&iostatusread);
		
	}
	Length = DATA_BLOCK_SIZE;
	while((Offset.QuadPart- DATA_BLOCK_SIZE) >=0) 
	{					
				// 每次读取4k。
		// 读取旧文件。注意status。	

		Offset.QuadPart-=DATA_BLOCK_SIZE;
		
		status = PfpReadFileByAllocatedIrp(pBuffer,Length,Offset,pFileObject,pNextDevice,&iostatusread);
		

		if(!NT_SUCCESS(status))
		{
			break;			
		}	

		// 现在读取了内容。读出的长度为length.那么我写入的长度也应该是length。	
		PfpEncryptBuffer(pBuffer,Length,&ase_en_context);

		OffsetWrite.QuadPart = Offset.QuadPart+ENCRYPTIONHEADLENGTH;
		
		status = PfpWriteFileByAllocatedIrp(pBuffer,Length,OffsetWrite,pFileObject,pNextDevice,&iostatusread);
		
		if(!NT_SUCCESS(status))		
		{			
			break;
		}
	};

	ExFreePoolWithTag(pBuffer,'N601');
	ExFreePoolWithTag(pStardInfo,'2107');
	return NT_SUCCESS(status);
}
BOOLEAN		DoDecryptOnSameFile(HANDLE hFile,PFILE_OBJECT pFileObject,PDEVICE_OBJECT pNextDevice)
{
	NTSTATUS			status;
	IO_STATUS_BLOCK		iostatusread;
	PVOID				pBuffer;
	LARGE_INTEGER		Offset;
	LARGE_INTEGER		OffsetWrite;
	BOOLEAN				bLastBlock	= FALSE;
	LONG				Length		= 0;


	Offset.QuadPart = ENCRYPTIONHEADLENGTH;

	pBuffer  = ExAllocatePoolWithTag(NonPagedPool,DATA_BLOCK_SIZE,'N701');
	if(pBuffer  == NULL)
	{
		return FALSE;
	}

	OffsetWrite.QuadPart = 0;
	while(1) 
	{					
		Length = DATA_BLOCK_SIZE;		// 每次读取4k。
		// 读取旧文件。注意status。

		status = PfpReadFileByAllocatedIrp(pBuffer,Length,Offset,pFileObject,pNextDevice,&iostatusread);
		

		if(!NT_SUCCESS(status) && status != STATUS_END_OF_FILE)
		{
			break;			
		}	

		if(status == STATUS_END_OF_FILE)
		{
			break;
		}

		if(iostatusread.Information!= Length)
		{					
			bLastBlock = TRUE;
			iostatusread.Information=(iostatusread.Information+15)&~((ULONG)15);
		}
		// 现在读取了内容。读出的长度为length.那么我写入的长度也应该是length。	
		PfpDecryptBuffer(pBuffer,Length,&ase_den_context);

		status = PfpWriteFileByAllocatedIrp(pBuffer,(ULONG)iostatusread.Information,OffsetWrite,pFileObject,pNextDevice,&iostatusread);
		

		if(!NT_SUCCESS(status))		
		{			
			break;
		}
		if(bLastBlock)
		{
			break;
		}
		OffsetWrite.QuadPart+=Length;
		// offset移动，然后继续。直到出现STATUS_END_OF_FILE		
		// 的时候才结束。
		Offset.QuadPart += Length;

	};

	ExFreePool(pBuffer);

	return NT_SUCCESS(status);
}

BOOLEAN  IsFileDirectroy(PWCHAR szFullPathWithoutDeicve,ULONG nLenWchar, PDEVICE_OBJECT pDevice)
{
	BOOLEAN						bFile = FALSE;
	UNICODE_STRING				szFullPath;
	OBJECT_ATTRIBUTES			Objs;
	PDEVICE_OBJECT				pShadowDevice;
	PFILESPY_DEVICE_EXTENSION	pExt;
	
	BOOLEAN						bNetWorkDevice= FALSE;
	
	LONG					   lShadowNameLen =0;
	PWCHAR						pTemp = NULL;
	PWCHAR						pDirWithDeviceName = NULL;
	PWCHAR						pDirectoryName  = NULL;
	LONG						nIndex = 0;
	HANDLE						hParent = INVALID_HANDLE_VALUE;
	BOOLEAN						bReadOnly = FALSE;
	BOOLEAN						bDir      = FALSE;
	LONGLONG					nFileSize = 0;
	IO_STATUS_BLOCK				iostatus;
	NTSTATUS					ntstatus;
	if(szFullPathWithoutDeicve== NULL ||pDevice== NULL)
		return FALSE;


	pExt = (PFILESPY_DEVICE_EXTENSION)pDevice->DeviceExtension;

	ASSERT(!pExt ->bShadow);
 
	pShadowDevice = pExt ->pShadowDevice;

	ASSERT(pShadowDevice);

	bNetWorkDevice = (pDevice->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM);

	
	pExt = (PFILESPY_DEVICE_EXTENSION)pShadowDevice ->DeviceExtension;

	lShadowNameLen = bNetWorkDevice?pExt ->UserNames.Length:wcslen(pExt->DeviceNames)*sizeof(WCHAR);

	pDirWithDeviceName = ExAllocatePoolWithTag(PagedPool,lShadowNameLen+(nLenWchar+2)*sizeof(WCHAR),'3107');

	if(!pDirWithDeviceName)
		return bFile ;

	pTemp = (PWCHAR)pDirWithDeviceName;

	memcpy(pTemp ,bNetWorkDevice?pExt->UserNames.Buffer:pExt->DeviceNames,lShadowNameLen);

	pTemp += lShadowNameLen/sizeof(WCHAR);	

	memcpy(pTemp ,szFullPathWithoutDeicve,nLenWchar*sizeof(WCHAR));
	
	pDirWithDeviceName[nLenWchar+lShadowNameLen/sizeof(WCHAR)]=0;
	nIndex  = nLenWchar+lShadowNameLen/sizeof(WCHAR);
	nIndex--;
	while(nIndex >=0 && pDirWithDeviceName[nIndex]!=L'\\')
	{
		nIndex--;
	};
	if(nIndex>0)
	{
		pDirWithDeviceName[nIndex] =0;
		pDirectoryName = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(nLenWchar+lShadowNameLen/sizeof(WCHAR)-nIndex),'4107');
		if(pDirectoryName )
		{
			//nIndex++;
			memcpy(pDirectoryName,&pDirWithDeviceName[nIndex+1],sizeof(WCHAR)*(nLenWchar+lShadowNameLen/sizeof(WCHAR)-1-nIndex));
			pDirectoryName[nLenWchar+lShadowNameLen/sizeof(WCHAR)-1-nIndex] =0;
		}

	}else
	{
		if(pDirWithDeviceName)
		{
			ExFreePool(pDirWithDeviceName);
		}
		return bFile ;
	}
	

	RtlInitUnicodeString(&szFullPath,pDirWithDeviceName);
	InitializeObjectAttributes( &Objs,
								&szFullPath,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL );
	ntstatus = ZwCreateFile(&hParent ,
							FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,
							&Objs,
							&iostatus,									
							NULL,
							FILE_ATTRIBUTE_DIRECTORY ,
							FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
							FILE_OPEN,
							FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE,
							NULL,
							0);
	if(hParent!= INVALID_HANDLE_VALUE)
	{
		if(PfpFileExistInDir(((PFILESPY_DEVICE_EXTENSION)pDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject,
								hParent,pDirectoryName,&bReadOnly,&bDir,&nFileSize))
		{
			bFile = bDir;
		} 
		ZwClose(hParent);
	}
	if(pDirectoryName)
	{
		ExFreePool_A(pDirectoryName);
		pDirectoryName = NULL;
	}
 
	if(pDirWithDeviceName)
	{
		ExFreePool(pDirWithDeviceName);
	}
	return bFile ;

}


BOOLEAN  IsFileUnderDirecotry(PWCHAR pszDir,ULONG nLenChar,PWCHAR pFilePath,ULONG nLenCharFile)
{
	LONG nIndex = 0;
	if(nLenChar>=nLenCharFile) return FALSE;
	if(_wcsnicmp(pszDir,pFilePath,nLenChar)==0)
	{
		return (pFilePath[nLenChar]==L'\\');
	}
	return FALSE;
}

NTSTATUS
PfpQueryForLongName(IN WCHAR *pDirPath,
					IN ULONG nLenofChar,
					IN PDEVICE_OBJECT pDevice,
					IN OUT WCHAR** pOutFullPath/*,
					ULONG* pFolder_File_Unknow*/)
{
 
	NTSTATUS nstatus1;
	HANDLE hDir   = INVALID_HANDLE_VALUE;
	PWCHAR szSeprateor = NULL;
	PWCHAR pszDir = ExAllocatePoolWithTag(PagedPool,1024*sizeof(WCHAR),'5107');
	PFILE_OBJECT pDirObject = NULL;
	IO_STATUS_BLOCK  ioquery;
	PVOID pQueryDir =  NULL;
	UNICODE_STRING szDirtoryName;
	NTSTATUS ntStatus1 ;
	PWCHAR pBufferForOrg = NULL;
	PWCHAR pHead = NULL;

	pBufferForOrg = ExAllocatePoolWithTag(PagedPool,(nLenofChar+2)*sizeof(WCHAR),'6107');
	if(pBufferForOrg == NULL)
	{
		*pOutFullPath = NULL;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memcpy(pBufferForOrg,pDirPath,sizeof(WCHAR)*nLenofChar);
	pBufferForOrg[nLenofChar]=0;
	pHead = pBufferForOrg;
	if(pszDir == NULL)
	{
		ExFreePool_A(pBufferForOrg);
		*pOutFullPath = NULL;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	pQueryDir = ExAllocatePoolWithTag(PagedPool,(1024+sizeof(FILE_BOTH_DIR_INFORMATION))*sizeof(WCHAR),'7107');

	pszDir[0]=L'\\';pszDir[1]=0;
	while(*pHead!=0 && *pHead==L'\\')pHead++;

	while((szSeprateor =wcschr(pHead,L'\\'))!= NULL && szSeprateor[1]!=0  )
	{
		*szSeprateor = 0;
		if(wcslen(pHead)==8 && wcschr(pHead,L'~')!= NULL)
		{
			nstatus1=PfpOpenDirByShadowDevice(pszDir,&hDir,pDevice);
			if(hDir== INVALID_HANDLE_VALUE)
			{
				if(pszDir[wcslen(pszDir)-1]!=L'\\')
				{
					wcscat(pszDir,L"\\");
				}
				wcscat(pszDir,pHead);
				*pHead = 0;
				break;
			}

			RtlInitUnicodeString(&szDirtoryName,pHead);

			ntStatus1=ObReferenceObjectByHandle(hDir,FILE_LIST_DIRECTORY|FILE_TRAVERSE,*IoFileObjectType,KernelMode,&pDirObject,NULL);
			if(NT_SUCCESS(ntStatus1))
			{
				ntStatus1=  PfpQueryDirectoryByIrp(((PFILESPY_DEVICE_EXTENSION)pDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject,
													pDirObject,
													FileBothDirectoryInformation,
													pQueryDir,
													(1024+sizeof(FILE_BOTH_DIR_INFORMATION))*sizeof(WCHAR),
													&szDirtoryName,
													&ioquery
													);
				ObDereferenceObject(pDirObject);
				pDirObject = NULL;
			}
 
			ZwClose(hDir);

			if(pszDir[wcslen(pszDir)-1]!=L'\\')
			{
				wcscat(pszDir,L"\\");
			}
			if(NT_SUCCESS(ntStatus1))
			{
				wcsncat(pszDir,((PFILE_BOTH_DIR_INFORMATION) pQueryDir)->FileName,((PFILE_BOTH_DIR_INFORMATION) pQueryDir)->FileNameLength/sizeof(WCHAR));
				
				pHead = szSeprateor;
				pHead++;
			}else
			{
				*szSeprateor = L'\\';
				wcscat(pszDir,pHead);
				*pHead = 0;
				break;
			}
			
		}else
		{
			if(pszDir[wcslen(pszDir)-1]!=L'\\')
			{
				wcscat(pszDir,L"\\");
			}
			wcscat(pszDir,pHead);
			pHead = szSeprateor;
			pHead++;			 
		}		
	};
	if(*pHead != 0)
	{
		if(szSeprateor!= NULL)*szSeprateor = 0;
		if(wcslen(pHead)==8 && wcschr(pHead,L'~')!= NULL)
		{
			nstatus1=PfpOpenDirByShadowDevice(pszDir,&hDir,pDevice);
			if(hDir== INVALID_HANDLE_VALUE)
			{
				if(pszDir[wcslen(pszDir)-1]!=L'\\')
				{
					wcscat(pszDir,L"\\");
				}
				wcscat(pszDir,pHead);
			}
			else
			{
				RtlInitUnicodeString(&szDirtoryName,pHead);
				ntStatus1=ObReferenceObjectByHandle(hDir,FILE_LIST_DIRECTORY|FILE_TRAVERSE,*IoFileObjectType,KernelMode,&pDirObject,NULL);
				
				if(NT_SUCCESS(ntStatus1))
				{
					ntStatus1=  PfpQueryDirectoryByIrp(((PFILESPY_DEVICE_EXTENSION)pDevice->DeviceExtension)->NLExtHeader.AttachedToDeviceObject,
														pDirObject,
														FileBothDirectoryInformation,
														pQueryDir,
														(1024+sizeof(FILE_BOTH_DIR_INFORMATION))*sizeof(WCHAR),
														&szDirtoryName,
														&ioquery
														);
					ObDereferenceObject(pDirObject);
					pDirObject = NULL;
				}

				ZwClose(hDir);				 
					
				if(pszDir[wcslen(pszDir)-1]!=L'\\')
				{
					wcscat(pszDir,L"\\");
				}		 

				if(NT_SUCCESS(ntStatus1))
				{
					wcsncat(pszDir,((PFILE_BOTH_DIR_INFORMATION) pQueryDir)->FileName,((PFILE_BOTH_DIR_INFORMATION) pQueryDir)->FileNameLength/sizeof(WCHAR));
				}else
				{
					wcscat(pszDir,pHead);	
				}
				 
			}
		
		}else
		{
			if(pszDir[wcslen(pszDir)-1]!=L'\\')
			{
				wcscat(pszDir,L"\\");
			}	 
			wcscat(pszDir,pHead); 
		}
		if(szSeprateor)
		{
			wcscat(pszDir,L"\\");
		}
	} 

	if(pQueryDir)
	{
		ExFreePool_A(pQueryDir);
	}
	if(pBufferForOrg)
	{
		ExFreePool_A(pBufferForOrg);
	}
	*pOutFullPath = pszDir;

	return STATUS_SUCCESS;
}

NTSTATUS
	PfpFsdSetEa (
	IN PDEVICE_OBJECT VolumeDeviceObject,
	IN PIRP Irp
	)
{
		return STATUS_EAS_NOT_SUPPORTED;
}
NTSTATUS
	PfpFsdQueryEa (
	IN PDEVICE_OBJECT VolumeDeviceObject,
	IN PIRP Irp
	)
{
		return STATUS_EAS_NOT_SUPPORTED;
}
