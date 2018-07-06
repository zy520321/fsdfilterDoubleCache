
#include <ntifs.h>
#include <wdm.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "MD5.h"
#include <wdmsec.h>
#include "LOG.h"
#include "UsbSecure.h"
NTSTATUS
SpyCommonDeviceIoControl (
						  __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
						  __in ULONG InputBufferLength,
						  __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
						  __in ULONG OutputBufferLength,
						  __in ULONG IoControlCode,
						  __inout PIO_STATUS_BLOCK IoStatus
						  )
						  /*++

						  Routine Description:

						  This routine does the common processing of interpreting the Device IO
						  Control request.

						  Arguments:

						  FileObject - The file object related to this operation.

						  InputBuffer - The buffer containing the input parameters for this control
						  operation.

						  InputBufferLength - The length in bytes of InputBuffer.

						  OutputBuffer - The buffer to receive any output from this control operation.

						  OutputBufferLength - The length in bytes of OutputBuffer.

						  IoControlCode - The control code specifying what control operation this is.

						  IoStatus - Receives the status of this operation.

						  Return Value:

						  None.

						  --*/
{
	PWSTR deviceName = NULL;
	FILESPYVER fileSpyVer;

	PAGED_CODE();

	ASSERT( IoStatus != NULL );

	IoStatus->Status      = STATUS_SUCCESS;
	IoStatus->Information = 0;

	//
	//  As we access the input and output buffers below, note that we wrap
	//  these accesses with a try/except.  Even though all of FileSpy's private
	//  IOCTLs are METHOD_BUFFERED, this is necessary when handling FileSpy's
	//  IOCTLs via the FASTIO path.  When the FASTIO path is called, the IO
	//  Manager has not done the work to buffer the input buffer, output buffer
	//  or both buffers (as specified by the IOCTL definition).  This work will
	//  only be done if the IOCTLs is passed down the IRP path after FALSE has
	//  been returned via the FASTIO path.  Therefore, the user could have
	//  passed down a bad buffer and we must protect ourselves from that.
	//
	//  Note that we do not just wrap this entire routine with a try/except
	//  block because some of the helper routines will call back into
	//  the operating system (like SpyStartLoggingDevice and
	//  SpyStopLoggingDevice) and we do not want to mask any exceptions that
	//  were raised by other components along these paths.
	//

	FsRtlEnterFileSystem();
	switch (IoControlCode) 
	{
	case FILESPY_Reset:
		IoStatus->Status = STATUS_INVALID_PARAMETER;
		break;

		//
		//  Request to start logging on a device
		//

	case FILESPY_StartLoggingDevice:

		//
		//  Check for:
		//      No input buffer
		//      Input buffer to small
		//      Input buffer has odd length
		//

		if ((InputBuffer == NULL) ||
			(InputBufferLength < sizeof(WCHAR)) ||
			((InputBufferLength & 1) != 0))
		{

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}

		//
		//  Copy the device name and add a null to ensure that it is null
		//  terminated
		//

		deviceName =  ExAllocatePoolWithTag( NonPagedPool,
			InputBufferLength + sizeof(WCHAR),
			FILESPY_POOL_TAG );

		if (NULL == deviceName) 
		{

			IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		__try 
		{

			RtlCopyMemory( deviceName, InputBuffer, InputBufferLength );

		} 
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{

			IoStatus->Status = GetExceptionCode();
		}

		if (NT_SUCCESS( IoStatus->Status ))
		{

			deviceName[InputBufferLength / sizeof(WCHAR)] = UNICODE_NULL;
			IoStatus->Status = SpyStartLoggingDevice( deviceName );
		}
		break;

		//         //
		//         //  Detach from a specified device
		//         //
		// 
		//         case FILESPY_StopLoggingDevice:
		// 
		//             //
		//             //  Check for:
		//             //      No input buffer
		//             //      Input buffer to small
		//             //      Input buffer has odd length
		//             //
		// 
		//             if ((InputBuffer == NULL) ||
		//                 (InputBufferLength < sizeof(WCHAR)) ||
		//                 ((InputBufferLength & 1) != 0)) 
		// 			{
		// 
		//                 IoStatus->Status = STATUS_INVALID_PARAMETER;
		//                 break;
		//             }
		// 
		//             //
		//             //  Copy the device name and add a null to ensure that it is null
		//             //  terminated
		//             //
		// 
		//             deviceName =  ExAllocatePoolWithTag( NonPagedPool,
		//                                                  InputBufferLength + sizeof(WCHAR),
		//                                                  FILESPY_POOL_TAG );
		// 
		//             if (NULL == deviceName)
		// 			{
		// 
		//                 IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		//                 break;
		//             }
		// 
		//             try 
		// 			{
		// 
		//                 RtlCopyMemory( deviceName, InputBuffer, InputBufferLength );
		// 
		//             } except (EXCEPTION_EXECUTE_HANDLER) 
		// 			{
		// 
		//                 IoStatus->Status = GetExceptionCode();
		//             }
		// 
		//             if (NT_SUCCESS( IoStatus->Status ))
		// 			{
		// 
		//                 deviceName[InputBufferLength / sizeof(WCHAR)] = UNICODE_NULL;
		//                 IoStatus->Status = SpyStopLoggingDevice( deviceName );
		//             }
		// 
		//             break;


	case FILESPY_GetVer:

		if ((OutputBufferLength < sizeof(FILESPYVER)) ||
			(OutputBuffer == NULL)) 
		{

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}

		fileSpyVer.Major = FILESPY_MAJ_VERSION;
		fileSpyVer.Minor = FILESPY_MIN_VERSION;
		IoStatus->Information = sizeof(FILESPYVER);

		__try 
		{

			RtlCopyMemory(OutputBuffer, &fileSpyVer, sizeof(FILESPYVER));

		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{

			IoStatus->Status = GetExceptionCode();
			IoStatus->Information = 0;
		}

		break;

	case PFPCOMMAND_ModifyPSW:
		{
			MODIFYPSW *			pModify ;
			MD5_CTX				ctx;
			unsigned char		digestUsePsw[16]; 
			unsigned char		digestKeyPsw[16]; 
			PWCHAR				pMd5Buffer= NULL;
			aes_encrypt_ctx		ase_en_contextlocal;
			aes_decrypt_ctx		ase_de_contextlocal;
			UCHAR				KeyEncryptedContent[16]={0};

			if(InputBuffer== NULL|| InputBufferLength < sizeof(MODIFYPSW))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if ((OutputBuffer == NULL) ||(OutputBufferLength != sizeof(ULONG))) 
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}	
			*(ULONG*)OutputBuffer	= 0;
			pModify  = (PMODIFYPSW)InputBuffer;

			if(pModify  ->nModifyType==1)
			{//just modify user psw

				MD5Init(&ctx);
				pMd5Buffer	 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szUserName)+wcslen(pModify->szOldUserPSW)+1), 'abcd');
				if(pMd5Buffer	 == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}
				// 使用用户名和密码 解密 文件的头16个字节
				wcscpy(pMd5Buffer,pModify->szUserName);
				wcscat(pMd5Buffer,pModify->szOldUserPSW);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestUsePsw, &ctx);  
				if(memcmp(digestUsePsw,g_digestForUserPSW,16)!=0)
				{
					IoStatus->Status		= STATUS_INVALID_PARAMETER;
					*(ULONG*)OutputBuffer	= 1;//用户名或者密码不匹配
					goto exit11;
				}
				//1：使用原始的key的md5 值加密keycontent 
				//2：使用新的username和psw 的md5值 加密keycontent
				aes_decrypt_key128((unsigned char*)g_digestForUserPSW,&ase_de_contextlocal);

				memcpy(KeyEncryptedContent,g_pKeyFileContent,16);
				//使用原始的Keypassword 加密 
				if(!PfpDecryptBuffer(KeyEncryptedContent,16,&ase_de_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}
				ExFreePool(pMd5Buffer);
				pMd5Buffer = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szUserName)+wcslen(pModify->szNewUserPSW)+1), 'abcd');
				if(pMd5Buffer == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}

				wcscpy(pMd5Buffer,pModify->szUserName);
				wcscat(pMd5Buffer,pModify->szNewUserPSW);
				MD5Init(&ctx);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestUsePsw, &ctx);

				aes_encrypt_key128((unsigned char*)digestUsePsw,&ase_en_contextlocal);
				// 使用新的username和psw 加密
				if(!PfpEncryptBuffer(KeyEncryptedContent,16,&ase_en_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				if(g_KeyFilePath)
				{
					PVOID pFileContent  = NULL;
					ULONG  nFileLen		= 0;
					PfpGetKeyFileContent(g_KeyFilePath,&pFileContent,&nFileLen);
					if(nFileLen== 256 &&pFileContent )
					{
						memcpy(pFileContent,KeyEncryptedContent,16);
						if(PfpWriteKeyFileContent(g_KeyFilePath,pFileContent,256))
						{
							memcpy(g_digestForUserPSW,digestUsePsw,16);
							memcpy(g_pKeyFileContent,KeyEncryptedContent,16);
						}
						else
						{
							*(ULONG*)OutputBuffer	= 3;//key file 的路径不存在
						}

					}else
					{
						*(ULONG*)OutputBuffer	= 4;//key file 的路径不存在
					}
					if(pFileContent)
					{
						ExFreePool(pFileContent);
					}

				}else
				{
					*(ULONG*)OutputBuffer	= 2;//key file 的路径不存在
				}


			}else if(pModify  ->nModifyType==2)
			{



				MD5Init(&ctx);
				pMd5Buffer	 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szOldKeyPSW)+1), 'abcd');
				if(pMd5Buffer	 == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}
				// 使用用户名和密码 解密 文件的头16个字节
				wcscpy(pMd5Buffer,pModify->szOldKeyPSW);					
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestKeyPsw, &ctx);  
				if(memcmp(digestKeyPsw,g_digestForKeyPSW,16)!=0)
				{
					IoStatus->Status		= STATUS_INVALID_PARAMETER;
					*(ULONG*)OutputBuffer	= 4;//用户名或者密码不匹配
					goto exit11;
				}

				ExFreePool(pMd5Buffer);
				pMd5Buffer = ExAllocatePool(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szNewKeyPSW)+1));
				if(pMd5Buffer == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}

				wcscpy(pMd5Buffer,pModify->szNewKeyPSW);
				MD5Init(&ctx);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestKeyPsw, &ctx);
				//1：使用原始的key的md5 值加密keycontent 
				//2：使用新的username和psw 的md5值 加密keycontent
				aes_decrypt_key128((unsigned char*)g_digestForUserPSW,&ase_de_contextlocal);

				memcpy(KeyEncryptedContent,g_pKeyFileContent,16);
				//使用原始的Keypassword 加密 
				if(!PfpDecryptBuffer(KeyEncryptedContent,16,&ase_de_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				aes_decrypt_key128((unsigned char*)g_digestForKeyPSW,&ase_de_contextlocal);

				//memcpy(KeyEncryptedContent,g_pKeyFileContent,16);
				//使用原始的Keypassword 加密 
				if(!PfpDecryptBuffer(KeyEncryptedContent,16,&ase_de_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				aes_encrypt_key128((unsigned char*)digestKeyPsw,&ase_en_contextlocal);
				// 使用新的username和psw 加密
				if(!PfpEncryptBuffer(KeyEncryptedContent,16,&ase_en_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				aes_encrypt_key128((unsigned char*)g_digestForUserPSW,&ase_en_contextlocal);
				// 使用新的username和psw 加密
				if(!PfpEncryptBuffer(KeyEncryptedContent,16,&ase_en_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				if(g_KeyFilePath)
				{						
					PVOID pFileContent  = NULL;
					ULONG  nFileLen		= 0;
					PfpGetKeyFileContent(g_KeyFilePath,&pFileContent,&nFileLen);
					if(nFileLen== 256 &&pFileContent )
					{
						memcpy(pFileContent,KeyEncryptedContent,16);
						if(PfpWriteKeyFileContent(g_KeyFilePath,pFileContent,256))
						{
							memcpy(g_digestForKeyPSW,digestKeyPsw,16);
						}
						else
						{
							*(ULONG*)OutputBuffer	= 3;//key file 的路径不存在
						}

					}else
					{
						*(ULONG*)OutputBuffer	= 4;//key file 的路径不存在
					}
					if(pFileContent)
					{
						ExFreePool(pFileContent);
					}
				}else
				{
					*(ULONG*)OutputBuffer	= 2;//key file 的路径不存在
				}



			}else
			{
				MD5Init(&ctx);
				//verify username and psw
				pMd5Buffer	 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szUserName)+wcslen(pModify->szOldUserPSW)+1), 'abcd');
				if(pMd5Buffer	 == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}
				// 使用用户名和密码 解密 文件的头16个字节
				wcscpy(pMd5Buffer,pModify->szUserName);
				wcscat(pMd5Buffer,pModify->szOldUserPSW);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestUsePsw, &ctx);  
				if(memcmp(digestUsePsw,g_digestForUserPSW,16)!=0)
				{
					IoStatus->Status		= STATUS_INVALID_PARAMETER;
					*(ULONG*)OutputBuffer	= 1;//用户名或者密码不匹配
					goto exit11;
				}
				///
				//////////////////////////////////////////////////////////////////////////
				//verify key psw
				ExFreePool(pMd5Buffer);

				pMd5Buffer	 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szOldKeyPSW)+1), 'abcd');
				if(pMd5Buffer	 == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}
				// 使用用户名和密码 解密 文件的头16个字节
				wcscpy(pMd5Buffer,pModify->szOldKeyPSW);
				MD5Init(&ctx);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestKeyPsw, &ctx);  
				if(memcmp(digestKeyPsw,g_digestForKeyPSW,16)!=0)
				{
					IoStatus->Status		= STATUS_INVALID_PARAMETER;
					*(ULONG*)OutputBuffer	= 4;//用户名或者密码不匹配
					goto exit11;
				}



				//1：使用新的key的md5 值加密keycontent 
				//2：使用新的username和psw 的md5值 加密keycontent

				ExFreePool(pMd5Buffer);
				pMd5Buffer = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szNewKeyPSW)+1), 'abcd');
				if(pMd5Buffer == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}

				wcscpy(pMd5Buffer,pModify->szNewKeyPSW);
				MD5Init(&ctx);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestKeyPsw, &ctx);
				//1：使用原始的key的md5 值加密keycontent 
				//2：使用新的username和psw 的md5值 加密keycontent
				aes_decrypt_key128((unsigned char*)g_digestForUserPSW,&ase_de_contextlocal);

				memcpy(KeyEncryptedContent,g_pKeyFileContent,16);
				//使用原始的Keypassword 加密 
				if(!PfpDecryptBuffer(KeyEncryptedContent,16,&ase_de_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				aes_decrypt_key128((unsigned char*)g_digestForKeyPSW,&ase_de_contextlocal);


				//使用原始的Keypassword 加密 
				if(!PfpDecryptBuffer(KeyEncryptedContent,16,&ase_de_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}





				aes_encrypt_key128((unsigned char*)digestKeyPsw	,&ase_en_contextlocal);
				if(!PfpEncryptBuffer(KeyEncryptedContent,16,&ase_en_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}


				ExFreePool(pMd5Buffer);
				pMd5Buffer = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pModify->szUserName)+wcslen(pModify->szNewUserPSW)+1), 'abcd');
				if(pMd5Buffer == NULL)
				{
					IoStatus->Status = STATUS_INVALID_PARAMETER;
					goto exit11;
				}
				wcscpy(pMd5Buffer,pModify->szUserName);
				wcscat(pMd5Buffer,pModify->szNewUserPSW);
				MD5Init(&ctx);
				MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
				MD5Final (digestUsePsw, &ctx);

				aes_encrypt_key128((unsigned char*)digestUsePsw,&ase_en_contextlocal);
				// 使用新的username和psw 加密
				if(!PfpEncryptBuffer(KeyEncryptedContent,16,&ase_en_contextlocal))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit11;
				}

				if(g_KeyFilePath)
				{

					PVOID pFileContent  = NULL;
					ULONG  nFileLen		= 0;
					PfpGetKeyFileContent(g_KeyFilePath,&pFileContent,&nFileLen);
					if(nFileLen== 256 &&pFileContent )
					{
						memcpy(pFileContent,KeyEncryptedContent,16);
						if(PfpWriteKeyFileContent(g_KeyFilePath,pFileContent,256))
						{
							memcpy(g_digestForUserPSW,digestUsePsw,16);
							memcpy(g_digestForKeyPSW,digestKeyPsw,16);
						}
						else
						{
							*(ULONG*)OutputBuffer	= 3;//key file 的路径不存在
						}

					}else
					{
						*(ULONG*)OutputBuffer	= 4;//key file 的路径不存在
					}
					if(pFileContent)
					{
						ExFreePool(pFileContent);
					}

				}else
				{
					*(ULONG*)OutputBuffer	= 2;//key file 的路径不存在
				}

			}

exit11:		
			if(pMd5Buffer)
			{
				ExFreePool(pMd5Buffer);
			}
		}


		break;
	case PFPCOMMAND_DOLOGON:
		{

                        //OUTPUTBUFFER
                        //·1： 文件内容有问题
                        //2:参数不标准
                        //3：内存不够
                    
			PWCHAR			 pKeyFilePath,pUser,pPsw,pKeyPsw;
			MD5_CTX			 ctx;
			unsigned char	 digest[16]; 
			aes_decrypt_ctx	 ase_den_contextlocal;

			PWCHAR pBuffer		= (PWCHAR)InputBuffer;
			PWCHAR pHeadBuffer	= pBuffer;
			PVOID  pFileContent = NULL;
			ULONG  nFileLen		= 0;
			PVOID  pMd5Buffer	= NULL;
			PVOID  pSample		= NULL;
			BOOLEAN	bHasLogon   = FALSE;

			pKeyFilePath	= NULL;
			pPsw			= NULL;
			pUser			= NULL;
			pKeyPsw			= NULL;
                        
                        *(ULONG*)OutputBuffer = 0;
                        IoStatus->Information = sizeof(ULONG);
                        IoStatus->Status      = STATUS_SUCCESS;
            
			if ((InputBuffer == NULL) ||(InputBufferLength < sizeof(WCHAR))) 
			{
                                *(ULONG*)OutputBuffer = 2;
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			if ((OutputBuffer == NULL) ||(OutputBufferLength < sizeof(ULONG))) 
			{
                                *(ULONG*)OutputBuffer = 2;
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			

			bHasLogon  = (g_pKeyContent!= NULL);

                        //传递过来的文件路径
			pKeyFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pKeyFilePath== NULL)
			{
                            *(ULONG*)OutputBuffer = 3;
			    IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			    goto exit;
			}

			wcscpy(pKeyFilePath ,pBuffer);
			pBuffer+=wcslen(pKeyFilePath)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
                            *(ULONG*)OutputBuffer = 2; 
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}
                        //传递过来的用户名
			pUser = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pUser== NULL)
			{
                            *(ULONG*)OutputBuffer = 3;
			    IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			    goto exit;
			}
			wcscpy(pUser ,pBuffer);
			pBuffer+=wcslen(pUser)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
                            *(ULONG*)OutputBuffer = 2;
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}
                        //传递过来用户密码
			pPsw = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pPsw== NULL)
			{
                            *(ULONG*)OutputBuffer = 3;
			    IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			    goto exit;
			}
			wcscpy(pPsw ,pBuffer);
			pBuffer+=wcslen(pPsw)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
                            *(ULONG*)OutputBuffer = 2;
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}
                        //传递过来的 KeyFile的密码
			pKeyPsw = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pKeyPsw== NULL)
			{   
                            *(ULONG*)OutputBuffer = 3;
			    IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			    goto exit;
			}

			wcscpy(pKeyPsw ,pBuffer);

                        //得到keyfile 里面的原始内容
			PfpGetKeyFileContent(pKeyFilePath,&pFileContent,&nFileLen);
			if(nFileLen==0 || (nFileLen&(ULONG)15) !=0 ||nFileLen != 256)
			{
                             *(ULONG*)OutputBuffer = 1;
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}


                        
			if(g_pKeyFileContent== NULL)
			{
			    g_pKeyFileContent = ExAllocatePoolWithTag(PagedPool,16, 'abcd');
			    if(g_pKeyFileContent== NULL )
			    {
                                 *(ULONG*)OutputBuffer = 3;   
			        IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			        goto exit;
			    }
			}

			RtlCopyMemory(g_pKeyFileContent,pFileContent,16);
			g_keyFileLen = nFileLen;
			memcpy(g_VerifyValues,&((PUCHAR)pFileContent)[16],240);
			//////////////////////////////////////////////////////////////////////////

			MD5Init(&ctx);
			pMd5Buffer	 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pUser)+wcslen(pPsw)+1), 'abcd');
			if(pMd5Buffer	 == NULL)
			{
                            *(ULONG*)OutputBuffer = 2;   
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}
                        
                        ///////////////////////////////////////////////////////////
			// 使用用户名和密码 解密 文件的头16个字节

			wcscpy(pMd5Buffer,pUser);
			wcscat(pMd5Buffer,pPsw);
			MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
			MD5Final (digest, &ctx);  
			 
			memcpy(g_digestForUserPSW,digest,16);
			 
			aes_decrypt_key128((unsigned char*)digest,&ase_den_contextlocal);

			if(!PfpDecryptBuffer(pFileContent,16,&ase_den_contextlocal))
			{
                            *(ULONG*)OutputBuffer = 2;   
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}


			//////////////////////////////////////////////////////////////////////////
                        // 使用key 访问密码 解密 文件的头16个字节    
			MD5Init(&ctx);
			MD5Update (&ctx,(unsigned char *)pKeyPsw,wcslen(pKeyPsw)*sizeof(WCHAR));
			MD5Final (digest, &ctx);  
			 
			memcpy(g_digestForKeyPSW,digest,16);		

			aes_decrypt_key128((unsigned char*)digest,&ase_den_contextlocal);

			if(!PfpDecryptBuffer(pFileContent,16,&ase_den_contextlocal))
			{
                            *(ULONG*)OutputBuffer = 2;   
			    IoStatus->Status = STATUS_INVALID_PARAMETER;
			    goto exit;
			}

			{
                            //使用原始文件的头16个字节 
                            //1:用户名和密码的 MD5值 把16个字节解密
                            //2：在用keypassword的 MD值 继续把16个字节解密
                            //3:解密出来的内容作为加密的key 去加密240字节的内容为23的数组内容
                            //4:加密后的内容和原始文件内容里面的第16字节后面的240个字节的内容比较

			    aes_encrypt_ctx ase_en_contextlocal1;
			    pSample = ExAllocatePoolWithTag(PagedPool,240, 'abcd');
			    if(pSample== NULL)
			    {
                                *(ULONG*)OutputBuffer = 3;   
			        IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			        goto exit;
			    }
			    memset(pSample,23,240);

			    aes_encrypt_key128((unsigned char*)pFileContent,&ase_en_contextlocal1);

			    if(!PfpEncryptBuffer(pSample,240,&ase_en_contextlocal1))
			    {
                                *(ULONG*)OutputBuffer = 2;   
			        IoStatus->Status = STATUS_INVALID_PARAMETER;
			        goto exit;
			    }
			    if(memcmp((unsigned char*)pSample,&((unsigned char*)pFileContent)[16],240)!=0)
			    {
                                *(ULONG*)OutputBuffer = 2;   
                                IoStatus->Status = STATUS_INVALID_PARAMETER;
                                goto exit;
			    }
			}

			*(ULONG*)OutputBuffer = 1;//success
			IoStatus->Information = sizeof(ULONG);
			g_ExcludeID = GetExcludeProcessID(L"MsMpEng.exe");
			if(bHasLogon)
			{
			    goto exit;
			}
			//////////////////////////////////////////////////////////////////////////

			if(g_pKeyContent)
			{
			    ExFreePool(g_pKeyContent);
			}

			g_pKeyContent = ExAllocatePoolWithTag(PagedPool,16, 'abcd');

			if(g_pKeyContent== NULL )
			{
                            *(ULONG*)OutputBuffer = 3;   
                            IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
			    goto exit;
			}

			//////////////////////////////////////////////////////////////////////////
			//save this keyfile content
			//////////////////////////////////////////////////////////////////////////
			RtlCopyMemory(g_pKeyContent,pFileContent,16);
			RtlZeroMemory(pFileContent,nFileLen);
			//1:decrypt the file's content;

			g_keyLen = 16;

			aes_encrypt_key128((unsigned char*)g_pKeyContent,&ase_en_context);
			aes_decrypt_key128((unsigned char*)g_pKeyContent,&ase_den_context);
			
			if(pKeyFilePath)
			{
			    g_KeyFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(1+wcslen(pKeyFilePath)), 'abcd');
			    if(g_KeyFilePath != NULL)
			    {
				    wcscpy(g_KeyFilePath,pKeyFilePath);
			    }
			}
exit:			
			if(IoStatus->Status == STATUS_SUCCESS && !ExeHasLoggon)
			{
				g_ourProcessHandle = PsGetCurrentProcessId();
				ExeHasLoggon    = 1;
				PfpCreateMonitorThreadForUserModeExe();
			}

			if(pSample)
			{
				ExFreePool(pSample);
			}
			if(pFileContent)
			{
				ExFreePool(pFileContent);
			}
			if(pKeyFilePath)
			{
				ExFreePool(pKeyFilePath);
			}
			if(pPsw)
			{
				ExFreePool(pPsw);
			}
			if(pUser)
			{
				ExFreePool(pUser);
			}
			if(pKeyPsw)
			{
				ExFreePool(pKeyPsw);
			}
			if(pMd5Buffer)
			{
				ExFreePool(pMd5Buffer);
			}

		}
		break;



	case PFPCOMMAND_VIERIFYKEYFILE:			
		{
			PWCHAR pKeyFilePath,pUser,pPsw,pKeyPsw;
			MD5_CTX			 ctx;
			unsigned char	 digest[16]; 
			//aes_encrypt_ctx  ase_en_contextlocal;
			aes_decrypt_ctx	 ase_den_contextlocal;
			PWCHAR pBuffer		= (PWCHAR)InputBuffer;
			PWCHAR pHeadBuffer	= pBuffer;
			PVOID  pFileContent = NULL;
			ULONG  nFileLen		= 0;
			PVOID  pMd5Buffer	= NULL;
			PVOID  pSample		= NULL;


			pKeyFilePath	= NULL;
			pPsw			= NULL;
			pUser			= NULL;
			pKeyPsw			= NULL;
			if ((InputBuffer == NULL) ||
				(InputBufferLength < sizeof(WCHAR))
				) 
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if ((OutputBuffer == NULL) ||
				(OutputBufferLength < sizeof(ULONG))
				) 
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			*(ULONG*)OutputBuffer = 0;
			IoStatus->Information = sizeof(ULONG);

			pKeyFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pKeyFilePath== NULL )
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}

			wcscpy(pKeyFilePath ,pBuffer);
			pBuffer+=wcslen(pKeyFilePath)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT;
			}

			pUser = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pUser== NULL )
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pUser ,pBuffer);
			pBuffer+=wcslen(pUser)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT;
			}

			pPsw = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pPsw== NULL )
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pPsw ,pBuffer);
			pBuffer+=wcslen(pPsw)+1;

			if(sizeof(WCHAR)* (pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT;
			}
			pKeyPsw = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pKeyPsw== NULL )
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pKeyPsw ,pBuffer);

			PfpGetKeyFileContent(pKeyFilePath,&pFileContent,&nFileLen);
			if(nFileLen==0 || (nFileLen&(ULONG)15) !=0 ||nFileLen != 256)
			{
				IoStatus->Status = STATUS_SUCCESS;
				goto EXIT;
			}

			//////////////////////////////////////////////////////////////////////////
			//save this keyfile content
			//////////////////////////////////////////////////////////////////////////


			//////////////////////////////////////////////////////////////////////////

			MD5Init(&ctx);
			pMd5Buffer	 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pUser)+wcslen(pPsw)+1), 'abcd');
			if(pMd5Buffer	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}

			wcscpy(pMd5Buffer,pUser);
			wcscat(pMd5Buffer,pPsw);
			MD5Update (&ctx,(unsigned char *)pMd5Buffer,wcslen(pMd5Buffer)*sizeof(WCHAR));
			MD5Final (digest, &ctx);  

			aes_decrypt_key128((unsigned char*)digest,&ase_den_contextlocal);

			if(!PfpDecryptBuffer(pFileContent,16,&ase_den_contextlocal))
			{
				goto EXIT;
			}


			//////////////////////////////////////////////////////////////////////////

			MD5Init(&ctx);
			MD5Update (&ctx,(unsigned char *)pKeyPsw,wcslen(pKeyPsw)*sizeof(WCHAR));
			MD5Final (digest, &ctx);  


			//aes_encrypt_key128((unsigned char*)szPrivateKey,&ase_en_contextlocal);
			aes_decrypt_key128((unsigned char*)digest,&ase_den_contextlocal);
			if(!PfpDecryptBuffer(pFileContent,16,&ase_den_contextlocal))
			{
				goto EXIT;
			}

			{
				aes_encrypt_ctx ase_en_contextlocal1;
				pSample = ExAllocatePoolWithTag(PagedPool,240, 'abcd');
				if(pSample	 == NULL)
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit;
				}
				memset(pSample,23,240);
				aes_encrypt_key128((unsigned char*)pFileContent,&ase_en_contextlocal1);
				if(!PfpEncryptBuffer(pSample,240,&ase_en_contextlocal1))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto EXIT;
				}
				if(memcmp((unsigned char*)pSample,&((unsigned char*)pFileContent)[16],240)!=0)
				{
					IoStatus->Status = STATUS_SUCCESS;
					goto EXIT;
				}
			}

			*(ULONG*)OutputBuffer = 1;//success
			IoStatus->Information = sizeof(ULONG);


			RtlZeroMemory(pFileContent,nFileLen);
			//1:decrypt the file's content;

EXIT:			
			if(pSample)
			{
				ExFreePool(pSample);
			}
			if(pFileContent)
			{
				ExFreePool(pFileContent);
			}
			if(pKeyFilePath)
			{
				ExFreePool(pKeyFilePath);
			}
			if(pPsw)
			{
				ExFreePool(pPsw);
			}
			if(pUser)
			{
				ExFreePool(pUser);
			}
			if(pKeyPsw)
			{
				ExFreePool(pKeyPsw);
			}
			if(pMd5Buffer)
			{
				ExFreePool(pMd5Buffer);
			}

		}
		break;

	case PFPCOMMAND_GENKEYFILE:
		{
			PWCHAR pKeyFilePath,pQ1,pA1,pQ2,pA2,pUser,pPsw,pKeyPsw;
			MD5_CTX				ctx;
			unsigned char		digest[16]; 
			unsigned char		Keys[16]; 
			aes_encrypt_ctx		ase_en_contextlocal;
			//aes_decrypt_ctx		ase_den_contextlocal;
			PWCHAR pBuffer		= (PWCHAR)InputBuffer;
			PVOID  pSample		= NULL;
			PWCHAR pHeadBuffer	= pBuffer;
			PVOID  pFileContent = NULL;
			ULONG  nFileLen		= 0;

			PVOID  pUserAndPsw	= NULL;


			pKeyFilePath	= NULL;
			pPsw			= NULL;
			pUser			= NULL;
			pKeyPsw			= NULL;
			if ((InputBuffer == NULL) ||(InputBufferLength < sizeof(WCHAR))) 
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			if ((OutputBuffer == NULL) ||(OutputBufferLength < sizeof(ULONG))) 
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			*(ULONG*)OutputBuffer = 0;
			IoStatus->Information = sizeof(ULONG);


			pKeyFilePath = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pKeyFilePath	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pKeyFilePath ,pBuffer);
			pBuffer+=wcslen(pKeyFilePath)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}

			pQ1 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pQ1	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pQ1 ,pBuffer);
			pBuffer+=wcslen(pQ1)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}
			pA1 = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pA1	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pA1 ,pBuffer);
			pBuffer+=wcslen(pA1)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer) > InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}
			pQ2 = ExAllocatePool(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1));
			if(pQ2	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pQ2 ,pBuffer);
			pBuffer+=wcslen(pQ2)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}

			pA2 = ExAllocatePool(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1));
			if(pA2	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pA2 ,pBuffer);
			pBuffer+=wcslen(pA2)+1;

			if(sizeof(WCHAR)* (pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}

			pKeyPsw = ExAllocatePoolWithTag(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1), 'abcd');
			if(pKeyPsw	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pKeyPsw ,pBuffer);
			pBuffer+=wcslen(pKeyPsw)+1;

			if( sizeof(WCHAR)*(pBuffer-pHeadBuffer)>InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}

			pUser = ExAllocatePool(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1));
			if(pUser	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pUser ,pBuffer);
			pBuffer+=wcslen(pUser)+1;

			if(  sizeof(WCHAR)*(pBuffer-pHeadBuffer) > InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto EXIT1;
			}

			pPsw = ExAllocatePool(PagedPool,sizeof(WCHAR)*(wcslen(pBuffer)+1));
			if(pPsw	 == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto exit;
			}
			wcscpy(pPsw ,pBuffer);


			pFileContent = ExAllocatePool(PagedPool,nFileLen=(sizeof(WCHAR)*(4+wcslen(pQ1)+wcslen(pA1)+wcslen(pQ2)+wcslen(pA2))));

			if(pFileContent == NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}

			MD5Init(&ctx);
			MD5Update (&ctx,(unsigned char*)pKeyPsw,wcslen(pKeyPsw)*sizeof(WCHAR));
			MD5Final (digest, &ctx);  

			aes_encrypt_key128((unsigned char*)digest,&ase_en_contextlocal);

			wcscpy(pFileContent,pQ1);
			wcscat(pFileContent,pA1);
			wcscat(pFileContent,pQ2);
			wcscat(pFileContent,pA2);
			MD5Init(&ctx);
			MD5Update (&ctx,(unsigned char *)pFileContent,wcslen(pFileContent)*sizeof(WCHAR));
			MD5Final (Keys, &ctx);  

			{
				aes_encrypt_ctx ase_en_contextlocal1;
				pSample = ExAllocatePool(PagedPool,256);
				if(pSample == NULL)
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto EXIT1;
				}
				memset(&((unsigned char*)pSample)[16],23,256-16);
				aes_encrypt_key128((unsigned char*)Keys,&ase_en_contextlocal1);
				//用问题和答案 MD5值 加密  sample 值
				if(!PfpEncryptBuffer(&((unsigned char*)pSample)[16],240,&ase_en_contextlocal1))
				{
					IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
					goto EXIT1;
				}
			}
			//用Key文件的访问密码的MD5值加密 问题和答案的MD5值
			if(!PfpEncryptBuffer(Keys,16,&ase_en_contextlocal))
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}

			pUserAndPsw = ExAllocatePool(PagedPool,sizeof(WCHAR)*(wcslen(pUser)+wcslen(pPsw)+1));
			if(pUserAndPsw== NULL)
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}
			wcscpy(pUserAndPsw,pUser);
			wcscat(pUserAndPsw,pPsw);

			MD5Init(&ctx);
			MD5Update (&ctx,(unsigned char *)pUserAndPsw,wcslen(pUserAndPsw)*sizeof(WCHAR));
			MD5Final (digest, &ctx);  
			aes_encrypt_key128((unsigned char*)digest,&ase_en_contextlocal);
			//用户名和密码 的MD5值 加密 （用Key文件的访问密码的MD5值加密 问题和答案的MD5值）的值
			if(!PfpEncryptBuffer(Keys,16,&ase_en_contextlocal))
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}

			memcpy(pSample,Keys,16);
			if(!PfpWriteKeyFileContent(pKeyFilePath,pSample,256))
			{
				IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
				goto EXIT1;
			}

			*(ULONG*)OutputBuffer = 1;//success
			IoStatus->Information = sizeof(ULONG);
			//////////////////////////////////////////////////////////////////////////
			//////////////////////////////////////////////////////////////////////////
EXIT1:
			if(pSample)
			{
				ExFreePool(pSample);
			}
			if(pFileContent)
			{
				ExFreePool(pFileContent);
			}
			if(pKeyFilePath)
			{
				ExFreePool(pKeyFilePath);
			}
			if(pQ1)
			{
				ExFreePool(pQ1);
			}
			if(pQ2)
			{
				ExFreePool(pQ2);
			}
			if(pA1)
			{
				ExFreePool(pA1);
			}
			if(pA2)
			{
				ExFreePool(pA2);
			}
			if(pPsw)
			{
				ExFreePool(pPsw);
			}
			if(pUser)
			{
				ExFreePool(pUser);
			}
			if(pKeyPsw)
			{
				ExFreePool(pKeyPsw);
			}

			if(pUserAndPsw)
			{
				ExFreePool(pUserAndPsw);
			}

		}
		break;
	case PFPCOMMAND_AddPrograms://get apps from the input buffer and record into buffer 
		// 1:check if this file has already exist
		// 2:new a memory block to store the information for filter a applicate operation to files.
		// 3:insert this memory pointer into golbal listentry.
		// 4:set the modify flag.
		// return success.

		IoStatus->Status = STATUS_INVALID_PARAMETER;
		break;
		if (InputBuffer == NULL|| InputBufferLength<sizeof(ConfigData)||OutputBuffer == NULL|| OutputBufferLength<sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;

		}else
		{
			*(ULONG*)OutputBuffer = 1;
			IoStatus->Information = sizeof(ULONG);
			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);

			__try
			{
				AddProcessInfoIntoGlobal((PConfigData)InputBuffer);		
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				IoStatus->Status = GetExceptionCode();
				*(ULONG*)OutputBuffer = 0;
				IoStatus->Information =  sizeof(ULONG);
			}

			ExReleaseResourceLite(&g_ProcessInfoResource);
		}

		break;
	case PFPCOMMAND_HASLOGGEDON://get apps from the input buffer and record into buffer 
		// 1:check if this file has already exist
		// 2:new a memory block to store the information for filter a applicate operation to files.
		// 3:insert this memory pointer into golbal listentry.
		// 4:set the modify flag.
		// return success.

		if (OutputBuffer == NULL|| OutputBufferLength<sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;

		}else
		{
			*(ULONG*)OutputBuffer =(g_pKeyContent!= NULL);
		}

		break;
	case PFPCOMMAND_DeleteProgram  :
		{
			BOOLEAN bSuc = FALSE;


			if (OutputBuffer == NULL|| OutputBufferLength<sizeof(ULONG) ||InputBuffer == NULL|| InputBufferLength!=PROCESSHASHVALULENGTH)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
			else
			{	
				ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
				__try
				{
					bSuc =  PfpDelProcessInfo(InputBuffer,PROCESSHASHVALULENGTH);	
					*(ULONG*)OutputBuffer = (bSuc?1:0);
					IoStatus->Information = sizeof(ULONG);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					IoStatus->Status		= GetExceptionCode();
					IoStatus->Information	= 0;
				}

				ExReleaseResourceLite(&g_ProcessInfoResource);
			}
		}
		break;
	case PFPCOMMAND_DeletePrograms  :
		//1:check if this program does exist.
		//2:if exist, find the entry from global listentry
		//3:delete the entry from global listentry.
		//4:set the modifiction flag.
		// return success.
		{
			BOOLEAN bSuc = FALSE;
			if (OutputBuffer == NULL|| OutputBufferLength<sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
			else
			{	
				ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);

				__try
				{
					bSuc =  PfpClearAllProcInfos();	
					*(ULONG*)OutputBuffer = (bSuc?1:0);
					IoStatus->Information = sizeof(ULONG);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					IoStatus->Status = GetExceptionCode();
					IoStatus->Information = 0;
				}

				ExReleaseResourceLite(&g_ProcessInfoResource);


			}
		}
		break;
	case PFPCOMMAND_GetPrograms	   :
		//1:get the length of buffer to store the apps filtered by our driver.
		// if the length is 0,so the user just send a request for the length of all filtered apps.
		// just return the length we need.
		//2:just copy as much as the amount the buffer can hold.
		//return success.


		if(OutputBuffer == NULL|| OutputBufferLength==0)
		{
			IoStatus->Status = STATUS_MORE_PROCESSING_REQUIRED ;

			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Information = PfpCalcProgramLen();

			ExReleaseResourceLite(&g_ProcessInfoResource);
		}else
		{
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);

			__try
			{
				ULONG nLenCopyed = 0;
				IoStatus->Information =OutputBufferLength;
				
				PfpCopyAllProgramsIntoBuffer(OutputBuffer,&nLenCopyed );
				IoStatus->Information =nLenCopyed;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				IoStatus->Status = GetExceptionCode();
				IoStatus->Information = 0;
			}		
			ExReleaseResourceLite(&g_ProcessInfoResource);
		}


		break;
	case PFPCOMMAND_GetProgramsLen:
		if(OutputBuffer == NULL|| OutputBufferLength<sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
		}else
		{
			IoStatus->Information = sizeof(ULONG);
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			*(ULONG*)OutputBuffer = PfpCalcProgramLen();
			ExReleaseResourceLite(&g_ProcessInfoResource);
		}

		break;
	case PFPCOMMAND_SaveConfigInformation:
		// clear all data in file, and write all data from head into the config file.
		// return success.

		IoStatus->Status = PfpSaveSystemSettingsEx();

		break;
	case PFPCOMMAND_LoadConfigInformation:
		// clear all data in file, and write all data from head into the config file.
		// return success.
		{

			if(g_bInitialized)
			{
				break;
			}
			if ((InputBufferLength < sizeof(HANDLE)) ||(InputBuffer == NULL)) 
			{

				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_bInitialized = TRUE;

			IoStatus->Status = PfpInitSystemSettings(*(HANDLE*)InputBuffer);
		}
		break;
	case PFPCOMMAND_ClearAllConfigInformation:
		//set the file size of config file to 0;
		// return success.

		break;

	case PFPCOMMAND_StartDriver:
		if(g_pKeyContent!= NULL && g_keyLen==16)
			g_nRunningState = (ULONG )TRUE;
		break;

	case PFPCOMMAND_StopDriver:

		if ((OutputBufferLength < sizeof(ULONG)) ||(OutputBuffer == NULL)) 
		{

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		{
			*(ULONG*)OutputBuffer=0;
			IoStatus->Information = sizeof(ULONG);
			g_nRunningState = (ULONG )FALSE;
		}
		break;
	case PFPCOMMAND_CANStopDriver:

		if ((OutputBufferLength < sizeof(ULONG)) ||
			(OutputBuffer == NULL)) 
		{

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}

		IoStatus->Information = sizeof(ULONG);
		*(ULONG*)OutputBuffer = (PfpGetFileOpenCount()==0)?1:0;


		break;

	case PFPCOMMAND_SETHIDE:
		if(InputBuffer== NULL ||InputBufferLength !=sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;		
		}
		g_nHIDEState = *(ULONG*)InputBuffer;
		break;
	case 	PFPCOMMAND_QueryHIDE:
		if ((OutputBufferLength < sizeof(ULONG)) ||
			(OutputBuffer == NULL)) 
		{

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		__try 
		{
			IoStatus->Information = sizeof(ULONG);
			RtlCopyMemory(OutputBuffer, &g_nHIDEState, sizeof(ULONG ));

		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{

			IoStatus->Status = GetExceptionCode();
			IoStatus->Information = 0;
		}
		break;
	case PFPCOMMAND_QueryState:

		if ((OutputBufferLength < sizeof(ULONG)) ||
			(OutputBuffer == NULL)) 
		{

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PfpGetRunState(OutputBuffer,IoStatus);

		break;

	case CDO_ADD_FILE:
		if(InputBuffer== NULL ||InputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;		
		}
		AddHideObject(InputBuffer, CDO_FLAG_FILE);
		break;
	case CDO_ADD_DIRECTORY:
		if(InputBuffer== NULL ||InputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;		
		}
		AddHideObject(InputBuffer, CDO_FLAG_DIRECTORY);
		break;
	case CDO_REMOVE_FILE:
		if(InputBuffer== NULL ||InputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;		
		}
		DelHideObject(InputBuffer, CDO_FLAG_FILE);
	case CDO_REMOVE_DIRECTORY:
		if(InputBuffer== NULL ||InputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;		
		}
		DelHideObject(InputBuffer, CDO_FLAG_DIRECTORY);
		break;

	case PFPCOMMAND_SETBACKUPDIR:
		if(InputBuffer== NULL ||InputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;		
		}
		PfpSetBackUpDir(InputBuffer,InputBufferLength);

		break;

	case PFPCOMMAND_GETBACKUPDIR:
		if(OutputBuffer== NULL ||OutputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}

		PfpGetBackUpDir(OutputBuffer,OutputBufferLength,IoStatus);
		break;

	case CDO_GET_FILES_LEN:
		if(OutputBuffer== NULL ||OutputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PfpGetHideLen(OutputBuffer,IoStatus,CDO_FLAG_FILE);
		break;

	case CDO_GET_DIRECTORYS_LEN:
		if(OutputBuffer== NULL ||OutputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PfpGetHideLen(OutputBuffer,IoStatus,CDO_FLAG_DIRECTORY);
		break;

	case CDO_GET_DIRECTORYS:
		if(OutputBuffer== NULL ||OutputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PfpGetHides(OutputBuffer,OutputBufferLength,IoStatus,CDO_FLAG_DIRECTORY);
		break;
	case CDO_GET_FILES:
		if(OutputBuffer== NULL ||OutputBufferLength ==0)
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		PfpGetHides(OutputBuffer,OutputBufferLength,IoStatus,CDO_FLAG_FILE);
		break;
	case CDO_SETBACKUP_FOR_PROCESS_FILETYPE:
		{
			PBACKUPSETTING pBackUpSetting= NULL;
			PPROCESSINFO pProcInfo=  NULL;
			if(OutputBuffer== NULL ||OutputBufferLength !=sizeof(LONG)||InputBuffer == NULL||InputBufferLength <sizeof(BackUpSetting))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pBackUpSetting = (PBACKUPSETTING) InputBuffer;

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);

			__try
			{
				pProcInfo = PfpGetProcessInfoUsingHashValue(pBackUpSetting->HashValue,PROCESSHASHVALULENGTH,NULL);
				if(pProcInfo)
				{
					*(ULONG*)OutputBuffer = PfpSetBackupForProcess(pProcInfo,pBackUpSetting);
					InterlockedDecrement(&pProcInfo->nRef);
				}else
				{
					*(ULONG*)OutputBuffer = 0;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				IoStatus->Status = GetExceptionCode();
				*(ULONG*)OutputBuffer = 0;					
			}

			ExReleaseResourceLite(&g_ProcessInfoResource);
			IoStatus->Information= sizeof(ULONG);

		}
		break;
	case CDO_GETBACKUP_FOR_PROCESS_FILETYPE:

		{
			PBACKUPSETTING  pBackUpSetting	= NULL;
			PPROCESSINFO	pProcInfo		= NULL;
			if(OutputBuffer== NULL ||OutputBufferLength !=sizeof(LONG)||InputBuffer == NULL||InputBufferLength <sizeof(BackUpSetting))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pBackUpSetting	= (PBACKUPSETTING)InputBuffer;

			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			pProcInfo = PfpGetProcessInfoUsingHashValue(pBackUpSetting->HashValue,PROCESSHASHVALULENGTH,NULL);
			if(pProcInfo)
			{
				*(ULONG*) OutputBuffer	= PfpGetBackupInfoFromProg(pProcInfo,pBackUpSetting);
				InterlockedDecrement(&pProcInfo->nRef);
			}else
			{
				*(ULONG*) OutputBuffer = 0;
			}

			ExReleaseResourceLite(&g_ProcessInfoResource);

			IoStatus->Information	= sizeof(ULONG);
		}

		break;
	case PFPCOMMAND_ENADNDEBUFFER:
		{
		 
			if(InputBuffer == NULL||InputBufferLength<16)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}	
			if(InputBufferLength&15)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			if(!PfpEncryptBuffer(InputBuffer,InputBufferLength,&ase_en_context))
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			 
		}
		break;
	case PFPCOMMAND_DEBUFFER :
		{
			if(InputBuffer == NULL||InputBufferLength<16)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}	
			if(InputBufferLength&15)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if(!PfpDecryptBuffer(InputBuffer,InputBufferLength,&ase_den_context))
				IoStatus->Status = STATUS_INVALID_PARAMETER;
		}
		break;
	case PFPCOMMAND_ISFOLDERPROTECTED:
		{
			WCHAR* pFolderProtect = NULL;
			if(InputBuffer == NULL|| InputBufferLength ==0||
				OutputBuffer== NULL ||OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}	
			pFolderProtect  = ExAllocatePool(PagedPool,InputBufferLength+sizeof(WCHAR));
			if(pFolderProtect  == NULL)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			memcpy(pFolderProtect  ,InputBuffer,InputBufferLength);
			pFolderProtect  [InputBufferLength/sizeof(WCHAR)] =0;
			
			 
			ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
			*(ULONG*)OutputBuffer = IsFolderUnderProtect(pFolderProtect,wcslen(pFolderProtect))?1:0;
			ExReleaseResourceLite(&g_FolderResource);
			 
			IoStatus->Information = sizeof(ULONG);

			ExFreePool(pFolderProtect);


		}
		break;
	case PFPCOMMAND_FOLDERPROTECTED:
		break;
	case PFPCOMMAND_QUERYFOLDERPROTECTEDLEN:
		{
			if(OutputBuffer== NULL||OutputBufferLength != sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			ExAcquireResourceSharedLite(&g_FolderResource,TRUE);

			*(ULONG*)OutputBuffer=CalcFolderProctectionLen();

			ExReleaseResourceLite(&g_FolderResource);
		 
			 
			IoStatus->Information = sizeof(ULONG); 
		}
		break;

	case	PFPCOMMAND_LOCKFOLDERS:
		{
			if(InputBuffer== NULL||InputBufferLength==0||OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			*((ULONG*)OutputBuffer) = SetLockFolderState(InputBuffer,InputBufferLength,LOCKED);
			ExReleaseResourceLite(&g_FolderResource);
			
			 
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_UNLOCKFOLDERS:
		{
			if(InputBuffer== NULL||InputBufferLength==0||OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			
			*((ULONG*)OutputBuffer) = SetLockFolderState(InputBuffer,InputBufferLength,UNLOCK);
			ExReleaseResourceLite(&g_FolderResource);
			 
			IoStatus->Information = sizeof(ULONG);

		}
		break;
	case PFPCOMMAND_QUERY_ALL_FOLDERPROTECTED:
		{
			if(OutputBuffer== NULL||OutputBufferLength==0)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
		 
			ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
			IoStatus->Information = CopyFolderItemsIntoUserBuffer(OutputBuffer,OutputBufferLength);
			ExReleaseResourceLite(&g_FolderResource);
			 
		}
		break;
	case PFPCOMMAND_QUERYHIDERLEN:
		{
			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			
			ExAcquireResourceSharedLite(&g_HideEresource,TRUE);
			*(ULONG*)OutputBuffer = CalcHidderLen();
			ExReleaseResourceLite(&g_HideEresource);

			 
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GETHIDDER:
		{
			if(OutputBuffer== NULL||OutputBufferLength==0)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			ExAcquireResourceSharedLite(&g_HideEresource,TRUE);
			IoStatus->Information = CopyHidderIntoBuffer(OutputBuffer,OutputBufferLength);
			ExReleaseResourceLite(&g_HideEresource);
			 
		}
		break;
	case PFPCOMMAND_SETSYSProtect:
		{
			if(InputBuffer== NULL||InputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_bProtectSySself = (*(ULONG*)InputBuffer)==0?FALSE:TRUE;

		}
		break;
	case PFPCOMMAND_QUERYSYSProtect:
		{
			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			(*(ULONG*)OutputBuffer)= g_bProtectSySself?1:0;				
		}
		break;


	case PFPCOMMAND_SETLogEnable:
		{
			if(InputBuffer== NULL||InputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_bLog = (*(ULONG*)InputBuffer)==0?FALSE:TRUE;

		}
		break;
	case PFPCOMMAND_QUERYLogStatus:
		{
			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			(*(ULONG*)OutputBuffer)= g_bLog?1:0;				
		}
		break;
	case PFPCOMMAND_SETUDISKENCRYPT:
		{
			if(InputBuffer== NULL||InputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_bEncrypteUDISK = (*(ULONG*)InputBuffer)==0?FALSE:TRUE;

		}
		break;
	case PFPCOMMAND_QUERYUDISKENCRYPT:
		{
			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			(*(ULONG*)OutputBuffer)= g_bEncrypteUDISK?1:0;

		}
		break;
	case PFPCOMMAND_SendReCyclePath:
		{
			PWCHAR szPaths = NULL;
			PWCHAR szTemp  = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(WCHAR)*3)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			szPaths = (PWCHAR)InputBuffer;
			memcpy(szRootforCycle,szPaths,4);
			ASSERT(szPaths[2]== L'|');
			szPaths+=3;

			ExAcquireFastMutex(&g_fastRecycle);
			ClearAllRecycleList();
			while( *szPaths!= L'\0'  && (szTemp=wcschr(szPaths,L'|')))
			{
				*szTemp = L'\0';
				AddIntoRecycleList(szPaths);
				szPaths= (++szTemp);
			};

			ExReleaseFastMutex(&g_fastRecycle);
		}
		break;
	case PFPCOMMAND_ENABLE_PROCESS_BACKUP:
		{
			EnableProc* pEnabler = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(EnableProc))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);

			pEnabler =(EnableProc*)InputBuffer;
			IoStatus->Information  = sizeof(ULONG);
			PfpEnableBackupForProg(pEnabler->HashValue,pEnabler->bEnable);
			*(ULONG*) OutputBuffer = TRUE;

			ExReleaseResourceLite(&g_ProcessInfoResource);
		}
		break;
	case PFPCOMMAND_ENABLE_PROCESS_ENCRYPT:
		{
			EnableProc* pEnabler = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(EnableProc))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);

			pEnabler =(EnableProc*)InputBuffer;
			IoStatus->Information  = sizeof(ULONG);
			PfpEnableEnCryptForProg(pEnabler->HashValue,pEnabler->bEnable);
			*(ULONG*) OutputBuffer = TRUE;

			ExReleaseResourceLite(&g_ProcessInfoResource);
		}
		break;
	case PFPCOMMAND_ENABLE_PROCESS_INHER:
		{
			EnableProc* pEnabler = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(EnableProc))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);

			pEnabler =(EnableProc*)InputBuffer;
			IoStatus->Information  = sizeof(ULONG);
			PfpEnableInherForProg(pEnabler->HashValue,pEnabler->bEnable);
			*(ULONG*) OutputBuffer = TRUE;

			ExReleaseResourceLite(&g_ProcessInfoResource);
		}
	case PFPCOMMAND_READ_LOG:
		{
			// 				if(OutputBuffer== NULL||OutputBufferLength!=512)
			// 				{
			// 					IoStatus->Status = STATUS_INVALID_PARAMETER;
			// 					break;
			// 				}
			// 				if(!GetLogInfoFromQue((WCHAR*)OutputBuffer,OutputBufferLength))
			// 					IoStatus->Status  = STATUS_NO_MORE_FILES;
			// 
			// 				IoStatus->Information = OutputBufferLength;
		}
		break;
	case PFPCOMMAND_LOGEVENT_HANDLE:
		{
			NTSTATUS status;
			UNICODE_STRING UnicodeName; 
			WCHAR UnicodeBuffer[128] = L"\\BaseNamedObjects\\PfpLogEvent"; 
			HANDLE pEventHandle = INVALID_HANDLE_VALUE;
			OBJECT_ATTRIBUTES objattri;
			RtlInitUnicodeString(&UnicodeName, UnicodeBuffer); 
			 
			if(InputBuffer == NULL||InputBufferLength!=sizeof(LARGE_INTEGER)||OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if(g_LogEvent!= NULL)
			{

				break;
			} 
			//if(sizeof(HANDLE)==4)
			//{
				 
// 			}else
// 			{
// 				pEventHandle = (HANDLE)((LARGE_INTEGER*)InputBuffer)->QuadPart;
// 			}
			
			InitializeObjectAttributes(&objattri,
				&UnicodeName,
				OBJ_CASE_INSENSITIVE |OBJ_KERNEL_HANDLE,
				NULL,
				NULL
				);
			status =ZwOpenEvent(&pEventHandle,EVENT_ALL_ACCESS,&objattri);
			if(!NT_SUCCESS(status ))
			{
				IoStatus->Information  = sizeof(ULONG);	 
				*(ULONG*) OutputBuffer = status;				 
				g_UsbDeviceSignal = NULL;
				break;				
			}


			status = ObReferenceObjectByHandle( pEventHandle,
				SYNCHRONIZE,
				*ExEventObjectType,
				KernelMode,
				&g_LogEvent,
				NULL);

			IoStatus->Information  = sizeof(ULONG);	 
			*(ULONG*) OutputBuffer = status;

			if(!NT_SUCCESS(status))
			{
				g_LogEvent = NULL;
			}

		}

		break;

	case PFPCOMMAND_USBEVENT_HANDLE:
		{
			NTSTATUS status;
			UNICODE_STRING UnicodeName; 
			WCHAR UnicodeBuffer[128] = L"\\BaseNamedObjects\\PfpUsbEvent"; 
			HANDLE pEventHandle = INVALID_HANDLE_VALUE;
			OBJECT_ATTRIBUTES objattri;
			ULONG majorver,minver,buildnumber;
			RtlInitUnicodeString(&UnicodeName, UnicodeBuffer); 
			//UnicodeName.MaximumLength = 128; 
			
			
			PsGetVersion(&majorver,&minver,&buildnumber,NULL);
			if(InputBuffer == NULL||InputBufferLength!=sizeof(LARGE_INTEGER)||OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if(g_UsbDeviceSignal!= NULL)
			{

				break;
			} 
		 
			InitializeObjectAttributes(&objattri,
			  								&UnicodeName,
			  								OBJ_CASE_INSENSITIVE |OBJ_KERNEL_HANDLE,
			  								NULL,
			  								NULL
			  								);
			status =ZwOpenEvent(&pEventHandle,EVENT_ALL_ACCESS,&objattri);
			if(!NT_SUCCESS(status ))
			{
				IoStatus->Information  = sizeof(ULONG);	 
				*(ULONG*) OutputBuffer = status;				 
				g_UsbDeviceSignal = NULL;
				break;				
			}

			status = ObReferenceObjectByHandle(pEventHandle,
											SYNCHRONIZE,
											*ExEventObjectType,
											KernelMode,
											&g_UsbDeviceSignal,
											NULL);
			ZwClose(pEventHandle);

			IoStatus->Information  = sizeof(ULONG);	 
			*(ULONG*) OutputBuffer = status;

			if(!NT_SUCCESS(status))
			{
				g_UsbDeviceSignal = NULL;
			}

		}

		break;
	case PFPCOMMAND_SetForceEncryption:		
		{
			EnableProc* pEnabler = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(EnableProc))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
			pEnabler =(EnableProc*)InputBuffer;
			IoStatus->Information  = sizeof(ULONG);
			PfpSetForcEncryption(pEnabler->HashValue,pEnabler->bEnable);
			ExReleaseResourceLite(&g_ProcessInfoResource);
		}
		break;

	case PFPCOMMAND_SetBrowserCreateExeFile:		
		{
			EnableProc* pEnabler = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(EnableProc))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
			pEnabler =(EnableProc*)InputBuffer;
			IoStatus->Information  = sizeof(ULONG);
			PfpSetBrowserAllowCreateExeFile(pEnabler->HashValue,pEnabler->bEnable);
			ExReleaseResourceLite(&g_ProcessInfoResource);
		}
		break;
	case PFPCOMMAND_QueryFileTypeOfFolderEncryption: 
		break;
	case PFPCOMMAND_SetFileTypeForFolderEncryption:
		{
			PWCHAR szFolderPath = NULL;
			ULONG   nIndex		= 0;
			if(InputBuffer== NULL||InputBufferLength==0)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			szFolderPath = (PWCHAR)InputBuffer;
			while(nIndex<InputBufferLength/sizeof(WCHAR) && szFolderPath[nIndex]!= L'|')nIndex++;
			if(nIndex== InputBufferLength)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			szFolderPath[nIndex]=0;
			nIndex++;
			//ExAcquireFastMutex(&g_FolderLock);
			//SetFileTypesForFolderEncryption(szFolderPath,&szFolderPath[nIndex]);
			//ExReleaseFastMutex(&g_FolderLock);
		}
		break;
	case PFPCOMMAND_QueryFileTypeLenForFolder:
		{

			if(InputBuffer== NULL||InputBufferLength==0||OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			*(ULONG*)OutputBuffer = 0;
			//ExAcquireFastMutex(&g_FolderLock);
			//QueryFileTypesLenForFolderEncryption((PWCHAR)InputBuffer,(ULONG*)OutputBuffer);
			//ExReleaseFastMutex(&g_FolderLock);
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GetProgNum:
		{
			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			*(ULONG*)OutputBuffer = PfpGetProgNum();
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GetProgHashValues:
		{
			if(OutputBuffer== NULL||OutputBufferLength<sizeof(PROGHASHVALUEITEM))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if((ULONG)OutputBufferLength&(sizeof(PROGHASHVALUEITEM)-1))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Status = PfpGetHashValueIntoArray(OutputBuffer,OutputBufferLength/sizeof(PROGHASHVALUEITEM));
			ExReleaseResourceLite(&g_ProcessInfoResource);
			if(NT_SUCCESS(IoStatus->Status))
			{
				IoStatus->Information= OutputBufferLength;
			}
		}
		break;
	case PFPCOMMAND_GetBrowserHashValues:
		{
			if(OutputBuffer== NULL||OutputBufferLength<sizeof(PROGHASHVALUEITEM))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			if((ULONG)OutputBufferLength &(sizeof(PROGHASHVALUEITEM)-1))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Status = PfpGetBrowserHashValueIntoArray(OutputBuffer,OutputBufferLength/sizeof(PROGHASHVALUEITEM));
			ExReleaseResourceLite(&g_ProcessInfoResource);
			if(NT_SUCCESS(IoStatus->Status))
			{
				IoStatus->Information= OutputBufferLength;
			}
		}
		break;
	case PFPCOMMAND_GetProgFileTypes:
		{
			if(InputBuffer== NULL||InputBufferLength==0||OutputBuffer== NULL||OutputBufferLength<sizeof(FILETYPE_INFO))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			IoStatus->Status = PfpGetFileTypesForProg(InputBuffer,InputBufferLength,(PFILETYPE_INFO)OutputBuffer,OutputBufferLength/sizeof(FILETYPE_INFO));
			if(NT_SUCCESS(IoStatus->Status ))
			{
				IoStatus->Information = sizeof(FILETYPE_INFO)*(OutputBufferLength/sizeof(FILETYPE_INFO));
			}

		}
		break;

	case PFPCOMMAND_GetFileTypeNumForProg:
		if(InputBuffer== NULL||InputBufferLength!=PROCESSHASHVALULENGTH||OutputBuffer== NULL||OutputBufferLength<sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
		IoStatus->Status = PfpGetFileFileTypeNumForProg(InputBuffer,InputBufferLength,(ULONG*)OutputBuffer);
		ExReleaseResourceLite(&g_ProcessInfoResource);
		FsRtlExitFileSystem();
		if(NT_SUCCESS(IoStatus->Status ))
		{
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_AddPrograms_New:
		{
			if(InputBuffer== NULL||InputBufferLength<sizeof(ADDPROTECTIONFORPROG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Status = PfpAddProtectionFroProg((PADDPROTECTIONFORPROG)InputBuffer);
			ExReleaseResourceLite(&g_ProcessInfoResource);
			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status ))
			{
				IoStatus->Information = InputBufferLength;
			}
		}
		break;
	case PFPCOMMAND_GetProgInfoForProtection:
		if(InputBuffer== NULL||InputBufferLength!=PROCESSHASHVALULENGTH||OutputBuffer== NULL||OutputBufferLength<sizeof(PROGPROTECTION))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
		IoStatus->Status = PfpGetProtectionInfoForProg(InputBuffer,InputBufferLength,(PPROGPROTECTION)OutputBuffer);
		ExReleaseResourceLite(&g_ProcessInfoResource);
		FsRtlExitFileSystem();
		if(NT_SUCCESS(IoStatus->Status ))
		{
			IoStatus->Information = sizeof(PROGPROTECTION);
		}					
		break;
	case PFPCOMMAND_SetFileTypesByArray:
		{
			PPROCESSINFO	pProcessInfo  = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(SETFILETYPESBYARRAY))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
			pProcessInfo  =PfpGetProcessInfoUsingHashValue(((PSETFILETYPESBYARRAY)InputBuffer)->hashvalue.HashValue,PROCESSHASHVALULENGTH,NULL);
			
			if(pProcessInfo == NULL)
			{
				ExReleaseResourceLite(&g_ProcessInfoResource);
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto casexit;
			}

			PfpAddFileTypesToProcessInfoByFileTypeArray(pProcessInfo,
				&((PSETFILETYPESBYARRAY)InputBuffer)->Filetype[0],
				((PSETFILETYPESBYARRAY)InputBuffer)->nFileTypes);
			InterlockedDecrement(&pProcessInfo->nRef);

			ExReleaseResourceLite(&g_ProcessInfoResource);

casexit:	
			;
			FsRtlExitFileSystem();
		}
		break;
	case PFPCOMMAND_SetFolderEncrypt:

		if(InputBuffer== NULL||InputBufferLength<sizeof(FOLDERPROTECTSETTING))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		 
		FsRtlEnterFileSystem();

		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpEnableFolderRealTimeEncrypt((PFOLDERPROTECTSETTING)InputBuffer);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		 
		break;
	case PFPCOMMAND_SetFolderBackup:
		if(InputBuffer== NULL||InputBufferLength<sizeof(FOLDERPROTECTSETTING))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}

		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);

		IoStatus->Status = PfpEnableFolderBackup((PFOLDERPROTECTSETTING)InputBuffer);
		
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		 
		break;
	case PFPCOMMAND_SetFolderLockState:
		if(InputBuffer== NULL||InputBufferLength<sizeof(FOLDERPROTECTSETTING))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem(); 
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpChangeFolderState((PFOLDERPROTECTSETTING)InputBuffer);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		break;

	case PFPCOMMAND_SetFolderProtectType:
		if(InputBuffer== NULL||InputBufferLength<sizeof(FOLDERPROTECTSETTING))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpChangeFolderProtectType((PFOLDERPROTECTSETTING)InputBuffer);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		break;
	case PFPCOMMAND_SetFolderEncryptType:
		if(InputBuffer== NULL||InputBufferLength<sizeof(FOLDERPROTECTSETTING))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpChangeEncryptionTypeForFolder((PFOLDERPROTECTSETTING)InputBuffer);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		break;
	case PFPCOMMAND_IsFolerLocked:
		if(InputBuffer== NULL||InputBufferLength== 0||OutputBuffer==  NULL ||OutputBufferLength!= sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		 
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&g_FolderResource,TRUE);
		IoStatus->Status= PfpIsFolderLocked(InputBuffer,(BOOLEAN*)OutputBuffer);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		if(NT_SUCCESS(IoStatus->Status))
		{
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_DeleteProtectorFolder:
		{
		 
			if(InputBuffer== NULL||InputBufferLength>1023*sizeof(WCHAR))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			FsRtlEnterFileSystem();
		 
			PfpCloseDiskFileObjectsUnderDir((PWCHAR)InputBuffer);

			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			IoStatus->Status = PfpDelProtectedFolder((PWCHAR)InputBuffer);
			ExReleaseResourceLite(&g_FolderResource);
 
			FsRtlExitFileSystem();
		}
		break;
	case PFPCOMMAND_SetDispalyNameForFolder:
		if(InputBuffer== NULL||InputBufferLength!= sizeof(FOLDERDISPLAYNAME))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		
		IoStatus->Status= PfpSetDisplayNameForFolder(((PFOLDERDISPLAYNAME)InputBuffer)->szFolderPath,((PFOLDERDISPLAYNAME)InputBuffer)->szDisplayName);
		ExReleaseResourceLite(&g_FolderResource);
		if(NT_SUCCESS(IoStatus->Status))
		{
			IoStatus->Information = sizeof(FOLDERDISPLAYNAME);
		}
		FsRtlExitFileSystem();
		break;
	case PFPCOMMAND_GetDispalyNameForFolder:
		if(InputBuffer== NULL||InputBufferLength==0||OutputBuffer == NULL ||OutputBufferLength <50*sizeof(WCHAR))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&g_FolderResource,TRUE);

		IoStatus->Status	= PfpGetDisplayNameForFolder((PWCHAR)InputBuffer,(PWCHAR )OutputBuffer,OutputBufferLength);
		ExReleaseResourceLite(&g_FolderResource);

		FsRtlExitFileSystem();
		IoStatus->Information = OutputBufferLength;
		break;
	case PFPCOMMAND_AddFolderProtectionInfo :

		if(InputBuffer== NULL||InputBufferLength!=sizeof(ADDPROTECTEDFOLDER))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpAddProtectedFolder(((PADDPROTECTEDFOLDER)InputBuffer)->szFolderPath,&((PADDPROTECTEDFOLDER)InputBuffer)->FolderProtectInfo);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();

		if(NT_SUCCESS(IoStatus->Status))
		{
			IoStatus->Information = InputBufferLength; 
		}
		break;
	case PFPCOMMAND_SetFolderProtectInfo:
		{
			if(InputBuffer== NULL||InputBufferLength!=sizeof(ADDPROTECTEDFOLDER))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			FsRtlEnterFileSystem();
			
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			IoStatus->Status = PfpSetProtectedFolder(((PADDPROTECTEDFOLDER)InputBuffer)->szFolderPath,&((PADDPROTECTEDFOLDER)InputBuffer)->FolderProtectInfo);
			ExReleaseResourceLite(&g_FolderResource);
			
			PfpCloseDiskFileObjectsUnderDir(((PADDPROTECTEDFOLDER)InputBuffer)->szFolderPath);

			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status))
			{
				IoStatus->Information = InputBufferLength; 
			}
		}
		break;
	case PFPCOMMAND_GetNumOfProtectedFolder:
		if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();

		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpGetProtectedFolderNum((ULONG*)OutputBuffer);
		ExReleaseResourceLite(&g_FolderResource);

		FsRtlExitFileSystem();
		if(NT_SUCCESS(IoStatus->Status))
		{
			IoStatus->Information = sizeof(ULONG); 
		}
		break;
	case PFPCOMMAND_GetProtectedFoldersIntoArray:
		{
			ULONG nReturned =0;
			if(OutputBuffer== NULL||OutputBufferLength<sizeof(FOLDERPATH))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			nReturned = OutputBufferLength/sizeof(FOLDERPATH);
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			IoStatus->Status = PfpGetFolderPathIntoArray((PFOLDERPATH)OutputBuffer,&nReturned);
			ExReleaseResourceLite(&g_FolderResource);
			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status))
			{
				IoStatus->Information = nReturned*sizeof(FOLDERPATH); 
			}
		}
		break;
	case PFPCOMMAND_GetNumOfFileTypesForProtectedFolder:
		if(InputBuffer== NULL||InputBufferLength>sizeof(WCHAR)*1024||OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
		IoStatus->Status = PfpGetNumofFiletypsForProtectedFolder((PWCHAR)InputBuffer,(ULONG*)OutputBuffer);
		ExReleaseResourceLite(&g_FolderResource);
		FsRtlExitFileSystem();
		if(NT_SUCCESS(IoStatus->Status ))
		{
			IoStatus->Information = sizeof(ULONG);
		}

		break;
	case PFPCOMMAND_GetFileTypesbyArrayForProtectedFolder:
		{
			ULONG nFileTypes = 0;
			if(InputBuffer== NULL||InputBufferLength>sizeof(WCHAR)*1024||OutputBuffer == NULL || OutputBufferLength<sizeof(FOLDERFILETYPE))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			nFileTypes = OutputBufferLength/sizeof(FOLDERFILETYPE);
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			IoStatus->Status = PfpGetFileTypesForProtectedFolder((PWCHAR)InputBuffer,(PFOLDERFILETYPE)OutputBuffer,&nFileTypes);
			ExReleaseResourceLite(&g_FolderResource);
			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status ))
			{
				IoStatus->Information = nFileTypes*sizeof(FOLDERFILETYPE);
			}
		}
		break;
	case PFPCOMMAND_GetNumOfHidder:
		{
			if(OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			*(ULONG*)OutputBuffer = PfpGetNumOfHidder();
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GetHidderByArray:
		{
			ULONG nNum = 0;

			if(OutputBuffer == NULL || OutputBufferLength< sizeof(HIDDERITEM))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			nNum  = OutputBufferLength/sizeof(HIDDERITEM);

			IoStatus->Status =PfpGetHidderItemsByArray((PHIDDERITEM)OutputBuffer,&nNum  );
			if(NT_SUCCESS(IoStatus->Status ))
			{
				IoStatus->Information = nNum*sizeof(HIDDERITEM);
			}

		}
		break;
	case PFPCOMMAND_AddHidderItem:
		{
			ULONG  nNum = 0;
			if(InputBuffer== NULL||InputBufferLength<sizeof(HIDDERITEM))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			nNum  = InputBufferLength/sizeof(HIDDERITEM);
			IoStatus->Status =  PfpAddHidderItem((PHIDDERITEM)InputBuffer,&nNum  );
			IoStatus->Information =InputBufferLength;
		}		
		break;
	case PFPCOMMAND_SetHideItemState:
		{
			ULONG  nNum = 0;
			if(InputBuffer== NULL||InputBufferLength<sizeof(HIDDERITEM))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			
			IoStatus->Status =  PfpSetHideItemState((PHIDDERITEM)InputBuffer);
			IoStatus->Information =InputBufferLength;
		}	
		break;
	case PFPCOMMAND_SetUsbDeviceEncryptMode:
		{
// 			if(InputBuffer== NULL||InputBufferLength!=sizeof(ULONG))
// 			{
// 				IoStatus->Status = STATUS_INVALID_PARAMETER;
// 				break;
// 			}
// 			IoStatus->Status =  PfpSetUsbEncryptMode((BOOLEAN)(*(ULONG*)InputBuffer)!=0);
// 			IoStatus->Information = sizeof(InputBufferLength);
		}
		break;
	case PFPCOMMAND_GetUsbDeviceEncryptMode:
		{

// 			BOOLEAN bUsb = FALSE;
// 			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(ULONG))
// 			{
// 				IoStatus->Status = STATUS_INVALID_PARAMETER;
// 				break;
// 			}
// 			IoStatus->Status =  PfpGetUsbEncryptMode(&bUsb );
// 			*(ULONG*)OutputBuffer  = bUsb;
// 			IoStatus->Information =  sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_SetFileTypesForUsbDevice:
		{
// 			if(InputBuffer== NULL||InputBufferLength<sizeof(FILETYPE_REMOVEABLEDEVICE))
// 			{
// 				IoStatus->Status = STATUS_INVALID_PARAMETER;
// 				break;
// 			}
// 			IoStatus->Status =  PfpSetFileTypesForUsb((PFILETYPE_REMOVEABLEDEVICE)InputBuffer,InputBufferLength/sizeof(FILETYPE_REMOVEABLEDEVICE));
// 			IoStatus->Information = sizeof(InputBufferLength);
		}
		break;
	case PFPCOMMAND_GetFileTypesForUsbDevice:
		{
// 			ULONG nNum=0;
// 			if(OutputBuffer== NULL||OutputBufferLength<sizeof(FILETYPE_REMOVEABLEDEVICE))
// 			{
// 				IoStatus->Status = STATUS_INVALID_PARAMETER;
// 				break;
// 			} 
// 			nNum = OutputBufferLength/sizeof(FILETYPE_REMOVEABLEDEVICE);
// 			IoStatus->Status = PfpGetFileTypesForUsb((PFILETYPE_REMOVEABLEDEVICE)OutputBuffer,&nNum);
// 			if(NT_SUCCESS(IoStatus->Status ))
// 			{
// 				IoStatus->Information= nNum*sizeof(FILETYPE_REMOVEABLEDEVICE);
// 			}

		}
		break;
	case PFPCOMMAND_GetFileTypesNumForUsbDevice:
		{

// 			if(OutputBuffer== NULL||OutputBufferLength!= sizeof(ULONG))
// 			{
// 				IoStatus->Status = STATUS_INVALID_PARAMETER;
// 				break;
// 			} 
// 			IoStatus->Status= PfpGetNumofFileTypesForUsb((ULONG*)OutputBuffer);
// 			if(NT_SUCCESS(IoStatus->Status))
// 			{
// 				IoStatus->Information = sizeof(ULONG);
// 			}
		}
		break;
	case PFPCOMMAND_SetFileTypesForFolder:
		{
			PSETFILETYPESFORFOLDER pFolderFileTypeSetting = NULL;
			if(InputBuffer==NULL ||InputBufferLength<sizeof(SETFILETYPESFORFOLDER) )
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			IoStatus->Status = PfpSetFileTypesForFolder((PSETFILETYPESFORFOLDER)InputBuffer);
			ExReleaseResourceLite(&g_FolderResource);
			FsRtlExitFileSystem();

		}
		break;
	case PFPCOMMAND_GetFolderProtectInfo:
		{
			if(InputBuffer==NULL ||InputBufferLength>1023*sizeof(WCHAR) ||OutputBuffer == NULL || OutputBufferLength<sizeof(FODLERPROTECTORINFO))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			} 
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_FolderResource,TRUE);
			IoStatus->Status =PfpGetFolderProtectInfo((PWCHAR)InputBuffer,(PFODLERPROTECTORINFO)OutputBuffer);
			ExReleaseResourceLite(&g_FolderResource);
			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status ))
			{
				IoStatus->Information =sizeof(FODLERPROTECTORINFO);
			}
		}
		break;
	case PFPCOMMAND_READ_LOG_NEW:
		{
			if(OutputBuffer== NULL||OutputBufferLength!=sizeof(READLOG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if(!GetLogInfoFromQueNew((READLOG*)OutputBuffer))
				IoStatus->Status  = STATUS_NO_MORE_FILES;

			IoStatus->Information = OutputBufferLength;
		}
		break;
	case PFPCOMMAND_IsProcessCanStop:
		{
			if(InputBuffer==NULL ||InputBufferLength!=PROCESSHASHVALULENGTH||OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			} 
			*((ULONG*)OutputBuffer)=(PfpCanProcessbeStoped((PUCHAR)InputBuffer,InputBufferLength)?1:0);
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GetBrowserCount:
		{
			if(OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			} 
			*(ULONG*)OutputBuffer = PfpGetBrowserCount();
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GetBrowserEncryptTypeValue:
		if(InputBuffer==NULL ||InputBufferLength!=PROCESSHASHVALULENGTH||OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		} 
		PfpGetBrowserEncryptTypeValue((UCHAR*)InputBuffer,(ULONG*)OutputBuffer);
		IoStatus->Information = sizeof(ULONG);

		break;
	case PFPCOMMAND_SetBrowserEncryptTypeValue:
		if(InputBuffer==NULL ||InputBufferLength!=sizeof(BROWSERFILETYPE) )
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		} 
		PfpSetBrowserEncryptTypeValue(((PBROWSERFILETYPE)InputBuffer)->hashValue.HashValue,(ULONG)((PBROWSERFILETYPE)InputBuffer)->lBrowserEncryptType);
		IoStatus->Information = sizeof(ULONG);

		break;
	case PFPCOMMAND_GetBrowserEncryptTypes:
		{
			PBROWSERFILETYPE pBrowser = NULL;
			if(InputBuffer==NULL ||InputBufferLength!=sizeof(BROWSERFILETYPE)||OutputBuffer == NULL || OutputBufferLength<sizeof(FILETYPE_INFO))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			} 
			pBrowser =  (PBROWSERFILETYPE)InputBuffer;
			FsRtlEnterFileSystem();
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Status = PfpGetBrowserEncryptFileTypes((UCHAR*)(pBrowser->hashValue.HashValue),pBrowser->lBrowserEncryptType,
				(PFILETYPE_INFO)OutputBuffer,OutputBufferLength/sizeof(FILETYPE_INFO));
			ExReleaseResourceLite(&g_ProcessInfoResource);
			FsRtlExitFileSystem();

			if(NT_SUCCESS(IoStatus->Status))
				IoStatus->Information = OutputBufferLength;
		}
		break;

	case PFPCOMMAND_IsBrowser:
		{
			if(InputBuffer==NULL ||InputBufferLength!=PROCESSHASHVALULENGTH||OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			} 
			*(ULONG*)OutputBuffer =(IsBrower((UCHAR*)InputBuffer)?1:0);
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_GetBrowserEncryptTypesNum:
		{
			PBROWSERFILETYPE pBrowser = NULL;
			if(InputBuffer==NULL ||InputBufferLength!=sizeof(BROWSERFILETYPE)||OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			} 
			pBrowser =  (PBROWSERFILETYPE)InputBuffer;

			FsRtlEnterFileSystem();
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			PfpGetBrowserEncryptFileTypesNum((UCHAR*)pBrowser->hashValue.HashValue,pBrowser->lBrowserEncryptType,(ULONG*)OutputBuffer);
			ExReleaseResourceLite(&g_ProcessInfoResource);
			FsRtlExitFileSystem();

			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_SetBrowserFileTypesByArray:
		{
			PPROCESSINFO	pProcessInfo  = NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(SETFILETYPESBYARRAY))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
			pProcessInfo  =PfpGetProcessInfoUsingHashValue(((PSETFILETYPESBYARRAY)InputBuffer)->hashvalue.HashValue,PROCESSHASHVALULENGTH,NULL);
			
			if(pProcessInfo == NULL)
			{
				ExReleaseResourceLite(&g_ProcessInfoResource);			
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				goto caseexit;
			}

			PfpAddFileTypesForBrowserInfoByFileTypeArray(	pProcessInfo,
				((PSETFILETYPESBYARRAY)InputBuffer)->nEncryptionTypeValue,
				&((PSETFILETYPESBYARRAY)InputBuffer)->Filetype[0],
				((PSETFILETYPESBYARRAY)InputBuffer)->nFileTypes
				);
			InterlockedDecrement(&pProcessInfo->nRef);
			ExReleaseResourceLite(&g_ProcessInfoResource);
caseexit:
			FsRtlExitFileSystem();
		}
		break;
	case PFPCOMMAND_AddBrowserProtection:
		{
			PBROWSERPROTECTION pBrowser= NULL;
			if(InputBuffer== NULL||InputBufferLength<sizeof(BROWSERPROTECTION))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pBrowser = (PBROWSERPROTECTION)InputBuffer;
			
			FsRtlEnterFileSystem();

			ExAcquireResourceExclusiveLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Status = PfpAddBrowserProtection(pBrowser);
			ExReleaseResourceLite(&g_ProcessInfoResource);

			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status))
			{
				IoStatus->Information = InputBufferLength;
			}
		}
		break;

	case PFPCOMMAND_GetBrowserProtection:
		{
			PPROGHASHVALUEITEM phashValue= NULL;

			if(InputBuffer == NULL||InputBufferLength<sizeof(PROGHASHVALUEITEM)||
				OutputBuffer == NULL || OutputBufferLength!= sizeof(BROWSERPROTECTION))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			phashValue = (PPROGHASHVALUEITEM)InputBuffer;

			FsRtlEnterFileSystem();
			ExAcquireResourceSharedLite(&g_ProcessInfoResource,TRUE);
			IoStatus->Status = PfpGetBrowserProtection(phashValue,(PBROWSERPROTECTION)OutputBuffer);
			ExReleaseResourceLite(&g_ProcessInfoResource);
			
			FsRtlExitFileSystem();
			if(NT_SUCCESS(IoStatus->Status))
			{
				IoStatus->Information = OutputBufferLength;
			}
		}
		break;
	case PFPCOMMAND_SetDiaplyFramONWindow:
		{
			if(InputBuffer == NULL||InputBufferLength!= sizeof(ULONG)||
				OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_AllowDisplayFrameOnWindow = (BOOLEAN)((*(ULONG*)InputBuffer)==1);
			*(ULONG*)OutputBuffer = 1;
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_QueryDispalyFramOnWindow:
		if( OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
		{
			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		*(ULONG*)OutputBuffer=(g_AllowDisplayFrameOnWindow ?1:0);

		IoStatus->Information = sizeof(ULONG);
		break;
	case PFPCOMMAND_QueryUsbDeviceNum:
		{
			if( OutputBuffer == NULL || OutputBufferLength!= sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			*(ULONG*)OutputBuffer=PfpQueryUsbConfigNum();

			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_QueryUsbAllIds:
		{
			ULONG nLenOrignal = 0;
			if( OutputBuffer == NULL || OutputBufferLength<sizeof(USBQUERYIDS))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			 
			nLenOrignal = OutputBufferLength;
			if(PfpQueryAllUsbIDs(OutputBuffer,&nLenOrignal))
			{
				IoStatus->Information = (OutputBufferLength-nLenOrignal);
			}else
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
			
		}
		break;
	case PFPCOMMAND_QueryUsbSecureFileTypsLen:
		{
			PUSBQUERYIDS pUsbIds = NULL;
			ULONG		 nReturned = 0;
			if(InputBuffer == NULL||InputBufferLength!= sizeof(USBQUERYIDS)||
				OutputBuffer == NULL || OutputBufferLength==0)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbIds =(PUSBQUERYIDS )InputBuffer ;
			if(PfpQueryUsbFileTypesLen(pUsbIds->VolumeID,pUsbIds->DeviceID,strlen(pUsbIds->DeviceID),&nReturned ))
			{
				*(ULONG*)OutputBuffer = nReturned;
				IoStatus->Information = sizeof(ULONG);
			}else
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}

		}
		break;
	case PFPCOMMAND_QueryUsbControlStatus:
		{
			PUSBQUERYIDS pUsbIds = NULL;
			ULONG		 nReturned = 0;
			BOOLEAN		 bEncrytpAll= FALSE;
			PUSBCONTROLSTATUS pControlStatus = NULL;
			if(InputBuffer == NULL||InputBufferLength!= sizeof(USBQUERYIDS)||
				OutputBuffer == NULL || OutputBufferLength<sizeof(USBCONTROLSTATUS))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbIds =(PUSBQUERYIDS )InputBuffer ;
			pControlStatus = (PUSBCONTROLSTATUS)OutputBuffer; 
			if(PfpQueryUsbControlStatus(pUsbIds->VolumeID,pUsbIds->DeviceID,strlen(pUsbIds->DeviceID),&bEncrytpAll,&pControlStatus->nControlStatus ))
			{
				pControlStatus->nEncryptAll = (bEncrytpAll?1:0);
				IoStatus->Information = sizeof(USBCONTROLSTATUS);
			}else
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
		}
		break;
	case PFPCOMMAND_SetUsbControlStatus:
		{
			PUSBCONTROLSTATUSSET pSetUsbControls= NULL;
			if(InputBuffer == NULL||InputBufferLength!= sizeof(USBCONTROLSTATUSSET))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pSetUsbControls =(PUSBCONTROLSTATUSSET) InputBuffer;
			if(!PfpSetUsbControlSTATUS(pSetUsbControls->usbIds.VolumeID,pSetUsbControls->usbIds.DeviceID,strlen(pSetUsbControls->usbIds.DeviceID),pSetUsbControls->ControlStatus.nControlStatus))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
		}
		break;
	case PFPCOMMAND_SetUsbEncryptType:
		{
			PUSBCONTROLSTATUSSET pSetUsbControls= NULL;
			if(InputBuffer == NULL||InputBufferLength!= sizeof(USBCONTROLSTATUSSET))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pSetUsbControls = (PUSBCONTROLSTATUSSET)InputBuffer;
			if(!PfpSetUsbFileEncryptType(pSetUsbControls->usbIds.VolumeID,pSetUsbControls->usbIds.DeviceID,strlen(pSetUsbControls->usbIds.DeviceID),(pSetUsbControls->ControlStatus.nEncryptAll==1?TRUE:FALSE)))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
		}
		break;
	case PFPCOMMAND_SetUsbEncryptFileTypes:
		{
			
			PUSBFILETYPESSET pSetUsbFileTypes= NULL;
			if(InputBuffer == NULL||InputBufferLength< sizeof(USBFILETYPESSET))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pSetUsbFileTypes = (PUSBFILETYPESSET)InputBuffer;
			if(!PfpSetUsbEncryptionFileTypes(pSetUsbFileTypes->usbIds.VolumeID,pSetUsbFileTypes->usbIds.DeviceID,strlen(pSetUsbFileTypes->usbIds.DeviceID),pSetUsbFileTypes->FileTypes,pSetUsbFileTypes->nFiletypeLen))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
			}
		}
		break;
	case PFPCOMMAND_DeleteUsbSecure:		
		{
			PUSBQUERYIDS pUsbId= NULL;
			if(InputBuffer == NULL||InputBufferLength< sizeof(USBQUERYIDS))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbId = (PUSBQUERYIDS)InputBuffer ;
			PfpDeleteUsbSecure(pUsbId->VolumeID,pUsbId->DeviceID,strlen(pUsbId->DeviceID));
			 
		}
		break;
	case PFPCOMMAND_QueryUsbEncryptType:
		{
			PUSBQUERYIDS pUsbId= NULL;
			ULONG nForceEncryptAll=0;
			ANSI_STRING ansiString;
			if(InputBuffer == NULL||InputBufferLength< sizeof(USBQUERYIDS)||
				OutputBuffer == NULL || OutputBufferLength<sizeof(ULONG)
				)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbId = (PUSBQUERYIDS)InputBuffer ;
			RtlInitAnsiString(&ansiString,pUsbId->DeviceID);
			PfpQueryUsbFileEncryptType(pUsbId->VolumeID,ansiString.Buffer,ansiString.Length,&nForceEncryptAll);
			*(ULONG*)OutputBuffer = nForceEncryptAll;
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_QueryUsbEncryptFileTypes:
		{
			PUSBQUERYIDS pUsbId= NULL;
			ULONG nOutLen = 0;
			ULONG nForceEncryptAll=0;
			if(InputBuffer == NULL||InputBufferLength< sizeof(USBQUERYIDS)||
				OutputBuffer == NULL || OutputBufferLength==0)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbId = (PUSBQUERYIDS)InputBuffer ;
			nOutLen   = OutputBufferLength;
			if(PfpQueryUsbFileTypes(pUsbId->VolumeID,pUsbId->DeviceID,strlen(pUsbId->DeviceID),(WCHAR*)OutputBuffer,&nOutLen))
			{
				IoStatus->Information =nOutLen;
			}
		}
		break;
	case PFPCOMMAND_GetUsbDriverLetter:
		{
			PUSBQUERYIDS pUsbId= NULL;
			PUSBSECURE   pSecureItem = NULL;
 
			if(InputBuffer == NULL||InputBufferLength< sizeof(USBQUERYIDS)||
				OutputBuffer == NULL || OutputBufferLength<3)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbId		= (PUSBQUERYIDS)InputBuffer;
			pSecureItem = PfpGetUsbSecure(pUsbId->VolumeID,pUsbId->DeviceID,strlen(pUsbId->DeviceID));
			if(pSecureItem == NULL)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			memcpy(OutputBuffer,pSecureItem->DriverLetter,2*sizeof(WCHAR));
			((WCHAR*)OutputBuffer)[2]=L'\0';
			IoStatus->Information =2*sizeof(WCHAR);			
		}
		break;
	case PFPCOMMAND_GetUsbDriverDesrciption:
		{
			PUSBQUERYIDS pUsbId= NULL;
			PUSBSECURE   pSecureItem = NULL;

			if(InputBuffer == NULL||InputBufferLength< sizeof(USBQUERYIDS)||
				OutputBuffer == NULL || OutputBufferLength<40*sizeof(WCHAR))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbId		= (PUSBQUERYIDS)InputBuffer;
			pSecureItem = PfpGetUsbSecure(pUsbId->VolumeID,pUsbId->DeviceID,strlen(pUsbId->DeviceID));
			if(pSecureItem == NULL)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if(pSecureItem->DriverDescription[0]==L'\0')
			{
				((WCHAR*)OutputBuffer)[0]=L'\0';
				IoStatus->Information =1*sizeof(WCHAR);		
			}else
			{
				memcpy(OutputBuffer,pSecureItem->DriverDescription,min(wcslen(pSecureItem->DriverDescription),(OutputBufferLength>>1)-1)*sizeof(WCHAR));
				((WCHAR*)OutputBuffer)[min(wcslen(pSecureItem->DriverDescription),(OutputBufferLength>>1)-1)] =L'\0';
				IoStatus->Information =min(wcslen(pSecureItem->DriverDescription),(OutputBufferLength>>1)-1)*sizeof(WCHAR);		
			}
		}
		break;
	case PFPCOMMAND_SetUsbDriverDescription:
		{
			PUSBQUERYIDS pUsbId				= NULL;
			PUSBSECURE   pSecureItem		= NULL;
			ULONG		 nDescriptionLen	= 0;
			if(InputBuffer == NULL||InputBufferLength< sizeof(USBQUERYIDS)
				 || (nDescriptionLen =(InputBufferLength-sizeof(USBQUERYIDS)))>39*sizeof(WCHAR))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			
			pUsbId		= (PUSBQUERYIDS)InputBuffer;
			pSecureItem = PfpGetUsbSecure(pUsbId->VolumeID,pUsbId->DeviceID,strlen(pUsbId->DeviceID));
			if(pSecureItem == NULL)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			pUsbId++;
			memcpy(pSecureItem->DriverDescription,(PUCHAR)pUsbId,nDescriptionLen);	
			pSecureItem->DriverDescription[nDescriptionLen>>1] =L'\0';
		}
		break;
	case PFPCOMMAND_IsUsbDriverConnected:
		{
			PUSBQUERYIDS pUsbId				= NULL;
			PUSBSECURE   pSecureItem		= NULL;
			 
			if(InputBuffer == NULL||InputBufferLength!=sizeof(USBQUERYIDS)
				||OutputBuffer == NULL || OutputBufferLength!=sizeof(ULONG))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}

			pUsbId		= (PUSBQUERYIDS)InputBuffer;
			pSecureItem = PfpGetUsbSecure(pUsbId->VolumeID,pUsbId->DeviceID,strlen(pUsbId->DeviceID));
			if(pSecureItem == NULL)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			*(ULONG*)OutputBuffer = (pSecureItem->pUsbVolumeDevice!= NULL?1:0);
			IoStatus->Information = sizeof(ULONG);
		}
		break;
	case PFPCOMMAND_RegisterProtect:
		{
			if(InputBuffer == NULL||InputBufferLength!=sizeof(BOOLEAN))
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_bRegisterProtect = *(BOOLEAN*)InputBuffer ;
			IoStatus->Status = STATUS_SUCCESS;
		}
		break;
	case PFPCOMMAND_SetEncryptKey:
		{
			if(InputBuffer == NULL||InputBufferLength!=16)
			{
				IoStatus->Status = STATUS_INVALID_PARAMETER;
				break;
			}
			
			if(g_pKeyFileContent)
			{
				IoStatus->Status = STATUS_SUCCESS;				 
			}else
			{
				g_pKeyContent = ExAllocatePool(PagedPool,16);
				if(g_pKeyContent )				
				{
					RtlCopyBytes(g_pKeyContent,(PVOID)InputBuffer,16);
					IoStatus->Status = STATUS_SUCCESS;
					ExeHasLoggon = 1;
					aes_encrypt_key128((unsigned char*)g_pKeyContent,&ase_en_context);
					aes_decrypt_key128((unsigned char*)g_pKeyContent,&ase_den_context);

				}else
				{
					IoStatus->Status = STATUS_INSUFF_SERVER_RESOURCES;
				}
			}
			
		}
		break;
	default:

		IoStatus->Status = STATUS_INVALID_PARAMETER;
		break;
	}

	FsRtlExitFileSystem();
	if (NULL != deviceName)
	{
		ExFreePoolWithTag( deviceName, FILESPY_POOL_TAG );
	}

	return IoStatus->Status;
} 
