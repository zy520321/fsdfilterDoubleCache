#define NTDDI_WINXPSP2 0x05010200
#define OSVERSION_MASK 0xFFFF0000
#define SPVERSION_MASK 0x0000FF00
#define SUBVERSION_MASK 0x000000FF

#define OSVER(Version) ((Version) & OSVERSION_MASK)
#define SPVER(Version) (((Version) & SPVERSION_MASK) >> 8)
#define SUBVER(Version) (((Version) & SUBVERSION_MASK) )

#define FILE_DEVICE_UNKNOWN 0x00000022
#define IOCTL_UNKNOWN_BASE FILE_DEVICE_UNKNOWN
#define IOCTL_CAPTURE_GET_REGEVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER,FILE_READ_DATA | FILE_WRITE_DATA) 
#define USERSPACE_CONNECTION_TIMEOUT 10
#define REGISTRY_POOL_TAG 'pRE'
 
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "fspykern.h"
#include <ntstrsafe.h>

 

BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PUNICODE_STRING pPartialRegistryPath, PVOID pRegistryObject)
{
	PCAPTURE_REGISTRY_MANAGER pRegistryManager;
	BOOLEAN foundCompleteName = FALSE;
	BOOLEAN partial = FALSE;
	pRegistryManager = &g_RegistrContext;
	if((!MmIsAddressValid(pRegistryObject)) ||
		(pRegistryObject == NULL))
	{
		return FALSE;
	}
	if(pPartialRegistryPath != NULL)
	{
		if( (((pPartialRegistryPath->Buffer[0] == '\\') || (pPartialRegistryPath->Buffer[0] == '%')) ||
			((pPartialRegistryPath->Buffer[0] == 'T') && (pPartialRegistryPath->Buffer[1] == 'R') && (pPartialRegistryPath->Buffer[2] == 'Y') && (pPartialRegistryPath->Buffer[3] == '\\'))) )
		{
			RtlUnicodeStringCopy(pRegistryPath, pPartialRegistryPath);
			partial = TRUE;
			foundCompleteName = TRUE;
		}
	}

	if(!foundCompleteName)
	{
		NTSTATUS status;
		ULONG returnedLength;
		PUNICODE_STRING pObjectName = NULL;

		status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength );
		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGISTRY_POOL_TAG); 
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength );
			if(NT_SUCCESS(status))
			{
				RtlUnicodeStringCopy(pRegistryPath, pObjectName);
				foundCompleteName = TRUE;
			}
			ExFreePoolWithTag(pObjectName, REGISTRY_POOL_TAG);
		}
	}
	return foundCompleteName;
}
 
NTSTATUS RegistryCallback(IN PVOID CallbackContext, 
						  IN PVOID Argument1, 
						  IN PVOID Argument2)
{
	BOOLEAN registryEventIsValid = FALSE;
	BOOLEAN exception = FALSE;
	NTSTATUS	ntstatus = STATUS_SUCCESS;
 
	int type;
	UNICODE_STRING registryPath;
	UCHAR* registryData = NULL;
	ULONG registryDataLength = 0;
	ULONG registryDataType = 0;

	if(!g_bRegisterProtect)
		return STATUS_SUCCESS;


	registryPath.Length = 0;
	registryPath.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	registryPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, registryPath.MaximumLength, REGISTRY_POOL_TAG); 
	if(registryPath.Buffer == NULL)
	{
		return STATUS_SUCCESS;
	}
// 	KeQuerySystemTime(&CurrentSystemTime);
// 	ExSystemTimeToLocalTime(&CurrentSystemTime,&CurrentLocalTime);
	
	

	type = (REG_NOTIFY_CLASS)Argument1;
	__try
	{
		switch(type)
		{
// 		case RegNtPostCreateKey:
// 			{
// 				PREG_POST_CREATE_KEY_INFORMATION createKey = (PREG_POST_CREATE_KEY_INFORMATION)Argument2;
// 				if(NT_SUCCESS(createKey->Status)) 
// 				{
// 					PVOID* registryObject = createKey->Object;
// 					registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, createKey->CompleteName, *registryObject);
// 				}
// 				break;
// 			}
// 		case RegNtPostOpenKey:
// 			{
// 				PREG_POST_OPEN_KEY_INFORMATION openKey = (PREG_POST_OPEN_KEY_INFORMATION)Argument2;
// 				if(NT_SUCCESS(openKey->Status)) 
// 				{
// 					PVOID* registryObject = openKey->Object;
// 					registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, openKey->CompleteName, *registryObject);
// 				}
// 				break;
// 			}
		case RegNtPreDeleteKey:
			{
				PREG_DELETE_KEY_INFORMATION deleteKey = (PREG_DELETE_KEY_INFORMATION)Argument2;
				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, deleteKey->Object);
				if(registryEventIsValid )
				{					
					if(IsProtectedRegisterKey(&registryPath))
					{
						ntstatus  = STATUS_ACCESS_DENIED;
					}
				}
				break;
			}
		case RegNtDeleteValueKey:
			{
				PREG_DELETE_VALUE_KEY_INFORMATION deleteValueKey = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, deleteValueKey->Object);
				if(registryEventIsValid )
				{					
					if(IsProtectedRegisterKey(&registryPath))
					{
						ntstatus  = STATUS_ACCESS_DENIED;
					}
				}
// 				if((registryEventIsValid) && (deleteValueKey->ValueName->Length > 0)) 
// 				{
// 					RtlUnicodeStringCatString(&registryPath,L"\\");
// 					RtlUnicodeStringCat(&registryPath, deleteValueKey->ValueName);
// 				}
				break;
			}
		case RegNtPreSetValueKey:
			{
				PREG_SET_VALUE_KEY_INFORMATION setValueKey = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, setValueKey->Object);
				if(registryEventIsValid )
				{					
					if(IsProtectedRegisterKey(&registryPath))
					{
						ntstatus  = STATUS_ACCESS_DENIED;
					}
				}
// 				if((registryEventIsValid) && (setValueKey->ValueName->Length > 0)) 
// 				{
// 					registryDataType = setValueKey->Type;
// 					registryDataLength = setValueKey->DataSize;
// 					registryData = ExAllocatePoolWithTag(NonPagedPool, registryDataLength, REGISTRY_POOL_TAG);
// 					if(registryData != NULL)
// 					{
// 						RtlCopyBytes(registryData,setValueKey->Data,setValueKey->DataSize);
// 					} else {
// 					}
// 					RtlUnicodeStringCatString(&registryPath,L"\\");
// 					RtlUnicodeStringCat(&registryPath, setValueKey->ValueName);
// 				}
				break;
			}
// 		case RegNtEnumerateKey:
// 			{
// 				PREG_ENUMERATE_KEY_INFORMATION enumerateKey = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
// 				registryDataType = enumerateKey->KeyInformationClass;
// 				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, enumerateKey->Object);
// 				break;
// 			}
// 		case RegNtEnumerateValueKey:
// 			{
// 				PREG_ENUMERATE_VALUE_KEY_INFORMATION enumerateValueKey = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
// 				registryDataType = enumerateValueKey->KeyValueInformationClass;
// 				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, enumerateValueKey->Object);
// 				break;
// 			}
// 		case RegNtQueryKey:
// 			{
// 				PREG_QUERY_KEY_INFORMATION queryKey = (PREG_QUERY_KEY_INFORMATION)Argument2;
// 				registryDataType = queryKey->KeyInformationClass;
// 				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, queryKey->Object);
// 				break;
// 			}
// 		case RegNtQueryValueKey:
// 			{
// 				PREG_QUERY_VALUE_KEY_INFORMATION queryValueKey = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
// 				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, queryValueKey->Object);
// 				if((registryEventIsValid) && (queryValueKey->ValueName->Length > 0)) 
// 				{
// 					registryDataType = queryValueKey->KeyValueInformationClass;
// 					RtlUnicodeStringCatString(&registryPath,L"\\");
// 					RtlUnicodeStringCat(&registryPath, queryValueKey->ValueName);
// 				}
// 				break;
// 			}
// 		case RegNtKeyHandleClose:
// 			{
// 				PREG_KEY_HANDLE_CLOSE_INFORMATION closeKey = (PREG_KEY_HANDLE_CLOSE_INFORMATION)Argument2;
// 				registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, closeKey->Object);
// 				break;
// 			}
		default:
			break;
		}
	} 
	__except( EXCEPTION_EXECUTE_HANDLER ) {
		registryEventIsValid = FALSE;
		exception = TRUE;
	}
// 	if(registryEventIsValid)
// 	{
// 		PREGISTRY_EVENT pRegistryEvent;
// 		UINT eventSize = sizeof(REGISTRY_EVENT)+registryPath.Length+(sizeof(WCHAR))+registryDataLength;
// 		pRegistryEvent = ExAllocatePoolWithTag(NonPagedPool, eventSize, REGISTRY_POOL_TAG); 
// 
// 		if(pRegistryEvent != NULL)
// 		{ 
// 			pRegistryEvent->registryPathLengthB = registryPath.Length+sizeof(WCHAR);
// 			pRegistryEvent->dataType = registryDataType;
// 			pRegistryEvent->dataLengthB = registryDataLength;
// 			RtlCopyBytes(pRegistryEvent->registryData, registryPath.Buffer, registryPath.Length);
// 			pRegistryEvent->registryData[registryPath.Length] = '\0';
// 			pRegistryEvent->registryData[registryPath.Length+1] = '\0';
// 			RtlCopyBytes(pRegistryEvent->registryData+pRegistryEvent->registryPathLengthB, registryData, registryDataLength);
// 			if(registryData != NULL)
// 			{
// 				ExFreePoolWithTag(registryData, REGISTRY_POOL_TAG);
// 			}
// 
// 			pRegistryEvent->processId = PsGetCurrentProcessId(); 
// 			RtlTimeToTimeFields(&CurrentLocalTime,&pRegistryEvent->time);
// 			pRegistryEvent->eventType = (REG_NOTIFY_CLASS)Argument1;
// 			if(!QueueRegistryEvent(pRegistryEvent))
// 			{
// 				ExFreePoolWithTag(pRegistryEvent, REGISTRY_POOL_TAG);
// 			}
// 		}
// 	}
	if(registryPath.Buffer != NULL)
	{
		ExFreePoolWithTag(registryPath.Buffer, REGISTRY_POOL_TAG);
	}
	return ntstatus;
}
 
BOOLEAN IsProtectedRegisterKey(PUNICODE_STRING pRegisterPath)
{
 
	if(pRegisterPath== NULL) return FALSE;

	if(pRegisterPath->Buffer&& (pRegisterPath->Length>>1)>=(USHORT)g_nLenOfKey&&(_wcsnicmp(pRegisterPath->Buffer,g_szRegisterKey,g_nLenOfKey)==0))
	{
		return TRUE;	
	}
	else
	if(pRegisterPath->Buffer&& (pRegisterPath->Length>>1)>=(USHORT)g_nLenOfKey && (_wcsnicmp(pRegisterPath->Buffer,g_szRegisterKeyMin,g_nLenOfKeyMin)==0))
	{
		return TRUE;	
	}
	else
	if(pRegisterPath->Buffer&& (pRegisterPath->Length>>1)>=(USHORT)g_nLenOfKey &&(_wcsnicmp(pRegisterPath->Buffer,g_szRegisterKeyNetwork,g_nLenOfKeyNetwork)==0))
	{
		return TRUE;	
	}
	return FALSE;
}