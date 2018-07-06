#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
typedef struct _FILETIME
{
	ULONG dwLowDateTime;
	ULONG dwHighDateTime;
} 	FILETIME;
typedef struct _SYSTEM_PROCESS_INFORMATION  
{  
	ULONG NextEntryDelta;  
	ULONG dThreadCount;  
	ULONG dReserved01;  
	ULONG dReserved02;  
	ULONG dReserved03;  
	ULONG dReserved04;  
	ULONG dReserved05;  
	ULONG dReserved06;  
	FILETIME ftCreateTime; /* relative to 01-01-1601 */  
	FILETIME ftUserTime; /* 100 nsec units */  
	FILETIME ftKernelTime; /* 100 nsec units */  
	UNICODE_STRING ProcessName;      //这就是进程名
	ULONG BasePriority;  
	ULONG dUniqueProcessId;            //进程ID
	ULONG dParentProcessID;  
	ULONG dHandleCount;  
	ULONG dReserved07;  
	ULONG dReserved08;  
	ULONG VmCounters;  
	ULONG dCommitCharge;  
	PVOID ThreadInfos[1]; 
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

//---------系统信息结构---------
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts,
	SystemConfigurationInformation,
	SystemProcessorTimes,
	SystemGlobalFlag,
	SystemNotImplemented2,
	SystemModuleInformation,
	SystemLockInformation,
	SystemNotImplemented3,
	SystemNotImplemented4,
	SystemNotImplemented5,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPagefileInformation,
	SystemInstructionEmulationCounts,
	SystemInvalidInfoClass1,
	SystemCacheInformation,
	SystemPoolTagInformation,
	SystemProcessorStatistics,
	SystemDpcInformation,
	SystemNotImplemented6,
	SystemLoadImage,
	SystemUnloadImage,
	SystemTimeAdjustment,
	SystemNotImplemented7,
	SystemNotImplemented8,
	SystemNotImplemented9,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,
	SystemPrioritySeparation,
	SystemNotImplemented10,
	SystemNotImplemented11,
	SystemInvalidInfoClass2,
	SystemInvalidInfoClass3,
	SystemTimeZoneInformation,
	SystemLookasideInformation,
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession,
	SystemInvalidInfoClass4,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;



typedef NTSTATUS (__stdcall *PZWQUERYSYSTEMINFORMATION) 
														(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,  
														 IN OUT PVOID SystemInformation,  
														 IN ULONG SystemInformationLength,  
														 OUT PULONG ReturnLength);
HANDLE GetExcludeProcessID(WCHAR* pszProcessName)
{
	ULONG cbBuffer = 0x8000;   
	HANDLE hExclude = INVALID_HANDLE_VALUE;
	PVOID pBuffer = NULL;
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION pInfo;
	UNICODE_STRING functionName;
	LARGE_INTEGER pLargeValue = {0};
	PZWQUERYSYSTEMINFORMATION pzwQuery;
	ULONG nLen = wcslen(pszProcessName);
	RtlInitUnicodeString( &functionName, L"ZwQuerySystemInformation" );
	pzwQuery = (PZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&functionName);
	do
	{
		pBuffer = ExAllocatePool (NonPagedPool, cbBuffer); 

		if (pBuffer == NULL) 
			return INVALID_HANDLE_VALUE;
		

		Status = pzwQuery(SystemProcessesAndThreadsInformation, pBuffer, cbBuffer, NULL);
		if (Status == STATUS_INFO_LENGTH_MISMATCH) 
		{
			ExFreePool(pBuffer); 
			cbBuffer *= 2; 
		}
		else if (!NT_SUCCESS(Status)) 
		{
			ExFreePool(pBuffer); 
			return INVALID_HANDLE_VALUE; 

		}
	}
	while (Status == STATUS_INFO_LENGTH_MISMATCH);

	pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

	for (;;) 
	{
		
		if(pInfo->ProcessName.Buffer && (nLen<<1)== pInfo->ProcessName.Length)
		{
			if(_wcsnicmp(pInfo->ProcessName.Buffer,pszProcessName,nLen)==0)
			{
				pLargeValue .LowPart=pInfo->dParentProcessID;
				hExclude = (HANDLE)pLargeValue .QuadPart;
				break;
			}
		}
	 
		if (pInfo->NextEntryDelta == 0) 
			break;

		pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo)+ pInfo->NextEntryDelta); 
	}
	ExFreePool(pBuffer);
	
	return hExclude;
}