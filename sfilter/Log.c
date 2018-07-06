#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
#include "LOG.h"



void	AddIntoLogQeuue(WCHAR* szLog,ULONG nLen,
						WCHAR *szDevice,ULONG szdevicesize ,
						WCHAR * ProcessName, ULONG nSize,
						BOOLEAN bCreate,
						BOOLEAN bEncrypted,
						ULONG ProcessID)
{
	ULONG nIndex = 0;
	if(g_LogEvent==  NULL)
		return ;
	ExAcquireFastMutex(&g_LogMutex);
	
	if( g_LognIndex == g_LogMaxCount )
			g_LognIndex = 0;

	nIndex  = (g_LognIndex+g_LognCount)%g_LogMaxCount;

	if(g_LognCount == g_LogMaxCount)
	{
		g_LognIndex++;	
	}else
	{
		g_LognCount++;
	}
	if(ProcessName)
	{
		memcpy(g_LogItems[nIndex].szProcessName,ProcessName,sizeof(WCHAR)*(min(19,nSize)));
		g_LogItems[nIndex].szProcessName[min(19,nSize)]=L'\0';
	}else
	{
		g_LogItems[nIndex].szProcessName[0]=L'\0';
	}
	if(szDevice && szLog)
	{
		memcpy(g_LogItems[nIndex].szBuffer,szDevice,4);
		memcpy(&g_LogItems[g_LognIndex].szBuffer[2],szLog,sizeof(WCHAR)*(min(509,nLen)));
		g_LogItems[nIndex].szBuffer[min(511,nLen+2)]=0;
	}else
	{
		g_LogItems[nIndex].szBuffer[0]=0;
	}
	g_LogItems[nIndex].Operation = bCreate;
	g_LogItems[nIndex].encrypt   = bEncrypted;
	g_LogItems[nIndex].ProcessID = ProcessID;
	ExReleaseFastMutex(&g_LogMutex);
	if(g_LogEvent)
	{
		KeSetEvent(g_LogEvent ,IO_NO_INCREMENT, FALSE);
	}
}
 
BOOLEAN		GetLogInfoFromQueNew(PREADLOG szLogOut)
{
	ULONG nIndex = 0;

	ExAcquireFastMutex(&g_LogMutex);

	if(g_LognCount == 0)
	{
		ExReleaseFastMutex(&g_LogMutex);
		return FALSE;
	}

	if(g_LognIndex == g_LogMaxCount)
	{
		g_LognIndex =0;		
	}

	memcpy(szLogOut->szName,g_LogItems[g_LognIndex].szProcessName,20*sizeof(WCHAR));
	wcscpy(szLogOut->FilePath,g_LogItems[g_LognIndex].szBuffer);

	szLogOut->Operation = g_LogItems[g_LognIndex].Operation;
	szLogOut->encrypt   = g_LogItems[g_LognIndex].encrypt;
	szLogOut->ProcessID = g_LogItems[g_LognIndex].ProcessID;
	g_LognIndex++;
	g_LognCount--;

	ExReleaseFastMutex(&g_LogMutex);	
	return TRUE;
}