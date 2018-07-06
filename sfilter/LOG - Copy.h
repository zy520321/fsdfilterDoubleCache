 /*++

Copyright (c) 2008-2009  Erfasoft Corporation

Module Name:

    fspydef.h

Abstract:
    Header file which contains the definitions that may be
    shared with the file spy kernel debugger extensions


Environment:

    Kernel mode

--*/
#ifndef __FSPYDEF_H___LOG
#define __FSPYDEF_H___LOG

typedef struct _tagLog
{
	WCHAR			szBuffer[512];
	WCHAR			szProcessName[20];
	ULONG			ProcessID;
	ULONG			Operation;
	ULONG			encrypt;
}LOGItem;

LOGItem		g_LogItems[500];

FAST_MUTEX  g_LogMutex;


ULONG		g_LognIndex ;
ULONG		g_LognCount ;
ULONG		g_LogMaxCount;

void	AddIntoLogQeuue(WCHAR* szLog,ULONG nLen,
						WCHAR *szDevice,ULONG szdevicesize ,
						WCHAR * ProcessName, ULONG nSize,
						BOOLEAN bCreate,
						BOOLEAN bEncrypted,
						ULONG ProcessID);
 


KEVENT		*g_LogEvent;

BOOLEAN		g_bLog ;
#endif

