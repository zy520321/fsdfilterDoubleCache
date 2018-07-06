 /*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    namelookupdef.h

Abstract:

    Header file containing the name lookup definitions needed by both user
    and kernel mode.  No kernel-specific data types are used here.


Environment:

    User and kernel.

--*/
#ifndef __KEYVERIFY_H__
#define __KEYVERIFY_H__
typedef enum _tagKEYTYPE
{
	BASIC=0,
	ADVANCED,
	ULTIMATE,
	UNAuth
}KEYTYPE;
BOOLEAN PfpIsKeyCorrectofUltimate(WCHAR* pszUserName,LARGE_INTEGER KeyValue);
BOOLEAN PfpIsKeyCorrectofAdvanced(WCHAR* pszUserName,LARGE_INTEGER KeyValue);
BOOLEAN PfpIsKeyCorrectofBasic(WCHAR* pszUserName,LARGE_INTEGER KeyValue);

PVOID	PfpReadKeyFile(PWCHAR pszKeyFile,ULONG *pnLen);

KEYTYPE PfpGetKeyType(PWCHAR pszKeyFile);
void	decode( UCHAR *infile,ULONG lenin, UCHAR  *outfile,ULONG  lenout );
void	decodeblock( unsigned char in[4], unsigned char out[3] );
#endif

