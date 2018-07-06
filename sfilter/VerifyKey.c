 /*++

Copyright (c) 1998-1999 Microsoft Corporation

Module Name:

    fspyTx.c

Abstract:

    This module contains the support routines for the KTM transactions.
    This feature is only available in windows VISTA and later.

Environment:

    Kernel mode

--*/

#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#include <ntifs.h>
#include <stdio.h>
#include "filespy.h"
#include "fspyKern.h"
#include "VerifyKey.h"
BOOLEAN PfpIsKeyCorrectofBasic(WCHAR* pszUserName,LARGE_INTEGER KeyValue)
{
	LARGE_INTEGER Value;
	USHORT value1 ;
	USHORT* pBytes= NULL;
	UINT  n;
	pBytes= (USHORT*)&Value.QuadPart;
	value1  = (USHORT)pszUserName[0];
	
	for(n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 *=pszUserName[n];
		}
	}

	pBytes[0] = value1;

	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 *=pszUserName[n];
		}
		else
		{
			value1 +=pszUserName[n];
		}
	}
	pBytes[1] = value1;


	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 -=pszUserName[n];
		}
	}
	pBytes[2] = value1;


	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 -=pszUserName[n];
		}
	}
	pBytes[3] = value1;


	pBytes[0] = pBytes[0] *pBytes[1];
	pBytes[1] = pBytes[1] *pBytes[2];
	pBytes[2] = pBytes[2] *pBytes[3];
	pBytes[3] = pBytes[3] *pBytes[0];

	pBytes[0] = pBytes[3] *pBytes[1];
	pBytes[2] = pBytes[3] *pBytes[2];
	pBytes[1] = pBytes[1] *pBytes[2];
	return (KeyValue.QuadPart == Value.QuadPart);
}
BOOLEAN PfpIsKeyCorrectofAdvanced(WCHAR* pszUserName,LARGE_INTEGER KeyValue)
{
	LARGE_INTEGER Value;
	USHORT value1 ;
	USHORT* pBytes= NULL;
	UINT  n;
	pBytes= (USHORT*)&Value.QuadPart;
	value1  = (USHORT)pszUserName[0];
	for(n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 *=pszUserName[n];
		}
	}

	pBytes[0] = value1;

	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 *=pszUserName[n];
		}
		else
		{
			value1 +=pszUserName[n];
		}
	}
	pBytes[2] = value1;


	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 -=pszUserName[n];
		}
	}
	pBytes[1] = value1;


	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 -=pszUserName[n];
		}
	}
	pBytes[3] = value1;


	pBytes[0] = pBytes[3] *pBytes[1];
	pBytes[2] = pBytes[3] *pBytes[2];
	pBytes[1] = pBytes[1] *pBytes[2];

	pBytes[0] = pBytes[0] *pBytes[1];
	pBytes[1] = pBytes[1] *pBytes[2];
	pBytes[2] = pBytes[2] *pBytes[3];
	pBytes[3] = pBytes[3] *pBytes[0];


	return (KeyValue.QuadPart == Value.QuadPart);
};
BOOLEAN PfpIsKeyCorrectofUltimate(WCHAR* pszUserName,LARGE_INTEGER KeyValue)
{
	LARGE_INTEGER Value;
	USHORT value1 ;
	USHORT* pBytes= NULL;
	UINT  n;
	pBytes= (USHORT*)&Value.QuadPart;
	value1  = (USHORT)pszUserName[0];
	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 *=pszUserName[n];
		}
	}

	pBytes[3] = value1;

	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 *=pszUserName[n];
		}
		else
		{
			value1 +=pszUserName[n];
		}
	}
	pBytes[2] = value1;


	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 -=pszUserName[n];
		}
	}
	pBytes[1] = value1;


	for(  n=1;n<wcslen(pszUserName);n++)
	{
		if(n<3)
		{
			value1 +=pszUserName[n];
		}
		else
		{
			value1 -=pszUserName[n];
		}
	}
	pBytes[0] = value1;


	pBytes[0] = pBytes[0] *pBytes[1];
	pBytes[1] = pBytes[1] *pBytes[2];


	pBytes[0] = pBytes[3] *pBytes[1];
	pBytes[2] = pBytes[3] *pBytes[2];

	pBytes[2] = pBytes[2] *pBytes[3];
	pBytes[3] = pBytes[3] *pBytes[0];


	pBytes[1] = pBytes[1] *pBytes[2];

	return (KeyValue.QuadPart == Value.QuadPart);

}

PVOID	PfpReadKeyFile(PWCHAR pszKeyFile,ULONG *pnLen)
{
	return NULL;
}

KEYTYPE PfpGetKeyType(PWCHAR pszKeyFile)
{

	return BASIC;
}
/*
** Translation Table to decode (created by author)
*/
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
void decodeblock( unsigned char in[4], unsigned char out[3] )
{   
	out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
	out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
	out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}
void	decode( UCHAR *infile,ULONG lenin, UCHAR  *outfile,ULONG  lenout )
{
/*	unsigned char in[4], out[3], v;
	int i, len;
	
	while( !feof( infile ) ) 
	{
		for( len = 0, i = 0; i < 4 && !feof( infile ); i++ ) 
		{
			v = 0;
			while( !feof( infile ) && v == 0 ) 
			{
				v = (unsigned char) getc( infile );
				v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
				if( v )
				{
					v = (unsigned char) ((v == '$') ? 0 : v - 61);
				}
			}
			if( !feof( infile ) ) 
			{
				len++;
				if( v ) 
				{
					in[ i ] = (unsigned char) (v - 1);
				}
			}
			else 
			{
				in[i] = 0;
			}
		}
		if( len ) 
		{
			decodeblock( in, out );
			for( i = 0; i < len - 1; i++ ) 
			{
				putc( out[i], outfile );
			}
		}
	}*/
}