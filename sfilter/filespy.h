 /*++

Copyright (c) 1989-1999  Microsoft Corporation

Module Name:

    filespy.h

Abstract:

    Header file which contains the structures, type definitions,
    and constants that are shared between the kernel mode driver,
    filespy.sys, and the user mode executable, filespy.exe.

Environment:

    Kernel mode

--*/

#ifndef __FILESPY_H__
#define __FILESPY_H__


#include "namelookupdef.h"

//
//  Enable these warnings in the code.
//

#pragma warning(error:4100)   // Unreferenced formal parameter
#pragma warning(error:4101)   // Unreferenced local variable


#define FILESPY_Reset              (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x00, METHOD_BUFFERED, FILE_WRITE_ACCESS )
#define FILESPY_StartLoggingDevice (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x01, METHOD_BUFFERED, FILE_READ_ACCESS )
#define FILESPY_StopLoggingDevice  (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x02, METHOD_BUFFERED, FILE_READ_ACCESS )
#define FILESPY_GetLog             (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x03, METHOD_BUFFERED, FILE_READ_ACCESS )
#define FILESPY_GetVer             (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x04, METHOD_BUFFERED, FILE_READ_ACCESS )
#define FILESPY_ListDevices        (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x05, METHOD_BUFFERED, FILE_READ_ACCESS )
#define FILESPY_GetStats           (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x06, METHOD_BUFFERED, FILE_READ_ACCESS )

#define PFPCOMMAND_AddPrograms     (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x07, METHOD_BUFFERED, FILE_WRITE_ACCESS )//used by config app to add program
#define PFPCOMMAND_DeletePrograms  (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x08, METHOD_BUFFERED, FILE_READ_ACCESS )//used by config app to delete program
#define PFPCOMMAND_GetPrograms	   (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x09, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_SaveConfigInformation	    (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x0A, METHOD_BUFFERED, FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_ClearAllConfigInformation	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x0B, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_LoadConfigInformation		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x0C, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_StartDriver					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x0D, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_StopDriver					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x0E, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_QueryState					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x0F, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_SETBACKUPDIR					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x10, METHOD_BUFFERED, FILE_WRITE_DATA  )//used by app to get all programs to show users.
#define PFPCOMMAND_GETBACKUPDIR					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x11, METHOD_BUFFERED, FILE_READ_ACCESS  )//used by app to get all programs to show users.


#define PFPCOMMAND_GetProgramsLen					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x12, METHOD_BUFFERED, FILE_READ_ACCESS  )//used by app to get all programs to show users.

#define CDO_ADD_FILE						(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x13, METHOD_BUFFERED, FILE_WRITE_ACCESS )//used by app to get all programs to show users.
#define CDO_ADD_DIRECTORY					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x14, METHOD_BUFFERED, FILE_WRITE_ACCESS )//used by app to get all programs to show users.

#define CDO_REMOVE_FILE						(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x15, METHOD_BUFFERED, FILE_WRITE_ACCESS )//used by app to get all programs to show users.
#define CDO_REMOVE_DIRECTORY				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x16, METHOD_BUFFERED, FILE_WRITE_ACCESS )//used by app to get all programs to show users.


#define CDO_GET_FILES						(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x17, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define CDO_GET_FILES_LEN					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x18, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define CDO_GET_DIRECTORYS					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x19, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define CDO_GET_DIRECTORYS_LEN				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x1a, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define CDO_SETBACKUP_FOR_PROCESS_FILETYPE	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x1b, METHOD_BUFFERED, FILE_WRITE_ACCESS )//used by app to get all programs to show users.
#define CDO_GETBACKUP_FOR_PROCESS_FILETYPE	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x1c, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.



#define PFPCOMMAND_DOLOGON					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x20, METHOD_BUFFERED, FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_VIERIFYKEYFILE			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x21, METHOD_BUFFERED, FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_GENKEYFILE				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x22, METHOD_BUFFERED, FILE_WRITE_DATA )//used by app to get all programs to show users.

#define PFPCOMMAND_HASLOGGEDON				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x23, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_ENADNDEBUFFER			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x24, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_CANStopDriver			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x25, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_QueryBACKUP				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x30, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_QueryHIDE				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x31, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.


#define PFPCOMMAND_SETBACKUP				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x32, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_SETHIDE					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x33, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_ISFOLDERPROTECTED		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x34, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define PFPCOMMAND_FOLDERPROTECTED			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x35, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define PFPCOMMAND_QUERYFOLDERPROTECTEDLEN	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x36, METHOD_BUFFERED, FILE_READ_ACCESS)//used by app to get all programs to show users.
#define PFPCOMMAND_QUERY_ALL_FOLDERPROTECTED (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x37, METHOD_BUFFERED, FILE_READ_ACCESS)//used by app to get all programs to show users.

#define PFPCOMMAND_LOCK_AND_UNLOCK_FOLDER	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x38, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_QueryFOLDER				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x39, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_QUERYHIDERLEN			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x3A, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_GETHIDDER			    (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x3B, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_LOCKFOLDERS			    (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x40, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define PFPCOMMAND_UNLOCKFOLDERS			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x41, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define PFPCOMMAND_ModifyPSW				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x42, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS|FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.


#define PFPCOMMAND_SETSYSProtect			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x43, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_QUERYSYSProtect			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x44, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_SETUDISKENCRYPT			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x45, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_QUERYUDISKENCRYPT		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x46, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.



#define PFPCOMMAND_SendReCyclePath			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x47, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define PFPCOMMAND_ENABLE_PROCESS_BACKUP	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x71, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA |FILE_READ_DATA|FILE_READ_ACCESS)//used by app to get all programs to show users.

#define PFPCOMMAND_ENABLE_PROCESS_ENCRYPT	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x72, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_ENABLE_PROCESS_INHER		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x73, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_DeleteProgram			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x60, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA |FILE_READ_DATA|FILE_READ_ACCESS)//used by app to get all programs to show users.

#define PFPCOMMAND_READ_LOG					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x74, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.


#define PFPCOMMAND_LOGEVENT_HANDLE			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x75, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.


#define	PFPCOMMAND_SETLogEnable				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x76, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_QUERYLogStatus			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x77, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_SetForceEncryption			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x78, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.



#define	PFPCOMMAND_QueryFileTypeOfFolderEncryption	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x79, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define	PFPCOMMAND_QueryFileTypeLenForFolder		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x7A, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define	PFPCOMMAND_SetFileTypeForFolderEncryption	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x7B, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.



#define	PFPCOMMAND_GetProgNum	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x80, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetProgHashValues	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x81, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetProgFileTypes	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x82, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetFileTypeNumForProg	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x83, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetProgInfoForProtection	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x84, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_SetFileTypesByArray	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x85, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_SetFolderEncrypt	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x86, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define	PFPCOMMAND_SetFolderBackup	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x87, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define	PFPCOMMAND_SetFolderLockState	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x88, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define	PFPCOMMAND_SetFolderProtectType	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x89, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define	PFPCOMMAND_SetFolderEncryptType	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x90, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define	PFPCOMMAND_IsFolerLocked	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x91, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_SetDispalyNameForFolder	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x92, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define	PFPCOMMAND_GetDispalyNameForFolder	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x93, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_AddFolderProtectionInfo (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x94, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define	PFPCOMMAND_GetNumOfProtectedFolder (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x95, METHOD_BUFFERED,  FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetProtectedFoldersIntoArray (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x96, METHOD_BUFFERED,  FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.


#define	PFPCOMMAND_GetNumOfFileTypesForProtectedFolder	 (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x97, METHOD_BUFFERED,  FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetFileTypesbyArrayForProtectedFolder (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x98, METHOD_BUFFERED,  FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define	PFPCOMMAND_GetNumOfHidder				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x99, METHOD_BUFFERED,  FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define	PFPCOMMAND_GetHidderByArray				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA0, METHOD_BUFFERED,  FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define	PFPCOMMAND_AddHidderItem				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA1, METHOD_BUFFERED,  FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define	PFPCOMMAND_SetUsbDeviceEncryptMode		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA2, METHOD_BUFFERED,  FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.

#define	PFPCOMMAND_GetUsbDeviceEncryptMode		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA3, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS)//used by app to get all programs to show users.

#define	PFPCOMMAND_SetFileTypesForUsbDevice		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA4, METHOD_BUFFERED,  FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define	PFPCOMMAND_GetFileTypesForUsbDevice		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA5, METHOD_BUFFERED,  FILE_READ_DATA|FILE_READ_ACCESS)//used by app to get all programs to show users.

#define	PFPCOMMAND_GetFileTypesNumForUsbDevice		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA6, METHOD_BUFFERED,  FILE_READ_DATA|FILE_READ_ACCESS)//used by app to get all programs to show users.
#define	PFPCOMMAND_AddPrograms_New		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA7, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA)//used by app to get all programs to show users.
#define	PFPCOMMAND_SetFileTypesForFolder		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA8, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA)//used by app to get all programs to show users.
#define	PFPCOMMAND_GetFolderProtectInfo			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xA9, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS|FILE_WRITE_ACCESS|FILE_WRITE_DATA)//used by app to get all programs to show users.

#define PFPCOMMAND_READ_LOG_NEW					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xB0, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_SetFolderProtectInfo			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xB1, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_DeleteProtectorFolder		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xB2, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_IsProcessCanStop			    (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xB3, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_GetBrowserCount			    (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC0, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_GetBrowserHashValues			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC1, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_SetBrowserCreateExeFile		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC2, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_GetBrowserEncryptTypeValue	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC3, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS|FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_GetBrowserEncryptTypes    	(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC4, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS|FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_GetBrowserEncryptTypesNum    (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC5, METHOD_BUFFERED, FILE_READ_DATA|FILE_READ_ACCESS|FILE_WRITE_ACCESS|FILE_WRITE_DATA )//used by app to get all programs to show users.
#define PFPCOMMAND_SetBrowserFileTypesByArray   (ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC6, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_AddBrowserProtection			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC7, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_GetBrowserProtection			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC8, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_SetBrowserEncryptTypeValue		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xC9, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_SetDiaplyFramONWindow			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD0, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_QueryDispalyFramOnWindow			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD1, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA| FILE_READ_DATA|FILE_READ_ACCESS )


#define PFPCOMMAND_QueryUsbDeviceNum				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD2, METHOD_BUFFERED,FILE_READ_DATA|FILE_READ_ACCESS )

#define PFPCOMMAND_QueryUsbAllIds					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD3, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_QueryUsbSecureFileTypsLen		(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD4, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )

#define PFPCOMMAND_QueryUsbControlStatus			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD5, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )

#define PFPCOMMAND_SetUsbControlStatus				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD6, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )

#define PFPCOMMAND_SetUsbEncryptType				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD7, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )
#define PFPCOMMAND_SetUsbEncryptFileTypes			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD8, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )
#define PFPCOMMAND_DeleteUsbSecure			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xD9, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA )
#define PFPCOMMAND_QueryUsbEncryptType				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xDA, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_QueryUsbEncryptFileTypes				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xDB, METHOD_BUFFERED,FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )
#define PFPCOMMAND_USBEVENT_HANDLE					(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xDC, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.




#define PFPCOMMAND_GetUsbDriverLetter				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xDD, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_GetUsbDriverDesrciption			(ULONG)	CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xDE, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_SetUsbDriverDescription			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xDF, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_IsUsbDriverConnected				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xE0, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_IsBrowser				(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xE1, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_SetHideItemState			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xE2, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_DEBUFFER			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xE3, METHOD_BUFFERED, FILE_READ_ACCESS )//used by app to get all programs to show users.

#define PFPCOMMAND_RegisterProtect			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xE4, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define PFPCOMMAND_SetEncryptKey			(ULONG) CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0xE5, METHOD_BUFFERED, FILE_WRITE_ACCESS|FILE_WRITE_DATA|FILE_READ_DATA|FILE_READ_ACCESS )//used by app to get all programs to show users.
#define FILESPY_DRIVER_NAME      L"PfpDrv.SYS"
#define FILESPY_DEVICE_NAME      L"sfilter"
#define FILESPY_W32_DEVICE_NAME  L"\\\\.\\sfilter"
#define FILESPY_DOSDEVICE_NAME   L"\\DosDevices\\sfilter"
#define FILESPY_FULLDEVICE_NAME1 L"\\FileSystem\\Filters\\sfilter"
#define FILESPY_FULLDEVICE_NAME2 L"\\FileSystem\\sfilterCDO"


#define FILESPY_MAJ_VERSION 1
#define FILESPY_MIN_VERSION 0

#ifndef ROUND_TO_SIZE
#define ROUND_TO_SIZE(_length, _alignment)    \
            (((_length) + ((_alignment)-1)) & ~((_alignment) - 1))
#endif

typedef struct _FILESPYVER 
{
    USHORT Major;
    USHORT Minor;
} FILESPYVER, *PFILESPYVER;

//
//  To allow passing up PFILE_OBJECT as a unique file identifier in user-mode.
//
typedef ULONG_PTR FILE_ID;

//
//  To allow passing up PDEVICE_OBJECT as a unique device identifier in
//  user-mode.
//

typedef ULONG_PTR DEVICE_ID;

//
//  To allow passing up PKTRANSACTION as a unique object identifier in 
//  user-mode.

typedef ULONG_PTR TX_ID;

//
//  To allow status values to be passed up to user-mode.
//

typedef LONG NTSTATUS;



//
//  An array of these structures are returned when the attached device list is
//  returned.
//

typedef struct _ATTACHED_DEVICE 
{

    BOOLEAN LoggingOn;
    WCHAR DeviceNames[DEVICE_NAME_SZ];

} ATTACHED_DEVICE, *PATTACHED_DEVICE;

#define MAX_BUFFERS     100

//
//  Attach modes for the filespy kernel driver
//

#define FILESPY_ATTACH_ON_DEMAND    1
    //  Filespy will only attach to a volume when a user asks to start logging
    //  that volume.

#define FILESPY_ATTACH_ALL_VOLUMES  2
    //  VERSION NOTE:
    //
    //  On Windows 2000, Filespy will attach to all volumes in the system that
    //  it sees mount but not turn on logging until requested to through the
    //  filespy user application.  Therefore, if filespy is set to mount on
    //  demand, it will miss the mounting of the local volumes at boot time.
    //  If filespy is set to load at boot time, it will see all the local
    //  volumes be mounted and attach.  This can be beneficial if you want
    //  filespy to attach low in the device stack.
    //
    //  On Windows XP and later, Filespy will attach to all volumes in the
    //  system when it is loaded and all volumes that mount after Filespy is
    //  loaded.  Again, logging on these volumes will not be turned on until
    //  the user asks it to be.
    //


//
//  Size of the actual records with the name built in.
//

#define MAX_NAME_SPACE  (260 * sizeof( WCHAR ))
#define RECORD_SIZE     (SIZE_OF_RECORD_LIST + MAX_NAME_SPACE)

#endif /* __FILESPY_H__ */

