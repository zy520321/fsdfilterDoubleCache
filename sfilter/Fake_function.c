#include "fspyKern.h"
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
//#include "filespy.h"


#include "Fake_function.h"
NTSTATUS Fake_PfpRead( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsRead(DeviceObject,Irp);
}

NTSTATUS Fake_PfpWrite( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsWrite(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdClose( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsClose(DeviceObject,Irp);
}

NTSTATUS Fake_PfpQueryInformation( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsQuery(DeviceObject,Irp);
}

NTSTATUS Fake_PfpSetInformation( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsSet(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdQueryEa( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsQueryEA(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdSetEa( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsSetEA(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdFlushBuffers( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsFlush(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdCleanup( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsCleanup(DeviceObject,Irp);
}


NTSTATUS Fake_PfpFsQueryAndSetSec( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_NtfsRead(DeviceObject,Irp);
}
//////////////////////////////////////////////////////////////////////////





NTSTATUS Fake_PfpReadFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Read(DeviceObject,Irp);
}

NTSTATUS Fake_PfpWriteFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Write(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdCloseFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Close(DeviceObject,Irp);
}

NTSTATUS Fake_PfpQueryInformationFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Query(DeviceObject,Irp);
}

NTSTATUS Fake_PfpSetInformationFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Set(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdQueryEaFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32QueryEA(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdSetEaFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32SetEA(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdFlushBuffersFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Flush(DeviceObject,Irp);
}

NTSTATUS Fake_PfpFsdCleanupFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Cleanup(DeviceObject,Irp);
}


NTSTATUS Fake_PfpFsQueryAndSetSecFat( __in PDEVICE_OBJECT DeviceObject, __in PIRP Irp )
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	if(pFileObject && PfpFileObjectHasOurFCB(pFileObject ))
	{
		IoGetCurrentIrpStackLocation(Irp)->FileObject = ((PPfpFCB)pFileObject ->FsContext)->pDiskFileObject->pDiskFileObjectWriteThrough;		
	}
	return g_Fat32Query(DeviceObject,Irp);
}