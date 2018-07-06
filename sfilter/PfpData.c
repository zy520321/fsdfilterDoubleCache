
#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
  

LONG
PfpProcessExceptionFilter (
							IN PEXCEPTION_POINTERS ExceptionPointer
							)
{
	UNREFERENCED_PARAMETER( ExceptionPointer );

	ASSERT( NT_SUCCESS( ExceptionPointer->ExceptionRecord->ExceptionCode ));

	return EXCEPTION_EXECUTE_HANDLER;
}



VOID
PfpRaiseStatus (
				 IN PIRP_CONTEXT IrpContext,
				 IN NTSTATUS Status,				
				 IN PPfpFCB Fcb OPTIONAL
				 )

{
	//
	//  If the caller is declaring corruption, then let's mark the
	//  the volume corrupt appropriately, and maybe generate a popup.
	//

	/*if (Status == STATUS_DISK_CORRUPT_ERROR) {

		NtfsPostVcbIsCorrupt( IrpContext, Status, FileReference, Fcb );

	} else if ((Status == STATUS_FILE_CORRUPT_ERROR) ||
		(Status == STATUS_EA_CORRUPT_ERROR)) {

			NtfsPostVcbIsCorrupt( IrpContext, Status, FileReference, Fcb );
	}
*/
	//
	//  Set a flag to indicate that we raised this status code and store
	//  it in the IrpContext.
	//
	UNREFERENCED_PARAMETER( Fcb );

	SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_RAISED_STATUS );

	if (NT_SUCCESS( IrpContext->ExceptionStatus ))
	{

		//
		//  If this is a paging io request and we got a Quota Exceeded error
		//  then translate the status to FILE_LOCK_CONFLICT so that this
		//  is a retryable condition.
		//

		if ((Status == STATUS_QUOTA_EXCEEDED) &&
			(IrpContext->OriginatingIrp != NULL) &&
			(FlagOn( IrpContext->OriginatingIrp->Flags, IRP_PAGING_IO )))
		{

				Status = STATUS_FILE_LOCK_CONFLICT;
		}

		IrpContext->ExceptionStatus = Status;
	}

	//
	//  Now finally raise the status, and make sure we do not come back.
	//

	ExRaiseStatus( IrpContext->ExceptionStatus );
}
