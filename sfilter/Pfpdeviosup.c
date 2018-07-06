#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
  
VOID
PfpLockUserBuffer (
					IN PIRP_CONTEXT IrpContext,
					IN OUT PIRP Irp,
					IN LOCK_OPERATION Operation,
					IN ULONG BufferLength
					)

					/*++

					Routine Description:

					This routine locks the specified buffer for the specified type of
					access.  The file system requires this routine since it does not
					ask the I/O system to lock its buffers for direct I/O.  This routine
					may only be called from the Fsd while still in the user context.

					Arguments:

					Irp - Pointer to the Irp for which the buffer is to be locked.

					Operation - IoWriteAccess for read operations, or IoReadAccess for
					write operations.

					BufferLength - Length of user buffer.

					Return Value:

					None

					--*/

{
	PMDL Mdl = NULL;

	//ASSERT_IRP_CONTEXT( IrpContext );
	//ASSERT_IRP( Irp );

	if (Irp->MdlAddress == NULL) 
	{

		//
		// Allocate the Mdl, and Raise if we fail.
		//

		Mdl = IoAllocateMdl( Irp->UserBuffer, BufferLength, FALSE, FALSE, Irp );

		if (Mdl == NULL) 
		{

			PfpRaiseStatus( IrpContext, STATUS_INSUFFICIENT_RESOURCES, NULL );
		}

		//
		//  Now probe the buffer described by the Irp.  If we get an exception,
		//  deallocate the Mdl and return the appropriate "expected" status.
		//

		__try 
		{

			MmProbeAndLockPages( Mdl, Irp->RequestorMode, Operation );

		} 
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

			NTSTATUS Status;

			Status = GetExceptionCode();

			IoFreeMdl( Mdl );
			Irp->MdlAddress = NULL;

			PfpRaiseStatus( IrpContext,
							FsRtlIsNtstatusExpected(Status) ? Status : STATUS_INVALID_USER_BUFFER,
							NULL
							);
		}
	}

	//
	//  And return to our caller
	//

	return;
}



PVOID
PfpMapUserBuffer (
				  IN OUT PIRP Irp
				  )

				  /*++

				  Routine Description:

				  This routine conditionally maps the user buffer for the current I/O
				  request in the specified mode.  If the buffer is already mapped, it
				  just returns its address.

				  Arguments:

				  Irp - Pointer to the Irp for the request.

				  Return Value:

				  Mapped address

				  --*/

{
	PVOID SystemBuffer;
	PAGED_CODE();

	//
	// If there is no Mdl, then we must be in the Fsd, and we can simply
	// return the UserBuffer field from the Irp.
	//

	if (Irp->MdlAddress == NULL) 
	{
		SystemBuffer = Irp->UserBuffer;

	} else 
	{
		//
		//  MM can return NULL if there are no system ptes.
		//
		SystemBuffer = MmGetSystemAddressForMdlSafe ( Irp->MdlAddress,NormalPagePriority  );

	}
	return SystemBuffer;
}