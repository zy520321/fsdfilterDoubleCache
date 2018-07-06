#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
 
BOOLEAN
PfpZeroData (
			  IN PIRP_CONTEXT IrpContext,
			  IN PPfpFCB Scb,
			  IN PFILE_OBJECT FileObject,
			  IN LONGLONG StartingZero,
			  IN LONGLONG ByteCount
			  )

			  /*++

			  Routine Description:

			  This routine is called to zero a range of a file in order to
			  advance valid data length.

			  Arguments:

			  Scb - Scb for the stream to zero.

			  FileObject - FileObject for the stream.

			  StartingZero - Offset to begin the zero operation.

			  ByteCount - Length of range to zero.

			  Return Value:

			  BOOLEAN - TRUE if the entire range was zeroed, FALSE if the request
			  is broken up or the cache manager would block.

			  --*/

{	
	ULONG SectorSize;
	BOOLEAN Finished;
	BOOLEAN CompleteZero = TRUE;
	BOOLEAN ScbAcquired = FALSE;

	LONGLONG ZeroStart;
	LONGLONG BeyondZeroEnd;	

	BOOLEAN Wait;
	PAGED_CODE();

	Wait = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);

	SectorSize = 512;

	//
	//  If this is a non-compressed file and the amount to zero is larger
	//  than our threshold then limit the range.
	//

	if (ByteCount > MAX_ZERO_THRESHOLD) 
	{
		ByteCount = MAX_ZERO_THRESHOLD;
		CompleteZero = FALSE;
	}

	ZeroStart = StartingZero + (SectorSize - 1);
	(ULONG)ZeroStart &= ~(SectorSize - 1);

	BeyondZeroEnd = StartingZero + ByteCount + (SectorSize - 1);
	(ULONG)BeyondZeroEnd &= ~(SectorSize - 1);

	
	//
	//  If we were called to just zero part of a sector we are screwed.
	//

	if (ZeroStart == BeyondZeroEnd)
	{
		return TRUE;
	}

	if( (BeyondZeroEnd>(ZeroStart+(ULONG)0x10000)) && !Wait)
	{
		Wait = TRUE;
	}

	Finished = CcZeroData( FileObject,
							(PLARGE_INTEGER)&ZeroStart,
							(PLARGE_INTEGER)&BeyondZeroEnd,
							Wait );

	//
	//  If we are breaking this request up then commit the current
	//  transaction (including updating the valid data length in
	//  in the Scb) and return FALSE.
	//

	if (Finished && !CompleteZero)
	{

		//
		//  Synchronize the valid data length change using the mutex.
		//

		ExAcquireFastMutex( Scb->Header.FastMutex );
		Scb->Header.ValidDataLength.QuadPart = BeyondZeroEnd;
		ExReleaseFastMutex( Scb->Header.FastMutex );
		
		return FALSE;
	}

	return Finished;
}
