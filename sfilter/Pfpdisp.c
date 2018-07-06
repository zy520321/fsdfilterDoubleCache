#include <ntifs.h>
#include <stdlib.h>
#include <suppress.h>
#include "filespy.h"
#include "fspyKern.h"
 
VOID
PfpFspDispatchEX (
				  IN PDEVICE_OBJECT  DeviceObject,
				  IN PVOID  Context 

				)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PfpFspDispatch(Context );
}
VOID
PfpFspDispatch (
				 IN PVOID Context
				 )

				 /*++

				 Routine Description:

				 This is the main FSP thread routine that is executed to receive
				 and dispatch IRP requests.  Each FSP thread begins its execution here.
				 There is one thread created at system initialization time and subsequent
				 threads created as needed.

				 Arguments:


				 Context - Supplies the thread id.

				 Return Value:

				 None - This routine never exits

				 --*/

{
	TOP_LEVEL_CONTEXT TopLevelContext;
	PTOP_LEVEL_CONTEXT ThreadTopLevelContext;

	PIRP Irp;
	PIRP_CONTEXT IrpContext;
	
	BOOLEAN Retry;

	IrpContext = (PIRP_CONTEXT)Context;

	Irp = IrpContext->OriginatingIrp;

	//
	//  Now because we are the Fsp we will force the IrpContext to
	//  indicate true on Wait.
	//

	SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
	//
	//  Now case on the function code.  For each major function code,
	//  either call the appropriate FSP routine or case on the minor
	//  function and then call the FSP routine.  The FSP routine that
	//  we call is responsible for completing the IRP, and not us.
	//  That way the routine can complete the IRP and then continue
	//  post processing as required.  For example, a read can be
	//  satisfied right away and then read can be done.
	//
	//  We'll do all of the work within an exception handler that
	//  will be invoked if ever some underlying operation gets into
	//  trouble (e.g., if NtfsReadSectorsSync has trouble).
	//

	
	FsRtlEnterFileSystem();

	ThreadTopLevelContext = PfpSetTopLevelIrp( &TopLevelContext, TRUE, TRUE );
	ASSERT( ThreadTopLevelContext == &TopLevelContext );

	Retry = FALSE;

	

	do 
	{

		__try 
		{

			//
			//  Always clear the exception code in the IrpContext so we respond
			//  correctly to errors encountered in the Fsp.
			//

			IrpContext->ExceptionStatus = 0;

			//ClearFlag( IrpContext->Flags, IRP_CONTEXT_FLAGS_CLEAR_ON_POST );
		
			SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP );
			SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_DONT_DELETE);
			//
			//  If this ins the initial try with this Irp Context, update the
			//  top level Irp fields.
			//

			if (!Retry) 
			{
				PfpUpdateIrpContextWithTopLevel( IrpContext, ThreadTopLevelContext );
			} else 
			{
				Retry = FALSE;
			}

			//
			//  See if we were posted due to a log file full condition, and
			//  if so, then do a clean volume checkpoint if we are the
			//  first ones to get there.  If we see a different Lsn and do
			//  not do the checkpoint, the worst that can happen is that we
			//  will get posted again if the log file is still full.
			//

			//
			//  If we have an Irp then proceed with our normal processing.
			//

			if (Irp != NULL) 
			{

				switch ( IrpContext->MajorFunction ) 
				{

					//
					//  For Create Operation,
					//
					// I will not take care this case for creating delay,
					case IRP_MJ_CREATE:
						(VOID) PfpCommonCreate( IrpContext,  IrpContext->RealDevice,Irp );
						
						break;

						//
						//  For read operations
						//

					case IRP_MJ_READ:

						(VOID) PfpCommonRead( IrpContext, Irp);
						break;

						//
						//  For write operations,
						//

					case IRP_MJ_WRITE:

						(VOID)PfpCommonWrite( IrpContext, Irp );
						break;

						//
						//  For Query Information operations,
						//

					case IRP_MJ_QUERY_INFORMATION:

						(VOID) PfpCommonQueryInformation( IrpContext, Irp );
						break;

						//
						//  For Set Information operations,
						//

					case IRP_MJ_SET_INFORMATION:

						(VOID) PfpCommonSetInformation( IrpContext, Irp );
						break;

			
						//
						//  For Flush buffers operations,
						//

					case IRP_MJ_FLUSH_BUFFERS:

						(VOID) PfpCommonFlushBuffers( IrpContext, Irp );
						break;

						//
						//  For File Cleanup operations,
						//

					case IRP_MJ_CLEANUP:

						(VOID) PfpCommonCleanup( IrpContext, Irp );
						break;


						//
						//  For Lock Control operations,
						//

					case IRP_MJ_LOCK_CONTROL:

						(VOID) PfpCommonLockControl( IrpContext, Irp );
						break;


					default:
	
						PfpCompleteRequest( &IrpContext, &Irp, STATUS_INVALID_DEVICE_REQUEST );
						break;
				}

				//
				//  Otherwise complete the request to clean up this Irp Context.
				//

			} else 
			{
				PfpCompleteRequest( &IrpContext, NULL, STATUS_SUCCESS );
			}

		}
		__except(PfpExceptionFilter( IrpContext, GetExceptionInformation() ))
		 {

			NTSTATUS ExceptionCode;
			PIO_STACK_LOCATION IrpSp;

			//
			//  We had some trouble trying to perform the requested
			//  operation, so we'll abort the I/O request with
			//  the error status that we get back from the
			//  execption code
			//

			if (Irp != NULL)
			{

				IrpSp = IoGetCurrentIrpStackLocation( Irp );

				ExceptionCode = GetExceptionCode();

				if (ExceptionCode == STATUS_FILE_DELETED
					&& (IrpContext->MajorFunction == IRP_MJ_READ
					|| IrpContext->MajorFunction == IRP_MJ_WRITE
					|| (IrpContext->MajorFunction == IRP_MJ_SET_INFORMATION
					&& IrpSp->Parameters.SetFile.FileInformationClass == FileEndOfFileInformation))) 
				{

						IrpContext->ExceptionStatus = ExceptionCode = STATUS_SUCCESS;
				}
			}

			ExceptionCode = PfpProcessException( IrpContext, Irp, ExceptionCode );

			if (ExceptionCode == STATUS_CANT_WAIT ||
				ExceptionCode == STATUS_LOG_FILE_FULL) 
			{

				Retry = TRUE;
			}
		}

	} while (Retry);

	PfpRestoreTopLevelIrp( ThreadTopLevelContext );

	FsRtlExitFileSystem();	

	//
	//  Decrement the PostedRequestCount.
	//

	return;
}
