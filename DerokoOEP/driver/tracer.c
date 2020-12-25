#include <ntifs.h>
#include <ntstrsafe.h>
#include "..\tracer.h"

#define MAX_PROCESSORS (RTL_BITS_OF(ULONG_PTR))
const ULONG dwPageSize=0x1000;
const ULONG dwPoolTag='FOUQ';

#pragma pack(push,1)

typedef struct
{
	USHORT IdtLimit;
	ULONG_PTR IdtBase;
} SIDT_ENTRY;

typedef struct
{
	ULONG LowPart:16;
	ULONG SegmentSelector:16;
	ULONG Reserved1:5;
	ULONG Reserved2:3;
	ULONG Type:3;
	ULONG Size:1;
	ULONG Reserved3:1;
	ULONG Dpl:2;
	ULONG Present:1;
	ULONG HighPart:16;
#if defined _M_AMD64
	ULONG HighestPart;
	ULONG Reserved;
#endif
} KIDT_ENTRY;

typedef struct
{
	ULONG Present:1;
	ULONG ReadWrite:1;
	ULONG UserSupervisor:1;
	ULONG WriteThrough:1;
	ULONG CacheDisabled:1;
	ULONG Accessed:1;
	ULONG Dirty:1;
	ULONG PageAttributeTable:1;
	ULONG Global:1;
	ULONG Ignored:3;
	ULONG PhysicalAddress:20;
} PTE_NOPAE;

typedef struct
{
	ULONGLONG Present:1;
	ULONGLONG ReadWrite:1;
	ULONGLONG UserSupervisor:1;
	ULONGLONG WriteThrough:1;
	ULONGLONG CacheDisabled:1;
	ULONGLONG Accessed:1;
	ULONGLONG Dirty:1;
	ULONGLONG PageAttributeTable:1;
	ULONGLONG Global:1;
	ULONGLONG Ignored:3;
	ULONGLONG PhysicalAddress:24;
	ULONGLONG Reserved:27;
	ULONGLONG NX:1;
} PTE_PAE;

typedef struct
{
	ULONG_PTR pEThread;
	ULONG_PTR CurrentIp;
	ULONG_PTR CurrentCR2;
	ULONG_PTR IsExec;
} THREAD_STATE;

#pragma pack(pop)

ULONG_PTR OriginalInt1[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0E[MAX_PROCESSORS]={0};

BOOLEAN fPaeEnabled=FALSE;
TRACER_STRUCT TracerData,*pUserTracerData=NULL;
PMDL pMdl=NULL;
ULONG Counter=0;
HANDLE GlobalPID=NULL;
BREAKPOINT Bpx={0};
THREAD_STATE Threads[1024]={0};

WCHAR szDevice[256]=L"\\Device";
WCHAR szSymLink[256]=L"\\DosDevices";

extern void DoCli();

extern void EngineInt01(void);
extern void EngineInt0e(void);

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(__in HANDLE ProcessId,__deref_out PEPROCESS *Process);

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeAttachProcess(__inout PEPROCESS Process);

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeDetachProcess();

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ZwYieldExecution();

ULONG_PTR __stdcall GetProcessorNumber()
{
	return KeGetCurrentProcessorNumber();
}

#pragma optimize("",off)
UCHAR TouchPage(ULONG_PTR Address)
{
	return *(UCHAR*)Address;
}
#pragma optimize("",on)

PTE_NOPAE *FindPTE_NoPAE(ULONG_PTR Address)
{
	return (PTE_NOPAE*)(NON_PAE_PTE_BASE+sizeof(PTE_NOPAE)*(Address>>12));
}

PTE_PAE *FindPTE_PAE(ULONG_PTR Address)
{
	return (PTE_PAE*)(PAE_PTE_BASE+sizeof(PTE_PAE)*(Address>>12));
}

ULONG_PTR __stdcall Deactivate(ULONG_PTR Address)
{
	if(fPaeEnabled!=FALSE)
	{
		PTE_PAE *Pointer=FindPTE_PAE(Address);
		if(Pointer->Present!=0)
		{
			Pointer->UserSupervisor=1;
			return (ULONG_PTR)Pointer->ReadWrite;
		}
		else
			return 0;
	}
	else
	{
		PTE_NOPAE *Pointer=FindPTE_NoPAE(Address);
		if(Pointer->Present!=0)
		{
			Pointer->UserSupervisor=1;
			return (ULONG_PTR)Pointer->ReadWrite;
		}
		else
			return 0;
	}
}

void DeactivateAll()
{
	ULONG_PTR Current;

	__try
	{
		ProbeForRead((void*)Bpx.StartRange,Bpx.BpSize,1);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	for(Current=Bpx.StartRange;Current<Bpx.StartRange+Bpx.BpSize;Current+=PAGE_SIZE)
	{
		TouchPage(Current);				//pagein page...
		Deactivate(Current);
		__invlpg(Current);
	}
}

ULONG_PTR __stdcall Activate(ULONG_PTR Address)
{
	if(fPaeEnabled!=FALSE)
	{
		PTE_PAE *Pointer=FindPTE_PAE(Address);
		if(Pointer->Present!=0)
		{
			Pointer->UserSupervisor=0;
			return (ULONG_PTR)Pointer->ReadWrite;
		}
		else
			return 0;
	}
	else
	{
		PTE_NOPAE *Pointer=FindPTE_NoPAE(Address);
		if(Pointer->Present!=0)
		{
			Pointer->UserSupervisor=0;
			return (ULONG_PTR)Pointer->ReadWrite;
		}
		else
			return 0;
	}
}

void ActivateAll()
{
	ULONG_PTR Current;
	__try
	{
		ProbeForRead((void*)Bpx.StartRange,Bpx.BpSize,1);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	for(Current=Bpx.StartRange;Current<Bpx.StartRange+Bpx.BpSize;Current+=PAGE_SIZE)
	{
		TouchPage(Current);				//pagein page...
		Activate(Current);
		__invlpg(Current);
	}
}

NTSTATUS UnhookPages()
{
	PEPROCESS pEProcess;

	Bpx.MyCr3=0;
	Bpx.StartRange=0;
	Bpx.BpSize=0;

	if(GlobalPID!=NULL)
	{
		if(PsLookupProcessByProcessId(GlobalPID,&pEProcess)!=STATUS_SUCCESS)
			return STATUS_INVALID_PARAMETER;

		KeAttachProcess(pEProcess);

		__try
		{
			DeactivateAll();
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			KeDetachProcess();
			ObDereferenceObject(pEProcess);
			GlobalPID=NULL;
			return GetExceptionCode();
		}
		KeDetachProcess();
		ObDereferenceObject(pEProcess);
		GlobalPID=NULL;
	}
	return STATUS_SUCCESS;
}

void __stdcall AddThread(ULONG_PTR CurrentIp,ULONG_PTR CurrentCR2,ULONG_PTR IsExec)
{
	ULONG i;

	for(i=0;i!=RTL_NUMBER_OF(Threads);++i)
	{
		if(Threads[i].pEThread==0)
		{
			Threads[i].pEThread=(ULONG_PTR)PsGetCurrentThread();
			Threads[i].CurrentIp=CurrentIp;
			Threads[i].CurrentCR2=CurrentCR2;
			Threads[i].IsExec=IsExec;
			break;
		}
	}
}

THREAD_STATE *__stdcall FindThread()
{
	ULONG i;

	for(i=0;i!=RTL_NUMBER_OF(Threads);++i)
	{
		if((ULONG_PTR)PsGetCurrentThread()==Threads[i].pEThread)
			return &Threads[i];
	}
	return 0;
}

ULONG_PTR __stdcall WaitRing3Process(ULONG_PTR IpInRange)
{
	TracerData.CurrentIp=IpInRange;
	TracerData.State=STATE_WAIT;

	while(TracerData.State==STATE_WAIT)
		ZwYieldExecution();
	return TracerData.CurrentIp;
}

void HookInterrupt(KIDT_ENTRY *pIdtEntry,ULONG IntNumber,ULONG_PTR NewAddress,ULONG_PTR *pOldAddress,ULONG_PTR BakAddress)
{
	ULONG_PTR Current,CurrentFlags;
	KIDT_ENTRY OldIdtEntry,NewIdtEntry;

	if(NewAddress==0)
		return;

	CurrentFlags=__readeflags();
	DoCli();

	OldIdtEntry=pIdtEntry[IntNumber];
#if defined _M_AMD64
	Current=((ULONG_PTR)OldIdtEntry.HighestPart << 0x20)+(OldIdtEntry.HighPart << 0x10)+OldIdtEntry.LowPart;
#elif defined _M_IX86
	Current=(OldIdtEntry.HighPart << 0x10)+OldIdtEntry.LowPart;
#else
!!!
#endif

	if(NewAddress==Current)
	{
		if(pOldAddress!=NULL)
			*pOldAddress=BakAddress;
	}
	else
	{
		if(pOldAddress!=NULL)
			*pOldAddress=Current;

		NewIdtEntry=OldIdtEntry;
#if defined _M_AMD64
		NewIdtEntry.HighestPart=(ULONG)(NewAddress >> 0x20);
#endif
		NewIdtEntry.HighPart=(USHORT)((NewAddress >> 0x10) & 0xffff);
		NewIdtEntry.LowPart=(USHORT)(NewAddress & 0xffff);

#if defined _M_AMD64
		_InterlockedCompareExchange128((__int64*)&pIdtEntry[IntNumber],*((__int64*)&NewIdtEntry+1),*(__int64*)&NewIdtEntry,(__int64*)&OldIdtEntry);
#elif defined _M_IX86
		_InterlockedCompareExchange64((__int64*)&pIdtEntry[IntNumber],*(__int64*)&NewIdtEntry,*(__int64*)&OldIdtEntry);
#else
!!!
#endif
	}
	_mm_sfence();
	__writeeflags(CurrentFlags);
}

void TracerHook(BOOLEAN fEnableHook)
{
	ULONG i,j;
	KAFFINITY AffinityMask,OldAffinityMask,TargetAffinityMask;
	SIDT_ENTRY Idt;
	PROCESS_BASIC_INFORMATION pbi;
	ULONG_PTR IdtBase[MAX_PROCESSORS]={0};

	memset(&pbi,0,sizeof(pbi));
	NtQueryInformationProcess(NtCurrentProcess(),ProcessBasicInformation,&pbi,sizeof(pbi),NULL);
	OldAffinityMask=pbi.AffinityMask;

	AffinityMask=KeQueryActiveProcessors();

	for(i=0;i!=MAX_PROCESSORS;++i)
	{
		TargetAffinityMask=(ULONG_PTR)1<<i;

		if((AffinityMask & TargetAffinityMask)==0)
			continue;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&TargetAffinityMask,sizeof(TargetAffinityMask));

		__sidt(&Idt);
		IdtBase[i]=Idt.IdtBase;

		for(j=0;j!=i;++j)
		{
			if(IdtBase[j]==Idt.IdtBase)
				break;
		}

		if(fEnableHook!=FALSE)
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,1,(ULONG_PTR)EngineInt01,&OriginalInt1[i],OriginalInt1[j]);
		else
		{
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,1,OriginalInt1[i],NULL,0);
			OriginalInt1[i]=0;
		}

		if(fEnableHook!=FALSE)
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,0xe,(ULONG_PTR)EngineInt0e,&OriginalInt0E[i],OriginalInt0E[j]);
		else
		{
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,0xe,OriginalInt0E[i],NULL,0);
			OriginalInt0E[i]=0;
		}

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
}

void Unhook()
{
	UnhookPages();
	TracerHook(FALSE);

	while(Counter!=0)
	{
		TracerData.State=STATE_READY;
		ZwYieldExecution();
	}

	if(pUserTracerData!=NULL)
	{
		MmUnmapLockedPages(pUserTracerData,pMdl);
		pUserTracerData=NULL;
		IoFreeMdl(pMdl);
		pMdl=NULL;
	}
}

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH CreateHandler;
NTSTATUS CreateHandler(PDEVICE_OBJECT pDevice,PIRP pIrp)
{
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	pIrp->IoStatus.Information=0;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH CloseHandler;
NTSTATUS CloseHandler(PDEVICE_OBJECT pDevice,PIRP pIrp)
{
	Unhook();

	pIrp->IoStatus.Status=STATUS_SUCCESS;
	pIrp->IoStatus.Information=0;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH ServiceHandler;
NTSTATUS ServiceHandler(PDEVICE_OBJECT pDevice,PIRP pIrp)
{
	NTSTATUS Status=STATUS_INVALID_PARAMETER;
	PIO_STACK_LOCATION IrpStack;
	ULONG Information=0,InputBufferLength,OutputBufferLength;
	PVOID pBuffer;
	PROCESS_INFO *pProcessInfo;
	TRACER_STRUCT *pTracerStruct;
	PEPROCESS pEProcess;
	ULONG i;

	IrpStack=IoGetCurrentIrpStackLocation(pIrp);
	pBuffer=pIrp->AssociatedIrp.SystemBuffer;
	InputBufferLength=IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength=IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch(IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
		case GET_VERSION:
			if(OutputBufferLength!=sizeof(ULONG))
				break;
			*(ULONG*)pBuffer=CURRENT_VERSION;
			Information=sizeof(ULONG);
			Status=STATUS_SUCCESS;
			break;
		case INIT_TRACER:
			if(OutputBufferLength!=sizeof(ULONG_PTR))
				break;
			if(pUserTracerData==NULL)
			{
				pMdl=IoAllocateMdl(&TracerData,sizeof(TRACER_STRUCT),FALSE,FALSE,NULL);
				MmBuildMdlForNonPagedPool(pMdl);
				__try
				{
					pUserTracerData=(TRACER_STRUCT*)MmMapLockedPagesSpecifyCache(pMdl,UserMode,MmCached,NULL,FALSE,NormalPagePriority);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					pUserTracerData=NULL;
					IoFreeMdl(pMdl);
					pMdl=NULL;
				}
			}
			*(ULONG_PTR*)pBuffer=(ULONG_PTR)pUserTracerData;
			Information=sizeof(ULONG_PTR);
			Status=STATUS_SUCCESS;
			break;
		case SET_RANGE:
			if(InputBufferLength!=sizeof(PROCESS_INFO))
				break;

			pProcessInfo=(PROCESS_INFO*)pBuffer;

			Bpx.StartRange=pProcessInfo->StartRange & ~(PAGE_SIZE-1);
			Bpx.BpSize=((pProcessInfo->Size-1) & ~(PAGE_SIZE-1))+PAGE_SIZE;

			if(Bpx.StartRange>(ULONG_PTR)MM_HIGHEST_USER_ADDRESS || Bpx.BpSize>(ULONG_PTR)MM_HIGHEST_USER_ADDRESS
				|| Bpx.StartRange+Bpx.BpSize>(ULONG_PTR)MM_HIGHEST_USER_ADDRESS)
				break;

			if(PsLookupProcessByProcessId(pProcessInfo->Pid,&pEProcess)!=STATUS_SUCCESS)
				break;

			KeAttachProcess(pEProcess);

			__try
			{
				ActivateAll();
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				KeDetachProcess();
				ObDereferenceObject(pEProcess);
				Status=GetExceptionCode();
				break;
			}

			Bpx.MyCr3=__readcr3();

			GlobalPID=pProcessInfo->Pid;

			KeDetachProcess();
			ObDereferenceObject(pEProcess);

			for(i=0;i!=RTL_NUMBER_OF(Threads);++i)
				Threads[i].pEThread=0;
			TracerData.State=STATE_READY;

			Information=0;
			Status=STATUS_SUCCESS;
			break;
		case STOP_TRACER:
			Information=0;
			Status=UnhookPages();
			break;
	}
	pIrp->IoStatus.Status=Status;
	pIrp->IoStatus.Information=Information;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return Status;
}

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING SymbolicLink;

	Unhook();

	RtlUnicodeStringInit(&SymbolicLink,szSymLink);
	IoDeleteSymbolicLink(&SymbolicLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

VOID SetDeviceDacl(PDEVICE_OBJECT pDeviceObject)
{
	HANDLE hDevice;
	PACL pAcl;
	ULONG AclSize;
	SECURITY_DESCRIPTOR SecDesc;

	ObOpenObjectByPointer(pDeviceObject,OBJ_KERNEL_HANDLE,NULL,WRITE_DAC,NULL,KernelMode,&hDevice);

	AclSize=sizeof(ACL);
	AclSize+=RtlLengthSid(SeExports->SeLocalSystemSid);
	AclSize+=RtlLengthSid(SeExports->SeAliasAdminsSid);
	AclSize+=2*FIELD_OFFSET(ACCESS_ALLOWED_ACE,SidStart);

	pAcl=ExAllocatePoolWithTag(PagedPool,AclSize,dwPoolTag);
	RtlCreateAcl(pAcl,AclSize,ACL_REVISION);
	RtlAddAccessAllowedAce(pAcl,ACL_REVISION,GENERIC_READ | GENERIC_WRITE | DELETE,SeExports->SeLocalSystemSid);
	RtlAddAccessAllowedAce(pAcl,ACL_REVISION,GENERIC_READ | GENERIC_WRITE | DELETE,SeExports->SeAliasAdminsSid);

	RtlCreateSecurityDescriptor(&SecDesc,SECURITY_DESCRIPTOR_REVISION);
	RtlSetDaclSecurityDescriptor(&SecDesc,TRUE,pAcl,FALSE);
	ZwSetSecurityObject(hDevice,DACL_SECURITY_INFORMATION,&SecDesc);

	ExFreePoolWithTag(pAcl,dwPoolTag);
	ZwClose(hDevice);
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pRegPath)
{
	int i;
	UNICODE_STRING DeviceName,SymbolicLink;
	PDEVICE_OBJECT pDeviceObject;
	ULONG_PTR CurrentCR4;

	CurrentCR4=__readcr4();
	if((CurrentCR4 & 0x20)!=0)
		fPaeEnabled=TRUE;
	else
		fPaeEnabled=FALSE;

	TracerHook(TRUE);

	for(i=wcslen(pRegPath->Buffer)-1;i>0;--i)
	{
		if(pRegPath->Buffer[i]==L'\\')
			break;
	}

	RtlStringCbCatW(szDevice,sizeof(szDevice),pRegPath->Buffer+i);
	RtlStringCbCatW(szSymLink,sizeof(szSymLink),pRegPath->Buffer+i);

	RtlUnicodeStringInit(&DeviceName,szDevice);
	if(IoCreateDevice(pDriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,0,TRUE,&pDeviceObject)!=STATUS_SUCCESS)
	{
		TracerHook(FALSE);
		return STATUS_UNSUCCESSFUL;
	}
	SetDeviceDacl(pDeviceObject);
	pDeviceObject->Flags|=DO_BUFFERED_IO;
	RtlUnicodeStringInit(&SymbolicLink,szSymLink);
	IoCreateSymbolicLink(&SymbolicLink,&DeviceName);

	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=ServiceHandler;
	pDriverObject->MajorFunction[IRP_MJ_CREATE]=CreateHandler;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]=CloseHandler;
	pDriverObject->DriverUnload=DriverUnload;
	return STATUS_SUCCESS;
}