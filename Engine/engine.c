#include <ntifs.h>
#include <ntstrsafe.h>
#include "..\interface.h"

#define MAX_PROCESSORS (RTL_BITS_OF(ULONG_PTR))
const ULONG dwPoolTag='pnUQ';

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

#pragma pack(pop)

ULONG Counter=0,ProcessID=0,Shift=0;
ULONG IncreaseAX=0,IncreaseDX=0;
ULONG_PTR OriginalInt1[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0D[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0E[MAX_PROCESSORS]={0};
ULONG_PTR OriginalCR4[MAX_PROCESSORS]={0};
DATA_STATE DataState,*pUserDataState=NULL;
PMDL pMdl=NULL;

WCHAR szDevice[256]=L"\\Device";
WCHAR szSymLink[256]=L"\\DosDevices";

extern void DoCli();

extern void EngineInt1(void);
extern void EngineInt0d(void);
extern void EngineInt0e(void);

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ZwYieldExecution();

ULONG_PTR __stdcall GetProcessorNumber()
{
	return KeGetCurrentProcessorNumber();
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

void EmulateRdtsc(ULONG Hook)
{
	ULONG i;
	KAFFINITY AffinityMask,OldAffinityMask,TargetAffinityMask;
	PROCESS_BASIC_INFORMATION pbi;

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
		if(Hook!=0)
		{
			if(OriginalCR4[i]==0)
			{
				OriginalCR4[i]=__readcr4();
				__writecr4(OriginalCR4[i] | 4);
			}
		}
		else
		{
			if(OriginalCR4[i]!=0)
			{
				__writecr4(OriginalCR4[i]);
				OriginalCR4[i]=0;
			}
		}
		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
}

void EngineHook(const DATA_HOOK *pDataHook)
{
	ULONG i,j;
	KAFFINITY AffinityMask,OldAffinityMask,TargetAffinityMask;
	SIDT_ENTRY Idt;
	PROCESS_BASIC_INFORMATION pbi;
	ULONG_PTR IdtBase[MAX_PROCESSORS]={0};

	ProcessID=pDataHook->ProcessID;

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

		if(pDataHook->Int1==HOOK_HOOK)
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,1,(ULONG_PTR)EngineInt1,&OriginalInt1[i],OriginalInt1[j]);
		else if(pDataHook->Int1==HOOK_UNHOOK)
		{
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,1,OriginalInt1[i],NULL,0);
			OriginalInt1[i]=0;
		}

		if(pDataHook->Int0d==HOOK_HOOK)
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,0xd,(ULONG_PTR)EngineInt0d,&OriginalInt0D[i],OriginalInt0D[j]);
		else if(pDataHook->Int0d==HOOK_UNHOOK)
		{
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,0xd,OriginalInt0D[i],NULL,0);
			OriginalInt0D[i]=0;
		}

		if(pDataHook->Int0e==HOOK_HOOK)
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,0xe,(ULONG_PTR)EngineInt0e,&OriginalInt0E[i],OriginalInt0E[j]);
		else if(pDataHook->Int0e==HOOK_UNHOOK)
		{
			HookInterrupt((KIDT_ENTRY*)Idt.IdtBase,0xe,OriginalInt0E[i],NULL,0);
			OriginalInt0E[i]=0;
		}

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
}

void EngineUnhook()
{
	DATA_HOOK DataHook;
	DataHook.ProcessID=0;
	DataHook.Int1=HOOK_UNHOOK;
	DataHook.Int0d=HOOK_UNHOOK;
	DataHook.Int0e=HOOK_UNHOOK;
	EmulateRdtsc(0);
	EngineHook(&DataHook);

	ProcessID=0;
	Shift=0;

	while(Counter!=0)
	{
		DataState.State=STATE_READY;
		ZwYieldExecution();
	}
	IncreaseAX=0;
	IncreaseDX=0;

	if(pUserDataState!=NULL)
	{
		MmUnmapLockedPages(pUserDataState,pMdl);
		pUserDataState=NULL;
		IoFreeMdl(pMdl);
		pMdl=NULL;
	}
}

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH CreateHandler;
NTSTATUS CreateHandler(PDEVICE_OBJECT pDevice,PIRP pIrp)
{
	DataState.State=STATE_READY;

	pIrp->IoStatus.Status=STATUS_SUCCESS;
	pIrp->IoStatus.Information=0;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH CloseHandler;
NTSTATUS CloseHandler(PDEVICE_OBJECT pDevice,PIRP pIrp)
{
	EngineUnhook();

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
	DATA_HOOK *pDataHook;
	RDTSC_HOOK *pRdtscHook;
	ULONGLONG RdtscValue;

	IrpStack=IoGetCurrentIrpStackLocation(pIrp);
	pBuffer=pIrp->AssociatedIrp.SystemBuffer;
	InputBufferLength=IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength=IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch(IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
		case ENGINE_GETVERSION:
			if(OutputBufferLength!=sizeof(ULONG))
				break;
			*(ULONG*)pBuffer=ENGINE_VERSION;
			Information=sizeof(ULONG);
			Status=STATUS_SUCCESS;
			break;
		case ENGINE_INIT:
			if(OutputBufferLength!=sizeof(ULONG_PTR))
				break;
			EngineUnhook();
			if(pUserDataState==NULL)
			{
				pMdl=IoAllocateMdl(&DataState,sizeof(DataState),FALSE,FALSE,NULL);
				MmBuildMdlForNonPagedPool(pMdl);
				__try
				{
					pUserDataState=(DATA_STATE*)MmMapLockedPagesSpecifyCache(pMdl,UserMode,MmCached,NULL,FALSE,NormalPagePriority);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					pUserDataState=NULL;
					IoFreeMdl(pMdl);
					pMdl=NULL;
				}
			}
			*(ULONG_PTR*)pBuffer=(ULONG_PTR)pUserDataState;
			Information=sizeof(ULONG_PTR);
			Status=STATUS_SUCCESS;
			break;
		case ENGINE_HOOK:
			if(InputBufferLength!=sizeof(DATA_HOOK))
				break;
			pDataHook=(DATA_HOOK*)pBuffer;
			EngineHook(pDataHook);
			Information=0;
			Status=STATUS_SUCCESS;
			break;
		case ENGINE_EMULATE_RDTSC:
			if(InputBufferLength!=sizeof(RDTSC_HOOK))
				break;
			pRdtscHook=(RDTSC_HOOK*)pBuffer;
			Shift=pRdtscHook->Shift;
			if((Shift & MINLONG)!=0)
			{
				IncreaseAX=0;
				IncreaseDX=0;
			}
			else
			{
				RdtscValue=__rdtsc();
				IncreaseAX=RdtscValue & MAXULONG;
				IncreaseDX=RdtscValue >> 0x20;
			}
			EmulateRdtsc(pRdtscHook->Hook);
			Information=0;
			Status=STATUS_SUCCESS;
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

	EngineUnhook();

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

	for(i=wcslen(pRegPath->Buffer)-1;i>0;--i)
	{
		if(pRegPath->Buffer[i]==L'\\')
			break;
	}

	RtlStringCbCatW(szDevice,sizeof(szDevice),pRegPath->Buffer+i);
	RtlStringCbCatW(szSymLink,sizeof(szSymLink),pRegPath->Buffer+i);

	RtlUnicodeStringInit(&DeviceName,szDevice);
	if(IoCreateDevice(pDriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,0,TRUE,&pDeviceObject)!=STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;
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