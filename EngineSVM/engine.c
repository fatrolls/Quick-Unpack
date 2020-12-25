#include <ntifs.h>
#include <ntstrsafe.h>
#include "svm.h"
#include "..\interface.h"

#define MAX_PROCESSORS (RTL_BITS_OF(ULONG_PTR))
const ULONG dwPageSize=0x1000;
const ULONG dwStackSize=0x3000;
const ULONG dwPoolTag='pnUQ';
const ULONG RPL_MASK=3;

enum
{
	VMC_EXIT=0,
	VMC_READEXC,
	VMC_WRITEEXC,
	VMC_WRITERDTSC,
	VMC_WRITECPUID
};

#pragma pack(push,1)

typedef struct
{
	USHORT Limit;
	ULONG_PTR Base;
} SIDT_ENTRY,SGDT_ENTRY;

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
	ULONG SegmentLimitLo:16;
	ULONG BaseLow:16;
	ULONG BaseMid:8;
	ULONG SegmentType:4;
	ULONG DescriptorType:1;
	ULONG Dpl:2;
	ULONG Present:1;
	ULONG SegmentLimitHi:4;
	ULONG Available:1;
	ULONG Large64:1;
	ULONG Size:1;
	ULONG Granularity:1;
	ULONG BaseHi:8;
} KGDT_ENTRY;

typedef struct
{
	ULONG_PTR RegDi;
	ULONG_PTR RegSi;
	ULONG_PTR RegBp;
#if defined _M_IX86
	ULONG_PTR RegSp;
#endif
	ULONG_PTR RegBx;
	ULONG_PTR RegDx;
	ULONG_PTR RegCx;
	ULONG_PTR RegAx;
#if defined _M_AMD64
	ULONG_PTR Reg8;
	ULONG_PTR Reg9;
	ULONG_PTR Reg10;
	ULONG_PTR Reg11;
	ULONG_PTR Reg12;
	ULONG_PTR Reg13;
	ULONG_PTR Reg14;
	ULONG_PTR Reg15;
#endif
} PUSHED_REGS;

typedef struct
{
#if defined _M_AMD64
	ULONG Reserved1;
	ULONGLONG Sp0;
	ULONGLONG Sp1;
	ULONGLONG Sp2;
#elif defined _M_IX86
	USHORT PreviousTask;
	USHORT Reserved1;
	ULONG Sp0;
	USHORT Ss0;
	USHORT Reserved2;
	ULONG Sp1;
	USHORT Ss1;
	USHORT Reserved3;
	ULONG Sp2;
	USHORT Ss2;
	USHORT Reserved4;
#endif
} TSS;

#pragma pack(pop)

ULONG Counter=0,ProcessID=0,Shift=0,MagicEAX=0,MagicEBX=0,MagicECX=0,MagicEDX=0;
ULONG IncreaseAX=0,IncreaseDX=0;
ULONG_PTR OriginalInt1[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0D[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0E[MAX_PROCESSORS]={0};
ULONGLONG OriginalEfer[MAX_PROCESSORS]={0};
void *pHostRegion[MAX_PROCESSORS]={NULL};
void *pVMCBRegion[MAX_PROCESSORS]={NULL};
void *pHostStack[MAX_PROCESSORS]={NULL};
DATA_STATE DataState,*pUserDataState=NULL;
PMDL pMdl=NULL;

WCHAR szDevice[256]=L"\\Device";
WCHAR szSymLink[256]=L"\\DosDevices";

extern void DoCli();
extern void DoSGDT(void*);
extern ULONG_PTR ReadCR8();
extern USHORT ReadCS();
extern USHORT ReadDS();
extern USHORT ReadES();
extern USHORT ReadSS();
extern USHORT ReadTR();
extern void DoVMRun(ULONG_PTR);
extern ULONG_PTR DoVMMCall(ULONG,ULONG);
extern void DoRunVMM();
extern ULONG_PTR SkipPrefixes(ULONG_PTR);

extern void EngineInt1(void);
extern void EngineInt0d(void);
extern void EngineInt0e(void);
extern void EngineCpuid(void);

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ZwYieldExecution();

ULONG_PTR __stdcall GetProcessorNumber()
{
	return KeGetCurrentProcessorNumber();
}

ULONG GetSegmLimit(ULONG SegmentSelector)
{
	ULONG index,result;
	SGDT_ENTRY Gdt;
	KGDT_ENTRY *pGdtEntry;

	DoSGDT(&Gdt);
	pGdtEntry=(KGDT_ENTRY*)Gdt.Base;

	index=SegmentSelector >> 3;
	result=pGdtEntry[index].SegmentLimitLo+(pGdtEntry[index].SegmentLimitHi << 0x10);
	if(pGdtEntry[index].Granularity!=0)
		result=result*dwPageSize+dwPageSize-1;

	return result;
}

USHORT GetSegmAttributes(ULONG SegmentSelector)
{
	ULONG index;
	USHORT result;
	SGDT_ENTRY Gdt;
	KGDT_ENTRY *pGdtEntry;

	DoSGDT(&Gdt);
	pGdtEntry=(KGDT_ENTRY*)Gdt.Base;

	index=SegmentSelector >> 3;
	result=(*((USHORT*)(pGdtEntry+index)+2) >> 8) & 0xff;
	result+=(*((USHORT*)(pGdtEntry+index)+3) << 4) & 0xf00;
	return result;
}

ULONG_PTR GetSegmBase(ULONG SegmentSelector,BOOLEAN fx64System)
{
	ULONG index;
	ULONG_PTR result;
	SGDT_ENTRY Gdt;
	KGDT_ENTRY *pGdtEntry;

	DoSGDT(&Gdt);
	pGdtEntry=(KGDT_ENTRY*)Gdt.Base;

	index=SegmentSelector >> 3;
	result=pGdtEntry[index].BaseLow+(pGdtEntry[index].BaseMid << 0x10)+(pGdtEntry[index].BaseHi << 0x18);
#if defined _M_AMD64
	if(fx64System!=FALSE)	//system descriptor on x64 is 16-bytes long
		result+=(ULONG_PTR)((ULONG*)&pGdtEntry[index])[2] << 0x20;
#endif

	return result;
}

USHORT GetIntSelector(ULONG IntNumber)
{
	USHORT result;
	SIDT_ENTRY Idt;
	KIDT_ENTRY *pIdtEntry;
	ULONG_PTR CurrentFlags;

	__sidt(&Idt);
	pIdtEntry=(KIDT_ENTRY*)Idt.Base;

	CurrentFlags=__readeflags();
	DoCli();
	result=(USHORT)pIdtEntry[IntNumber].SegmentSelector;
	__writeeflags(CurrentFlags);

	return result;
}

ULONG_PTR GetIntAddress(ULONG IntNumber)
{
	SIDT_ENTRY Idt;
	KIDT_ENTRY *pIdtEntry;
	ULONG_PTR result,CurrentFlags;

	__sidt(&Idt);
	pIdtEntry=(KIDT_ENTRY*)Idt.Base;

	CurrentFlags=__readeflags();
	DoCli();
#if defined _M_AMD64
	result=((ULONG_PTR)pIdtEntry[IntNumber].HighestPart << 0x20)+(pIdtEntry[IntNumber].HighPart << 0x10)+pIdtEntry[IntNumber].LowPart;
#elif defined _M_IX86
	result=(pIdtEntry[IntNumber].HighPart << 0x10)+pIdtEntry[IntNumber].LowPart;
#endif
	__writeeflags(CurrentFlags);

	return result;
}

void PrepareIntHandler(VMCB *pVMCB,ULONG IntNumber,ULONG_PTR NewIp,BOOLEAN fErrorCode,ULONG_PTR ErrorCode)
{
	TSS *pTss;
	UCHAR NewCpl;
	USHORT NewCs,NewSs;
	ULONG_PTR NewSp;

	NewCs=GetIntSelector(IntNumber);
	NewCpl=(UCHAR)NewCs & RPL_MASK;
	if(pVMCB->Cpl==NewCpl)
	{
		NewSs=pVMCB->Ss.Selector;
		NewSp=(ULONG_PTR)pVMCB->Rsp;
	}
	else
	{
#if defined _M_AMD64
		pTss=(TSS*)GetSegmBase(ReadTR(),TRUE);
		NewSs=0;
#elif defined _M_IX86
		pTss=(TSS*)GetSegmBase(ReadTR(),FALSE);
		NewSs=pTss->Ss0;
#endif
		NewSp=pTss->Sp0;
	}
#if defined _M_AMD64
	NewSp&=~0xf;
#elif defined _M_IX86
	if(pVMCB->Cpl!=NewCpl)
#endif
	{
		NewSp-=sizeof(ULONG_PTR);
		*(ULONG_PTR*)NewSp=pVMCB->Ss.Selector;
		NewSp-=sizeof(ULONG_PTR);
		*(ULONG_PTR*)NewSp=(ULONG_PTR)pVMCB->Rsp;
	}
	NewSp-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)NewSp=(ULONG_PTR)pVMCB->RFlags;
	NewSp-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)NewSp=pVMCB->Cs.Selector;
	NewSp-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)NewSp=(ULONG_PTR)pVMCB->Rip;
	if(fErrorCode!=FALSE)
	{
		NewSp-=sizeof(ULONG_PTR);
		*(ULONG_PTR*)NewSp=ErrorCode;
	}

	pVMCB->Rip=NewIp;
	pVMCB->Cpl=NewCpl;
	pVMCB->Cs.Selector=NewCs;
	pVMCB->Cs.Attributes=GetSegmAttributes(NewCs);
	pVMCB->Cs.Limit=GetSegmLimit(NewCs);
	pVMCB->Cs.Base=GetSegmBase(NewCs,FALSE);
	pVMCB->RFlags=pVMCB->RFlags & ~0x34300;		//clear TF+IF+NT+RF+VM
	pVMCB->Rsp=NewSp;
	pVMCB->Ss.Selector=NewSs;
	if(NewSs==0)
		pVMCB->Ss.Attributes=0;
	else
		pVMCB->Ss.Attributes=GetSegmAttributes(NewSs);
	pVMCB->Ss.Limit=GetSegmLimit(NewSs);
	pVMCB->Ss.Base=GetSegmBase(NewSs,FALSE);

	pVMCB->VMCBClean&=~VMCBCLEAN_SEG;
}

ULONG __stdcall HandleVMM(VMCB *pVMCB,PUSHED_REGS *pRegs)
{
	ULONG ExitCode;

	ExitCode=(ULONG)pVMCB->ExitCode;
	pVMCB->VMCBClean=MAXULONG;

	switch(ExitCode)
	{
		case VMEXIT_VMMCALL:
			pVMCB->Rip=SkipPrefixes((ULONG_PTR)pVMCB->Rip)+3;
			if(pVMCB->Rax==MagicEAX && pRegs->RegBx==MagicEBX && pRegs->RegCx==MagicECX && pRegs->RegDx==MagicEDX)
			{
				if(pRegs->RegSi==VMC_EXIT)
					return ExitCode;
				else if(pRegs->RegSi==VMC_READEXC)
					pVMCB->Rax=pVMCB->InterceptExceptions;
				else if(pRegs->RegSi==VMC_WRITEEXC)
				{
					pVMCB->InterceptExceptions=(ULONG)pRegs->RegDi;
					pVMCB->VMCBClean&=~VMCBCLEAN_INTERCEPTS;
				}
				else if(pRegs->RegSi==VMC_WRITERDTSC)
				{
					if(pRegs->RegDi==0)
					{
						pVMCB->InterceptGeneric1&=~GENERICINTERCEPT1_RDTSC;
						pVMCB->InterceptGeneric2&=~GENERICINTERCEPT2_RDTSCP;
					}
					else
					{
						pVMCB->InterceptGeneric1|=GENERICINTERCEPT1_RDTSC;
						pVMCB->InterceptGeneric2|=GENERICINTERCEPT2_RDTSCP;
					}
					pVMCB->VMCBClean&=~VMCBCLEAN_INTERCEPTS;
				}
				else if(pRegs->RegSi==VMC_WRITECPUID)
				{
					if(pRegs->RegDi==0)
						pVMCB->InterceptGeneric1&=~GENERICINTERCEPT1_CPUID;
					else
						pVMCB->InterceptGeneric1|=GENERICINTERCEPT1_CPUID;
					pVMCB->VMCBClean&=~VMCBCLEAN_INTERCEPTS;
				}
			}
			return 0;
		case VMEXIT_INT1:
			PrepareIntHandler(pVMCB,1,(ULONG_PTR)&EngineInt1,FALSE,0);
			return 0;
		case VMEXIT_INT13:
			PrepareIntHandler(pVMCB,0xd,(ULONG_PTR)&EngineInt0d,TRUE,(ULONG_PTR)pVMCB->ExitInfo1);
			return 0;
		case VMEXIT_INT14:
			pVMCB->Cr2=pVMCB->ExitInfo2;
			pVMCB->VMCBClean&=~VMCBCLEAN_CR2;
			PrepareIntHandler(pVMCB,0xe,(ULONG_PTR)&EngineInt0e,TRUE,(ULONG_PTR)pVMCB->ExitInfo1);
			return 0;
		case VMEXIT_VMRUN:
			pVMCB->Rip=SkipPrefixes((ULONG_PTR)pVMCB->Rip)+3;
			return 0;
		case VMEXIT_RDTSC:
			if(pVMCB->Cpl==0)
			{
				pVMCB->Rip=SkipPrefixes((ULONG_PTR)pVMCB->Rip)+2;
				return ExitCode;
			}
			else
			{
				PrepareIntHandler(pVMCB,0xd,(ULONG_PTR)&EngineInt0d,TRUE,0);
				return 0;
			}
		case VMEXIT_RDTSCP:
			if(pVMCB->Cpl==0)
			{
				pVMCB->Rip=SkipPrefixes((ULONG_PTR)pVMCB->Rip)+3;
				return ExitCode;
			}
			else
			{
				PrepareIntHandler(pVMCB,0xd,(ULONG_PTR)&EngineInt0d,TRUE,0);
				return 0;
			}
		case VMEXIT_CPUID:
			if(pVMCB->Cpl==0 || (DWORD)PsGetCurrentProcessId()!=ProcessID)
			{
				pVMCB->Rip=SkipPrefixes((ULONG_PTR)pVMCB->Rip)+2;
				return ExitCode;
			}
			else
			{
				PrepareIntHandler(pVMCB,0xd,(ULONG_PTR)&EngineCpuid,TRUE,0);
				return 0;
			}
	}
	__debugbreak();
	return ExitCode;
}

void __stdcall RunVirtualMachine(ULONG_PTR GuestIp,ULONG_PTR GuestSp)
{
	ULONG i;
	SGDT_ENTRY Gdt;
	SIDT_ENTRY Idt;
	VMCB *pVMCB;
	ULONG_PTR PhysVMCB,HostStackTop;

	DoSGDT(&Gdt);
	__sidt(&Idt);

	i=KeGetCurrentProcessorNumber();
	pVMCB=pVMCBRegion[i];
	PhysVMCB=(ULONG_PTR)MmGetPhysicalAddress(pVMCB).QuadPart;

	pVMCB->Cs.Selector=ReadCS();
	pVMCB->Cs.Attributes=GetSegmAttributes(ReadCS());
	pVMCB->Cs.Limit=GetSegmLimit(ReadCS());
	pVMCB->Cs.Base=GetSegmBase(ReadCS(),FALSE);

	pVMCB->Ss.Selector=ReadSS();
	if(ReadSS()==0)
		pVMCB->Ss.Attributes=0;
	else
		pVMCB->Ss.Attributes=GetSegmAttributes(ReadSS());
	pVMCB->Ss.Limit=GetSegmLimit(ReadSS());
	pVMCB->Ss.Base=GetSegmBase(ReadSS(),FALSE);

	pVMCB->Es.Selector=ReadES();
	if(ReadES()==0)
		pVMCB->Es.Attributes=0;
	else
		pVMCB->Es.Attributes=GetSegmAttributes(ReadES());
	pVMCB->Es.Limit=GetSegmLimit(ReadES());
	pVMCB->Es.Base=GetSegmBase(ReadES(),FALSE);

	pVMCB->Ds.Selector=ReadDS();
	if(ReadDS()==0)
		pVMCB->Ds.Attributes=0;
	else
		pVMCB->Ds.Attributes=GetSegmAttributes(ReadDS());
	pVMCB->Ds.Limit=GetSegmLimit(ReadDS());
	pVMCB->Ds.Base=GetSegmBase(ReadDS(),FALSE);

	pVMCB->Idtr.Limit=Idt.Limit;
	pVMCB->Idtr.Base=Idt.Base;

	pVMCB->Gdtr.Limit=Gdt.Limit;
	pVMCB->Gdtr.Base=Gdt.Base;

	pVMCB->Rip=GuestIp;
	pVMCB->RFlags=__readeflags();
	pVMCB->Rax=0;
	pVMCB->Rsp=GuestSp;

	pVMCB->Cr0=(ULONG_PTR)__readcr0();
	pVMCB->Cr2=(ULONG_PTR)__readcr2();
	pVMCB->Cr3=(ULONG_PTR)__readcr3();
	pVMCB->Cr4=(ULONG_PTR)__readcr4();
	pVMCB->Efer=__readmsr(MSR_EFER);

	pVMCB->IntShadow=0;
	pVMCB->Dr6=__readdr(6);
	pVMCB->Dr7=__readdr(7);
	pVMCB->VTPR=ReadCR8();
	pVMCB->VIRQ=0;
	pVMCB->Cpl=(UCHAR)ReadCS() & RPL_MASK;

	pVMCB->GuestASID=1;

	pVMCB->InterceptGeneric2=GENERICINTERCEPT2_VMRUN | GENERICINTERCEPT2_VMMCALL;

	HostStackTop=(ULONG_PTR)pHostStack[i]+dwStackSize-sizeof(ULONG_PTR);
	HostStackTop-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)HostStackTop=(ULONG_PTR)pVMCB;
	HostStackTop-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)HostStackTop=PhysVMCB;
#if defined _M_AMD64
	HostStackTop-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)HostStackTop=0;
#endif
	DoVMRun(HostStackTop);
}

BOOLEAN StartSVM()
{
	BOOLEAN fError;
	ULONG i,CpuID[4];
	KAFFINITY AffinityMask,OldAffinityMask,TargetAffinityMask;
	PROCESS_BASIC_INFORMATION pbi;
	PHYSICAL_ADDRESS LowAddr,HighAddr,BoundaryAddr;

	memset(&pbi,0,sizeof(pbi));
	NtQueryInformationProcess(NtCurrentProcess(),ProcessBasicInformation,&pbi,sizeof(pbi),NULL);
	OldAffinityMask=pbi.AffinityMask;

	AffinityMask=KeQueryActiveProcessors();

	//check cpuid.ecx.svm bit and BIOS bit 4
	for(i=0;i!=MAX_PROCESSORS;++i)
	{
		TargetAffinityMask=(ULONG_PTR)1<<i;

		if((AffinityMask & TargetAffinityMask)==0)
			continue;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&TargetAffinityMask,sizeof(TargetAffinityMask));

		__cpuid(&CpuID,0x80000001);
		fError=((CpuID[2] & 4)==0 || (__readmsr(MSR_VM_CR) & 0x10)!=0) ? TRUE : FALSE;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));

		if(fError!=FALSE)
			return FALSE;
	}

	LowAddr.QuadPart=0;
	HighAddr.QuadPart=-1;
	BoundaryAddr.QuadPart=dwPageSize;
	for(i=0;i!=MAX_PROCESSORS;++i)
	{
		TargetAffinityMask=(ULONG_PTR)1<<i;

		if((AffinityMask & TargetAffinityMask)==0)
			continue;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&TargetAffinityMask,sizeof(TargetAffinityMask));

		OriginalEfer[i]=__readmsr(MSR_EFER);
		__writemsr(MSR_EFER,OriginalEfer[i] | 0x1000);
		pHostRegion[i]=MmAllocateContiguousMemorySpecifyCache(dwPageSize,LowAddr,HighAddr,BoundaryAddr,MmCached);
		memset(pHostRegion[i],0,dwPageSize);
		__writemsr(MSR_VM_HSAVE_PA,MmGetPhysicalAddress(pHostRegion[i]).QuadPart);

		pVMCBRegion[i]=MmAllocateContiguousMemorySpecifyCache(dwPageSize,LowAddr,HighAddr,BoundaryAddr,MmCached);
		memset(pVMCBRegion[i],0,dwPageSize);

		pHostStack[i]=ExAllocatePoolWithTag(NonPagedPool,dwStackSize,dwPoolTag);

		DoRunVMM();

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
	return TRUE;
}

void StopSVM()
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

		if(pHostStack[i]!=NULL)
		{
			DoVMMCall(VMC_EXIT,0);

			ExFreePoolWithTag(pHostStack[i],dwPoolTag);
			pHostStack[i]=NULL;

			MmFreeContiguousMemory(pVMCBRegion[i]);
			pVMCBRegion[i]=NULL;
			__writemsr(MSR_VM_HSAVE_PA,0);

			MmFreeContiguousMemory(pHostRegion[i]);
			pHostRegion[i]=NULL;

			__writemsr(MSR_EFER,OriginalEfer[i]);
			OriginalEfer[i]=0;
		}

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
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

		DoVMMCall(VMC_WRITERDTSC,Hook);

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
}

void EmulateCpuid(ULONG Hook)
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

		DoVMMCall(VMC_WRITECPUID,Hook);

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
}

void EngineHook(const DATA_HOOK *pDataHook)
{
	ULONG i,ExcMask;
	KAFFINITY AffinityMask,OldAffinityMask,TargetAffinityMask;
	PROCESS_BASIC_INFORMATION pbi;

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

		ExcMask=(ULONG)DoVMMCall(VMC_READEXC,0);

		if(pDataHook->Int1==HOOK_HOOK)
		{
			OriginalInt1[i]=GetIntAddress(1);
			ExcMask|=1 << 1;
		}
		else if(pDataHook->Int1==HOOK_UNHOOK)
		{
			OriginalInt1[i]=0;
			ExcMask&=~(1 << 1);
		}

		if(pDataHook->Int0d==HOOK_HOOK)
		{
			OriginalInt0D[i]=GetIntAddress(0xd);
			ExcMask|=1 << 0xd;
		}
		else if(pDataHook->Int0d==HOOK_UNHOOK)
		{
			OriginalInt0D[i]=0;
			ExcMask&=~(1 << 0xd);
		}

		if(pDataHook->Int0e==HOOK_HOOK)
		{
			OriginalInt0E[i]=GetIntAddress(0xe);
			ExcMask|=1 << 0xe;
		}
		else if(pDataHook->Int0e==HOOK_UNHOOK)
		{
			OriginalInt0E[i]=0;
			ExcMask&=~(1 << 0xe);
		}

		DoVMMCall(VMC_WRITEEXC,ExcMask);

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
	EmulateCpuid(0);
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
	CPUID_HOOK *pCpuidHook;

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
		case ENGINE_EMULATE_CPUID:
			if(InputBufferLength!=sizeof(CPUID_HOOK))
				break;
			pCpuidHook=(CPUID_HOOK*)pBuffer;
			EmulateCpuid(pCpuidHook->Hook);
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
	StopSVM();

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

	MagicEAX=0;
	for(i=0;i!=2*sizeof(MagicEAX);++i)
	{
		MagicEAX=(MagicEAX << 4) | (__rdtsc() & 0xf);
		ZwYieldExecution();
	}
	MagicEBX=0;
	for(i=0;i!=2*sizeof(MagicEBX);++i)
	{
		MagicEBX=(MagicEBX << 4) | (__rdtsc() & 0xf);
		ZwYieldExecution();
	}
	MagicECX=0;
	for(i=0;i!=2*sizeof(MagicECX);++i)
	{
		MagicECX=(MagicECX << 4) | (__rdtsc() & 0xf);
		ZwYieldExecution();
	}
	MagicEDX=0;
	for(i=0;i!=2*sizeof(MagicEDX);++i)
	{
		MagicEDX=(MagicEDX << 4) | (__rdtsc() & 0xf);
		ZwYieldExecution();
	}

	if(StartSVM()==FALSE)
		return STATUS_UNSUCCESSFUL;

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