#include <ntifs.h>
#include <ntstrsafe.h>
#include "vmx.h"
#include "..\interface.h"

#define MAX_PROCESSORS (RTL_BITS_OF(ULONG_PTR))
const ULONG dwPageSize=0x1000;
const ULONG dwStackSize=0x3000;
const ULONG dwBitmapsSize=0x1000;
const ULONG dwPoolTag='pnUQ';
const ULONG RPL_MASK=3;

enum
{
	VMC_EXIT=0,
	VMC_READEXC,
	VMC_WRITEEXC,
	VMC_WRITERDTSC
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

ULONG Counter=0,ProcessID=0,Shift=0,HookCpuid=0,MagicEAX=0,MagicEBX=0,MagicECX=0,MagicEDX=0;
ULONG IncreaseAX=0,IncreaseDX=0;
ULONG_PTR OriginalInt1[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0D[MAX_PROCESSORS]={0};
ULONG_PTR OriginalInt0E[MAX_PROCESSORS]={0};
ULONG_PTR OriginalCR4[MAX_PROCESSORS]={0};
void *pVMXOnRegion[MAX_PROCESSORS]={NULL};
void *pVMCSRegion[MAX_PROCESSORS]={NULL};
void *pHostStack[MAX_PROCESSORS]={NULL};
void *pMSRBitmaps[MAX_PROCESSORS]={NULL};
DATA_STATE DataState,*pUserDataState=NULL;
PMDL pMdl=NULL;

WCHAR szDevice[256]=L"\\Device";
WCHAR szSymLink[256]=L"\\DosDevices";

extern void DoCli();
extern void DoSGDT(void*);
extern void WriteCR2(ULONG_PTR);
extern USHORT ReadCS();
extern USHORT ReadDS();
extern USHORT ReadES();
extern USHORT ReadFS();
extern USHORT ReadGS();
extern USHORT ReadSS();
extern USHORT ReadTR();
extern ULONG_PTR DoVMXOn(ULONGLONG*);
extern ULONG_PTR DoVMClear(ULONGLONG*);
extern ULONG_PTR DoVMPtrLd(ULONGLONG*);
extern ULONG_PTR DoVMRead(ULONG);
extern void DoVMWrite(ULONG,ULONG_PTR);
extern void DoVMLaunch();
extern ULONG_PTR DoVMCall(ULONG,ULONG);
extern void DoRunVMM();
extern void VMEntry(void);

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

ULONG GetSegmAccessRights(ULONG SegmentSelector)
{
	ULONG index;
	SGDT_ENTRY Gdt;
	KGDT_ENTRY *pGdtEntry;

	DoSGDT(&Gdt);
	pGdtEntry=(KGDT_ENTRY*)Gdt.Base;

	index=SegmentSelector >> 3;
	return (*((ULONG*)(pGdtEntry+index)+1) >> 8) & 0xf0ff;
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

void HandleCr(PUSHED_REGS *pRegs,const MOV_CR_QUALIFICATION *pMovCr)
{
	ULONG_PTR CrValue,GPReg;

	if(pMovCr->AccessType==0)
	{
		switch(pMovCr->GPRegister)
		{
			case 0:
				GPReg=pRegs->RegAx;
				break;
			case 1:
				GPReg=pRegs->RegCx;
				break;
			case 2:
				GPReg=pRegs->RegDx;
				break;
			case 3:
				GPReg=pRegs->RegBx;
				break;
			case 4:
				GPReg=DoVMRead(VMX_GUEST_RSP);
				break;
			case 5:
				GPReg=pRegs->RegBp;
				break;
			case 6:
				GPReg=pRegs->RegSi;
				break;
			case 7:
				GPReg=pRegs->RegDi;
				break;
#if defined _M_AMD64
			case 8:
				GPReg=pRegs->Reg8;
				break;
			case 9:
				GPReg=pRegs->Reg9;
				break;
			case 10:
				GPReg=pRegs->Reg10;
				break;
			case 11:
				GPReg=pRegs->Reg11;
				break;
			case 12:
				GPReg=pRegs->Reg12;
				break;
			case 13:
				GPReg=pRegs->Reg13;
				break;
			case 14:
				GPReg=pRegs->Reg14;
				break;
			case 15:
				GPReg=pRegs->Reg15;
				break;
#endif
		}
		switch(pMovCr->NumberOfControlRegister)
		{
			case 0:
				DoVMWrite(VMX_GUEST_CR0,GPReg);
				return;
			case 3:
				DoVMWrite(VMX_GUEST_CR3,GPReg);
				return;
			case 4:
				DoVMWrite(VMX_GUEST_CR4,GPReg);
				return;
		}
	}
	else if(pMovCr->AccessType==1)
	{
		switch(pMovCr->NumberOfControlRegister)
		{
			case 0:
				CrValue=DoVMRead(VMX_GUEST_CR0);
				break;
			case 3:
				CrValue=DoVMRead(VMX_GUEST_CR3);
				break;
			case 4:
				CrValue=DoVMRead(VMX_GUEST_CR4);
				break;
		}
		switch(pMovCr->GPRegister)
		{
			case 0:
				pRegs->RegAx=CrValue;
				return;
			case 1:
				pRegs->RegCx=CrValue;
				return;
			case 2:
				pRegs->RegDx=CrValue;
				return;
			case 3:
				pRegs->RegBx=CrValue;
				return;
			case 4:
				DoVMWrite(VMX_GUEST_RSP,CrValue);
				return;
			case 5:
				pRegs->RegBp=CrValue;
				return;
			case 6:
				pRegs->RegSi=CrValue;
				return;
			case 7:
				pRegs->RegDi=CrValue;
				return;
#if defined _M_AMD64
			case 8:
				pRegs->Reg8=CrValue;
				return;
			case 9:
				pRegs->Reg9=CrValue;
				return;
			case 10:
				pRegs->Reg10=CrValue;
				return;
			case 11:
				pRegs->Reg11=CrValue;
				return;
			case 12:
				pRegs->Reg12=CrValue;
				return;
			case 13:
				pRegs->Reg13=CrValue;
				return;
			case 14:
				pRegs->Reg14=CrValue;
				return;
			case 15:
				pRegs->Reg15=CrValue;
				return;
#endif
		}
	}
}

void PrepareIntHandler(ULONG IntNumber,ULONG_PTR NewIp,BOOLEAN fErrorCode,ULONG_PTR ErrorCode)
{
	TSS *pTss;
	USHORT GuestCs,NewCs,NewSs;
	ULONG_PTR GuestIp,GuestSp,GuestFlags,NewSp;

	GuestIp=DoVMRead(VMX_GUEST_RIP);
	GuestFlags=DoVMRead(VMX_GUEST_RFLAGS);
	GuestCs=(USHORT)DoVMRead(VMX_GUEST_CS);
	NewCs=GetIntSelector(IntNumber);
	if((GuestCs & RPL_MASK)==(NewCs & RPL_MASK))
	{
		NewSs=(USHORT)DoVMRead(VMX_GUEST_SS);
		NewSp=DoVMRead(VMX_GUEST_RSP);
	}
	else
	{
		pTss=(TSS*)DoVMRead(VMX_GUEST_TRBASE);
#if defined _M_AMD64
		NewSs=0;
#elif defined _M_IX86
		NewSs=pTss->Ss0;
#endif
		NewSp=pTss->Sp0;
	}
#if defined _M_AMD64
	NewSp&=~0xf;
#elif defined _M_IX86
	if((GuestCs & RPL_MASK)!=(NewCs & RPL_MASK))
#endif
	{
		NewSp-=sizeof(ULONG_PTR);
		*(ULONG_PTR*)NewSp=DoVMRead(VMX_GUEST_SS);
		NewSp-=sizeof(ULONG_PTR);
		*(ULONG_PTR*)NewSp=DoVMRead(VMX_GUEST_RSP);
	}
	NewSp-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)NewSp=GuestFlags;
	NewSp-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)NewSp=GuestCs;
	NewSp-=sizeof(ULONG_PTR);
	*(ULONG_PTR*)NewSp=GuestIp;
	if(fErrorCode!=FALSE)
	{
		NewSp-=sizeof(ULONG_PTR);
		*(ULONG_PTR*)NewSp=ErrorCode;
	}

	DoVMWrite(VMX_GUEST_RIP,NewIp);
	DoVMWrite(VMX_GUEST_CS,NewCs);
	DoVMWrite(VMX_GUEST_CSACCESS,GetSegmAccessRights(NewCs));
	DoVMWrite(VMX_GUEST_CSBASE,GetSegmBase(NewCs,FALSE));
	DoVMWrite(VMX_GUEST_CSLIMIT,GetSegmLimit(NewCs));
	DoVMWrite(VMX_GUEST_RFLAGS,GuestFlags & ~0x34300);	//clear TF+IF+NT+RF+VM
	DoVMWrite(VMX_GUEST_RSP,NewSp);
	DoVMWrite(VMX_GUEST_SS,NewSs);
	if(NewSs==0)
		DoVMWrite(VMX_GUEST_SSACCESS,0 | 0x10000);
	else
		DoVMWrite(VMX_GUEST_SSACCESS,GetSegmAccessRights(NewSs));
	DoVMWrite(VMX_GUEST_SSBASE,GetSegmBase(NewSs,FALSE));
	DoVMWrite(VMX_GUEST_SSLIMIT,GetSegmLimit(NewSs));
}

ULONG __stdcall HandleVMM(PUSHED_REGS *pRegs)
{
	INTERRUPTION_INFORMATION IntInfo;
	ULONG ExitReason,ExitInstructionLength,temp32;
	ULONG_PTR ExitQualification,GuestIp,NewIp;

	ExitReason=DoVMRead(VMX_EXIT_REASON) & MAXUSHORT;
	ExitQualification=DoVMRead(VMX_EXIT_QUALIFICATION);
	ExitInstructionLength=(ULONG)DoVMRead(VMX_EXIT_INSTRLENGTH);
	GuestIp=DoVMRead(VMX_GUEST_RIP);

	switch(ExitReason)
	{
		case VMEXIT_TRIPLEFAULT:
		case VMEXIT_GETSEC:
		case VMEXIT_VMCLEAR:
		case VMEXIT_VMLAUNCH:
		case VMEXIT_VMPTRLD:
		case VMEXIT_VMPTRST:
		case VMEXIT_VMREAD:
		case VMEXIT_VMRESUME:
		case VMEXIT_VMWRITE:
		case VMEXIT_VMXOFF:
		case VMEXIT_VMXON:
		case VMEXIT_INVEPT:
		case VMEXIT_INVVPID:

		case VMEXIT_INVD:
		case VMEXIT_RDMSR:
		case VMEXIT_WRMSR:
		case VMEXIT_XSETBV:
			DoVMWrite(VMX_GUEST_RIP,GuestIp+ExitInstructionLength);
			return ExitReason;
		case VMEXIT_MOVCR:
			HandleCr(pRegs,(MOV_CR_QUALIFICATION*)&ExitQualification);
			DoVMWrite(VMX_GUEST_RIP,GuestIp+ExitInstructionLength);
			return 0;
		case VMEXIT_VMCALL:
			DoVMWrite(VMX_GUEST_RIP,GuestIp+ExitInstructionLength);
			if(pRegs->RegAx==MagicEAX && pRegs->RegBx==MagicEBX && pRegs->RegCx==MagicECX && pRegs->RegDx==MagicEDX)
			{
				if(pRegs->RegSi==VMC_EXIT)
					return ExitReason;
				else if(pRegs->RegSi==VMC_READEXC)
					pRegs->RegAx=DoVMRead(VMX_CTRL_EXCEPTIONS);
				else if(pRegs->RegSi==VMC_WRITEEXC)
				{
					DoVMWrite(VMX_CTRL_EXCEPTIONS,pRegs->RegDi);
					if((pRegs->RegDi & (1 << 0xe))==0)
					{
						DoVMWrite(VMX_CTRL_PFMASK,0);
						DoVMWrite(VMX_CTRL_PFMATCH,0);
					}
					else
					{
						DoVMWrite(VMX_CTRL_PFMASK,0x1d);
						DoVMWrite(VMX_CTRL_PFMATCH,0x15);	//exec+usermode+prot.violation
					}
				}
				else if(pRegs->RegSi==VMC_WRITERDTSC)
				{
					temp32=(ULONG)DoVMRead(VMX_CTRL_PROCBASED);
					if(pRegs->RegDi==0)
						temp32&=~0x1000;
					else
						temp32|=0x1000;
					DoVMWrite(VMX_CTRL_PROCBASED,temp32);
				}
			}
			return 0;
		case VMEXIT_EXCEPTION:
			*(ULONG*)(&IntInfo)=(ULONG)DoVMRead(VMX_EXIT_INTINFO);
			if(IntInfo.Valid==1)
			{
				NewIp=0;
				if(IntInfo.Vector==1)
				{
					NewIp=(ULONG_PTR)&EngineInt1;
					__writedr(6,0xffff0ff0 | (ExitQualification & 0x600f));
				}
				else if(IntInfo.Vector==0xd)
					NewIp=(ULONG_PTR)&EngineInt0d;
				else if(IntInfo.Vector==0xe)
				{
					NewIp=(ULONG_PTR)&EngineInt0e;
					WriteCR2(ExitQualification);
				}
				if(NewIp!=0)
				{
					PrepareIntHandler(IntInfo.Vector,NewIp,IntInfo.ValidErrorCode==1,DoVMRead(VMX_EXIT_INTERROR));
					return 0;
				}
			}
			break;
		case VMEXIT_RDTSC:
		case VMEXIT_RDTSCP:
			if((DoVMRead(VMX_GUEST_CS) & RPL_MASK)==0)
			{
				DoVMWrite(VMX_GUEST_RIP,GuestIp+ExitInstructionLength);
				return ExitReason;
			}
			else
			{
				PrepareIntHandler(0xd,(ULONG_PTR)&EngineInt0d,TRUE,0);
				return 0;
			}
		case VMEXIT_CPUID:
			if(HookCpuid==0 || (DoVMRead(VMX_GUEST_CS) & RPL_MASK)==0 || (DWORD)PsGetCurrentProcessId()!=ProcessID)
			{
				DoVMWrite(VMX_GUEST_RIP,GuestIp+ExitInstructionLength);
				return ExitReason;
			}
			else
			{
				PrepareIntHandler(0xd,(ULONG_PTR)&EngineCpuid,TRUE,0);
				return 0;
			}
	}
	__debugbreak();
	return ExitReason;
}

void __stdcall RunVirtualMachine(ULONG_PTR GuestIp,ULONG_PTR GuestSp)
{
	ULONG i;
	ULONG temp32;
	ULONGLONG temp64;
	SGDT_ENTRY Gdt;
	SIDT_ENTRY Idt;
	VMX_BASIC_MSR VMXBasic;
	PHYSICAL_ADDRESS PhysVMXOn,PhysVMCS;

	DoSGDT(&Gdt);
	__sidt(&Idt);
	*(ULONGLONG*)(&VMXBasic)=__readmsr(IA32_VMX_BASIC);

	i=KeGetCurrentProcessorNumber();
	PhysVMXOn=MmGetPhysicalAddress(pVMXOnRegion[i]);
	if((DoVMXOn(&PhysVMXOn.QuadPart) & 0x41)!=0)
		return;
	PhysVMCS=MmGetPhysicalAddress(pVMCSRegion[i]);
	if((DoVMClear(&PhysVMCS.QuadPart) & 0x41)!=0)
		return;
	if((DoVMPtrLd(&PhysVMCS.QuadPart) & 0x41)!=0)
		return;

	//setting 16-bit guest registers
	DoVMWrite(VMX_GUEST_CS,ReadCS());
	DoVMWrite(VMX_GUEST_DS,ReadDS());
	DoVMWrite(VMX_GUEST_ES,ReadES());
	DoVMWrite(VMX_GUEST_FS,ReadFS());
	DoVMWrite(VMX_GUEST_GS,ReadGS());
	DoVMWrite(VMX_GUEST_SS,ReadSS());
	DoVMWrite(VMX_GUEST_TR,ReadTR());

	//setting 16-bit host registers
	DoVMWrite(VMX_HOST_CS,ReadCS() & ~RPL_MASK);
	DoVMWrite(VMX_HOST_DS,ReadDS() & ~RPL_MASK);
	DoVMWrite(VMX_HOST_ES,ReadES() & ~RPL_MASK);
	DoVMWrite(VMX_HOST_FS,ReadFS() & ~RPL_MASK);
	DoVMWrite(VMX_HOST_GS,ReadGS() & ~RPL_MASK);
	DoVMWrite(VMX_HOST_SS,ReadSS() & ~RPL_MASK);
	DoVMWrite(VMX_HOST_TR,ReadTR() & ~RPL_MASK);

	//setting 64-bit guest registers
	temp64=0xffffffffffffffff;
#if defined _M_AMD64
	DoVMWrite(VMX_GUEST_VMCSLINKFULL,temp64);
#elif defined _M_IX86
	DoVMWrite(VMX_GUEST_VMCSLINKFULL,temp64 & MAXULONG);
	DoVMWrite(VMX_GUEST_VMCSLINKHIGH,temp64 >> 0x20);
#endif

	temp64=__readmsr(IA32_DEBUGCTL);
#if defined _M_AMD64
	DoVMWrite(VMX_GUEST_DEBUGCTLFULL,temp64);
#elif defined _M_IX86
	DoVMWrite(VMX_GUEST_DEBUGCTLFULL,temp64 & MAXULONG);
	DoVMWrite(VMX_GUEST_DEBUGCTLHIGH,temp64 >> 0x20);
#endif

	//setting 32-bit control fields
	if(VMXBasic.MayDefBeCleared!=0)
		temp64=__readmsr(IA32_VMX_TRUE_PINBASED_CTLS);
	else
		temp64=__readmsr(IA32_VMX_PINBASED_CTLS);
	temp32=0;						//nothing here
	temp32|=temp64 & MAXULONG;
	temp32&=temp64 >> 0x20;
	DoVMWrite(VMX_CTRL_PINBASED,temp32);

	if(VMXBasic.MayDefBeCleared!=0)
		temp64=__readmsr(IA32_VMX_TRUE_PROCBASED_CTLS);
	else
		temp64=__readmsr(IA32_VMX_PROCBASED_CTLS);
	temp32=0x90000000;					//MSR bitmaps+secondary controls
	temp32|=temp64 & MAXULONG;
	temp32&=temp64 >> 0x20;
	if((temp32 & 0x10000000)!=0)				//MSR bitmaps usable
	{
		temp64=MmGetPhysicalAddress(pMSRBitmaps[i]).QuadPart;
#if defined _M_AMD64
		DoVMWrite(VMX_CTRL_MSRBMFULL,temp64);
#elif defined _M_IX86
		DoVMWrite(VMX_CTRL_MSRBMFULL,temp64 & MAXULONG);
		DoVMWrite(VMX_CTRL_MSRBMHIGH,temp64 >> 0x20);
#endif
	}
	if((temp32 & 0x80000000)!=0)				//secondary controls usable
	{
		ULONG sectemp32=0x101008;			//enable rdtscp
		temp64=__readmsr(IA32_VMX_PROCBASED_CTLS2);
		sectemp32|=temp64 & MAXULONG;
		sectemp32&=temp64 >> 0x20;
		DoVMWrite(VMX_CTRL_PROCBASED2,sectemp32);
	}
	DoVMWrite(VMX_CTRL_PROCBASED,temp32);

	DoVMWrite(VMX_CTRL_EXCEPTIONS,0);			//nothing for now
	DoVMWrite(VMX_CTRL_PFMASK,0);
	DoVMWrite(VMX_CTRL_PFMATCH,0);

	if(VMXBasic.MayDefBeCleared!=0)
		temp64=__readmsr(IA32_VMX_TRUE_EXIT_CTLS);
	else
		temp64=__readmsr(IA32_VMX_EXIT_CTLS);
	temp32=0;						//nothing here
#if defined _M_AMD64
	temp32|=0x200;						//bit 9 for x64
#endif
	temp32|=temp64 & MAXULONG;
	temp32&=temp64 >> 0x20;
	DoVMWrite(VMX_CTRL_VMEXIT,temp32);

	if(VMXBasic.MayDefBeCleared!=0)
		temp64=__readmsr(IA32_VMX_TRUE_ENTRY_CTLS);
	else
		temp64=__readmsr(IA32_VMX_ENTRY_CTLS);
	temp32=0;						//nothing here
#if defined _M_AMD64
	temp32|=0x200;						//bit 9 for x64
#endif
	temp32|=temp64 & MAXULONG;
	temp32&=temp64 >> 0x20;
	DoVMWrite(VMX_CTRL_VMENTRY,temp32);

	//setting 32-bit guest fields
	DoVMWrite(VMX_GUEST_CSLIMIT,GetSegmLimit(ReadCS()));
	DoVMWrite(VMX_GUEST_DSLIMIT,GetSegmLimit(ReadDS()));
	DoVMWrite(VMX_GUEST_ESLIMIT,GetSegmLimit(ReadES()));
	DoVMWrite(VMX_GUEST_FSLIMIT,GetSegmLimit(ReadFS()));
	DoVMWrite(VMX_GUEST_GSLIMIT,GetSegmLimit(ReadGS()));
	DoVMWrite(VMX_GUEST_SSLIMIT,GetSegmLimit(ReadSS()));
	DoVMWrite(VMX_GUEST_TRLIMIT,GetSegmLimit(ReadTR()));

	DoVMWrite(VMX_GUEST_GDTLIMIT,Gdt.Limit);
	DoVMWrite(VMX_GUEST_IDTLIMIT,Idt.Limit);

	DoVMWrite(VMX_GUEST_CSACCESS,GetSegmAccessRights(ReadCS()));
	if(ReadDS()==0)
		DoVMWrite(VMX_GUEST_DSACCESS,0 | 0x10000);
	else
		DoVMWrite(VMX_GUEST_DSACCESS,GetSegmAccessRights(ReadDS()));
	if(ReadES()==0)
		DoVMWrite(VMX_GUEST_ESACCESS,0 | 0x10000);
	else
		DoVMWrite(VMX_GUEST_ESACCESS,GetSegmAccessRights(ReadES()));
	if(ReadFS()==0)
		DoVMWrite(VMX_GUEST_FSACCESS,0 | 0x10000);
	else
		DoVMWrite(VMX_GUEST_FSACCESS,GetSegmAccessRights(ReadFS()));
	if(ReadGS()==0)
		DoVMWrite(VMX_GUEST_GSACCESS,0 | 0x10000);
	else
		DoVMWrite(VMX_GUEST_GSACCESS,GetSegmAccessRights(ReadGS()));
	if(ReadSS()==0)
		DoVMWrite(VMX_GUEST_SSACCESS,0 | 0x10000);
	else
		DoVMWrite(VMX_GUEST_SSACCESS,GetSegmAccessRights(ReadSS()));
	DoVMWrite(VMX_GUEST_TRACCESS,GetSegmAccessRights(ReadTR()));

	DoVMWrite(VMX_GUEST_LDTRACCESS,0 | 0x10000);		//unusable

	DoVMWrite(VMX_GUEST_SYSENTER_CS,__readmsr(IA32_SYSENTER_CS) & MAXUSHORT);

	//setting 32-bit host fields
	DoVMWrite(VMX_HOST_SYSENTER_CS,__readmsr(IA32_SYSENTER_CS) & MAXUSHORT);

	//setting natural-width guest fields
	DoVMWrite(VMX_GUEST_CR0,__readcr0());
	DoVMWrite(VMX_GUEST_CR3,__readcr3());
	DoVMWrite(VMX_GUEST_CR4,__readcr4());

	DoVMWrite(VMX_GUEST_CSBASE,GetSegmBase(ReadCS(),FALSE));
	DoVMWrite(VMX_GUEST_DSBASE,GetSegmBase(ReadDS(),FALSE));
	DoVMWrite(VMX_GUEST_ESBASE,GetSegmBase(ReadES(),FALSE));
	DoVMWrite(VMX_GUEST_SSBASE,GetSegmBase(ReadSS(),FALSE));
#if defined _M_AMD64
	DoVMWrite(VMX_GUEST_FSBASE,__readmsr(IA32_FS_BASE));
	DoVMWrite(VMX_GUEST_GSBASE,__readmsr(IA32_GS_BASE));
	DoVMWrite(VMX_GUEST_TRBASE,GetSegmBase(ReadTR(),TRUE));
#elif defined _M_IX86
	DoVMWrite(VMX_GUEST_FSBASE,GetSegmBase(ReadFS(),FALSE));
	DoVMWrite(VMX_GUEST_GSBASE,GetSegmBase(ReadGS(),FALSE));
	DoVMWrite(VMX_GUEST_TRBASE,GetSegmBase(ReadTR(),FALSE));
#endif

	DoVMWrite(VMX_GUEST_GDTBASE,Gdt.Base);
	DoVMWrite(VMX_GUEST_IDTBASE,Idt.Base);

	DoVMWrite(VMX_GUEST_RSP,GuestSp);
	DoVMWrite(VMX_GUEST_RIP,GuestIp);
	DoVMWrite(VMX_GUEST_RFLAGS,__readeflags());

	DoVMWrite(VMX_GUEST_SYSENTER_ESP,(ULONG_PTR)__readmsr(IA32_SYSENTER_ESP));
	DoVMWrite(VMX_GUEST_SYSENTER_EIP,(ULONG_PTR)__readmsr(IA32_SYSENTER_EIP));

	//setting natural-width host fields
	DoVMWrite(VMX_HOST_CR0,__readcr0());
	DoVMWrite(VMX_HOST_CR3,__readcr3());
	DoVMWrite(VMX_HOST_CR4,__readcr4());

#if defined _M_AMD64
	DoVMWrite(VMX_HOST_FSBASE,__readmsr(IA32_FS_BASE));
	DoVMWrite(VMX_HOST_GSBASE,__readmsr(IA32_GS_BASE));
	DoVMWrite(VMX_HOST_TRBASE,GetSegmBase(ReadTR(),TRUE));
#elif defined _M_IX86
	DoVMWrite(VMX_HOST_FSBASE,GetSegmBase(ReadFS(),FALSE));
	DoVMWrite(VMX_HOST_GSBASE,GetSegmBase(ReadGS(),FALSE));
	DoVMWrite(VMX_HOST_TRBASE,GetSegmBase(ReadTR(),FALSE));
#endif

	DoVMWrite(VMX_HOST_GDTBASE,Gdt.Base);
	DoVMWrite(VMX_HOST_IDTBASE,Idt.Base);

	DoVMWrite(VMX_HOST_SYSENTER_ESP,(ULONG_PTR)__readmsr(IA32_SYSENTER_ESP));
	DoVMWrite(VMX_HOST_SYSENTER_EIP,(ULONG_PTR)__readmsr(IA32_SYSENTER_EIP));

	DoVMWrite(VMX_HOST_RSP,(ULONG_PTR)pHostStack[i]+dwStackSize-sizeof(ULONG_PTR));
	DoVMWrite(VMX_HOST_RIP,(ULONG_PTR)&VMEntry);

	//activate
	DoVMWrite(VMX_GUEST_ACTIVITY,0);

	DoVMLaunch();
}

BOOLEAN StartVMX()
{
	BOOLEAN fError;
	ULONG i,CpuID[4];
	VMX_BASIC_MSR VMXBasic;
	KAFFINITY AffinityMask,OldAffinityMask,TargetAffinityMask;
	PROCESS_BASIC_INFORMATION pbi;
	PHYSICAL_ADDRESS LowAddr,HighAddr,BoundaryAddr;

	memset(&pbi,0,sizeof(pbi));
	NtQueryInformationProcess(NtCurrentProcess(),ProcessBasicInformation,&pbi,sizeof(pbi),NULL);
	OldAffinityMask=pbi.AffinityMask;

	AffinityMask=KeQueryActiveProcessors();

	//check cpuid.ecx.vmx bit and BIOS bits 0 and 2
	for(i=0;i!=MAX_PROCESSORS;++i)
	{
		TargetAffinityMask=(ULONG_PTR)1<<i;

		if((AffinityMask & TargetAffinityMask)==0)
			continue;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&TargetAffinityMask,sizeof(TargetAffinityMask));

		__cpuid(&CpuID,1);
		fError=((CpuID[2] & 0x20)==0 || (__readmsr(IA32_FEATURE_CONTROL) & 5)!=5) ? TRUE : FALSE;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));

		if(fError!=FALSE)
			return FALSE;
	}

	LowAddr.QuadPart=0;
	HighAddr.QuadPart=-1;
	BoundaryAddr.QuadPart=dwPageSize;
	*(ULONGLONG*)(&VMXBasic)=__readmsr(IA32_VMX_BASIC);
	for(i=0;i!=MAX_PROCESSORS;++i)
	{
		TargetAffinityMask=(ULONG_PTR)1<<i;

		if((AffinityMask & TargetAffinityMask)==0)
			continue;

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&TargetAffinityMask,sizeof(TargetAffinityMask));

		OriginalCR4[i]=__readcr4();
		__writecr4(OriginalCR4[i] | 0x2000);
		pVMXOnRegion[i]=MmAllocateContiguousMemorySpecifyCache(VMXBasic.VmxRegionSize,LowAddr,HighAddr,BoundaryAddr,MmCached);
		memset(pVMXOnRegion[i],0,VMXBasic.VmxRegionSize);
		*(ULONG*)(pVMXOnRegion[i])=VMXBasic.RevisionId;

		pVMCSRegion[i]=MmAllocateContiguousMemorySpecifyCache(VMXBasic.VmxRegionSize,LowAddr,HighAddr,BoundaryAddr,MmCached);
		memset(pVMCSRegion[i],0,VMXBasic.VmxRegionSize);
		*(ULONG*)(pVMCSRegion[i])=VMXBasic.RevisionId;

		pMSRBitmaps[i]=MmAllocateContiguousMemorySpecifyCache(dwBitmapsSize,LowAddr,HighAddr,BoundaryAddr,MmCached);
		memset(pMSRBitmaps[i],0,dwBitmapsSize);

		pHostStack[i]=ExAllocatePoolWithTag(NonPagedPool,dwStackSize,dwPoolTag);

		DoRunVMM();

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
	return TRUE;
}

void StopVMX()
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
			DoVMCall(VMC_EXIT,0);

			ExFreePoolWithTag(pHostStack[i],dwPoolTag);
			pHostStack[i]=NULL;

			MmFreeContiguousMemory(pMSRBitmaps[i]);
			pMSRBitmaps[i]=NULL;

			MmFreeContiguousMemory(pVMCSRegion[i]);
			pVMCSRegion[i]=NULL;

			MmFreeContiguousMemory(pVMXOnRegion[i]);
			pVMXOnRegion[i]=NULL;

			__writecr4(OriginalCR4[i]);
			OriginalCR4[i]=0;
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

		DoVMCall(VMC_WRITERDTSC,Hook);

		ZwSetInformationThread(NtCurrentThread(),ThreadAffinityMask,&OldAffinityMask,sizeof(OldAffinityMask));
	}
}

void EmulateCpuid(ULONG Hook)
{
	HookCpuid=Hook;
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

		ExcMask=(ULONG)DoVMCall(VMC_READEXC,0);

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

		DoVMCall(VMC_WRITEEXC,ExcMask);

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
	StopVMX();

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

	if(StartVMX()==FALSE)
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