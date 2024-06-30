option	casemap:none

include interface64.inc

public DoCli
public DoSGDT
public WriteCR2
public ReadCS
public ReadDS
public ReadES
public ReadFS
public ReadGS
public ReadSS
public ReadTR
public DoVMXOn
public DoVMClear
public DoVMPtrLd
public DoVMRead
public DoVMWrite
public DoVMLaunch
public DoVMCall
public DoRunVMM
public VMEntry

public EngineInt1
public EngineInt0d
public EngineInt0e
public EngineCpuid

extern MagicEAX:DWORD
extern MagicEBX:DWORD
extern MagicECX:DWORD
extern MagicEDX:DWORD
extern IncreaseAX:DWORD
extern IncreaseDX:DWORD
extern Counter:DWORD
extern Shift:DWORD
extern ProcessID:DWORD
extern OriginalInt1:QWORD
extern OriginalInt0D:QWORD
extern OriginalInt0E:QWORD
extern DataState:DATA_STATE

extern GetProcessorNumber:proc
extern HandleVMM:proc
extern RunVirtualMachine:proc
extern memmove:proc
extern PsGetCurrentProcessId:proc
extern PsGetCurrentThreadId:proc
extern ZwYieldExecution:proc

PUSH_REGS MACRO
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
ENDM

POP_REGS MACRO
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
ENDM

.data
ALIGN sizeof QWORD
GdtLimit	dw	0
IdtLimit	dw	0
GuestIp		dq	0
GuestSp		dq	0
ExtraShift	dq	0
HandlerReturn	dq	0
SpinLock	dd	0

.code
ALIGN sizeof QWORD
DoCli:		cli
		ret

ALIGN sizeof QWORD
DoSGDT:		sgdt [rcx]
		ret

ALIGN sizeof QWORD
WriteCR2:	mov cr2,rcx
		ret

ALIGN sizeof QWORD
ReadCS:		xor eax,eax
		mov ax,cs
		ret

ALIGN sizeof QWORD
ReadDS:		xor eax,eax
		mov ax,ds
		ret

ALIGN sizeof QWORD
ReadES:		xor eax,eax
		mov ax,es
		ret

ALIGN sizeof QWORD
ReadFS:		xor eax,eax
		mov ax,fs
		ret

ALIGN sizeof QWORD
ReadGS:		xor eax,eax
		mov ax,gs
		ret

ALIGN sizeof QWORD
ReadSS:		xor eax,eax
		mov ax,ss
		ret

ALIGN sizeof QWORD
ReadTR:		xor eax,eax
		str ax
		ret

ALIGN sizeof QWORD
DoVMXOn:
		db 0f3h,0fh,0c7h,31h 	;vmxon [rcx]
		pushfq
		pop rax
		ret

ALIGN sizeof QWORD
DoVMClear:
		db 066h,0fh,0c7h,31h 	;vmclear [rcx]
		pushfq
		pop rax
		ret

ALIGN sizeof QWORD
DoVMPtrLd:
		db 0fh,0c7h,31h 	;vmptrld [rcx]
		pushfq
		pop rax
		ret

ALIGN sizeof QWORD
DoVMRead:
		db 0fh,78h,0c8h 	;vmread rax,rcx
		ret

ALIGN sizeof QWORD
DoVMWrite:
		db 0fh,79h,0cah 	;vmwrite rcx,rdx
		ret

ALIGN sizeof QWORD
DoVMLaunch:
		db 0fh,01h,0c2h 	;vmlaunch
		pushfq
		pop rax
		ret

ALIGN sizeof QWORD
DoVMCall:	push rbx
		push rsi
		push rdi
		mov esi,ecx
		mov edi,edx
		mov eax,MagicEAX
		mov ebx,MagicEBX
		mov ecx,MagicECX
		mov edx,MagicEDX
		db 0fh,01h,0c1h 	;vmcall
		pop rdi
		pop rsi
		pop rbx
		ret

ALIGN sizeof QWORD
DoRunVMM:	PUSH_REGS
		pushfq
		mov rdx,rsp
		lea rcx,qword ptr[VMMGuestIp]
		cli
		sub rsp,5*sizeof QWORD
		call RunVirtualMachine
		add rsp,5*sizeof QWORD
	VMMGuestIp:
		popfq
		POP_REGS
		ret

SkipPrefixes:	cmp byte ptr[rcx],26h	;es
		je IncPref
		cmp byte ptr[rcx],2eh	;cs
		je IncPref
		cmp byte ptr[rcx],36h	;ss
		je IncPref
		cmp byte ptr[rcx],3eh	;ds
		je IncPref
		cmp byte ptr[rcx],64h	;fs
		je IncPref
		cmp byte ptr[rcx],65h	;gs
		je IncPref
		cmp byte ptr[rcx],66h	;opsize
		je IncPref
		cmp byte ptr[rcx],67h	;addrsize
		je IncPref
		cmp byte ptr[rcx],0f0h	;lock
		je IncPref
		cmp byte ptr[rcx],0f2h	;repne
		je IncPref
		cmp byte ptr[rcx],0f3h	;repe
		je IncPref
		mov al,[rcx]
		and al,0f0h
		cmp al,40h		;rex
		je IncPref
		jmp EndOfPref
	IncPref:
		inc rcx
		jmp SkipPrefixes
	EndOfPref:
		mov rax,rcx
		ret

FixRDTSCCall:	test Shift,80000000h
		jz NoFixRDTSC
		push rax
		mov eax,Shift
		and eax,7fffffffh
		lock add IncreaseAX,eax
		lock adc IncreaseDX,0
		pop rax
	NoFixRDTSC:
		ret

LockSection:	push rax
		mov eax,1
	WaitLock:
		lock xchg SpinLock,eax
		test eax,eax
		jnz WaitLock
		pop rax
		ret

FreeSection:	push rax
		xor eax,eax
		lock xchg SpinLock,eax
		pop rax
		ret

DoSwapGS:	test qword ptr[rbp+sizeof QWORD],3
		jz NoSwapGS
		swapgs
	NoSwapGS:
		ret
		
ALIGN sizeof QWORD
VMEntry:	cli
		PUSH_REGS

		mov rcx,rsp
		sub rsp,4*sizeof QWORD
		call HandleVMM
		add rsp,4*sizeof QWORD

		cmp eax,10			;cpuid
		jne RunInvd
		POP_REGS
		cpuid
		jmp RunVMResume

	RunInvd:
		cmp eax,13			;invd
		jne RunRdtsc
		POP_REGS
		invd
		jmp RunVMResume

	RunRdtsc:
		cmp eax,16			;rdtsc
		jne RunRdmsr
		POP_REGS
		rdtsc
		jmp RunVMResume

	RunRdmsr:
		cmp eax,31			;rdmsr
		jne RunWrmsr
		POP_REGS
		rdmsr
		jmp RunVMResume

	RunWrmsr:
		cmp eax,32			;wrmsr
		jne RunRdtscp
		POP_REGS
		wrmsr
		jmp RunVMResume

	RunRdtscp:
		cmp eax,51			;rdtscp
		jne RunXSetBv
		POP_REGS
		db 0fh,01h,0f9h			;rdtscp
		jmp RunVMResume

	RunXSetBv:
		cmp eax,55			;xsetbv
		jne RunVmCall
		POP_REGS
		db 0fh,01h,0d1h 		;xsetbv
		jmp RunVMResume

	RunVmCall:
		cmp eax,18			;vmcall
		jne VmPopRegs

		call LockSection

		mov rcx,VMX_GUEST_GDTLIMIT
		call DoVMRead
		mov GdtLimit,ax
		mov rcx,VMX_GUEST_IDTLIMIT
		call DoVMRead
		mov IdtLimit,ax
		mov rcx,VMX_GUEST_RIP
		call DoVMRead
		mov GuestIp,rax
		mov rcx,VMX_GUEST_RSP
		call DoVMRead
		mov GuestSp,rax
		db 0fh,01h,0c4h 		;vmxoff

		POP_REGS
		mov rsp,GuestSp
		sub rsp,10
		sgdt [rsp]
		push GdtLimit
		pop word ptr [rsp]
		lgdt fword ptr [rsp]
		sidt [rsp]
		push IdtLimit
		pop word ptr [rsp]
		lidt fword ptr [rsp]
		add rsp,10
		sti
		push GuestIp
		call FreeSection
		ret

	VmPopRegs:
		POP_REGS
	RunVMResume:
		db 0fh,01h,0c3h 		;vmresume
		int 3

ALIGN sizeof QWORD
EngineMain PROC FRAME
		.setframe r12,0
		.endprolog
		lea r12,qword ptr[rbp-KTRAP_SIZE]

		call DoSwapGS

		sub rsp,5*sizeof QWORD
		call GetProcessorNumber
		add rsp,5*sizeof QWORD
		push qword ptr[rbx+rax*sizeof QWORD]	;HandlerReturn

		test qword ptr[rbp+sizeof QWORD],3
		jz GotoOriginal

		sub rsp,4*sizeof QWORD
		call PsGetCurrentProcessId
		add rsp,4*sizeof QWORD
		cmp eax,ProcessID
		jne GotoOriginal

		lock inc Counter

		rdtsc
		push rax
		push rdx

		mov rax,dr7
		push rax
		mov rcx,0ffffffff0000dc00h
		and rax,rcx
		mov dr7,rax
		mov rax,dr6
		push rax
		mov rcx,0ffffffffffff1ff0h
		and rax,rcx
		mov dr6,rax
		mov rax,dr3
		push rax
		mov rax,dr2
		push rax
		mov rax,dr1
		push rax
		mov rax,dr0
		push rax

		xor eax,eax
		mov dr0,rax
		mov dr1,rax
		mov dr2,rax
		mov dr3,rax

		mov rbx,cr2

		cld
		sti

		sub rsp,4*sizeof QWORD
	EngineWait:
		call ZwYieldExecution
		mov eax,STATE_READY
		mov ecx,STATE_BUSY
		lock cmpxchg DataState.State,ecx
		jne EngineWait

		call PsGetCurrentThreadId
		mov DataState.ThreadID,eax

		mov DataState.RegCr2,rbx

		mov r8,4*sizeof QWORD
		mov rdx,rbp
		lea rcx,offset DataState.RegIp
		call memmove

		mov r8,15*sizeof QWORD
		lea rdx,qword ptr[rbp-KTRAP_SIZE-15*sizeof QWORD]
		lea rcx,offset DataState.RegDi
		call memmove

		mov r8,6*sizeof QWORD
		lea rdx,qword ptr[rsp+4*sizeof QWORD]
		lea rcx,offset DataState.RegDr0
		call memmove

		mov DataState.State,edi
	WaitLoop:
		call ZwYieldExecution
		cmp DataState.State,edi
		je WaitLoop

		mov r8,4*sizeof QWORD
		lea rdx,offset DataState.RegIp
		mov rcx,rbp
		call memmove

		mov r8,15*sizeof QWORD
		lea rdx,offset DataState.RegDi
		lea rcx,qword ptr[rbp-KTRAP_SIZE-15*sizeof QWORD]
		call memmove
		add rsp,4*sizeof QWORD+6*sizeof QWORD

		cli

		mov rax,DataState.RegDr0
		mov dr0,rax
		mov rax,DataState.RegDr1
		mov dr1,rax	
		mov rax,DataState.RegDr2
		mov dr2,rax
		mov rax,DataState.RegDr3
		mov dr3,rax	
		mov rax,DataState.RegDr6
		mov dr6,rax	
		mov rax,DataState.RegDr7
		mov dr7,rax
		mov rax,DataState.RegCr2
		mov cr2,rax

		test Shift,80000000h
		jz StupidSet1

		rdtsc
		sub eax,[rsp+sizeof QWORD]
		sbb edx,[rsp]
		lock add IncreaseAX,eax
		lock adc IncreaseDX,edx
	StupidSet1:
		add rsp,2*sizeof QWORD

		lock dec Counter

		mov edi,DataState.State
		mov DataState.State,STATE_READY

		cmp edi,STATE_HANDLED
		je GotoHandled
	GotoOriginal:
		call DoSwapGS
		call LockSection
		pop HandlerReturn
		mov ExtraShift,rsi
		POP_REGS
		sub rsp,ExtraShift
		add rsp,KTRAP_SIZE
		push HandlerReturn
		call FreeSection
		ret

	GotoHandled:
		call DoSwapGS
		pop rax					;HandlerReturn
		call FixRDTSCCall
		POP_REGS
		add rsp,KTRAP_SIZE
		iretq
EngineMain ENDP

ALIGN sizeof QWORD
EngineInt1:	sub rsp,KTRAP_SIZE
		PUSH_REGS

		mov rsi,0
		lea rbp,qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD]
		lea rbx,qword ptr[OriginalInt1]
		mov edi,STATE_SINGLESTEP

		jmp EngineMain

ALIGN sizeof QWORD
EngineInt0d:	sub rsp,KTRAP_SIZE-sizeof QWORD
		PUSH_REGS

		test qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD+sizeof QWORD],3
		jz ExitInt0d

		mov rcx,qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD]
		call SkipPrefixes
		cmp byte ptr[rax],0fh
		jne CheckRDTSCP
		cmp byte ptr[rax+1],31h
		jne CheckRDTSCP

		add rax,2
		mov qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD],rax

		call FixRDTSCCall

		rdtsc
		jmp FixRegs

	CheckRDTSCP:
		cmp byte ptr[rax],0fh
		jne ExitInt0d
		cmp byte ptr[rax+1],01h
		jne ExitInt0d
		cmp byte ptr[rax+2],0f9h
		jne ExitInt0d

		add rax,3
		mov qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD],rax

		call FixRDTSCCall

		db 0fh,01h,0f9h		;rdtscp
		mov qword ptr[rsp+5*sizeof QWORD],rcx

	FixRegs:
		test Shift,80000000h
		jz StupidSet2
		sub eax,IncreaseAX
		sbb edx,IncreaseDX

		mov qword ptr[rsp+6*sizeof QWORD],rax
		mov qword ptr[rsp+4*sizeof QWORD],rdx
		POP_REGS
		jmp PopSegs

	StupidSet2:
		and eax,0ffh
		mov ecx,Shift
		and ecx,7FFFFFFFh
		add eax,ecx
		lock add IncreaseAX,eax
		lock adc IncreaseDX,0

		POP_REGS
		mov eax,IncreaseAX
		mov edx,IncreaseDX

	PopSegs:
		add rsp,KTRAP_SIZE

		test qword ptr[rsp+2*sizeof QWORD],100h
		jnz Trap01

		iretq

	Trap01:
		push rax
		mov rax,dr6
		or rax,4000h
		mov dr6,rax
		pop rax
		jmp EngineInt1

	ExitInt0d:
		mov rsi,sizeof QWORD
		lea rbp,qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD]
		lea rbx,qword ptr[OriginalInt0D]
		mov edi,STATE_BREAK

		jmp EngineMain

ALIGN sizeof QWORD
EngineInt0e:	sub rsp,KTRAP_SIZE-sizeof QWORD
		PUSH_REGS

		test qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD-sizeof QWORD],1
		jz OldInt0e							;not present
		test qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD-sizeof QWORD],4
		jz OldInt0e							;was supervisor mode
		test qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD-sizeof QWORD],8
		jnz OldInt0e							;reserved bits set
		test qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD-sizeof QWORD],16
		jz OldInt0e							;not instruction fetch

		mov rsi,sizeof QWORD
		lea rbp,qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD]
		lea rbx,qword ptr[OriginalInt0E]
		mov edi,STATE_BREAKMEM

		jmp EngineMain

	OldInt0e:
		lea rbp,qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD]
		call DoSwapGS
		sub rsp,5*sizeof QWORD
		call GetProcessorNumber
		add rsp,5*sizeof QWORD
		call DoSwapGS
		lea rbx,qword ptr[OriginalInt0E]
		push qword ptr[rbx+rax*sizeof QWORD]
		call LockSection
		pop HandlerReturn
		POP_REGS
		add rsp,KTRAP_SIZE-sizeof QWORD
		push HandlerReturn
		call FreeSection
		ret

ALIGN sizeof QWORD
EngineCpuid:	sub rsp,KTRAP_SIZE-sizeof QWORD
		PUSH_REGS

		mov rsi,sizeof QWORD
		lea rbp,qword ptr[rsp+KTRAP_SIZE+15*sizeof QWORD]
		lea rbx,qword ptr[OriginalInt0D]
		mov edi,STATE_BREAKCPUID

		jmp EngineMain
end