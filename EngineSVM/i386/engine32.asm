.586p
.model	flat,stdcall
option	casemap:none

include interface32.inc

public DoCli@0
public DoSGDT@4
public ReadCR8@0
public ReadCS@0
public ReadDS@0
public ReadES@0
public ReadSS@0
public ReadTR@0
public DoVMRun@4
public DoVMMCall@8
public DoRunVMM@0
public SkipPrefixes@4

public EngineInt1@0
public EngineInt0d@0
public EngineInt0e@0
public EngineCpuid@0

extern MagicEAX:DWORD
extern MagicEBX:DWORD
extern MagicECX:DWORD
extern MagicEDX:DWORD
extern IncreaseAX:DWORD
extern IncreaseDX:DWORD
extern Counter:DWORD
extern Shift:DWORD
extern ProcessID:DWORD
extern OriginalInt1:DWORD
extern OriginalInt0D:DWORD
extern OriginalInt0E:DWORD
extern DataState:DATA_STATE

extern GetProcessorNumber@0:proc
extern HandleVMM@8:proc
extern RunVirtualMachine@8:proc
extern memmove:proc
extern PsGetCurrentProcessId@0:proc
extern PsGetCurrentThreadId@0:proc
extern ZwYieldExecution@0:proc

.data
ALIGN sizeof DWORD
GuestIp		dd	0
GuestSp		dd	0
ExtraShift	dd	0
HandlerReturn	dd	0
SpinLock	dd	0

.code
ALIGN sizeof DWORD
DoCli@0:	cli
		ret

ALIGN sizeof DWORD
DoSGDT@4:	mov ecx,dword ptr[esp+sizeof DWORD]
		sgdt [ecx]
		ret sizeof DWORD

ALIGN sizeof DWORD
ReadCR8@0:
		db 0f0h,0fh,20h,00h 	;mov eax,cr8
		ret

ALIGN sizeof DWORD
ReadCS@0:	xor eax,eax
		mov ax,cs
		ret

ALIGN sizeof DWORD
ReadDS@0:	xor eax,eax
		mov ax,ds
		ret

ALIGN sizeof DWORD
ReadES@0:	xor eax,eax
		mov ax,es
		ret

ALIGN sizeof DWORD
ReadSS@0:	xor eax,eax
		mov ax,ss
		ret

ALIGN sizeof DWORD
ReadTR@0:	xor eax,eax
		str ax
		ret

ALIGN sizeof DWORD
DoVMRun@4:	mov esp,dword ptr[esp+sizeof DWORD]
		mov eax,dr7
		push eax
		mov eax,dword ptr[esp+sizeof DWORD]
		db 0fh,01h,0d8h 	;vmrun eax
		xchg eax,dword ptr[esp]
		mov dr7,eax
		pop eax
		jmp VMEntry

ALIGN sizeof DWORD
DoVMMCall@8:	push ebx
		push esi
		push edi
		mov esi,dword ptr[esp+4*sizeof DWORD]
		mov edi,dword ptr[esp+5*sizeof DWORD]
		mov eax,MagicEAX
		mov ebx,MagicEBX
		mov ecx,MagicECX
		mov edx,MagicEDX
		db 0fh,01h,0d9h 	;vmmcall
		pop edi
		pop esi
		pop ebx
		ret 2*sizeof DWORD

ALIGN sizeof DWORD
DoRunVMM@0:	pushad
		pushfd
		push esp
		push offset VMMGuestIp
		db 0fh,01h,0ddh 	;clgi
		call RunVirtualMachine@8
	VMMGuestIp:
		popfd
		popad
		ret

ALIGN sizeof DWORD
SkipPrefixes@4:	mov ecx,dword ptr[esp+sizeof DWORD]
DoSkipPrefixes:	cmp byte ptr[ecx],26h	;es
		je IncPref
		cmp byte ptr[ecx],2eh	;cs
		je IncPref
		cmp byte ptr[ecx],36h	;ss
		je IncPref
		cmp byte ptr[ecx],3eh	;ds
		je IncPref
		cmp byte ptr[ecx],64h	;fs
		je IncPref
		cmp byte ptr[ecx],65h	;gs
		je IncPref
		cmp byte ptr[ecx],66h	;opsize
		je IncPref
		cmp byte ptr[ecx],67h	;addrsize
		je IncPref
		cmp byte ptr[ecx],0f0h	;lock
		je IncPref
		cmp byte ptr[ecx],0f2h	;repne
		je IncPref
		cmp byte ptr[ecx],0f3h	;repe
		je IncPref
		jmp EndOfPref
	IncPref:
		inc ecx
		jmp DoSkipPrefixes
	EndOfPref:
		mov eax,ecx
		ret sizeof DWORD

FixRDTSCCall:	test Shift,80000000h
		jz NoFixRDTSC
		push eax
		mov eax,Shift
		and eax,7fffffffh
		lock add IncreaseAX,eax
		lock adc IncreaseDX,0
		pop eax
	NoFixRDTSC:
		ret

LockSection:	push eax
		mov eax,1
	WaitLock:
		lock xchg ss:[SpinLock],eax
		test eax,eax
		jnz WaitLock
		pop eax
		ret

FreeSection:	push eax
		xor eax,eax
		lock xchg ss:[SpinLock],eax
		pop eax
		ret

VMEntry:	pushad

		push esp
		push dword ptr[esp+9*sizeof DWORD+sizeof DWORD]
		call HandleVMM@8

		cmp eax,110			;rdtsc
		jne RunRdtscp
		popad
		rdtsc
		jmp RunVMRun

	RunRdtscp:
		cmp eax,135			;rdtscp
		jne RunVmmCall
		popad
		db 0fh,01h,0f9h			;rdtscp
		jmp RunVMRun

	RunVmmCall:
		cmp eax,129			;vmmcall
		jne VmPopRegs

		call LockSection

		mov eax,dword ptr[esp+9*sizeof DWORD]
		mov ecx,dword ptr[eax+VMCB_RIP_OFFSET]
		mov GuestIp,ecx
		mov ecx,dword ptr[eax+VMCB_RSP_OFFSET]
		mov GuestSp,ecx

		popad
		mov esp,GuestSp
		db 0fh,01h,0dch 		;stgi
		push GuestIp
		call FreeSection
		ret

	VmPopRegs:
		popad
	RunVMRun:
		push esp
		call DoVMRun@4

EngineMain:	push dword ptr[eax]		;HandlerReturn

		test dword ptr[ebp+sizeof DWORD],3
		jz GotoOriginal

		call PsGetCurrentProcessId@0
		cmp eax,ProcessID
		jne GotoOriginal

		lock inc Counter

		rdtsc
		push eax
		push edx

		mov eax,dr7
		push eax
		and eax,0dc00h
		mov dr7,eax
		mov eax,dr6
		push eax
		and eax,0ffff1ff0h
		mov dr6,eax
		mov eax,dr3
		push eax
		mov eax,dr2
		push eax
		mov eax,dr1
		push eax
		mov eax,dr0
		push eax

		xor eax,eax
		mov dr0,eax
		mov dr1,eax
		mov dr2,eax
		mov dr3,eax

		mov ebx,cr2

		cld
		sti

	EngineWait:
		call ZwYieldExecution@0
		mov eax,STATE_READY
		mov ecx,STATE_BUSY
		lock cmpxchg DataState.State,ecx
		jne EngineWait

		call PsGetCurrentThreadId@0
		mov DataState.ThreadID,eax

		mov DataState.RegCr2,ebx

		push 4*sizeof DWORD
		push ebp
		push offset DataState.RegIp
		call memmove
		add esp,3*sizeof DWORD

		push 8*sizeof DWORD
		lea eax,dword ptr[ebp-KTRAP_SIZE-12*sizeof DWORD]
		push eax
		push offset DataState.RegDi
		call memmove
		add esp,3*sizeof DWORD

		push 6*sizeof DWORD
		push esp
		add dword ptr[esp],sizeof DWORD
		push offset DataState.RegDr0
		call memmove
		add esp,3*sizeof DWORD

		mov DataState.State,edi
	WaitLoop:
		call ZwYieldExecution@0
		cmp DataState.State,edi
		je WaitLoop

		push 4*sizeof DWORD
		push offset DataState.RegIp
		push ebp
		call memmove
		add esp,3*sizeof DWORD

		push 8*sizeof DWORD
		push offset DataState.RegDi
		lea eax,dword ptr[ebp-KTRAP_SIZE-12*sizeof DWORD]
		push eax
		call memmove
		add esp,3*sizeof DWORD+6*sizeof DWORD

		cli

		mov eax,DataState.RegDr0
		mov dr0,eax
		mov eax,DataState.RegDr1
		mov dr1,eax	
		mov eax,DataState.RegDr2
		mov dr2,eax
		mov eax,DataState.RegDr3
		mov dr3,eax	
		mov eax,DataState.RegDr6
		mov dr6,eax	
		mov eax,DataState.RegDr7
		mov dr7,eax
		mov eax,DataState.RegCr2
		mov cr2,eax

		test Shift,80000000h
		jz StupidSet1

		rdtsc
		sub eax,[esp+sizeof DWORD]
		sbb edx,[esp]
		lock add IncreaseAX,eax
		lock adc IncreaseDX,edx
	StupidSet1:
		add esp,2*sizeof DWORD

		lock dec Counter

		mov edi,DataState.State
		mov DataState.State,STATE_READY

		cmp edi,STATE_HANDLED
		je GotoHandled
	GotoOriginal:
		call LockSection
		pop HandlerReturn
		mov ExtraShift,esi
		popad
		pop gs
		pop fs
		pop es
		pop ds
		sub esp,ss:ExtraShift
		add esp,KTRAP_SIZE
		push ss:HandlerReturn
		call FreeSection
		ret

	GotoHandled:
		pop eax				;HandlerReturn
		call FixRDTSCCall
		popad
		pop gs
		pop fs
		pop es
		pop ds
		add esp,KTRAP_SIZE
		iretd

ALIGN sizeof DWORD
EngineInt1@0:	sub esp,KTRAP_SIZE
		push ds
		push es
		push fs
		push gs
		pushad
		mov ax,23h
		mov ds,ax
		mov es,ax
		mov ax,30h
		mov fs,ax

		mov esi,0
		lea ebp,dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD]

		call GetProcessorNumber@0

		lea eax,dword ptr[OriginalInt1+eax*sizeof DWORD]
		mov edi,STATE_SINGLESTEP

		jmp EngineMain

ALIGN sizeof DWORD
EngineInt0d@0:	sub esp,KTRAP_SIZE-sizeof DWORD
		push ds
		push es
		push fs
		push gs
		pushad
		mov ax,23h
		mov ds,ax
		mov es,ax
		mov ax,30h
		mov fs,ax

		test dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD+sizeof DWORD],3
		jz ExitInt0d

		push dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD]
		call SkipPrefixes@4
		cmp byte ptr[eax],0fh
		jne CheckRDTSCP
		cmp byte ptr[eax+1],31h
		jne CheckRDTSCP

		add eax,2
		mov dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD],eax

		call FixRDTSCCall

		rdtsc
		jmp FixRegs

	CheckRDTSCP:
		cmp byte ptr[eax],0fh
		jne ExitInt0d
		cmp byte ptr[eax+1],01h
		jne ExitInt0d
		cmp byte ptr[eax+2],0f9h
		jne ExitInt0d

		add eax,3
		mov dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD],eax

		call FixRDTSCCall

		db 0fh,01h,0f9h		;rdtscp
		mov dword ptr[esp+6*sizeof DWORD],ecx

	FixRegs:
		test Shift,80000000h
		jz StupidSet2
		sub eax,IncreaseAX
		sbb edx,IncreaseDX
		mov dword ptr[esp+7*sizeof DWORD],eax
		mov dword ptr[esp+5*sizeof DWORD],edx
		popad
		jmp PopSegs

	StupidSet2:
		and eax,0ffh
		mov ecx,Shift
		and ecx,7FFFFFFFh
		add eax,ecx
		lock add IncreaseAX,eax
		lock adc IncreaseDX,0

		popad
		mov eax,IncreaseAX
		mov edx,IncreaseDX

	PopSegs:
		pop gs
		pop fs
		pop es
		pop ds
		add esp,KTRAP_SIZE

		test dword ptr ss:[esp+2*sizeof DWORD],100h
		jnz Trap01

		iretd

	Trap01:
		push eax
		mov eax,dr6
		or eax,4000h
		mov dr6,eax
		pop eax
		jmp EngineInt1@0

	ExitInt0d:
		mov esi,sizeof DWORD
		lea ebp,dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD]

		call GetProcessorNumber@0

		lea eax,dword ptr[OriginalInt0D+eax*sizeof DWORD]
		mov edi,STATE_BREAK

		jmp EngineMain

ALIGN sizeof DWORD
EngineInt0e@0:	sub esp,KTRAP_SIZE-sizeof DWORD
		push ds
		push es
		push fs
		push gs
		pushad
		mov ax,23h
		mov ds,ax
		mov es,ax
		mov ax,30h
		mov fs,ax

		test dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD-sizeof DWORD],1
		jz OldInt0e							;not present
		test dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD-sizeof DWORD],4
		jz OldInt0e							;was supervisor mode
		test dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD-sizeof DWORD],8
		jnz OldInt0e							;reserved bits set
		test dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD-sizeof DWORD],16
		jz OldInt0e							;not instruction fetch

		mov esi,sizeof DWORD
		lea ebp,dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD]

		call GetProcessorNumber@0

		lea eax,dword ptr[OriginalInt0E+eax*sizeof DWORD]
		mov edi,STATE_BREAKMEM

		jmp EngineMain

	OldInt0e:
		call GetProcessorNumber@0
		push dword ptr[OriginalInt0E+eax*sizeof DWORD]
		call LockSection
		pop HandlerReturn
		popad
		pop gs
		pop fs
		pop es
		pop ds
		add esp,KTRAP_SIZE-sizeof DWORD
		push ss:HandlerReturn
		call FreeSection
		ret

ALIGN sizeof DWORD
EngineCpuid@0:	sub esp,KTRAP_SIZE-sizeof DWORD
		push ds
		push es
		push fs
		push gs
		pushad
		mov ax,23h
		mov ds,ax
		mov es,ax
		mov ax,30h
		mov fs,ax

		mov esi,sizeof DWORD
		lea ebp,dword ptr[esp+KTRAP_SIZE+12*sizeof DWORD]

		call GetProcessorNumber@0

		lea eax,dword ptr[OriginalInt0D+eax*sizeof DWORD]
		mov edi,STATE_BREAKCPUID

		jmp EngineMain
end