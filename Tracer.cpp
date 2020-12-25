#include "StdAfx.h"
#include "DlgMain.h"
#include "Tracer.h"
#include ".\\Disasm\\mediana.h"

typedef DWORD(NTAPI *cNtUnmapViewOfSection)
(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

CBreak::CBreak()
:	BreakType1(btOpcode),
	BreakType2(bt2Execute),
	nEnabled(0),
	nExists(0),
	Where(0),
	nSize(0)
{
}

CTracer::CTracer(const TCHAR *szVictimName,HMODULE hDllHandle):CEngine(hDllHandle),
	FirstVictimBase(0),
	PageLastUsed(0),
	PagesAllocked(0),
	pPageDir((PAGE_ENTRY*)VirtualAlloc(NULL,sizeof(PAGE_ENTRY)*PAGES_COUNT,MEM_COMMIT,PAGE_READWRITE)),
	BreakWhere(0),
	VictimBase(0),
	hVictim(NULL),
	dwVictimPID(0),
	bGetTickCount(0),
	bGetTickCount64(0),
	bVirtualAlloc(0),
	bVirtualFree(0)
{
	sVictimName=szVictimName;

	State.State=STATE_READY;

	TCHAR szPath[MAX_PATH];
	ExtractFilePath(szPath,_countof(szPath),(TCHAR*)sVictimName.c_str());
	sWorkDir=szPath;
	GetCurrentDirectory(_countof(szPath),szPath);
	sOldDir=szPath;

	SetCurrentDirectory(sWorkDir.c_str());
}

CTracer::~CTracer()
{
	Terminate();
	VirtualFree(pPageDir,0,MEM_RELEASE);

	EmulateCPUID(0);
	EmulateRDTSC(0,0);
	Hook(0,HOOK_UNHOOK,HOOK_UNHOOK,HOOK_UNHOOK);

	SetCurrentDirectory(sOldDir.c_str());
}

//BYTE bOpcode[]={0x6c};		//ins byte[edi],dx
//BYTE bOpcode[]={0x6d};		//ins dword[edi],dx
//BYTE bOpcode[]={0x6e};		//outs dx,byte[edi]
//BYTE bOpcode[]={0x6f};		//outs dx,dword[edi]
//BYTE bOpcode[]={0xec};		//in al,dx
BYTE bOpcode[]={0xed};		//in eax,dx
//BYTE bOpcode[]={0xee};		//out dx,al
//BYTE bOpcode[]={0xef};		//out dx,eax
//BYTE bOpcode[]={0xf4};		//hlt
//BYTE bOpcode[]={0xfa};		//cli

BYTE bCC[]={0xcc};

bool IsHWBP(EBreakType1 BreakType1)
{
	return BreakType1==btDr0 || BreakType1==btDr1 || BreakType1==btDr2 || BreakType1==btDr3;
}

bool CTracer::AddBreak(DWORD_PTR Where,EBreakType1 BreakType1,EBreakType2 BreakType2)
{
	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Where || (IsHWBP(BreakType1) && Breaks[n]->BreakType1==BreakType1))
			break;
	}
	if(n!=Breaks.size())
	{
		if(IsHWBP(BreakType1) && Breaks[n]->BreakType1==BreakType1)
			DisableBreak(Where);
		else if(Breaks[n]->Where==Where)
		{
			++Breaks[n]->nExists;
			return true;
		}
	}

	CBreak *pNewBreak=new CBreak;
	pNewBreak->BreakType1=BreakType1;
	pNewBreak->BreakType2=BreakType2;
	pNewBreak->nEnabled=0;
	pNewBreak->nExists=1;
	pNewBreak->nSize=1;
	pNewBreak->Where=Where;

	if(pNewBreak->BreakType1==btOpcode)
		pNewBreak->nSize=sizeof(bOpcode);
	else if(pNewBreak->BreakType1==btCC)
		pNewBreak->nSize=sizeof(bCC);

	Breaks.push_back(pNewBreak);
	return true;
}

bool CTracer::DeleteBreak(DWORD_PTR Where)
{
	std::vector<CBreak*>::iterator Iter(Breaks.begin());
	for(;Iter!=Breaks.end();++Iter)
	{
		if((*Iter)->Where==Where)
			break;
	}
	if(Iter==Breaks.end())
		return false;

	--(*Iter)->nExists;
	if((*Iter)->nExists>0)
		return true;

	if((*Iter)->nEnabled>0)
	{
		(*Iter)->nEnabled=1;
		DisableBreak(Where);
	}

	delete *Iter;
	Breaks.erase(Iter);
	return true;
}

void CTracer::DeleteBreakAll()
{
	DeleteMemoryBreaks();
	while(!Breaks.empty())
	{
		Breaks[0]->nExists=1;
		DeleteBreak(Breaks[0]->Where);
	}
	DeleteDrRegs();

	bLoadLibrary=0;
	bExceptionDispatcher=0;
	bContinue=0;
	bGetContextThread=0;
	bSetContextThread=0;
	bCreateThread=0;
	bCreateThreadEx=0;
	bVirtualAlloc=0;
	bVirtualFree=0;
	bVirtualProtect=0;
	bOpenProcess=0;
	bOpenThread=0;
	bGetTickCount=0;
	bGetTickCount64=0;
}

bool CTracer::EnableBreak(DWORD_PTR Where)
{
	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Where)
			break;
	}
	if(n==Breaks.size())
		return false;
	if(Breaks[n]->nEnabled++)
		return true;

	if(Breaks[n]->BreakType1==btOpcode || Breaks[n]->BreakType1==btCC)
	{
		Breaks[n]->bOldBytes.resize(Breaks[n]->nSize);
		if((int)ReadMem(Breaks[n]->Where,&Breaks[n]->bOldBytes[0],Breaks[n]->nSize)==Breaks[n]->nSize)
		{
			if(Breaks[n]->BreakType1==btOpcode)
				WriteMem(Breaks[n]->Where,&bOpcode,Breaks[n]->nSize);
			else
				WriteMem(Breaks[n]->Where,&bCC,Breaks[n]->nSize);
		}
		else
		{
			Breaks[n]->bOldBytes.clear();
			return false;
		}
	}
	else if(IsHWBP(Breaks[n]->BreakType1))
	{
		int nDr;
		if(Breaks[n]->BreakType1==btDr0)
			nDr=0;
		else if(Breaks[n]->BreakType1==btDr1)
			nDr=1;
		else if(Breaks[n]->BreakType1==btDr2)
			nDr=2;
		else if(Breaks[n]->BreakType1==btDr3)
			nDr=3;
		else
			return false;

		DWORD_PTR m1=~((DWORD_PTR)0xf0000 << nDr*4);
		m1&=~((DWORD_PTR)3 << nDr*2);
		DWORD_PTR m2=(DWORD_PTR)Breaks[n]->BreakType2 << (16+nDr*4);//0=x,1=w,2=IO r+w,3=r+w
		m2|=(DWORD_PTR)0 << (18+nDr*4);								//0=1 byte,1=2 bytes,2=8 bytes(rare),3=4 bytes
		m2|=(DWORD_PTR)1 << nDr*2;									//local enable

		for(size_t m=0;m!=DrRegs.size();++m)
		{
			DrRegs[m].Dr[nDr]=Breaks[n]->Where;
			DrRegs[m].Dr[7]|=0x100;
			DrRegs[m].Dr[7]&=m1;
			DrRegs[m].Dr[7]|=m2;
		}
	}
	return true;
}

bool CTracer::DisableBreak(DWORD_PTR Where)
{
	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Where)
			break;
	}
	if(n==Breaks.size())
		return false;
	if(Breaks[n]->nEnabled==0)
		return true;
	if(--Breaks[n]->nEnabled)
		return true;

	if(Breaks[n]->BreakType1==btOpcode || Breaks[n]->BreakType1==btCC)
	{
		::WriteMem(hVictim,Breaks[n]->Where,&Breaks[n]->bOldBytes[0],Breaks[n]->nSize);
		Breaks[n]->bOldBytes.clear();
	}
	else if(IsHWBP(Breaks[n]->BreakType1))
	{
		int nDr;
		if(Breaks[n]->BreakType1==btDr0)
			nDr=0;
		else if(Breaks[n]->BreakType1==btDr1)
			nDr=1;
		else if(Breaks[n]->BreakType1==btDr2)
			nDr=2;
		else if(Breaks[n]->BreakType1==btDr3)
			nDr=3;
		else
			return false;

		DWORD_PTR m1=~((DWORD_PTR)0xf0000 << nDr*4);
		m1&=~((DWORD_PTR)3 << nDr*2);

		for(size_t m=0;m!=DrRegs.size();++m)
		{
			DrRegs[m].Dr[nDr]=0;
			DrRegs[m].Dr[7]&=m1;
		}
	}
	return true;
}

void CTracer::DisableBreakAll()
{
	for(size_t n=0;n!=Breaks.size();++n)
	{
		if(Breaks[n]->nEnabled!=0)
		{
			Breaks[n]->nEnabled=1;
			DisableBreak(Breaks[n]->Where);
		}
	}
	DeleteDrRegs();
}

int CTracer::IsEnabled(DWORD_PTR Where) const
{
	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Where)
			break;
	}
	if(n==Breaks.size())
		return 0;
	else
		return Breaks[n]->nEnabled;
}

int CTracer::IsExist(DWORD_PTR Where) const
{
	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Where)
			break;
	}
	if(n==Breaks.size())
		return 0;
	else
		return Breaks[n]->nExists;
}

int CTracer::AddDrReg(DWORD dwTID)
{
	for(size_t n=0;n!=DrRegs.size();++n)
	{
		if(DrRegs[n].dwTID==dwTID)
			return (int)n;
	}

	CDrReg NewReg;
	NewReg.dwTID=dwTID;
	DrRegs.push_back(NewReg);

	if(DrRegs.size()>1)
		memcpy(&DrRegs[DrRegs.size()-1].Dr[0],&DrRegs[DrRegs.size()-2].Dr[0],RTL_FIELD_SIZE(CDrReg,Dr));

	return (int)DrRegs.size()-1;
}

void CTracer::DeleteDrRegs()
{
	DrRegs.clear();
}

bool CTracer::AddMemoryBreak(DWORD_PTR StartAddr,DWORD Size)
{
	Size=(DWORD)AlignTo(Size+StartAddr-CutTo(StartAddr,PAGE_SIZE),PAGE_SIZE);
	StartAddr=CutTo(StartAddr,PAGE_SIZE);
	Size/=PAGE_SIZE;
	if(StartAddr+Size<StartAddr)
		return false;

	MEMORY_BASIC_INFORMATION MemInfo;
	for(DWORD i=0;i!=Size;++i)
	{
		if(VirtualQueryEx(hVictim,(void*)(StartAddr+i*PAGE_SIZE),&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo))
			return false;
		if(MemInfo.State!=MEM_COMMIT)
			return false;
	}

	DWORD dwOldProtect;
	for(DWORD i=0;i!=Size;++i)
	{
		VirtualQueryEx(hVictim,(void*)(StartAddr+i*PAGE_SIZE),&MemInfo,sizeof(MemInfo));
		MemBreaks.insert(std::make_pair(StartAddr+i*PAGE_SIZE,(BYTE)(MemInfo.Protect & 0xff)));
		VirtualProtectEx(hVictim,(void*)(StartAddr+i*PAGE_SIZE),PAGE_SIZE,
			(MemInfo.Protect & ~0xff) | StripNXBit(MemInfo.Protect & 0xff),&dwOldProtect);
	}
	return true;
}

void CTracer::DeleteMemoryBreaks()
{
	std::map<DWORD_PTR,BYTE>::const_iterator itMemBreaks(MemBreaks.begin());
	for(;itMemBreaks!=MemBreaks.end();++itMemBreaks)
	{
		DWORD dwOldProtect;
		MEMORY_BASIC_INFORMATION MemInfo;
		VirtualQueryEx(hVictim,(void*)itMemBreaks->first,&MemInfo,sizeof(MemInfo));
		VirtualProtectEx(hVictim,(void*)itMemBreaks->first,PAGE_SIZE,
			(MemInfo.Protect & ~0xff) | itMemBreaks->second,&dwOldProtect);
	}
	MemBreaks.clear();
}

DWORD_PTR CTracer::NextInstr(DWORD_PTR Address)
{
	BYTE bBuf[2*MAX_INSTRUCTION_LEN];
	INSTRUCTION Instr;
	DISASM_PARAMS Params;

	if(ReadMem(Address,&bBuf,sizeof(bBuf))!=sizeof(bBuf))
		return 0;

	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Address)
			break;
	}
	if(n!=Breaks.size() && Breaks[n]->nEnabled>0)
		memcpy(bBuf,&Breaks[n]->bOldBytes[0],Breaks[n]->nSize);

	Params.arch=ARCH_ALL;
	Params.sf_prefixes=NULL;
#if defined _M_AMD64
	Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
	Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
	if(medi_disassemble((uint8_t*)bBuf,sizeof(bBuf),&Instr,&Params)==DASM_ERR_OK)
		return Address+Instr.length;
	else
		return 0;
}

bool CTracer::IsThreadDying() const
{
	if(State.State==STATE_UNHANDLED)
	{
		HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,State.ThreadID);
		if(hThread==NULL)
			return true;
		DWORD dwCount=SuspendThread(hThread);
		ResumeThread(hThread);
		CloseHandle(hThread);
		if(dwCount==-1)
			return true;
		else
			return false;
	}
	else
		return false;
}

void CTracer::TraceAndReplace(DWORD_PTR Where)
{
	size_t n=0;
	for(;n!=Breaks.size();++n)
	{
		if(Breaks[n]->Where==Where)
			break;
	}
	if(n==Breaks.size())
		return;

	SuspendAllOther();
	while(!IsThreadDying())
	{
		if(BreakWhere==bProcessTerminated)
			return;
		if(State.RegIp<Breaks[n]->Where || State.RegIp>=Breaks[n]->Where+Breaks[n]->nSize)
			break;
		Trace();
	}
	ResumeAllOther();
	EnableBreak(Where);
}

DWORD CTracer::Suspend()
{
	HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,State.ThreadID);
	if(hThread==NULL)
		return MAXDWORD;
	DWORD dwResult=SuspendThread(hThread);
	CloseHandle(hThread);
	return dwResult;
}

DWORD CTracer::Resume()
{
	HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,State.ThreadID);
	if(State.State==STATE_HANDLED)
	{
		int m=AddDrReg(State.ThreadID);

		State.RegDr0=DrRegs[m].Dr[0];
		State.RegDr1=DrRegs[m].Dr[1];
		State.RegDr2=DrRegs[m].Dr[2];
		State.RegDr3=DrRegs[m].Dr[3];
		State.RegDr6=0;
		State.RegDr7=DrRegs[m].Dr[7];

		if(DrRegs[m].fTraceFlag)
			State.RegFlags|=TRACE_FLAG;
		else
			State.RegFlags&=~TRACE_FLAG;
		State.RegFlags&=~RESUME_FLAG;

		CONTEXT Context;
		Context.ContextFlags=CONTEXT_DEBUG_REGISTERS;
		Context.Dr0=DrRegs[m].Dr[0];
		Context.Dr1=DrRegs[m].Dr[1];
		Context.Dr2=DrRegs[m].Dr[2];
		Context.Dr3=DrRegs[m].Dr[3];
		Context.Dr6=0;
		Context.Dr7=DrRegs[m].Dr[7];
		SetThreadContext(hThread,&Context);
	}
	SetState(&State);

	DWORD dwResult;
	if(hThread==NULL)
		dwResult=MAXDWORD;
	else
	{
		dwResult=ResumeThread(hThread);
		CloseHandle(hThread);
	}

	SwitchToThread();
	return dwResult;
}

void CTracer::SuspendAllOther()
{
	for(std::vector<CDrReg>::iterator it_regs(DrRegs.begin());it_regs!=DrRegs.end();)
	{
		if(it_regs->dwTID==State.ThreadID)
		{
			++it_regs;
			continue;
		}
		HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,it_regs->dwTID);
		if(hThread==NULL)
		{
			it_regs=DrRegs.erase(it_regs);
			continue;
		}
		SuspendThread(hThread);
		CloseHandle(hThread);
		++it_regs;
	}
}

void CTracer::ResumeAllOther()
{
	for(std::vector<CDrReg>::iterator it_regs(DrRegs.begin());it_regs!=DrRegs.end();)
	{
		if(it_regs->dwTID==State.ThreadID)
		{
			++it_regs;
			continue;
		}
		HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,it_regs->dwTID);
		if(hThread==NULL)
		{
			it_regs=DrRegs.erase(it_regs);
			continue;
		}
		ResumeThread(hThread);
		CloseHandle(hThread);
		++it_regs;
	}
}

void CTracer::Attach()
{
	memset(pPageDir,0,sizeof(PAGE_ENTRY)*PAGES_COUNT);
	PageLastUsed=0;
	DeleteBreakAll();

	DWORD dwOldVictimPID=dwVictimPID;
	dwVictimPID=pMain->pInitData->dwPID;

	VictimFile.Read(sVictimName.c_str());
	if(VictimFile.IsEmpty())
	{
		WriteEx(cantopen+sVictimName.c_str(),TRUE,TRUE,RGB(255,0,0));
		return;
	}
	sVictimLoaderName.clear();

	pMain->Modules.Clear();
	Hook(dwVictimPID,HOOK_HOOK,HOOK_HOOK,HOOK_HOOK);
	if(pMain->pInitData->dwTimeDelta!=0)
		EmulateRDTSC(1,pMain->pInitData->dwTimeDelta);

	if(pMain->pInitData->fMemoryManager)
	{
		void *pTempImage;
		std::vector<DWORD> Array;
		DWORD_PTR Current;
		MEMORY_BASIC_INFORMATION MemInfo;

		pTempImage=VirtualAlloc(NULL,VictimFile.pPEHeader->OptionalHeader.SizeOfImage,MEM_COMMIT,PAGE_READWRITE);
		ReadMem(VictimBase,pTempImage,VictimFile.pPEHeader->OptionalHeader.SizeOfImage);

		Current=VictimBase;
		for(;;)
		{
			if(VirtualQueryEx(hVictim,(void*)Current,&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo))
				break;
			if((MemInfo.Protect & 0xff)==PAGE_EXECUTE_WRITECOPY)
				MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_EXECUTE_READWRITE;
			if((MemInfo.Protect & 0xff)==PAGE_WRITECOPY)
				MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_READWRITE;
			Current+=MemInfo.RegionSize;
			Array.push_back((DWORD)MemInfo.RegionSize);
			Array.push_back(MemInfo.Protect);
			if(Current>=VictimBase+VictimFile.pPEHeader->OptionalHeader.SizeOfImage)
				break;
		}

		cNtUnmapViewOfSection NtUnmapViewOfSection=(cNtUnmapViewOfSection)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtUnmapViewOfSection");
		NtUnmapViewOfSection(hVictim,(void*)VictimBase);
		if(VirtualAllocEx(hVictim,(void*)VictimBase,AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+PAGE_SIZE*PAGES_COUNT,
			MEM_COMMIT | MEM_RESERVE,PAGE_NOACCESS)==NULL)
		{
			Terminate();
			MessageBox(NULL,_T("Unable to allocate memory!"),_T("QuickUnpack"),MB_OK);
			return;
		}
		WriteMem(VictimBase,pTempImage,VictimFile.pPEHeader->OptionalHeader.SizeOfImage);
		VirtualFree(pTempImage,0,MEM_RELEASE);

		Current=VictimBase;
		for(size_t j=0;j!=Array.size();j+=2)
		{
			VirtualProtectEx(hVictim,(void*)Current,Array[j],Array[j+1],&Array[1]);
			Current+=Array[j];
		}

		PagesAllocked=VictimBase+AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE);
		VictimFile.pPEHeader->OptionalHeader.SizeOfImage=(DWORD)AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+PAGE_SIZE*PAGES_COUNT;

		bVirtualAlloc=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtAllocateVirtualMemory"));
		AddBreak(bVirtualAlloc);EnableBreak(bVirtualAlloc);
		bVirtualFree=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtFreeVirtualMemory"));
		AddBreak(bVirtualFree);EnableBreak(bVirtualFree);
	}
	bOEP=pMain->pInitData->dwOEP+VictimBase;
	AddBreak(bOEP); EnableBreak(bOEP);

	for(;;)
	{
		SwitchToThread();
		GetState(&State);
		if(State.State==STATE_READY || GetPIDByTID(State.ThreadID)!=dwOldVictimPID)
			break;
		State.State=STATE_HANDLED;
		Resume();
	}

	if(State.State==STATE_READY)
		State.ThreadID=pMain->pInitData->dwTID;
	else
	{
		HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,pMain->pInitData->dwTID);
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

	Resume();
	DeleteDrRegs();
	Wait();
	DeleteBreak(bOEP);

	pMain->Modules.Reload(VictimBase,&VictimFile,hVictim);
	if(pMain->pInitData->ImportRec==irSmartTracer)
	{
		pMain->Modules.HookExport();
		pMain->Modules.HookImport();
	}
}

void CTracer::Detach()
{
	size_t nCount=DrRegs.size();

	pMain->Modules.UnHookExport();
	DisableBreakAll();
	EmulateCPUID(0);
	EmulateRDTSC(0,0);
	Hook(0,HOOK_UNHOOK,HOOK_UNHOOK,HOOK_UNHOOK);
	for(size_t i=0;i!=nCount;++i)
	{
		GetState(&State);
		if(State.State!=STATE_READY)
			State.State=STATE_HANDLED;
		Resume();
		SwitchToThread();
	}
	DeleteBreakAll();
	DeleteDrRegs();
}

void CTracer::Start(bool fUseGhost,BOOL fStopSystem)
{
	memset(pPageDir,0,sizeof(PAGE_ENTRY)*PAGES_COUNT);
	PageLastUsed=0;
	DeleteBreakAll();
	VictimFile.Read(sVictimName.c_str());
	if(VictimFile.IsEmpty())
	{
		WriteEx(cantopen+sVictimName.c_str(),TRUE,TRUE,RGB(255,0,0));
		return;
	}

	int nBreakOffset=0;
	if((VictimFile.pPEHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)==IMAGE_FILE_DLL)
	{
		CPEFile LoaderFile;
		if(fUseGhost)
		{
			LoaderFile.CreateEmpty();
			LoaderFile.pPEHeader->FileHeader.Characteristics|=IMAGE_FILE_DLL;
			LoaderFile.pPEHeader->OptionalHeader.ImageBase=FirstVictimBase;

#if defined _M_AMD64
			BYTE bGhost[]={	0x48,0x31,0xc0,		//xor rax,rax
							0x48,0xff,0xc0,		//inc rax
							0xc3};				//ret
#elif defined _M_IX86
			BYTE bGhost[]={	0x31,0xc0,			//xor eax,eax
							0xff,0xc0,			//inc eax
							0xc2,0x0c,0x00};	//ret 0c
#else
!!!
#endif
			LoaderFile.CreateSection(".text",bGhost,sizeof(bGhost),IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);
			LoaderFile.pPEHeader->OptionalHeader.AddressOfEntryPoint=LoaderFile.pSectionHeader[0].VirtualAddress;
			sVictimGhostName=sWorkDir+_T("\\")+GHOST_NAME;
			LoaderFile.Save(sVictimGhostName.c_str());
		}
		LoaderFile.CreateEmpty();
		LoaderFile.pPEHeader->OptionalHeader.ImageBase=0x400000;

		if(!fUseGhost)
		{
#if defined _M_AMD64
			BYTE bLoader1[]={0x48,0x83,0xec,0x28,					//sub rsp,28
							0x48,0xc7,0xc1,0x00,0x11,0x40,0};		//mov rcx,401100
			BYTE bLoader2[]={0xff,0x15,0xef,0x04,0,0,				//call [LoadLibraryA]
							0x48,0xc7,0xc1,0,0,0,0,					//mov rcx,0
							0xff,0x15,0xf2,0x04,0,0,				//call [ExitProcess]
							0x48,0x83,0xc4,0x28,					//add rsp,28
							0xc3};									//ret
#elif defined _M_IX86
			BYTE bLoader1[]={0x68,0x00,0x11,0x40,0};				//push 401100
			BYTE bLoader2[]={0xff,0x15,0x00,0x15,0x40,0,			//call [LoadLibraryA]
							0x68,0,0,0,0,							//push 0
							0xff,0x15,0x10,0x15,0x40,0,				//call [ExitProcess]
							0xc3};									//ret
#else
!!!
#endif
			nBreakOffset=sizeof(bLoader1);
			BYTE *bLoader=new BYTE[0x400];
			memset(bLoader,0,0x400);
			memcpy(bLoader,bLoader1,sizeof(bLoader1));
			memcpy(bLoader+sizeof(bLoader1),bLoader2,sizeof(bLoader2));
			_tcscpy_s((TCHAR*)(bLoader+0x100),0x300/sizeof(TCHAR),sVictimName.c_str());
			LoaderFile.CreateSection(".text",bLoader,0x400,IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);
			delete[] bLoader;
		}
		else
		{
#if defined _M_AMD64
			BYTE bLoader1[]={0x48,0x83,0xec,0x28,					//sub rsp,28
							0x48,0xc7,0xc1,0x00,0x11,0x40,0,		//mov rcx,401100
							0xff,0x15,0xef,0x04,0,0};				//call [LoadLibraryA]
			BYTE bLoader2[]={0x48,0xc7,0xc1,0x00,0x13,0x40,0,		//mov rcx,401300
							0xff,0x15,0xe2,0x04,0,0,				//call [LoadLibraryA]
							0x48,0xc7,0xc1,0,0,0,0,					//mov rcx,0
							0xff,0x15,0xe5,0x04,0,0,				//call [ExitProcess]
							0x48,0x83,0xc4,0x28,					//add rsp,28
							0xc3};									//ret
#elif defined _M_IX86
			BYTE bLoader1[]={0x68,0,0x11,0x40,0,					//push 401100
							0xff,0x15,0x00,0x15,0x40,0};			//call [LoadLibraryA]
			BYTE bLoader2[]={0x68,0x00,0x13,0x40,0x00,				//push 401300
							0xff,0x15,0x00,0x15,0x40,0,				//call [LoadLibraryA]
							0x68,0,0,0,0,							//push 0
							0xff,0x15,0x10,0x15,0x40,0,				//call [ExitProcess]
							0xc3};									//ret
#else
!!!
#endif
			nBreakOffset=sizeof(bLoader1);
			BYTE *bLoader=new BYTE[0x600];
			memset(bLoader,0,0x600);
			memcpy(bLoader,bLoader1,sizeof(bLoader1));
			memcpy(bLoader+sizeof(bLoader1),bLoader2,sizeof(bLoader2));
			_tcscpy_s((TCHAR*)(bLoader+0x100),0x200/sizeof(TCHAR),GHOST_NAME);
			_tcscpy_s((TCHAR*)(bLoader+0x300),0x200/sizeof(TCHAR),sVictimName.c_str());
			LoaderFile.CreateSection(".text",bLoader,0x600,IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);
			delete[] bLoader;
		}
		LoaderFile.pPEHeader->OptionalHeader.AddressOfEntryPoint=LoaderFile.pSectionHeader[0].VirtualAddress;

		CImport Import;
#ifdef UNICODE
		Import.AddRecord(CImportRecord(_T("kernel32.dll"),"LoadLibraryW",0,0x1500,itIndirectCall));
#else
		Import.AddRecord(CImportRecord(_T("kernel32.dll"),"LoadLibraryA",0,0x1500,itIndirectCall));
#endif
		Import.AddRecord(CImportRecord(_T("kernel32.dll"),"ExitProcess",0,0x1510,itIndirectCall));
		Import.AddRecord(CImportRecord(_T("user32.dll"),"MessageBoxA",0,0x1520,itIndirectCall));
		Import.SaveToFile(LoaderFile,0);

		sVictimLoaderName=sWorkDir+_T("\\")+LOADER_NAME;
		LoaderFile.Save(sVictimLoaderName.c_str());
	}
	else
		sVictimLoaderName=sVictimName;

	PROCESS_INFORMATION pi;
	TCHAR sParam[2*MAX_PATH+4];
	_tcscpy_s(sParam,_T("\""));
	_tcscat_s(sParam,sVictimLoaderName.c_str());
	_tcscat_s(sParam,_T("\" "));
	_tcscat_s(sParam,pMain->pInitData->sParameters.c_str());
	if(!CreateRestrictedProcess(NULL,sParam,CREATE_SUSPENDED,sWorkDir.c_str(),&pi))
		return;

	dwVictimPID=pi.dwProcessId;
	hVictim=pi.hProcess;
	State.ThreadID=pi.dwThreadId;
	State.State=STATE_READY;

	pMain->Modules.Clear();
	Hook(dwVictimPID,HOOK_HOOK,HOOK_HOOK,HOOK_HOOK);
	if(pMain->pInitData->dwTimeDelta!=0)
		EmulateRDTSC(1,pMain->pInitData->dwTimeDelta);
	SetState(&State);

	DWORD_PTR Addr;
	MEMORY_BASIC_INFORMATION MemInfo;
	if(_tcsicmp(sVictimLoaderName.c_str(),sVictimName.c_str())!=0)
	{
		CPEFile LoaderFile;
		LoaderFile.Read(sVictimLoaderName.c_str());
		CloseHandle(pi.hThread);
		bProcessCreated=LoaderFile.pPEHeader->OptionalHeader.ImageBase+LoaderFile.pPEHeader->OptionalHeader.AddressOfEntryPoint+nBreakOffset;
		AddBreak(bProcessCreated);EnableBreak(bProcessCreated);
		do Continue();
		while(BreakWhere!=bProcessCreated && BreakWhere!=bProcessTerminated);
		DeleteBreak(bProcessCreated);

		DWORD_PTR bLibraryLoad=LoadLibraryAddress;
		AddBreak(bLibraryLoad);EnableBreak(bLibraryLoad);
		Continue();
		DeleteBreak(bLibraryLoad);

		HANDLE hModuleSnap;
		do hModuleSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetProcessId(hVictim));
		while(hModuleSnap==INVALID_HANDLE_VALUE && GetLastError()==ERROR_BAD_LENGTH);
		MODULEENTRY32 me32;
		me32.dwSize=sizeof(me32);
		if(Module32First(hModuleSnap,&me32))
		{
			do
			{
				if(_tcsicmp(me32.szExePath,sVictimName.c_str())==0)
				{
					VictimBase=(DWORD_PTR)me32.modBaseAddr;
					break;
				}
			}
			while(Module32Next(hModuleSnap,&me32));
		}
		CloseHandle(hModuleSnap);

		pMain->SetMainBreaks();
		bOEP=VictimBase+VictimFile.pPEHeader->OptionalHeader.AddressOfEntryPoint;
		if(pMain->pInitData->fMemoryManager)
		{
			void *pTempImage;
			std::vector<DWORD> Array;
			DWORD_PTR Current;

			pTempImage=VirtualAlloc(NULL,VictimFile.pPEHeader->OptionalHeader.SizeOfImage,MEM_COMMIT,PAGE_READWRITE);
			ReadMem(VictimBase,pTempImage,VictimFile.pPEHeader->OptionalHeader.SizeOfImage);

			Current=VictimBase;
			for(;;)
			{
				if(VirtualQueryEx(hVictim,(void*)Current,&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo))
					break;
				if((MemInfo.Protect & 0xff)==PAGE_EXECUTE_WRITECOPY)
					MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_EXECUTE_READWRITE;
				if((MemInfo.Protect & 0xff)==PAGE_WRITECOPY)
					MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_READWRITE;
				Current+=MemInfo.RegionSize;
				Array.push_back((DWORD)MemInfo.RegionSize);
				Array.push_back(MemInfo.Protect);
				if(Current>=VictimBase+VictimFile.pPEHeader->OptionalHeader.SizeOfImage)
					break;
			}

			cNtUnmapViewOfSection NtUnmapViewOfSection=(cNtUnmapViewOfSection)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtUnmapViewOfSection");
			NtUnmapViewOfSection(hVictim,(void*)VictimBase);
			if(VirtualAllocEx(hVictim,(void*)VictimBase,AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+PAGE_SIZE*PAGES_COUNT,
				MEM_COMMIT | MEM_RESERVE,PAGE_NOACCESS)==NULL)
			{
				Terminate();
				MessageBox(NULL,_T("Unable to allocate memory!"),_T("QuickUnpack"),MB_OK);
				return;
			}
			WriteMem(VictimBase,pTempImage,VictimFile.pPEHeader->OptionalHeader.SizeOfImage);
			VirtualFree(pTempImage,0,MEM_RELEASE);

			Current=VictimBase;
			for(size_t j=0;j!=Array.size();j+=2)
			{
				VirtualProtectEx(hVictim,(void*)Current,Array[j],Array[j+1],&Array[1]);
				Current+=Array[j];
			}

			PagesAllocked=VictimBase+AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE);
			VictimFile.pPEHeader->OptionalHeader.SizeOfImage=(DWORD)AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+PAGE_SIZE*PAGES_COUNT;

			bVirtualAlloc=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtAllocateVirtualMemory"));
			AddBreak(bVirtualAlloc);EnableBreak(bVirtualAlloc);
			bVirtualFree=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtFreeVirtualMemory"));
			AddBreak(bVirtualFree);EnableBreak(bVirtualFree);
		}
		if(DrRegs.empty())
			AddDrReg(State.ThreadID);
		AddBreak(bOEP,btDr0);EnableBreak(bOEP);
		do Continue();
		while(BreakWhere!=bDr0 && BreakWhere!=bProcessTerminated);
	}
	else
	{
		CONTEXT Context;
		Context.ContextFlags=CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(pi.hThread,&Context);
		pMain->SetMainBreaks();
		VictimBase=GetIBFromPEB(hVictim,Context);
		if(pMain->pInitData->fMemoryManager)
		{
			void *pTempImage;
			std::vector<DWORD> Array;
			DWORD_PTR Current;

			pTempImage=VirtualAlloc(NULL,VictimFile.pPEHeader->OptionalHeader.SizeOfImage,MEM_COMMIT,PAGE_READWRITE);
			ReadMem(VictimBase,pTempImage,VictimFile.pPEHeader->OptionalHeader.SizeOfImage);

			Current=VictimBase;
			for(;;)
			{
				if(VirtualQueryEx(hVictim,(void*)Current,&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo))
					break;
				if((MemInfo.Protect & 0xff)==PAGE_EXECUTE_WRITECOPY)
					MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_EXECUTE_READWRITE;
				if((MemInfo.Protect & 0xff)==PAGE_WRITECOPY)
					MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_READWRITE;
				Current+=MemInfo.RegionSize;
				Array.push_back((DWORD)MemInfo.RegionSize);
				Array.push_back(MemInfo.Protect);
				if(Current>=VictimBase+VictimFile.pPEHeader->OptionalHeader.SizeOfImage)
					break;
			}

			cNtUnmapViewOfSection NtUnmapViewOfSection=(cNtUnmapViewOfSection)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtUnmapViewOfSection");
			NtUnmapViewOfSection(hVictim,(void*)VictimBase);
			if(VirtualAllocEx(hVictim,(void*)VictimBase,AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+PAGE_SIZE*PAGES_COUNT,
				MEM_COMMIT | MEM_RESERVE,PAGE_NOACCESS)==NULL)
			{
				Terminate();
				MessageBox(NULL,_T("Unable to allocate memory!"),_T("QuickUnpack"),MB_OK);
				return;
			}
			WriteMem(VictimBase,pTempImage,VictimFile.pPEHeader->OptionalHeader.SizeOfImage);
			VirtualFree(pTempImage,0,MEM_RELEASE);

			Current=VictimBase;
			for(size_t j=0;j!=Array.size();j+=2)
			{
				VirtualProtectEx(hVictim,(void*)Current,Array[j],Array[j+1],&Array[1]);
				Current+=Array[j];
			}

			PagesAllocked=VictimBase+AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE);
			VictimFile.pPEHeader->OptionalHeader.SizeOfImage=(DWORD)AlignTo(VictimFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+PAGE_SIZE*PAGES_COUNT;

			bVirtualAlloc=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtAllocateVirtualMemory"));
			AddBreak(bVirtualAlloc);EnableBreak(bVirtualAlloc);
			bVirtualFree=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtFreeVirtualMemory"));
			AddBreak(bVirtualFree);EnableBreak(bVirtualFree);
		}
		if(fStopSystem)
			CloseHandle(pi.hThread);
		else
		{
			CTLS TLSDir;
			TLSDir.ReadFromFile(VictimFile);
			Addr=TLSDir.GetFirstCallback();
			bProcessCreated=VictimBase+VictimFile.pPEHeader->OptionalHeader.AddressOfEntryPoint;
			if(DrRegs.empty())
				AddDrReg(State.ThreadID);
			Context.Dr0=bProcessCreated;
			Context.Dr1=Addr;
#if defined _M_AMD64
			Context.Dr7&=0xffffffff0000dc00;
#elif defined _M_IX86
			Context.Dr7&=0xdc00;
#else
!!!
#endif
			Context.Dr7|=1 | 4 | 0x100;
			SetThreadContext(pi.hThread,&Context);
			AddBreak(bProcessCreated,btDr0); EnableBreak(bProcessCreated);
			AddBreak(Addr,btDr1); EnableBreak(Addr);
			ResumeThread(pi.hThread);
			CloseHandle(pi.hThread);
			Wait();

			while(BreakWhere!=bDr0 && BreakWhere!=bDr1 && BreakWhere!=bProcessTerminated)
				Continue();
			DeleteBreak(bProcessCreated); DeleteBreak(Addr);
			if(BreakWhere==bDr1)
			{
				DWORD_PTR AddrContinue;
				AddrContinue=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtContinue");
				AddBreak(AddrContinue);EnableBreak(AddrContinue);
				while(BreakWhere!=AddrContinue && BreakWhere!=bProcessTerminated)
					Continue();
				DeleteBreak(AddrContinue);
				DWORD_PTR ContextAddress;
#if defined _M_AMD64
				ContextAddress=State.RegCx;
#elif defined _M_IX86
				ReadMem(State.RegSp+sizeof(DWORD_PTR),&ContextAddress,sizeof(ContextAddress));
#else
!!!
#endif
				DWORD_PTR Temp=0;
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr0),&Temp,sizeof(Temp));
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr1),&Temp,sizeof(Temp));
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr2),&Temp,sizeof(Temp));
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr3),&Temp,sizeof(Temp));
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr6),&Temp,sizeof(Temp));
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr7),&Temp,sizeof(Temp));
			}
			else
			{
				for(size_t i=0;i!=DrRegs.size();++i)
				{
					DWORD dwTID=DrRegs[i].dwTID;
					DrRegs[i].Clear();
					DrRegs[i].dwTID=dwTID;
				}
			}
		}
	}
	WriteLog(_T("PID: ")+IntToStr(dwVictimPID,16,sizeof(dwVictimPID)*2)+_T(", TID: ")+IntToStr(pi.dwThreadId,16,sizeof(pi.dwThreadId)*2));
	pMain->Modules.Reload(VictimBase,&VictimFile,hVictim);
	if(pMain->pInitData->ImportRec==irSmartTracer)
	{
		pMain->Modules.HookExport();
		pMain->Modules.HookImport();
	}
	WriteLog(targetloaded+IntToStr(VictimBase,16,sizeof(VictimBase)*2));
}

void CTracer::Terminate()
{
	DisableBreakAll();
	if(hVictim!=NULL)
	{
		if(!TerminateProcess(hVictim,0))
			WriteLog(cantterminate+IntToStr(dwVictimPID,16,sizeof(dwVictimPID)*2));

		do
		{
			State.State=STATE_READY;
			Resume();
			TerminateProcess(hVictim,0);
		}
		while(WaitForSingleObject(hVictim,100)==WAIT_TIMEOUT);

		CloseHandle(hVictim);
		hVictim=NULL;
		pMain->Modules.hVictim=NULL;
	}
	dwVictimPID=0;
	BreakWhere=bProcessTerminated;
	State.State=STATE_READY;
	Resume();
	DeleteBreakAll();
	DeleteDrRegs();
}

void CTracer::Continue()
{
	Resume();
	Wait();
}

DWORD_PTR PutMask(DWORD_PTR Result,int nSize)
{
	switch(nSize)
	{
	case 1:
		Result&=MAXBYTE;
		break;
	case 2:
		Result&=MAXWORD;
		break;
	case 4:
		Result&=MAXDWORD;
		break;
	case 8:
		Result&=MAXQWORD;
		break;
	}
	return Result;
}

DWORD_PTR GetRegValue(DATA_STATE *State,int nCode,int nSize)
{
	DWORD_PTR Result=0;

	switch(nCode)
	{
	case REG_CODE_AH:
		Result=State->RegAx >> 8;
		break;
	case REG_CODE_BH:
		Result=State->RegBx >> 8;
		break;
	case REG_CODE_CH:
		Result=State->RegCx >> 8;
		break;
	case REG_CODE_DH:
		Result=State->RegDx >> 8;
		break;
	case REG_CODE_AX:
		Result=State->RegAx;
		break;
	case REG_CODE_BX:
		Result=State->RegBx;
		break;
	case REG_CODE_CX:
		Result=State->RegCx;
		break;
	case REG_CODE_DX:
		Result=State->RegDx;
		break;
	case REG_CODE_BP:
		Result=State->RegBp;
		break;
	case REG_CODE_SP:
		Result=State->RegSp;
		break;
	case REG_CODE_SI:
		Result=State->RegSi;
		break;
	case REG_CODE_DI:
		Result=State->RegDi;
		break;
	case REG_CODE_EFL:
		Result=State->RegFlags;
		break;
#if defined _M_AMD64
	case REG_CODE_R8:
		Result=State->Reg8;
		break;
	case REG_CODE_R9:
		Result=State->Reg9;
		break;
	case REG_CODE_R10:
		Result=State->Reg10;
		break;
	case REG_CODE_R11:
		Result=State->Reg11;
		break;
	case REG_CODE_R12:
		Result=State->Reg12;
		break;
	case REG_CODE_R13:
		Result=State->Reg13;
		break;
	case REG_CODE_R14:
		Result=State->Reg14;
		break;
	case REG_CODE_R15:
		Result=State->Reg15;
		break;
	case REG_CODE_IP:
		Result=State->RegIp;
		break;
#endif
	}
	return PutMask(Result,nSize);
}

void CTracer::Trace()
{
	BYTE bBuf[2*MAX_INSTRUCTION_LEN];
	INSTRUCTION Instr;
	DISASM_PARAMS Params;

	if(ReadMem(State.RegIp,&bBuf,sizeof(bBuf))!=sizeof(bBuf))
	{
		Terminate();
		return;
	}

	size_t m=0;
	for(;m!=Breaks.size();++m)
	{
		if(Breaks[m]->Where==State.RegIp)
			break;
	}
	if(m!=Breaks.size() && Breaks[m]->nEnabled>0)
		memcpy(bBuf,&Breaks[m]->bOldBytes[0],Breaks[m]->nSize);

	Params.arch=ARCH_ALL;
	Params.sf_prefixes=NULL;
#if defined _M_AMD64
	Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
	Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
	medi_disassemble((uint8_t*)bBuf,sizeof(bBuf),&Instr,&Params);
	DWORD_PTR NextAddress=Instr.length;
	if(pMain->pInitData->fUseTf)
	{
		if(Instr.id==ID_POPF ||
			Instr.id==ID_PUSHF ||
			(Instr.id==ID_MOV &&
				(Instr.ops[0].flags & OPERAND_TYPE_REG) &&
				Instr.ops[0].value.reg.type==REG_TYPE_SEG &&
				Instr.ops[0].value.reg.code==SREG_CODE_SS) ||						//mov ss,XXX
			Instr.id==ID_INT ||
			Instr.id==ID_ICEBP ||
			*(bBuf+Instr.opcode_offset)==0x17)										//pop ss
		{
			NextAddress+=State.RegIp;
			AddBreak(NextAddress);EnableBreak(NextAddress);
			SuspendAllOther();
			while(BreakWhere!=NextAddress && BreakWhere!=bProcessTerminated && !IsThreadDying())
				Continue();
			ResumeAllOther();
			DeleteBreak(NextAddress);
		}
		else
		{
			m=AddDrReg(State.ThreadID);
			DrRegs[m].fTraceFlag=true;

			DWORD dwTID=State.ThreadID;
			SuspendAllOther();
			while(!IsThreadDying())
			{
				Continue();
				if(State.ThreadID==dwTID || BreakWhere==bProcessTerminated)
					break;
			}
			ResumeAllOther();
		}
	}
	else
	{
		DWORD_PTR Temp=0;
		if(Instr.id==ID_RETN)
		{
			NextAddress=0;
			ReadMem(State.RegSp,&NextAddress,Instr.opsize);
		}
		else if(Instr.id==ID_CALL ||
			Instr.id==ID_JMP)
		{
			if((Instr.ops[0].flags & OPERAND_TYPE_MEM)!=0)
			{
				if((Instr.ops[0].value.addr.mod & ADDR_MOD_DISP)!=0)
					NextAddress=(DWORD_PTR)Instr.disp.value.d64;
				else
					NextAddress=0;

				if((Instr.ops[0].value.addr.mod & ADDR_MOD_BASE)!=0)
					NextAddress+=GetRegValue(&State,Instr.ops[0].value.addr.base,Instr.addrsize);

				if((Instr.ops[0].value.addr.mod & ADDR_MOD_IDX)!=0)
					NextAddress+=GetRegValue(&State,Instr.ops[0].value.addr.index,Instr.addrsize)*Instr.ops[0].value.addr.scale;

				ReadMem(NextAddress,&NextAddress,Instr.ops[0].size);
			}
			else if((Instr.ops[0].flags & OPERAND_TYPE_IMM)!=0)
				NextAddress+=State.RegIp+(DWORD_PTR)Instr.ops[0].value.imm.imm64;
			else if((Instr.ops[0].flags & OPERAND_TYPE_REG)!=0)
			{
				if((Instr.ops[0].value.reg.type==REG_TYPE_GEN)!=0)
					NextAddress=GetRegValue(&State,Instr.ops[0].value.reg.code,Instr.ops[0].size);
			}
			NextAddress=PutMask(NextAddress,Instr.ops[0].size);
		}
		else if(Instr.id==ID_LOOP ||
			Instr.id==ID_LOOPZ ||
			Instr.id==ID_LOOPNZ ||
			Instr.id==ID_JCXZ ||
			Instr.id==ID_JO ||
			Instr.id==ID_JNO ||
			Instr.id==ID_JB ||
			Instr.id==ID_JAE ||
			Instr.id==ID_JZ ||
			Instr.id==ID_JNZ ||
			Instr.id==ID_JBE ||
			Instr.id==ID_JA ||
			Instr.id==ID_JS ||
			Instr.id==ID_JNS ||
			Instr.id==ID_JP ||
			Instr.id==ID_JNP ||
			Instr.id==ID_JL ||
			Instr.id==ID_JGE ||
			Instr.id==ID_JLE ||
			Instr.id==ID_JG)
		{
			Temp=NextAddress+State.RegIp;
			NextAddress=PutMask(Temp+(DWORD_PTR)Instr.ops[0].value.imm.imm64,Instr.ops[0].size);
		}
		else
			NextAddress+=State.RegIp;
		AddBreak(NextAddress); EnableBreak(NextAddress);
		AddBreak(Temp); EnableBreak(Temp);
		SuspendAllOther();
		while(BreakWhere!=NextAddress && BreakWhere!=Temp && BreakWhere!=bProcessTerminated && !IsThreadDying())
			Continue();
		ResumeAllOther();
		DeleteBreak(NextAddress); DeleteBreak(Temp);
	}
}

void CTracer::Wait()
{
	for(;;)
	{
		if(hVictim==NULL)
		{
			BreakWhere=bProcessTerminated;
			return;
		}
		if(IsProcessDead(hVictim))
		{
			CloseHandle(hVictim);
			hVictim=NULL;
			pMain->Modules.hVictim=NULL;
			dwVictimPID=0;

			BreakWhere=bProcessTerminated;
			return;
		}
		GetState(&State);
		if(State.State==STATE_BREAK)
		{
			if(Suspend()==-1)
			{
				State.State=STATE_UNHANDLED;
				BreakWhere=bThreadTerminating;
				return;
			}
			AddDrReg(State.ThreadID);
			BreakWhere=bUnhandledBreak;

			State.State=STATE_HANDLED;
			for(size_t i=0;i!=Breaks.size();++i)
			{
				if(Breaks[i]->BreakType1==btOpcode || Breaks[i]->BreakType1==btCC)
				{
					if(Breaks[i]->Where==State.RegIp && Breaks[i]->BreakType1==btOpcode)
					{
					}
					else if(Breaks[i]->Where+Breaks[i]->nSize==State.RegIp && Breaks[i]->BreakType1==btCC)
						State.RegIp-=Breaks[i]->nSize;
					else
						continue;

					BreakWhere=Breaks[i]->Where;
					DisableBreak(BreakWhere);
					break;
				}
			}
			if(BreakWhere==bUnhandledBreak)
			{
				if(State.RegIp==pMain->Modules.TrampolineBase+TRAMPOLINE_BREAK_OFFSET)
				{
					BreakWhere=bFunction;
					if(pMain->Modules.fUnhookInAction)
					{
						BYTE bNop=0x90;
						pMain->Modules.UnhookedBreaks.push_back(State.RegIp);
						WriteMem(State.RegIp,&bNop,sizeof(bNop));
					}
					++State.RegIp;
				}
			}
			if(!pMain->BreakHandler())
				return;
			Resume();
		}
		else if(State.State==STATE_SINGLESTEP)
		{
			if(Suspend()==-1)
			{
				State.State=STATE_UNHANDLED;
				BreakWhere=bThreadTerminating;
				return;
			}
			BreakWhere=bUnhandledSingleStep;
			State.State=STATE_HANDLED;

			int m=AddDrReg(State.ThreadID);
			if(DrRegs[m].fTraceFlag && (State.RegDr6 & DR6_TFHIT)==DR6_TFHIT)
			{
				BreakWhere=bSingleStep;
				DrRegs[m].fTraceFlag=false;
			}
			else if((DrRegs[m].Dr[7] & 0x1)==0x1 && (State.RegDr6 & 0x1)==0x1 && DrRegs[m].Dr[0]==State.RegDr0)
			{
				BreakWhere=bDr0;
				DisableBreak(DrRegs[m].Dr[0]);
			}
			else if((DrRegs[m].Dr[7] & 0x4)==0x4 && (State.RegDr6 & 0x2)==0x2 && DrRegs[m].Dr[1]==State.RegDr1)
			{
				BreakWhere=bDr1;
				DisableBreak(DrRegs[m].Dr[1]);
			}
			else if((DrRegs[m].Dr[7] & 0x10)==0x10 && (State.RegDr6 & 0x4)==0x4 && DrRegs[m].Dr[2]==State.RegDr2)
			{
				BreakWhere=bDr2;
				DisableBreak(DrRegs[m].Dr[2]);
			}
			else if((DrRegs[m].Dr[7] & 0x40)==0x40 && (State.RegDr6 & 0x8)==0x8 && DrRegs[m].Dr[3]==State.RegDr3)
			{
				BreakWhere=bDr3;
				DisableBreak(DrRegs[m].Dr[3]);
			}
			if(!pMain->BreakHandler())
				return;
			Resume();
		}
		else if(State.State==STATE_BREAKMEM)
		{
			if(Suspend()==-1)
			{
				State.State=STATE_UNHANDLED;
				BreakWhere=bThreadTerminating;
				return;
			}
			AddDrReg(State.ThreadID);
			BreakWhere=bUnhandledBreakMem;
			State.State=STATE_HANDLED;

			if(MemBreaks.find(CutTo(State.RegCr2,PAGE_SIZE))!=MemBreaks.end())
			{
				BreakWhere=bBreakMem;
				DeleteMemoryBreaks();
				return;
			}

			if(!pMain->BreakHandler())
				return;
			Resume();
		}
		else if(State.State==STATE_BREAKCPUID)
		{
			if(Suspend()==-1)
			{
				State.State=STATE_UNHANDLED;
				BreakWhere=bThreadTerminating;
				return;
			}
			AddDrReg(State.ThreadID);
			BreakWhere=bBreakCpuid;
			State.State=STATE_HANDLED;
			return;
		}
		else
			SwitchToThread();
	}
}

DWORD_PTR CTracer::ReadMem(DWORD_PTR Addr,void *pBuff,DWORD_PTR Size)
{
	if(IsProcessDying(hVictim))
	{
		Terminate();
		return 0;
	}
	else
		return ::ReadMem(hVictim,Addr,pBuff,Size);
}

DWORD_PTR CTracer::WriteMem(DWORD_PTR Addr,const void *pBuff,DWORD_PTR Size)
{
	if(IsProcessDying(hVictim))
	{
		Terminate();
		return 0;
	}
	else
		return ::WriteMem(hVictim,Addr,pBuff,Size);
}

DWORD_PTR CTracer::GetOrdinalAddress(const TCHAR *szLibName,WORD wOrdinal)
{
	pMain->Modules.Reload(VictimBase,&VictimFile,hVictim);

	CImportRecord ImportRecord(szLibName,wOrdinal,0,0,itNone);
	pMain->Modules.ForwardedNext(ImportRecord,INFINITE);
	if(ImportRecord.sApiName.empty())
	{
		szLibName=ImportRecord.sLibName.c_str();
		wOrdinal=ImportRecord.wOrdinal;
	}
	else
		return GetProcedureAddress(ImportRecord.sLibName.c_str(),ImportRecord.sApiName.c_str());

	DWORD_PTR LibBase=GetModHandle(dwVictimPID,szLibName);
	if(LibBase==0)
		return 0;

	CPEFile *pLibFile=NULL;
	for(size_t i=0;i!=pMain->Modules.Modules.size();++i)
	{
		if(pMain->Modules.Modules[i]->ModuleBase==LibBase)
		{
			pLibFile=&pMain->Modules.Modules[i]->ModuleFile;
			break;
		}
	}
	if(pLibFile==NULL || pLibFile->IsEmpty())
		return 0;

	IMAGE_EXPORT_DIRECTORY *pExports=(IMAGE_EXPORT_DIRECTORY*)pLibFile->RVA(pLibFile->pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if(pExports->NumberOfFunctions<(WORD)(wOrdinal-pExports->Base))
		return 0;
	else
		return LibBase+*(DWORD*)pLibFile->RVA(pExports->AddressOfFunctions+(wOrdinal-pExports->Base)*sizeof(DWORD));
}

DWORD_PTR CTracer::GetProcedureAddress(const TCHAR *szLibName,const char *szApiName)
{
	pMain->Modules.Reload(VictimBase,&VictimFile,hVictim);

	CImportRecord ImportRecord(szLibName,szApiName,0,0,itNone);
	pMain->Modules.ForwardedNext(ImportRecord,INFINITE);
	if(ImportRecord.wOrdinal!=0)
		return GetOrdinalAddress(ImportRecord.sLibName.c_str(),ImportRecord.wOrdinal);
	else
	{
		szLibName=ImportRecord.sLibName.c_str();
		szApiName=ImportRecord.sApiName.c_str();
	}

	DWORD_PTR LibBase=GetModHandle(dwVictimPID,szLibName);
	if(LibBase==0)
		return 0;

	CPEFile *pLibFile=NULL;
	for(size_t i=0;i!=pMain->Modules.Modules.size();++i)
	{
		if(pMain->Modules.Modules[i]->ModuleBase==LibBase)
		{
			pLibFile=&pMain->Modules.Modules[i]->ModuleFile;
			break;
		}
	}
	if(pLibFile==NULL || pLibFile->IsEmpty())
		return 0;

	IMAGE_EXPORT_DIRECTORY *pExports=(IMAGE_EXPORT_DIRECTORY*)pLibFile->RVA(pLibFile->pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	for(DWORD i=0;i!=pExports->NumberOfNames;++i)
	{
		const char *szCurrApiName=(char*)pLibFile->RVA(*(DWORD*)pLibFile->RVA(pExports->AddressOfNames+i*sizeof(DWORD)));
		if(_stricmp(szApiName,szCurrApiName)==0)
			return LibBase+*(DWORD*)pLibFile->RVA(pExports->AddressOfFunctions+
				(*(WORD*)pLibFile->RVA(pExports->AddressOfNameOrdinals+i*sizeof(WORD)))*sizeof(DWORD));
	}
	return 0;
}