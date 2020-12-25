#include "StdAfx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgImport.h"
#include <string>
#include "Main.h"
#include "PEFile.h"
#include "Modules.h"
#include "VersionHelpers.h"

struct CLIENT_ID
{
	DWORD_PTR ProcessId;
	DWORD_PTR ThreadId;
};

struct CREATE_THREAD_EX
{
	DWORD_PTR Size;
	DWORD_PTR Field1;
	DWORD_PTR Field2;
	DWORD_PTR pClientId;
	DWORD_PTR Field4;
	DWORD_PTR Field5;
	DWORD_PTR Field6;
	DWORD_PTR Field7;
	DWORD_PTR Field8;
};

struct THREAD_BASIC_INFORMATION
{
	DWORD ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	DWORD Priority;
	DWORD BasePriority;
};

typedef DWORD(NTAPI *cNtQueryInformationThread)
(
	HANDLE ThreadHandle,
	DWORD ThreadInformationClass,
	PVOID ThreadInformation,
	DWORD ThreadInformationLength,
	PDWORD ReturnLength
);

CMain *pMain=NULL;

unsigned int __stdcall MainThread(void *pInitData)
{
	_set_se_translator(SeTranslator);
	if(pMain==NULL)
	{
		try
		{
			pMain=new CMain((CInitData*)pInitData);
			pMain->Run();
			CMain *pOldMain=pMain;
			pMain=NULL;
			delete pOldMain;
		}
		catch(CException *e)
		{
			if(((CInitData*)pInitData)->UnpackMode==umFull)
				pMain->Terminate();
			else if(((CInitData*)pInitData)->UnpackMode==umSkipOEP)
			{
				pMain->Detach();
				CloseHandle(pMain->hVictim);
				pMain->hVictim=NULL;
			}
			CMain *pOldMain=pMain;
			pMain=NULL;
			delete pOldMain;
			if(e->IsKindOf(RUNTIME_CLASS(CMemoryException)))
				e->ReportError(MB_ICONEXCLAMATION|MB_SYSTEMMODAL,AFX_IDP_INTERNAL_FAILURE);
			else if(e->IsKindOf(RUNTIME_CLASS(CSeException)))
				theApp.HandleException((CSeException*)e);
			else if(!e->IsKindOf(RUNTIME_CLASS(CUserException)))
				e->ReportError(MB_ICONSTOP,AFX_IDP_INTERNAL_FAILURE);
		}
	}
	return 0;
}

void StopMainThread()
{
	if(pMain!=NULL)
		pMain->Stop();
}

CMain::CMain(CInitData *n_pInitData):CTracer(n_pInitData->sVictimFile.c_str(),n_pInitData->hDllHandle),
	fTerminate(false),
	TickCountAX(rand()),
	TickCountDX(rand())
{
	pInitData=n_pInitData;
}

CMain::~CMain()
{
	if(pInitData->fIsDll)
	{
		while(PathFileExists(sVictimLoaderName.c_str()))
		{
			SwitchToThread();
			DeleteFile(sVictimLoaderName.c_str());
		}
		while(PathFileExists(sVictimGhostName.c_str()))
		{
			SwitchToThread();
			DeleteFile(sVictimGhostName.c_str());
		}
	}
	if(UnpackedFile.IsEmpty())
		WriteLog(unpackednotcreated);
	WriteLog(unpackfinished);
	WriteLn(_T(""));
}

void CMain::Stop()
{
	fTerminate=true;

	if(hVictim!=NULL)
	{
		if(!TerminateProcess(hVictim,0))
			WriteLog(cantterminate+IntToStr(dwVictimPID,16,sizeof(dwVictimPID)*2));

		CloseHandle(hVictim);
		hVictim=NULL;
		Modules.hVictim=NULL;
	}
}

void CMain::Run()
{
	if(pInitData->UnpackMode==umFull)
	{
		if(pInitData->fIsDll && PreLoadDLL())
			FullUnpack();
		else if(PreLoad())
			FullUnpack();
	}
	else if(pInitData->UnpackMode==umSkipOEP)
		UnpackSkipOEP();
}

int CMain::PreLoadDLL()
{
	nBreakNumber=0;
	Start(true,FALSE);
	Modules.fUnhookInAction=TRUE;
	DWORD_PTR OEP=pInitData->dwOEP+VictimBase;
	WriteLn(_T(""));
	WriteLog(forceactivated);

	AddBreak(OEP,btDr0);EnableBreak(OEP);
	DWORD_PTR StopReason;
	for(;;)
	{
		Continue();

		if(BreakWhere==bProcessTerminated)
		{
			if(fTerminate)
				return 0;
			else
				break;
		}
		if(State.RegIp==OEP)
		{
#if defined _M_AMD64
			StopReason=State.RegDx;
#elif defined _M_IX86
			ReadMem(State.RegSp+sizeof(DWORD_PTR)+sizeof(HINSTANCE),&StopReason,sizeof(StopReason));
#else
!!!
#endif
			if(StopReason==DLL_PROCESS_ATTACH)
			{
				++nBreakNumber;
				VirginVictim.Clear();
				VirginVictim.Dump(hVictim,VictimBase,&VictimFile,csSimple);
				VirginVictim.pPEHeader->OptionalHeader.ImageBase=VictimBase;
				FirstVictimBase=VictimBase;
			}
			TraceAndReplace(OEP);
		}
	}

	int nFixNum;
	if(nBreakNumber==0)
		nFixNum=1;
	else
		nFixNum=nBreakNumber;
	WriteLog(falsedetected+IntToStr(nFixNum-1,10,0));
	WriteLn(_T(""));

	DeleteBreak(OEP);
	Modules.Clear();
	Terminate();
	return 1;
}

int CMain::PreLoad()
{
	nBreakNumber=0;
	if(!pInitData->fForce)
		return 1;
	WriteLog(forceactivated);
	WriteLog(loadingtarget);
	Start(true,FALSE);
	Modules.fUnhookInAction=TRUE;
	DWORD_PTR OEP=pInitData->dwOEP+VictimBase;

	AddBreak(OEP,btDr0);EnableBreak(OEP);
	WriteLn(_T(""));
	WriteLog(closeloaded);
	for(;;)
	{
		Continue();
		if(BreakWhere==bProcessTerminated)
		{
			if(fTerminate)
				return 0;
			else
				break;
		}
		if(State.RegIp==OEP)
		{
			++nBreakNumber;
			TraceAndReplace(OEP);
		}
	}

	int nFixNum;
	if(nBreakNumber==0)
		nFixNum=1;
	else
		nFixNum=nBreakNumber;
	WriteLog(falsedetected+IntToStr(nFixNum-1,10,0));
	WriteLn(_T(""));

	DeleteBreak(OEP);
	Modules.Clear();
	Terminate();
	return 1;
}

void CMain::FullUnpack()
{
	Start(true,FALSE);
	Modules.fUnhookInAction=TRUE;
	DWORD_PTR OEP=pInitData->dwOEP+VictimBase;

	WriteLn(_T(""));
	WriteLog(_T("EP: ")+IntToStr(State.RegIp,16,sizeof(State.RegIp)*2));
	WriteLog(_T("OEP: ")+IntToStr(OEP,16,sizeof(OEP)*2));

	AddBreak(OEP,btDr0);EnableBreak(OEP);

	for(;;)
	{
		Continue();
		if(BreakWhere==bProcessTerminated)
			return;
		if(State.RegIp==OEP)
		{
			if(nBreakNumber<=1)
				break;
			else
			{
				--nBreakNumber;
				TraceAndReplace(OEP);
			}
		}
	}
	SuspendAllOther();
	WriteLog(breaked+IntToStr(State.RegIp,16,sizeof(State.RegIp)*2));
	WriteLog(dumping);
	UnpackedFile.Clear();
	UnpackedFile.Dump(hVictim,VictimBase,&VictimFile,csMemoryManager);
	if(UnpackedFile.IsEmpty())
	{
		WriteEx(cantdump,TRUE,TRUE,RGB(255,0,0));
		return;
	}
	UnpackedFile.pPEHeader->OptionalHeader.ImageBase=VictimBase;
	UnpackedFile.pPEHeader->OptionalHeader.AddressOfEntryPoint=(DWORD)(State.RegIp-VictimBase);

	if(pInitData->fRemoveSect)
	{
		UnpackedFile.CutSections();
		WriteLog(sectionsdirs);
	}

	Modules.fUnhookInAction=FALSE;
	Modules.SetUnhookedBreaksBack();
	RestoreDelphiInit(false);
	if(pInitData->fRemoveSect ||
		UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress<UnpackedFile.pPEHeader->OptionalHeader.SizeOfHeaders)
		UnpackedFile.ProcessExport();
	if(pInitData->fRemoveSect ||
		UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress<UnpackedFile.pPEHeader->OptionalHeader.SizeOfHeaders)
		UnpackedFile.ProcessTLS();
	if(UnpackedFile.RVA(UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)!=NULL)
		((IMAGE_TLS_DIRECTORY*)UnpackedFile.RVA(UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress))->AddressOfCallBacks=0;
	RestoreImportRelocs();
	UnpackedFile.ProcessResources();

	if(pInitData->fAppendOverlay)
	{
		UnpackedFile.PreserveOverlay(VictimFile);
		WriteLog(overlayappended);
	}
	else if(!VictimFile.bOverlay.empty())
		WriteEx(overlayexists,TRUE,TRUE,RGB(255,0,0));
	UnpackedFile.Save(pInitData->sUnpackedFile.c_str());
	WriteLog(unpackedsaved+pInitData->sUnpackedFile.c_str());

	ResumeAllOther();
	Modules.UnHookExport();
	Modules.Clear();
	Terminate();
}

void CMain::UnpackSkipOEP()
{
	VictimFile.Read(sVictimName.c_str());
	if(VictimFile.IsEmpty())
	{
		WriteEx(cantopen+sVictimName.c_str(),TRUE,TRUE,RGB(255,0,0));
		return;
	}

	sVictimLoaderName.clear();
	hVictim=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pInitData->dwPID);
	VictimBase=pInitData->ImageBase;

	HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,pInitData->dwTID);
	ResumeThread(hThread);
	SuspendThread(hThread);

	CONTEXT Context;
	Context.ContextFlags=CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread,&Context);
	CloseHandle(hThread);

	DWORD_PTR CurrIP;
#if defined _M_AMD64
	CurrIP=Context.Rip;
#elif defined _M_IX86
	CurrIP=Context.Eip;
#else
!!!
#endif
	pInitData->dwOEP=(DWORD)(CurrIP-VictimBase);
	if(pInitData->ImportRec==irSmartTracer)
		Attach();
	else
		Modules.Reload(VictimBase,&VictimFile,hVictim);

	WriteLn(_T(""));
	WriteLog(targetloaded+IntToStr(VictimBase,16,sizeof(VictimBase)*2));
	WriteLog(_T("EIP: ")+IntToStr(CurrIP,16,sizeof(CurrIP)*2));

	WriteLog(dumping);
	UnpackedFile.Clear();
	UnpackedFile.Dump(hVictim,VictimBase,&VictimFile,csSimple);
	if(UnpackedFile.IsEmpty())
	{
		WriteEx(cantdump,TRUE,TRUE,RGB(255,0,0));
		return;
	}
	UnpackedFile.pPEHeader->OptionalHeader.ImageBase=VictimBase;
	UnpackedFile.pPEHeader->OptionalHeader.AddressOfEntryPoint=pInitData->dwOEP;

	if(pInitData->fRemoveSect)
	{
		UnpackedFile.CutSections();
		WriteLog(sectionsdirs);
	}

	if(dwVictimPID!=0)
		RestoreDelphiInit(false);
	else
		RestoreDelphiInit(true);
	if(pInitData->fRemoveSect ||
		UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress<UnpackedFile.pPEHeader->OptionalHeader.SizeOfHeaders)
		UnpackedFile.ProcessExport();
	if(pInitData->fRemoveSect ||
		UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress<UnpackedFile.pPEHeader->OptionalHeader.SizeOfHeaders)
		UnpackedFile.ProcessTLS();
	if(UnpackedFile.RVA(UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)!=NULL)
		((IMAGE_TLS_DIRECTORY*)UnpackedFile.RVA(UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress))->AddressOfCallBacks=0;
	RestoreImportRelocs();
	UnpackedFile.ProcessResources();

	Detach();
	Modules.Clear();
	CloseHandle(hVictim);
	hVictim=NULL;

	if(pInitData->fAppendOverlay)
	{
		UnpackedFile.PreserveOverlay(VictimFile);
		WriteLog(overlayappended);
	}
	else if(!VictimFile.bOverlay.empty())
		WriteEx(overlayexists,TRUE,TRUE,RGB(255,0,0));

	UnpackedFile.Save(pInitData->sUnpackedFile.c_str());
	WriteLog(unpackedsaved+pInitData->sUnpackedFile.c_str());
}

void CMain::RestoreDelphiInit(bool fIsStatic)
{
	if(!pInitData->fDelphiInit)
		return;

	BYTE bInstruct;
	DWORD_PTR PatchPlace=0,TableAddr;
	DWORD dwSize;

	BakState=State;
	do
	{
		ReadMem(State.RegIp,&bInstruct,sizeof(bInstruct));
		if(bInstruct==0xb8)
			PatchPlace=State.RegIp+1;
		if(fIsStatic)
			State.RegIp=NextInstr(State.RegIp);
		else
			Trace();
	}
	while(bInstruct!=0xe8 && !IsThreadDying() && BreakWhere!=bProcessTerminated);
	State=BakState;

	ReadMem(PatchPlace,&TableAddr,sizeof(TableAddr));
	ReadMem(TableAddr,&dwSize,sizeof(dwSize));
	dwSize=(dwSize+1)*sizeof(DWORD_PTR)*2;
	if(ReadMem(TableAddr,UnpackedFile.RVA((DWORD)(State.RegIp-VictimBase))-dwSize,dwSize)!=dwSize ||
		UnpackedFile.RVA((DWORD)(PatchPlace-VictimBase))==NULL)
	{
		WriteLog(delphiinitfailed);
		return;
	}
	*(DWORD_PTR*)UnpackedFile.RVA((DWORD)(PatchPlace-VictimBase))=State.RegIp-dwSize;
	WriteLog(delphiinitok);
}

bool ChooseForwardedLib(const std::map<TSTRING,size_t> &sLibs,TSTRING &sLibName)
{
	bool fResult=false;
	size_t nLength=MAXDWORD;

	std::map<TSTRING,size_t>::const_iterator it_libs(sLibs.begin());
	for(;it_libs!=sLibs.end();++it_libs)
	{
		if(it_libs->second<nLength)
		{
			sLibName=it_libs->first;
			nLength=it_libs->second;
			fResult=true;
		}
	}
	return fResult;
}

void CMain::IntersecLibsArray(std::map<TSTRING,size_t> &sLibs,const CImportRecord &ImportRecord)
{
	std::map<TSTRING,size_t> sRecordLibs;
	FillLibsArray(sRecordLibs,ImportRecord);

	std::map<TSTRING,size_t>::iterator it_libs(sLibs.begin());
	while(it_libs!=sLibs.end())
	{
		std::map<TSTRING,size_t>::const_iterator it_recordlib(sRecordLibs.find(it_libs->first));
		if(it_recordlib==sRecordLibs.end())
			it_libs=sLibs.erase(it_libs);
		else
		{
			it_libs->second+=it_recordlib->second-it_recordlib->first.length();
			++it_libs;
		}
	}
}

void CMain::FillLibsArray(std::map<TSTRING,size_t> &sLibs,CImportRecord ImportRecord)
{
	Modules.ForwardedPrev(ImportRecord,INFINITE);
	do sLibs.insert(std::make_pair(ImportRecord.sLibName,ImportRecord.sLibName.length()+ImportRecord.sApiName.length()));
	while(Modules.ForwardedNext(ImportRecord,1));
}

void CMain::ChangeForwardedImport()
{
	if(Import.Records.empty())
		return;
	Import.SortRecords(siByRecord);

	TSTRING sLibName;
	size_t i=0,j,nFirstRecord=(size_t)-1,nPrevRecord=(size_t)-1;
	std::map<TSTRING,size_t> sLibs;
	for(;i!=Import.Records.size();++i)
	{
		if(Import.Records[i].dwRecordRVA==0)
		{
			if(Import.Records[i].sApiName.empty())
			{
				CImportRecord temp(Import.Records[i]);
				while(temp.sApiName.empty() && Modules.ForwardedNext(temp,1)) {}
				if(!temp.sApiName.empty())
					Import.Records[i]=temp;
			}
			continue;
		}
		if(nPrevRecord!=-1)
		{
			if(Import.Records[i].dwRecordRVA==Import.Records[nPrevRecord].dwRecordRVA)
				continue;
			if(Import.Records[i].dwRecordRVA-Import.Records[nPrevRecord].dwRecordRVA!=sizeof(DWORD_PTR))
			{
				if(ChooseForwardedLib(sLibs,sLibName))
				{
					for(j=nFirstRecord;j!=i;++j)
					{
						Modules.ForwardedPrev(Import.Records[j],INFINITE);
						while(_tcsicmp(Import.Records[j].sLibName.c_str(),sLibName.c_str())!=0)
							Modules.ForwardedNext(Import.Records[j],1);
					}
				}
				sLibs.clear();
				nFirstRecord=(size_t)-1;
			}
		}
		if(nFirstRecord==-1)
		{
			FillLibsArray(sLibs,Import.Records[i]);
			nFirstRecord=i;
		}
		else
			IntersecLibsArray(sLibs,Import.Records[i]);
		nPrevRecord=i;
	}

	if(nFirstRecord!=-1 && ChooseForwardedLib(sLibs,sLibName))
	{
		for(j=nFirstRecord;j!=i;++j)
		{
			Modules.ForwardedPrev(Import.Records[j],INFINITE);
			while(_tcsicmp(Import.Records[j].sLibName.c_str(),sLibName.c_str())!=0)
				Modules.ForwardedNext(Import.Records[j],1);
		}
	}
}

void CMain::RestoreImportRelocs()
{
	if(UnpackedFile.IsEmpty())
		return;
	CDlgImport DlgImport(&Import,&UnpackedFile,&Modules,pInitData->sVictimFile.c_str(),pMain);
	if(pInitData->ImportRec==irNone)
	{
		ProcessRelocation();
		WriteLog(importwasnt);
		pInitData->sUnpackedFile=pInitData->sUnpackedShort;
	}
	else if(pInitData->ImportRec==irLoadLibs)
	{
		ProcessImportOnlyLibs();
		EnableWindow(pInitData->hMain,FALSE);
		DlgImport.DoModal();
		EnableWindow(pInitData->hMain,TRUE);
		SetForegroundWindow(pInitData->hMain);
		ProcessRelocation();
		Import.SaveToFile(UnpackedFile,pInitData->dwImportRVA);
		pInitData->sUnpackedFile=pInitData->sUnpackedShort;
		WriteLog(importonlylibs);
	}
	else if(pInitData->ImportRec==irSmart)
	{
		ProcessImport();
		ChangeForwardedImport();
		Import.RedirectToOldIAT(false,NULL,NULL);
		if(Import.Records.empty())
			WriteLog(noimportfound);
		EnableWindow(pInitData->hMain,FALSE);
		DlgImport.DoModal();
		EnableWindow(pInitData->hMain,TRUE);
		SetForegroundWindow(pInitData->hMain);
		ProcessRelocation();
		Import.SaveToFile(UnpackedFile,pInitData->dwImportRVA);
		pInitData->sUnpackedFile=pInitData->sUnpackedLong;
		WriteLog(importusedsmart);
	}
	if(pInitData->ImportRec==irSmartTracer)
	{
		ProcessImportWTrace();
		ChangeForwardedImport();
		Import.RedirectToOldIAT(false,NULL,NULL);
#ifdef DLLFILE
		CImport NewImport;
		for(size_t i=0;i!=Import.Records.size();++i)
		{
			if(!Import.Records[i].sApiName.empty() ||
				GetProcAddress(LoadLibrary(Import.Records[i].sLibName.c_str()),(char*)Import.Records[i].wOrdinal)!=NULL)
				NewImport.AddRecord(Import.Records[i]);
		}

		Import.Clear();

		for(size_t i=0;i!=NewImport.Records.size();++i)
			Import.AddRecord(NewImport.Records[i]);
#else
		if(Import.Records.empty())
			WriteLog(noimportfound);
		EnableWindow(pInitData->hMain,FALSE);
		DlgImport.DoModal();
		EnableWindow(pInitData->hMain,TRUE);
		SetForegroundWindow(pInitData->hMain);
#endif
		ProcessRelocation();
		Import.SaveToFile(UnpackedFile,pInitData->dwImportRVA);
		pInitData->sUnpackedFile=pInitData->sUnpackedLong;
		WriteLog(importusedtracer);
	}
	FixUp.SaveToFile(UnpackedFile);
}

DWORD CMain::GetNeededThreadId(HANDLE hThr)
{
	if(hThr==GetCurrentThread())
		return State.ThreadID;

	HANDLE hThread=NULL;
	DuplicateHandle(hVictim,hThr,GetCurrentProcess(),&hThread,THREAD_ALL_ACCESS,FALSE,0);
	THREAD_BASIC_INFORMATION tbi;
	cNtQueryInformationThread NtQueryInformationThread=(cNtQueryInformationThread)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtQueryInformationThread");
	NtQueryInformationThread(hThread,0,&tbi,sizeof(tbi),NULL);
	CloseHandle(hThread);
	return tbi.ClientId.ProcessId==dwVictimPID ? (DWORD)tbi.ClientId.ThreadId : 0;
}

bool CMain::IsNeededProcess(HANDLE hProc)
{
	if(hProc==GetCurrentProcess())
		return true;

	HANDLE hProcess=NULL;
	DuplicateHandle(hVictim,hProc,GetCurrentProcess(),&hProcess,PROCESS_ALL_ACCESS,FALSE,0);
	DWORD dwPID=GetProcessId(hProcess);
	CloseHandle(hProcess);
	return dwPID==dwVictimPID;
}

bool CMain::BreakHandler()
{
	if(BreakWhere==bUnhandledSingleStep)
	{
		State.State=STATE_UNHANDLED;
		return true;
	}
	else if(BreakWhere==bUnhandledBreak)
	{
		State.State=STATE_UNHANDLED;
		return true;
	}
	else if(BreakWhere==bUnhandledBreakMem)
	{
		State.State=STATE_UNHANDLED;
		return true;
	}
	else if(BreakWhere==bLoadLibrary)
	{
		Modules.Reload(VictimBase,&VictimFile,hVictim);
		if(pInitData->ImportRec==irSmartTracer)
			Modules.HookExport();

		TraceAndReplace(bLoadLibrary);
		return true;
	}
	else if(BreakWhere==bExceptionDispatcher)
	{
		DWORD_PTR ExcAddress;
#if defined _M_AMD64
		ExcAddress=State.RegSp+sizeof(CONTEXT);
		if(IsWindows7OrGreater())
			ExcAddress+=0x20;
#elif defined _M_IX86
		ReadMem(State.RegSp,&ExcAddress,sizeof(ExcAddress));
#else
!!!
#endif
		DWORD dwExcCode;
		ReadMem(ExcAddress+offsetof(EXCEPTION_RECORD,ExceptionCode),&dwExcCode,sizeof(dwExcCode));
		WriteLn(_T(""));
		WriteTime();
		WriteEx(_T(" - 0x")+IntToStr(dwExcCode,16,sizeof(dwExcCode)*2),FALSE,TRUE,RGB(0,0,0));
		Write(exceptionat);

		DWORD_PTR ContextAddress,RegIp;
#if defined _M_AMD64
		ContextAddress=State.RegSp;
		ReadMem(ContextAddress+offsetof(CONTEXT,Rip),&RegIp,sizeof(RegIp));
#elif defined _M_IX86
		ReadMem(State.RegSp+sizeof(DWORD_PTR),&ContextAddress,sizeof(ContextAddress));
		ReadMem(ContextAddress+offsetof(CONTEXT,Eip),&RegIp,sizeof(RegIp));
#else
!!!
#endif
		WriteEx(_T("0x")+IntToStr(RegIp,16,sizeof(RegIp)*2),FALSE,TRUE,RGB(0,0,0));
		if(pInitData->fProtectDr)
		{
			int m=AddDrReg(State.ThreadID);
			WriteMem(ContextAddress+offsetof(CONTEXT,Dr0),&DrRegs[m].OrigDr[0],4*RTL_FIELD_SIZE(CDrReg,OrigDr[0]));
			WriteMem(ContextAddress+offsetof(CONTEXT,Dr7),&DrRegs[m].OrigDr[7],RTL_FIELD_SIZE(CDrReg,OrigDr[7]));
		}
		TraceAndReplace(bExceptionDispatcher);
		return true;
	}
	else if(BreakWhere==bContinue)
	{
		if(pInitData->fProtectDr)
		{
			DWORD_PTR ContextAddress;
#if defined _M_AMD64
			ContextAddress=State.RegCx;
#elif defined _M_IX86
			ReadMem(State.RegSp+sizeof(DWORD_PTR),&ContextAddress,sizeof(ContextAddress));
#else
!!!
#endif
			DWORD dwContextFlags;
			ReadMem(ContextAddress+offsetof(CONTEXT,ContextFlags),&dwContextFlags,sizeof(dwContextFlags));

			int m=AddDrReg(State.ThreadID);
			if((dwContextFlags & CONTEXT_DEBUG_REGISTERS)==CONTEXT_DEBUG_REGISTERS)
			{
				ReadMem(ContextAddress+offsetof(CONTEXT,Dr0),&DrRegs[m].OrigDr[0],4*RTL_FIELD_SIZE(CDrReg,OrigDr[0]));
				ReadMem(ContextAddress+offsetof(CONTEXT,Dr7),&DrRegs[m].OrigDr[7],RTL_FIELD_SIZE(CDrReg,OrigDr[7]));
			}
			dwContextFlags|=CONTEXT_DEBUG_REGISTERS;
			WriteMem(ContextAddress+offsetof(CONTEXT,ContextFlags),&dwContextFlags,sizeof(dwContextFlags));
			WriteMem(ContextAddress+offsetof(CONTEXT,Dr0),&DrRegs[m].Dr[0],4*RTL_FIELD_SIZE(CDrReg,Dr[0]));
			WriteMem(ContextAddress+offsetof(CONTEXT,Dr7),&DrRegs[m].Dr[7],RTL_FIELD_SIZE(CDrReg,Dr[7]));
		}
		TraceAndReplace(bContinue);
		return true;
	}
	else if(BreakWhere==bGetContextThread)
	{
		if(pInitData->fProtectDr)
		{
			DWORD_PTR ThreadHandle;
#if defined _M_AMD64
			ThreadHandle=State.RegCx;
#elif defined _M_IX86
			ReadMem(State.RegSp+sizeof(DWORD_PTR),&ThreadHandle,sizeof(ThreadHandle));
#else
!!!
#endif
			DWORD ThreadId=GetNeededThreadId((HANDLE)ThreadHandle);
			if(ThreadId!=0)
			{
				int m=AddDrReg(ThreadId);
				DWORD_PTR ContextAddress;
#if defined _M_AMD64
				ContextAddress=State.RegDx;
#elif defined _M_IX86
				ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&ContextAddress,sizeof(ContextAddress));
#else
!!!
#endif
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr0),&DrRegs[m].OrigDr[0],4*RTL_FIELD_SIZE(CDrReg,OrigDr[0]));
				WriteMem(ContextAddress+offsetof(CONTEXT,Dr7),&DrRegs[m].OrigDr[7],RTL_FIELD_SIZE(CDrReg,OrigDr[7]));
			}
		}
		TraceAndReplace(bGetContextThread);
		return true;
	}
	else if(BreakWhere==bSetContextThread)
	{
		if(pInitData->fProtectDr)
		{
			DWORD_PTR ThreadHandle;
#if defined _M_AMD64
			ThreadHandle=State.RegCx;
#elif defined _M_IX86
			ReadMem(State.RegSp+sizeof(DWORD_PTR),&ThreadHandle,sizeof(ThreadHandle));
#else
!!!
#endif
			DWORD ThreadId=GetNeededThreadId((HANDLE)ThreadHandle);
			if(ThreadId!=0)
			{
				int m=AddDrReg(ThreadId);
				DWORD_PTR ContextAddress;
#if defined _M_AMD64
				ContextAddress=State.RegDx;
#elif defined _M_IX86
				ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&ContextAddress,sizeof(ContextAddress));
#else
!!!
#endif
				DWORD dwContextFlags;
				ReadMem(ContextAddress+offsetof(CONTEXT,ContextFlags),&dwContextFlags,sizeof(dwContextFlags));
				if((dwContextFlags & CONTEXT_DEBUG_REGISTERS)==CONTEXT_DEBUG_REGISTERS)
				{
					ReadMem(ContextAddress+offsetof(CONTEXT,Dr0),&DrRegs[m].OrigDr[0],4*RTL_FIELD_SIZE(CDrReg,OrigDr[0]));
					ReadMem(ContextAddress+offsetof(CONTEXT,Dr7),&DrRegs[m].OrigDr[7],RTL_FIELD_SIZE(CDrReg,OrigDr[7]));
					WriteMem(ContextAddress+offsetof(CONTEXT,Dr0),&DrRegs[m].Dr[0],4*RTL_FIELD_SIZE(CDrReg,Dr[0]));
					WriteMem(ContextAddress+offsetof(CONTEXT,Dr7),&DrRegs[m].Dr[7],RTL_FIELD_SIZE(CDrReg,Dr[7]));
				}
			}
		}
		TraceAndReplace(bSetContextThread);
		return true;
	}
	else if(BreakWhere==bCreateThread)
	{
		DWORD_PTR ProcessHandle;
#if defined _M_AMD64
		ProcessHandle=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&ProcessHandle,sizeof(ProcessHandle));
#else
!!!
#endif
		if(!IsNeededProcess((HANDLE)ProcessHandle))
		{
			TraceAndReplace(bCreateThread);
			return true;
		}
		DWORD_PTR Suspended,Temp;
		ReadMem(State.RegSp+8*sizeof(DWORD_PTR),&Suspended,sizeof(Suspended));
		Temp=Suspended | 1;
		WriteMem(State.RegSp+8*sizeof(DWORD_PTR),&Temp,sizeof(Temp));

		DWORD_PTR ClientAddress,CreatedAddress;
		ReadMem(State.RegSp+5*sizeof(DWORD_PTR),&ClientAddress,sizeof(ClientAddress));
		ReadMem(State.RegSp,&CreatedAddress,sizeof(CreatedAddress));
		AddBreak(CreatedAddress);EnableBreak(CreatedAddress);
		SuspendAllOther();
		while(BreakWhere!=CreatedAddress && BreakWhere!=bProcessTerminated && !IsThreadDying())
			Continue();
		ResumeAllOther();
		DeleteBreak(CreatedAddress);

		EnableBreak(bCreateThread);
		if(State.RegAx!=STATUS_SUCCESS)
			return true;

		DWORD dwTID;
		ReadMem(ClientAddress+offsetof(CLIENT_ID,ThreadId),&dwTID,sizeof(dwTID));
		HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,dwTID);

		if(Suspended==0)
			ResumeThread(hThread);
		CloseHandle(hThread);

		AddDrReg(dwTID);

		WriteLn(_T(""));
		WriteTime();
		WriteEx(_T(" - 0x")+IntToStr(dwTID,16,sizeof(dwTID)*2),FALSE,TRUE,RGB(0,0,0));
		Write(threadcreated);
		return true;
	}
	else if(BreakWhere==bCreateThreadEx)
	{
		DWORD_PTR ProcessHandle;
#if defined _M_AMD64
		ProcessHandle=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&ProcessHandle,sizeof(ProcessHandle));
#else
!!!
#endif
		if(!IsNeededProcess((HANDLE)ProcessHandle))
		{
			TraceAndReplace(bCreateThreadEx);
			return true;
		}
		DWORD_PTR Suspended,Temp;
		ReadMem(State.RegSp+7*sizeof(DWORD_PTR),&Suspended,sizeof(Suspended));
		Temp=Suspended | 1;
		WriteMem(State.RegSp+7*sizeof(DWORD_PTR),&Temp,sizeof(Temp));

		DWORD_PTR ClientAddress,CreatedAddress;
		ReadMem(State.RegSp+11*sizeof(DWORD_PTR),&ClientAddress,sizeof(ClientAddress));
		ReadMem(ClientAddress+offsetof(CREATE_THREAD_EX,pClientId),&ClientAddress,sizeof(ClientAddress));
		ReadMem(State.RegSp,&CreatedAddress,sizeof(CreatedAddress));
		AddBreak(CreatedAddress);EnableBreak(CreatedAddress);
		SuspendAllOther();
		while(BreakWhere!=CreatedAddress && BreakWhere!=bProcessTerminated && !IsThreadDying())
			Continue();
		ResumeAllOther();
		DeleteBreak(CreatedAddress);

		EnableBreak(bCreateThreadEx);
		if(State.RegAx!=STATUS_SUCCESS)
			return true;

		DWORD dwTID;
		ReadMem(ClientAddress+offsetof(CLIENT_ID,ThreadId),&dwTID,sizeof(dwTID));
		HANDLE hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,dwTID);

		if(Suspended==0)
			ResumeThread(hThread);
		CloseHandle(hThread);

		AddDrReg(dwTID);

		WriteLn(_T(""));
		WriteTime();
		WriteEx(_T(" - 0x")+IntToStr(dwTID,16,sizeof(dwTID)*2),FALSE,TRUE,RGB(0,0,0));
		Write(threadcreated);
		return true;
	}
#ifndef DLLFILE
	else if(BreakWhere==bVirtualAlloc && pInitData->fMemoryManager)
	{
		DWORD_PTR ProcessHandle;
#if defined _M_AMD64
		ProcessHandle=State.RegCx;
#elif defined _M_IX86
		ReadMem(State.RegSp+sizeof(DWORD_PTR),&ProcessHandle,sizeof(ProcessHandle));
#else
!!!
#endif
		if(!IsNeededProcess((HANDLE)ProcessHandle))
		{
			TraceAndReplace(bVirtualAlloc);
			return true;
		}
		DWORD dwOldProtect;
		DWORD_PTR Size,Address,Type,Protect,Temp,i;
		int nNumber;
#if defined _M_AMD64
		Address=State.RegDx;
#elif defined _M_IX86
		ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&Address,sizeof(Address));
#else
!!!
#endif
		ReadMem(Address,&Address,sizeof(Address));
#if defined _M_AMD64
		Size=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&Size,sizeof(Size));
#else
!!!
#endif
		ReadMem(Size,&Size,sizeof(Size));
		ReadMem(State.RegSp+5*sizeof(DWORD_PTR),&Type,sizeof(Type));
		ReadMem(State.RegSp+6*sizeof(DWORD_PTR),&Protect,sizeof(Protect));

		Protect&=~PAGE_NOCACHE | PAGE_WRITECOMBINE;
		if(Address==0)
			Type|=MEM_RESERVE;

		if((Type & MEM_RESERVE)==MEM_RESERVE)
		{
			if(Address!=0)
			{
				ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
				EnableBreak(bVirtualAlloc);
#if defined _M_AMD64
				State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
				State.RegSp+=7*sizeof(DWORD_PTR);
#else
!!!
#endif
				State.RegAx=STATUS_CONFLICTING_ADDRESSES;
				return true;
			}
			Size=AlignTo(Size,PAGE_SIZE)/PAGE_SIZE;
			nNumber=0;
			i=0;
			for(;;)
			{
				if(nNumber+(int)Size>=PAGES_COUNT)
					break;
				if(pPageDir[nNumber].Address==0 && ((PagesAllocked+nNumber*PAGE_SIZE) & (PAGE_GRANULARITY-1))==0)
				{
					for(i=0;i!=Size;++i)
					{
						if(pPageDir[nNumber+i].Address!=0)
							break;
					}
					if(i==Size)
						break;
					else
						nNumber+=(int)i;
				}
				++nNumber;
			}
			if(i==Size)
			{
				Address=PagesAllocked+nNumber*PAGE_SIZE;
				for(i=0;i!=Size;++i)
				{
					pPageDir[nNumber+i].Address=Address/PAGE_SIZE;
					pPageDir[nNumber+i].Reserved=1;
				}
				Size=Size*PAGE_SIZE;
				VirtualProtectEx(hVictim,(void*)Address,Size,PAGE_NOACCESS,&dwOldProtect);
			}
			else
			{
				MessageBox(NULL,_T("Out of process memory!"),_T("QuickUnpack"),MB_OK);
				TraceAndReplace(bVirtualAlloc);
				return true;
			}
		}
		if((Type & MEM_COMMIT)==MEM_COMMIT)
		{
			nNumber=(int)((Address-PagesAllocked)/PAGE_SIZE);
			Size=AlignTo(Size+Address-CutTo(Address,PAGE_SIZE),PAGE_SIZE)/PAGE_SIZE;
			Address=CutTo(Address,PAGE_SIZE);

			i=0;
			if(nNumber+(int)Size<PAGES_COUNT && nNumber>0 && (int)Size<PAGES_COUNT)
			{
				for(i=nNumber;i!=nNumber+Size;++i)
				{
					if(pPageDir[i].Reserved!=1)
						break;
				}

				if(i==nNumber+Size)
				{
					for(i=nNumber;i!=nNumber+Size;++i)
						pPageDir[i].Committed=1;
				}
			}
			if(i!=nNumber+Size)
			{
				if(nNumber+(int)Size<PAGES_COUNT && nNumber>0 && (int)Size<PAGES_COUNT)
				{
					ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
					EnableBreak(bVirtualAlloc);
#if defined _M_AMD64
					State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
					State.RegSp+=7*sizeof(DWORD_PTR);
#else
!!!
#endif
					State.RegAx=STATUS_CONFLICTING_ADDRESSES;
					return true;
				}
				else
				{
//					MessageBox(NULL,_T("Out of reserved memory!"),_T("QuickUnpack"),MB_OK);
					TraceAndReplace(bVirtualAlloc);
					return true;
				}
			}
			Size*=PAGE_SIZE;
			VirtualProtectEx(hVictim,(void*)Address,Size,(DWORD)Protect,&dwOldProtect);
		}
#if defined _M_AMD64
		Temp=State.RegDx;
#elif defined _M_IX86
		ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&Temp,sizeof(Temp));
#else
!!!
#endif
		WriteMem(Temp,&Address,sizeof(Address));
#if defined _M_AMD64
		Temp=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&Temp,sizeof(Temp));
#else
!!!
#endif
		WriteMem(Temp,&Size,sizeof(Size));

		ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
		EnableBreak(bVirtualAlloc);
#if defined _M_AMD64
		State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
		State.RegSp+=7*sizeof(DWORD_PTR);
#else
!!!
#endif
		State.RegAx=STATUS_SUCCESS;

		if(PageLastUsed<Address+Size)
			PageLastUsed=Address+Size;
		return true;
	}
	else if(BreakWhere==bVirtualFree && pInitData->fMemoryManager)
	{
		DWORD_PTR ProcessHandle;
#if defined _M_AMD64
		ProcessHandle=State.RegCx;
#elif defined _M_IX86
		ReadMem(State.RegSp+sizeof(DWORD_PTR),&ProcessHandle,sizeof(ProcessHandle));
#else
!!!
#endif
		if(!IsNeededProcess((HANDLE)ProcessHandle))
		{
			TraceAndReplace(bVirtualFree);
			return true;
		}
		DWORD_PTR Address,Size,Type,Temp,i;
		int nNumber;
#if defined _M_AMD64
		Address=State.RegDx;
#elif defined _M_IX86
		ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&Address,sizeof(Address));
#else
!!!
#endif
		ReadMem(Address,&Address,sizeof(Address));
#if defined _M_AMD64
		Size=State.Reg8;
#elif defined _M_IX86
		ReadMem(State.RegSp+3*sizeof(DWORD_PTR),&Size,sizeof(Size));
#else
!!!
#endif
		ReadMem(Size,&Size,sizeof(Size));
#if defined _M_AMD64
		Type=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&Type,sizeof(Type));
#else
!!!
#endif
		if(Type!=MEM_DECOMMIT && Type!=MEM_RELEASE)
		{
			ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
			EnableBreak(bVirtualFree);
#if defined _M_AMD64
			State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
			State.RegSp+=5*sizeof(DWORD_PTR);
#else
!!!
#endif
			State.RegAx=STATUS_INVALID_PARAMETER_4;
			return true;
		}

		nNumber=(int)((Address-PagesAllocked)/PAGE_SIZE);
		Size=AlignTo(Size+Address-CutTo(Address,PAGE_SIZE),PAGE_SIZE)/PAGE_SIZE;
		Address/=PAGE_SIZE;

		i=0;
		if(nNumber+(int)Size<PAGES_COUNT && nNumber>0 && (int)Size<PAGES_COUNT)
		{
			for(;;)
			{
				if(pPageDir[nNumber+i].Address==0)
					break;
				if(pPageDir[nNumber+i].Address>Address && Type==MEM_DECOMMIT)
					break;
				if(pPageDir[nNumber+i].Address!=Address && Type==MEM_RELEASE)
					break;
				if(Size!=0 && i==Size)
					break;
				++i;
			}
			if(i==0 || (Size!=0 && i!=Size))
			{
				ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
				EnableBreak(bVirtualFree);
#if defined _M_AMD64
				State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
				State.RegSp+=5*sizeof(DWORD_PTR);
#else
!!!
#endif
				if(i==0)
					State.RegAx=STATUS_MEMORY_NOT_ALLOCATED;
				else
					State.RegAx=STATUS_UNABLE_TO_FREE_VM;
				return true;
			}

			void *pZero=VirtualAlloc(NULL,PAGE_SIZE,MEM_COMMIT,PAGE_READONLY);
			i=0;
			DWORD dwOldProtect;
			for(;;)
			{
				if(pPageDir[nNumber+i].Address>Address && Type==MEM_DECOMMIT)
					break;
				if(pPageDir[nNumber+i].Address!=Address && Type==MEM_RELEASE)
					break;
				if(Size!=0 && i>=Size)
					break;

				if(Type==MEM_DECOMMIT)
				{
					pPageDir[nNumber+i].Committed=0;
					VirtualProtectEx(hVictim,(void*)(PagesAllocked+(nNumber+i)*PAGE_SIZE),PAGE_SIZE,PAGE_NOACCESS,&dwOldProtect);
				}
				if(Type==MEM_RELEASE)
				{
					pPageDir[nNumber+i].Address=0;
					pPageDir[nNumber+i].Reserved=0;
					pPageDir[nNumber+i].Committed=0;
					WriteMem(PagesAllocked+(nNumber+i)*PAGE_SIZE,pZero,PAGE_SIZE);
					VirtualProtectEx(hVictim,(void*)(PagesAllocked+(nNumber+i)*PAGE_SIZE),PAGE_SIZE,PAGE_NOACCESS,&dwOldProtect);
				}
				++i;
			}
			VirtualFree(pZero,0,MEM_RELEASE);
		}
		else
		{
			TraceAndReplace(bVirtualFree);
			return true;
		}
		Address*=PAGE_SIZE;
		Size*=PAGE_SIZE;
		if(PageLastUsed==Address+Size)
			PageLastUsed=Address;
#if defined _M_AMD64
		Temp=State.RegDx;
#elif defined _M_IX86
		ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&Temp,sizeof(Temp));
#else
!!!
#endif
		WriteMem(Temp,&Address,sizeof(Address));
#if defined _M_AMD64
		Temp=State.Reg8;
#elif defined _M_IX86
		ReadMem(State.RegSp+3*sizeof(DWORD_PTR),&Temp,sizeof(Temp));
#else
!!!
#endif
		WriteMem(Temp,&Size,sizeof(Size));

		ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
		EnableBreak(bVirtualFree);
#if defined _M_AMD64
		State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
		State.RegSp+=5*sizeof(DWORD_PTR);
#else
!!!
#endif
		State.RegAx=STATUS_SUCCESS;
		return true;
	}
#endif
	else if(BreakWhere==bVirtualProtect)
	{
		DWORD_PTR ProcessHandle;
#if defined _M_AMD64
		ProcessHandle=State.RegCx;
#elif defined _M_IX86
		ReadMem(State.RegSp+sizeof(DWORD_PTR),&ProcessHandle,sizeof(ProcessHandle));
#else
!!!
#endif
		if(!IsNeededProcess((HANDLE)ProcessHandle))
		{
			TraceAndReplace(bVirtualProtect);
			return true;
		}
		DWORD_PTR Address,Size,Protect,pOldProtect;
#if defined _M_AMD64
		Address=State.RegDx;
#elif defined _M_IX86
		ReadMem(State.RegSp+2*sizeof(DWORD_PTR),&Address,sizeof(Address));
#else
!!!
#endif
		ReadMem(Address,&Address,sizeof(Address));
#if defined _M_AMD64
		Size=State.Reg8;
#elif defined _M_IX86
		ReadMem(State.RegSp+3*sizeof(DWORD_PTR),&Size,sizeof(Size));
#else
!!!
#endif
		ReadMem(Size,&Size,sizeof(Size));
#if defined _M_AMD64
		Protect=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&Protect,sizeof(Protect));
#else
!!!
#endif

		ReadMem(State.RegSp+5*sizeof(DWORD_PTR),&pOldProtect,sizeof(pOldProtect));

		Size=AlignTo(Size+Address-CutTo(Address,PAGE_SIZE),PAGE_SIZE);
		Address=CutTo(Address,PAGE_SIZE);
		Size/=PAGE_SIZE;

		DWORD_PTR ProtectedAddress;
		ReadMem(State.RegSp,&ProtectedAddress,sizeof(ProtectedAddress));
		AddBreak(ProtectedAddress);EnableBreak(ProtectedAddress);
		SuspendAllOther();
		while(BreakWhere!=ProtectedAddress && BreakWhere!=bProcessTerminated && !IsThreadDying())
			Continue();
		ResumeAllOther();
		DeleteBreak(ProtectedAddress);

		EnableBreak(bVirtualProtect);
		if(State.RegAx!=STATUS_SUCCESS)
			return true;

		for(DWORD i=0;i!=Size;++i)
		{
			std::map<DWORD_PTR,BYTE>::iterator itMemBreaks(MemBreaks.find(Address+i*PAGE_SIZE));
			if(itMemBreaks!=MemBreaks.end())
			{
				DWORD dwOldProtect;
				if(i==0)
				{
					ReadMem(pOldProtect,&dwOldProtect,sizeof(dwOldProtect));
					dwOldProtect=(dwOldProtect & ~0xff) | itMemBreaks->second;
					WriteMem(pOldProtect,&dwOldProtect,sizeof(dwOldProtect));
				}
				VirtualProtectEx(hVictim,(void*)(Address+i*PAGE_SIZE),PAGE_SIZE,
					(Protect & ~0xff) | StripNXBit(Protect & 0xff),&dwOldProtect);
				itMemBreaks->second=Protect & 0xff;
			}
		}
		return true;
	}
	else if(BreakWhere==bOpenProcess)
	{
		DWORD_PTR ClientAddress;
#if defined _M_AMD64
		ClientAddress=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&ClientAddress,sizeof(ClientAddress));
#else
!!!
#endif
		DWORD dwPID;
		ReadMem(ClientAddress+offsetof(CLIENT_ID,ProcessId),&dwPID,sizeof(dwPID));
		if(dwPID==GetCurrentProcessId())
		{
			ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
#if defined _M_AMD64
			State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
			State.RegSp+=5*sizeof(DWORD_PTR);
#else
!!!
#endif
			State.RegAx=STATUS_INVALID_PARAMETER;
			EnableBreak(bOpenProcess);
		}
		else
			TraceAndReplace(bOpenProcess);
		return true;
	}
	else if(BreakWhere==bOpenThread)
	{
		DWORD_PTR ClientAddress;
#if defined _M_AMD64
		ClientAddress=State.Reg9;
#elif defined _M_IX86
		ReadMem(State.RegSp+4*sizeof(DWORD_PTR),&ClientAddress,sizeof(ClientAddress));
#else
!!!
#endif
		DWORD dwTID;
		ReadMem(ClientAddress+offsetof(CLIENT_ID,ThreadId),&dwTID,sizeof(dwTID));
		if(GetPIDByTID(dwTID)==GetCurrentProcessId())
		{
			ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
#if defined _M_AMD64
			State.RegSp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
			State.RegSp+=5*sizeof(DWORD_PTR);
#else
!!!
#endif
			State.RegAx=STATUS_INVALID_PARAMETER;
			EnableBreak(bOpenThread);
		}
		else
			TraceAndReplace(bOpenThread);
		return true;
	}
	else if(BreakWhere==bGetTickCount)
	{
		if((pInitData->dwTimeDelta & MAXLONG)!=0 && (pInitData->dwTimeDelta & MINLONG)==0)
		{
			ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
			State.RegSp+=sizeof(DWORD_PTR);
			DWORD_PTR ResultAX;
			ResultAX=TickCountAX+rand()%(MAXBYTE+1)+pInitData->dwTimeDelta & MAXLONG;
			if(ResultAX<TickCountAX)
				++TickCountDX;
			TickCountAX=ResultAX;
			State.RegAx=TickCountAX;
			State.RegDx=TickCountDX;
			EnableBreak(bGetTickCount);
		}
		else
			TraceAndReplace(bGetTickCount);
		return true;
	}
	else if(BreakWhere==bGetTickCount64)
	{
		if((pInitData->dwTimeDelta & MAXLONG)!=0 && (pInitData->dwTimeDelta & MINLONG)==0)
		{
			ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
			State.RegSp+=sizeof(DWORD_PTR);
			DWORD_PTR ResultAX;
			ResultAX=TickCountAX+rand()%(MAXBYTE+1)+pInitData->dwTimeDelta & MAXLONG;
			if(ResultAX<TickCountAX)
				++TickCountDX;
			TickCountAX=ResultAX;
			State.RegAx=TickCountAX;
			State.RegDx=TickCountDX;
			EnableBreak(bGetTickCount64);
		}
		else
			TraceAndReplace(bGetTickCount64);
		return true;
	}
	return false;
}

void CMain::ProcessRelocation()
{
	if(!pInitData->fRelocs)
		return;
	if(pInitData->UnpackMode==umSkipOEP)
	{
		Detach();
		CloseHandle(hVictim);
		hVictim=NULL;
		Modules.hVictim=NULL;
		FirstVictimBase=VictimBase;
		Modules.Clear();
		PreLoadDLL();
	}

	if(UnpackedFile.IsEmpty() || VirginVictim.IsEmpty())
		return;

	WriteLog(relocations);

#if defined _M_AMD64
	DWORD dwType=IMAGE_REL_BASED_DIR64;
#elif defined _M_IX86
	DWORD dwType=IMAGE_REL_BASED_HIGHLOW;
#else
!!!
#endif
	DWORD dwEnd=pInitData->dwCutModule!=0 ? pInitData->dwCutModule :
		UnpackedFile.pPEHeader->OptionalHeader.SizeOfImage;
	for(int i=0;i!=UnpackedFile.pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(dwEnd<=UnpackedFile.pSectionHeader[i].VirtualAddress)
			break;
		for(int j=0;j<(int)(UnpackedFile.pSectionHeader[i].SizeOfRawData-(sizeof(DWORD_PTR)-1));++j)
		{
			DWORD dwRVA=UnpackedFile.pSectionHeader[i].VirtualAddress+j;
			if(UnpackedFile.RVA(dwRVA)==NULL || VirginVictim.RVA(dwRVA)==NULL)
				continue;
			if(*(DWORD_PTR*)UnpackedFile.RVA(dwRVA)-*(DWORD_PTR*)VirginVictim.RVA(dwRVA)==UnpackedFile.pPEHeader->OptionalHeader.ImageBase-VirginVictim.pPEHeader->OptionalHeader.ImageBase &&
				*(DWORD_PTR*)UnpackedFile.RVA(dwRVA)>=UnpackedFile.pPEHeader->OptionalHeader.ImageBase &&
				*(DWORD_PTR*)UnpackedFile.RVA(dwRVA)<UnpackedFile.pPEHeader->OptionalHeader.ImageBase+dwEnd)
			{
				FixUp.AddItem(dwRVA,dwType);
				j+=sizeof(DWORD_PTR)-1;
			}
		}
	}
}

bool CMain::IsAddressInModule(DWORD_PTR Address)
{
	DWORD_PTR EndOfModule=pInitData->dwModuleEnd!=0 ? pInitData->dwModuleEnd :
		UnpackedFile.pPEHeader->OptionalHeader.SizeOfImage;
	if(pInitData->dwCutModule!=0 && EndOfModule>pInitData->dwCutModule)
		EndOfModule=pInitData->dwCutModule;
	return Address>VictimBase && (Address-VictimBase)<EndOfModule;
}

BYTE setseh1[]={0xff,0x15,0xf2,0xff,0xff,0xff,			//call [SetUnhandledExceptionFilter]
				0x90};									//nop
#if defined _M_AMD64
BYTE setseh2[]={0x48,0x31,0xc0,							//xor rax,rax
				0x48,0xff,0xc8,							//dec rax		EXCEPTION_CONTINUE_EXECUTION
				0xc3,									//ret
				0x90,0x90,0x90,							//nop
				0x90,0x90,0x90,							//nop
				0x90,0x90,0x90,							//nop
				0x90};									//nop
#elif defined _M_IX86
BYTE setseh2[]={0x33,0xc0,								//xor eax,eax
				0x48,									//dec eax		EXCEPTION_CONTINUE_EXECUTION
				0xc2,0x04,0,							//ret 4
				0x90,0x90,0x90,							//nop
				0x90,0x90,0x90,							//nop
				0x90,0x90,0x90,							//nop
				0x90,0x90};								//nop
#else
!!!
#endif
DWORD_PTR CMain::SetLastSEH()
{
	void *pAllocked;
	DWORD_PTR bBr0,Temp;

	pAllocked=VirtualAllocEx(hVictim,NULL,sizeof(DWORD_PTR)+sizeof(setseh1)+sizeof(setseh2),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(pAllocked==NULL)
		return MAX_NUM;
#if defined _M_IX86
	*(DWORD*)(setseh1+2)=(DWORD)pAllocked;
#endif
	Temp=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"SetUnhandledExceptionFilter");
	WriteMem((DWORD_PTR)pAllocked,&Temp,sizeof(Temp));
	if(WriteMem((DWORD_PTR)pAllocked+sizeof(DWORD_PTR),&setseh1,sizeof(setseh1))!=sizeof(setseh1))
		return MAX_NUM;
	if(WriteMem((DWORD_PTR)pAllocked+sizeof(DWORD_PTR)+sizeof(setseh1),&setseh2,sizeof(setseh2))!=sizeof(setseh2))
		return MAX_NUM;
	Temp=(DWORD_PTR)pAllocked+sizeof(DWORD_PTR)+sizeof(setseh1);
#if defined _M_AMD64
	State.RegCx=Temp;
#elif defined _M_IX86
	State.RegSp-=sizeof(DWORD_PTR);
	WriteMem(State.RegSp,&Temp,sizeof(Temp));
#else
!!!
#endif
	Temp=State.RegIp;
	bBr0=(DWORD_PTR)pAllocked+sizeof(DWORD_PTR)+sizeof(setseh1);
	State.RegIp=(DWORD_PTR)pAllocked+sizeof(DWORD_PTR);
	AddBreak(bBr0);EnableBreak(bBr0);
	do Continue();
	while(BreakWhere!=bBr0 && BreakWhere!=bProcessTerminated);
	DeleteBreak(bBr0);
	State.RegIp=Temp;
	State.RegSp-=STACK_SHIFT*sizeof(DWORD_PTR);
	return (DWORD_PTR)pAllocked+sizeof(DWORD_PTR)+sizeof(setseh1);
}

void CMain::RemoveLastSEH(DWORD_PTR SehAddr)
{
	DWORD_PTR bBr0,Temp=0;

	State.RegSp+=STACK_SHIFT*sizeof(DWORD_PTR);
#if defined _M_AMD64
	State.RegCx=Temp;
#elif defined _M_IX86
	State.RegSp-=sizeof(DWORD_PTR);
	WriteMem(State.RegSp,&Temp,sizeof(Temp));
#else
!!!
#endif
	Temp=State.RegIp;
	bBr0=SehAddr;
	State.RegIp=SehAddr-sizeof(setseh1);
	AddBreak(bBr0);EnableBreak(bBr0);
	do Continue();
	while(BreakWhere!=bBr0 && BreakWhere!=bProcessTerminated);
	DeleteBreak(bBr0);
	State.RegIp=Temp;
	VirtualFreeEx(hVictim,(void*)(SehAddr-sizeof(DWORD_PTR)-sizeof(setseh1)),0,MEM_RELEASE);
}

void CMain::ProcessImportOnlyLibs()
{
	CImportRecord ImportRecord;

	WriteLog(processinglibs);
	for(DWORD i=0;i!=Modules.Modules.size();++i)
	{
		if(Modules.Modules[i]->Exports.empty())
			continue;
		ImportRecord.Clear();
		ImportRecord.sLibName=Modules.Modules[i]->sImportName;
		ImportRecord.sApiName=Modules.Modules[i]->Exports[0].sFuncName;
		ImportRecord.wOrdinal=Modules.Modules[i]->Exports[0].wFuncOrdinal;
		ImportRecord.dwRecordRVA=UnpackedFile.dwSectionsBegin+UnpackedFile.dwSectionsSize+i*sizeof(DWORD_PTR);
		ImportRecord.Type=itNone;
		Import.AddRecord(ImportRecord);
	}
}

void CMain::ProcessImport()
{
	WriteLog(processingsmart);

	DWORD_PTR redir1,redir2;
	DWORD dwRVA;
	WORD wPrev;
	CImportRecord ImportRecord;
	for(int i=0;i!=UnpackedFile.pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(pInitData->dwCutModule!=0 && pInitData->dwCutModule<=UnpackedFile.pSectionHeader[i].VirtualAddress)
			break;
		for(int j=2;j<(int)(UnpackedFile.pSectionHeader[i].SizeOfRawData-(sizeof(DWORD)-1));++j)
		{
			dwRVA=UnpackedFile.pSectionHeader[i].VirtualAddress+j;

			ImportRecord.Clear();
			redir2=0;
			if(UnpackedFile.RVA(dwRVA-2)!=NULL)
				wPrev=*(WORD*)UnpackedFile.RVA(dwRVA-2);
			else
				continue;
			if(UnpackedFile.RVA(dwRVA)!=NULL)
				redir1=*(DWORD*)UnpackedFile.RVA(dwRVA);
			else
				continue;

			if(wPrev==0x15ff || wPrev==0x25ff)
			{
#if defined _M_AMD64
				redir1=dwRVA+sizeof(DWORD)+VictimBase+(LONG)redir1;
#endif
				if(ReadMem(redir1,&redir2,sizeof(redir2))==0)
					redir2=0;
				IdentifyFunction(ImportRecord,redir2);
				if(ImportRecord.Exist() || (pMain->pInitData->fSuspectFunc && redir2!=0))
				{
					ImportRecord.dwReferenceRVA=dwRVA;
					ImportRecord.dwRecordRVA=(DWORD)(redir1-VictimBase);
					if(wPrev==0x15ff)
						ImportRecord.Type=itIndirectCall;
					else
						ImportRecord.Type=itIndirectJmp;
					Import.AddRecord(ImportRecord);
					j+=sizeof(DWORD)-1;
				}
			}
			else if(wPrev==0x35ff ||
				(((wPrev>>8)==0x0d || (wPrev>>8)==0x1d || (wPrev>>8)==0x2d || (wPrev>>8)==0x3d ||
				(wPrev>>8)==0x05 || (wPrev>>8)==0x15 || (wPrev>>8)==0x25 || (wPrev>>8)==0x35) &&
				((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40)))
			{
#if defined _M_AMD64
				redir1=dwRVA+sizeof(DWORD)+VictimBase+(LONG)redir1;
#endif
				if(ReadMem(redir1,&redir2,sizeof(redir2))==0)
					redir2=0;
				IdentifyFunction(ImportRecord,redir2);
				if(ImportRecord.Exist() || (pMain->pInitData->fSuspectFunc && redir2!=0))
				{
					ImportRecord.dwReferenceRVA=dwRVA;
					ImportRecord.dwRecordRVA=(DWORD)(redir1-VictimBase);
					ImportRecord.Type=itIndirectOther;
					Import.AddRecord(ImportRecord);
					j+=sizeof(DWORD)-1;
				}
			}
			else if((wPrev>>8)==0xa1)
			{
				redir1=*(DWORD_PTR*)UnpackedFile.RVA(dwRVA);
				if(ReadMem(redir1,&redir2,sizeof(redir2))==0)
					redir2=0;
				IdentifyFunction(ImportRecord,redir2);
				if(ImportRecord.Exist() || (pMain->pInitData->fSuspectFunc && redir2!=0))
				{
					ImportRecord.dwReferenceRVA=dwRVA;
					ImportRecord.dwRecordRVA=(DWORD)(redir1-VictimBase);
					ImportRecord.Type=itIndirectAx;
					Import.AddRecord(ImportRecord);
					j+=sizeof(DWORD)-1;
				}
			}
			else if(pInitData->fDirectRefs && ((wPrev>>8)==0xe8 || (wPrev>>8)==0xe9))
			{
				redir1=dwRVA+VictimBase;
				redir2=redir1+sizeof(DWORD)+*(LONG*)UnpackedFile.RVA(dwRVA);
#if defined _M_AMD64
				if(!IsAddressInModule(redir2))
				{
					DWORD redir3;
					if(ReadMem(redir2+2,&redir3,sizeof(redir3))==0)
						redir2=0;
					redir2+=2+sizeof(DWORD)+(LONG)redir3;
					if(ReadMem(redir2,&redir2,sizeof(redir2))==0)
						redir2=0;
				}
#endif
				IdentifyFunction(ImportRecord,redir2);
				if(ImportRecord.Exist())
				{
					if(!pInitData->fLeaveDirectRefs)
					{
//						if(NextInstr(redir1+sizeof(DWORD))!=(redir1+sizeof(DWORD)+1) && NextInstr(redir1-2)==(redir1-1))
//							--redir1;
						if(ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
							--redir1;
						else if(ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
							--redir1;
#if defined _M_AMD64
						else if(ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & 0xf8)==0x50))
							--redir1;
#endif
					}
					ImportRecord.dwReferenceRVA=(DWORD)(redir1-VictimBase+1);
					if((wPrev>>8)==0xe8)
						ImportRecord.Type=itDirectCall;
					else
						ImportRecord.Type=itDirectJmp;
					Import.AddRecord(ImportRecord);
					j+=sizeof(DWORD)-1;
				}
			}
#if defined _M_IX86
			else if(pInitData->fDirectRefs && (((wPrev>>8) & 0xf8)==0xb8 || (wPrev>>8)==0x68))
			{
				redir1=dwRVA+VictimBase;
				if(ReadMem(redir1,&redir2,sizeof(DWORD))==0)
					redir2=0;
				IdentifyFunction(ImportRecord,redir2);
				if(ImportRecord.Exist())
				{
					if(!pInitData->fLeaveDirectRefs)
					{
//						if(NextInstr(redir1+sizeof(DWORD))!=(redir1+sizeof(DWORD)+1) && NextInstr(redir1-2)==(redir1-1))
//							--redir1;
						if(ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
							--redir1;
						else if(ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
							--redir1;
#if defined _M_AMD64
						else if(ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & 0xf8)==0x50))
							--redir1;
#endif
					}
					ImportRecord.dwReferenceRVA=(DWORD)(redir1-VictimBase+1);
					ImportRecord.Type=itDirectOther;
					Import.AddRecord(ImportRecord);
					j+=sizeof(DWORD)-1;
				}
			}
#endif
		}
	}
}

void CMain::ProcessImportWTrace()
{
	WriteLog(processingtracer);
	DWORD_PTR garb1,garb2,redir1,redir2;
	EImportRecordType k;

	bLastSEH=SetLastSEH();
	bOEP=bLastSEH+sizeof(setseh2)-1;
	AddBreak(bOEP);
	AddBreak(bLastSEH);

	CImportRecord ImportRecord;
	for(int i=0;i!=UnpackedFile.pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(pInitData->dwCutModule!=0 && pInitData->dwCutModule<=UnpackedFile.pSectionHeader[i].VirtualAddress)
			break;
		for(int j=2;j<(int)(UnpackedFile.pSectionHeader[i].SizeOfRawData-(sizeof(DWORD)-1));++j)
		{
			WORD wPrev,wCaller;
			DWORD dwRVA=UnpackedFile.pSectionHeader[i].VirtualAddress+j;

			if(BreakWhere==bProcessTerminated)
			{
				WriteEx(badtracing+IntToStr(dwRVA,16,sizeof(dwRVA)*2),TRUE,TRUE,RGB(255,0,0));
				return;
			}

			if(UnpackedFile.RVA(dwRVA-2)!=NULL)
				wPrev=*(WORD*)UnpackedFile.RVA(dwRVA-2);
			else
				continue;
			if(UnpackedFile.RVA(dwRVA)!=NULL)
				redir1=*(DWORD*)UnpackedFile.RVA(dwRVA);
			else
				continue;
			if(wPrev==0x15ff || wPrev==0x25ff || wPrev==0x35ff)
			{
				garb1=State.RegSp;
				garb2=State.RegIp;
#if defined _M_AMD64
				redir1=dwRVA+sizeof(DWORD)+VictimBase+(LONG)redir1;
#endif
				if(wPrev==0x15ff)
					k=itIndirectCall;
				else if(wPrev==0x25ff)
					k=itIndirectJmp;
				else
					k=itIndirectOther;
				if(pInitData->UnpackMode==umSkipOEP)
					j+=FindTraceSkipOEP(dwRVA,redir1,k);
				else
					j+=FindTrace(dwRVA,redir1,k);
				State.RegSp=garb1;
				State.RegIp=garb2;
				continue;
			}
#if defined _M_IX86
			if((wPrev>>8)==0x68 && pInitData->fDirectRefs)
			{
				garb1=State.RegSp;
				garb2=State.RegIp;
				if(pInitData->UnpackMode==umSkipOEP)
					j+=FindTraceSkipOEP(dwRVA,dwRVA,itDirectOther);
				else
					j+=FindTrace(dwRVA,dwRVA,itDirectOther);
				State.RegSp=garb1;
				State.RegIp=garb2;
				continue;
			}
#endif
			if(pInitData->fDirectRefs && ((wPrev>>8)==0xe8 || (wPrev>>8)==0xe9))
			{
				garb1=State.RegSp;
				garb2=State.RegIp;
				if((wPrev>>8)==0xe8)
					k=itDirectCall;
				else
					k=itDirectJmp;
				if(pInitData->UnpackMode==umSkipOEP)
					j+=FindTraceSkipOEP(dwRVA,dwRVA,k);
				else
					j+=FindTrace(dwRVA,dwRVA,k);
				State.RegSp=garb1;
				State.RegIp=garb2;
				continue;
			}

			if((wPrev>>8)==0xa1)
			{
				redir1=*(DWORD_PTR*)UnpackedFile.RVA(dwRVA);
				wCaller=0xd0ff;
				k=itIndirectAx;
			}
			else if((wPrev>>8)==0x0d && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd1ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x1d && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd3ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x2d && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd5ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x3d && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd7ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x05 && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd0ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x15 && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd2ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x25 && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd4ff;
				k=itIndirectOther;
			}
			else if((wPrev>>8)==0x35 && ((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40))
			{
				wCaller=0xd6ff;
				k=itIndirectOther;
			}
#if defined _M_IX86
			else if((wPrev>>8)==0xb9 && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd1ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xbb && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd3ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xbd && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd5ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xbf && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd7ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xb8 && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd0ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xba && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd2ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xbc && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd4ff;
				k=itDirectOther;
			}
			else if((wPrev>>8)==0xbe && pInitData->fDirectRefs)
			{
				redir1=dwRVA;
				wCaller=0xd6ff;
				k=itDirectOther;
			}
#endif
			else
				continue;

#if defined _M_AMD64
			if((wPrev>>8)!=0xa1)
				redir1=dwRVA+sizeof(DWORD)+VictimBase+(LONG)redir1;
#endif
			ImportRecord.Clear();
			if(ReadMem(redir1,&redir2,sizeof(redir2))==0)
				redir2=0;
			IdentifyFunction(ImportRecord,redir2);
			if(ImportRecord.Exist())
			{
				ImportRecord.dwReferenceRVA=dwRVA;
				ImportRecord.Type=k;
				if(k==itIndirectOther || k==itIndirectAx)
					ImportRecord.dwRecordRVA=(DWORD)(redir1-VictimBase);
				Import.AddRecord(ImportRecord);
				j+=sizeof(DWORD)-1;
				continue;
			}

			for(int l=sizeof(DWORD);l!=MAX_DEST;++l)
			{
				if(UnpackedFile.RVA(dwRVA+l)!=NULL)
					wPrev=*(WORD*)UnpackedFile.RVA(dwRVA+l);
				else
					break;
				if(wPrev==wCaller || pInitData->fSuspectFunc)
				{
					garb1=State.RegSp;
					garb2=State.RegIp;
					if(pInitData->UnpackMode==umSkipOEP)
						j+=FindTraceSkipOEP(dwRVA,redir1,k);
					else
						j+=FindTrace(dwRVA,redir1,k);
					State.RegSp=garb1;
					State.RegIp=garb2;
					break;
				}
			}
		}
	}
	DeleteBreak(bOEP);
	DeleteBreak(bLastSEH);
	RemoveLastSEH(bLastSEH);
}

const int fakefuncs=100;

int CMain::FindTrace(DWORD dwRefRVA,DWORD_PTR RecordAddr,EImportRecordType Type)
{
	DWORD_PTR Addresses[fakefuncs],bRet1=0,bRet2=0,Axs[fakefuncs],Cxs[fakefuncs],Dxs[fakefuncs],SehTriggered=0,Random,redir2=0;
	int nNumber=0;

	if(Type==itIndirectJmp || Type==itIndirectCall || Type==itIndirectOther || Type==itIndirectAx)
	{
		if(ReadMem(RecordAddr,&redir2,sizeof(redir2))==0)
			return 0;
	}
	else
	{
		RecordAddr+=VictimBase;
		if(ReadMem(RecordAddr,&redir2,sizeof(DWORD))==0)
			return 0;
		if(Type==itDirectJmp || Type==itDirectCall)
			redir2=RecordAddr+sizeof(DWORD)+(LONG)redir2;
	}
	if(IsAddressInModule(redir2))
		return 0;

	CImportRecord ir;
	IdentifyFunction(ir,redir2);
	if(ir.Exist())
	{
		if(Type==itIndirectJmp || Type==itIndirectCall || Type==itIndirectOther || Type==itIndirectAx)
		{
			ir.dwReferenceRVA=dwRefRVA;
			ir.dwRecordRVA=(DWORD)(RecordAddr-VictimBase);
			ir.Type=Type;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
		else
		{
			if(!pInitData->fLeaveDirectRefs)
			{
//				if(NextInstr(RecordAddr+sizeof(DWORD))!=(RecordAddr+sizeof(DWORD)+1) && NextInstr(RecordAddr-2)==(RecordAddr-1))
//					--RecordAddr;
				if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
					--RecordAddr;
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
					--RecordAddr;
#if defined _M_AMD64
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & 0xf8)==0x50))
					--RecordAddr;
#endif
			}
			ir.dwReferenceRVA=(DWORD)(RecordAddr-VictimBase+1);
			ir.Type=Type;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
	}

	for(size_t i=0;i!=Modules.Modules.size();++i)
	{
		if((redir2<Modules.Modules[i]->ModuleBase+Modules.Modules[i]->dwModuleSize && redir2>=Modules.Modules[i]->ModuleBase) ||
			(redir2<Modules.Modules[i]->HookBase+Modules.Modules[i]->dwHookSize && redir2>=Modules.Modules[i]->HookBase))
			return 0;
	}

	MEMORY_BASIC_INFORMATION MemInfo;
	if(VirtualQueryEx(hVictim,(void*)redir2,&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo) ||
		MemInfo.State!=MEM_COMMIT || (MemInfo.Protect & 0xff)==PAGE_NOACCESS)
		return 0;

	for(DWORD i=STACK_SHIFT;i!=0;--i)
	{
		State.RegSp-=sizeof(DWORD_PTR);
		if(WriteMem(State.RegSp,&bOEP,sizeof(bOEP))==0)
			return 0;
	}
	DisableBreak(bOEP); EnableBreak(bOEP);
	DisableBreak(bLastSEH); EnableBreak(bLastSEH);
	if(Type==itIndirectOther || Type==itIndirectAx || Type==itDirectOther)
		State.RegIp=redir2;
	else
	{
		if(Type==itIndirectJmp || Type==itIndirectCall)
			State.RegIp=VictimBase+dwRefRVA-2;
		else
			State.RegIp=VictimBase+dwRefRVA-1;
		bRet1=State.RegIp+5;
		AddBreak(bRet1,btDr2);EnableBreak(bRet1);
		bRet2=bRet1+1;
		AddBreak(bRet2,btDr3);EnableBreak(bRet2);
	}

	DATA_STATE TmpState;
	TmpState=State;
	TmpState.RegSp-=sizeof(DWORD_PTR);
	Random=rand();

	Continue();

	redir2=0;
	for(;;)
	{
		if(BreakWhere==bOEP || BreakWhere==bDr2 || BreakWhere==bDr3)
			break;
		if(BreakWhere==bProcessTerminated)
		{
			DeleteBreak(bRet1); DeleteBreak(bRet2);
			return 0;
		}
		if(BreakWhere==bLastSEH)
		{
#if defined _M_AMD64
			SehTriggered=State.RegCx;
			ReadMem(SehTriggered+offsetof(EXCEPTION_POINTERS,ContextRecord),&SehTriggered,sizeof(SehTriggered));
			WriteMem(SehTriggered+offsetof(CONTEXT,Rip),&bOEP,sizeof(bOEP));
#elif defined _M_IX86
			ReadMem(State.RegSp+sizeof(DWORD_PTR),&SehTriggered,sizeof(SehTriggered));
			ReadMem(SehTriggered+offsetof(EXCEPTION_POINTERS,ContextRecord),&SehTriggered,sizeof(SehTriggered));
			WriteMem(SehTriggered+offsetof(CONTEXT,Eip),&bOEP,sizeof(bOEP));
#else
!!!
#endif
			SehTriggered=1;
		}
		if(BreakWhere==bFunction && (pInitData->fSuspectFunc ||
			(State.RegAx==TmpState.RegAx && State.RegCx==TmpState.RegCx && State.RegDx==TmpState.RegDx) ||
			 State.RegSp==TmpState.RegSp))
		{
			if(ReadMem(State.RegSp,&Addresses[nNumber],sizeof(Addresses[0]))==0)
			{
				DeleteBreak(bRet1); DeleteBreak(bRet2);
				return 0;
			}
			if(!pInitData->fExecuteFunc)
			{
				State.RegAx=Random*nNumber;
				State.RegCx=Random*nNumber;
				State.RegDx=Random*nNumber;
				if(ReadMem(State.RegSp+sizeof(DWORD_PTR),&State.RegIp,sizeof(State.RegIp))==0)
				{
					DeleteBreak(bRet1); DeleteBreak(bRet2);
					return 0;
				}
				State.RegSp+=2*sizeof(DWORD_PTR);
			}
			else
			{
				if(ReadMem(State.RegSp+sizeof(DWORD_PTR),&redir2,sizeof(redir2))==0)
				{
					DeleteBreak(bRet1); DeleteBreak(bRet2);
					return 0;
				}
				AddBreak(redir2);EnableBreak(redir2);
				while(BreakWhere!=redir2 && BreakWhere!=bProcessTerminated)
					Continue();
				DeleteBreak(redir2);
			}
			Axs[nNumber]=State.RegAx;
			Cxs[nNumber]=State.RegCx;
			Dxs[nNumber]=State.RegDx;
			++nNumber;
			if(nNumber==fakefuncs)
			{
				DeleteBreak(bRet1); DeleteBreak(bRet2);
				Terminate();
				MessageBox(NULL,_T("Too many fake functions called!"),_T("QuickUnpack"),MB_OK);
				return 0;
			}
		}
		DisableBreak(bOEP); EnableBreak(bOEP);
		DisableBreak(bRet1); EnableBreak(bRet1);
		DisableBreak(bRet2); EnableBreak(bRet2);
		Continue();
	}
	DeleteBreak(bRet1); DeleteBreak(bRet2);
	if(pInitData->fSuspectFunc)
		redir2=Addresses[nNumber-1];
	else
		redir2=0;
	for(int i=0;i!=nNumber;++i)
	{
		if(State.RegAx==Axs[i] && State.RegCx==Cxs[i] && State.RegDx==Dxs[i])
			redir2=Addresses[i];
	}
	IdentifyFunction(ir,redir2);
	if((ir.Exist() && SehTriggered==0) || pInitData->fSuspectFunc)
	{
		if(Type==itIndirectJmp || Type==itIndirectCall || Type==itIndirectOther || Type==itIndirectAx)
		{
			ir.dwReferenceRVA=dwRefRVA;
			ir.dwRecordRVA=(DWORD)(RecordAddr-VictimBase);
			if(Type==itIndirectOther)
				ir.Type=itIndirectOther;
			else if(Type==itIndirectAx)
				ir.Type=itIndirectAx;
			else if(BreakWhere==bDr2 || BreakWhere==bDr3)
				ir.Type=itIndirectCall;
			else
				ir.Type=itIndirectJmp;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
		else
		{
			if(!pInitData->fLeaveDirectRefs)
			{
//				if(NextInstr(RecordAddr+sizeof(DWORD))!=(RecordAddr+sizeof(DWORD)+1) && NextInstr(RecordAddr-2)==(RecordAddr-1))
//					--RecordAddr;
				if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
					--RecordAddr;
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
					--RecordAddr;
#if defined _M_AMD64
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & 0xf8)==0x50))
					--RecordAddr;
#endif
			}
			ir.dwReferenceRVA=(DWORD)(RecordAddr-VictimBase+1);
			if(Type==itDirectOther)
				ir.Type=itDirectOther;
			else if(BreakWhere==bDr2 || BreakWhere==bDr3)
				ir.Type=itDirectCall;
			else
				ir.Type=itDirectJmp;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
	}
	return 0;
}

int CMain::FindTraceSkipOEP(DWORD dwRefRVA,DWORD_PTR RecordAddr,EImportRecordType Type)
{
	DWORD_PTR Addresses[fakefuncs],bRet1=0,bRet2=0,Axs[fakefuncs],Cxs[fakefuncs],Dxs[fakefuncs],SehTriggered=0,Random,redir2=0;
	int nNumber=0;

	if(Type==itIndirectJmp || Type==itIndirectCall || Type==itIndirectOther || Type==itIndirectAx)
	{
		if(ReadMem(RecordAddr,&redir2,sizeof(redir2))==0)
			return 0;
	}
	else
	{
		RecordAddr+=VictimBase;
		if(ReadMem(RecordAddr,&redir2,sizeof(DWORD))==0)
			return 0;
		if(Type==itDirectJmp || Type==itDirectCall)
			redir2=RecordAddr+sizeof(DWORD)+(LONG)redir2;
	}
	if(IsAddressInModule(redir2))
		return 0;

	CImportRecord ir;
	IdentifyFunction(ir,redir2);
	if(ir.Exist())
	{
		if(Type==itIndirectJmp || Type==itIndirectCall || Type==itIndirectOther || Type==itIndirectAx)
		{
			ir.dwReferenceRVA=dwRefRVA;
			ir.dwRecordRVA=(DWORD)(RecordAddr-VictimBase);
			ir.Type=Type;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
		else
		{
			if(!pInitData->fLeaveDirectRefs)
			{
//				if(NextInstr(RecordAddr+sizeof(DWORD))!=(RecordAddr+sizeof(DWORD)+1) && NextInstr(RecordAddr-2)==(RecordAddr-1))
//					--RecordAddr;
				if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
					--RecordAddr;
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
					--RecordAddr;
#if defined _M_AMD64
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & 0xf8)==0x50))
					--RecordAddr;
#endif
			}
			ir.dwReferenceRVA=(DWORD)(RecordAddr-VictimBase+1);
			ir.Type=Type;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
	}

	for(size_t i=0;i!=Modules.Modules.size();++i)
	{
		if((redir2<Modules.Modules[i]->ModuleBase+Modules.Modules[i]->dwModuleSize && redir2>=Modules.Modules[i]->ModuleBase) ||
			(redir2<Modules.Modules[i]->HookBase+Modules.Modules[i]->dwHookSize && redir2>=Modules.Modules[i]->HookBase))
			return 0;
	}

	MEMORY_BASIC_INFORMATION MemInfo;
	if(VirtualQueryEx(hVictim,(void*)redir2,&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo) ||
		MemInfo.State!=MEM_COMMIT || (MemInfo.Protect & 0xff)==PAGE_NOACCESS)
		return 0;

	for(DWORD i=STACK_SHIFT;i!=0;--i)
	{
		State.RegSp-=sizeof(DWORD_PTR);
		if(WriteMem(State.RegSp,&bOEP,sizeof(bOEP))==0)
			return 0;
	}
	DisableBreak(bOEP); EnableBreak(bOEP);
	DisableBreak(bLastSEH); EnableBreak(bLastSEH);
	if(Type==itIndirectOther || Type==itIndirectAx || Type==itDirectOther)
		State.RegIp=redir2;
	else
	{
		if(Type==itIndirectJmp || Type==itIndirectCall)
			State.RegIp=VictimBase+dwRefRVA-2;
		else
			State.RegIp=VictimBase+dwRefRVA-1;
		bRet1=State.RegIp+5;
		AddBreak(bRet1,btDr2);EnableBreak(bRet1);
		bRet2=bRet1+1;
		AddBreak(bRet2,btDr3);EnableBreak(bRet2);
	}

	DATA_STATE TmpState;
	TmpState=State;
	TmpState.RegSp-=sizeof(DWORD_PTR);
	Random=rand();

	redir2=0;
	for(;;)
	{
		IdentifyFunction(ir,State.RegIp);
		if(ir.Exist() && (pInitData->fSuspectFunc ||
			(State.RegAx==TmpState.RegAx && State.RegCx==TmpState.RegCx && State.RegDx==TmpState.RegDx) ||
			 State.RegSp==TmpState.RegSp))
		{
			Addresses[nNumber]=State.RegIp;
			if(!pInitData->fExecuteFunc)
			{
				State.RegAx=Random*nNumber;
				State.RegCx=Random*nNumber;
				State.RegDx=Random*nNumber;
				ReadMem(State.RegSp,&State.RegIp,sizeof(State.RegIp));
				State.RegSp+=sizeof(DWORD_PTR);
			}
			else
			{
				if(ReadMem(State.RegSp,&redir2,sizeof(redir2))==0)
				{
					DeleteBreak(bRet1); DeleteBreak(bRet2);
					return 0;
				}
				AddBreak(redir2);EnableBreak(redir2);
				while(BreakWhere!=redir2 && BreakWhere!=bProcessTerminated)
					Continue();
				DeleteBreak(redir2);
			}
			Axs[nNumber]=State.RegAx;
			Cxs[nNumber]=State.RegCx;
			Dxs[nNumber]=State.RegDx;
			++nNumber;
			if(nNumber==fakefuncs)
			{
				DeleteBreak(bRet1); DeleteBreak(bRet2);
				Terminate();
				MessageBox(NULL,_T("Too many fake functions called!"),_T("QuickUnpack"),MB_OK);
				return 0;
			}
		}
		if(State.RegIp==bOEP || State.RegIp==bRet1 || State.RegIp==bRet2)
			break;
		if(IsThreadDying() || BreakWhere==bProcessTerminated)
		{
			DeleteBreak(bRet1); DeleteBreak(bRet2);
			return 0;
		}
		if(State.RegIp==bLastSEH)
		{
#if defined _M_AMD64
			SehTriggered=State.RegCx;
			ReadMem(SehTriggered+offsetof(EXCEPTION_POINTERS,ContextRecord),&SehTriggered,sizeof(SehTriggered));
			WriteMem(SehTriggered+offsetof(CONTEXT,Rip),&bOEP,sizeof(bOEP));
#elif defined _M_IX86
			ReadMem(State.RegSp+sizeof(DWORD_PTR),&SehTriggered,sizeof(SehTriggered));
			ReadMem(SehTriggered+offsetof(EXCEPTION_POINTERS,ContextRecord),&SehTriggered,sizeof(SehTriggered));
			WriteMem(SehTriggered+offsetof(CONTEXT,Eip),&bOEP,sizeof(bOEP));
#else
!!!
#endif
			SehTriggered=1;
		}
		DisableBreak(bOEP); EnableBreak(bOEP);
		DisableBreak(bRet1); EnableBreak(bRet1);
		DisableBreak(bRet2); EnableBreak(bRet2);
		Trace();
	}
	DeleteBreak(bRet1); DeleteBreak(bRet2);
	if(pInitData->fSuspectFunc)
		redir2=Addresses[nNumber-1];
	else
		redir2=0;
	for(int i=0;i!=nNumber;++i)
	{
		if(State.RegAx==Axs[i] && State.RegCx==Cxs[i] && State.RegDx==Dxs[i])
			redir2=Addresses[i];
	}
	IdentifyFunction(ir,redir2);
	if((ir.Exist() && SehTriggered==0) || pInitData->fSuspectFunc)
	{
		if(Type==itIndirectJmp || Type==itIndirectCall || Type==itIndirectOther || Type==itIndirectAx)
		{
			ir.dwReferenceRVA=dwRefRVA;
			ir.dwRecordRVA=(DWORD)(RecordAddr-VictimBase);
			if(Type==itIndirectOther)
				ir.Type=itIndirectOther;
			else if(Type==itIndirectAx)
				ir.Type=itIndirectAx;
			else if(BreakWhere==bDr2 || BreakWhere==bDr3)
				ir.Type=itIndirectCall;
			else
				ir.Type=itIndirectJmp;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
		else
		{
			if(!pInitData->fLeaveDirectRefs)
			{
//				if(NextInstr(RecordAddr+sizeof(DWORD))!=(RecordAddr+sizeof(DWORD)+1) && NextInstr(RecordAddr-2)==(RecordAddr-1))
//					--RecordAddr;
				if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
					--RecordAddr;
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
					--RecordAddr;
#if defined _M_AMD64
				else if(ReadMem(RecordAddr-2,&redir2,1)!=0 && ((redir2 & 0xf8)==0x50))
					--RecordAddr;
#endif
			}
			ir.dwReferenceRVA=(DWORD)(RecordAddr-VictimBase+1);
			if(Type==itDirectOther)
				ir.Type=itDirectOther;
			else if(State.RegIp==bRet1 || State.RegIp==bRet2)
				ir.Type=itDirectCall;
			else
				ir.Type=itDirectJmp;
			Import.AddRecord(ir);
			return sizeof(DWORD);
		}
	}
	return 0;
}

void CMain::IdentifyFunction(CImportRecord &ImportRecord,DWORD_PTR FuncAddress) const
{
	Modules.IdentifyFunction(ImportRecord,FuncAddress);
	Modules.ForwardedPrev(ImportRecord,INFINITE);
}

void CMain::SetMainBreaks()
{
	bLoadLibrary=LoadLibraryAddress;
	AddBreak(bLoadLibrary);EnableBreak(bLoadLibrary);
	bExceptionDispatcher=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"KiUserExceptionDispatcher");
	AddBreak(bExceptionDispatcher);EnableBreak(bExceptionDispatcher);
	bContinue=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtContinue"));
	AddBreak(bContinue);EnableBreak(bContinue);
	bGetContextThread=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtGetContextThread"));
	AddBreak(bGetContextThread);EnableBreak(bGetContextThread);
	bSetContextThread=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtSetContextThread"));
	AddBreak(bSetContextThread);EnableBreak(bSetContextThread);
	bCreateThread=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtCreateThread"));
	AddBreak(bCreateThread);EnableBreak(bCreateThread);
	bCreateThreadEx=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtCreateThreadEx"));
	AddBreak(bCreateThreadEx);EnableBreak(bCreateThreadEx);
	bVirtualProtect=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtProtectVirtualMemory"));
	AddBreak(bVirtualProtect);EnableBreak(bVirtualProtect);
	bOpenProcess=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtOpenProcess"));
	AddBreak(bOpenProcess);EnableBreak(bOpenProcess);
	bOpenThread=NextInstr((DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtOpenThread"));
	AddBreak(bOpenThread);EnableBreak(bOpenThread);
	if((pInitData->dwTimeDelta & MAXLONG)!=0 && (pInitData->dwTimeDelta & MINLONG)==0)
	{
		HMODULE hKernel=GetModuleHandle(_T("KernelBase.dll"));
		if(hKernel==NULL)
			hKernel=GetModuleHandle(_T("kernel32.dll"));
		bGetTickCount=(DWORD_PTR)GetProcAddress(hKernel,"GetTickCount");
		AddBreak(bGetTickCount);EnableBreak(bGetTickCount);
		bGetTickCount64=(DWORD_PTR)GetProcAddress(hKernel,"GetTickCount64");
		AddBreak(bGetTickCount64);EnableBreak(bGetTickCount64);
	}
}

DWORD_PTR CMain::LoadExtraLibrary(const TCHAR *szPath)
{
	DATA_STATE Bak;
	void *pAllocked;
	size_t nSize=_tcslen(szPath)+1;
	DWORD_PTR bBr0;

	if(GetModHandle(dwVictimPID,szPath)==0)
	{
		Bak=State;
		pAllocked=VirtualAllocEx(hVictim,NULL,nSize,MEM_COMMIT,PAGE_READONLY);
		if(WriteMem((DWORD_PTR)pAllocked,szPath,nSize)==0)
			return MAX_NUM;
		bBr0=State.RegIp;
		AddBreak(bBr0);
#if defined _M_AMD64
		State.RegCx=State.RegIp;
		State.RegDx=(DWORD_PTR)pAllocked;
		State.RegSp-=4*sizeof(DWORD_PTR);
#elif defined _M_IX86
		if(WriteMem(State.RegSp-2*sizeof(DWORD_PTR),&State.RegIp,sizeof(State.RegIp))==0)
			return MAX_NUM;
		if(WriteMem(State.RegSp-sizeof(DWORD_PTR),&pAllocked,sizeof(pAllocked))==0)
			return MAX_NUM;
		State.RegSp-=2*sizeof(DWORD_PTR);
#else
!!!
#endif
		State.RegIp=GetProcedureAddress(_T("kernel32.dll"),"LoadLibraryA");
		EnableBreak(bBr0);

		SuspendAllOther();
		while(!IsThreadDying())
		{
			Continue();
			if(BreakWhere==bBr0 || BreakWhere==bProcessTerminated)
				break;
		}
		ResumeAllOther();
		DeleteBreak(bBr0);
		if(BreakWhere==bProcessTerminated)
		{
			TSTRING sTemp;
			sTemp=badloading;
			sTemp.append(szPath);
			WriteEx(sTemp.c_str(),TRUE,TRUE,RGB(255,0,0));
			return MAX_NUM;
		}
		VirtualFreeEx(hVictim,pAllocked,0,MEM_RELEASE);
		State=Bak;
		Modules.Reload(VictimBase,&VictimFile,hVictim);
	}
	return 0;
}

DWORD_PTR CMain::ExecuteFunction(const TCHAR *szPath,const char *szFunc,DWORD_PTR Arg1,DWORD_PTR Arg2,DWORD_PTR Arg3,DWORD_PTR Arg4,DWORD_PTR Arg5)
{
	DATA_STATE Bak;
	DWORD_PTR Temp,bBr0;

	if(LoadExtraLibrary(szPath)==-1)
		return MAX_NUM;
	Bak=State;
	bBr0=State.RegIp;
	AddBreak(bBr0);

	if(WriteMem(State.RegSp-sizeof(DWORD_PTR)-5*sizeof(DWORD_PTR),&Bak.RegIp,sizeof(Bak.RegIp))==0)
		return MAX_NUM;
	if(WriteMem(State.RegSp-sizeof(DWORD_PTR)-0*sizeof(DWORD_PTR),&Arg5,sizeof(Arg5))==0)
		return MAX_NUM;
#if defined _M_AMD64
	State.RegCx=Arg1;
	State.RegDx=Arg2;
	State.Reg8=Arg3;
	State.Reg9=Arg4;
	State.RegSp-=6*sizeof(DWORD_PTR);
#elif defined _M_IX86
	if(WriteMem(State.RegSp-sizeof(DWORD_PTR)-4*sizeof(DWORD_PTR),&Arg1,sizeof(Arg1))==0)
		return MAX_NUM;
	if(WriteMem(State.RegSp-sizeof(DWORD_PTR)-3*sizeof(DWORD_PTR),&Arg2,sizeof(Arg2))==0)
		return MAX_NUM;
	if(WriteMem(State.RegSp-sizeof(DWORD_PTR)-2*sizeof(DWORD_PTR),&Arg3,sizeof(Arg3))==0)
		return MAX_NUM;
	if(WriteMem(State.RegSp-sizeof(DWORD_PTR)-1*sizeof(DWORD_PTR),&Arg4,sizeof(Arg4))==0)
		return MAX_NUM;
	State.RegSp-=sizeof(DWORD)+5*sizeof(DWORD);
#else
!!!
#endif
	State.RegIp=GetProcedureAddress(szPath,szFunc);
	if(State.RegIp==0)
		return MAX_NUM;
	EnableBreak(bBr0);

	SuspendAllOther();
	while(!IsThreadDying())
	{
		Continue();
		if(BreakWhere==bBr0 || BreakWhere==bProcessTerminated)
			break;
	}
	ResumeAllOther();
	DeleteBreak(bBr0);
	if(BreakWhere==bProcessTerminated)
	{
		TSTRING sTemp;
		sTemp=badfunction;
#ifdef UNICODE
		int nMultiLength=(int)strlen(szFunc)+1;
		WCHAR *pWideArray=new WCHAR[nMultiLength];
		MultiByteToWideChar(CP_ACP,0,szFunc,nMultiLength,pWideArray,nMultiLength);
		sTemp.append(pWideArray);
		delete[] pWideArray;
#else
		sTemp.append(szFunc);
#endif
		sTemp.append(from);
		sTemp.append(szPath);
		WriteEx(sTemp.c_str(),TRUE,TRUE,RGB(255,0,0));
		return MAX_NUM;
	}
	Temp=State.RegAx;
	State=Bak;
	return Temp;
}

DWORD_PTR CMain::Find(const BYTE *bBuf,int nLength,DWORD_PTR StartAddr,DWORD_PTR EndAddr)
{
	DWORD_PTR dBegin,dEnd,dSize,sBegin,sEnd;
	BYTE *bLocMem;

	if(StartAddr>=EndAddr)
		return 0;

	DWORD_PTR Result=0;
	DWORD_PTR sb=StartAddr/PAGE_SIZE;
	DWORD_PTR se=EndAddr/PAGE_SIZE;
	__int64 i=0,j=0,k=0,sn=se-sb+1;

	bLocMem=(BYTE*)VirtualAlloc(NULL,PAGE_SIZE,MEM_COMMIT,PAGE_READWRITE);
	for(;i<sn;++i)
	{
		sBegin=(sb+(DWORD_PTR)i)*PAGE_SIZE;
		sEnd=sBegin+PAGE_SIZE;

		dBegin=max(StartAddr,sBegin);
		dEnd=min(EndAddr,sEnd);
		dSize=dEnd-dBegin;

		dSize=ReadMem(dBegin,bLocMem,dSize);
		if(dSize==0)
			k=0;
		else
		{
			for(j=0;j<(__int64)dSize;++j)
			{
				sBegin=(DWORD_PTR)k;
				for(;k!=nLength;++k)
				{
					if(j+k-sBegin>=dSize || bBuf[k]!=bLocMem[j+k-sBegin])
						break;
				}
				if(k==nLength)
					break;
				if(j+k-sBegin<dSize)
					k=0;
			}
		}
		if(k==nLength)
		{
			Result=dBegin+(DWORD_PTR)j-sBegin;
			break;
		}
	}
	VirtualFree((void*)bLocMem,0,MEM_RELEASE);
	return Result;
}

DWORD_PTR CMain::FindByMask(const BYTE *bBuf,int nLength,DWORD_PTR StartAddr,DWORD_PTR EndAddr)
{
	DWORD_PTR dBegin,dEnd,dSize,NewLen,sBegin,sEnd;
	BYTE *bLocMem;

	if(StartAddr>=EndAddr)
		return 0;

	NewLen=nLength/2;
	if((nLength%2)!=0)
		++NewLen;
	BYTE *bBuffer=new BYTE[NewLen];
	BYTE *bMask=new BYTE[NewLen];
	BYTE bBufferTemp,bMaskTemp;
	__int64 i=0;
	for(;i<nLength/2;++i)
	{
		if(bBuf[2*i]>='0' && bBuf[2*i]<='9')
		{
			bBufferTemp=(bBuf[2*i]-'0')<<4;
			bMaskTemp=0xf0;
		}
		else if(bBuf[2*i]>='A' && bBuf[2*i]<='F')
		{
			bBufferTemp=(bBuf[2*i]-('A'-0xa))<<4;
			bMaskTemp=0xf0;
		}
		else if(bBuf[2*i]>='a' && bBuf[2*i]<='f')
		{
			bBufferTemp=(bBuf[2*i]-('a'-0xa))<<4;
			bMaskTemp=0xf0;
		}
		else
		{
			bBufferTemp=0;
			bMaskTemp=0;
		}

		if(bBuf[2*i+1]>='0' && bBuf[2*i+1]<='9')
		{
			bBufferTemp|=(bBuf[2*i+1]-'0');
			bMaskTemp|=0xf;
		}
		else if(bBuf[2*i+1]>='A' && bBuf[2*i+1]<='F')
		{
			bBufferTemp|=(bBuf[2*i+1]-('A'-0xa));
			bMaskTemp|=0xf;
		}
		else if(bBuf[2*i+1]>='a' && bBuf[2*i+1]<='f')
		{
			bBufferTemp|=(bBuf[2*i+1]-('a'-0xa));
			bMaskTemp|=0xf;
		}
		bBuffer[i]=bBufferTemp;
		bMask[i]=bMaskTemp;
	}
	if((nLength%2)!=0)
	{
		if(bBuf[2*i]>='0' && bBuf[2*i]<='9')
		{
			bBuffer[i]=(bBuf[2*i]-'0')<<4;
			bMask[i]=0xf0;
		}
		else if(bBuf[2*i]>='A' && bBuf[2*i]<='F')
		{
			bBuffer[i]=(bBuf[2*i]-('A'-0xa))<<4;
			bMask[i]=0xf0;
		}
		else if(bBuf[2*i]>='a' && bBuf[2*i]<='f')
		{
			bBuffer[i]=(bBuf[2*i]-('a'-0xa))<<4;
			bMask[i]=0xf0;
		}
		else
		{
			bBuffer[i]=0;
			bMask[i]=0;
		}
	}
	DWORD_PTR Result=0;
	DWORD_PTR sb=StartAddr/PAGE_SIZE;
	DWORD_PTR se=EndAddr/PAGE_SIZE;
	__int64 j=0,k=0,sn=se-sb+1;

	bLocMem=(BYTE*)VirtualAlloc(NULL,PAGE_SIZE,MEM_COMMIT,PAGE_READWRITE);
	for(i=0;i<sn;++i)
	{
		sBegin=(sb+(DWORD_PTR)i)*PAGE_SIZE;
		sEnd=sBegin+PAGE_SIZE;

		dBegin=max(StartAddr,sBegin);
		dEnd=min(EndAddr,sEnd);
		dSize=dEnd-dBegin;

		dSize=ReadMem(dBegin,bLocMem,dSize);
		if(dSize==0)
			k=0;
		else
		{
			for(j=0;j<(__int64)dSize;++j)
			{
				sBegin=(DWORD_PTR)k;
				for(;k!=(__int64)NewLen;++k)
				{
					if(j+k-sBegin>=dSize || bBuffer[k]!=(bLocMem[j+k-sBegin] & bMask[k]))
						break;
				}
				if(k==(__int64)NewLen)
					break;
				if(j+k-sBegin<dSize)
					k=0;
			}
		}
		if(k==(__int64)NewLen)
		{
			Result=dBegin+(DWORD_PTR)j-sBegin;
			break;
		}
	}
	VirtualFree((void*)bLocMem,0,MEM_RELEASE);
	delete[] bBuffer;
	delete[] bMask;
	return Result;
}