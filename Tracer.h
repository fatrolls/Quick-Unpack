#pragma once

#include "EngineHandler.h"
#include "PEFile.h"
#include "Modules.h"

enum EBreakType1 {btOpcode=1,btCC=2,btDr0=3,btDr1=4,btDr2=5,btDr3=6};
enum EBreakType2 {bt2Execute=0,bt2MemoryWrite=1,bt2MemoryAll=3};

class CBreak
{
	friend class CTracer;

	EBreakType1 BreakType1;
	EBreakType2 BreakType2;
	int nEnabled,nExists;
	DWORD_PTR Where;
	int nSize;
	std::vector<BYTE> bOldBytes;

public:
	CBreak();
};

class CDrReg
{
public:
	DWORD_PTR Dr[8];
	DWORD_PTR OrigDr[8];
	DWORD dwTID;
	bool fTraceFlag;

	CDrReg() {Clear();}
	void Clear() {	Dr[0]=0; Dr[1]=0; Dr[2]=0; Dr[3]=0; Dr[4]=0; Dr[5]=0; Dr[6]=0; Dr[7]=0;
					OrigDr[0]=0; OrigDr[1]=0; OrigDr[2]=0; OrigDr[3]=0; OrigDr[4]=0; OrigDr[5]=0;
					OrigDr[6]=0; OrigDr[7]=0; dwTID=0; fTraceFlag=false;}
};

class CTracer:public CEngine
{
	friend class CDlgImport;
public:
	DWORD_PTR bProcessCreated,bOEP,bLoadLibrary,bExceptionDispatcher,bContinue,bGetContextThread,
		bSetContextThread,bCreateThread,bCreateThreadEx,bVirtualAlloc,bVirtualFree,bVirtualProtect,
		bOpenProcess,bOpenThread,bGetTickCount,bGetTickCount64,bLastSEH;

	TSTRING sVictimName;
	CPEFile VictimFile;

	DWORD dwVictimPID;
	DWORD_PTR PageLastUsed,PagesAllocked,VictimBase;
	PAGE_ENTRY *pPageDir;
	HANDLE hVictim;
	std::map<DWORD_PTR,BYTE> MemBreaks;

	TSTRING sWorkDir,sOldDir;

	DATA_STATE State,BakState;

	CTracer(const TCHAR *szVictimName,HMODULE hDllHandle);
	~CTracer();

	DWORD_PTR BreakWhere,FirstVictimBase;
	TSTRING sVictimGhostName,sVictimLoaderName;

	DWORD Suspend();
	DWORD Resume();
	void SuspendAllOther();
	void ResumeAllOther();

	void Attach();
	void Detach();
	void Start(bool fUseGhost,BOOL fStopSystem);
	void Terminate();

	void Continue();
	void Trace();
	void Wait();

	std::vector<CBreak*> Breaks;
	bool AddBreak(DWORD_PTR Where,EBreakType1 BreakType1=btOpcode,EBreakType2 BreakType2=bt2Execute);
	bool DeleteBreak(DWORD_PTR Where);
	void DeleteBreakAll();
	bool EnableBreak(DWORD_PTR Where);
	bool DisableBreak(DWORD_PTR Where);
	void DisableBreakAll();
	int IsEnabled(DWORD_PTR Where) const;
	int IsExist(DWORD_PTR Where) const;

	std::vector<CDrReg> DrRegs;
	int AddDrReg(DWORD dwTID);
	void DeleteDrRegs();

	bool AddMemoryBreak(DWORD_PTR StartAddr,DWORD Size);
	void DeleteMemoryBreaks();

	DWORD_PTR NextInstr(DWORD_PTR Address);
	bool IsThreadDying() const;

	void TraceAndReplace(DWORD_PTR Where);

	DWORD_PTR ReadMem(DWORD_PTR Addr,void *pBuff,DWORD_PTR Size);
	DWORD_PTR WriteMem(DWORD_PTR Addr,const void *pBuff,DWORD_PTR Size);
	DWORD_PTR GetOrdinalAddress(const TCHAR *szLibName,WORD wOrdinal);
	DWORD_PTR GetProcedureAddress(const TCHAR *szLibName,const char *szApiName);
};