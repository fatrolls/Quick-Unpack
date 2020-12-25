#pragma once

#include "Tracer.h"
#include "PEFile.h"
#include "Modules.h"

enum EImpRecType {irNone,irSmart,irSmartTracer,irLoadLibs};
enum EUnpackModeType {umFull,umSkipOEP,umScript};

struct CInitData
{
	TSTRING sParameters,sScriptFile,sUnpackedLong,sUnpackedShort,sUnpackedFile,sVictimFile,sVictimName;
	DWORD dwCutModule,dwImportRVA,dwOEP,dwModuleEnd,dwPID,dwTimeDelta,dwTID;
	DWORD_PTR ImageBase;
	EImpRecType ImportRec;
	EUnpackModeType UnpackMode;
	BOOL fAppendOverlay,fAutosaveLog,fDelphiInit,fDirectRefs,fExecuteFunc,fForce,fIsDll,fLeaveDirectRefs,fLongImport,fMemoryManager,fPathToLibs,fProtectDr,fRelocs,fRemoveSect,fSuspectFunc,fUseTf;
	HWND hMain;
	HMODULE hDllHandle;
};

unsigned int __stdcall MainThread(void *pInitData);
void StopMainThread();

class CMain:public CTracer
{
	friend CDlgImport;
	friend CTracer;

	void IntersecLibsArray(std::map<TSTRING,size_t> &sLibs,const CImportRecord &ImportRecord);
	void FillLibsArray(std::map<TSTRING,size_t> &sLibs,CImportRecord ImportRecord);
	DWORD GetNeededThreadId(HANDLE hThread);
	bool IsNeededProcess(HANDLE hProcess);
public:
	CInitData *pInitData;
	bool fTerminate;
	CPEFile UnpackedFile;
	CModules Modules;
	CImport Import;
	CFixUp FixUp;
	CPEFile VirginVictim;
	DWORD_PTR TickCountAX,TickCountDX;
	int nBreakNumber;

	CMain(CInitData *n_pInitData);
	~CMain();

	int PreLoad();
	int PreLoadDLL();
	void FullUnpack();
	void RestoreDelphiInit(bool fIsStatic);
	void ChangeForwardedImport();
	void RestoreImportRelocs();
	void Run();
	void RunScript();
	void Stop();
	void UnpackSkipOEP();

	bool IsAddressInModule(DWORD_PTR Address);
	DWORD_PTR SetLastSEH();
	void RemoveLastSEH(DWORD_PTR SehAddr);
	void ProcessRelocation();
	void ProcessImport();
	void ProcessImportOnlyLibs();
	int FindTrace(DWORD dwRefRVA,DWORD_PTR RecordAddr,EImportRecordType Type);
	int FindTraceSkipOEP(DWORD dwRefRVA,DWORD_PTR RecordAddr,EImportRecordType Type);
	void ProcessImportWTrace();
	void IdentifyFunction(CImportRecord &ImportRecord,DWORD_PTR FuncAddress) const;

	void SetMainBreaks();
	DWORD_PTR LoadExtraLibrary(const TCHAR *szPath);
	DWORD_PTR ExecuteFunction(const TCHAR *szPath,const char *szFunc,DWORD_PTR Arg1,DWORD_PTR Arg2,DWORD_PTR Arg3,DWORD_PTR Arg4,DWORD_PTR Arg5);
	DWORD_PTR Find(const BYTE *bBuf,int nLength,DWORD_PTR StartAddr,DWORD_PTR EndAddr);
	DWORD_PTR FindByMask(const BYTE *bBuf,int nLength,DWORD_PTR StartAddr,DWORD_PTR EndAddr);
	bool BreakHandler();
};

extern CMain *pMain;