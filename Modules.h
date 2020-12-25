#pragma once
#include"PEFile.h"

class CExportFunction
{
public:
	std::string sFuncName;
	WORD wFuncOrdinal;
	DWORD dwFuncAddress;
	DWORD dwFuncAddressHook;

	CExportFunction():sFuncName(""),wFuncOrdinal(0),dwFuncAddress(0),dwFuncAddressHook(MAXDWORD) {}
};

struct SCHEMA_LIBRARY
{
	TSTRING sSchemaName;
	TSTRING sRealName;
};

struct FORWARDED_FUNC
{
	TSTRING sToLib;
	std::string sToName;
	WORD wToOrdinal;

	TSTRING sFromLib;
	std::string sFromName;
	WORD wFromOrdinal;
};

class CModule
{
	friend class CModules;
	friend class CTracer;
	friend class CMain;
	friend class CDlgEditImport;
	friend class CDlgAttach;
	friend class CDlgMain;

	HANDLE hVictim;

	DWORD dwOffsetToPe;

	std::vector<CExportFunction> Exports;
public:
	TSTRING sModuleName,sFullName,sImportName;
	CPEFile ModuleFile;

	CModule(HANDLE n_hVictim,DWORD_PTR n_ModuleBase,const TCHAR *szModuleName,
		const TCHAR *szFullName,const TCHAR *szImportName);
	CModule &operator=(const CModule &other);
	void AddForwarded();

	DWORD_PTR ModuleBase;
	DWORD dwModuleSize;
	DWORD_PTR HookBase;
	DWORD dwHookSize;

	void HookExport();
	void UnHookExport();
	void FreeMemory();
	bool TestVictim();
};

class CModules
{
public:
	CModules();
	~CModules();

	std::vector<CModule*> Modules;
	std::vector<TSTRING> UnhookModules;
	std::vector<DWORD_PTR> UnhookedBreaks;
	DWORD_PTR VictimBase;
	DWORD_PTR TrampolineBase;
	CPEFile *pVictimFile;
	HANDLE hVictim;
	bool fHookedImport;
	BOOL fUnhookInAction;

	void Clear();
	void AddModule(DWORD_PTR ModuleBase,bool fAddForwarded);
	void Reload(DWORD_PTR n_VictimBase,CPEFile *n_pVictimFile,HANDLE n_hVictim);

	void HookExport();
	void UnHookExport();
	void HookImport();
	void SetUnhookedBreaksBack();

	DWORD_PTR GetModHandle(const TCHAR *szModuleName) const;
	DWORD_PTR GetProcedureAddr(const TCHAR *szModuleName,const char *szFuncName,WORD wFuncOrdinal,bool fAddressHook) const;

	void IdentifyFunction(CImportRecord &ImportRecord,DWORD_PTR FuncAddress) const;
	bool IdentifyFunctionPrev(CImportRecord &ImportRecord) const;
	bool IdentifyFunctionNext(CImportRecord &ImportRecord) const;
	bool ForwardedPrev(CImportRecord &ImportRecord,DWORD dwCount) const;
	bool ForwardedNext(CImportRecord &ImportRecord,DWORD dwCount) const;
};