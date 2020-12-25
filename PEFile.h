#pragma once

enum EImportRecordType {itNone,itIndirectJmp,itIndirectCall,itIndirectOther,itDirectJmp,itDirectCall,itDirectOther,itIndirectAx};
enum ESortImportType {siByName,siByRecord,siByReference};
enum ECutSectionsType {csNone,csSimple,csMemoryManager};

class CImportRecord
{
public:
	TSTRING sLibName;
	std::string sApiName;
	WORD wOrdinal;

	DWORD dwReferenceRVA;
	DWORD dwRecordRVA;
	DWORD_PTR NameRVA;

	EImportRecordType Type;

	int nLib,nApi,nTrampoline;

	CImportRecord();
	CImportRecord(const TCHAR *szLibName,const char *szApiName,DWORD n_dwReferenceRVA,DWORD n_dwRecordRVA,EImportRecordType n_Type);
	CImportRecord(const TCHAR *szLibName,WORD n_wOrdinal,DWORD n_dwReferenceRVA,DWORD n_dwRecordRVA,EImportRecordType n_Type);

	void Clear();

	bool Exist() const {return !sLibName.empty();};
	bool IsDirectRef() const {return Type==itDirectJmp || Type==itDirectCall || Type==itDirectOther;};
};

class CImport
{
	friend class CDlgImport;
	friend class CPEFile;
	friend class CTracer;
	friend class CMain;

	ESortImportType CurrentSort;
	std::vector<CImportRecord> Records;

	bool CheckOldIAT(const CPEFile &File,DWORD *pLibsNumber);
	void SaveToIAT(CPEFile &File,DWORD dwImportRVA);
public:
	void Clear();
	void AddRecord(const CImportRecord &ImportRecord);
	void ReadFromFile(const CPEFile &File);
	void SortRecords(ESortImportType SortType);
	void RedirectToOldIAT(bool fRedirectToEmpty,DWORD *pLibsNumber,DWORD *pDirectRefs);
	void SaveToFile(CPEFile &File,DWORD dwImportRVA);
};

class CFixUp
{
public:
	struct RELOCATION
	{
		DWORD dwRVA;
		DWORD dwType;
	};
	std::vector<RELOCATION> Items;

	void Clear();

	void AddItem(DWORD dwRVA,DWORD dwType);
	int Compare(DWORD dwRVA) const;

	void ReadFromFile(const CPEFile &File);
	void SaveToFile(CPEFile &File);

	void ProcessToFile(CPEFile &File,DWORD dwDelta) const;
};

class CTLS
{
	friend CPEFile;

	std::vector<BYTE> bTLSSection;
public:
	void Clear();

	void ReadFromFile(const CPEFile &File);
	void SaveToFile(CPEFile &File,bool fSaveCallbacks) const;
	DWORD_PTR GetFirstCallback() const;
};

class CExport
{
public:
	class CExportFunc
	{
	public:
		std::string sFuncName;
		WORD wFuncOrdinal;
		DWORD dwFuncAddress;
		std::string sForwardedName;

		CExportFunc():sFuncName(""),wFuncOrdinal(0),dwFuncAddress(0),sForwardedName("") {}
	};
private:
	IMAGE_EXPORT_DIRECTORY ExpHeader;
	std::string sExportName;
	std::vector<CExportFunc> Exports;
public:
	void Clear();

	void ReadFromFile(const CPEFile &File);
	void SaveToFile(CPEFile &File);
};

class CPEFile
{
public:
	IMAGE_DOS_HEADER *pMZHeader;
	IMAGE_NT_HEADERS *pPEHeader;
	IMAGE_SECTION_HEADER *pSectionHeader;

	std::vector<BYTE> bOverlay;

	DWORD dwSectionsBegin;
	DWORD dwSectionsSize;
private:
	std::vector<BYTE> bHeader;
	BYTE *bSections[MAX_SECTIONS];

	void AddResourceDelta(DWORD dwDirRVA,DWORD dwResourceBase,DWORD dwResHeadersSize);
	void AlignRes(std::vector<BYTE> &bRes,DWORD dwAlignment);
	bool AddRes(std::vector<BYTE> &bRes,DWORD dwRVA,DWORD dwSize);
	DWORD AddResource(std::vector<BYTE> &bRes,DWORD dwRVA,DWORD dwSize);
	DWORD RipResources(DWORD dwDirRVA,DWORD dwResourceBase,std::vector<BYTE> &bResHeaders,std::vector<BYTE> &bResources);

public:
	CPEFile();
	~CPEFile();

	void Clear();
	void Read(const TCHAR *szFileName);
	void Save(const TCHAR *szFileName);

	void Dump(HANDLE hProcess,DWORD_PTR ModuleBase,const CPEFile *pFileOnDisk,ECutSectionsType TruncateSections);
	bool IsEmpty() const;

	void CreateEmpty();
	void CreateSection(const char *szName,const BYTE *bBody,DWORD dwSize,DWORD dwchars);

	void SetSectionWritable(DWORD dwRvaInSection);

	void DeleteLastSection();
	void ClearSection(int i);

	int GetSectionNumber(DWORD dwRVA) const;
	std::string GetSectionName(DWORD dwRVA) const;
	void RenameSection(DWORD dwRVA,const char *szName);

	void ReBuild();
	void ProcessExport();
	void ProcessTLS();
	void ProcessResources();
	void CutSections();

	void PreserveOverlay(const CPEFile &Source);
	void ClearOverlay();

	BYTE *RVA(DWORD dwRVA) const;
};

DWORD_PTR WriteMem(HANDLE hProcess,DWORD_PTR Addr,const void *pBuff,DWORD_PTR Size);
DWORD_PTR ReadMem(HANDLE hProcess,DWORD_PTR Addr,void *pBuff,DWORD_PTR Size);