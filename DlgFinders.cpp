#include "stdafx.h"
#include "Init.h"
#include "DlgFinders.h"
#include "DlgMain.h"

bool fIsDll;
CListBox FindersBox;
DWORD dwOEPFinderResult;

IMPLEMENT_DYNAMIC(CDlgFinders,CDialog)

CDlgFinders::CDlgFinders(bool n_fIsDll):CDialog(CDlgFinders::IDD,NULL)
{
	fIsDll=n_fIsDll;
}

CDlgFinders::~CDlgFinders()
{
	UnloadOEPFinders();
}

void CDlgFinders::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDC_OEPFINDERSBOX,FindersBox);
}

BEGIN_MESSAGE_MAP(CDlgFinders,CDialog)
	ON_LBN_DBLCLK(IDC_OEPFINDERSBOX,OnLbnDblclkOepfindersbox)
END_MESSAGE_MAP()

const TCHAR szOEPPluginSearch[]=_T("\\OEPFinders\\*.dll");
const TCHAR szOEPPluginDir[]=_T("\\OEPFinders\\");
const char szGetOEP[]="GetOEPNow";
const char szGetDllOEP[]="GetDllOEPNow";
const char szOEPGetNamePluginFn[]="ShortFinderName";

typedef DWORD (__stdcall *StartFinder)(const BYTE*);
typedef const BYTE *(__stdcall *GetFinderName)();

struct FINDER_INFO
{
	HMODULE hModule;
	StartFinder StartFunc;
	bool fUnicode;
};

std::vector<FINDER_INFO> OEPFinders;

void LoadOEPFinders(HWND hWnd)
{
	TCHAR cBuff[MAX_PATH]={_T('\0')};
	WIN32_FIND_DATA Find={0};
	HANDLE hFind;

	GetModuleFileName(NULL,cBuff,_countof(cBuff));
	PathToDir(cBuff);
	_tcscat_s(cBuff,szOEPPluginSearch);

	hFind=FindFirstFile(cBuff,&Find);
	if(hFind!=INVALID_HANDLE_VALUE)
	{
		do ProcessOEPFinder(Find.cFileName);
		while(FindNextFile(hFind,&Find));

		FindClose(hFind);
	}

	EnableWindow(hWnd,OEPFinders.empty() ? FALSE : TRUE);
}

void ProcessOEPFinder(TCHAR *szDllName)
{
	StartFinder pFn;
	GetFinderName pFnGetName;
	HMODULE hModule;
	TCHAR cBuff[MAX_PATH]={_T('\0')};

	GetModuleFileName(NULL,cBuff,_countof(cBuff));
	PathToDir(cBuff);
	_tcscat_s(cBuff,szOEPPluginDir);
	_tcscat_s(cBuff,szDllName);

	hModule=LoadLibrary(cBuff);
	if(hModule==NULL)
		return;

	if(fIsDll)
		pFn=(StartFinder)GetProcAddress(hModule,szGetDllOEP);
	else
		pFn=(StartFinder)GetProcAddress(hModule,szGetOEP);
	pFnGetName=(GetFinderName)GetProcAddress(hModule,szOEPGetNamePluginFn);

	if(pFn!=NULL && pFnGetName!=NULL)
	{
		FINDER_INFO FinderInfo;
		FinderInfo.hModule=hModule;
		FinderInfo.StartFunc=pFn;
		FinderInfo.fUnicode=pFnGetName()[1]==0;
		OEPFinders.push_back(FinderInfo);

		TCHAR *szName;
		if(FinderInfo.fUnicode)
		{
			size_t nLength=wcslen((WCHAR*)pFnGetName())+2;
			szName=new TCHAR[nLength];
#ifdef UNICODE
			_stprintf_s(szName,nLength,_T("%ls"),pFnGetName());
#else
			_stprintf_s(szName,nLength,_T("%ls*"),pFnGetName());
#endif
		}
		else
		{
			size_t nLength=strlen((char*)pFnGetName())+2;
			szName=new TCHAR[nLength];
#ifdef UNICODE
			_stprintf_s(szName,nLength,_T("%hs*"),pFnGetName());
#else
			_stprintf_s(szName,nLength,_T("%hs"),pFnGetName());
#endif
		}
		FindersBox.AddString(szName);
		delete[] szName;
	}
}

void UnloadOEPFinders()
{
	for(size_t i=0;i!=OEPFinders.size();++i)
		FreeLibrary(OEPFinders[i].hModule);
	OEPFinders.clear();
}

BOOL CDlgFinders::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);

	LoadOEPFinders(GetSafeHwnd());
	FindersBox.SetCurSel(0);
	FindersBox.SelectString(-1,_T("ForceOEP"));

	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}

void CDlgFinders::OnLbnDblclkOepfindersbox()
{
	size_t nLength=pDlgMain->InitData.sVictimFile.length()+1;
	BYTE *szName;
	if(OEPFinders[FindersBox.GetCurSel()].fUnicode)
	{
		szName=(BYTE*)new WCHAR[nLength];
#ifdef UNICODE
		swprintf_s((WCHAR*)szName,nLength,L"%ls",pDlgMain->InitData.sVictimFile.c_str());
#else
		swprintf_s((WCHAR*)szName,nLength,L"%hs",pDlgMain->InitData.sVictimFile.c_str());
#endif
	}
	else
	{
		szName=(BYTE*)new char[nLength];
#ifdef UNICODE
		sprintf_s((char*)szName,nLength,"%ls",pDlgMain->InitData.sVictimFile.c_str());
#else
		sprintf_s((char*)szName,nLength,"%hs",pDlgMain->InitData.sVictimFile.c_str());
#endif
	}
	dwOEPFinderResult=OEPFinders[FindersBox.GetCurSel()].StartFunc(szName);
	delete[] szName;

	pDlgMain->UpdateData(TRUE);
	pDlgMain->sOEPbox.Format(_T("%08X"),dwOEPFinderResult);
	pDlgMain->UpdateData(FALSE);

	OnOK();
}