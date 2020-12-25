#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgPref.h"
#include "RegistryKey.h"
#include ".\DlgPref.h"

IMPLEMENT_DYNAMIC(CDlgPref,CDialog)
CDlgPref::CDlgPref():CDialog(CDlgPref::IDD,NULL)
{
}

CDlgPref::~CDlgPref()
{
}

void CDlgPref::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDC_LANGS,Lang);
}

BEGIN_MESSAGE_MAP(CDlgPref,CDialog)
	ON_BN_CLICKED(IDC_SAVEPREF,OnBnClickedSavePref)
END_MESSAGE_MAP()

void CDlgPref::OnBnClickedSavePref()
{
	bool fNeedLocalize=true;
	CString sTemp;
	Lang.GetLBText(Lang.GetCurSel(),sTemp);
	if(_tcscmp(pDlgMain->Option.szLang,sTemp.GetBuffer())==0)
		fNeedLocalize=false;
	else
		_tcscpy_s(pDlgMain->Option.szLang,sTemp.GetBuffer());

	if(IsDlgButtonChecked(IDC_ALWAYSONTOP)==BST_CHECKED)
		pDlgMain->Option.fAlwaysOnTop=true;
	else
		pDlgMain->Option.fAlwaysOnTop=false;

	CRegistryKey RegKey;
	RegKey.RegistryWriteStruct(REG_KEY_NAME,REG_VALUE_NAME,(void*)&pDlgMain->Option,sizeof(pDlgMain->Option));
	if(fNeedLocalize)
	{
		pDlgMain->Localize(false);
		pDlgMain->LoadLocalization();
		pDlgMain->Localize(true);
	}

	if(IsDlgButtonChecked(IDC_REGSHELLEXT)==BST_CHECKED)
		RegKey.RegisterShellExt();
	else
		RegKey.UnRegisterShellExt();

	AnimateWindow(300,AW_BLEND | AW_HIDE);
	OnOK();
}

BOOL CDlgPref::OnInitDialog()
{
	TCHAR cBuff[MAX_PATH]={_T('\0')};
	WIN32_FIND_DATA Find={0};
	HANDLE hFind;

	CDialog::OnInitDialog();

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);
	GetDlgItemText(IDC_SAVEPREF,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_SAVEPREF,sTemp);
	GetDlgItemText(IDC_REGSHELLEXT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_REGSHELLEXT,sTemp);
	GetDlgItemText(IDCANCEL,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDCANCEL,sTemp);
	GetDlgItemText(IDC_ALWAYSONTOP,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_ALWAYSONTOP,sTemp);

	CRegistryKey RegKey;
	GetDlgItem(IDC_REGSHELLEXT)->SendMessage(BM_SETCHECK,RegKey.IsShellRegisterExt(),0);
	GetDlgItem(IDC_ALWAYSONTOP)->SendMessage(BM_SETCHECK,pDlgMain->Option.fAlwaysOnTop,0);

	GetModuleFileName(NULL,cBuff,_countof(cBuff));
	PathToDir(cBuff);
	_tcscat_s(cBuff,_T("\\*.lng"));

	Lang.ResetContent();
	Lang.AddString(_T("english.lng"));
	hFind=FindFirstFile(cBuff,&Find);
	if(hFind!=INVALID_HANDLE_VALUE)
	{
		do Lang.AddString(Find.cFileName);
		while(FindNextFile(hFind,&Find));
		FindClose(hFind);
	}
	Lang.SelectString(-1,pDlgMain->Option.szLang);
	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}