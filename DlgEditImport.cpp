#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgEditImport.h"
#include "PEFile.h"
#include "Modules.h"

IMPLEMENT_DYNAMIC(CDlgEditImport,CDialog)

CDlgEditImport::CDlgEditImport(CModules *n_pModules,CImportRecord *n_pImportRecord):CDialog(CDlgEditImport::IDD,NULL),
	pModules(n_pModules),
	pImportRecord(n_pImportRecord)
{
}

CDlgEditImport::~CDlgEditImport()
{
}

void CDlgEditImport::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDC_MODULE,ModuleName);
	DDX_Control(pDX,IDC_FUNCTIONS,Functions);
}

BEGIN_MESSAGE_MAP(CDlgEditImport,CDialog)
	ON_BN_CLICKED(IDOK,&CDlgEditImport::OnBnClickedOK)
	ON_BN_CLICKED(IDCANCEL,&CDlgEditImport::OnBnClickedCancel)
	ON_CBN_SELCHANGE(IDC_MODULE,&CDlgEditImport::OnCbnSelchangeCombo1)
END_MESSAGE_MAP()

BOOL CDlgEditImport::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);
	GetDlgItemText(IDCANCEL,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDCANCEL,sTemp);

	for(size_t i=0;i!=pModules->Modules.size();++i)
	{
		if(!pModules->Modules[i]->Exports.empty())
			ModuleName.AddString(pModules->Modules[i]->sImportName.c_str());
	}
	if(!pImportRecord->Exist())
		ModuleName.SelectString(-1,_T("kernel32.dll"));
	else
		ModuleName.SelectString(-1,pImportRecord->sLibName.c_str());
	OnCbnSelchangeCombo1();
	Functions.SelectString(-1,ord2+IntToStr(pImportRecord->wOrdinal,16,4));

	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}

void CDlgEditImport::OnBnClickedOK()
{
	CString sTemp;
	if(ModuleName.GetCurSel()!=CB_ERR && Functions.GetCurSel()!=CB_ERR)
	{
		ModuleName.GetLBText(ModuleName.GetCurSel(),sTemp);
		pImportRecord->sLibName=sTemp;
		Functions.GetText(Functions.GetCurSel(),sTemp);
		sTemp.Delete(0,ord2.GetLength());
		pImportRecord->wOrdinal=(WORD)_tcstoul(sTemp.Left(4),NULL,16);
		sTemp.Delete(0,4+name.GetLength());
#ifdef UNICODE
		int nWideLength=sTemp.GetLength()+1;
		char *pMultiArray=new char[nWideLength];
		WideCharToMultiByte(CP_ACP,0,sTemp.GetBuffer(),nWideLength,pMultiArray,nWideLength,NULL,NULL);
		pImportRecord->sApiName=pMultiArray;
		delete[] pMultiArray;
#else
		pImportRecord->sApiName=sTemp;
#endif
	}
	OnOK();
}
void CDlgEditImport::OnBnClickedCancel()
{
	OnCancel();
}

void CDlgEditImport::OnCbnSelchangeCombo1()
{
	if(ModuleName.GetCurSel()==CB_ERR)
		return;

	CString sTemp;
	ModuleName.GetLBText(ModuleName.GetCurSel(),sTemp);
	for(size_t i=0;i!=pModules->Modules.size();++i)
	{
		if(sTemp!=pModules->Modules[i]->sImportName.c_str())
			continue;

		Functions.ResetContent();
		for(size_t j=0;j!=pModules->Modules[i]->Exports.size();++j)
		{
			if(pModules->Modules[i]->Exports[j].dwFuncAddress==0)
				continue;
#ifdef UNICODE
			int nMultiLength=(int)pModules->Modules[i]->Exports[j].sFuncName.length()+1;
			WCHAR *pWideArray=new WCHAR[nMultiLength];
			MultiByteToWideChar(CP_ACP,0,pModules->Modules[i]->Exports[j].sFuncName.c_str(),nMultiLength,
				pWideArray,nMultiLength);
			Functions.AddString(ord2+IntToStr(pModules->Modules[i]->Exports[j].wFuncOrdinal,16,4)+
				name+pWideArray);
			delete[] pWideArray;
#else
			Functions.AddString(ord2+IntToStr(pModules->Modules[i]->Exports[j].wFuncOrdinal,16,4)+
				name+pModules->Modules[i]->Exports[j].sFuncName.c_str());
#endif
		}
		break;
	}
	Functions.SetFocus();
}

BOOL CDlgEditImport::PreTranslateMessage(MSG *pMsg)
{
	if(pMsg->message==WM_CHAR)
	{
		CString sHeader,sFunction;

		GetWindowText(sHeader);
		if(sHeader==editfunction)
			sHeader=_T("");
		if(pMsg->wParam==VK_BACK)
			sHeader.Delete(sHeader.GetLength()-1);
		else
			sHeader.AppendChar((TCHAR)pMsg->wParam);
		for(int i=0;i!=Functions.GetCount();++i)
		{
			Functions.GetText(i,sFunction);
			sFunction.Delete(0,ord2.GetLength()+4+name.GetLength());
			if(sHeader.MakeLower()==sFunction.Left(sHeader.GetLength()).MakeLower())
			{
				Functions.SetCurSel(i);
				break;
			}
		}
		SetWindowText(sHeader.GetString());
	}
	else if(pMsg->message==WM_LBUTTONDOWN)
		SetWindowText(editfunction);
	return CDialog::PreTranslateMessage(pMsg);
}