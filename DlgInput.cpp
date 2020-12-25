#include "stdafx.h"
#include "Init.h"
#include "DlgInput.h"
#include "DlgMain.h"

IMPLEMENT_DYNAMIC(CDlgInput,CDialog)

CDlgInput::CDlgInput(TSTRING *n_pName,const TCHAR *szCaption,const TCHAR *szDefault)
:CDialog(CDlgInput::IDD,NULL),
	pName(n_pName),
	sCaption(szCaption),
	sDefault(szDefault)
{
}

void CDlgInput::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX,IDC_INPUTEDIT,sValue);
}

BEGIN_MESSAGE_MAP(CDlgInput,CDialog)
	ON_EN_CHANGE(IDC_INPUTEDIT,DoUpdateData)
END_MESSAGE_MAP()

void CDlgInput::DoUpdateData()
{
	UpdateData(TRUE);
}

BOOL CDlgInput::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);
	GetDlgItemText(IDCANCEL,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDCANCEL,sTemp);

	SetWindowText(sCaption.c_str());
	sValue=sDefault.c_str();
	GetDlgItem(IDC_INPUTEDIT)->SetFocus();
	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return FALSE;
}

void CDlgInput::OnOK()
{
	*pName=sValue;
	CDialog::OnOK();
}