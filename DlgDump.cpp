#include "stdafx.h"
#include "Init.h"
#include "DlgDump.h"

IMPLEMENT_DYNAMIC(CDlgDump,CDialog)
CDlgDump::CDlgDump():CDialog(CDlgDump::IDD,NULL),
	sData(_T(""))
{
}

CDlgDump::~CDlgDump()
{
}

void CDlgDump::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX,IDC_DUMPDATA,sData);
}

BEGIN_MESSAGE_MAP(CDlgDump,CDialog)
	ON_WM_CTLCOLOR()
	ON_BN_CLICKED(IDC_COPYTOCLIPBOARD,OnBnClickedButtonCopyToClipboard)
END_MESSAGE_MAP()

BOOL CDlgDump::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}

HBRUSH CDlgDump::OnCtlColor(CDC *pDC,CWnd *pWnd,UINT nCtlColor)
{
	HBRUSH hbr=CDialog::OnCtlColor(pDC,pWnd,nCtlColor);

	if(pWnd->GetDlgCtrlID()==IDC_CRASHTEXT)
	{
		pDC->SetTextColor(RGB(0,0,0));
		pDC->SetBkColor(RGB(255,255,255));
	}
	return hbr;
}

void CDlgDump::OnBnClickedButtonCopyToClipboard()
{
	OpenClipboard();
	EmptyClipboard();
	HGLOBAL gl=GlobalAlloc(GMEM_MOVEABLE,(sData.GetLength()+1)*sizeof(sData.GetString()[0]));
	_tcscpy_s((TCHAR*)GlobalLock(gl),sData.GetLength()+1,sData.GetString());
	GlobalUnlock(gl);
	SetClipboardData(CF_TEXT,gl);
	CloseClipboard();
}