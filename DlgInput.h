#pragma once

#include "afxwin.h"

class CDlgInput:public CDialog
{
	DECLARE_DYNAMIC(CDlgInput)

public:
	CDlgInput(TSTRING *n_pName,const TCHAR *szCaption,const TCHAR *szDefault);
	afx_msg void DoUpdateData();
	BOOL OnInitDialog();
	void OnOK();

	enum {IDD=IDD_DLG_INPUT};
protected:
	DECLARE_MESSAGE_MAP()
	virtual void DoDataExchange(CDataExchange *pDX);
	TSTRING *pName,sCaption,sDefault;
	CString sValue;
};