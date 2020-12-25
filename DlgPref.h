#pragma once

#include "afxwin.h"

class CDlgPref:public CDialog
{
	DECLARE_DYNAMIC(CDlgPref)

public:
	CDlgPref();
	virtual ~CDlgPref();

	enum {IDD=IDD_DLG_PREF};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);
	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedSavePref();
	CComboBox Lang;
};