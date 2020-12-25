#pragma once

#include "afxcmn.h"

class CDlgLicense:public CDialog
{
	DECLARE_DYNAMIC(CDlgLicense)

public:
	CString sLicense;
	CDlgLicense(bool n_fEnableButton);
	virtual ~CDlgLicense();
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedOK();
	afx_msg void OnTimer(UINT_PTR nIDEvent);

	enum {IDD=IDD_DLG_LICENSE};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

	bool fEnableButton;
	DECLARE_MESSAGE_MAP()
};