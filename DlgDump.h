#pragma once

class CDlgDump:public CDialog
{
	DECLARE_DYNAMIC(CDlgDump)

public:
	CDlgDump();
	virtual BOOL OnInitDialog();
	virtual ~CDlgDump();

	enum {IDD=IDD_DLG_DUMP};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

	DECLARE_MESSAGE_MAP()
public:
	afx_msg HBRUSH OnCtlColor(CDC *pDC,CWnd *pWnd,UINT nCtlColor);
	afx_msg void OnBnClickedButtonCopyToClipboard();
	CString sData;
};
