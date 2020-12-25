#pragma once

#include "afxwin.h"
#include ".\\effects\\Picture.h"

class CDlgAbout:public CDialog
{
	DECLARE_DYNAMIC(CDlgAbout)

public:
	CDlgAbout();
	CPicture Picture;
	virtual ~CDlgAbout();
	BOOL fSecret;

	enum {IDD=IDD_DLG_ABOUT};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

	DECLARE_MESSAGE_MAP()
public:
	BOOL OnInitDialog();
	afx_msg void OnDestroy();
	afx_msg void OnBnClickedOk();
	afx_msg void OnPaint();
	void ConvertStaticToHyperlink(HWND hWndCtl);
};