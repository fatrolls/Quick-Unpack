#pragma once

#include "afxwin.h"

class CDlgFinders:public CDialog
{
	DECLARE_DYNAMIC(CDlgFinders)

public:
	CDlgFinders(bool n_fIsDll);
	~CDlgFinders();

	enum {IDD=IDD_DLG_FINDERS};

protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange *pDX);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnLbnDblclkOepfindersbox();
};

void LoadOEPFinders(HWND hWnd);
void UnloadOEPFinders();
void ProcessOEPFinder(TCHAR *szDllName);