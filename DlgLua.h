#pragma once

#include "afxcmn.h"
#include "Main.h"

unsigned int __stdcall ScriptThread(void *pInitData);

class CDlgLua:public CDialog
{
	DECLARE_DYNAMIC(CDlgLua)

public:
	HANDLE hTimerThread,hInitialEvent,hTimerEvent;
	DWORD dwTimerTimeout;

	CDlgLua(CInitData *pInitData);
	virtual ~CDlgLua();
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange *pDX);
	afx_msg void OnBnClickedLoad();
	afx_msg void OnBnClickedSave();
	afx_msg void OnBnClickedRun();
	afx_msg void OnBnClickedClose();
	afx_msg void OnBnClickedSaveAs();
	afx_msg void OnClose();

	enum {IDD=IDD_DLG_LUA};
protected:
	CString sScript;
	HWND hWndTemp;
	DECLARE_MESSAGE_MAP()
	void UpdateScript();
};