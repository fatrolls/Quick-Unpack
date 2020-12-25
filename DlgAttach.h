#pragma once

#include "afxcmn.h"
#include "PEFile.h"
#include "DlgDisasm.h"
#include "afxwin.h"

class CDlgAttach:public CDialog
{
	friend class CDlgMain;

	DECLARE_DYNAMIC(CDlgAttach)

public:
	CDlgAttach(CModules *n_pAttModules,DWORD *n_pPID,DWORD_PTR *n_pImageBase,DWORD *n_pTID);
	virtual ~CDlgAttach();

	enum {IDD=IDD_DLG_ATTACH};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl ImportList;
	virtual BOOL OnInitDialog();
	void RefreshProcesses();
private:
	CModules *pAttModules;
	DWORD_PTR *pImageBase;
	DWORD *pPID,*pTID;
public:
	CListBox ProcessName;
	CListBox Modules;
	afx_msg void OnLbnDblclkListModules();
	afx_msg void OnLbnSelchangeListProcesses();
};
