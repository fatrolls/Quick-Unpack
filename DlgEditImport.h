#pragma once

#include "afxcmn.h"
#include "afxwin.h"
#include "DlgDisasm.h"
#include "PEFile.h"

class CDlgEditImport:public CDialog
{
	DECLARE_DYNAMIC(CDlgEditImport)

public:
	CDlgEditImport(CModules *n_pModules,CImportRecord *n_pImportRecord);
	virtual ~CDlgEditImport();

	enum {IDD=IDD_DLG_EDITIMPORT};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl ImportList;
	afx_msg void OnBnClickedOK();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnCbnSelchangeCombo1();
	virtual BOOL OnInitDialog();

protected:
	CModules *pModules;
	CImportRecord *pImportRecord;
public:
	CComboBox ModuleName;
	CListBox Functions;
	BOOL PreTranslateMessage(MSG *pMsg);
};