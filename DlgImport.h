#pragma once

#include "PEFile.h"

class CDlgImport:public CDialog
{
	DECLARE_DYNAMIC(CDlgImport)

public:
	CDlgImport(CImport *n_pImport,CPEFile *n_pPEMain,CModules *n_pModules,const TCHAR *n_szPEFileName,CMain *n_pMain);
	virtual ~CDlgImport();

	enum {IDD=IDD_DLG_IMPORT};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl ImportList;
	virtual BOOL OnInitDialog();

private:
	void ChangeWndHeader();
	void FillImport();
	void FillRecord(int i);
	void FillTable();

	ESortImportType ImportSortType;
	CImport *pImport;
	CPEFile *pPEMain;
	CModules *pModules;
	const TCHAR *szPEFileName;
	CMain *pMain;
	CString sImpRVAbox;
public:
	afx_msg void DoUpdateData();
	afx_msg void OnBnClickedUseOldIAT();
	afx_msg void OnBnClickedSaveOriginal();
	afx_msg void OnBnClickedDeleteSelected();
	afx_msg void OnBnClickedDeleteInvalid();
	afx_msg void OnBnClickedExport();
	afx_msg void OnBnClickedImpEdit();
	afx_msg void OnBnClickedImpLoadLib();
	afx_msg void OnBnClickedImport();
	afx_msg void OnBnClickedImpDisasm();
	afx_msg void OnNMCustomdrawImportlist(NMHDR *pNMHDR,LRESULT *pResult);
	afx_msg void OnItemChangedImportlist(NMHDR *pNMHDR,LRESULT *pResult);
	afx_msg void OnBnClickedChangeSort();
	afx_msg void OnBnClickedPrevForw();
	afx_msg void OnBnClickedNextForw();
	afx_msg void OnBnClickedPrevFunc();
	afx_msg void OnBnClickedNextFunc();
};
