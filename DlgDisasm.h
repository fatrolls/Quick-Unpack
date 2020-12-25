#pragma once

#include "afxwin.h"

class CDlgDisasm:public CDialog
{
	DECLARE_DYNAMIC(CDlgDisasm)

public:
	CDlgDisasm();
	virtual ~CDlgDisasm();
	BOOL OnInitDialog();
	void Disasm();
	void *pAddr;
	DWORD_PTR AltAddress;

	enum {IDD=IDD_DLG_DISASM};

protected:
	virtual void DoDataExchange(CDataExchange *pDX);

public:
	CListBox DisasmList;
};