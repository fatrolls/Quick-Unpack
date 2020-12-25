#pragma once

#include "afxcmn.h"
#include "afxwin.h"
#include "Init.h"
#include "EngineHandler.h"
#include "Main.h"
#include "DlgDisasm.h"

struct OPTIONS
{
	bool fAlwaysOnTop;
	bool fShowLicense;
	TCHAR szCurrDir[MAX_PATH];
	TCHAR szLang[MAX_PATH];
	TCHAR szDrvName[17];
	TCHAR szSymbLinkName[17];
};

class CDlgMain:public CDialog
{
public:
#ifdef DLLFILE
	HMODULE hForce;
	CDlgMain(TCHAR *szPath);
	~CDlgMain();
#else
	CDlgMain();
#endif

	enum {IDD=IDD_DLG_MAIN};

	HICON hIcon;
	CRichEditCtrl RichEdit;
	CFont Font;

	OPTIONS Option;
	CString sCutModuleBox,sModEndBox,sOEPbox,sParamBox,sTimeDeltabox;
	BOOL fAppendOverlay,fAutosaveLog,fDelphiInit,fDirectRefs,fExecuteFunc,fForce,fLeaveDirectRefs,fLongImport,fPathToLibs,fProtectDr,fRelocs,fRemoveSect,fSuspectFunc,fUseTf;

	bool fExit;
	HANDLE hMainThread;
	CInitData InitData;
	std::vector<CString> Localization;
	BOOL fSecret;

	void ClearLog();
	void SaveLogToFile(const TCHAR *szFileName,bool fAnnounceSize);
	void SaveLog();
	void WriteEx(CString sLine,BOOL fDoBreak,BOOL fBold,COLORREF Color);
	void Write(const CString &sLine);
	void WriteLn(const CString &sLine);
	void WriteTime();
	void WriteLog(const CString &sLine);
	void ProcessString(std::vector<CString> &StrArray,CString sString);
	CString LocalizeString(CString sName,bool fForward);
	void Localize(bool fForward);
	void LoadLocalization();

	afx_msg void OnBnClickedOpen();
	afx_msg void OnBnClickedAttach();
	afx_msg void OnBnClickedUnpack();
	afx_msg void OnBnClickedKill();
	afx_msg void OnBnClickedFindOEP();
#ifndef DLLFILE
	DECLARE_MESSAGE_MAP()
	virtual void DoDataExchange(CDataExchange *pDX);
	afx_msg void DoUpdateData();
	afx_msg void OnClose();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	virtual LRESULT WindowProc(UINT message,WPARAM wParam,LPARAM lParam);
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedChangeEngine();
	afx_msg void OnBnClickedScript();
	afx_msg void OnBnClickedTest();
	afx_msg void OnBnClickedFindObject();
	afx_msg void OnBnClickedUnpDel();
	afx_msg void OnBnClickedExit();
	afx_msg void OnBnClickedDisasm();
	afx_msg void OnBnClickedFindDelta();
	afx_msg void OnOptionsPreferences();
	afx_msg void OnAboutLicenseAgreement();
	afx_msg void OnAboutAbout();
	void BlockButtonsAndMenus(BOOL fEnable);
	void SetDLLUnpackingMode(BOOL fIsDll);
#endif
};
extern CDlgMain *pDlgMain;

extern OPTIONS *pOptions;
void ClearLog();
void WriteEx(CString sLine,BOOL fDoBreak,BOOL fBold,COLORREF Color);
void Write(const CString &sLine);
void WriteLn(const CString &sLine);
void WriteTime();
void WriteLog(const CString &sLine);