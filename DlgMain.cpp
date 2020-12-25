#include "stdafx.h"
#include "intrin.h"
#include "Init.h"
#include "DlgMain.h"
#include "Main.h"
#ifndef DLLFILE
#include "DlgAbout.h"
#include "DlgAttach.h"
#include "DlgLicense.h"
#include "DlgLua.h"
#include "DlgFinders.h"
#include "Imagehlp.h"
#include "DlgPref.h"
#endif
#include "RegistryKey.h"

#include ".\\Disasm\\mediana.h"

typedef DWORD (__stdcall *_GetDllOEPNow)(const TCHAR *szFileName);
_GetDllOEPNow GetDllOEPNow;
typedef DWORD (__stdcall *_GetOEPNow)(const TCHAR *szFileName);
_GetOEPNow GetOEPNow;

bool fDropped;
TSTRING sDropName;
HMODULE hDllHandle=NULL;
CMenu MenuFind;

const int nTimerID=1;

bool IsHEX(const TCHAR *szValue)
{
	for(size_t i=0;i!=_tcslen(szValue);++i)
	{
		if((szValue[i]>=_T('0') && szValue[i]<=_T('9')) ||
			(szValue[i]>=_T('a') && szValue[i]<=_T('f')) ||
			(szValue[i]>=_T('A') && szValue[i]<=_T('F')))
			{}
		else
			return false;
	}
	return true;
}

CDlgMain *pDlgMain=NULL;

void ClearLog()
{
	if(pDlgMain!=NULL)
		pDlgMain->ClearLog();
}

void WriteEx(CString Line,BOOL fDoBreak,BOOL fBold,COLORREF Color)
{
	if(pDlgMain!=NULL)
		pDlgMain->WriteEx(Line,fDoBreak,fBold,Color);
}

void Write(const CString &sLine)
{
	if(pDlgMain!=NULL)
		pDlgMain->Write(sLine);
}

void WriteLn(const CString &sLine)
{
	if(pDlgMain!=NULL)
		pDlgMain->WriteLn(sLine);
}

void WriteTime()
{
	if(pDlgMain!=NULL)
		pDlgMain->WriteTime();
}

void WriteLog(const CString &sLine)
{
	if(pDlgMain!=NULL)
		pDlgMain->WriteLog(sLine);
}

bool CheckCall(uint8_t *Address,DISASM_PARAMS &Params,int nLength)
{
	INSTRUCTION Instr;
	if(medi_disassemble(Address,BUFSIZ_INFINITY,&Instr,&Params)!=DASM_ERR_OK)
		return false;
	if(Instr.length!=nLength || Instr.id!=ID_CALL || Instr.ops[0].size!=sizeof(DWORD_PTR))
		return false;
	if((Instr.ops[0].flags & OPERAND_TYPE_MASK)!=OPERAND_TYPE_REG && (Instr.ops[0].flags & OPERAND_TYPE_MASK)!=OPERAND_TYPE_MEM)
		return false;
	if((Instr.ops[0].flags & OPERAND_TYPE_MASK)==OPERAND_TYPE_MEM && Instr.addrsize!=sizeof(DWORD_PTR))
		return false;
	return true;
}

void GetLoadLibraryAddress()
{
	TCHAR cBuff[MAX_PATH];

	GetModuleFileName(hDllHandle,cBuff,_countof(cBuff));
	PathToDir(cBuff);
	_tcscat_s(cBuff,_T("\\GetLoadDll.dll"));

	typedef DWORD_PTR (__stdcall *_GetLoadLibrary)();
	_GetLoadLibrary GetLoadLibrary;

	HMODULE hDll=LoadLibrary(cBuff);
	GetLoadLibrary=(_GetLoadLibrary)GetProcAddress(hDll,"GetLoadDllAddress");
	if(hDll==NULL || GetLoadLibrary==NULL)
		LoadLibraryAddress=0;
	else
		LoadLibraryAddress=GetLoadLibrary();
	FreeLibrary(hDll);

	if(LoadLibraryAddress!=0)
	{
		DISASM_PARAMS Params;
		Params.arch=ARCH_ALL;
		Params.sf_prefixes=NULL;
#if defined _M_AMD64
		Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
		Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
		int i=1;
		for(;i!=MAX_INSTRUCTION_LEN;++i)
		{
			if(CheckCall((uint8_t*)LoadLibraryAddress-i,Params,i))
			{
				if(CheckCall((uint8_t*)LoadLibraryAddress-i-1,Params,i+1))
					++i;
				break;
			}
		}
		if(i==MAX_INSTRUCTION_LEN)
			LoadLibraryAddress=0;
		else
			LoadLibraryAddress-=i;
	}
	if(LoadLibraryAddress==0)
		MessageBox(NULL,_T("Bad LoadDll address"),_T("QuickUnpack"),MB_OK);
}

#ifdef DLLFILE
CDlgMain::CDlgMain(TCHAR *szPath)
{
	TCHAR cBuff[MAX_PATH];

	GetModuleFileName(hDllHandle,cBuff,_countof(cBuff));
	PathToDir(cBuff);
	_tcscat_s(cBuff,_T("\\Force.dll"));

	hForce=LoadLibrary(cBuff);

	GetDllOEPNow=(_GetDllOEPNow)GetProcAddress(hForce,"GetDllOEPNow");
	GetOEPNow=(_GetOEPNow)GetProcAddress(hForce,"GetOEPNow");

	hMainThread=NULL;
	fExit=false;

	InitData.hMain=m_hWnd;

	size_t i=_tcslen(szPath)-1;
	for(;i>=0 && szPath[i]!=_T('\\');--i);
	InitData.sVictimFile=szPath;
	InitData.sVictimName=szPath+i+1;
	for(i=_tcslen(szPath)-1;i>=0 && szPath[i]!=_T('.');--i);
	InitData.sUnpackedLong=InitData.sVictimFile;
	InitData.sUnpackedLong.insert(i,_T("_unpacked"));

	GetLoadLibraryAddress();
}

CDlgMain::~CDlgMain()
{
	FreeLibrary(hForce);
}

__declspec(dllexport) DWORD __stdcall UnPack(TCHAR *szPath,DWORD dwTimeout)
{
	CDlgMain dialog(szPath);
	pDlgMain=&dialog;
	dialog.OnBnClickedOpen();
	dialog.OnBnClickedFindOEP();
	if(dialog.sOEPbox.IsEmpty() || !IsHEX(dialog.sOEPbox.GetString()) || _tcstoul(dialog.sOEPbox.GetString(),NULL,16)==0)
		return 1;
	dialog.OnBnClickedUnpack();
	if(WaitForSingleObject(dialog.hMainThread,dwTimeout)!=WAIT_OBJECT_0)
	{
		dialog.OnBnClickedKill();
		WaitForSingleObject(dialog.hMainThread,INFINITE);
		return 2;
	}
	if(!PathFileExists(dialog.InitData.sUnpackedFile.c_str()))
		return 3;

	return 0;
}

bool __stdcall DllMain(HANDLE hInstDLL,DWORD dwReason,void*)
{
	if(dwReason==DLL_PROCESS_ATTACH)
	{
		hDllHandle=(HMODULE)hInstDLL;
		DisableThreadLibraryCalls(hDllHandle);
	}
	return true;
}
#else
CDlgMain::CDlgMain():CDialog(CDlgMain::IDD,NULL),
	sCutModuleBox(_T("00000000")),
	sModEndBox(_T("00000000")),
	sTimeDeltabox(_T("00000000")),
	sOEPbox(_T("")),
	sParamBox(_T("")),
	fAppendOverlay(FALSE),
	fAutosaveLog(FALSE),
	fDelphiInit(FALSE),
	fDirectRefs(FALSE),
	fExecuteFunc(FALSE),
	fForce(FALSE),
	fLeaveDirectRefs(FALSE),
	fLongImport(TRUE),
	fPathToLibs(FALSE),
	fProtectDr(TRUE),
	fRelocs(TRUE),
	fRemoveSect(FALSE),
	fSuspectFunc(FALSE),
	fUseTf(TRUE)
{
	hIcon=AfxGetApp()->LoadIcon(IDR_MAINICON);
	GetLoadLibraryAddress();
}
#endif

void CDlgMain::ClearLog()
{
	RichEdit.SendMessage(WM_SETTEXT,0,(LPARAM)_T(""));
	WriteEx(ver,FALSE,TRUE,RGB(0,0,0));
	WriteLn(_T(""));
	Write(cop1);
	WriteLn(_T(""));
	Write(cop2);
	WriteLn(_T(""));
}

void CDlgMain::SaveLogToFile(const TCHAR *szFileName,bool fAnnounceSize)
{
	int nTemp;
	GETTEXTLENGTHEX Len;
	CString sString;

	Len.flags=GTL_NUMCHARS | GTL_PRECISE;
	Len.codepage=CP_ACP;
	nTemp=(int)RichEdit.SendMessage(EM_GETTEXTLENGTHEX,(WPARAM)&Len,0);
	++nTemp;

	CHARRANGE OldRange,NewRange;
	RichEdit.SendMessage(EM_EXGETSEL,0,(LPARAM)&OldRange);
	NewRange.cpMin=0;
	NewRange.cpMax=-1;
	RichEdit.SendMessage(EM_EXSETSEL,0,(LPARAM)&NewRange);

	TCHAR *szString=new TCHAR[nTemp];
	memset(szString,0,nTemp*sizeof(szString[0]));
	RichEdit.SendMessage(EM_GETSELTEXT,0,(LPARAM)szString);
	sString=szString;
	delete[] szString;
	RichEdit.SendMessage(EM_EXSETSEL,0,(LPARAM)&OldRange);

	HANDLE hFile=CreateFile(szFileName,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
		MessageBox(cantopen,_T("QuickUnpack"),MB_OK);
	else
	{
		sString.Replace(_T("\xd"),_T("\xd\xa"));
		DWORD dwBytesWritten;
		WriteFile(hFile,sString.GetString(),sString.GetLength()*sizeof(sString.GetString()[0]),&dwBytesWritten,NULL);
		CloseHandle(hFile);
		if(fAnnounceSize)
			MessageBox(logsaved1+_T("\r\n")+logsaved2+IntToStr(sString.GetLength()*sizeof(sString.GetString()[0]),10,0)+bytes,_T("QuickUnpack"),MB_OK+MB_ICONINFORMATION);
	}
}

void CDlgMain::SaveLog()
{
	TCHAR szCurrDir[MAX_PATH],szLogDir[MAX_PATH];
	
	GetCurrentDirectory(_countof(szCurrDir),szCurrDir);

	GetModuleFileName(NULL,szLogDir,_countof(szLogDir));
	PathToDir(szLogDir);
	_tcscat_s(szLogDir,_T("\\Logs"));

	TCHAR szFileName[MAX_PATH]=_T("log");
	OPENFILENAME ofn;
	memset(&ofn,0,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=GetSafeHwnd();
	ofn.lpstrDefExt=_T("txt");
	ofn.Flags=OFN_OVERWRITEPROMPT|OFN_HIDEREADONLY;
	ofn.lpstrFilter=_T("txt files\0*.txt\0");
	ofn.lpstrInitialDir=szLogDir;
	ofn.lpstrFile=szFileName;
	ofn.nMaxFile=_countof(szFileName);

	if(GetSaveFileName(&ofn))
		SaveLogToFile(ofn.lpstrFile,true);

	SetCurrentDirectory(szCurrDir);
}

void CDlgMain::WriteEx(CString sLine,BOOL fDoBreak,BOOL fBold,COLORREF Color)
{
	int nOldLines=0,nNewLines=0,nScroll=0;
	CHARFORMAT CharFormat,OldCharFormat;
	nOldLines=RichEdit.GetLineCount();
	OldCharFormat.cbSize=sizeof(OldCharFormat);

	RichEdit.GetDefaultCharFormat(OldCharFormat);
	CharFormat.cbSize=sizeof(CharFormat);
	CharFormat.dwMask=CFM_COLOR;
	CharFormat.dwEffects=0;
	if(fBold)
	{
		CharFormat.dwMask|=CFM_BOLD;
		CharFormat.dwEffects=CFE_BOLD;
	}
	if(fDoBreak)
		sLine=_T("\r\n")+sLine;
	CharFormat.crTextColor=Color;
	RichEdit.SetSel(RichEdit.GetWindowTextLength(),-1);
	RichEdit.SetSelectionCharFormat(CharFormat);
	sLine.GetBufferSetLength(sLine.GetLength()+4);
	RichEdit.ReplaceSel(sLine);
	RichEdit.SetSelectionCharFormat(OldCharFormat);
	nNewLines=RichEdit.GetLineCount();
	nScroll=nNewLines-nOldLines;
	RichEdit.LineScroll(nScroll);

	if(InitData.fAutosaveLog && nNewLines>=5000)
	{
		TCHAR szCurrFileName[MAX_PATH],szLogFileName[MAX_PATH];
		GetModuleFileName(hDllHandle,szCurrFileName,_countof(szCurrFileName));
		ExtractFilePath(szLogFileName,_countof(szLogFileName),szCurrFileName);
		_tcscat_s(szLogFileName,_T("\\Logs\\"));

		CString sLogName;
		for(DWORD i=1;i!=0;++i)
		{
			sLogName=szLogFileName;
			sLogName=sLogName+_T("log")+IntToStr(i,10,0)+_T(".txt");
			if(!PathFileExists(sLogName))
				break;
		}
		SaveLogToFile(sLogName.GetBuffer(),false);
		ClearLog();
	}
}

void CDlgMain::Write(const CString &sLine)
{
	WriteEx(sLine,FALSE,FALSE,0);
}

void CDlgMain::WriteLn(const CString &sLine)
{
	Write(_T("\r\n")+sLine);
}

void CDlgMain::WriteTime()
{
	Write(CTime::GetCurrentTime().Format(_T("%H:%M:%S")));
}

void CDlgMain::WriteLog(const CString &sLine)
{
	WriteLn(_T(""));WriteTime();Write(_T(" - ")+sLine);
}

void CDlgMain::ProcessString(std::vector<CString> &StrArray,CString sString)
{
	int nNewPos,nPos;

	nPos=sString.Find(_T('!'));
	StrArray.push_back(sString.Mid(0,nPos));

	nNewPos=sString.Find(_T("=="),nPos);
	StrArray.push_back(sString.Mid(nPos+1,(nNewPos-nPos)-1));

	nPos=sString.Find(_T('!'),nNewPos);
	StrArray.push_back(sString.Mid(nNewPos+2,(nPos-nNewPos)-2));

	StrArray.push_back(sString.Mid(sString.Find(_T('!'),nNewPos)+1));
}

CString CDlgMain::LocalizeString(CString sName,bool fForward)
{
	int nIter=0;
	size_t nCountOf=Localization.size()/2;

	for(size_t i=0;i!=nCountOf;++i)
	{
		if(fForward)
		{
			if(sName==Localization[i+nIter])
				return Localization[i+nIter+1];
		}
		else
		{
			if(sName==Localization[i+nIter+1])
				return Localization[i+nIter];
		}
		++nIter;
	}
	return sName;
}

void CDlgMain::Localize(bool fForward)
{
	attachedto=LocalizeString(attachedto,fForward);
	cantload=LocalizeString(cantload,fForward);
	cantopen=LocalizeString(cantopen,fForward);
	choosefile=LocalizeString(choosefile,fForward);
	cop1=LocalizeString(cop1,fForward);
	cop2=LocalizeString(cop2,fForward);
	findtarget=LocalizeString(findtarget,fForward);
	findunpacked=LocalizeString(findunpacked,fForward);
	incorroep=LocalizeString(incorroep,fForward);
	invalidpe=LocalizeString(invalidpe,fForward);
	logsaved1=LocalizeString(logsaved1,fForward);
	logsaved2=LocalizeString(logsaved2,fForward);
	notmemory=LocalizeString(notmemory,fForward);
	opened=LocalizeString(opened,fForward);
	someoep=LocalizeString(someoep,fForward);
	switchfailed=LocalizeString(switchfailed,fForward);
	switchedtonormal=LocalizeString(switchedtonormal,fForward);
	switchedtovmm=LocalizeString(switchedtovmm,fForward);
	unpdeleted=LocalizeString(unpdeleted,fForward);
	unpnotfound=LocalizeString(unpnotfound,fForward);
	ver=LocalizeString(ver,fForward);
	withpid=LocalizeString(withpid,fForward);

	CString sTemp;
	GetDlgItemText(IDC_EXIT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_EXIT,sTemp);
	GetDlgItemText(IDC_CHANGEENGINE,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_CHANGEENGINE,sTemp);
	GetDlgItemText(IDC_OPENFILE,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_OPENFILE,sTemp);
	GetDlgItemText(IDC_UNPACK,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_UNPACK,sTemp);
	GetDlgItemText(IDC_APPOVERLAY,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_APPOVERLAY,sTemp);
	GetDlgItemText(IDC_ATTACH,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_ATTACH,sTemp);
	GetDlgItemText(IDC_CLEARLOG,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_CLEARLOG,sTemp);
	GetDlgItemText(IDC_DELPHIINIT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_DELPHIINIT,sTemp);
	GetDlgItemText(IDC_DISASM,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_DISASM,sTemp);
	GetDlgItemText(IDC_EXECFUNC,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_EXECFUNC,sTemp);
	GetDlgItemText(IDC_FINDOBJECT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_FINDOBJECT,sTemp);
	GetDlgItemText(IDC_USEFORCE,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_USEFORCE,sTemp);
	GetDlgItemText(IDC_IMPREC_SMART,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_IMPREC_SMART,sTemp);
	GetDlgItemText(IDC_IMPREC_TRACER,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_IMPREC_TRACER,sTemp);
	GetDlgItemText(IDC_IMPREC_NONE,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_IMPREC_NONE,sTemp);
	GetDlgItemText(IDC_IMPREC_LIBSONLY,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_IMPREC_LIBSONLY,sTemp);
	GetDlgItemText(IDC_KILL,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_KILL,sTemp);
	GetDlgItemText(IDC_PROTECTDR,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_PROTECTDR,sTemp);
	GetDlgItemText(IDC_RELOCS,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_RELOCS,sTemp);
	GetDlgItemText(IDC_REMSECT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_REMSECT,sTemp);
	GetDlgItemText(IDC_USESCRIPT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_USESCRIPT,sTemp);
	GetDlgItemText(IDC_DIRECTREFS,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_DIRECTREFS,sTemp);
	GetDlgItemText(IDC_LEAVEDIRECTREFS,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_LEAVEDIRECTREFS,sTemp);
	GetDlgItemText(IDC_STATICOPTIONS,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICOPTIONS,sTemp);
	GetDlgItemText(IDC_STATICOEP,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICOEP,sTemp);
	GetDlgItemText(IDC_STATICIMPORT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICIMPORT,sTemp);
	GetDlgItemText(IDC_STATICENDMODULE,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICENDMODULE,sTemp);
	GetDlgItemText(IDC_STATICDELTA,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICDELTA,sTemp);
	GetDlgItemText(IDC_STATICPARAMS,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICPARAMS,sTemp);
	GetDlgItemText(IDC_STATICCUTAT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_STATICCUTAT,sTemp);
	GetDlgItemText(IDC_SUSPFUNC,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_SUSPFUNC,sTemp);
	GetDlgItemText(IDC_TEST,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_TEST,sTemp);
	GetDlgItemText(IDC_UNPDEL,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_UNPDEL,sTemp);
	GetDlgItemText(IDC_USETF,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_USETF,sTemp);
	GetDlgItemText(IDC_LONGIMPORT,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_LONGIMPORT,sTemp);
	GetDlgItemText(IDC_PATHLIBS,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_PATHLIBS,sTemp);
	GetDlgItemText(IDC_AUTOSAVELOG,sTemp); sTemp=LocalizeString(sTemp,fForward); SetDlgItemText(IDC_AUTOSAVELOG,sTemp);

	CMenu *pMainMenu=GetMenu();
	pMainMenu->GetMenuString(ID_MENU_EXIT,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(ID_MENU_EXIT,MF_STRING,ID_MENU_EXIT,sTemp);
	pMainMenu->GetMenuString(ID_MENU_CLEARLOG,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(ID_MENU_CLEARLOG,MF_STRING,ID_MENU_CLEARLOG,sTemp);
	pMainMenu->GetMenuString(ID_MENU_SAVELOG,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(ID_MENU_SAVELOG,MF_STRING,ID_MENU_SAVELOG,sTemp);
	pMainMenu->GetMenuString(ID_MENU_PREF,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(ID_MENU_PREF,MF_STRING,ID_MENU_PREF,sTemp);
	pMainMenu->GetMenuString(ID_MENU_LICENSE,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(ID_MENU_LICENSE,MF_STRING,ID_MENU_LICENSE,sTemp);
	pMainMenu->GetMenuString(ID_MENU_ABOUT,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(ID_MENU_ABOUT,MF_STRING,ID_MENU_ABOUT,sTemp);

	pMainMenu->GetMenuString(0,sTemp,MF_BYPOSITION); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(0,MF_STRING | MF_BYPOSITION,0,sTemp);
	pMainMenu->GetMenuString(1,sTemp,MF_BYPOSITION); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(1,MF_STRING | MF_BYPOSITION,1,sTemp);
	pMainMenu->GetMenuString(2,sTemp,MF_BYPOSITION); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(2,MF_STRING | MF_BYPOSITION,2,sTemp);
	pMainMenu->GetMenuString(3,sTemp,MF_BYPOSITION); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(3,MF_STRING | MF_BYPOSITION,3,sTemp);
	pMainMenu->GetMenuString(4,sTemp,MF_BYPOSITION); sTemp=LocalizeString(sTemp,fForward);
	pMainMenu->ModifyMenu(4,MF_STRING | MF_BYPOSITION,4,sTemp);

	MenuFind.GetMenuString(ID_FINDTARGET,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	MenuFind.ModifyMenu(ID_FINDTARGET,MF_STRING,ID_FINDTARGET,sTemp);
	MenuFind.GetMenuString(ID_FINDUNPACKED,sTemp,MF_BYCOMMAND); sTemp=LocalizeString(sTemp,fForward);
	MenuFind.ModifyMenu(ID_FINDUNPACKED,MF_STRING,ID_FINDUNPACKED,sTemp);

	bytes=LocalizeString(bytes,fForward);
	importtableheader=LocalizeString(importtableheader,fForward);
	importtablebyname=LocalizeString(importtablebyname,fForward);
	importtablebyrec=LocalizeString(importtablebyrec,fForward);
	importtablebyref=LocalizeString(importtablebyref,fForward);
	importtableok=LocalizeString(importtableok,fForward);
	importtableerror=LocalizeString(importtableerror,fForward);
	exporttofile=LocalizeString(exporttofile,fForward);
	function=LocalizeString(function,fForward);
	importempty=LocalizeString(importempty,fForward);
	importexported1=LocalizeString(importexported1,fForward);
	importexported2=LocalizeString(importexported2,fForward);
	library=LocalizeString(library,fForward);
	name=LocalizeString(name,fForward);
	no=LocalizeString(no,fForward);
	yes=LocalizeString(yes,fForward);
	noname=LocalizeString(noname,fForward);
	notfound=LocalizeString(notfound,fForward);
	ordinal=LocalizeString(ordinal,fForward);
	problem=LocalizeString(problem,fForward);
	referencerva=LocalizeString(referencerva,fForward);
	recordrva=LocalizeString(recordrva,fForward);

	badfunction=LocalizeString(badfunction,fForward);
	badloading=LocalizeString(badloading,fForward);
	badtracing=LocalizeString(badtracing,fForward);
	breaked=LocalizeString(breaked,fForward);
	cantdump=LocalizeString(cantdump,fForward);
	closeloaded=LocalizeString(closeloaded,fForward);
	delphiinitfailed=LocalizeString(delphiinitfailed,fForward);
	delphiinitok=LocalizeString(delphiinitok,fForward);
	dumping=LocalizeString(dumping,fForward);
	exceptionat=LocalizeString(exceptionat,fForward);
	falsedetected=LocalizeString(falsedetected,fForward);
	forceactivated=LocalizeString(forceactivated,fForward);
	from=LocalizeString(from,fForward);
	importonlylibs=LocalizeString(importonlylibs,fForward);
	importusedsmart=LocalizeString(importusedsmart,fForward);
	importusedtracer=LocalizeString(importusedtracer,fForward);
	importwasnt=LocalizeString(importwasnt,fForward);
	loaded=LocalizeString(loaded,fForward);
	loadingtarget=LocalizeString(loadingtarget,fForward);
	module=LocalizeString(module,fForward);
	noimportfound=LocalizeString(noimportfound,fForward);
	overlayappended=LocalizeString(overlayappended,fForward);
	overlayexists=LocalizeString(overlayexists,fForward);
	processinglibs=LocalizeString(processinglibs,fForward);
	processingsmart=LocalizeString(processingsmart,fForward);
	processingtracer=LocalizeString(processingtracer,fForward);
	relocations=LocalizeString(relocations,fForward);
	sectionsdirs=LocalizeString(sectionsdirs,fForward);
	targetloaded=LocalizeString(targetloaded,fForward);
	threadcreated=LocalizeString(threadcreated,fForward);
	unpackednotcreated=LocalizeString(unpackednotcreated,fForward);
	unpackedsaved=LocalizeString(unpackedsaved,fForward);
	unpackfinished=LocalizeString(unpackfinished,fForward);

	processingfunction=LocalizeString(processingfunction,fForward);

	cantterminate=LocalizeString(cantterminate,fForward);

	exporthooked=LocalizeString(exporthooked,fForward);
	importhooked=LocalizeString(importhooked,fForward);
	exportunhooked=LocalizeString(exportunhooked,fForward);

	editfunction=LocalizeString(editfunction,fForward);
	ord2=LocalizeString(ord2,fForward);

	cantluastate=LocalizeString(cantluastate,fForward);
	errorreadingmem=LocalizeString(errorreadingmem,fForward);
	luascripting=LocalizeString(luascripting,fForward);
	scriptfinished=LocalizeString(scriptfinished,fForward);

	ClearLog();
}

void CDlgMain::LoadLocalization()
{
	TCHAR cBuff[MAX_PATH]={_T('\0')};
	HANDLE hFile;
	int nLen=0;

	Localization.clear();
	if(_tcsicmp(Option.szLang,_T("english.lng"))==0)
		return;

	GetModuleFileName(NULL,cBuff,_countof(cBuff));
	PathToDir(cBuff);
	_tcscat_s(cBuff,_T("\\"));
	_tcscat_s(cBuff,Option.szLang);

	hFile=CreateFile(cBuff,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		MessageBox(_T("Couldn't load language file!"),_T("QuickUnpack"),MB_OK);
		return;
	}
	CString sLocalization;
	DWORD dwFileSize=GetFileSize(hFile,NULL);
	BYTE *bLocalization=new BYTE[dwFileSize];
	DWORD dwBytesRead;
	ReadFile(hFile,bLocalization,dwFileSize,&dwBytesRead,NULL);
	if(IsTextUnicode(bLocalization,dwFileSize,NULL) && *(WORD*)bLocalization==UNICODE_MAGIC)
	{
		dwFileSize-=sizeof(UNICODE_MAGIC);
		memmove(bLocalization,bLocalization+sizeof(UNICODE_MAGIC),dwFileSize);
	}
#ifdef UNICODE
	if(!IsTextUnicode(bLocalization,dwFileSize,NULL))
	{
		nLen=dwFileSize;
		WCHAR *pWideArray=new WCHAR[nLen];
		MultiByteToWideChar(CP_ACP,0,(char*)bLocalization,nLen,pWideArray,nLen);
		sLocalization.SetString(pWideArray,nLen);
		delete[] pWideArray;
	}
	else
	{
		nLen=dwFileSize/sizeof(WCHAR);
		sLocalization.SetString((WCHAR*)bLocalization,nLen);
	}
#else
	if(IsTextUnicode(bLocalization,dwFileSize,NULL))
	{
		nLen=dwFileSize/sizeof(WCHAR);
		char *pMultiArray=new char[nLen];
		WideCharToMultiByte(CP_ACP,0,(WCHAR*)bLocalization,nLen,pMultiArray,nLen,NULL,NULL);
		sLocalization.SetString(pMultiArray,nLen);
		delete[] pMultiArray;
	}
	else
	{
		nLen=dwFileSize;
		sLocalization.SetString((char*)bLocalization,nLen);
	}
#endif
	CloseHandle(hFile);
	delete[] bLocalization;

	TCHAR *pName;
	TCHAR *p=sLocalization.GetBuffer();
	CString sTemp;
	while(nLen>0)
	{
		while(nLen>0 && (p[0]==0 || p[0]==_T('\n') || p[0]==_T('\r')))
		{
			++p;--nLen;
		}
		pName=p;
		while(nLen>0 && (p[0]!=0 && p[0]!=_T('\n') && p[0]!=_T('\r')))
		{
			++p;--nLen;
		}
		p[0]=_T('\0');
		++p;--nLen;

		sTemp=pName;
		if(pName[0]!=_T(';'))
		{
			Localization.push_back(sTemp.Mid(0,sTemp.Find(_T("=="))));
			Localization.push_back(sTemp.Mid(sTemp.Find(_T("=="))+2));
		}
	}
}

void CDlgMain::OnBnClickedOpen()
{
#ifndef DLLFILE
	if(!fDropped)
	{
		TCHAR szFileName[MAX_PATH];
		OPENFILENAME ofn;
		memset(&ofn,0,sizeof(ofn));
		ofn.lStructSize=sizeof(ofn);
		ofn.hwndOwner=GetSafeHwnd();
		ofn.Flags=OFN_HIDEREADONLY;
		ofn.lpstrFilter=_T("Executable files\0*.cpl;*.dll;*.drv;*.exe;*.ocx;*.scr\0All files\0*.*\0");
		ofn.lpstrInitialDir=Option.szCurrDir;
		ofn.lpstrFile=szFileName;
		ofn.lpstrFile[0]=_T('\0');
		ofn.nMaxFile=_countof(szFileName);

		if(GetOpenFileName(&ofn))
		{
			GetCurrentDirectory(_countof(Option.szCurrDir),Option.szCurrDir);

			InitData.sVictimFile=ofn.lpstrFile;

			std::string::size_type nExtPos=InitData.sVictimFile.rfind(_T('.'));
			if(nExtPos==std::string::npos)
				nExtPos=InitData.sVictimFile.length();

			InitData.sVictimName=InitData.sVictimFile.c_str()+InitData.sVictimFile.rfind(_T('\\'))+1;

			InitData.sUnpackedShort=InitData.sVictimFile;
			InitData.sUnpackedShort.insert(nExtPos,_T("_"));

			InitData.sUnpackedLong=InitData.sVictimFile;
			InitData.sUnpackedLong.insert(nExtPos,_T("__"));

			InitData.UnpackMode=umFull;
			GetDlgItem(IDC_OEPBOX)->EnableWindow(TRUE);
			GetDlgItem(IDC_FINDOEP)->EnableWindow(TRUE);
#endif
			CPEFile VictimFile;
			VictimFile.Read(InitData.sVictimFile.c_str());
			if(VictimFile.IsEmpty())
			{
#ifndef DLLFILE
				WriteEx(cantopen+InitData.sVictimFile.c_str(),TRUE,TRUE,RGB(255,0,0));
#endif
				return;
			}
			if((VictimFile.pPEHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)==IMAGE_FILE_DLL)
				InitData.fIsDll=TRUE;
			else
				InitData.fIsDll=FALSE;
#ifndef DLLFILE
			SetDLLUnpackingMode(InitData.fIsDll);

			WriteLog(opened+ofn.lpstrFile);

			TSTRING sCaption(_T("QuickUnpack 4.3 - "));
			sCaption=sCaption+InitData.sVictimName.c_str();
			SetWindowText(sCaption.c_str());
		}
	}
	else
	{
		fDropped=false;
		InitData.sVictimFile=sDropName;

		std::string::size_type nExtPos=InitData.sVictimFile.rfind(_T('.'));
		if(nExtPos==std::string::npos)
			nExtPos=InitData.sVictimFile.length();

		InitData.sVictimName=InitData.sVictimFile.c_str()+InitData.sVictimFile.rfind(_T('\\'))+1;

		InitData.sUnpackedShort=InitData.sVictimFile;
		InitData.sUnpackedShort.insert(nExtPos,_T("_"));

		InitData.sUnpackedLong=InitData.sVictimFile;
		InitData.sUnpackedLong.insert(nExtPos,_T("__"));

		InitData.UnpackMode=umFull;
		GetDlgItem(IDC_OEPBOX)->EnableWindow(TRUE);
		GetDlgItem(IDC_FINDOEP)->EnableWindow(TRUE);

		CPEFile VictimFile;
		VictimFile.Read(InitData.sVictimFile.c_str());
		if(VictimFile.IsEmpty())
		{
			WriteEx(cantopen+InitData.sVictimFile.c_str(),TRUE,TRUE,RGB(255,0,0));
			return;
		}
		if((VictimFile.pPEHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)==IMAGE_FILE_DLL)
			InitData.fIsDll=TRUE;
		else
			InitData.fIsDll=FALSE;
		SetDLLUnpackingMode(InitData.fIsDll);

		WriteLog(opened+InitData.sVictimName.c_str());

		TSTRING sCaption(_T("QuickUnpack 4.3 - "));
		sCaption=sCaption+InitData.sVictimName.c_str();
		SetWindowText(sCaption.c_str());
	}
	UpdateData(FALSE);
#endif
}

void CDlgMain::OnBnClickedAttach()
{
#ifndef DLLFILE
	DWORD dwPID,dwTID;
	DWORD_PTR ImageBase;
	CModules AttModules;

	CDlgAttach DlgAttach(&AttModules,&dwPID,&ImageBase,&dwTID);
	EnableWindow(FALSE);
	if(DlgAttach.DoModal()==IDOK)
	{
		size_t i=0;
		for(;i!=AttModules.Modules.size();++i)
		{
			if(AttModules.Modules[i]->ModuleBase==ImageBase)
				break;
		}
		InitData.sVictimFile=AttModules.Modules[i]->sFullName;
		InitData.sVictimName=AttModules.Modules[i]->sModuleName;
		for(i=InitData.sVictimFile.length()-1;i>=0;--i)
		{
			if(InitData.sVictimFile[i]==_T('.'))
				break;
		}
		InitData.sUnpackedShort=InitData.sVictimFile;
		InitData.sUnpackedShort.insert(i,_T("_"));
		InitData.sUnpackedLong=InitData.sVictimFile;
		InitData.sUnpackedLong.insert(i,_T("__"));
		InitData.dwPID=dwPID;
		InitData.ImageBase=ImageBase;
		InitData.dwTID=dwTID;
		InitData.UnpackMode=umSkipOEP;

		CPEFile VictimFile;
		VictimFile.Read(InitData.sVictimFile.c_str());
		if(VictimFile.IsEmpty())
		{
			WriteEx(cantopen+InitData.sVictimFile.c_str(),TRUE,TRUE,RGB(255,0,0));
			return;
		}

		if((VictimFile.pPEHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)==IMAGE_FILE_DLL)
			InitData.fIsDll=TRUE;
		else
			InitData.fIsDll=FALSE;

		SetDLLUnpackingMode(InitData.fIsDll);
		GetDlgItem(IDC_DISASM)->EnableWindow(FALSE);
		GetDlgItem(IDC_FINDOEP)->EnableWindow(FALSE);
		GetDlgItem(IDC_USEFORCE)->EnableWindow(FALSE);
		GetDlgItem(IDC_OEPBOX)->EnableWindow(FALSE);
		GetDlgItem(IDC_PARAMSBOX)->EnableWindow(FALSE);
		sParamBox=_T("");

		WriteLog(attachedto+InitData.sVictimName.c_str()+withpid+IntToStr(dwPID,16,sizeof(dwPID)*2));
	}
	EnableWindow(TRUE);
	SetForegroundWindow();
#endif
}

void CDlgMain::OnBnClickedUnpack()
{
	CPEFile VictimFile;
	VictimFile.Read(InitData.sVictimFile.c_str());
#ifdef DLLFILE
	InitData.dwCutModule=VictimFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	InitData.dwImportRVA=0;
	InitData.dwModuleEnd=0;
	InitData.dwOEP=_tcstoul(sOEPbox.GetString(),NULL,16);
	InitData.dwTimeDelta=0;
	InitData.fAppendOverlay=FALSE;
	InitData.fAutosaveLog=FALSE;
	InitData.fDelphiInit=FALSE;
	InitData.fDirectRefs=FALSE;
	InitData.fExecuteFunc=FALSE;
	InitData.fForce=FALSE;
	InitData.fLeaveDirectRefs=FALSE;
	InitData.fLongImport=TRUE;
	InitData.fMemoryManager=FALSE;
	InitData.fPathToLibs=FALSE;
	InitData.fProtectDr=TRUE;
	if(InitData.fIsDll)
		InitData.fRelocs=TRUE;
	else
		InitData.fRelocs=FALSE;
	InitData.fRemoveSect=TRUE;
	InitData.fSuspectFunc=FALSE;
	InitData.fUseTf=TRUE;
	InitData.hDllHandle=hDllHandle;
	InitData.sParameters.clear();
	InitData.ImportRec=irSmartTracer;
	InitData.UnpackMode=umFull;
	hMainThread=(HANDLE)_beginthreadex(NULL,0,MainThread,&InitData,0,NULL);
#else
	if(!InitData.sVictimFile.empty() && (!sOEPbox.IsEmpty() || InitData.UnpackMode!=umFull))
	{
		InitData.dwCutModule=_tcstoul(sCutModuleBox.GetString(),NULL,16);
		InitData.dwImportRVA=0;
		InitData.dwModuleEnd=_tcstoul(sModEndBox.GetString(),NULL,16);
		InitData.dwOEP=_tcstoul(sOEPbox.GetString(),NULL,16);
		InitData.dwTimeDelta=_tcstoul(sTimeDeltabox.GetString(),NULL,16);
		InitData.fAppendOverlay=fAppendOverlay;
		InitData.fAutosaveLog=fAutosaveLog;
		InitData.fDelphiInit=fDelphiInit;
		InitData.fDirectRefs=fDirectRefs;
		InitData.fExecuteFunc=fExecuteFunc;
		InitData.fForce=fForce;
		InitData.fLeaveDirectRefs=fLeaveDirectRefs;
		InitData.fLongImport=fLongImport;
		InitData.fMemoryManager=fSecret;
		InitData.fPathToLibs=fPathToLibs;
		InitData.fProtectDr=fProtectDr;
		if(InitData.fIsDll)
			InitData.fRelocs=fRelocs;
		else
			InitData.fRelocs=FALSE;
		InitData.fRemoveSect=fRemoveSect;
		if(InitData.fRemoveSect && InitData.dwCutModule==0)
			InitData.dwCutModule=VictimFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
		InitData.fSuspectFunc=fSuspectFunc;
		InitData.fUseTf=fUseTf;
		InitData.hDllHandle=hDllHandle;
		InitData.sParameters=sParamBox;

		if(IsDlgButtonChecked(IDC_IMPREC_SMART))
			InitData.ImportRec=irSmart;
		else if(IsDlgButtonChecked(IDC_IMPREC_TRACER))
			InitData.ImportRec=irSmartTracer;
		else if(IsDlgButtonChecked(IDC_IMPREC_NONE))
			InitData.ImportRec=irNone;
		else if(IsDlgButtonChecked(IDC_IMPREC_LIBSONLY))
			InitData.ImportRec=irLoadLibs;

		if(InitData.UnpackMode==umScript)
			hMainThread=(HANDLE)_beginthreadex(NULL,0,ScriptThread,&InitData,0,NULL);
		else
			hMainThread=(HANDLE)_beginthreadex(NULL,0,MainThread,&InitData,0,NULL);

#ifndef DLLFILE
		SetTimer(nTimerID,1000,NULL);
#endif
		BlockButtonsAndMenus(FALSE);
	}
	else
	{
		if((sOEPbox.IsEmpty() || !IsHEX(sOEPbox.GetString())) && InitData.UnpackMode==umFull)
			WriteLog(incorroep);
		if(InitData.sVictimFile.empty())
			WriteLog(choosefile);
	}
#endif
}

void CDlgMain::OnBnClickedKill()
{
	if(hMainThread!=NULL)
		StopMainThread();
}

void CDlgMain::OnBnClickedFindOEP()
{
	if(InitData.sVictimFile.empty())
	{
		WriteLog(choosefile);
		return;
	}
	if(InitData.fIsDll)
	{
#ifdef DLLFILE
		sOEPbox.Format(_T("%08X"),GetDllOEPNow(InitData.sVictimFile.c_str()));
#else
		CDlgFinders DlgFinders(true);
		DlgFinders.DoModal();
#endif
	}
	else
	{
#ifdef DLLFILE
		sOEPbox.Format(_T("%08X"),GetOEPNow(InitData.sVictimFile.c_str()));
#else
		CDlgFinders DlgFinders(false);
		DlgFinders.DoModal();
#endif
	}
	if(sOEPbox.IsEmpty() || !IsHEX(sOEPbox.GetString()) || _tcstoul(sOEPbox.GetString(),NULL,16)==0)
		WriteLog(incorroep);
	else
		WriteLog(someoep+sOEPbox);
}

#ifndef DLLFILE
BEGIN_MESSAGE_MAP(CDlgMain,CDialog)
	ON_BN_CLICKED(IDC_CHANGEENGINE,OnBnClickedChangeEngine)
	ON_BN_CLICKED(IDC_OPENFILE,OnBnClickedOpen)
	ON_BN_CLICKED(IDC_ATTACH,OnBnClickedAttach)
	ON_BN_CLICKED(IDC_UNPACK,OnBnClickedUnpack)
	ON_BN_CLICKED(IDC_USESCRIPT,OnBnClickedScript)
	ON_BN_CLICKED(IDC_KILL,OnBnClickedKill)
	ON_BN_CLICKED(IDC_TEST,OnBnClickedTest)
	ON_BN_CLICKED(IDC_FINDOBJECT,OnBnClickedFindObject)
	ON_BN_CLICKED(IDC_UNPDEL,OnBnClickedUnpDel)
	ON_BN_CLICKED(IDC_CLEARLOG,ClearLog)
	ON_BN_CLICKED(IDC_EXIT,OnBnClickedExit)
	ON_BN_CLICKED(IDC_FINDOEP,OnBnClickedFindOEP)
	ON_BN_CLICKED(IDC_DISASM,OnBnClickedDisasm)
	ON_BN_CLICKED(IDC_USEFORCE,DoUpdateData)
	ON_BN_CLICKED(IDC_IMPREC_SMART,DoUpdateData)
	ON_BN_CLICKED(IDC_IMPREC_TRACER,DoUpdateData)
	ON_BN_CLICKED(IDC_IMPREC_NONE,DoUpdateData)
	ON_BN_CLICKED(IDC_IMPREC_LIBSONLY,DoUpdateData)
	ON_BN_CLICKED(IDC_RELOCS,DoUpdateData)
	ON_BN_CLICKED(IDC_FINDDELTA,OnBnClickedFindDelta)
	ON_BN_CLICKED(IDC_REMSECT,DoUpdateData)
	ON_BN_CLICKED(IDC_SUSPFUNC,DoUpdateData)
	ON_BN_CLICKED(IDC_DIRECTREFS,DoUpdateData)
	ON_BN_CLICKED(IDC_LEAVEDIRECTREFS,DoUpdateData)
	ON_BN_CLICKED(IDC_EXECFUNC,DoUpdateData)
	ON_BN_CLICKED(IDC_APPOVERLAY,DoUpdateData)
	ON_BN_CLICKED(IDC_PROTECTDR,DoUpdateData)
	ON_BN_CLICKED(IDC_DELPHIINIT,DoUpdateData)
	ON_BN_CLICKED(IDC_USETF,DoUpdateData)
	ON_BN_CLICKED(IDC_LONGIMPORT,DoUpdateData)
	ON_BN_CLICKED(IDC_PATHLIBS,DoUpdateData)
	ON_BN_CLICKED(IDC_AUTOSAVELOG,DoUpdateData)
	ON_EN_CHANGE(IDC_OEPBOX,DoUpdateData)
	ON_EN_CHANGE(IDC_PARAMSBOX,DoUpdateData)
	ON_EN_CHANGE(IDC_MODENDBOX,DoUpdateData)
	ON_EN_CHANGE(IDC_CUTMODULEBOX,DoUpdateData)
	ON_EN_CHANGE(IDC_TIMEDELTABOX,DoUpdateData)
	ON_COMMAND(ID_MENU_EXIT,OnBnClickedExit)
	ON_COMMAND(ID_MENU_CLEARLOG,ClearLog)
	ON_COMMAND(ID_MENU_SAVELOG,SaveLog)
	ON_COMMAND(ID_MENU_PREF,OnOptionsPreferences)
	ON_COMMAND(ID_MENU_LICENSE,OnAboutLicenseAgreement)
	ON_COMMAND(ID_MENU_ABOUT,OnAboutAbout)
	ON_WM_CLOSE()
	ON_WM_DESTROY()
	ON_WM_DROPFILES()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_SYSCOMMAND()
	ON_WM_TIMER()
END_MESSAGE_MAP()

void CDlgMain::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX,IDC_OEPBOX,sOEPbox);
	DDX_Check(pDX,IDC_USEFORCE,fForce);
	DDX_Text(pDX,IDC_PARAMSBOX,sParamBox);
	DDX_Check(pDX,IDC_RELOCS,fRelocs);
	DDX_Text(pDX,IDC_MODENDBOX,sModEndBox);
	DDX_Text(pDX,IDC_CUTMODULEBOX,sCutModuleBox);
	DDX_Text(pDX,IDC_TIMEDELTABOX,sTimeDeltabox);
	DDX_Check(pDX,IDC_REMSECT,fRemoveSect);
	DDX_Check(pDX,IDC_SUSPFUNC,fSuspectFunc);
	DDX_Check(pDX,IDC_DIRECTREFS,fDirectRefs);
	DDX_Check(pDX,IDC_LEAVEDIRECTREFS,fLeaveDirectRefs);
	DDX_Check(pDX,IDC_EXECFUNC,fExecuteFunc);
	DDX_Check(pDX,IDC_APPOVERLAY,fAppendOverlay);
	DDX_Check(pDX,IDC_PROTECTDR,fProtectDr);
	DDX_Check(pDX,IDC_DELPHIINIT,fDelphiInit);
	DDX_Check(pDX,IDC_USETF,fUseTf);
	DDX_Check(pDX,IDC_LONGIMPORT,fLongImport);
	DDX_Check(pDX,IDC_PATHLIBS,fPathToLibs);
	DDX_Check(pDX,IDC_AUTOSAVELOG,fAutosaveLog);
	DDX_Control(pDX,IDC_MAINLOG,RichEdit);

	GetDlgItem(IDC_MODENDBOX)->EnableWindow(IsDlgButtonChecked(IDC_IMPREC_TRACER));
	GetDlgItem(IDC_CUTMODULEBOX)->EnableWindow(fRemoveSect);

	GetDlgItem(IDC_SUSPFUNC)->EnableWindow(IsDlgButtonChecked(IDC_IMPREC_SMART) || IsDlgButtonChecked(IDC_IMPREC_TRACER));
	GetDlgItem(IDC_DIRECTREFS)->EnableWindow(IsDlgButtonChecked(IDC_IMPREC_SMART) || IsDlgButtonChecked(IDC_IMPREC_TRACER));
	GetDlgItem(IDC_LEAVEDIRECTREFS)->EnableWindow(IsDlgButtonChecked(IDC_IMPREC_SMART) || IsDlgButtonChecked(IDC_IMPREC_TRACER));
	GetDlgItem(IDC_EXECFUNC)->EnableWindow(IsDlgButtonChecked(IDC_IMPREC_TRACER));
	GetDlgItem(IDC_UNPACK)->EnableWindow(!InitData.sVictimFile.empty() && (InitData.UnpackMode!=umFull || (!sOEPbox.IsEmpty() && IsHEX(sOEPbox.GetString()))));
	GetDlgItem(IDC_DISASM)->EnableWindow(!InitData.sVictimFile.empty() && !InitData.fIsDll && !sOEPbox.IsEmpty() && IsHEX(sOEPbox.GetString()));
}

void CDlgMain::DoUpdateData()
{
	UpdateData(TRUE);
}

void CDlgMain::OnClose()
{
	OnBnClickedExit();
}

void CDlgMain::OnDropFiles(HDROP hDropInfo)
{
	TCHAR szFileName[MAX_PATH];
	DragQueryFile(hDropInfo,0,szFileName,_countof(szFileName));
	DragFinish(hDropInfo);
	fDropped=true;
	sDropName=szFileName;
	OnBnClickedOpen();
	CDialog::OnDropFiles(hDropInfo);
}

void CDlgMain::OnPaint()
{
	if(IsIconic())
	{
		CPaintDC dc(this);

		SendMessage(WM_ICONERASEBKGND,reinterpret_cast<WPARAM>(dc.GetSafeHdc()),0);

		int cxIcon=GetSystemMetrics(SM_CXICON);
		int cyIcon=GetSystemMetrics(SM_CYICON);
		RECT Rect;
		GetClientRect(&Rect);
		int x=(Rect.right-Rect.left-cxIcon+1)/2;
		int y=(Rect.bottom-Rect.top-cyIcon+1)/2;

		dc.DrawIcon(x,y,hIcon);
	}
	else
		CDialog::OnPaint();
}

HCURSOR CDlgMain::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(hIcon);
}

void CDlgMain::OnTimer(UINT_PTR nIDEvent)
{
	if(nIDEvent==nTimerID)
	{
		DWORD dwExitCode;
		if(hMainThread==NULL || !GetExitCodeThread(hMainThread,&dwExitCode) || dwExitCode!=STILL_ACTIVE)
		{
			KillTimer(nTimerID);
			hMainThread=NULL;
			BlockButtonsAndMenus(TRUE);

			if(fExit)
				OnOK();
		}
	}
	else
		CDialog::OnTimer(nIDEvent);
}

LRESULT CDlgMain::WindowProc(UINT message,WPARAM wParam,LPARAM lParam)
{
	switch(message)
	{
		case WM_COMMAND:
		{
			if(LOWORD(wParam)==ID_FINDTARGET)
			{
				if(!InitData.sVictimFile.empty())
				{
					TCHAR szParams[MAX_PATH],szExplorer[MAX_PATH];
					GetSystemWindowsDirectory(szExplorer,_countof(szExplorer));
					_tcscat_s(szExplorer,_T("\\explorer.exe"));
					_stprintf_s(szParams,_T("/select, \"%s\""),InitData.sVictimFile.c_str());
					ShellExecute(0,_T("open"),szExplorer,szParams,NULL,SW_SHOWNORMAL);
				}
			}
			else if(LOWORD(wParam)==ID_FINDUNPACKED)
			{
				if(!InitData.sUnpackedFile.empty())
				{
					TCHAR szParams[MAX_PATH],szExplorer[MAX_PATH];
					GetSystemWindowsDirectory(szExplorer,_countof(szExplorer));
					_tcscat_s(szExplorer,_T("\\explorer.exe"));
					_stprintf_s(szParams,_T("/select, \"%s\""),InitData.sUnpackedFile.c_str());
					ShellExecute(0,_T("open"),szExplorer,szParams,NULL,SW_SHOWNORMAL);
				}
			}
			break;
		}
	}
	return CDialog::WindowProc(message,wParam,lParam);
}

enum SUPPORTED_VMM {SV_NONE,SV_AMD,SV_INTEL};
SUPPORTED_VMM GetSupportedVMM()
{
	const char szAMDId[]="AuthcAMDenti";
	const char szIntelId[]="GenuntelineI";

	int CPUInfo[4];
	__cpuid(CPUInfo,0);
	if(strncmp((const char*)&CPUInfo[1],szAMDId,strlen(szAMDId))==0)
	{
		__cpuid(CPUInfo,0x80000001);
		if((CPUInfo[2] & 4)==4)
			return SV_AMD;
	}
	else if(strncmp((const char*)&CPUInfo[1],szIntelId,strlen(szIntelId))==0)
	{
		__cpuid(CPUInfo,1);
		if((CPUInfo[2] & 0x20)==0x20)
			return SV_INTEL;
	}
	return SV_NONE;
}

void CDlgMain::OnBnClickedChangeEngine()
{
	TCHAR szCurrFile[MAX_PATH],szCurrPath[MAX_PATH],szIDTEngineFile[MAX_PATH],szVMMEngineFile[MAX_PATH];
	GetModuleFileName(hDllHandle,szCurrFile,_countof(szCurrFile));
	ExtractFilePath(szCurrPath,_countof(szCurrPath),szCurrFile);
	_tcscat_s(szCurrPath,_T("\\"));

	_tcscpy_s(szCurrFile,szCurrPath);
	_tcscat_s(szCurrFile,Option.szDrvName);
	_tcscat_s(szCurrFile,_T(".sys"));
	_tcscpy_s(szIDTEngineFile,szCurrPath);
	_tcscat_s(szIDTEngineFile,szIDTEngineName);

	switch(GetSupportedVMM())
	{
	case SV_NONE:
		MessageBox(switchfailed,_T("QuickUnpack"),MB_OK);
		return;
	case SV_AMD:
		_tcscpy_s(szVMMEngineFile,szCurrPath);
		_tcscat_s(szVMMEngineFile,szSVMEngineName);
		break;
	case SV_INTEL:
		_tcscpy_s(szVMMEngineFile,szCurrPath);
		_tcscat_s(szVMMEngineFile,szVMXEngineName);
		break;
	}

	if(PathFileExists(szIDTEngineFile))
	{
		MoveFile(szCurrFile,szVMMEngineFile);
		MoveFile(szIDTEngineFile,szCurrFile);
		WriteLog(switchedtonormal);
	}
	else if(PathFileExists(szVMMEngineFile))
	{
		MoveFile(szCurrFile,szIDTEngineFile);
		MoveFile(szVMMEngineFile,szCurrFile);
		WriteLog(switchedtovmm);
	}
	else
		MessageBox(switchfailed,_T("QuickUnpack"),MB_OK);
}

BOOL CDlgMain::OnInitDialog()
{
	CDialog::OnInitDialog();
#if defined _M_IX86
	if(IsWOW64(GetCurrentProcess()))
	{
		MessageBox(_T("For x64 OS take the x64 version"),_T("QuickUnpack"),MB_OK);
		ExitProcess(1);
	}
#endif
	SetIcon(hIcon,TRUE);
	SetIcon(hIcon,FALSE);

	((CEdit*)GetDlgItem(IDC_CUTMODULEBOX))->LimitText(2*sizeof(InitData.dwCutModule));
	((CEdit*)GetDlgItem(IDC_MODENDBOX))->LimitText(2*sizeof(InitData.dwModuleEnd));
	((CEdit*)GetDlgItem(IDC_OEPBOX))->LimitText(2*sizeof(InitData.dwOEP));
	((CEdit*)GetDlgItem(IDC_TIMEDELTABOX))->LimitText(2*sizeof(InitData.dwTimeDelta));

	RichEdit.SendMessage(EM_SETTEXTMODE,TM_SINGLECODEPAGE,0);

//	LoadCursor(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDR_ANICURSOR));

	hMainThread=NULL;
	fSecret=FALSE;
	fExit=false;

	Font.CreateFont(10,0,0,0,FW_ULTRALIGHT,0,0,0,DEFAULT_CHARSET,OUT_CHARACTER_PRECIS,CLIP_CHARACTER_PRECIS,DEFAULT_QUALITY,FF_DONTCARE,_T("MS Sans Serif"));
	RichEdit.SetFont(&Font);
	RichEdit.SetBackgroundColor(FALSE,RGB(255,255,255));

	InitData.hMain=m_hWnd;

	InitData.sVictimFile.clear();
	InitData.sUnpackedFile.clear();
	CheckDlgButton(IDC_IMPREC_SMART,BST_CHECKED);
	UpdateData(FALSE);

	CRegistryKey RegKey;
	Option.fAlwaysOnTop=false;
	Option.fShowLicense=true;
	_tcscpy_s(Option.szCurrDir,_T(""));
	_tcscpy_s(Option.szLang,_T("english.lng"));
	_tcscpy_s(Option.szDrvName,szDriverName);
	_tcscpy_s(Option.szSymbLinkName,szSymbolicLink);
	RegKey.RegistryReadStruct(REG_KEY_NAME,REG_VALUE_NAME,&Option,sizeof(Option));

	if(Option.fShowLicense)
	{
		CDlgLicense DlgLicense(false);
		DlgLicense.DoModal();

		Option.fShowLicense=false;
		RegKey.RegistryWriteStruct(REG_KEY_NAME,REG_VALUE_NAME,&Option,sizeof(Option));
	}

	srand((DWORD)time(NULL));
	if(_tcsicmp(Option.szDrvName,szDriverName)==0)
	{
		TCHAR szCurrFile[MAX_PATH],szCurrPath[MAX_PATH];
		GetModuleFileName(hDllHandle,szCurrFile,_countof(szCurrFile));
		ExtractFilePath(szCurrPath,_countof(szCurrPath),szCurrFile);
		_tcscat_s(szCurrPath,_T("\\"));

		CString sDrvName,sNewName,sOldName=szCurrPath;
		sOldName.MakeLower();
		for(;;)
		{
			sDrvName=_T("");
			for(int i=0;i!=_countof(szDriverName)-1;++i)
				sDrvName=sDrvName+IntToStr(GetRandomByte() & 0xf,16,0);
			sDrvName.MakeLower();
			sNewName=sOldName+sDrvName+_T(".sys");
			if(!PathFileExists(sNewName))
				break;
		}
		sOldName.Append(szDriverName);
		sOldName.Append(_T(".sys"));
		sOldName.MakeLower();
		_tcscpy_s(szDriverName,sDrvName.GetBuffer());
		MoveFile(sOldName,sNewName);
		_tcscpy_s(Option.szDrvName,szDriverName);

		CString sLinkName;
		for(int i=0;i!=_countof(szSymbolicLink)-1;++i)
			sLinkName=sLinkName+IntToStr(GetRandomByte() & 0xf,16,0);
		sLinkName.MakeLower();
		_tcscpy_s(szSymbolicLink,sLinkName.GetBuffer());

		_tcscpy_s(Option.szSymbLinkName,szSymbolicLink);
		RegKey.RegistryWriteStruct(REG_KEY_NAME,REG_VALUE_NAME,(void*)&Option,sizeof(Option));
#if defined _M_AMD64
		if(GetSupportedVMM()!=SV_NONE)
			OnBnClickedChangeEngine();
#endif
	}
	else
	{
		_tcscpy_s(szDriverName,Option.szDrvName);
		_tcscpy_s(szSymbolicLink,Option.szSymbLinkName);
	}

	MenuFind.CreatePopupMenu();
	MenuFind.AppendMenu(MF_STRING,ID_FINDTARGET,findtarget);
	MenuFind.AppendMenu(MF_STRING,ID_FINDUNPACKED,findunpacked);

	LoadOEPFinders(GetDlgItem(IDC_FINDOEP)->GetSafeHwnd());
	UnloadOEPFinders();

	LoadLocalization();
	Localize(true);

	ClearLog();

	CString sArgStr=AfxGetApp()->m_lpCmdLine;
	sArgStr.Trim(_T("\""));

	if(!sArgStr.IsEmpty())
	{
		fDropped=true;
		sDropName=sArgStr;
		OnBnClickedOpen();
	}

	if(Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return FALSE;
}

void CDlgMain::OnBnClickedScript()
{
	InitData.UnpackMode=umScript;
	OnBnClickedUnpack();
}

void CDlgMain::OnBnClickedTest()
{
	if(PathFileExists(InitData.sUnpackedFile.c_str()))
		ShellExecute(m_hWnd,_T("open"),InitData.sUnpackedFile.c_str(),NULL,NULL,SW_NORMAL);
}

void CDlgMain::OnBnClickedFindObject()
{
	RECT Rect;
	GetDlgItem(IDC_FINDOBJECT)->GetWindowRect(&Rect);

	MenuFind.TrackPopupMenu(TPM_LEFTALIGN | TPM_LEFTBUTTON,Rect.left,Rect.bottom,this);
}

void CDlgMain::OnBnClickedUnpDel()
{
	if(PathFileExists(InitData.sUnpackedFile.c_str()))
	{
		if(!DeleteFile(InitData.sUnpackedFile.c_str()))
			WriteLog(unpnotfound);
		else
			WriteLog(unpdeleted);
	}
}

void CDlgMain::OnBnClickedExit()
{
	fExit=true;

	CRegistryKey RegKey;
	RegKey.RegistryWriteStruct(REG_KEY_NAME,REG_VALUE_NAME,(void*)&Option,sizeof(Option));

#ifndef DLLFILE
	AnimateWindow(300,AW_BLEND | AW_HIDE);
#endif
	if(hMainThread!=NULL)
	{
		GetDlgItem(IDC_EXIT)->EnableWindow(FALSE);
		OnBnClickedKill();
	}
	else
		OnOK();
}

void CDlgMain::OnBnClickedDisasm()
{
	if(sOEPbox.IsEmpty() || !IsHEX(sOEPbox.GetString()))
		WriteLog(incorroep);
	else
	{
		BYTE bBuffer[INSTRS_TO_DISASM*MAX_INSTRUCTION_LEN];
		CDlgDisasm DlgDisasm;

		PROCESS_INFORMATION pi;
		if(!CreateRestrictedProcess(NULL,InitData.sVictimFile.c_str(),NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED,NULL,&pi))
			WriteLog(cantload);
		else
		{
			CONTEXT Context;
			Context.ContextFlags=CONTEXT_INTEGER;
			GetThreadContext(pi.hThread,&Context);
			DWORD_PTR VictimBase=GetIBFromPEB(pi.hProcess,Context);
			ResumeThread(pi.hThread);

			WaitForInputIdle(pi.hProcess,INFINITE);
			SuspendThread(pi.hThread);

			DWORD_PTR Address=VictimBase+_tcstoul(sOEPbox.GetString(),NULL,16);
			ReadProcessMemory(pi.hProcess,(void*)Address,&bBuffer,sizeof(bBuffer),NULL);
			TerminateProcess(pi.hProcess,0);
			WaitForSingleObject(pi.hProcess,INFINITE);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

			DlgDisasm.pAddr=(void*)bBuffer;
			DlgDisasm.AltAddress=Address;
			DlgDisasm.DoModal();
		}
	}
}

DWORD GetMeanRDTSC()
{
	const DWORD RDTSC_ITER_COUNT=1000;
	const DWORD RDTSC_FILTER=20;

	DWORD Timings[RDTSC_ITER_COUNT];
	for(int i=0;i!=RDTSC_ITER_COUNT;++i)
	{
		unsigned __int64 Timing=__rdtsc();
		Timings[i]=(DWORD)(__rdtsc()-Timing);
	}
	std::sort(Timings,Timings+_countof(Timings));

	DWORD64 qwResult=0;
	for(int i=RDTSC_FILTER;i!=RDTSC_ITER_COUNT-RDTSC_FILTER;++i)
		qwResult+=Timings[i];
	return (DWORD)(qwResult/(RDTSC_ITER_COUNT-2*RDTSC_FILTER));
}

void CDlgMain::OnBnClickedFindDelta()
{
	CTracer *pTracer=new CTracer(_T(""),NULL);
	pTracer->Hook(0,HOOK_UNHOOK,HOOK_HOOK,HOOK_UNHOOK);
	pTracer->EmulateRDTSC(1,MINLONG);
	DWORD dwDelta=GetMeanRDTSC();
	delete pTracer;
	dwDelta=dwDelta-GetMeanRDTSC();
	sTimeDeltabox=IntToStr(dwDelta | MINLONG,16,8);
	UpdateData(FALSE);
}

void CDlgMain::OnOptionsPreferences()
{
	CDlgPref DlgPref;
	DlgPref.DoModal();
	if(Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	else
		SetWindowPos(&wndNoTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
}

void CDlgMain::OnAboutLicenseAgreement()
{
	CDlgLicense DlgLicense(true);
	DlgLicense.DoModal();
}

void CDlgMain::OnAboutAbout()
{
	CDlgAbout DlgAbout;
	DlgAbout.DoModal();
	fSecret=DlgAbout.fSecret;
}

void CDlgMain::BlockButtonsAndMenus(BOOL fEnable)
{
	GetDlgItem(IDC_CHANGEENGINE)->EnableWindow(fEnable);
	GetDlgItem(IDC_OPENFILE)->EnableWindow(fEnable);
	GetDlgItem(IDC_ATTACH)->EnableWindow(fEnable);
	GetDlgItem(IDC_UNPACK)->EnableWindow(fEnable);
	GetDlgItem(IDC_USESCRIPT)->EnableWindow(fEnable);
	GetDlgItem(IDC_KILL)->EnableWindow(!fEnable);
	if(!fEnable || !InitData.fIsDll)
		GetDlgItem(IDC_TEST)->EnableWindow(fEnable);
	GetDlgItem(IDC_FINDOBJECT)->EnableWindow(fEnable);
	GetDlgItem(IDC_UNPDEL)->EnableWindow(fEnable);
	GetDlgItem(IDC_FINDDELTA)->EnableWindow(fEnable);
}

void CDlgMain::SetDLLUnpackingMode(BOOL fIsDll)
{
	GetDlgItem(IDC_USEFORCE)->EnableWindow(!fIsDll);
	GetDlgItem(IDC_PARAMSBOX)->EnableWindow(!fIsDll);
	GetDlgItem(IDC_RELOCS)->EnableWindow(fIsDll);
	GetDlgItem(IDC_TEST)->EnableWindow(!fIsDll);
	if(fIsDll)
		sParamBox=_T("");
	GetDlgItem(IDC_FINDOEP)->EnableWindow(TRUE);
	GetDlgItem(IDC_UNPACK)->EnableWindow(TRUE);
	GetDlgItem(IDC_USESCRIPT)->EnableWindow(TRUE);
	GetDlgItem(IDC_FINDOBJECT)->EnableWindow(TRUE);
	GetDlgItem(IDC_UNPDEL)->EnableWindow(TRUE);
}
#endif