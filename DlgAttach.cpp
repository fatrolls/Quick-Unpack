#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgAttach.h"
#include "PEFile.h"
#include "Modules.h"
#include "psapi.h"

IMPLEMENT_DYNAMIC(CDlgAttach,CDialog)
CDlgAttach::CDlgAttach(CModules *n_pAttModules,DWORD *n_pPID,DWORD_PTR *n_pImageBase,DWORD *n_pTID):CDialog(CDlgAttach::IDD,NULL),
	pAttModules(n_pAttModules),
	pPID(n_pPID),
	pImageBase(n_pImageBase),
	pTID(n_pTID)
{
}

CDlgAttach::~CDlgAttach()
{
}

void CDlgAttach::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDC_PROCESSES,ProcessName);
	DDX_Control(pDX,IDC_MODULES,Modules);
}

BEGIN_MESSAGE_MAP(CDlgAttach,CDialog)
	ON_LBN_DBLCLK(IDC_MODULES,&CDlgAttach::OnLbnDblclkListModules)
	ON_LBN_SELCHANGE(IDC_PROCESSES,&CDlgAttach::OnLbnSelchangeListProcesses)
END_MESSAGE_MAP()

BOOL CDlgAttach::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);

	RefreshProcesses();

	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}

void CDlgAttach::OnLbnDblclkListModules()
{
	CString sTemp;
	Modules.GetText(Modules.GetCurSel(),sTemp);
	if(sTemp==_T("-----"))
		return;
	*pImageBase=(DWORD_PTR)_tcstoi64(sTemp.Left(sizeof(DWORD_PTR)*2),NULL,16);
	ProcessName.GetText(ProcessName.GetCurSel(),sTemp);
	*pPID=_tcstoul(sTemp.Left(8),NULL,16);

	HANDLE hThreadSnap;
	hThreadSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,*pPID);
	THREADENTRY32 te32;
	te32.dwSize=sizeof(te32);
	if(!Thread32First(hThreadSnap,&te32))
	{
		CloseHandle(hThreadSnap);
		return;
	}

	*pTID=0;
	HANDLE hThread;
	do
	{
		if(te32.th32OwnerProcessID==*pPID)
		{
			if(*pTID==0)
				*pTID=te32.th32ThreadID;
			hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);
		}
	}
	while(Thread32Next(hThreadSnap,&te32));

	CloseHandle(hThreadSnap);
	OnOK();
}

void CDlgAttach::RefreshProcesses()
{
	TCHAR cTmpBuf[0x400];
	TCHAR szTmpName[MAX_PATH];
	HANDLE hProcess;

	ProcessName.ResetContent();

	HANDLE hProcessSnap;
	hProcessSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	PROCESSENTRY32 pe32;
	pe32.dwSize=sizeof(pe32);
	if(!Process32First(hProcessSnap,&pe32))
	{
		CloseHandle(hProcessSnap);
		return;
	}
	do
	{
		hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pe32.th32ProcessID);
		if(IsWOW64(GetCurrentProcess())!=IsWOW64(hProcess))
		{
			CloseHandle(hProcess);
			continue;
		}
		memset(cTmpBuf,0,sizeof(cTmpBuf));
		memset(szTmpName,0,sizeof(szTmpName));
		if(IsProcessDying(hProcess))
			_tcscat_s(szTmpName,pe32.szExeFile);
		else
			GetModuleFileNameEx(hProcess,NULL,szTmpName,_countof(szTmpName));
		CloseHandle(hProcess);
		_stprintf_s(cTmpBuf,_T("%08X - %s"),pe32.th32ProcessID,szTmpName);
		ProcessName.AddString(cTmpBuf);
	}
	while(Process32Next(hProcessSnap,&pe32));

	CloseHandle(hProcessSnap);
	ProcessName.SetCurSel(0);
	OnLbnSelchangeListProcesses();
}

void CDlgAttach::OnLbnSelchangeListProcesses()
{
	CString sTemp;

	pAttModules->Clear();
	Modules.ResetContent();
	ProcessName.GetText(ProcessName.GetCurSel(),sTemp);
	HANDLE hVictim=OpenProcess(PROCESS_ALL_ACCESS,FALSE,_tcstoul(sTemp.Left(8),NULL,16));
	pAttModules->Reload(MAX_NUM,NULL,hVictim);
	CloseHandle(hVictim);

	if(pAttModules->Modules.empty())
		Modules.AddString(_T("-----"));

	for(size_t i=0;i!=pAttModules->Modules.size();++i)
		Modules.AddString(IntToStr(pAttModules->Modules[i]->ModuleBase,16,sizeof(pAttModules->Modules[0]->ModuleBase)*2)+_T(" - ")+pAttModules->Modules[i]->sFullName.c_str());
}