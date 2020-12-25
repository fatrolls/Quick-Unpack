#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include <eh.h>

#include "DlgDump.h"
#include <signal.h>

BEGIN_MESSAGE_MAP(CApp,CWinApp)
	ON_COMMAND(ID_HELP,CWinApp::OnHelp)
END_MESSAGE_MAP()

CApp::CApp()
{
}

CApp theApp;

void CApp::HandleException(CSeException *e) const
{
	CString sDump,sRegs,sStack;
	e->FormatDump(sDump);
	e->FormatRegs(sRegs);
	e->FormatStack(sStack);
	CDlgDump DlgDump;

	DlgDump.sData.Format(_T("There has been a critical error in exe, please report to the author\r\n\r\n")
		_T("Compiled       : %s\r\nOS             : %s\r\nOS build       : %s\r\n"),
		sTime.c_str(),sOSName.c_str(),sOSBuild.c_str());

	DlgDump.sData+=sDump+_T("\r\n")+sRegs+_T("\r\n")+sStack;
	DlgDump.DoModal();
	e->Delete();

	AfxWinTerm();
	raise(SIGABRT);
	_exit(3);
}

BOOL CApp::PumpMessage()
{
	BOOL fRet=TRUE;
	try
	{
		fRet=CWinApp::PumpMessage();
	}
	catch(CException *e)
	{
		if(e->IsKindOf(RUNTIME_CLASS(CMemoryException)))
			e->ReportError(MB_ICONEXCLAMATION|MB_SYSTEMMODAL,AFX_IDP_INTERNAL_FAILURE);
		else if(e->IsKindOf(RUNTIME_CLASS(CSeException)))
			HandleException((CSeException*)e);
		else if(!e->IsKindOf(RUNTIME_CLASS(CUserException)))
			e->ReportError(MB_ICONSTOP,AFX_IDP_INTERNAL_FAILURE);
	}
	return fRet;
}

void EnableDebugPrivilege(bool fEnable)
{
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken);
	
	LUID Luid;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&Luid);
	
	TOKEN_PRIVILEGES Tp;
	Tp.PrivilegeCount=1;
	Tp.Privileges[0].Luid=Luid;
	Tp.Privileges[0].Attributes=fEnable ? SE_PRIVILEGE_ENABLED : 0;
	AdjustTokenPrivileges(hToken,FALSE,&Tp,0,NULL,NULL);

	CloseHandle(hToken);
}

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PGPI)(DWORD,DWORD,DWORD,DWORD,PDWORD);
const DWORD PRODUCT_PROFESSIONAL=0x00000030;
const DWORD VER_SUITE_WH_SERVER=0x00008000;

BOOL CApp::InitInstance()
{
	InitCommonControls();
	CWinApp::InitInstance();

	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;
	PGNSI pGNSI;
	PGPI pGPI;
	DWORD dwType;

	memset(&si,0,sizeof(si));
	memset(&osvi,0,sizeof(osvi));

	pGNSI=(PGNSI)GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"GetNativeSystemInfo");
	if(pGNSI!=NULL)
		pGNSI(&si);
	else
		GetSystemInfo(&si);

	osvi.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	if(GetVersionEx((OSVERSIONINFO*)&osvi))
	{
		if(osvi.dwMajorVersion==10)
		{
			if(osvi.dwMinorVersion==0)
			{
				if(osvi.wProductType==VER_NT_WORKSTATION)
					sOSName=_T("Windows 10");
				else
					sOSName=_T("Windows Server 2016");
			}
		}
		else if(osvi.dwMajorVersion==6)
		{
			if(osvi.dwMinorVersion==3)
			{
				if(osvi.wProductType==VER_NT_WORKSTATION)
					sOSName=_T("Windows 8.1 ");
				else
					sOSName=_T("Windows Server 2012 R2 ");
			}
			else if(osvi.dwMinorVersion==2)
			{
				if(osvi.wProductType==VER_NT_WORKSTATION)
					sOSName=_T("Windows 8 ");
				else
					sOSName=_T("Windows Server 2012 ");
			}
			else if(osvi.dwMinorVersion==1)
			{
				if(osvi.wProductType==VER_NT_WORKSTATION)
					sOSName=_T("Windows 7 ");
				else
					sOSName=_T("Windows Server 2008 R2 ");
			}
			else if(osvi.dwMinorVersion==0)
			{
				if(osvi.wProductType==VER_NT_WORKSTATION)
					sOSName=_T("Windows Vista ");
				else
					sOSName=_T("Windows Server 2008 ");
			}

			pGPI=(PGPI)GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"GetProductInfo");
			pGPI(osvi.dwMajorVersion,osvi.dwMinorVersion,0,0,&dwType);

			switch(dwType)
			{
			case PRODUCT_ULTIMATE:
				sOSName+=_T("Ultimate Edition");
				break;
			case PRODUCT_PROFESSIONAL:
				sOSName+=_T("Professional");
				break;
			case PRODUCT_HOME_PREMIUM:
				sOSName+=_T("Home Premium Edition");
				break;
			case PRODUCT_HOME_BASIC:
				sOSName+=_T("Home Basic Edition");
				break;
			case PRODUCT_ENTERPRISE:
				sOSName+=_T("Enterprise Edition");
				break;
			case PRODUCT_BUSINESS:
				sOSName+=_T("Business Edition");
				break;
			case PRODUCT_STARTER:
				sOSName+=_T("Starter Edition");
				break;
			case PRODUCT_CLUSTER_SERVER:
				sOSName+=_T("Cluster Server Edition");
				break;
			case PRODUCT_DATACENTER_SERVER:
				sOSName+=_T("Datacenter Edition");
				break;
			case PRODUCT_DATACENTER_SERVER_CORE:
				sOSName+=_T("Datacenter Edition (core installation)");
				break;
			case PRODUCT_ENTERPRISE_SERVER:
				sOSName+=_T("Enterprise Edition");
				break;
			case PRODUCT_ENTERPRISE_SERVER_CORE:
				sOSName+=_T("Enterprise Edition (core installation)");
				break;
			case PRODUCT_ENTERPRISE_SERVER_IA64:
				sOSName+=_T("Enterprise Edition for Itanium-based Systems");
				break;
			case PRODUCT_SMALLBUSINESS_SERVER:
				sOSName+=_T("Small Business Server");
				break;
			case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
				sOSName+=_T("Small Business Server Premium Edition");
				break;
			case PRODUCT_STANDARD_SERVER:
				sOSName+=_T("Standard Edition");
				break;
			case PRODUCT_STANDARD_SERVER_CORE:
				sOSName+=_T("Standard Edition (core installation)");
				break;
			case PRODUCT_WEB_SERVER:
				sOSName+=_T("Web Server Edition");
				break;
			}
		}
		else if(osvi.dwMajorVersion==5)
		{
			if(osvi.dwMinorVersion==2)
			{
				if(GetSystemMetrics(SM_SERVERR2))
					sOSName=_T("Windows Server 2003 R2, ");
				else if((osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER)==VER_SUITE_STORAGE_SERVER)
					sOSName=_T("Windows Storage Server 2003");
				else if((osvi.wSuiteMask & VER_SUITE_WH_SERVER)==VER_SUITE_WH_SERVER)
					sOSName=_T("Windows Home Server");
				else if(osvi.wProductType==VER_NT_WORKSTATION && si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
					sOSName=_T("Windows XP Professional x64 Edition");
				else
					sOSName=_T("Windows Server 2003, ");

				if(osvi.wProductType!=VER_NT_WORKSTATION)
				{
					if(si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
					{
						if((osvi.wSuiteMask & VER_SUITE_DATACENTER)==VER_SUITE_DATACENTER)
							sOSName+=_T("Datacenter x64 Edition");
						else if((osvi.wSuiteMask & VER_SUITE_ENTERPRISE)==VER_SUITE_ENTERPRISE)
							sOSName+=_T("Enterprise x64 Edition");
						else
							sOSName+=_T("Standard x64 Edition");
					}
					else
					{
						if((osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER)==VER_SUITE_COMPUTE_SERVER)
							sOSName+=_T("Compute Cluster Edition");
						else if((osvi.wSuiteMask & VER_SUITE_DATACENTER)==VER_SUITE_DATACENTER)
							sOSName+=_T("Datacenter Edition");
						else if((osvi.wSuiteMask & VER_SUITE_ENTERPRISE)==VER_SUITE_ENTERPRISE)
							sOSName+=_T("Enterprise Edition");
						else if((osvi.wSuiteMask & VER_SUITE_BLADE)==VER_SUITE_BLADE)
							sOSName+=_T("Web Edition");
						else
							sOSName+=_T("Standard Edition");
					}
				}
			}
			else if(osvi.dwMinorVersion==1)
			{
				sOSName=_T("Windows XP ");
				if((osvi.wSuiteMask & VER_SUITE_PERSONAL)==VER_SUITE_PERSONAL)
					sOSName+=_T("Home Edition");
				else
					sOSName+=_T("Professional");
			}
		}

		if(osvi.szCSDVersion[0]!=_T('\0'))
		{
			sOSBuild=osvi.szCSDVersion;
			sOSBuild+=_T(" ");
		}
		else
			sOSBuild.clear();

		TCHAR cTemp[0x100];
		_stprintf_s(cTemp,_T("(build %d)"),osvi.dwBuildNumber);
		sOSBuild+=cTemp;

		if(osvi.dwMajorVersion>=6)
		{
			if(si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
				sOSBuild+=_T(", 64-bit");
			else if(si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL)
				sOSBuild+=_T(", 32-bit");
		}
		sOSBuild+=_T("\r\n");
	}
	sTime=_T(__DATE__) _T(" at ") _T(__TIME__);

	AfxEnableControlContainer();
	AfxInitRichEdit2();

	_set_se_translator(SeTranslator);
	EnableDebugPrivilege(true);

	PAGE_SIZE=si.dwPageSize;
	PAGE_GRANULARITY=si.dwAllocationGranularity;

#ifndef DLLFILE
	pDlgMain=new CDlgMain();
#endif

	m_pMainWnd=pDlgMain;
	pDlgMain->DoModal();
	delete pDlgMain;

	EnableDebugPrivilege(false);
	return FALSE;
}