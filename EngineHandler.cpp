#include "StdAfx.h"
#include "EngineHandler.h"

#include "DlgMain.h"

HANDLE CEngine::hEngine=NULL;

CEngine::CEngine(HMODULE hDllHandle)
{
	fStartedByThisProgram=false;
	fStartedByThisCopy=false;
	if(hEngine!=NULL)
		return;

	GetEngineHandle(false);
	if(hEngine!=NULL)
		return;

	Create(hDllHandle);
	GetEngineHandle(true);
	if(hEngine!=NULL)
		return;

	PostQuitMessage(0);
}

CEngine::~CEngine()
{
	if(fStartedByThisCopy)
	{
		if(hEngine!=NULL)
		{
			CloseHandle(hEngine);
			hEngine=NULL;
			pContext=NULL;
		}

		if(fStartedByThisProgram)
			Delete();
	}
}

void CEngine::GetEngineHandle(bool fShowError)
{
	if(hEngine!=NULL)
		return;

	TSTRING sSymbolicLink(_T("\\\\.\\"));
	hEngine=CreateFile((sSymbolicLink+szSymbolicLink).c_str(),0,0,NULL,OPEN_EXISTING,0,NULL);
	if(hEngine==INVALID_HANDLE_VALUE)
	{
		hEngine=NULL;
		pContext=NULL;

		if(fShowError)
		{
			TSTRING sError(_T("Can't open service...\n"));
			sError+=_T("CreateFile error - INVALID_HANDLE_VALUE");
			sError+=_T("\n - service name - \"")+sSymbolicLink+szSymbolicLink+_T("\"");

			MessageBox(NULL,sError.c_str(),_T("Fatal error"),MB_OK);
		}
		return;
	}
	DWORD dwVersion=0;
	Control(ENGINE_GETVERSION,NULL,0,&dwVersion,sizeof(dwVersion));
	if(dwVersion!=ENGINE_VERSION)
	{
		CloseHandle(hEngine);
		hEngine=NULL;
		pContext=NULL;

		if(fShowError)
			MessageBox(NULL,_T("Can't start engine\nwrong engine version"),_T("Fatal error"),MB_OK);
		return;
	}
	Control(ENGINE_INIT,NULL,0,&pContext,sizeof(pContext));
	if(pContext==NULL)
	{
		CloseHandle(hEngine);
		hEngine=NULL;
		pContext=NULL;

		if(fShowError)
			MessageBox(NULL,_T("Unable to allocate driver memory"),_T("Fatal error"),MB_OK);
		return;
	}
	fStartedByThisCopy=true;
}

void CEngine::Create(HMODULE hDllHandle)
{
	TCHAR szCurrFile[MAX_PATH],szCurrPath[MAX_PATH];
	GetModuleFileName(hDllHandle,szCurrFile,_countof(szCurrFile));

	ExtractFilePath(szCurrPath,_countof(szCurrPath),szCurrFile);
	_tcscat_s(szCurrPath,_T("\\"));
	_tcscat_s(szCurrPath,szDriverName);
	_tcscat_s(szCurrPath,_T(".sys"));

	SC_HANDLE hSCManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(hSCManager==NULL)
	{
		TCHAR szError[0x400];
		_tcscpy_s(szError,_T("Can't open SC manager\n"));

		DWORD dwLastError=GetLastError();
		if(dwLastError==ERROR_ACCESS_DENIED)
			_tcscat_s(szError,_T("ERROR_ACCESS_DENIED"));
		else if(dwLastError==ERROR_DATABASE_DOES_NOT_EXIST)
			_tcscat_s(szError,_T("ERROR_DATABASE_DOES_NOT_EXIST"));
		else if(dwLastError==ERROR_INVALID_PARAMETER)
			_tcscat_s(szError,_T("ERROR_INVALID_PARAMETER"));

		MessageBox(NULL,szError,_T("Fatal error"),MB_OK);
	}

	SC_HANDLE hService=OpenService(hSCManager,szSymbolicLink,SERVICE_STOP | DELETE);
	if(hService!=NULL)
	{
		SERVICE_STATUS ServiceStatus;
		ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus);
		DeleteService(hService);
		CloseServiceHandle(hService);
	}
	for(int i=0;i!=10;++i)
	{
		hService=CreateService(hSCManager,szSymbolicLink,szSymbolicLink,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,szCurrPath,NULL,NULL,NULL,NULL,NULL);
		if(hService!=NULL)
			break;
		if(GetLastError()!=ERROR_SERVICE_MARKED_FOR_DELETE)
			break;
		WaitForSingleObject(GetCurrentThread(),100);
	}
	if(hService==NULL)
	{
		TCHAR szError[0x400];
		_tcscpy_s(szError,_T("Can't create service\n"));

		DWORD dwLastError=GetLastError();
		if(dwLastError==ERROR_ACCESS_DENIED)
			_tcscat_s(szError,_T("ERROR_ACCESS_DENIED"));
		else if(dwLastError==ERROR_CIRCULAR_DEPENDENCY)
			_tcscat_s(szError,_T("ERROR_CIRCULAR_DEPENDENCY"));
		else if(dwLastError==ERROR_DUP_NAME)
			_tcscat_s(szError,_T("ERROR_DUP_NAME"));
		else if(dwLastError==ERROR_INVALID_HANDLE)
			_tcscat_s(szError,_T("ERROR_INVALID_HANDLE"));
		else if(dwLastError==ERROR_INVALID_NAME)
			_tcscat_s(szError,_T("ERROR_INVALID_NAME"));
		else if(dwLastError==ERROR_INVALID_PARAMETER)
			_tcscat_s(szError,_T("ERROR_INVALID_PARAMETER"));
		else if(dwLastError==ERROR_INVALID_SERVICE_ACCOUNT)
			_tcscat_s(szError,_T("ERROR_INVALID_SERVICE_ACCOUNT"));
		else if(dwLastError==ERROR_SERVICE_EXISTS)
			_tcscat_s(szError,_T("ERROR_SERVICE_EXISTS"));

		MessageBox(NULL,szError,_T("Fatal error"),MB_OK);
	}
	else
	{
		if(StartService(hService,0,NULL))
			fStartedByThisProgram=true;
		else
		{
			DWORD dwLastError=GetLastError();
			DeleteService(hService);

			TCHAR szError[0x400];
			_tcscpy_s(szError,_T("Can't start service\n"));

			if(dwLastError==ERROR_ACCESS_DENIED)
				_tcscat_s(szError,_T("ERROR_ACCESS_DENIED"));
			else if(dwLastError==ERROR_INVALID_HANDLE)
				_tcscat_s(szError,_T("ERROR_INVALID_HANDLE"));
			else if(dwLastError==ERROR_PATH_NOT_FOUND)
				_tcscat_s(szError,_T("ERROR_PATH_NOT_FOUND"));
			else if(dwLastError==ERROR_SERVICE_ALREADY_RUNNING)
				_tcscat_s(szError,_T("ERROR_SERVICE_ALREADY_RUNNING"));
			else if(dwLastError==ERROR_SERVICE_DATABASE_LOCKED)
				_tcscat_s(szError,_T("ERROR_SERVICE_DATABASE_LOCKED"));
			else if(dwLastError==ERROR_SERVICE_DEPENDENCY_DELETED)
				_tcscat_s(szError,_T("ERROR_SERVICE_DEPENDENCY_DELETED"));
			else if(dwLastError==ERROR_SERVICE_DEPENDENCY_FAIL)
				_tcscat_s(szError,_T("ERROR_SERVICE_DEPENDENCY_FAIL"));
			else if(dwLastError==ERROR_SERVICE_DISABLED)
				_tcscat_s(szError,_T("ERROR_SERVICE_DISABLED"));
			else if(dwLastError==ERROR_SERVICE_LOGON_FAILED)
				_tcscat_s(szError,_T("ERROR_SERVICE_LOGON_FAILED"));
			else if(dwLastError==ERROR_SERVICE_MARKED_FOR_DELETE)
				_tcscat_s(szError,_T("ERROR_SERVICE_MARKED_FOR_DELETE"));
			else if(dwLastError==ERROR_SERVICE_NO_THREAD)
				_tcscat_s(szError,_T("ERROR_SERVICE_NO_THREAD"));
			else if(dwLastError==ERROR_SERVICE_REQUEST_TIMEOUT)
				_tcscat_s(szError,_T("ERROR_SERVICE_REQUEST_TIMEOUT"));

			MessageBox(NULL,szError,_T("Fatal error"),MB_OK);
		}
	}
	if(hService!=NULL)
		CloseServiceHandle(hService);
	if(hSCManager!=NULL)
		CloseServiceHandle(hSCManager);
}

void CEngine::Delete()
{
	SC_HANDLE hSCManager=OpenSCManager(NULL,NULL,SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS);
	SC_HANDLE hService=OpenService(hSCManager,szSymbolicLink,SERVICE_STOP | DELETE);

	SERVICE_STATUS ServiceStatus;
	ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus);
	DeleteService(hService);

	if(hService!=NULL)
		CloseServiceHandle(hService);
	if(hSCManager!=NULL)
		CloseServiceHandle(hSCManager);
}

void CEngine::Control(DWORD dwCode,void *pInData,DWORD dwInSize,void *pOutData,DWORD dwOutSize) const
{
	DWORD dwBytesWritten;
	DeviceIoControl(hEngine,dwCode,pInData,dwInSize,pOutData,dwOutSize,&dwBytesWritten,NULL);
}

void CEngine::Hook(DWORD dwPID,DWORD dwInt1,DWORD dwInt0d,DWORD dwInt0e) const
{
	DATA_HOOK Data;
	Data.ProcessID=dwPID;
	Data.Int1=dwInt1;
	Data.Int0d=dwInt0d;
	Data.Int0e=dwInt0e;

	Control(ENGINE_HOOK,&Data,sizeof(Data),NULL,0);
}

void CEngine::GetState(DATA_STATE *pData) const
{
	if(pContext==NULL)
		return;
	*pData=*pContext;
}

void CEngine::SetState(DATA_STATE *pData)
{
	if(pContext==NULL)
		return;
	DATA_STATE TempState;
	TempState=*pData;
	TempState.State=pContext->State;
	*pContext=TempState;
	pContext->State=pData->State;
}

void CEngine::EmulateCPUID(DWORD dwHook) const
{
	CPUID_HOOK CpuidData;
	CpuidData.Hook=dwHook;
	Control(ENGINE_EMULATE_CPUID,&CpuidData,sizeof(CpuidData),NULL,0);
}

void CEngine::EmulateRDTSC(DWORD dwHook,DWORD dwShift) const
{
	RDTSC_HOOK RdtscData;
	RdtscData.Hook=dwHook;
	RdtscData.Shift=dwShift;
	Control(ENGINE_EMULATE_RDTSC,&RdtscData,sizeof(RdtscData),NULL,0);
}

DWORD_PTR CEngine::GetModHandle(DWORD dwPID,const TCHAR *szModuleName) const
{
	HANDLE hModuleSnap;
	do hModuleSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwPID);
	while(hModuleSnap==INVALID_HANDLE_VALUE && GetLastError()==ERROR_BAD_LENGTH);
	MODULEENTRY32 me32;
	me32.dwSize=sizeof(me32);
	if(!Module32First(hModuleSnap,&me32))
	{
		CloseHandle(hModuleSnap);
		return 0;
	}

	do
	{
		if(_tcsicmp(szModuleName,me32.szModule)==0)
		{
			CloseHandle(hModuleSnap);
			return (DWORD_PTR)me32.modBaseAddr;
		}
	}
	while(Module32Next(hModuleSnap,&me32));

	CloseHandle(hModuleSnap);
	return 0;
}