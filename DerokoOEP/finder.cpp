#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>
#include <vector>

#include "mediana.h"
#include "resource.h"
#include "tracer.h"

using namespace std;

const DWORD PAGE_SIZE=0x1000;
const DWORD SECTOR_SIZE=0x200;
DWORD_PTR ImageBase;

HANDLE hInstance;
BOOL fIsDll,fCanDump;
HWND hSections,hRangeStart,hRangeSize,hMemStart,hMemEnd;

TCHAR cBuffer[MAX_PATH]={_T('\0')};
TCHAR cCommand[MAX_PATH]={_T('\0')};

PROCESS_INFORMATION ProcessInformation;

vector<IMAGE_SECTION_HEADER> SectInfo;

BOOL fDetach=FALSE;

DWORD_PTR AlignTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return (Value+(Alignment-1)) & ~(Alignment-1);
}

DWORD_PTR CutTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return Value & ~(Alignment-1);
}

BOOL __stdcall DllMain(HANDLE hInst,DWORD dwReason,void*)
{
	if(dwReason==DLL_PROCESS_ATTACH)
	{
		hInstance=hInst;
		DisableThreadLibraryCalls((HMODULE)hInstance);
	}
	return TRUE;
}

void CloseDialog(HWND hwndDialog)
{
	EndDialog(hwndDialog,0);
	ImageBase=0;
}

void DoDump(HWND hwndDialog)
{
	if(!fCanDump)
		return;

	TCHAR cEditBuff[9];
	if(GetDlgItemText(hwndDialog,IDC_MEMSTART,cEditBuff,_countof(cEditBuff))==0)
		return;

	DWORD dwDumpStart;
	_stscanf_s(cEditBuff,_T("%X"),&dwDumpStart);
	if(dwDumpStart==0)
		return;

	if(GetDlgItemText(hwndDialog,IDC_MEMEND,cEditBuff,_countof(cEditBuff))==0)
		return;

	DWORD dwDumpEnd;
	_stscanf_s(cEditBuff,_T("%X"),&dwDumpEnd);
	if(dwDumpEnd==0)
		return;

	BYTE *pDump=(PBYTE)VirtualAlloc(NULL,dwDumpEnd-dwDumpStart,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	for(DWORD i=dwDumpStart;i<dwDumpEnd;i+=PAGE_SIZE)
		ReadProcessMemory(ProcessInformation.hProcess,(void*)(ImageBase+i),pDump+i,PAGE_SIZE,NULL);

	TCHAR szDumpName[24];
	_stprintf_s(szDumpName,_T("DUMP_%08X-%08X"),dwDumpStart,dwDumpEnd);

	DWORD dwBytesWritten;
	HANDLE hFile=CreateFile(szDumpName,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	WriteFile(hFile,pDump,dwDumpEnd-dwDumpStart,&dwBytesWritten,NULL);
	CloseHandle(hFile);
	VirtualFree(pDump,0,MEM_RELEASE);
}

#if defined _M_AMD64
const DWORD IBoffset=0x3000;
#elif defined _M_IX86
const DWORD IBoffset=0x3000;
#else
!!!
#endif

void FindOEP(HWND hwndDialog)
{
	WORD wStolenBytes;

	DWORD dwBaseStart,dwRange;
	DWORD_PTR Zero=0;

	TCHAR cEditBuff[9];
	GetDlgItemText(hwndDialog,IDC_FILENAME,cBuffer,_countof(cBuffer));
	GetDlgItemText(hwndDialog,IDC_COMMAND,cCommand,_countof(cCommand));

	if(IsDlgButtonChecked(hwndDialog,IDC_USERANGE)==BST_UNCHECKED)
	{
		int nSectNum=(int)SendMessage(hSections,LB_GETCURSEL,0,0);
		dwBaseStart=SectInfo[nSectNum].VirtualAddress;
		dwRange=SectInfo[nSectNum].Misc.VirtualSize;
	}
	else
	{
		if(GetDlgItemText(hwndDialog,IDC_RANGESTART,cEditBuff,_countof(cEditBuff))==0)
			return;

		_stscanf_s(cEditBuff,_T("%X"),&dwBaseStart);
		if(dwBaseStart==0)
			return;

		if(GetDlgItemText(hwndDialog,IDC_RANGESIZE,cEditBuff,_countof(cEditBuff))==0)
			return;

		_stscanf_s(cEditBuff,_T("%X"),&dwRange);
		if(dwRange==0)
			return;
	}

	SC_HANDLE hSCManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(hSCManager==NULL)
		CloseDialog(hwndDialog);

	TCHAR cBuffer2[MAX_PATH];
	GetModuleFileName((HMODULE)hInstance,cBuffer2,_countof(cBuffer2));

	for(int i=(int)_tcslen(cBuffer2);i>0;--i)
	{
		if(cBuffer2[i]==_T('\\'))
		{
			cBuffer2[i]=_T('\0');
			break;
		}
	}
	_tcscat_s(cBuffer2,_T("\\split.sys"));

	SC_HANDLE hService=OpenService(hSCManager,_T("SplitTLB"),SERVICE_STOP | DELETE);
	if(hService!=NULL)
	{
 		SERVICE_STATUS ServiceStatus;
		ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus);
		DeleteService(hService);
		CloseServiceHandle(hService);
	}
	for(int i=0;i<10;++i)
	{
		hService=CreateService(hSCManager,_T("SplitTLB"),_T("SplitTLB"),SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,cBuffer2,NULL,NULL,NULL,NULL,NULL);
		if(hService!=NULL)
			break;
		if(GetLastError()!=ERROR_SERVICE_MARKED_FOR_DELETE)
			break;
		WaitForSingleObject(GetCurrentThread(),100);
	}
	if(hService==NULL)
	{
		CloseServiceHandle(hSCManager);
		CloseDialog(hwndDialog);
		return;
	}

	StartService(hService,0,NULL);

	HANDLE hDevice=CreateFile(_T("\\\\.\\SplitTLB"),GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);

	STARTUPINFO StartupInfo;
	memset(&StartupInfo,0,sizeof(StartupInfo));
	memset(&ProcessInformation,0,sizeof(ProcessInformation));
	StartupInfo.cb=sizeof(StartupInfo);

	BOOL bResult=FALSE;

	if(!fIsDll)
	{
		TCHAR cParam[2*MAX_PATH+3];
		_tcscpy_s(cParam,_T("\""));
		_tcscat_s(cParam,cBuffer);
		_tcscat_s(cParam,_T("\" "));
		_tcscat_s(cParam,cCommand);
		bResult=CreateProcess(NULL,cParam,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&StartupInfo,&ProcessInformation);

		CONTEXT Context;
		Context.ContextFlags=CONTEXT_INTEGER;
		GetThreadContext(ProcessInformation.hThread,&Context);
#if defined _M_AMD64
		ReadProcessMemory(ProcessInformation.hProcess,(BYTE*)Context.Rdx+0x10,&ImageBase,sizeof(ImageBase),NULL);
#elif defined _M_IX86
		ReadProcessMemory(ProcessInformation.hProcess,(BYTE*)Context.Ebx+0x8,&ImageBase,sizeof(ImageBase),NULL);
#else
!!!
#endif
	}
	else
	{
		_tcscat_s(cBuffer,_T("2"));

		GetModuleFileName(GetModuleHandle(NULL),cBuffer2,_countof(cBuffer2));

		for(int i=(int)_tcslen(cBuffer2);i>0;--i)
		{
			if(cBuffer2[i]==_T('\\'))
			{
				cBuffer2[i]=_T('\0');
				break;
			}
		}
		_tcscat_s(cBuffer2,_T("\\OEPFinders\\loaddll.exe"));
		bResult=CreateProcess(cBuffer2,cBuffer,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&StartupInfo,&ProcessInformation);

		CONTEXT Context;
		DWORD_PTR ExeBase;
		Context.ContextFlags=CONTEXT_INTEGER;
		GetThreadContext(ProcessInformation.hThread,&Context);
#if defined _M_AMD64
		ReadProcessMemory(ProcessInformation.hProcess,(BYTE*)Context.Rdx+0x10,&ExeBase,sizeof(ExeBase),NULL);
#elif defined _M_IX86
		ReadProcessMemory(ProcessInformation.hProcess,(BYTE*)Context.Ebx+0x8,&ExeBase,sizeof(ExeBase),NULL);
#else
!!!
#endif
		ResumeThread(ProcessInformation.hThread);
		do
		{
			SwitchToThread();
			ReadProcessMemory(ProcessInformation.hProcess,(void*)(ExeBase+IBoffset),&ImageBase,sizeof(ImageBase),NULL);
		}
		while(ImageBase==0);

		SuspendThread(ProcessInformation.hThread);
		WriteProcessMemory(ProcessInformation.hProcess,(void*)(ExeBase+IBoffset),&Zero,sizeof(Zero),NULL);
	}

	if(!bResult)
	{
		SERVICE_STATUS ServiceStatus;
		ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus);
		DeleteService(hService);
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		CloseDialog(hwndDialog);
		return;
	}

	DWORD dwTemp;
	PROCESS_INFO Bpx;
	Bpx.Pid=(HANDLE)ProcessInformation.dwProcessId;
	Bpx.StartRange=ImageBase+dwBaseStart;
	Bpx.Size=dwRange;
	DeviceIoControl(hDevice,SET_RANGE,&Bpx,sizeof(Bpx),NULL,0,&dwTemp,NULL);
	SwitchToThread();
	ResumeThread(ProcessInformation.hThread);

	INSTRUCTION Instr;
	DISASM_PARAMS Params;
	TRACER_STRUCT TempData,TracerData,*pTracerData=NULL;
	DeviceIoControl(hDevice,INIT_TRACER,NULL,0,&pTracerData,sizeof(pTracerData),&dwTemp,NULL);
	if(pTracerData==NULL)
	{
		SERVICE_STATUS ServiceStatus;
		ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus);
		DeleteService(hService);
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		CloseDialog(hwndDialog);
		return;
	}
	TracerData.State=STATE_BUSY;
	for(;;)
	{
		while(TracerData.State!=STATE_WAIT)
		{
			SwitchToThread();
			GetExitCodeProcess(ProcessInformation.hProcess,&dwTemp);
			if(dwTemp!=STILL_ACTIVE)
			{
				ImageBase=0;
				break;
			}
			if(GetAsyncKeyState(VK_ESCAPE)!=0)
			{
				ImageBase=0;
				break;
			}
			memcpy(&TracerData,pTracerData,sizeof(TracerData));
		}
		memcpy(&TracerData,pTracerData,sizeof(TracerData));
		if(ImageBase==0)
			break;

		HGLOBAL pMem=GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,10000);

		DWORD dwCommands=13;
		BYTE bTempArray[13*MAX_INSTRUCTION_LEN];

		TCHAR cAddr[sizeof(DWORD_PTR)*2+2],cOutput[256];
		ReadProcessMemory(ProcessInformation.hProcess,(void*)TracerData.CurrentIp,&bTempArray,sizeof(bTempArray),NULL);

		int nLen=0;
		Params.arch=ARCH_ALL;
		Params.base=TracerData.CurrentIp;
		Params.options=DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP | DISASM_OPTION_COMPUTE_RIP;
		Params.sf_prefixes=NULL;
#if defined _M_AMD64
		Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
		Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
		for(;dwCommands>0;--dwCommands)
		{
			if(medi_disassemble((uint8_t*)(bTempArray+nLen),sizeof(bTempArray)-nLen,&Instr,&Params)!=DASM_ERR_OK)
				break;
			_stprintf_s(cAddr,_T("%I64X:"),Params.base);
			_tcscat_s((TCHAR*)pMem,10000,cAddr);
			_tcscat_s((TCHAR*)pMem,10000,_T("   "));
			nLen+=Instr.length;
			Params.base+=Instr.length;
			cOutput[medi_dump(&Instr,cOutput,_countof(cOutput),NULL)]=_T('\0');
			_tcscat_s((TCHAR*)pMem,10000,cOutput);
			_tcscat_s((TCHAR*)pMem,10000,_T("\n"));
		}
		int res=MessageBox(hwndDialog,(TCHAR*)pMem,_T("Is this OEP?"),MB_YESNO);
		GlobalFree(pMem);

		if(res==IDYES)
		{
			ImageBase=TracerData.CurrentIp-ImageBase;

			if(!fDetach)
				break;
			else
			{
				WORD wInfJump=0xFEEB;
				ReadProcessMemory(ProcessInformation.hProcess,(void*)TracerData.CurrentIp,&wStolenBytes,sizeof(wStolenBytes),NULL);
				WriteProcessMemory(ProcessInformation.hProcess,(void*)TracerData.CurrentIp,&wInfJump,sizeof(wInfJump),NULL);

				wStolenBytes=_byteswap_ushort(wStolenBytes);
				TCHAR cStolenText[5];
				_stprintf_s(cStolenText,_T("%04X"),cStolenText);
				MessageBox(hwndDialog,cStolenText,_T("Rewritten 2 bytes"),MB_OK);
				SendMessage(hMemStart,EM_SETREADONLY,0,0);
				SendMessage(hMemEnd,EM_SETREADONLY,0,0);
				fCanDump=TRUE;

				TracerData.CurrentIp=0;
				TracerData.State=STATE_BUSY;
				memcpy(&TempData,&TracerData,sizeof(TempData));
				TempData.State=pTracerData->State;
				memcpy(pTracerData,&TempData,sizeof(TempData));
				pTracerData->State=TracerData.State;
				break;
			}
		}
		else
		{
			TracerData.State=STATE_BUSY;
			memcpy(&TempData,&TracerData,sizeof(TempData));
			TempData.State=pTracerData->State;
			memcpy(pTracerData,&TempData,sizeof(TempData));
			pTracerData->State=TracerData.State;
		}
	}
	TerminateProcess(ProcessInformation.hProcess,0);
	CloseHandle(ProcessInformation.hThread);
	CloseHandle(ProcessInformation.hProcess);

	DeviceIoControl(hDevice,STOP_TRACER,NULL,0,NULL,0,&dwTemp,NULL);
	do
	{
		TracerData.CurrentIp=0;
		TracerData.State=STATE_BUSY;
		memcpy(&TempData,&TracerData,sizeof(TempData));
		TempData.State=pTracerData->State;
		memcpy(pTracerData,&TempData,sizeof(TempData));
		pTracerData->State=TracerData.State;
		SwitchToThread();
	}
	while(TracerData.State!=STATE_BUSY);
	CloseHandle(hDevice);

	SERVICE_STATUS ServiceStatus;
	ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus);
	DeleteService(hService);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	EndDialog(hwndDialog,0);
}

INT_PTR CALLBACK DialogProc(HWND hwndDialog,UINT uMsg,WPARAM wParam,LPARAM)
{
	int nSectionCounter;
	HANDLE hFile;
	BOOL fFlag;

	TCHAR cListSecTmp[100];

	switch(uMsg)
	{
		case WM_INITDIALOG:
			{
			hSections=GetDlgItem(hwndDialog,IDC_SECTIONS);
			hRangeStart=GetDlgItem(hwndDialog,IDC_RANGESTART);
			hRangeSize=GetDlgItem(hwndDialog,IDC_RANGESIZE);
			hMemStart=GetDlgItem(hwndDialog,IDC_MEMSTART);
			hMemEnd=GetDlgItem(hwndDialog,IDC_MEMEND);

			_tcscpy_s(cBuffer,(TCHAR*)ImageBase);
			ImageBase=0;

			SetDlgItemText(hwndDialog,IDC_FILENAME,cBuffer);
			SetDlgItemText(hwndDialog,IDC_COMMAND,cCommand);
			if(fIsDll)
			{
				ShowWindow(GetDlgItem(hwndDialog,6),SW_HIDE);
				ShowWindow(GetDlgItem(hwndDialog,IDC_COMMAND),SW_HIDE);
			}

			SendMessage(hSections,LB_RESETCONTENT,0,0);
			SendMessage(hMemStart,EM_SETREADONLY,1,0);
			SendMessage(hMemEnd,EM_SETREADONLY,1,0);
			fCanDump=FALSE;

			hFile=CreateFile(cBuffer,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

			DWORD dwBytesRead;
			IMAGE_DOS_HEADER MZHeader;
			IMAGE_NT_HEADERS PEHeader;
			ReadFile(hFile,&MZHeader,sizeof(MZHeader),&dwBytesRead,NULL);
			SetFilePointer(hFile,MZHeader.e_lfanew,NULL,FILE_BEGIN);
			ReadFile(hFile,&PEHeader,sizeof(PEHeader),&dwBytesRead,NULL);

			DWORD dwFileSize=GetFileSize(hFile,NULL);
			SetFilePointer(hFile,MZHeader.e_lfanew+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+PEHeader.FileHeader.SizeOfOptionalHeader,NULL,FILE_BEGIN);
			for(nSectionCounter=0;nSectionCounter<PEHeader.FileHeader.NumberOfSections;++nSectionCounter)
			{
				IMAGE_SECTION_HEADER SectionHeader;
				ReadFile(hFile,&SectionHeader,sizeof(SectionHeader),&dwBytesRead,NULL);
				if(SectionHeader.Misc.VirtualSize==0)
					SectionHeader.Misc.VirtualSize=SectionHeader.SizeOfRawData;
				if(SectionHeader.SizeOfRawData==0)
					SectionHeader.PointerToRawData=0;
				if(SectionHeader.PointerToRawData==0)
					SectionHeader.SizeOfRawData=0;
				if(PEHeader.OptionalHeader.SectionAlignment>=PAGE_SIZE)
				{
					SectionHeader.Misc.VirtualSize=(DWORD)AlignTo(SectionHeader.Misc.VirtualSize,PEHeader.OptionalHeader.SectionAlignment);
					DWORD dwAlignedRawPtr=(DWORD)CutTo(SectionHeader.PointerToRawData,SECTOR_SIZE);
					SectionHeader.SizeOfRawData=min((DWORD)AlignTo(SectionHeader.PointerToRawData+SectionHeader.SizeOfRawData,PEHeader.OptionalHeader.FileAlignment)-dwAlignedRawPtr,(DWORD)AlignTo(SectionHeader.SizeOfRawData,PAGE_SIZE));
					SectionHeader.PointerToRawData=dwAlignedRawPtr;
				}
				if(SectionHeader.SizeOfRawData>SectionHeader.Misc.VirtualSize)
					SectionHeader.SizeOfRawData=SectionHeader.Misc.VirtualSize;
				if(SectionHeader.SizeOfRawData>dwFileSize-SectionHeader.PointerToRawData)
					SectionHeader.SizeOfRawData=(DWORD)AlignTo(dwFileSize-SectionHeader.PointerToRawData,PEHeader.OptionalHeader.FileAlignment);
				SectInfo.push_back(SectionHeader);

				TCHAR cTempStr[9];
#ifdef UNICODE
				MultiByteToWideChar(CP_ACP,0,(char*)SectionHeader.Name,_countof(SectionHeader.Name),cTempStr,_countof(cTempStr));
#else
				_tcsncpy_s(cTempStr,(char*)SectionHeader.Name,_countof(SectionHeader.Name));
#endif
				while(_tcslen(cTempStr)<sizeof(DWORD)*2)
					_tcscat_s(cTempStr,_T(" "));

				_tcscpy_s(cListSecTmp,cTempStr);
				_tcscat_s(cListSecTmp,_T(" - "));

				_stprintf_s(cTempStr,_T("%08X"),SectionHeader.VirtualAddress);
				_tcscat_s(cListSecTmp,cTempStr);
				_tcscat_s(cListSecTmp,_T(" - "));

				_stprintf_s(cTempStr,_T("%08X"),SectionHeader.Misc.VirtualSize);
				_tcscat_s(cListSecTmp,cTempStr);
				_tcscat_s(cListSecTmp,_T(" - "));

				_tcscpy_s(cTempStr,_T("   "));
				if(SectionHeader.Characteristics & IMAGE_SCN_MEM_READ)
					cTempStr[0]=_T('R');
				if(SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE)
					cTempStr[1]=_T('W');
				if(SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE)
					cTempStr[2]=_T('X');

				_tcscat_s(cListSecTmp,cTempStr);

				SendMessage(hSections,LB_ADDSTRING,0,(LPARAM)cListSecTmp);
			}
			CloseHandle(hFile);

			SendMessage(hSections,LB_SETCURSEL,0,0);
			break;
			}
		case WM_COMMAND:
			switch(wParam)
			{
				case IDC_USERANGE:
					fFlag=(IsDlgButtonChecked(hwndDialog,IDC_USERANGE) & 1) ^ 1;
					SendMessage(hRangeStart,EM_SETREADONLY,fFlag,0);
					SendMessage(hRangeSize,EM_SETREADONLY,fFlag,0);
					EnableWindow(hSections,fFlag);
					break;
				case IDC_OEP:
					fDetach=FALSE;
					FindOEP(hwndDialog);
					break;
				case IDC_DETACH:
					fDetach=TRUE;
					FindOEP(hwndDialog);
					break;
				case IDC_DUMP:
					DoDump(hwndDialog);
					break;
				case IDC_EXIT:
					CloseDialog(hwndDialog);
					break;
			}
			break;
		case WM_CLOSE:
			CloseDialog(hwndDialog);
			break;
		case WM_LBUTTONDOWN:
			SendMessage(hwndDialog,WM_NCLBUTTONDOWN,HTCAPTION,0);
			break;
	}
	return 0;
}

DWORD __stdcall GetOEPNow(const TCHAR *szFileName)
{
	ImageBase=(DWORD_PTR)szFileName;
	InitCommonControls();
	DialogBoxParam((HINSTANCE)hInstance,MAKEINTRESOURCE(IDD_MAINDLG),NULL,DialogProc,NULL);
	SectInfo.clear();
	return (DWORD)ImageBase;
}

DWORD __stdcall GetDllOEPNow(const TCHAR *szFileName)
{
	fIsDll=TRUE;
	return GetOEPNow(szFileName);
}

TCHAR *__stdcall ShortFinderName()
{
	return _T("SplitTLB by Archer & deroko");
}