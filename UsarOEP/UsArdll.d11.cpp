#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <commctrl.h>
#include <intrin.h>
#include <tchar.h>
#include <vector>

#include "mediana.h"
#include "resource.h"

using namespace std;

const DWORD PAGE_SIZE=0x1000;

TCHAR szNum[]=_T("00");

const BYTE OEPopcodeTable[256]={
//  0 1 2 3 4 5 6 7 8 9 A B C D E F
	0,0,1,2,0,0,0,0,0,1,0,0,0,0,0,0,/*0*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*1*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*2*/
	2,0,0,2,0,0,0,0,2,0,0,2,0,0,0,0,/*3*/
	1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,/*4*/
	0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,/*5*/
	0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,/*6*/
	0,0,1,1,1,1,0,0,1,0,1,0,1,0,1,1,/*7*/
	2,0,0,2,1,1,0,0,2,2,2,2,0,0,0,1,/*8*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*9*/
	0,0,0,0,1,0,0,0,0,0,1,1,1,1,0,0,/*A*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*B*/
	0,0,3,1,0,0,2,2,0,0,0,0,1,0,0,0,/*C*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*D*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*E*/
	0,0,0,0,0,0,2,1,0,0,0,0,0,0,0,3 /*F*/
};

const BYTE OEPopcodeTableEx[256]={
//  0 1 2 3 4 5 6 7 8 9 A B C D E F
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*0*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*1*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*2*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*3*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*4*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*5*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*6*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*7*/
	1,0,0,0,1,1,0,0,1,1,0,0,1,0,0,0,/*8*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*9*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*A*/
	0,0,0,0,0,0,2,2,0,0,0,0,0,0,0,0,/*B*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*C*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*D*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,/*E*/
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 /*F*/
};

CRITICAL_SECTION CriticalSection;
DWORD_PTR ImageBase,OEP,ESP;
DWORD dwImageSize;
HINSTANCE hInstance;
BOOL fHWBP,fAbout=FALSE,fExit=FALSE;

typedef struct _OLD_EP
{
	DWORD_PTR OldIp;
	DWORD Bytes;
} OLD_EP;

vector<OLD_EP> EpArray;

NTSTATUS (__stdcall *OldTerminateProcess)
(
	HANDLE hProcess,
	NTSTATUS ExitStatus
);

NTSTATUS (__stdcall *OldLoadLibrary)
(
	PWSTR SearchPath,
	PULONG pFlags,
	PVOID DllName,
	PVOID *pBaseAddress
);

NTSTATUS (__stdcall *OldGetProcAddressForCaller)
(
	HMODULE hModule,
	PVOID FunctionName,
	WORD wOrdinal,
	PVOID *pFunctionAddress,
	PULONG pFlags,
	PVOID ReturnAddress
);

NTSTATUS (__stdcall *OldGetProcAddress)
(
	HMODULE hModule,
	PVOID FunctionName,
	WORD wOrdinal,
	PVOID *pFunctionAddress
);

void (*DummyFunc)();

HBRUSH hBrush1,hBrush2,hBrush3,hBrush4;
HWND hOutput,hYes,hNext,hAbout,hOK;

DWORD_PTR CutTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return Value & ~(Alignment-1);
}

BOOL IfInRange(DWORD_PTR Value,DWORD_PTR RangeStart,DWORD dwRangeSize)
{
	return((Value>=RangeStart) && (Value<=RangeStart+dwRangeSize));
}

void BackSpToIp(PEXCEPTION_POINTERS pRecord)
{
#if defined _M_AMD64
	pRecord->ContextRecord->Rip=*(DWORD_PTR*)pRecord->ContextRecord->Rsp;
	pRecord->ContextRecord->Rsp+=sizeof(DWORD_PTR);
#elif defined _M_IX86
	pRecord->ContextRecord->Eip=*(DWORD_PTR*)pRecord->ContextRecord->Esp;
	pRecord->ContextRecord->Esp+=sizeof(DWORD_PTR);
#else
!!!
#endif
}

void InstallHWBP(PCONTEXT pContext)
{
	pContext->Dr0=ESP;
	pContext->Dr1=0;
	pContext->Dr2=0;
	pContext->Dr3=0;
	pContext->Dr6&=~0xe00f;
	pContext->Dr7=0x30501;
}

void CreateRect(PRECT pRect,LONG Left,LONG Top,LONG Right,LONG Bottom)
{
	pRect->bottom=Bottom;
	pRect->right=Right;
	pRect->top=Top;
	pRect->left=Left;
}

void wndEraseBkg(PRECT pRect,HDC hDc)
{
	CreateRect(pRect,0,16,620,180);
	FillRect(hDc,pRect,hBrush3);
	CreateRect(pRect,5,23,615,175);
	FrameRect(hDc,pRect,hBrush4);
	++pRect->left;
	--pRect->right;
	FrameRect(hDc,pRect,hBrush4);
	InflateRect(pRect,-3,-3);
	FrameRect(hDc,pRect,hBrush4);
	++pRect->left;
	--pRect->right;
	FrameRect(hDc,pRect,hBrush4);
}

void DrawButton(DWORD_PTR *lParam)
{
	DRAWITEMSTRUCT *pDI;
	COLORREF FColor,BColor;

	pDI=(DRAWITEMSTRUCT*)lParam;

	BColor=SetBkColor(pDI->hDC,RGB(0,128,128));
	FColor=SetTextColor(pDI->hDC,RGB(0,0,0));
	FillRect(pDI->hDC,&(pDI->rcItem),hBrush2);
	SelectObject(pDI->hDC,hBrush2);

	switch(pDI->CtlID)
	{
	case IDC_YES:
			DrawText(pDI->hDC,_T("YES         "),-1,&pDI->rcItem,DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		break;
	case IDC_NEXT:
			DrawText(pDI->hDC,_T("NEXT        "),-1,&pDI->rcItem,DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		break;
	case IDC_ABOUT:
			DrawText(pDI->hDC,_T("About       "),-1,&pDI->rcItem,DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		break;
	case IDC_OK:
			DrawText(pDI->hDC,_T("OK          "),-1,&pDI->rcItem,DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		break;
	}
	SetTextColor(pDI->hDC,FColor);
	SetBkColor(pDI->hDC,BColor);
}

void MakeDialogTransparent(HWND hWnd,BYTE bTransValue)
{
	SetWindowLongPtr(hWnd,GWL_EXSTYLE,GetWindowLongPtr(hWnd,GWL_EXSTYLE) | WS_EX_LAYERED);
	SetLayeredWindowAttributes(hWnd,0,bTransValue,LWA_ALPHA);
}

void ShowDlgItem(HWND hWnd,DWORD DlgId,int lParam)
{
	ShowWindow(GetDlgItem(hWnd,DlgId),lParam);
}

void CloseWnd(HWND hDlg,int Code)
{
	DeleteObject(hBrush1);
	DeleteObject(hBrush2);
	DeleteObject(hBrush3);
	DeleteObject(hBrush4);
	EndDialog(hDlg,Code);
}

INT_PTR CALLBACK DlgWndProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	int nCommands,nTmp;
	HICON hIcon;
	LOGBRUSH LogBrush;
	RECT Rect;
	TCHAR cTmpBuff[2048],cOutput[256],cString[100];
	DWORD_PTR Ptr;
	INSTRUCTION Instr;
	DISASM_PARAMS Params;

	switch(uMsg)
	{
	case WM_INITDIALOG:
		MakeDialogTransparent(hDlg,240);
		hIcon=LoadIcon(hInstance,(TCHAR*)200);
		SendMessage(hDlg,WM_SETICON,1,(LPARAM)hIcon);
		hOutput=GetDlgItem(hDlg,IDC_OUTPUT);
		hYes=GetDlgItem(hDlg,IDC_YES);
		hNext=GetDlgItem(hDlg,IDC_NEXT);
		hAbout=GetDlgItem(hDlg,IDC_ABOUT);
		hOK=GetDlgItem(hDlg,IDC_OK);

		ShowWindow(hOK,SW_HIDE);
		ShowDlgItem(hDlg,IDC_STATICABOUT,SW_HIDE);

		hBrush1=CreateSolidBrush(RGB(0,128,128));
		hBrush2=CreateSolidBrush(RGB(0,0,0));
		hBrush3=CreateSolidBrush(RGB(0,0,0x80));
		hBrush4=CreateSolidBrush(RGB(0,255,255));

		if(lParam!=0)
		{
			if(szNum[1]==_T('9'))
			{
				if(szNum[0]==_T('9'))
					szNum[0]=_T('0');
				else
					++szNum[0];
				szNum[1]=_T('0');
			}
			else
				++szNum[1];
			GetDlgItemText(hDlg,IDC_STATICCAPTION,cTmpBuff,_countof(cTmpBuff));
			cTmpBuff[2]=szNum[0];
			cTmpBuff[3]=szNum[1];
			SetDlgItemText(hDlg,IDC_STATICCAPTION,cTmpBuff);

			Ptr=(DWORD_PTR)lParam;
			cTmpBuff[0]=_T('\0');
			Params.arch=ARCH_ALL;
			Params.base=Ptr;
			Params.options=DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP | DISASM_OPTION_COMPUTE_RIP;
			Params.sf_prefixes=NULL;
#if defined _M_AMD64
			Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
			Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
			for(nCommands=0;nCommands<13;++nCommands)
			{
				if(IsBadReadPtr((void*)Ptr,2*MAX_INSTRUCTION_LEN))
					break;
				if(medi_disassemble((uint8_t*)Ptr,2*MAX_INSTRUCTION_LEN,&Instr,&Params)!=DASM_ERR_OK)
					break;
				cOutput[medi_dump(&Instr,cOutput,_countof(cOutput),NULL)]=_T('\0');
				_stprintf_s(cString,_T("%I64X:   %s\r\n"),Params.base,cOutput);
				_tcscat_s(cTmpBuff,cString);
				Ptr+=Instr.length;
				Params.base+=Instr.length;
			}
			SetDlgItemText(hDlg,IDC_OUTPUT,cTmpBuff);
		}
		else
			ExitProcess(0);
		return 1;
	case WM_ERASEBKGND:
		{
		LogBrush.lbStyle=BS_SOLID;
		LogBrush.lbColor=RGB(1,1,1);
		HBRUSH hBrush=CreateBrushIndirect(&LogBrush);
		GetClientRect(hDlg,&Rect);
		FillRect((HDC)wParam,&Rect,hBrush);
		DeleteObject(hBrush);
		wndEraseBkg(&Rect,(HDC)wParam);
		return 1;
		}
	case WM_CTLCOLORDLG:
		return(INT_PTR)hBrush2;
	case WM_CTLCOLORSTATIC:
	case WM_CTLCOLOREDIT:
		SelectObject((HDC)wParam,hBrush2);
		nTmp=GetDlgCtrlID((HWND)lParam);
		switch(nTmp)
		{
		case IDC_OUTPUT:
			SetTextColor((HDC)wParam,RGB(0,255,255));
			SetBkColor((HDC)wParam,RGB(0,0,128));
			return(INT_PTR)hBrush3;
		case IDC_STATICCAPTION:
			SetTextColor((HDC)wParam,RGB(0,0,0));
			SetBkMode((HDC)wParam,TRANSPARENT);
			return(INT_PTR)hBrush1;
		case IDC_STATICABOUT:
			SetTextColor((HDC)wParam,RGB(0,255,255));
			SetBkMode((HDC)wParam,TRANSPARENT);
			return(INT_PTR)hBrush3;
		case -1:
			SetTextColor((HDC)wParam,RGB(0xc0,0xc0,0xc0));
			SetBkMode((HDC)wParam,TRANSPARENT);
			return(INT_PTR)hBrush2;
		}
		break;
	case WM_DRAWITEM:
		DrawButton((DWORD_PTR*)lParam);
		return 1;
	case WM_LBUTTONDOWN:
		SendMessage(hDlg,WM_NCLBUTTONDOWN,HTCAPTION,lParam);
		return 1;
	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
		case IDC_YES:
			if(!fAbout)
				CloseWnd(hDlg,1);
			break;
		case IDC_ABOUT:
			if(!fAbout)
			{
				ShowWindow(hYes,SW_HIDE);
				ShowWindow(hNext,SW_HIDE);
				ShowWindow(hAbout,SW_HIDE);
				ShowWindow(hOutput,SW_HIDE);
				ShowWindow(hOK,SW_SHOW);

				CreateRect(&Rect,35,47,585,157);
				FillRect(GetDC(hDlg),&Rect,hBrush2);

				fAbout=TRUE;

				ShowDlgItem(hDlg,IDC_STATICABOUT,SW_SHOW);
			}
			break;
		case IDC_NEXT:
			if(!fAbout)
				CloseWnd(hDlg,0);
		case IDC_OK:
			if(fAbout)
			{
				ShowDlgItem(hDlg,IDC_STATICABOUT,SW_HIDE);
				ShowWindow(hOK,SW_HIDE);

				ShowWindow(hYes,SW_SHOW);
				ShowWindow(hNext,SW_SHOW);
				ShowWindow(hAbout,SW_SHOW);

				wndEraseBkg(&Rect,GetDC(hDlg));

				ShowWindow(hOutput,SW_SHOW);

				fAbout=FALSE;
			}
			break;
		}
		return 1;
	case WM_CLOSE:
		CloseWnd(hDlg,0);
		break;
	}
	return 0;
}

BOOL IsGoodInstruction(DWORD_PTR TempOEP)
{
	BYTE bCode;
	int i;
	INSTRUCTION Instr;
	DISASM_PARAMS Params;

	Params.arch=ARCH_ALL;
	Params.base=0;
	Params.options=0;
	Params.sf_prefixes=NULL;
#if defined _M_AMD64
	Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
	Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
	medi_disassemble((uint8_t*)TempOEP,2*MAX_INSTRUCTION_LEN,&Instr,&Params);

	if((Instr.prefixes & (INSTR_PREFIX_REP_MASK | INSTR_PREFIX_LOCK))!=0)
		return FALSE;

	if(Instr.opcodes[0]==0x0f)
		bCode=OEPopcodeTableEx[Instr.opcodes[1]];
	else
		bCode=OEPopcodeTable[Instr.opcodes[0]];
	if(bCode==1)
		return FALSE;

	if(bCode==2 && (Instr.prefixes & INSTR_PREFIX_SS)==0)
	{
		if((Instr.modrm & 0xc0)!=0xc0)
			return FALSE;
	}

	if(bCode==3 && Instr.disp.size==0)
		return FALSE;

	OLD_EP OldEP;
	for(i=0;i!=(int)EpArray.size();++i)
		if(EpArray[i].OldIp==TempOEP && EpArray[i].Bytes==*(DWORD*)TempOEP)
			return FALSE;

	OldEP.OldIp=TempOEP;
	OldEP.Bytes=*(DWORD*)TempOEP;
	EpArray.push_back(OldEP);

	return TRUE;
}

void CheckOEP(DWORD_PTR TempOEP,PEXCEPTION_POINTERS pRecord)
{
	if(!IsBadReadPtr((void*)TempOEP,2*MAX_INSTRUCTION_LEN))
	{
		if(IsGoodInstruction(TempOEP))
		{
			OEP=TempOEP;
			if(DialogBoxParam(hInstance,MAKEINTRESOURCE(IDD_MAINDLG),NULL,&DlgWndProc,OEP)!=0)
				ExitProcess(0);
		}
	}
	if(fHWBP)
	{
		fHWBP=FALSE;
		InstallHWBP(pRecord->ContextRecord);
	}
}

LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS pRecord)
{
	LONG Result=EXCEPTION_CONTINUE_SEARCH;
	PCONTEXT pContext;
	DWORD_PTR TempOEP;

	EnterCriticalSection(&CriticalSection);
#if defined _M_AMD64
	TempOEP=pRecord->ContextRecord->Rip;
#elif defined _M_IX86
	TempOEP=pRecord->ContextRecord->Eip;
#else
!!!
#endif
	switch(pRecord->ExceptionRecord->ExceptionCode)
	{
	case STATUS_GUARD_PAGE_VIOLATION:
		if(IfInRange(TempOEP,ImageBase,dwImageSize))
			CheckOEP(TempOEP,pRecord);
		if(fHWBP)
		{
			fHWBP=FALSE;
			InstallHWBP(pRecord->ContextRecord);
		}
		Result=EXCEPTION_CONTINUE_EXECUTION;
		break;
	case STATUS_ACCESS_VIOLATION:
		 switch(TempOEP)
		 {
		 case 0xDEADC0DE:	// uninstall
			pContext=pRecord->ContextRecord;
			pContext->Dr0=0;
			pContext->Dr1=0;
			pContext->Dr2=0;
			pContext->Dr3=0;
			pContext->Dr6=0;
			pContext->Dr7=0;
			BackSpToIp(pRecord);
			Result=EXCEPTION_CONTINUE_EXECUTION;
		 	break;
		 case 0xBAADC0DE:	// install
			InstallHWBP(pRecord->ContextRecord);
			BackSpToIp(pRecord);
			Result=EXCEPTION_CONTINUE_EXECUTION;
			break;
		}
		break;
	case STATUS_SINGLE_STEP:
		if(IfInRange(TempOEP,ImageBase,dwImageSize))
		{
			*(DWORD_PTR*)&DummyFunc=0xdeadc0de;
			DummyFunc();
			fHWBP=TRUE;
			CheckOEP(TempOEP,pRecord);
		}
		Result=EXCEPTION_CONTINUE_EXECUTION;
		break;
	}
	LeaveCriticalSection(&CriticalSection);
	return Result;
}

void ProtectMemory()
{
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MemInfo;
	DWORD_PTR Ptr=ImageBase;

	if(fExit)
		return;

	do
	{
		VirtualQuery((void*)Ptr,&MemInfo,sizeof(MemInfo));
		if((MemInfo.Protect & 0xff)==PAGE_EXECUTE_WRITECOPY)
			MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_EXECUTE_READWRITE;
		if((MemInfo.Protect & 0xff)==PAGE_WRITECOPY)
			MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_READWRITE;
		VirtualProtect((void*)Ptr,MemInfo.RegionSize,MemInfo.Protect | PAGE_GUARD,&dwOldProtect);
		Ptr+=MemInfo.RegionSize;
	}
	while(Ptr<ImageBase+dwImageSize);
}

void UnprotectMemory()
{
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MemInfo;
	DWORD_PTR Ptr=ImageBase;

	do
	{
		VirtualQuery((void*)Ptr,&MemInfo,sizeof(MemInfo));
		VirtualProtect((void*)Ptr,MemInfo.RegionSize,MemInfo.Protect & ~PAGE_GUARD,&dwOldProtect);
		Ptr+=MemInfo.RegionSize;
	}
	while(Ptr<ImageBase+dwImageSize);
}

NTSTATUS __stdcall MyTerminateProcess(HANDLE hProcess,NTSTATUS)
{
	fExit=TRUE;
	UnprotectMemory();
	return OldTerminateProcess(hProcess,(DWORD)(OEP-ImageBase));
}

NTSTATUS __stdcall MyLoadLibrary(PWSTR SearchPath,PULONG pFlags,PVOID DllName,PVOID *pBaseAddress)
{
	ProtectMemory();
	return OldLoadLibrary(SearchPath,pFlags,DllName,pBaseAddress);
}

NTSTATUS __stdcall MyGetProcAddressForCaller(HMODULE hModule,PVOID FunctionName,WORD wOrdinal,
											 PVOID *pFunctionAddress,PULONG pFlags,PVOID ReturnAddress)
{
	ProtectMemory();
	return OldGetProcAddressForCaller(hModule,FunctionName,wOrdinal,pFunctionAddress,pFlags,ReturnAddress);
}

NTSTATUS __stdcall MyGetProcAddress(HMODULE hModule,PVOID FunctionName,WORD wOrdinal,PVOID *pFunctionAddress)
{
	ProtectMemory();
	return OldGetProcAddress(hModule,FunctionName,wOrdinal,pFunctionAddress);
}

BYTE HookStub[]={
#if defined _M_AMD64
							0x48,0xb8,0,0,0,0,0,0,0,0,		//mov rax,MY_HOOK
							0xff,0xe0};						//jmp rax
#elif defined _M_IX86
							0xb8,0,0,0,0,					//mov eax,MY_HOOK
							0xff,0xe0};						//jmp eax
#else
!!!
#endif

void HookFunc(DWORD_PTR HookAddr,DWORD_PTR MyHook,DWORD_PTR *pOldHook)
{
	DWORD dwOldProtect;
	DWORD_PTR i,Ptr;
	INSTRUCTION Instr;
	DISASM_PARAMS Params;

	i=CutTo(HookAddr,PAGE_SIZE);
	do
	{
		i+=PAGE_SIZE;
		Ptr=(DWORD_PTR)VirtualAlloc((void*)i,PAGE_SIZE,MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	}
	while(Ptr==0);

	i=0;
	Params.arch=ARCH_ALL;
	Params.base=0;
	Params.options=0;
	Params.sf_prefixes=NULL;
#if defined _M_AMD64
	Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
	Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
	do
	{
		medi_disassemble((uint8_t*)(HookAddr+i),BUFSIZ_INFINITY,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	*(DWORD_PTR*)(HookStub+sizeof(DWORD_PTR)/4)=MyHook;

	memcpy((void*)Ptr,HookStub,sizeof(HookStub));
	memcpy((void*)(Ptr+sizeof(HookStub)),(void*)HookAddr,i);
	*(BYTE*)(Ptr+sizeof(HookStub)+i)=0xe9;
	*(DWORD*)(Ptr+sizeof(HookStub)+i+1)=(DWORD)(HookAddr-Ptr-sizeof(HookStub)-5);

	*pOldHook=Ptr+sizeof(HookStub);

	VirtualProtect((void*)HookAddr,5,PAGE_EXECUTE_READWRITE,&dwOldProtect);
	*(BYTE*)HookAddr=0xe9;
	*(DWORD*)(HookAddr+1)=(DWORD)(Ptr-HookAddr-5);
	VirtualProtect((void*)HookAddr,5,dwOldProtect,&dwOldProtect);
}

void GetOEP()
{
	DWORD_PTR Address;
	IMAGE_NT_HEADERS *pNTHeader;

	pNTHeader=(IMAGE_NT_HEADERS*)(ImageBase+((IMAGE_DOS_HEADER*)ImageBase)->e_lfanew);
	dwImageSize=pNTHeader->OptionalHeader.SizeOfImage;

	ProtectMemory();

	Address=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtTerminateProcess");
	HookFunc(Address,(DWORD_PTR)&MyTerminateProcess,(DWORD_PTR*)&OldTerminateProcess);
	Address=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"LdrLoadDll");
	HookFunc(Address,(DWORD_PTR)&MyLoadLibrary,(DWORD_PTR*)&OldLoadLibrary);
	Address=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"LdrGetProcedureAddressForCaller");
	if(Address!=0)
		HookFunc(Address,(DWORD_PTR)&MyGetProcAddressForCaller,(DWORD_PTR*)&OldGetProcAddressForCaller);
	else
	{
		Address=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"LdrGetProcedureAddress");
		HookFunc(Address,(DWORD_PTR)&MyGetProcAddress,(DWORD_PTR*)&OldGetProcAddress);
	}

	AddVectoredExceptionHandler(0,&VEHHandler);

	*(DWORD_PTR*)&DummyFunc=0xbaadc0de;
	DummyFunc();
}

void __stdcall GetOEPEXE()
{
	ImageBase=(DWORD_PTR)GetModuleHandle(NULL);
#if defined _M_AMD64
	ESP=(DWORD_PTR)_AddressOfReturnAddress()+4*sizeof(DWORD_PTR)+0x28;
#elif defined _M_IX86
	ESP=(DWORD_PTR)_AddressOfReturnAddress()+4*sizeof(DWORD_PTR);
#else
!!!
#endif
	GetOEP();
};

void __stdcall GetOEPDLL(DWORD_PTR hModule)
{
	ImageBase=hModule;
#if defined _M_AMD64
	ESP=(DWORD_PTR)_AddressOfReturnAddress()-sizeof(DWORD_PTR);
#elif defined _M_IX86
	ESP=(DWORD_PTR)_AddressOfReturnAddress()-3*sizeof(DWORD_PTR);
#else
!!!
#endif
	GetOEP();
}

BOOL __stdcall DllMain(HINSTANCE hInst,DWORD dwReason,void*)
{
	if(dwReason==DLL_PROCESS_ATTACH)
	{
		hInstance=hInst;
		InitializeCriticalSection(&CriticalSection);
		DisableThreadLibraryCalls((HMODULE)hInstance);
	}
	return TRUE;
}