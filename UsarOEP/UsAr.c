#include <windows.h>
#include <string.h>
#include <tchar.h>
#include <intrin.h>

const DWORD PAGE_SIZE=0x1000;

DWORD_PTR pMem=0;

TCHAR *__stdcall ShortFinderName()
{
	return _T("Generic OEP Finder by Archer & UsAr");
}

#if defined _M_AMD64
BYTE InjectProc1[]={
					0x41,0x57,						//push r15
					0x41,0x56,						//push r14
					0x41,0x55,						//push r13
					0x41,0x54,						//push r12
					0x41,0x53,						//push r11
					0x41,0x52,						//push r10
					0x41,0x51,						//push r9
					0x41,0x50,						//push r8
					0x50,							//push rax
					0x51,							//push rcx
					0x52,							//push rdx
					0x53,							//push rbx
					0x55,							//push rbp
					0x56,							//push rsi
					0x57,							//push rdi
					0x48,0x83,0xec,0x30,			//sub rsp,30
					0xe8,0,0,0,0};					//call OVER_LIB_NAME
BYTE InjectProc2[]={
					0x59,							//pop rcx
					0x48,0xbb,0,0,0,0,0,0,0,0};		//mov rbx,LOAD_LIBRARY
BYTE InjectProc3[]={
					0xff,0xd3,						//call rbx
					0xe8,0x0a,0,0,0,				//call OVER_FUNC_NAME
					'G','e','t','O','E','P','E','X','E',0,
					0x5a,							//pop rdx
					0x50,							//push rax
					0x59,							//pop rcx
					0x48,0xbb,0,0,0,0,0,0,0,0};		//mov rbx,GET_PROC_ADDRESS
BYTE InjectProc4[]={
					0xff,0xd3,						//call rbx
					0xff,0xd0,						//call rax
					0x48,0x83,0xc4,0x30,			//add rsp,30
					0x5f,							//pop rdi
					0x5e,							//pop rsi
					0x5d,							//pop rbp
					0x5b,							//pop rbx
					0x5a,							//pop rdx
					0x59,							//pop rcx
					0x58,							//pop rax
					0x41,0x58,						//pop r8
					0x41,0x59,						//pop r9
					0x41,0x5a,						//pop r10
					0x41,0x5b,						//pop r11
					0x41,0x5c,						//pop r12
					0x41,0x5d,						//pop r13
					0x41,0x5e,						//pop r14
					0x41,0x5f,						//pop r15
					0xe9,0,0,0,0};					//jmp OLD_EIP
#elif defined _M_IX86
BYTE InjectProc1[]={
					0x60,							//pushad
					0xe8,0,0,0,0};					//call OVER_LIB_NAME
BYTE InjectProc2[]={
					0xbb,0,0,0,0};					//mov ebx,LOAD_LIBRARY
BYTE InjectProc3[]={
					0xff,0xd3,						//call ebx
					0xe8,0x0a,0,0,0,				//call OVER_FUNC_NAME
					'G','e','t','O','E','P','E','X','E',0,
					0x50,							//push eax
					0xbb,0,0,0,0};					//mov ebx,GET_PROC_ADDRESS
BYTE InjectProc4[]={
					0xff,0xd3,						//call ebx
					0xff,0xd0,						//call eax
					0x50,							//popad
					0xe9,0,0,0,0};					//jmp OLD_EIP
#else
!!!
#endif

DWORD_PTR CutTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return Value & ~(Alignment-1);
}

DWORD __stdcall GetOEPNow(const TCHAR *szFileName)
{
	CONTEXT Context;
	DWORD dwNTOffset;
	DWORD_PTR ImageBase,OldImageBase,OldIP,Temp;
	int i;
	DWORD dwOEP;
	TCHAR szLibName[MAX_PATH];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	TCHAR *pCmdLine=LocalAlloc(0,(_tcslen(szFileName)+1)*sizeof(TCHAR));

	GetModuleFileName((HMODULE)pMem,szLibName,_countof(szLibName));
	for(i=(int)_tcslen(szLibName)-1;i>0;--i)
	{
		if(szLibName[i]==_T('\\'))
		{
			szLibName[i]=_T('\0');
			break;
		}
	}
	_tcscat(szLibName,_T("\\UsArdll.d11"));

	RtlSecureZeroMemory(&si,sizeof(si));
	GetStartupInfo(&si);
	si.wShowWindow=SW_SHOW;
	si.cb=sizeof(si);

	_tcscpy(pCmdLine,szFileName);
	CreateProcess(NULL,pCmdLine,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi);
	LocalFree(pCmdLine);

	Context.ContextFlags=CONTEXT_FULL;
	GetThreadContext(pi.hThread,&Context);
#if defined _M_AMD64
	ReadProcessMemory(pi.hProcess,(BYTE*)Context.Rdx+0x10,&ImageBase,sizeof(ImageBase),NULL);
	OldIP=Context.Rcx;
#elif defined _M_IX86
	ReadProcessMemory(pi.hProcess,(BYTE*)Context.Ebx+0x8,&ImageBase,sizeof(ImageBase),NULL);
	OldIP=Context.Eax;
#else
!!!
#endif
	ReadProcessMemory(pi.hProcess,(BYTE*)ImageBase+offsetof(IMAGE_DOS_HEADER,e_lfanew),&dwNTOffset,sizeof(dwNTOffset),NULL);
	ReadProcessMemory(pi.hProcess,(BYTE*)ImageBase+dwNTOffset+offsetof(IMAGE_NT_HEADERS,OptionalHeader.ImageBase),&OldImageBase,sizeof(OldImageBase),NULL);

	Temp=CutTo(ImageBase,PAGE_SIZE);
	do
	{
		Temp+=PAGE_SIZE;
		pMem=(DWORD_PTR)VirtualAllocEx(pi.hProcess,(void*)Temp,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(pMem==0);
#if defined _M_AMD64
	Context.Rcx=pMem-ImageBase+OldImageBase;
#elif defined _M_IX86
	Context.Eax=pMem-ImageBase+OldImageBase;
#else
!!!
#endif
	*(DWORD*)(InjectProc1+sizeof(InjectProc1)-sizeof(DWORD))=(DWORD)(_tcslen(szLibName)+1)*sizeof(szLibName[0]);
	*(DWORD_PTR*)(InjectProc2+sizeof(InjectProc2)-sizeof(DWORD_PTR))=(DWORD_PTR)LoadLibrary;
	*(DWORD_PTR*)(InjectProc3+sizeof(InjectProc3)-sizeof(DWORD_PTR))=(DWORD_PTR)GetProcAddress;
	*(DWORD*)(InjectProc4+sizeof(InjectProc4)-sizeof(DWORD))=(DWORD)(OldIP+ImageBase-OldImageBase-pMem-
		(_tcslen(szLibName)+1)*sizeof(szLibName[0])-sizeof(InjectProc1)-sizeof(InjectProc2)-
		sizeof(InjectProc3)-sizeof(InjectProc4));

	WriteProcessMemory(pi.hProcess,(void*)pMem,InjectProc1,sizeof(InjectProc1),NULL);
	pMem+=sizeof(InjectProc1);
	WriteProcessMemory(pi.hProcess,(void*)pMem,szLibName,(_tcslen(szLibName)+1)*sizeof(szLibName[0]),NULL);
	pMem+=(_tcslen(szLibName)+1)*sizeof(szLibName[0]);
	WriteProcessMemory(pi.hProcess,(void*)pMem,InjectProc2,sizeof(InjectProc2),NULL);
	pMem+=sizeof(InjectProc2);
	WriteProcessMemory(pi.hProcess,(void*)pMem,InjectProc3,sizeof(InjectProc3),NULL);
	pMem+=sizeof(InjectProc3);
	WriteProcessMemory(pi.hProcess,(void*)pMem,InjectProc4,sizeof(InjectProc4),NULL);
	pMem+=sizeof(InjectProc4);

	SetThreadContext(pi.hThread,&Context);
	ResumeThread(pi.hThread);
	WaitForSingleObject(pi.hProcess,INFINITE);
	GetExitCodeProcess(pi.hProcess,&dwOEP);

	return dwOEP;
}

DWORD __stdcall GetDllOEPNow(const TCHAR *szFileName)
{
	int i;
	DWORD dwOEP;
	TCHAR cBuff[512];
	TCHAR szLibName1[MAX_PATH];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	GetModuleFileName((HMODULE)pMem,szLibName1,_countof(szLibName1));
	for(i=(int)_tcslen(szLibName1)-1;i>0;--i)
	{
		if(szLibName1[i]==_T('\\'))
		{
			szLibName1[i]=_T('\0');
			break;
		}
	}
	_tcscat(szLibName1,_T("\\loaddll.exe"));
	_tcscpy(cBuff,szFileName);
	_tcscat(cBuff,_T("0"));
	RtlSecureZeroMemory(&si,sizeof(si));
	GetStartupInfo(&si);
	si.wShowWindow=SW_SHOW;
	CreateProcess(szLibName1,cBuff,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi);
	WaitForSingleObject(pi.hProcess,INFINITE);
	GetExitCodeProcess(pi.hProcess,&dwOEP);

	return dwOEP;
}

BOOL __stdcall DllMain(HANDLE hInst,DWORD dwReason,void *pReserved)
{
	pReserved;

	if(dwReason==DLL_PROCESS_ATTACH)
	{
		pMem=(DWORD_PTR)hInst;
		DisableThreadLibraryCalls((HMODULE)hInst);
	}
	return TRUE;
}