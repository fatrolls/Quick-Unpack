#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>

#include "mediana.h"
#include "resource.h"

using namespace std;

const DWORD PAGE_SIZE=0x1000;
const DWORD SECTOR_SIZE=0x200;
DWORD_PTR ImageBase;

HANDLE hInstance;
BOOL fIsDll,fCanDump;
HWND hNumOfThreads,hSections,hRangeStart,hRangeSize,hMemStart,hMemEnd;

CONTEXT Context;
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

void RestoreGuard(HANDLE hProcess,DWORD dwBaseStart,DWORD dwRange)
{
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION MemInfo;

	if(ImageBase==0)
		return;

	for(DWORD_PTR i=ImageBase+dwBaseStart;i<ImageBase+dwBaseStart+dwRange;)
	{
		VirtualQueryEx(hProcess,(void*)i,&MemInfo,sizeof(MemInfo));
		if((MemInfo.Protect & 0xff)==PAGE_EXECUTE_WRITECOPY)
			MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_EXECUTE_READWRITE;
		if((MemInfo.Protect & 0xff)==PAGE_WRITECOPY)
			MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_READWRITE;
		VirtualProtectEx(hProcess,(void*)i,MemInfo.RegionSize,MemInfo.Protect | PAGE_GUARD,&dwOldProtect);
		i+=MemInfo.RegionSize;
	}
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

BYTE NewOpenProcess1[]={
#if defined _M_AMD64
						0x4C,0x89,0xc8,											//mov rax,r9
#elif defined _M_IX86
						0x8B,0x44,0x24,0x10,									//mov eax,[esp+10]
#else
!!!
#endif
						0x81,0x38,0x78,0x56,0x34,0x12};							//cmp [eax/rax],12345678
BYTE NewOpenProcess2[]={0xB8,0x22,0,0,0xC0,										//mov eax,C0000022
						0x75,0x03,												//jnz +1
#if defined _M_AMD64
						0xC3,0x90,0x90};										//ret
#elif defined _M_IX86
						0xC2,0x10,0};											//ret 10
#else
!!!
#endif

void HookOpenProcess(HANDLE hProcess)
{
	DWORD dwOldProtect;
	BYTE bJmp=0xe9;
	DWORD dwOffset;
	DWORD_PTR bOpenProcess=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtOpenProcess");

	VirtualProtectEx(hProcess,(void*)bOpenProcess,PAGE_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);

	void *Address;
	DWORD_PTR NTBase=(DWORD_PTR)GetModuleHandle(_T("ntdll.dll"));
	do
	{
		NTBase+=PAGE_SIZE;
		Address=VirtualAllocEx(hProcess,(void*)NTBase,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(Address==NULL);

	BYTE bTempMem[3*MAX_INSTRUCTION_LEN];
	ReadProcessMemory(hProcess,(void*)bOpenProcess,&bTempMem,sizeof(bTempMem),NULL);

	int i=0;
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
	do
	{
		medi_disassemble((uint8_t*)(bTempMem+i),sizeof(bTempMem)-i,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	BYTE *pOldOpenProcess=new BYTE[i];
	ReadProcessMemory(hProcess,(void*)bOpenProcess,pOldOpenProcess,i,NULL);

	WriteProcessMemory(hProcess,(void*)bOpenProcess,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)((DWORD_PTR)Address-bOpenProcess-5);
	WriteProcessMemory(hProcess,(void*)(bOpenProcess+1),&dwOffset,sizeof(dwOffset),NULL);

	WriteProcessMemory(hProcess,Address,&NewOpenProcess1,sizeof(NewOpenProcess1),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewOpenProcess1),&NewOpenProcess2,sizeof(NewOpenProcess2),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewOpenProcess1)+sizeof(NewOpenProcess2),pOldOpenProcess,i,NULL);

	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewOpenProcess1)+sizeof(NewOpenProcess2)+i,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)(bOpenProcess-(DWORD_PTR)Address-sizeof(NewOpenProcess1)-sizeof(NewOpenProcess2)-5);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewOpenProcess1)+sizeof(NewOpenProcess2)+i+1,&dwOffset,sizeof(dwOffset),NULL);

	VirtualProtectEx(hProcess,(void*)bOpenProcess,PAGE_SIZE,dwOldProtect,&dwOldProtect);
	delete[] pOldOpenProcess;
}

BYTE NewQueryInformationProcess2[]={
#if defined _M_AMD64
						0x4C,0x89,0xC0,											//mov rax,r8
#elif defined _M_IX86
						0x8B,0x44,0x24,0x0C,									//mov eax,[esp+C]
#else
!!!
#endif
						0xC7,0,0,0,0,0,											//mov [eax/rax],0
#if defined _M_AMD64
						0xC3};													//ret
#elif defined _M_IX86
						0xC2,0x14,0};											//ret 14
#else
!!!
#endif
BYTE NewQueryInformationProcess1[]={
#if defined _M_AMD64
						0x83,0xFA,0x07,											//cmp edx,7
#elif defined _M_IX86
						0x83,0x7C,0x24,0x08,0x07,								//cmp [esp+8],7
#else
!!!
#endif
						0x75,sizeof(NewQueryInformationProcess2)};				//jne _exit

void HookQInfProcess(HANDLE hProcess)
{
	DWORD dwOldProtect;
	BYTE bJmp=0xe9;
	DWORD dwOffset;
	DWORD_PTR bQueryInformationProcess=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtQueryInformationProcess");

	VirtualProtectEx(hProcess,(void*)bQueryInformationProcess,PAGE_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);

	void *Address;
	DWORD_PTR NTBase=(DWORD_PTR)GetModuleHandle(_T("ntdll.dll"));
	do
	{
		NTBase+=PAGE_SIZE;
		Address=VirtualAllocEx(hProcess,(void*)NTBase,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(Address==NULL);

	BYTE bTempMem[3*MAX_INSTRUCTION_LEN];
	ReadProcessMemory(hProcess,(void*)bQueryInformationProcess,&bTempMem,sizeof(bTempMem),NULL);

	int i=0;
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
	do
	{
		medi_disassemble((uint8_t*)(bTempMem+i),sizeof(bTempMem)-i,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	BYTE *pOldQueryInformationProcess=new BYTE[i];
	ReadProcessMemory(hProcess,(void*)bQueryInformationProcess,pOldQueryInformationProcess,i,NULL);

	WriteProcessMemory(hProcess,(void*)bQueryInformationProcess,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)((DWORD_PTR)Address-bQueryInformationProcess-5);
	WriteProcessMemory(hProcess,(void*)(bQueryInformationProcess+1),&dwOffset,sizeof(dwOffset),NULL);

	WriteProcessMemory(hProcess,Address,&NewQueryInformationProcess1,sizeof(NewQueryInformationProcess1),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewQueryInformationProcess1),&NewQueryInformationProcess2,sizeof(NewQueryInformationProcess2),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewQueryInformationProcess1)+sizeof(NewQueryInformationProcess2),pOldQueryInformationProcess,i,NULL);

	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewQueryInformationProcess1)+sizeof(NewQueryInformationProcess2)+i,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)(bQueryInformationProcess-(DWORD_PTR)Address-sizeof(NewQueryInformationProcess1)-sizeof(NewQueryInformationProcess2)-5);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewQueryInformationProcess1)+sizeof(NewQueryInformationProcess2)+i+1,&dwOffset,sizeof(dwOffset),NULL);

	VirtualProtectEx(hProcess,(void*)bQueryInformationProcess,PAGE_SIZE,dwOldProtect,&dwOldProtect);
	delete[] pOldQueryInformationProcess;
}

BYTE NewSetInformationThread2[]={
#if defined _M_AMD64
						0xC3};													//ret
#elif defined _M_IX86
						0xC2,0x10,0};											//ret 10
#else
!!!
#endif
BYTE NewSetInformationThread1[]={
#if defined _M_AMD64
						0x83,0xFA,0x11,											//cmp edx,11
#elif defined _M_IX86
						0x83,0x7C,0x24,0x08,0x11,								//cmp [esp+8],11
#else
!!!
#endif
						0x75,sizeof(NewSetInformationThread2)};					//jne _exit

void HookSetInfThread(HANDLE hProcess)
{
	DWORD dwOldProtect;
	BYTE bJmp=0xe9;
	DWORD dwOffset;
	DWORD_PTR bSetInformationThread=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtSetInformationThread");

	VirtualProtectEx(hProcess,(void*)bSetInformationThread,PAGE_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);

	void *Address;
	DWORD_PTR NTBase=(DWORD_PTR)GetModuleHandle(_T("ntdll.dll"));
	do
	{
		NTBase+=PAGE_SIZE;
		Address=VirtualAllocEx(hProcess,(void*)NTBase,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(Address==NULL);

	BYTE bTempMem[3*MAX_INSTRUCTION_LEN];
	ReadProcessMemory(hProcess,(void*)bSetInformationThread,&bTempMem,sizeof(bTempMem),NULL);

	int i=0;
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
	do
	{
		medi_disassemble((uint8_t*)(bTempMem+i),sizeof(bTempMem)-i,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	BYTE *pOldSetInformationThread=new BYTE[i];
	ReadProcessMemory(hProcess,(void*)bSetInformationThread,pOldSetInformationThread,i,NULL);

	WriteProcessMemory(hProcess,(void*)bSetInformationThread,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)((DWORD_PTR)Address-bSetInformationThread-5);
	WriteProcessMemory(hProcess,(void*)(bSetInformationThread+1),&dwOffset,sizeof(dwOffset),NULL);

	WriteProcessMemory(hProcess,Address,&NewSetInformationThread1,sizeof(NewSetInformationThread1),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewSetInformationThread1),&NewSetInformationThread2,sizeof(NewSetInformationThread2),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewSetInformationThread1)+sizeof(NewSetInformationThread2),pOldSetInformationThread,i,NULL);

	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewSetInformationThread1)+sizeof(NewSetInformationThread2)+i,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)(bSetInformationThread-(DWORD_PTR)Address-sizeof(NewSetInformationThread1)-sizeof(NewSetInformationThread2)-5);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewSetInformationThread1)+sizeof(NewSetInformationThread2)+i+1,&dwOffset,sizeof(dwOffset),NULL);

	VirtualProtectEx(hProcess,(void*)bSetInformationThread,PAGE_SIZE,dwOldProtect,&dwOldProtect);
	delete[] pOldSetInformationThread;
}

BYTE NewCreateThread2[]={
#if defined _M_AMD64
						0xC3,													//ret
#elif defined _M_IX86
						0xC2,0x20,0,											//ret 20
#else
!!!
#endif
						0xff,0x08};												//dec [eax/rax]
BYTE NewCreateThread1[]={0xE8,0x04,0,0,0,										//call +1
						0,0,0,0,
						0x58,													//pop eax/rax
						0x83,0x38,0,											//cmp [eax/rax],0
						0x75,sizeof(NewCreateThread2)-2};						//jne _exit

void HookCreateThread(HANDLE hProcess)
{
	DWORD dwOldProtect;
	BYTE bJmp=0xe9;
	DWORD dwOffset;
	DWORD_PTR bCreateThread=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtCreateThread");

	VirtualProtectEx(hProcess,(void*)bCreateThread,PAGE_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);

	void *Address;
	DWORD_PTR NTBase=(DWORD_PTR)GetModuleHandle(_T("ntdll.dll"));
	do
	{
		NTBase+=PAGE_SIZE;
		Address=VirtualAllocEx(hProcess,(void*)NTBase,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(Address==NULL);

	BYTE bTempMem[3*MAX_INSTRUCTION_LEN];
	ReadProcessMemory(hProcess,(void*)bCreateThread,&bTempMem,sizeof(bTempMem),NULL);

	int i=0;
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
	do
	{
		medi_disassemble((uint8_t*)(bTempMem+i),sizeof(bTempMem)-i,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	BYTE *pOldCreateThread=new BYTE[i];
	ReadProcessMemory(hProcess,(void*)bCreateThread,pOldCreateThread,i,NULL);

	WriteProcessMemory(hProcess,(void*)bCreateThread,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)((DWORD_PTR)Address-bCreateThread-5);
	WriteProcessMemory(hProcess,(void*)(bCreateThread+1),&dwOffset,sizeof(dwOffset),NULL);

	WriteProcessMemory(hProcess,Address,&NewCreateThread1,sizeof(NewCreateThread1),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewCreateThread1),&NewCreateThread2,sizeof(NewCreateThread2),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewCreateThread1)+sizeof(NewCreateThread2),pOldCreateThread,i,NULL);

	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewCreateThread1)+sizeof(NewCreateThread2)+i,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)(bCreateThread-(DWORD_PTR)Address-sizeof(NewCreateThread1)-sizeof(NewCreateThread2)-5);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewCreateThread1)+sizeof(NewCreateThread2)+i+1,&dwOffset,sizeof(dwOffset),NULL);

	VirtualProtectEx(hProcess,(void*)bCreateThread,PAGE_SIZE,dwOldProtect,&dwOldProtect);
	delete[] pOldCreateThread;
}

BYTE NewAllocMemory[]={
#if defined _M_AMD64
						0x48,0x89,0xd0,											//mov rax,rdx
						0x48,0xC7,0,0,0,0,0};									//mov [rax],0
#elif defined _M_IX86
						0x8B,0x44,0x24,0x08,									//mov eax,[esp+8]
						0xC7,0,0,0,0,0};										//mov [eax],0
#else
!!!
#endif

void HookAllocMemory(HANDLE hProcess)
{
	DWORD dwOldProtect;
	BYTE bJmp=0xe9;
	DWORD dwOffset;
	DWORD_PTR bAllocMemory=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtAllocateVirtualMemory");

	VirtualProtectEx(hProcess,(void*)bAllocMemory,PAGE_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);

	void *Address;
	DWORD_PTR NTBase=(DWORD_PTR)GetModuleHandle(_T("ntdll.dll"));
	do
	{
		NTBase+=PAGE_SIZE;
		Address=VirtualAllocEx(hProcess,(void*)NTBase,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(Address==NULL);

	BYTE bTempMem[3*MAX_INSTRUCTION_LEN];
	ReadProcessMemory(hProcess,(void*)bAllocMemory,&bTempMem,sizeof(bTempMem),NULL);

	int i=0;
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
	do
	{
		medi_disassemble((uint8_t*)(bTempMem+i),sizeof(bTempMem)-i,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	BYTE *pOldAllocMemory=new BYTE[i];
	ReadProcessMemory(hProcess,(void*)bAllocMemory,pOldAllocMemory,i,NULL);

	WriteProcessMemory(hProcess,(void*)bAllocMemory,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)((DWORD_PTR)Address-bAllocMemory-5);
	WriteProcessMemory(hProcess,(void*)(bAllocMemory+1),&dwOffset,sizeof(dwOffset),NULL);

	WriteProcessMemory(hProcess,Address,&NewAllocMemory,sizeof(NewAllocMemory),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewAllocMemory),pOldAllocMemory,i,NULL);

	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewAllocMemory)+i,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)(bAllocMemory-(DWORD_PTR)Address-sizeof(NewAllocMemory)-5);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewAllocMemory)+i+1,&dwOffset,sizeof(dwOffset),NULL);

	VirtualProtectEx(hProcess,(void*)bAllocMemory,PAGE_SIZE,dwOldProtect,&dwOldProtect);
	delete[] pOldAllocMemory;
}

BYTE NewVirtualProtect5[]={
#if defined _M_AMD64
						0x49,0x81,0xc9,0,0x01,0,0,								//or r9,100
#elif defined _M_IX86
						0x81,0x4C,0x24,0x10,0,0x01,0,0,							//or [esp+10],100
#else
!!!
#endif
						0x58};													//pop eax/rax
BYTE NewVirtualProtect4[]={
#if defined _M_AMD64
						0x48,0xb8,0,0,0,0,0,0,0,0,								//mov rax,start
						0x48,0x3B,0x04,0x24,									//cmp rax,[rsp]
#elif defined _M_IX86
						0xb8,0,0,0,0,											//mov eax,start
						0x3B,0x04,0x24,											//cmp eax,[esp]
#else
!!!
#endif
						0x73,sizeof(NewVirtualProtect5)-1};						//jae _exit
BYTE NewVirtualProtect3[]={
#if defined _M_AMD64
						0x4C,0x89,0xC0,											//mov rax,r8
						0x48,0x8B,0,											//mov rax,[rax]
						0x01,0x04,0x24};										//add [rsp],rax
#elif defined _M_IX86
						0x8B,0x44,0x24,0x10,									//mov eax,[esp+10]
						0x8B,0,													//mov eax,[eax]
						0x01,0x04,0x24};										//add [esp],eax
#else
!!!
#endif
BYTE NewVirtualProtect2[]={
#if defined _M_AMD64
						0x48,0xb8,0,0,0,0,0,0,0,0,								//mov rax,end
						0x48,0x3B,0x04,0x24,									//cmp rax,[rsp]
#elif defined _M_IX86
						0xb8,0,0,0,0,											//mov eax,end
						0x3B,0x04,0x24,											//cmp eax,[esp]
#else
!!!
#endif
						0x76,sizeof(NewVirtualProtect3)+sizeof(NewVirtualProtect4)+sizeof(NewVirtualProtect5)-1};//jbe _exit
BYTE NewVirtualProtect1[]={
#if defined _M_AMD64
						0x48,0x89,0xd0,											//mov rax,rdx
						0x48,0xff,0x30};										//push [rax]
#elif defined _M_IX86
						0x8B,0x44,0x24,0x08,									//mov eax,[esp+8]
						0xff,0x30};												//push [eax]
#else
!!!
#endif

void HookVirtProtect(HANDLE hProcess)
{
	DWORD dwOldProtect;
	BYTE bJmp=0xe9;
	DWORD dwOffset;
	DWORD_PTR bVirtualProtect=(DWORD_PTR)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtProtectVirtualMemory");

	VirtualProtectEx(hProcess,(void*)bVirtualProtect,PAGE_SIZE,PAGE_EXECUTE_READWRITE,&dwOldProtect);

	void *Address;
	DWORD_PTR NTBase=(DWORD_PTR)GetModuleHandle(_T("ntdll.dll"));
	do
	{
		NTBase+=PAGE_SIZE;
		Address=VirtualAllocEx(hProcess,(void*)NTBase,PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	}
	while(Address==NULL);

	BYTE bTempMem[3*MAX_INSTRUCTION_LEN];
	ReadProcessMemory(hProcess,(void*)bVirtualProtect,&bTempMem,sizeof(bTempMem),NULL);

	int i=0;
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
	do
	{
		medi_disassemble((uint8_t*)(bTempMem+i),sizeof(bTempMem)-i,&Instr,&Params);
		i+=Instr.length;
	}
	while(i<5);

	BYTE *pOldVirtualProtect=new BYTE[i];
	ReadProcessMemory(hProcess,(void*)bVirtualProtect,pOldVirtualProtect,i,NULL);

	WriteProcessMemory(hProcess,(void*)bVirtualProtect,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)((DWORD_PTR)Address-bVirtualProtect-5);
	WriteProcessMemory(hProcess,(void*)(bVirtualProtect+1),&dwOffset,sizeof(dwOffset),NULL);

	WriteProcessMemory(hProcess,Address,&NewVirtualProtect1,sizeof(NewVirtualProtect1),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1),&NewVirtualProtect2,sizeof(NewVirtualProtect2),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1)+sizeof(NewVirtualProtect2),&NewVirtualProtect3,sizeof(NewVirtualProtect3),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1)+sizeof(NewVirtualProtect2)+sizeof(NewVirtualProtect3),&NewVirtualProtect4,sizeof(NewVirtualProtect4),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1)+sizeof(NewVirtualProtect2)+sizeof(NewVirtualProtect3)+sizeof(NewVirtualProtect4),&NewVirtualProtect5,sizeof(NewVirtualProtect5),NULL);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1)+sizeof(NewVirtualProtect2)+sizeof(NewVirtualProtect3)+sizeof(NewVirtualProtect4)+sizeof(NewVirtualProtect5),pOldVirtualProtect,i,NULL);

	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1)+sizeof(NewVirtualProtect2)+sizeof(NewVirtualProtect3)+sizeof(NewVirtualProtect4)+sizeof(NewVirtualProtect5)+i,&bJmp,sizeof(bJmp),NULL);
	dwOffset=(DWORD)(bVirtualProtect-(DWORD_PTR)Address-sizeof(NewVirtualProtect1)-sizeof(NewVirtualProtect2)-sizeof(NewVirtualProtect3)-sizeof(NewVirtualProtect4)-sizeof(NewVirtualProtect5)-5);
	WriteProcessMemory(hProcess,(BYTE*)Address+sizeof(NewVirtualProtect1)+sizeof(NewVirtualProtect2)+sizeof(NewVirtualProtect3)+sizeof(NewVirtualProtect4)+sizeof(NewVirtualProtect5)+i+1,&dwOffset,sizeof(dwOffset),NULL);

	VirtualProtectEx(hProcess,(void*)bVirtualProtect,PAGE_SIZE,dwOldProtect,&dwOldProtect);
	delete[] pOldVirtualProtect;
}

#if defined _M_AMD64
const DWORD IBoffset=0x3000;
const DWORD INT3offset=0x1088+1;
#elif defined _M_IX86
const DWORD IBoffset=0x3000;
const DWORD INT3offset=0x1098+1;
#else
!!!
#endif

void FindOEP(HWND hwndDialog)
{
	WORD wStolenBytes;
	DWORD_PTR ExeBase=0,Int3Addr=0;
	int nPatched=0;
	BOOL fUseInt3,fHookVirtualAlloc,fHookVirtualProtect;

	DWORD dwBaseStart,dwRange;
	DWORD_PTR LastIp=0;

	fUseInt3=IsDlgButtonChecked(hwndDialog,IDC_USEINT3);
	fHookVirtualAlloc=IsDlgButtonChecked(hwndDialog,IDC_HOOKALLOCK);
	fHookVirtualProtect=IsDlgButtonChecked(hwndDialog,IDC_HOOKPROTECT);

	int nNumOfThreadsCount[]={0,1,2,-1};
	*(DWORD*)(NewCreateThread1+5)=nNumOfThreadsCount[SendMessage(hNumOfThreads,CB_GETCURSEL,0,0)];

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

	STARTUPINFO StartupInfo;
	memset(&StartupInfo,0,sizeof(StartupInfo));
	memset(&ProcessInformation,0,sizeof(ProcessInformation));
	StartupInfo.cb=sizeof(StartupInfo);

	BOOL bResult=FALSE,bFirstBreak=TRUE;

	if(!fIsDll)
	{
		TCHAR cParam[2*MAX_PATH+3];
		_tcscpy_s(cParam,_T("\""));
		_tcscat_s(cParam,cBuffer);
		_tcscat_s(cParam,_T("\" "));
		_tcscat_s(cParam,cCommand);
		bResult=CreateProcess(NULL,cParam,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,&StartupInfo,&ProcessInformation);
	}
	else
	{
		_tcscat_s(cBuffer,_T("1"));

		TCHAR cBuffer2[MAX_PATH];
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
		bResult=CreateProcess(cBuffer2,cBuffer,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,&StartupInfo,&ProcessInformation);
	}

	if(!bResult)
		return;

	DEBUG_EVENT DebugEvent;
	for(;;)
	{
		if(GetAsyncKeyState(VK_ESCAPE)!=0)
		{
			DebugActiveProcessStop(ProcessInformation.dwProcessId);
			TerminateProcess(ProcessInformation.hProcess,0);
			ImageBase=0;
			break;
		}
		if(!WaitForDebugEvent(&DebugEvent,1000))
			continue;

		if(DebugEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)
		{
			ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
			ImageBase=0;
			break;
		}
		else if(DebugEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)
		{
			CloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
			if(!fIsDll)
				ImageBase=(DWORD_PTR)DebugEvent.u.CreateProcessInfo.lpBaseOfImage;
			ExeBase=(DWORD_PTR)DebugEvent.u.CreateProcessInfo.lpBaseOfImage;

			if(IsDlgButtonChecked(hwndDialog,IDC_KILLLOWALLOCK)==BST_CHECKED)
			{
				void *pTmpAddressAlloc=NULL;

				do pTmpAddressAlloc=VirtualAllocEx(ProcessInformation.hProcess,NULL,PAGE_SIZE,MEM_RESERVE,PAGE_EXECUTE_READWRITE);
				while(ImageBase>((DWORD_PTR)pTmpAddressAlloc));

				VirtualFreeEx(ProcessInformation.hProcess,pTmpAddressAlloc,0,MEM_RELEASE);
			}
			GetThreadContext(ProcessInformation.hThread,&Context);

#if defined _M_AMD64
//			mov		rax,qword ptr gs:[30h]
//			mov		rcx,qword ptr [rax+60h]
//			movzx	eax,byte ptr [rcx+2]

			DWORD_PTR Gs60,Addr=(DWORD_PTR)DebugEvent.u.CreateProcessInfo.lpThreadLocalBase+0x60;
			BYTE Zero=0;

			ReadProcessMemory(ProcessInformation.hProcess,(void*)Addr,&Gs60,sizeof(Gs60),NULL);
			WriteProcessMemory(ProcessInformation.hProcess,(void*)(Gs60+2),&Zero,sizeof(Zero),NULL);
			LastIp=Context.Rip;
#elif defined _M_IX86
//			MOV EAX,DWORD PTR FS:[18]
//			MOV EAX,DWORD PTR DS:[EAX+30]
//			MOVZX EAX,BYTE PTR DS:[EAX+2]

			DWORD_PTR Fs30,Addr=(DWORD_PTR)DebugEvent.u.CreateProcessInfo.lpThreadLocalBase+0x30;
			BYTE Zero=0;

			ReadProcessMemory(ProcessInformation.hProcess,(void*)Addr,&Fs30,sizeof(Fs30),NULL);
			WriteProcessMemory(ProcessInformation.hProcess,(void*)(Fs30+2),&Zero,sizeof(Zero),NULL);
			LastIp=Context.Eip;
#else
!!!
#endif
			RestoreGuard(ProcessInformation.hProcess,dwBaseStart,dwRange);
			ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
			continue;
		}
		else if(DebugEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
		{
			CloseHandle(DebugEvent.u.CreateThread.hThread);
			ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
			continue;
		}
		else if(DebugEvent.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT)
		{
			CloseHandle(DebugEvent.u.LoadDll.hFile);

			if(nPatched==0 && DebugEvent.u.LoadDll.lpBaseOfDll==GetModuleHandle(_T("ntdll.dll")))
				nPatched=1;
			if(nPatched==1 && ImageBase!=0)
			{
				nPatched=2;

				*(DWORD_PTR*)(NewVirtualProtect2+sizeof(DWORD_PTR)/4)=ImageBase+dwBaseStart+dwRange;
				*(DWORD_PTR*)(NewVirtualProtect4+sizeof(DWORD_PTR)/4)=ImageBase+dwBaseStart;

				HookOpenProcess(ProcessInformation.hProcess);
				HookQInfProcess(ProcessInformation.hProcess);
				HookSetInfThread(ProcessInformation.hProcess);
				HookCreateThread(ProcessInformation.hProcess);
				if(fHookVirtualAlloc)
					HookAllocMemory(ProcessInformation.hProcess);
				if(fHookVirtualProtect)
					HookVirtProtect(ProcessInformation.hProcess);
			}
			ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
			continue;
		}
		else if(DebugEvent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)
		{
			if(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode==STATUS_INVALID_HANDLE)
			{
				RestoreGuard(ProcessInformation.hProcess,dwBaseStart,dwRange);
				ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
				continue;
			}
			else if(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP)
			{
				if(!fUseInt3 && Int3Addr!=0)
				{
					GetThreadContext(ProcessInformation.hThread,&Context);
#if defined _M_AMD64
					if(Int3Addr!=Context.Rip)
#elif defined _M_IX86
					if(Int3Addr!=Context.Eip)
#else
!!!
#endif
					{
						RestoreGuard(ProcessInformation.hProcess,dwBaseStart,dwRange);
						Int3Addr=0;
					}
					else
					{
						Context.EFlags |= 0x100;
						SetThreadContext(ProcessInformation.hThread,&Context);
					}
					ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
					continue;
				}
			}
			else if(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT)
			{
				if(fIsDll)
				{
					GetThreadContext(ProcessInformation.hThread,&Context);
#if defined _M_AMD64
					if(Context.Rip==ExeBase+INT3offset)
#elif defined _M_IX86
					if(Context.Eip==ExeBase+INT3offset)
#else
!!!
#endif
					{
						ReadProcessMemory(ProcessInformation.hProcess,(void*)(ExeBase+IBoffset),&ImageBase,sizeof(ImageBase),NULL);
						RestoreGuard(ProcessInformation.hProcess,dwBaseStart,dwRange);
						ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
						continue;
					}
				}

				if(fUseInt3 && Int3Addr!=0)
				{
					GetThreadContext(ProcessInformation.hThread,&Context);
#if defined _M_AMD64
					--Context.Rip;
#elif defined _M_IX86
					--Context.Eip;
#else
!!!
#endif

#if defined _M_AMD64
					if(Int3Addr==Context.Rip)
#elif defined _M_IX86
					if(Int3Addr==Context.Eip)
#else
!!!
#endif
					{
						WriteProcessMemory(ProcessInformation.hProcess,(void*)Int3Addr,&wStolenBytes,1,NULL);
						SetThreadContext(ProcessInformation.hThread,&Context);
						RestoreGuard(ProcessInformation.hProcess,dwBaseStart,dwRange);
						Int3Addr=0;
						ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
						continue;
					}
				}
				RestoreGuard(ProcessInformation.hProcess,dwBaseStart,dwRange);
				if(bFirstBreak)
				{
					ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
					bFirstBreak=FALSE;
					continue;
				}
			}
			else if(DebugEvent.u.Exception.ExceptionRecord.ExceptionCode==STATUS_GUARD_PAGE_VIOLATION)
			{
				GetThreadContext(ProcessInformation.hThread,&Context);

				DWORD_PTR TempLastIp=LastIp;
#if defined _M_AMD64
				DWORD_PTR TempIp=Context.Rip;
#elif defined _M_IX86
				DWORD_PTR TempIp=Context.Eip;
#else
!!!
#endif
				LastIp=TempIp;

				INSTRUCTION Instr;
				DISASM_PARAMS Params;
				BOOL fOurStop=FALSE;
				Params.arch=ARCH_ALL;
				Params.options=DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP | DISASM_OPTION_COMPUTE_RIP;
				Params.sf_prefixes=NULL;
#if defined _M_AMD64
				Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
				Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
				if(ImageBase!=0 && TempIp<=ImageBase+dwBaseStart+dwRange && TempIp>=ImageBase+dwBaseStart &&
					abs((int)(TempLastIp-TempIp))>=16)
				{
					fOurStop=TRUE;
					HGLOBAL pMem=GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,10000);

					DWORD dwCommands=13;
					BYTE bTempArray[13*MAX_INSTRUCTION_LEN];

					TCHAR cAddr[sizeof(DWORD_PTR)*2+2],cOutput[256];
#if defined _M_AMD64
					DWORD_PTR CurrAddr=Context.Rip;
#elif defined _M_IX86
					DWORD_PTR CurrAddr=Context.Eip;
#else
!!!
#endif
					Params.base=CurrAddr;
					ReadProcessMemory(ProcessInformation.hProcess,(void*)CurrAddr,&bTempArray,sizeof(bTempArray),NULL);

					int nLen=0;
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
					int nResult=MessageBox(hwndDialog,(TCHAR*)pMem,_T("Is this OEP?"),MB_YESNO);
					GlobalFree(pMem);

					if(nResult==IDYES)
					{
#if defined _M_AMD64
						ImageBase=Context.Rip-ImageBase;
#elif defined _M_IX86
						ImageBase=Context.Eip-ImageBase;
#else
!!!
#endif
						if(!fDetach)
						{
							DebugActiveProcessStop(ProcessInformation.dwProcessId);
							TerminateProcess(ProcessInformation.hProcess,0);
							CloseHandle(ProcessInformation.hThread);
							CloseHandle(ProcessInformation.hProcess);
							EndDialog(hwndDialog,0);
							return;
						}
						else
						{
							WORD wInfJmp=0xFEEB;
#if defined _M_AMD64
							ReadProcessMemory(ProcessInformation.hProcess,(void*)Context.Rip,&wStolenBytes,sizeof(wStolenBytes),NULL);
							WriteProcessMemory(ProcessInformation.hProcess,(void*)Context.Rip,&wInfJmp,sizeof(wInfJmp),NULL);
#elif defined _M_IX86
							ReadProcessMemory(ProcessInformation.hProcess,(void*)Context.Eip,&wStolenBytes,sizeof(wStolenBytes),NULL);
							WriteProcessMemory(ProcessInformation.hProcess,(void*)Context.Eip,&wInfJmp,sizeof(wInfJmp),NULL);
#else
!!!
#endif
							ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
							DebugActiveProcessStop(ProcessInformation.dwProcessId);

							wStolenBytes=_byteswap_ushort(wStolenBytes);
							TCHAR cStolenText[5];
							_stprintf_s(cStolenText,_T("%04X"),wStolenBytes);
							MessageBox(hwndDialog,cStolenText,_T("Rewritten 2 bytes"),MB_OK);
							SendMessage(hMemStart,EM_SETREADONLY,0,0);
							SendMessage(hMemEnd,EM_SETREADONLY,0,0);
							fCanDump=TRUE;
							break;
						}
					}
					else
						fOurStop=FALSE;
				}

				if(!fOurStop)
				{
					if(fUseInt3)
					{
						if(Int3Addr!=0)
						{
							ReadProcessMemory(ProcessInformation.hProcess,(void*)Int3Addr,&wStolenBytes+1,1,NULL);
							if((wStolenBytes & 0xff)==0xcc)
								WriteProcessMemory(ProcessInformation.hProcess,(void*)Int3Addr,&wStolenBytes,1,NULL);
						}
						BYTE bOpcode[MAX_INSTRUCTION_LEN];
#if defined _M_AMD64
						ReadProcessMemory(ProcessInformation.hProcess,(void*)Context.Rip,&bOpcode,sizeof(bOpcode),NULL);
#elif defined _M_IX86
						ReadProcessMemory(ProcessInformation.hProcess,(void*)Context.Eip,&bOpcode,sizeof(bOpcode),NULL);
#else
!!!
#endif
						if(bOpcode[0]!=0xc3)
						{
							medi_disassemble((uint8_t*)bOpcode,sizeof(bOpcode),&Instr,&Params);
#if defined _M_AMD64
							Int3Addr=Context.Rip+Instr.length;
#elif defined _M_IX86
							Int3Addr=Context.Eip+Instr.length;
#else
!!!
#endif
							ReadProcessMemory(ProcessInformation.hProcess,(void*)Int3Addr,&wStolenBytes,1,NULL);
							BYTE bInt3=0xcc;
							WriteProcessMemory(ProcessInformation.hProcess,(void*)Int3Addr,&bInt3,sizeof(bInt3),NULL);
						}
					}
					else
					{
						GetThreadContext(ProcessInformation.hThread,&Context);
						Context.EFlags |= 0x100;
						SetThreadContext(ProcessInformation.hThread,&Context);
#if defined _M_AMD64
						Int3Addr=Context.Rip;
#elif defined _M_IX86
						Int3Addr=Context.Eip;
#else
!!!
#endif
					}
					ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_CONTINUE);
					continue;
				}
			}
		}
		ContinueDebugEvent(DebugEvent.dwProcessId,DebugEvent.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
	}
	CloseHandle(ProcessInformation.hThread);
	CloseHandle(ProcessInformation.hProcess);
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
			Context.ContextFlags=CONTEXT_FULL;

			*(DWORD*)(NewOpenProcess1+sizeof(NewOpenProcess1)-sizeof(DWORD))=GetCurrentProcessId();

			hNumOfThreads=GetDlgItem(hwndDialog,IDC_NUMOFTHREADS);
			SendMessage(hNumOfThreads,CB_ADDSTRING,0,(LPARAM)_T("0"));
			SendMessage(hNumOfThreads,CB_ADDSTRING,0,(LPARAM)_T("1"));
			SendMessage(hNumOfThreads,CB_ADDSTRING,0,(LPARAM)_T("2"));
			SendMessage(hNumOfThreads,CB_ADDSTRING,0,(LPARAM)_T("All"));
			SendMessage(hNumOfThreads,CB_SETCURSEL,3,0);

			CheckDlgButton(hwndDialog,IDC_HOOKPROTECT,BST_CHECKED);

			hSections=GetDlgItem(hwndDialog,IDC_SECTIONS);
			hRangeStart=GetDlgItem(hwndDialog,IDC_RANGESTART);
			hRangeSize=GetDlgItem(hwndDialog,IDC_RANGESIZE);
			hMemStart=GetDlgItem(hwndDialog,IDC_MEMSTART);
			hMemEnd=GetDlgItem(hwndDialog,IDC_MEMEND);

			lstrcpy(cBuffer,(TCHAR*)ImageBase);
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
	return _T("Generic OEP Finder by Archer & Human");
}