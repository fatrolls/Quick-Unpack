#include "stdafx.h"
#include <tlhelp32.h>

int PAGES_COUNT=0x10000;
DWORD PAGE_SIZE=PAGE_SIZE_STATIC;
DWORD PAGE_GRANULARITY=0x10000;

DWORD FUNC_OFFSET=0;
DWORD TRAMPOLINE_OFFSET=0;

DWORD_PTR LoadLibraryAddress=0;

const TCHAR szIDTEngineName[]=_T("QuickUnpackRules.sys");
const TCHAR szVMXEngineName[]=_T("QuickUnpackRulesVMX.sys");
const TCHAR szSVMEngineName[]=_T("QuickUnpackRulesSVM.sys");

TCHAR szDriverName[17]=_T("QuickUnpackRules");
TCHAR szSymbolicLink[17]=_T("QuickUnpackRules");

CString attachedto=_T("Attached to ");
CString cantload=_T("Couldn't load target!");
CString cantopen=_T("Unable to open file ");
CString choosefile=_T("Choose a file to unpack!");
CString cop1=_T("founded by FEUERRADER [AHTeam]");
CString cop2=_T("(c) coded by Archer");
CString findtarget=_T("Find target");
CString findunpacked=_T("Find unpacked");
CString incorroep=_T("OEP is not correct!");
CString invalidpe=_T("Invalid PE File");
CString logsaved1=_T("Log successfully saved");
CString logsaved2=_T("Size of file: ");
CString notmemory=_T("Not enough memory");
CString opened=_T("Opened ");
CString someoep=_T("Some OEP has been detected...");
CString switchfailed=_T("No other engine found");
CString switchedtonormal=_T("Engine changed to normal");
CString switchedtovmm=_T("Engine changed to VMM");
CString unpdeleted=_T("Unpacked file was deleted");
CString unpnotfound=_T("Access denied or unpacked file not found");
#if defined _M_AMD64
CString ver=_T("QuickUnpack 4.3 x64 for Windows XP/2003/Vista/2008/7/8/2012/10/2016");
#elif defined _M_IX86
CString ver=_T("QuickUnpack 4.3 x86 for Windows XP/2003/Vista/2008/7/8/10");
#else
!!!
#endif
CString withpid=_T(" with PID:");

CString bytes=_T(" byte(s)");
CString importtableheader=_T("Import Table, ");
CString importtablebyname=_T("by name, ");
CString importtablebyrec=_T("by record, ");
CString importtablebyref=_T("by reference, ");
CString importtableok=_T("OK");
CString importtableerror=_T("error");
CString exporttofile=_T("Export to file");
CString function=_T("Function");
CString importempty=_T("Import list is empty. Export to file is unavailable.");
CString importexported1=_T("Import list successfully exported");
CString importexported2=_T("Size of list: ");
CString library=_T("Library");
CString name=_T(" Name: ");
CString no=_T("no");
CString yes=_T("yes");
CString noname=_T("[unnamed function]");
CString notfound=_T("Not found in modules!");
CString ordinal=_T("Ord");
CString problem=_T("Problem?");
CString referencerva=_T("Reference RVA");
CString recordrva=_T("Record RVA");

CString badfunction=_T("Something bad happened while executing function ");
CString badloading=_T("Something bad happened while loading library ");
CString badtracing=_T("Something bad happened while tracing import at RVA 0x");
CString breaked=_T("Breaked at ");
CString cantdump=_T("Can't dump file!");
CString closeloaded=_T("Close target, when it will be loaded...");
CString delphiinitfailed=_T("Delphi initialization table processing failed!");
CString delphiinitok=_T("Delphi initialization table was processed");
CString dumping=_T("Dumping...");
CString exceptionat=_T(" exception at ");
CString falsedetected=_T("False breaks detected: ");
CString forceactivated=_T("Force mode activated");
CString from=_T(" from ");
CString importonlylibs=_T("Attention! Only libraries were recovered!");
CString importusedsmart=_T("Used smart import recovery");
CString importusedtracer=_T("Used smart import recovery with tracer");
CString importwasnt=_T("Attention! Import was not recovered!");
CString loaded=_T(" loaded");
CString loadingtarget=_T("Loading target...");
CString module=_T(" - module ");
CString noimportfound=_T("Import thunks not found!");
CString overlayappended=_T("Overlay was appended");
CString overlayexists=_T("Overlay exists but was not processed");
CString processinglibs=_T("Processing libraries... be patient, it may take some time...");
CString processingsmart=_T("Processing import... be patient, it may take some time...");
CString processingtracer=_T("Processing import with tracer... be patient, it may take some time...");
CString relocations=_T("Processing relocations...");
CString sectionsdirs=_T("Last sections and directories were processed");
CString targetloaded=_T("Target loaded at 0x");
CString threadcreated=_T(" new thread created");
CString unpackednotcreated=_T("Unpacked file hasn't been created");
CString unpackedsaved=_T("Unpacked file saved as ");
CString unpackfinished=_T("Unpacking finished");

CString processingfunction=_T("Processing function ");

CString cantterminate=_T("Warning! Process of target couldn't be terminated! PID 0x");

CString exporthooked=_T(" export hooked");
CString importhooked=_T("Import hooked");
CString exportunhooked=_T(" export unhooked");

CString editfunction=_T("Edit function");
CString ord2=_T("ord:");

CString cantluastate=_T("Cannot create Lua state");
CString errorreadingmem=_T("Error when reading memory from ");
CString luascripting=_T("Lua scripting");
CString scriptfinished=_T("Script finished");

void PathToDir(TCHAR *szPath)
{
	TCHAR *pTemp=szPath+_tcslen(szPath);
	for(;pTemp[0]!=_T('\\');--pTemp)
	{
		if(pTemp==szPath)
			return;
	}
	pTemp[0]=_T('\0');
}

const TCHAR *FileFromDir(const TCHAR *szPath)
{
	const TCHAR *pTemp=szPath+_tcslen(szPath);
	for(;pTemp[0]!=_T('\\');--pTemp)
	{
		if(pTemp==szPath)
			return NULL;
	}
	++pTemp;
	return pTemp;
}

void ExtractFilePath(TCHAR *szPath,int nMaxLen,const TCHAR *szFullName)
{
	if(szFullName[0]!=_T('\"'))
		_tcscpy_s(szPath,nMaxLen,szFullName);
	else
		_tcscpy_s(szPath,nMaxLen,szFullName+1);
	PathToDir(szPath);
}

DWORD_PTR AlignTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return (Value+(Alignment-1)) & ~(Alignment-1);
}

DWORD_PTR CutTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return Value & ~(Alignment-1);
}

CString IntToStr(DWORD_PTR Number,int nRadix,int nLength)
{
	TCHAR cBuff[0x400];
	_ui64tot_s(Number,cBuff,_countof(cBuff),nRadix);
	CString sResult=cBuff;
	while(sResult.GetLength()<nLength)
		sResult=_T("0")+sResult;
	sResult.MakeUpper();
	return sResult;
}

BOOL CreateRestrictedProcess(const TCHAR *pApplicationName,const TCHAR *pCommandLine,DWORD dwCreationFlags,const TCHAR *pCurrentDirectory,PROCESS_INFORMATION *pi)
{
	HANDLE hToken,hRestrictedToken;
	OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,&hToken);

	LUID_AND_ATTRIBUTES Luid;
	Luid.Attributes=0;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&Luid.Luid);

	CreateRestrictedToken(hToken,0,0,NULL,1,&Luid,0,NULL,&hRestrictedToken);

	STARTUPINFO si;
	memset(&si,0,sizeof(si));
	si.cb=sizeof(si);

	TCHAR *pCmdLine=_tcsdup(pCommandLine);
	BOOL fResult=CreateProcessAsUser(hRestrictedToken,pApplicationName,pCmdLine,NULL,NULL,FALSE,dwCreationFlags,NULL,pCurrentDirectory,&si,pi);
	free(pCmdLine);
	CloseHandle(hRestrictedToken);
	CloseHandle(hToken);

	return fResult;
}

DWORD_PTR GetIBFromPEB(HANDLE hProcess,const CONTEXT &Context)
{
	struct SHORT_PEB
	{
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		BOOLEAN BitField;
		HANDLE Mutant;
		PVOID ImageBaseAddress;
	};

	DWORD_PTR ImageBase=0;
#if defined _M_AMD64
	ReadProcessMemory(hProcess,(BYTE*)Context.Rdx+offsetof(SHORT_PEB,ImageBaseAddress),&ImageBase,sizeof(ImageBase),NULL);
#elif defined _M_IX86
	ReadProcessMemory(hProcess,(BYTE*)Context.Ebx+offsetof(SHORT_PEB,ImageBaseAddress),&ImageBase,sizeof(ImageBase),NULL);
#else
!!!
#endif
	return ImageBase;
}

bool IsProcessDying(HANDLE hProcess)
{
	DWORD dwExitCode;
	return hProcess==NULL || GetExitCodeProcess(hProcess,&dwExitCode)==FALSE || dwExitCode!=STILL_ACTIVE;
}

bool IsProcessDead(HANDLE hProcess)
{
	return WaitForSingleObject(hProcess,0)==WAIT_OBJECT_0;
}

DWORD GetPIDByTID(DWORD dwTID)
{
	DWORD dwResult=0;
	HANDLE hSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);

	THREADENTRY32 te;
	te.dwSize=sizeof(te);
	if(Thread32First(hSnapshot,&te))
	{
		do
		{
			if(te.th32ThreadID==dwTID)
			{
				dwResult=te.th32OwnerProcessID;
				break;
			}
		}
		while(Thread32Next(hSnapshot,&te));
	}
	CloseHandle(hSnapshot);
	return dwResult;
}

bool IsWOW64(HANDLE hProcess)
{
	typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS)(HANDLE,BOOL*);
	LPFN_ISWOW64PROCESS FnIsWow64Process=(LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"IsWow64Process");

	BOOL fIsWow64=FALSE;
	if(FnIsWow64Process!=NULL)
		FnIsWow64Process(hProcess,&fIsWow64);
	return fIsWow64!=FALSE;
}

BYTE StripNXBit(BYTE Protection)
{
	switch(Protection)
	{
	case PAGE_NOACCESS:
	case PAGE_READONLY:
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
		return Protection;
	case PAGE_EXECUTE:
		return PAGE_NOACCESS;
	case PAGE_EXECUTE_READ:
		return PAGE_READONLY;
	case PAGE_EXECUTE_READWRITE:
		return PAGE_READWRITE;
	case PAGE_EXECUTE_WRITECOPY:
		return PAGE_WRITECOPY;
	default:
		return 0;
	}
}

BYTE GetRandomByte()
{
	SwitchToThread();

	BYTE bResult=0;
	for(int i=0;i!=RTL_BITS_OF(GetRandomByte());++i)
	{
		bResult<<=1;
		for(int j=0;j!=RTL_BITS_OF(__rdtsc());++j)
			bResult^=(__rdtsc() >> j) & 1;
	}
	return bResult;
}