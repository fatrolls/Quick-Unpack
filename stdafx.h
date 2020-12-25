// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers
#endif

#ifndef WINVER
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// some CString constructors will be explicit

// turns off MFC's hiding of some common and often safely ignored warning messages
#define _AFX_ALL_WARNINGS

#include <afxext.h>			// MFC extensions
#include <afxdisp.h>		// MFC Automation classes
#include <afxwin.h>			// MFC core and standard components

#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <afxdhtml.h>
#include <shlwapi.h>
#include <algorithm>
#include <cctype>
#include <map>
#include <string>
#include <vector>
#include <WinSvc.h>

typedef std::basic_string<TCHAR> TSTRING;

struct PAGE_ENTRY
{
	DWORD_PTR Address:RTL_BITS_OF(DWORD_PTR)-2;
	DWORD_PTR Reserved:1;
	DWORD_PTR Committed:1;
};

static const DWORD64 MAXQWORD=0xffffffffffffffff;

static const DWORD_PTR STATUS_SUCCESS=0;
static const DWORD_PTR STATUS_INVALID_PARAMETER=0xc000000d;
static const DWORD_PTR STATUS_CONFLICTING_ADDRESSES=0xc0000018;
static const DWORD_PTR STATUS_UNABLE_TO_FREE_VM=0xc000001a;
static const DWORD_PTR STATUS_INVALID_PAGE_PROTECTION=0xc0000045;
static const DWORD_PTR STATUS_MEMORY_NOT_ALLOCATED=0xc00000a0;
static const DWORD_PTR STATUS_INVALID_PARAMETER_4=0xc00000f2;
static const DWORD_PTR STATUS_INVALID_PARAMETER_5=0xc00000f3;

static const DWORD_PTR TRACE_FLAG=0x100;
static const DWORD_PTR RESUME_FLAG=0x10000;
static const DWORD_PTR DR6_TFHIT=0x4000;
static const WORD UNICODE_MAGIC=0xfeff;
static const DWORD BYTES_IN_PARAGRAPH=0x10;
static const DWORD PAGE_SIZE_STATIC=0x1000;
static const DWORD SECTOR_SIZE=0x200;
static const DWORD MAX_DEST=0x100;
static const DWORD STACK_SHIFT=100;
static const DWORD OFFSET_TO_DISASM=0x20;
static const DWORD INSTRS_TO_DISASM=40;
static const DWORD MAX_SECTIONS=(PAGE_SIZE_STATIC-sizeof(IMAGE_DOS_HEADER)-sizeof(IMAGE_NT_HEADERS))/sizeof(IMAGE_SECTION_HEADER);

extern int PAGES_COUNT;
extern DWORD PAGE_SIZE,PAGE_GRANULARITY;
extern DWORD_PTR LoadLibraryAddress;
extern DWORD FUNC_OFFSET,TRAMPOLINE_OFFSET;
static const DWORD TRAMPOLINE_BREAK_OFFSET=2+sizeof(DWORD_PTR)/4;

enum
{
	bProcessTerminated=0xf00,
	bThreadTerminating=0xf08,
	bSingleStep=0xf10,
	bBreakMem=0xf11,
	bBreakCpuid=0xf12,
	bFunction=0xf20,
	bUnhandledSingleStep=0xf30,
	bUnhandledBreak=0xf31,
	bUnhandledBreakMem=0xf32,
	bDr0=0xf40,
	bDr1=0xf41,
	bDr2=0xf42,
	bDr3=0xf43
};

static const TCHAR GHOST_NAME[]=_T("_ghost.dll");
static const TCHAR LOADER_NAME[]=_T("_loader.exe");

const TCHAR FILE_LOCATION[]=_T("\\QU.ini");
const TCHAR REG_KEY_NAME[]=_T("MainOptions");
const TCHAR REG_VALUE_NAME[]=_T("MainValue");

#if defined _M_AMD64
static const DWORD_PTR MIN_INT=0x8000000000000000;
static const DWORD_PTR MAX_INT=0x7fffffffffffffff;
static const DWORD_PTR MAX_NUM=0xffffffffffffffff;
#elif defined _M_IX86
static const DWORD_PTR MIN_INT=0x80000000;
static const DWORD_PTR MAX_INT=0x7fffffff;
static const DWORD_PTR MAX_NUM=0xffffffff;
#endif

extern const TCHAR szIDTEngineName[];
extern const TCHAR szVMXEngineName[];
extern const TCHAR szSVMEngineName[];

extern TCHAR szDriverName[17];
extern TCHAR szSymbolicLink[17];

extern CString attachedto;
extern CString cantload;
extern CString cantopen;
extern CString choosefile;
extern CString cop1;
extern CString cop2;
extern CString findtarget;
extern CString findunpacked;
extern CString incorroep;
extern CString invalidpe;
extern CString logsaved1;
extern CString logsaved2;
extern CString notmemory;
extern CString opened;
extern CString someoep;
extern CString switchfailed;
extern CString switchedtonormal;
extern CString switchedtovmm;
extern CString unpdeleted;
extern CString unpnotfound;
extern CString ver;
extern CString withpid;

extern CString bytes;
extern CString importtableheader;
extern CString importtablebyname;
extern CString importtablebyrec;
extern CString importtablebyref;
extern CString importtableok;
extern CString importtableerror;
extern CString exporttofile;
extern CString function;
extern CString importempty;
extern CString importexported1;
extern CString importexported2;
extern CString library;
extern CString name;
extern CString no;
extern CString yes;
extern CString noname;
extern CString notfound;
extern CString ordinal;
extern CString problem;
extern CString referencerva;
extern CString recordrva;

extern CString badfunction;
extern CString badloading;
extern CString badtracing;
extern CString breaked;
extern CString cantdump;
extern CString closeloaded;
extern CString delphiinitfailed;
extern CString delphiinitok;
extern CString dumping;
extern CString exceptionat;
extern CString falsedetected;
extern CString forceactivated;
extern CString from;
extern CString importonlylibs;
extern CString importusedsmart;
extern CString importusedtracer;
extern CString importwasnt;
extern CString loaded;
extern CString loadingtarget;
extern CString module;
extern CString noimportfound;
extern CString overlayappended;
extern CString overlayexists;
extern CString processinglibs;
extern CString processingsmart;
extern CString processingtracer;
extern CString relocations;
extern CString sectionsdirs;
extern CString targetloaded;
extern CString threadcreated;
extern CString unpackednotcreated;
extern CString unpackedsaved;
extern CString unpackfinished;

extern CString processingfunction;

extern CString cantterminate;

extern CString exporthooked;
extern CString importhooked;
extern CString exportunhooked;

extern CString editfunction;
extern CString ord2;

extern CString cantluastate;
extern CString errorreadingmem;
extern CString luascripting;
extern CString scriptfinished;

void PathToDir(TCHAR *szPath);
const TCHAR *FileFromDir(const TCHAR *szPath);
void ExtractFilePath(TCHAR *szPath,int nMaxLen,const TCHAR *szFullName);
DWORD_PTR AlignTo(DWORD_PTR Value,DWORD_PTR Alignment);
DWORD_PTR CutTo(DWORD_PTR Value,DWORD_PTR Alignment);
CString IntToStr(DWORD_PTR Number,int nRadix,int nLength);
BOOL CreateRestrictedProcess(const TCHAR *pApplicationName,const TCHAR *pCommandLine,DWORD dwCreationFlags,const TCHAR *pCurrentDirectory,PROCESS_INFORMATION *pi);
DWORD_PTR GetIBFromPEB(HANDLE hProcess,const CONTEXT &Context);
bool IsProcessDying(HANDLE hProcess);
bool IsProcessDead(HANDLE hProcess);
DWORD GetPIDByTID(DWORD dwTID);
bool IsWOW64(HANDLE hProcess);
BYTE StripNXBit(BYTE Protection);
BYTE GetRandomByte();