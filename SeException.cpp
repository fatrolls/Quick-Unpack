#include "stdafx.h"
#include "SeException.h"
#include <imagehlp.h>
#include ".\\Disasm\\mediana.h"

HANDLE hFile,hFileMapping;
void *pMemory;

typedef struct THUNK_INFO
{
	DWORD dwThunkRva;
	char *szDllName;
	char *szApiName;
} *PTHUNK_INFO;

typedef struct IT_INFO
{
	IMAGE_IMPORT_DESCRIPTOR *pIID;
	std::vector<DWORD> dwIIDThunkNum;
	std::vector<PTHUNK_INFO> dscApis;
} *PIT_INFO;

IT_INFO IT;

#define CASE(nSeCode,CsString) case EXCEPTION_##nSeCode: \
								CsString.Format(_T("Exception %s (0x%08x) at address 0x%0*IX."),_T(#nSeCode),EXCEPTION_##nSeCode,sizeof(DWORD_PTR)*2,pExcPointers->ExceptionRecord->ExceptionAddress); \
								break;

bool CleanUpAll()
{
	size_t c=IT.dscApis.size();
	while(c!=0)
	{
		--c;
		delete IT.dscApis[c];
	}
	IT.dscApis.clear();
	IT.dwIIDThunkNum.clear();
	return true;
}

bool ProcessImportTableInformation()
{
	IMAGE_IMPORT_DESCRIPTOR *pIID;
	DWORD dwIID,dwThunks;
	DWORD_PTR *pdwThunk,*pdwOrgThunk;
	bool fRet=true;
	PTHUNK_INFO TI;
	char *szDllName;
	TCHAR szFileName[MAX_PATH];
	DWORD dwExeSize;
	IMAGE_NT_HEADERS *pPEHeader;

	if(GetModuleFileName(NULL,szFileName,_countof(szFileName))==0)
		return false;

	hFile=CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
	dwExeSize=GetFileSize(hFile,NULL);
	hFileMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,dwExeSize,NULL);
	pMemory=MapViewOfFile(hFileMapping,FILE_MAP_READ,0,0,0);
	pPEHeader=ImageNtHeader(pMemory);
	pIID=(IMAGE_IMPORT_DESCRIPTOR*)ImageRvaToVa(pPEHeader,pMemory,pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,NULL);

	if(pIID==NULL)
		return false;
	IT.pIID=pIID;

	dwIID=0;
	CleanUpAll();
	while(pIID->FirstThunk!=0 && pIID->Name!=0)
	{
		szDllName=(char*)ImageRvaToVa(pPEHeader,pMemory,pIID->Name,NULL);
		if(szDllName==NULL)
			szDllName="???";

		pdwThunk=(DWORD_PTR*)ImageRvaToVa(pPEHeader,pMemory,pIID->FirstThunk,NULL);

		if(pIID->OriginalFirstThunk!=0)
			pdwOrgThunk=(DWORD_PTR*)ImageRvaToVa(pPEHeader,pMemory,pIID->OriginalFirstThunk,NULL);
		else
			pdwOrgThunk=pdwThunk;

		dwThunks=0;
		if(pdwThunk==NULL || pdwOrgThunk==NULL)
			fRet=false;
		else
		{
			while(*pdwThunk!=0)
			{
				TI=new THUNK_INFO;
				TI->dwThunkRva=pIID->FirstThunk+dwThunks*sizeof(DWORD);
				TI->szDllName=szDllName;

				if(IMAGE_SNAP_BY_ORDINAL(*pdwOrgThunk))
					TI->szApiName=(char*)*pdwOrgThunk;
				else
				{
					TI->szApiName=(char*)ImageRvaToVa(pPEHeader,pMemory,(DWORD)(*pdwOrgThunk+2),NULL);
					if(TI->szApiName==0)
						TI->szApiName="???";
				}

				IT.dscApis.push_back(TI);

				++dwThunks;
				++pdwThunk;
				++pdwOrgThunk;
			}
		}
		IT.dwIIDThunkNum.push_back(dwThunks);

		++dwIID;
		++pIID;
	}
	return fRet;
}

bool IsApiCall(DWORD_PTR VA,DWORD_PTR ImageBase)
{
	DWORD dwRVA;
	DWORD i=0;
	IMAGE_IMPORT_DESCRIPTOR *pIID=IT.pIID;

	dwRVA=(DWORD)(VA-ImageBase);
	__try
	{
		while(pIID->FirstThunk!=0)
		{
			if(dwRVA>=pIID->FirstThunk && dwRVA<=pIID->FirstThunk+IT.dwIIDThunkNum[i]*sizeof(DWORD))
				return true;
			++pIID;
			++i;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return false;
}

PTHUNK_INFO GetThunkInfo(DWORD_PTR IatVA,DWORD_PTR ImageBase)
{
	DWORD dwITRva=(DWORD)(IatVA-ImageBase);
	for(size_t i=0;i!=IT.dscApis.size();++i)
	{
		PTHUNK_INFO pTI=IT.dscApis[i];
		if(pTI->dwThunkRva==dwITRva)
			return pTI;
	}
	return NULL;
}

void Disasm(CString &sOutBuf,void *pAddr)
{
	TCHAR cBuff[0x400];
	void *cPtr;
	INSTRUCTION Instr;
	DISASM_PARAMS Params;
	CString sFormat;
	int nInstrNum;
	void *pBeginAddr=pAddr;
	CString sComment;

	PTHUNK_INFO pTI;
	ProcessImportTableInformation();

	pAddr=(BYTE*)pAddr-OFFSET_TO_DISASM;
	nInstrNum=0;
	cPtr=pAddr;
	Params.arch=ARCH_ALL;
	Params.base=(DWORD_PTR)cPtr;
	Params.options=DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP | DISASM_OPTION_COMPUTE_RIP;
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
		if(medi_disassemble((uint8_t*)cPtr,BUFSIZ_INFINITY,&Instr,&Params)!=DASM_ERR_OK)
			break;
		_stprintf_s(cBuff,_T("%I64X:"),Params.base);
		size_t nTempLen=_tcslen(cBuff);
		cBuff[nTempLen++]=_T(' ');
		cBuff[nTempLen++]=_T(' ');
		cBuff[nTempLen++]=_T(' ');
		nTempLen+=medi_dump(&Instr,cBuff+nTempLen,_countof(cBuff)-nTempLen,NULL);
		cBuff[nTempLen]=_T('\0');

		if(*((BYTE*)cPtr+Instr.opcode_offset)==0xff)
		{
			DWORD_PTR Address;
#if defined _M_AMD64
			if(Instr.disp.size==8)
				Address=(DWORD_PTR)Instr.disp.value.d64;
			else
				Address=(DWORD_PTR)cPtr+Instr.length+(DWORD_PTR)Instr.disp.value.d64;
#elif defined _M_IX86
			Address=(DWORD_PTR)Instr.disp.value.d64;
#else
!!!
#endif
			if(IsApiCall(Address,(DWORD_PTR)GetModuleHandle(NULL)))
			{
				pTI=GetThunkInfo(Address,(DWORD_PTR)GetModuleHandle(NULL));
				if(IMAGE_SNAP_BY_ORDINAL((DWORD_PTR)pTI->szApiName))
				{
#ifdef UNICODE
					int nMultiLength=(int)strlen(pTI->szDllName)+1;
					WCHAR *pWideArray=new WCHAR[nMultiLength];
					MultiByteToWideChar(CP_ACP,0,pTI->szDllName,nMultiLength,pWideArray,nMultiLength);
					sComment.Format(_T(" ; %s!Ordinal 0x%04X"),pWideArray,IMAGE_ORDINAL((DWORD_PTR)pTI->szApiName));
					delete[] pWideArray;
#else
					sComment.Format(_T(" ; %s!Ordinal 0x%04X"),pTI->szDllName,IMAGE_ORDINAL((DWORD_PTR)pTI->szApiName));
#endif
				}
				else
				{
#ifdef UNICODE
					int nMultiLength1=(int)strlen(pTI->szDllName)+1;
					int nMultiLength2=(int)strlen(pTI->szApiName)+1;
					WCHAR *pWideArray1=new WCHAR[nMultiLength1];
					WCHAR *pWideArray2=new WCHAR[nMultiLength2];
					MultiByteToWideChar(CP_ACP,0,pTI->szDllName,nMultiLength1,pWideArray1,nMultiLength1);
					MultiByteToWideChar(CP_ACP,0,pTI->szApiName,nMultiLength2,pWideArray2,nMultiLength2);
					sComment.Format(_T(" ; %s!%s"),pWideArray1,pWideArray2);
					delete[] pWideArray1;
					delete[] pWideArray2;
#else
					sComment.Format(_T(" ; %s!%s"),pTI->szDllName,pTI->szApiName);
#endif
				}
			}
			_tcscat_s(cBuff,sComment);
		}
		if(cPtr==pBeginAddr)
			sFormat.Format(_T("--> %s \r\n"),cBuff);
		else
			sFormat.Format(_T("%s \r\n"),cBuff);

		sOutBuf+=sFormat;
		cPtr=(BYTE*)cPtr+Instr.length;
		Params.base+=Instr.length;
		++nInstrNum;
	}
	while(nInstrNum!=INSTRS_TO_DISASM);

	UnmapViewOfFile(pMemory);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
}

void SeTranslator(UINT dwSeCode,EXCEPTION_POINTERS *pExcPointers)
{
	CSeException *pSe=new CSeException(dwSeCode,pExcPointers);

#if defined _M_AMD64
	DWORD_PTR *sp=(DWORD_PTR*)pExcPointers->ContextRecord->Rbp;
#elif defined _M_IX86
	DWORD_PTR *sp=(DWORD_PTR*)pExcPointers->ContextRecord->Ebp;
#else
!!!
#endif
	for(int i=0;i!=32;++i)
	{
		if(!IsBadReadPtr(sp,sizeof(DWORD_PTR)) && *sp!=0)
		{
			DWORD_PTR *np=(DWORD_PTR*)*sp;
			pSe->m_StackTrace[i]=*(sp+1);
			sp=np;
		}
		else
			pSe->m_StackTrace[i]=0;
	}
	throw pSe;
}

IMPLEMENT_DYNAMIC(CSeException,CException)

CSeException::CSeException(DWORD n_dwSeCode,EXCEPTION_POINTERS *n_pExcPointers)
{
	dwSeCode=n_dwSeCode;
	pExcPointers=n_pExcPointers;
}

CSeException::CSeException(CSeException &CSeExc)
{
	dwSeCode=CSeExc.dwSeCode;
	pExcPointers=CSeExc.pExcPointers;
}

DWORD CSeException::GetSeCode() const
{
	return dwSeCode;
}

EXCEPTION_POINTERS *CSeException::GetSePointers() const
{
	return pExcPointers;
}

void *CSeException::GetExceptionAddress() const
{
	return pExcPointers->ExceptionRecord->ExceptionAddress;
}

void CSeException::Delete()
{
	delete this;
}

void CSeException::ReportError(DWORD dwType,DWORD dwIDHelp) const
{
	CString sMessage;

	GetErrorMessage(sMessage,NULL);
	AfxMessageBox(sMessage,dwType,dwIDHelp);
}

void CSeException::GetErrorMessage(CString &sErrDescr,DWORD *pHelpContext) const
{
	if(pHelpContext!=NULL)
		*pHelpContext=0;

	switch(dwSeCode)
	{
		case EXCEPTION_ACCESS_VIOLATION:
			sErrDescr.Format(_T("Exception ACCESS_VIOLATION (0x%08x) at address 0x%0*IX trying to %s address 0x0*IX."),
				EXCEPTION_ACCESS_VIOLATION,
				sizeof(DWORD_PTR)*2,
				pExcPointers->ExceptionRecord->ExceptionAddress,
				pExcPointers->ExceptionRecord->ExceptionInformation[0]!=0 ? _T("write") : _T("read"),
				sizeof(DWORD_PTR)*2,
				pExcPointers->ExceptionRecord->ExceptionInformation[1]);
			break;
		CASE(DATATYPE_MISALIGNMENT,sErrDescr);
		CASE(BREAKPOINT,sErrDescr);
		CASE(SINGLE_STEP,sErrDescr);
		CASE(ARRAY_BOUNDS_EXCEEDED,sErrDescr);
		CASE(FLT_DENORMAL_OPERAND,sErrDescr);
		CASE(FLT_DIVIDE_BY_ZERO,sErrDescr);
		CASE(FLT_INEXACT_RESULT,sErrDescr);
		CASE(FLT_INVALID_OPERATION,sErrDescr);
		CASE(FLT_OVERFLOW,sErrDescr);
		CASE(FLT_STACK_CHECK,sErrDescr);
		CASE(FLT_UNDERFLOW,sErrDescr);
		CASE(INT_DIVIDE_BY_ZERO,sErrDescr);
		CASE(INT_OVERFLOW,sErrDescr);
		CASE(PRIV_INSTRUCTION,sErrDescr);
		CASE(IN_PAGE_ERROR,sErrDescr);
		CASE(ILLEGAL_INSTRUCTION,sErrDescr);
		CASE(NONCONTINUABLE_EXCEPTION,sErrDescr);
		CASE(STACK_OVERFLOW,sErrDescr);
		CASE(INVALID_DISPOSITION,sErrDescr);
		CASE(GUARD_PAGE,sErrDescr);
		CASE(INVALID_HANDLE,sErrDescr);
	default:
		sErrDescr=_T("Unknown exception.");
		break;
	}
}

void CSeException::GetErrorMessage(TCHAR *szError,DWORD dwMaxError,DWORD *pHelpContext) const
{
	if(pHelpContext!=NULL)
		*pHelpContext=0;

	CString sMessage;
	GetErrorMessage(sMessage,NULL);

	if((DWORD)sMessage.GetLength()>=dwMaxError)
		szError[0]=0;
	else
		_tcscpy_s(szError,dwMaxError,sMessage);
}

void CSeException::FormatDump(CString &sDump) const
{
	CString ExCodeErr=_T("unknown");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION)
		ExCodeErr=_T("EXCEPTION_ACCESS_VIOLATION");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_DATATYPE_MISALIGNMENT)
		ExCodeErr=_T("EXCEPTION_DATATYPE_MISALIGNMENT");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_BREAKPOINT)
		ExCodeErr=_T("EXCEPTION_BREAKPOINT");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_SINGLE_STEP)
		ExCodeErr=_T("EXCEPTION_SINGLE_STEP");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_ARRAY_BOUNDS_EXCEEDED)
		ExCodeErr=_T("EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_DENORMAL_OPERAND)
		ExCodeErr=_T("EXCEPTION_FLT_DENORMAL_OPERAND");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_DIVIDE_BY_ZERO)
		ExCodeErr=_T("EXCEPTION_FLT_DIVIDE_BY_ZERO");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_INEXACT_RESULT)
		ExCodeErr=_T("EXCEPTION_FLT_INEXACT_RESULT");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_INVALID_OPERATION)
		ExCodeErr=_T("EXCEPTION_FLT_INVALID_OPERATION");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_OVERFLOW)
		ExCodeErr=_T("EXCEPTION_FLT_OVERFLOW");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_STACK_CHECK)
		ExCodeErr=_T("EXCEPTION_FLT_STACK_CHECK");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_FLT_UNDERFLOW)
		ExCodeErr=_T("EXCEPTION_FLT_UNDERFLOW");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_INT_DIVIDE_BY_ZERO)
		ExCodeErr=_T("EXCEPTION_INT_DIVIDE_BY_ZERO");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_INT_OVERFLOW)
		ExCodeErr=_T("EXCEPTION_INT_OVERFLOW");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_PRIV_INSTRUCTION)
		ExCodeErr=_T("EXCEPTION_PRIV_INSTRUCTION");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_IN_PAGE_ERROR)
		ExCodeErr=_T("EXCEPTION_IN_PAGE_ERROR");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION)
		ExCodeErr=_T("EXCEPTION_ILLEGAL_INSTRUCTION");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_NONCONTINUABLE_EXCEPTION)
		ExCodeErr=_T("EXCEPTION_NONCONTINUABLE_EXCEPTION");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_STACK_OVERFLOW)
		ExCodeErr=_T("EXCEPTION_STACK_OVERFLOW");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_INVALID_DISPOSITION)
		ExCodeErr=_T("EXCEPTION_INVALID_DISPOSITION");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_GUARD_PAGE)
		ExCodeErr=_T("EXCEPTION_GUARD_PAGE");
	if(pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_INVALID_HANDLE)
		ExCodeErr=_T("EXCEPTION_INVALID_HANDLE");

	sDump.Format(_T("Exception      : %08X (%s)\r\n")
			       _T("Address        : %0*IX\r\n")
				   _T("Access Type    : %s\r\n")
				   _T("Access Address : %0*IX\r\n"),
					pExcPointers->ExceptionRecord->ExceptionCode,
					ExCodeErr.GetBuffer(),
					sizeof(DWORD_PTR)*2,
					pExcPointers->ExceptionRecord->ExceptionAddress,
					pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION ? pExcPointers->ExceptionRecord->ExceptionInformation[0]!=0 ? _T("write"):_T("read"):_T("N/A"),
					sizeof(DWORD_PTR)*2,
					pExcPointers->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION ? pExcPointers->ExceptionRecord->ExceptionInformation[1] : 0);
}

void CSeException::FormatRegs(CString &sDump) const
{
#if defined _M_AMD64
	sDump.Format(_T("Registers      : RAX=%016I64X RIP=%016I64X EFLAGS=%08X\r\n")
				   _T("               : RBX=%016I64X RSP=%016I64X RBP=%016I64X\r\n")
				   _T("               : RCX=%016I64X RSI=%016I64X\r\n")
				   _T("               : RDX=%016I64X RDI=%016I64X\r\n")
				   _T("               : R8=%016I64X R9=%016I64X R10=%016I64X\r\n")
				   _T("               : R11=%016I64X R12=%016I64X R13=%016I64X\r\n")
				   _T("               : R14=%016I64X R15=%016I64X\r\n"),
					pExcPointers->ContextRecord->Rax,
					pExcPointers->ContextRecord->Rip,
					pExcPointers->ContextRecord->EFlags,
					pExcPointers->ContextRecord->Rbx,
					pExcPointers->ContextRecord->Rsp,
					pExcPointers->ContextRecord->Rbp,
					pExcPointers->ContextRecord->Rcx,
					pExcPointers->ContextRecord->Rsi,
					pExcPointers->ContextRecord->Rdx,
					pExcPointers->ContextRecord->Rdi,
					pExcPointers->ContextRecord->R8,
					pExcPointers->ContextRecord->R9,
					pExcPointers->ContextRecord->R10,
					pExcPointers->ContextRecord->R11,
					pExcPointers->ContextRecord->R12,
					pExcPointers->ContextRecord->R13,
					pExcPointers->ContextRecord->R14,
					pExcPointers->ContextRecord->R15
					);
#elif defined _M_IX86
	sDump.Format(_T("Registers      : EAX=%08X CS=%04x EIP=%08X EFLAGS=%08X\r\n")
				 _T("               : EBX=%08X SS=%04x ESP=%08X EBP=%08X\r\n")
				 _T("               : ECX=%08X DS=%04x ESI=%08X FS=%04x\r\n")
				 _T("               : EDX=%08X ES=%04x EDI=%08X GS=%04x\r\n"),
					pExcPointers->ContextRecord->Eax,
					pExcPointers->ContextRecord->SegCs,
					pExcPointers->ContextRecord->Eip,
					pExcPointers->ContextRecord->EFlags,
					pExcPointers->ContextRecord->Ebx,
					pExcPointers->ContextRecord->SegSs,
					pExcPointers->ContextRecord->Esp,
					pExcPointers->ContextRecord->Ebp,
					pExcPointers->ContextRecord->Ecx,
					pExcPointers->ContextRecord->SegDs,
					pExcPointers->ContextRecord->Esi,
					pExcPointers->ContextRecord->SegFs,
					pExcPointers->ContextRecord->Edx,
					pExcPointers->ContextRecord->SegEs,
					pExcPointers->ContextRecord->Edi,
					pExcPointers->ContextRecord->SegGs
					);
#else
!!!
#endif
}

void CSeException::FormatStack(CString &sDump) const
{
	sDump.Format(_T("Stack Trace    : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n")
				 _T("               : %0*IX %0*IX %0*IX %0*IX\r\n"),
					sizeof(DWORD_PTR)*2,
					m_StackTrace[0],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[1],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[2],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[3],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[4],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[5],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[6],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[7],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[8],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[9],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[10],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[11],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[12],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[13],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[14],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[15],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[16],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[17],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[18],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[19],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[20],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[21],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[22],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[23],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[24],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[25],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[26],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[27],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[28],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[29],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[30],
					sizeof(DWORD_PTR)*2,
					m_StackTrace[31]);

	sDump+=_T("\r\nDisassembly    :\r\n\r\n");
	CString sDisasm;
#if defined _M_AMD64
	Disasm(sDisasm,(void*)pExcPointers->ContextRecord->Rip);
#elif defined _M_IX86
	Disasm(sDisasm,(void*)pExcPointers->ContextRecord->Eip);
#else
!!!
#endif
	sDump+=sDisasm;
}