#pragma once

class CSeException:public CException
{
	DECLARE_DYNAMIC(CSeException)
public:
	CSeException(DWORD n_dwSeCode,EXCEPTION_POINTERS *n_pExcPointers);
	CSeException(CSeException &CSeExc);

	DWORD GetSeCode() const;
	EXCEPTION_POINTERS *GetSePointers() const;
	void *GetExceptionAddress() const;

	void Delete();
	void ReportError(DWORD dwType,DWORD dwIDHelp) const;
	void GetErrorMessage(CString &sErrDescr,DWORD *pHelpContext) const;
	void GetErrorMessage(TCHAR *szError,DWORD dwMaxError,DWORD *pHelpContext) const;
private:
	DWORD dwSeCode;
	EXCEPTION_POINTERS *pExcPointers;
public:
	void FormatStack(CString &sDump) const;
	void FormatRegs(CString &sDump) const;
	void FormatDump(CString &sDump) const;
	DWORD_PTR m_StackTrace[32];
};

void SeTranslator(UINT dwSeCode,EXCEPTION_POINTERS *pExcPointers);