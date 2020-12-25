#pragma once

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"
#include "SeException.h"

class CApp:public CWinApp
{
protected:

public:
	CApp();
	TSTRING sFileName,sTime,sOSName,sOSBuild;
	void CApp::HandleException(CSeException *e) const;
	BOOL CApp::PumpMessage();

public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};

extern CApp theApp;