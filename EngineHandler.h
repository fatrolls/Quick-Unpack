#pragma once

#include "interface.h"
#include <Tlhelp32.h>
#include <winioctl.h>

class CEngine
{
	static HANDLE hEngine;
	DATA_STATE *pContext;
	bool fStartedByThisProgram;
	bool fStartedByThisCopy;

	void GetEngineHandle(bool fShowError);

	void Create(HMODULE hDllHandle);
	void Delete();

	void Control(DWORD dwCode,void *pInData,DWORD dwInSize,void *pOutData,DWORD dwOutSize) const;

public:
	CEngine(HMODULE hDllHandle);
	~CEngine();

	void Hook(DWORD dwPID,DWORD dwInt1,DWORD dwInt0d,DWORD dwInt0e) const;
	void GetState(DATA_STATE *pData) const;
	void SetState(DATA_STATE *pData);
	DWORD_PTR GetModHandle(DWORD dwPID,const TCHAR *szModuleName) const;

	void EmulateRDTSC(DWORD dwHook,DWORD dwShift) const;
	void EmulateCPUID(DWORD dwHook) const;
};