#include <windows.h>
#include <stdio.h>
#include <tchar.h>

typedef DWORD (__stdcall *_Unpack)(const TCHAR *szFileName,DWORD dwTimeout);
_Unpack Unpack;

int _tmain()
{
	HMODULE hModule;
	DWORD dwTemp;
	TCHAR szDllFile[MAX_PATH],szFileToUnpack[MAX_PATH];

	GetCurrentDirectory(_countof(szDllFile),szDllFile);
	_tcscat(szDllFile,_T("\\QUnpack.dll"));

	_tprintf(_T("Enter filename: "));
	_getts(szFileToUnpack);

	hModule=LoadLibrary(szDllFile);
	if(hModule==NULL)
	{
		_tprintf(_T("Couldn't load QUnpack.dll"));
		_getts(szFileToUnpack);
		return -1;
	}
	Unpack=(_Unpack)GetProcAddress(hModule,"UnPack");
	if(Unpack==0)
	{
		_tprintf(_T("Couldn't get address of Unpack procedure"));
		_getts(szFileToUnpack);
		return -1;
	}
	dwTemp=Unpack(szFileToUnpack,15000);
	if(dwTemp==0)
		_tprintf(_T("File successfully unpacked"));
	else if(dwTemp==1)
		_tprintf(_T("Couldn't find OEP"));
	else if(dwTemp==2)
		_tprintf(_T("Timeout reached"));
	else if(dwTemp==3)
		_tprintf(_T("Something went wrong"));
	Sleep(1000);							//needed for the unpacking thread to stop
	FreeLibrary(hModule);
	_getts(szFileToUnpack);

	return 1;
}