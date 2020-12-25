#include <windows.h>
#include <stdio.h>
#include <tchar.h>

LONG_PTR(WINAPI *GetOEPDLL)
(
	HMODULE hModuleBase
);

volatile HMODULE hExtra;

void main()
{
	TCHAR *pTmpBuff=GetCommandLine();
	TCHAR bIsNew=pTmpBuff[_tcslen(pTmpBuff)-1];
	pTmpBuff[_tcslen(pTmpBuff)-1]=_T('\0');

	HMODULE hDllBase=LoadLibrary(pTmpBuff);
	if(hDllBase==NULL)
		return;

	switch(bIsNew)
	{
	case _T('0'):
		{
		TCHAR szLibUsArDLLdl1[MAX_PATH];
		GetModuleFileName(GetModuleHandle(NULL),szLibUsArDLLdl1,_countof(szLibUsArDLLdl1));
		for(int i=(int)_tcslen(szLibUsArDLLdl1)-1;i>0;--i)
		{
			if(szLibUsArDLLdl1[i]==_T('\\'))
			{
				szLibUsArDLLdl1[i]=_T('\0');
				break;
			}
		}
		_tcscat(szLibUsArDLLdl1,_T("\\UsArdll.d11"));

		*(LPVOID*)&GetOEPDLL=GetProcAddress(LoadLibrary(szLibUsArDLLdl1),"GetOEPDLL");
		GetOEPDLL(hDllBase);			

		break;
		}
	case _T('1'):
		hExtra=hDllBase;
		__debugbreak();
		break;
	case _T('2'):
		hExtra=hDllBase;
		while(hExtra!=0)
		{		  
		}
		break;
	default:
		return;		
	}

	FreeLibrary(hDllBase);
}