#include <intrin.h>
#include <windows.h>

DWORD_PTR RetAddr=0;

__declspec(dllexport) DWORD_PTR __stdcall GetLoadDllAddress()
{
	return RetAddr;
}

BOOL __stdcall DllMain(HANDLE,DWORD,void*)
{
	RetAddr=(DWORD_PTR)_ReturnAddress();
	return TRUE;
}