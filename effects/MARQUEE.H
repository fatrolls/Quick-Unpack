#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <windows.h>

void MakeGradient(HDC hdcOn,DWORD gradWidth,DWORD gradHeight,DWORD leftEdge,DWORD rightEdge,DWORD textColor,DWORD toColor);

DWORD __stdcall MarqueeThread(void*);
void InstallMarquee();
void KillMarquee();
void SetParams(HWND sethw,TCHAR *szMText,COLORREF BackCl,COLORREF TextCl,DWORD pTop,DWORD pLeft,DWORD pWid,DWORD pHei);