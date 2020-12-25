// Marquee asm-code by Funbit/TSRh
// C++ conversion by Funbit & FEUERRADER

#include "stdafx.h"
#include "marquee.h"

TCHAR *szMarqText;
COLORREF clBackGr;
COLORREF clTextGr;

HWND mar_hWnd;
HANDLE hThreadMarquee;

HDC marqmemHDC;
HBITMAP hBitmapMemMarquee;
LOGFONT LogFontMarquee;
HFONT hFontMarquee;
DWORD marqL,marqT,marqW,marqH;

void MakeGradient(HDC hdcOn,DWORD gradWidth,DWORD gradHeight,DWORD leftEdge,DWORD rightEdge,DWORD textColor,DWORD toColor)
{
	BYTE rfactor,gfactor,bfactor,r0,g0,b0,r1,g1,b1;
	DWORD xPix,yPix;
	BYTE wSide;
	DWORD temp1,temp2;

	r0=LOBYTE(toColor);
	g0=HIBYTE(toColor);
	b0=LOBYTE(toColor>>16);

	r1=LOBYTE(textColor);
	g1=HIBYTE(textColor);
	b1=LOBYTE(textColor>>16);

	rfactor=(max(r0,r1)-min(r0,r1)) % LOBYTE(gradWidth);
	gfactor=(max(g0,g1)-min(g0,g1)) % LOBYTE(gradWidth);
	bfactor=(max(b0,b1)-min(b0,b1)) % LOBYTE(gradWidth);

	xPix=0;
	yPix=0;
	wSide=0;

	for(;;)
	{
		if(wSide!=0)
			temp1=rightEdge+xPix;
		else
			temp1=leftEdge+xPix;
		temp2=GetPixel(hdcOn,temp1,yPix);
		if(temp2==textColor)
		{
			if(LOBYTE(temp2)!=b0)
			{
				if(wSide==0)
					b1=LOBYTE(gradWidth-xPix);
				else
					b1=LOBYTE(xPix);
				b1=b1*bfactor;
				if(LOBYTE(temp2)<b0)
					b1=b1+LOBYTE(temp2);
				else
					if(LOBYTE(temp2)>b0)
						b1=LOBYTE(temp2)-b1;
				temp1=b1;
				temp2=temp2>>8;
			}
			if(LOBYTE(temp2)!=g0)
			{
				if(wSide==0)
					g1=LOBYTE(gradWidth-xPix);
				else
					g1=LOBYTE(xPix);
				g1=g1*gfactor;
				if(LOBYTE(temp2)<g0)
					g1=g1+LOBYTE(temp2);
				else
					if(LOBYTE(temp2)>g0)
						g1=LOBYTE(temp2)-g1;
				temp1=(temp1<<8) | g1;
				temp2=temp2>>8;
			}
			if(LOBYTE(temp2)!=r0)
			{
				if(wSide==0)
					r1=LOBYTE(gradWidth-xPix);
				else
					r1=LOBYTE(xPix);
				r1=r1*rfactor;
				if(LOBYTE(temp2)<r0)
					r1=r1+LOBYTE(temp2);
				else
					if(LOBYTE(temp2)>r0)
						r1=LOBYTE(temp2)-r1;
				temp1=(temp1<<8) | r1;
				temp2=temp2>>8;
			}
			temp2=temp1;
			if(wSide==0)
				temp1=leftEdge+xPix;
			else
				temp1=rightEdge+xPix;
			SetPixel(hdcOn,temp1,yPix,temp2);
		}
		wSide^=1;
		if(wSide==1)
			continue;
		++xPix;
		if(xPix!=gradWidth)
			continue;
		xPix=0;
		++yPix;
		if(yPix==gradHeight)
			break;
	}
}

DWORD __stdcall MarqueeThread(void*)
{
	HDC marqHDC;
	HBRUSH hBrushColor;
	DWORD x0,x,xMin;
	SIZE textSIZE;
	RECT tRect;

	x0=250;

	marqHDC=GetDC(mar_hWnd);

	marqmemHDC=CreateCompatibleDC(marqHDC);
	hBitmapMemMarquee=CreateCompatibleBitmap(marqHDC,marqW,marqH+10);
	SelectObject(marqmemHDC,hBitmapMemMarquee);
	LogFontMarquee.lfHeight=-9;
	LogFontMarquee.lfQuality=DEFAULT_PITCH;
	_tcscpy_s(LogFontMarquee.lfFaceName,_T("Tahoma"));
	hFontMarquee=CreateFontIndirect(&LogFontMarquee);

	SelectObject(marqmemHDC,hFontMarquee);
	SetTextColor(marqmemHDC,clTextGr);
	SetBkColor(marqmemHDC,clBackGr);
	SetBkMode(marqmemHDC,OPAQUE);
	SetBkMode(marqHDC,OPAQUE);

	GetTextExtentPoint32(marqmemHDC,szMarqText,(int)_tcslen(szMarqText),&textSIZE);
	xMin=-textSIZE.cx-100;
	x=x0;

	hBrushColor=CreateSolidBrush(clBackGr);
	tRect.left=0;
	tRect.top=0;
	tRect.right=marqW+20;
	tRect.bottom=marqH+20;

	for(;;)
	{
		FillRect(marqmemHDC,&tRect,hBrushColor);
		TextOut(marqmemHDC,x,1,szMarqText,(int)_tcslen(szMarqText));
		MakeGradient(marqmemHDC,15,15,0,marqW-15,clTextGr,clBackGr);
		BitBlt(marqHDC,marqL,marqT,marqW,marqH,marqmemHDC,0,0,SRCCOPY);
		Sleep(20);

		--x;
		if(x==xMin)
			x=x0;
	}
	return 0;
}

void InstallMarquee()
{
	hThreadMarquee=CreateThread(NULL,0,MarqueeThread,NULL,0,NULL);
	SetThreadPriority(hThreadMarquee,THREAD_PRIORITY_NORMAL);
}

void KillMarquee()
{
	TerminateThread(hThreadMarquee,0);
	DeleteDC(marqmemHDC);
	DeleteObject(hBitmapMemMarquee);
	DeleteObject(hFontMarquee);
}

void SetParams(HWND sethw,TCHAR *szMText,COLORREF BackCl,COLORREF TextCl,DWORD pTop,DWORD pLeft,DWORD pWid,DWORD pHei)
{
	mar_hWnd=sethw;
	szMarqText=szMText;
	clBackGr=BackCl;
	clTextGr=TextCl;
	marqL=pLeft;
	marqT=pTop;
	marqW=pWid;
	marqH=pHei;
}