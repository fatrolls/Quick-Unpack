#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgAbout.h"
#include ".\\effects\\marquee.h"
#include ".\DlgAbout.h"
#ifndef DLLFILE
#include ".\\MiniFMOD\\minifmod.h"
#endif

const TCHAR PROP_ORIGINAL_FONT[]=_T("_HLOF_");
const TCHAR PROP_ORIGINAL_PROC[]=_T("_HLOP_");
const TCHAR PROP_STATIC_HYPERLINK[]=_T("_HLFS_");
const TCHAR PROP_UNDERLINE_FONT[]=_T("_HLUF_");

TCHAR MarqText[]=_T("QuickUnpack founded by FEUERRADER [AHTeam]. Developer: Archer.   Thanks and Greetz to: tPORt, AHTeam, TSRh, KpTeam, REVENGE, CRACKL@B, ICU members, CoaxCable^CPH, Wild-Wolf and all CPH members on #cph, LaFarge[ICU] and SofT MANiAC for nice music, SergioPoverony, DillerInc, newborn for logo, syd, lord_Phoenix, NCRangeR, Grim Fandango, Aster!x, Quantum, MozgC, Sten, PolishOX, NEOx, WELL, GPcH, Funbit, sl0n, Ms-Rem, Bad_guy, dj-siba, =TS=, DillerInc, UsAr, Human, deroko, Errins, Bronco, HandMill, Executioner, 4kusN!ck, BiT-H@ck, Hellsp@wn, HoBleen, Smon, LaZzy, Mikae...");

const COLORREF BackGr=0x00cccccc;
const COLORREF TextGr=0;
const DWORD arcL=0;
const DWORD arcT=240;
const DWORD arcW=320;
const DWORD arcH=14;

#ifndef DLLFILE
struct MEMFILE
{
	int nLength;
	int nPos;
	void *pData;
};

FMUSIC_MODULE *pMod;
HRSRC hResource;
void *memopen(char*)
{
	MEMFILE *pMemFile;
	HGLOBAL hHandle;
	pMemFile=(MEMFILE*)malloc(sizeof(MEMFILE));

	hResource=FindResource(NULL,(TCHAR*)1,(TCHAR*)_T("MUSIC"));
	hHandle=LoadResource(NULL,hResource);
	pMemFile->pData=LockResource(hHandle);
	pMemFile->nLength=SizeofResource(NULL,hResource);
	pMemFile->nPos=0;
	return pMemFile;
}

void memclose(void *pHandle)
{
	MEMFILE *pMemFile=(MEMFILE*)pHandle;
	FreeResource(hResource);
	free(pMemFile);
}

int memread(void *pBuffer,int nSize,void *pHandle)
{
	MEMFILE *pMemFile=(MEMFILE*)pHandle;

	if(pMemFile->nPos+nSize>=pMemFile->nLength)
		nSize=pMemFile->nLength-pMemFile->nPos;

	memcpy(pBuffer,(BYTE*)pMemFile->pData+pMemFile->nPos,nSize);
	pMemFile->nPos+=nSize;

	return nSize;
}

void memseek(void *pHandle,int nPos,signed char mode)
{
	MEMFILE *pMemFile=(MEMFILE*)pHandle;

	if(mode==SEEK_SET)
		pMemFile->nPos=nPos;
	else if(mode==SEEK_CUR)
		pMemFile->nPos+=nPos;
	else if(mode==SEEK_END)
		pMemFile->nPos=pMemFile->nLength+nPos;

	if(pMemFile->nPos>pMemFile->nLength)
		pMemFile->nPos=pMemFile->nLength;
}

int memtell(void *pHandle)
{
	MEMFILE *pMemFile=(MEMFILE*)pHandle;
	return pMemFile->nPos;
}
#endif

IMPLEMENT_DYNAMIC(CDlgAbout,CDialog)
CDlgAbout::CDlgAbout():CDialog(CDlgAbout::IDD,0)
{
}

CDlgAbout::~CDlgAbout()
{
}

void CDlgAbout::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CDlgAbout,CDialog)
	ON_BN_CLICKED(IDOK,OnBnClickedOk)
	ON_WM_DESTROY()
	ON_WM_PAINT()
END_MESSAGE_MAP()

LRESULT CALLBACK _HyperlinkParentProc(HWND hWnd,UINT Message,WPARAM wParam,LPARAM lParam)
{
	WNDPROC pfnOrigProc=(WNDPROC)GetProp(hWnd,PROP_ORIGINAL_PROC);

	switch(Message)
	{
	case WM_CTLCOLORSTATIC:
		{
			HDC hDc=(HDC)wParam;
			HWND hWndCtl=(HWND)lParam;

			BOOL fHyperlink=(GetProp(hWndCtl,PROP_STATIC_HYPERLINK)!=NULL);
			if(fHyperlink)
			{
				LRESULT lr=CallWindowProc(pfnOrigProc,hWnd,Message,wParam,lParam);
				SetTextColor(hDc,RGB(0,0,192));
				return lr;
			}
			break;
		}
	case WM_DESTROY:
		{
			SetWindowLongPtr(hWnd,GWLP_WNDPROC,(LONG_PTR)pfnOrigProc);
			RemoveProp(hWnd,PROP_ORIGINAL_PROC);
			break;
		}
	}
	return CallWindowProc(pfnOrigProc,hWnd,Message,wParam,lParam);
}

int nSecret;

LRESULT CALLBACK _HyperlinkProc(HWND hWnd,UINT Message,WPARAM wParam,LPARAM lParam)
{
	WNDPROC pfnOrigProc=(WNDPROC)GetProp(hWnd,PROP_ORIGINAL_PROC);

	switch(Message)
	{
	case WM_DESTROY:
		{
			SetWindowLongPtr(hWnd,GWLP_WNDPROC,(LONG_PTR)pfnOrigProc);
			RemoveProp(hWnd,PROP_ORIGINAL_PROC);

			HFONT hOrigFont=(HFONT)GetProp(hWnd,PROP_ORIGINAL_FONT);
			SendMessage(hWnd,WM_SETFONT,(WPARAM)hOrigFont,0);
			RemoveProp(hWnd,PROP_ORIGINAL_FONT);

			HFONT hFont=(HFONT)GetProp(hWnd,PROP_UNDERLINE_FONT);
			DeleteObject(hFont);
			RemoveProp(hWnd,PROP_UNDERLINE_FONT);
			RemoveProp(hWnd,PROP_STATIC_HYPERLINK);

			break;
		}
	case WM_LBUTTONUP:
		{
			if(GetCapture()==hWnd)
			{
				if(nSecret==0 && GetAsyncKeyState(VK_SHIFT)!=0 && GetAsyncKeyState(VK_CONTROL)!=0)
					++nSecret;
				else
				{
					nSecret=0;
					SHELLEXECUTEINFO sei;
					memset(&sei,0,sizeof(sei));
					sei.cbSize=sizeof(sei);
					sei.lpVerb=_T("open");
					sei.lpFile=_T("http://qunpack.ahteam.org");
					sei.nShow=SW_SHOWNORMAL;
					ShellExecuteEx(&sei);
				}
			}
			break;
		}
	case WM_MOUSEMOVE:
		{
			if(GetCapture()!=hWnd)
			{
				HFONT hFont=(HFONT)GetProp(hWnd,PROP_UNDERLINE_FONT);
				SendMessage(hWnd,WM_SETFONT,(WPARAM)hFont,FALSE);
				InvalidateRect(hWnd,NULL,FALSE);
				SetCapture(hWnd);
			}
			else
			{
				RECT Rect;
				GetWindowRect(hWnd,&Rect);

				POINT Pt={LOWORD(lParam),HIWORD(lParam)};
				ClientToScreen(hWnd,&Pt);

				if(!PtInRect(&Rect,Pt))
				{
					HFONT hFont=(HFONT)GetProp(hWnd,PROP_ORIGINAL_FONT);
					SendMessage(hWnd,WM_SETFONT,(WPARAM)hFont,FALSE);
					InvalidateRect(hWnd,NULL,FALSE);
					ReleaseCapture();
				}
			}
			break;
		}
	case WM_SETCURSOR:
		{
			HCURSOR hCursor=LoadCursor(NULL,MAKEINTRESOURCE(32649));
			if(hCursor==NULL)
				hCursor=LoadCursor(NULL,MAKEINTRESOURCE(IDC_ARROW));
			SetCursor(hCursor);
			return TRUE;
		}
	}
	return CallWindowProc(pfnOrigProc,hWnd,Message,wParam,lParam);
}

void CDlgAbout::ConvertStaticToHyperlink(HWND hWndCtl)
{
	HWND hWndParent=::GetParent(hWndCtl);
	if(hWndParent!=NULL)
	{
		DWORD_PTR pfnOrigProc=GetWindowLongPtr(hWndParent,GWLP_WNDPROC);
		SetProp(hWndParent,PROP_ORIGINAL_PROC,(HANDLE)pfnOrigProc);
		SetWindowLongPtr(hWndParent,GWLP_WNDPROC,(LONG_PTR)_HyperlinkParentProc);
	}

	DWORD_PTR Style=GetWindowLongPtr(hWndCtl,GWL_STYLE);
	SetWindowLongPtr(hWndCtl,GWL_STYLE,Style | SS_NOTIFY);

	DWORD_PTR pfnOrigProc=GetWindowLongPtr(hWndCtl,GWLP_WNDPROC);
	SetProp(hWndCtl,PROP_ORIGINAL_PROC,(HANDLE)pfnOrigProc);
	SetWindowLongPtr(hWndCtl,GWLP_WNDPROC,(LONG_PTR)_HyperlinkProc);

	HFONT hOrigFont=(HFONT)::SendMessage(hWndCtl,WM_GETFONT,0,0);
	SetProp(hWndCtl,PROP_ORIGINAL_FONT,(HANDLE)hOrigFont);

	LOGFONT LogFont;
	GetObject(hOrigFont,sizeof(LogFont),&LogFont);
	LogFont.lfUnderline=TRUE;

	HFONT hFont=CreateFontIndirect(&LogFont);
	SetProp(hWndCtl,PROP_UNDERLINE_FONT,(HANDLE)hFont);

	SetProp(hWndCtl,PROP_STATIC_HYPERLINK,(HANDLE)1);
}

BOOL CDlgAbout::OnInitDialog()
{
	CDialog::OnInitDialog();
	fSecret=FALSE;
	nSecret=0;

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);

	Picture.Load(IDR_LOGO,_T("LOGO"));

	SetParams(m_hWnd,MarqText,BackGr,TextGr,arcT,arcL,arcW,arcH);
	InstallMarquee();

#ifndef DLLFILE
	FSOUND_File_SetCallbacks(memopen,memclose,memread,memseek,memtell);
	pMod=FMUSIC_LoadSong("",NULL);
	FMUSIC_PlaySong(pMod);
#endif
	ConvertStaticToHyperlink(::GetDlgItem(m_hWnd,IDC_URL));

	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return FALSE;
}

void CDlgAbout::OnDestroy()
{
	CDialog::OnDestroy();

	KillMarquee();
#ifndef DLLFILE
	FMUSIC_StopSong(pMod);
	FMUSIC_FreeSong(pMod);
#endif
}

void CDlgAbout::OnBnClickedOk()
{
	if(nSecret==1)
		fSecret=TRUE;
	AnimateWindow(300,AW_BLEND | AW_HIDE);
	OnOK();
}

void CDlgAbout::OnPaint()
{
	CPaintDC Dc(GetDlgItem(IDC_PICTURE));
	Picture.UpdateSizeOnDC(&Dc);
	Picture.Show(&Dc,CPoint(0,0),CPoint(Picture.m_Width,Picture.m_Height),0,0);
	CDialog::OnPaint();
}