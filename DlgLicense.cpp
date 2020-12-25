#include "stdafx.h"
#include "Init.h"
#include "DlgLicense.h"
#include "DlgMain.h"

const int nHotKeyID=50;
const int nTimerID=2;

IMPLEMENT_DYNAMIC(CDlgLicense,CDialog)
CDlgLicense::CDlgLicense(bool n_fEnableButton):CDialog(CDlgLicense::IDD,NULL),
	sLicense(_T("")),
	fEnableButton(n_fEnableButton)
{
}

CDlgLicense::~CDlgLicense()
{
}

void CDlgLicense::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX,IDC_LICENSETEXT,sLicense);
}

BEGIN_MESSAGE_MAP(CDlgLicense,CDialog)
	ON_BN_CLICKED(IDCANCEL,OnBnClickedCancel)
	ON_BN_CLICKED(IDOK,OnBnClickedOK)
	ON_WM_TIMER()
END_MESSAGE_MAP()

BOOL CDlgLicense::OnInitDialog()
{
	CDialog::OnInitDialog();

	sLicense="QuickUnpack is Copyright (c) 2007 Archer & FEUERRADER [AHTeam]\r\nAll rights reserved.\r\n\r\nTHIS  PROGRAM  IS PROTECTED  BY  COPYRIGHT LAW  AND  INTERNATIONAL TREATIES.\r\nBREAKING THE FOLLOWING AGREEMENT WILL  RESULT  IN SEVERE CIVIL AND  CRIMINAL\r\nPENALTIES AND WILL BE PROSECUTED TO THE MAXIMUM EXTENT POSSIBLE UNDER LAW.\r\n\r\nTHIS  AGREEMENT IS  A LEGAL  DOCUMENT. READ  IT CAREFULLY  BEFORE USING  THE\r\nSOFTWARE. IT PROVIDES A LICENSE TO USE THE  SOFTWARE.\r\n\r\n\"Software\" means the program supplied by FEUERRADER herewith.\r\n\r\nPermission is hereby  granted to any  individual, organization or  agency to\r\nuse  the  Software  for  any  legal  NON-COMMERCIAL  purpose,  without   any\r\nobligation  to  the  author.   You  may   distribute  the   Software freely,\r\nprovided that  the original distribution  package (binaries  and any   other\r\nfiles  included in  it) is  left intact. You may also disassemble,   reverse\r\nengineer or modify the  Software, but you MAY NOT distribute it in  modified\r\nform.\r\n\r\nAny COMMERCIAL  use of  the Software  without prior  written permission from\r\nthe author is strictly prohibited.\r\n\r\nDISCLAIMER OF LIABILITY\r\n\r\nTHIS  SOFTWARE IS   PROVIDED  BY  FEUERRADER \"AS  IS\"  AND   ANY EXPRESS   OR\r\nIMPLIED WARRANTIES,    INCLUDING,   BUT  NOT   LIMITED    TO, THE    IMPLIED\r\nWARRANTIES  OF  MERCHANTABILITY  AND   FITNESS  FOR   A  PARTICULAR  PURPOSE\r\nARE  DISCLAIMED.  IN  NO EVENT    SHALL THE   AUTHOR BE    LIABLE FOR   ANY\r\nDIRECT,   INDIRECT,  INCIDENTAL,  SPECIAL,   EXEMPLARY,  OR    CONSEQUENTIAL\r\nDAMAGES  (INCLUDING, BUT  NOT  LIMITED TO, PROCUREMENT OF  SUBSTITUTE  GOODS\r\nOR SERVICES;  LOSS OF USE,  DATA,  OR PROFITS; OR   BUSINESS   INTERRUPTION)\r\nHOWEVER    CAUSED    AND   ON    ANY    THEORY    OF  LIABILITY,  WHETHER IN\r\nCONTRACT, STRICT  LIABILITY, OR  TORT (INCLUDING   NEGLIGENCE OR  OTHERWISE)\r\nARISING IN  ANY WAY  OUT OF  THE USE  OF THIS  SOFTWARE, EVEN  IF ADVISED OF\r\nTHE POSSIBILITY OF SUCH DAMAGE.";
	GetDlgItem(IDC_LICENSETEXT)->SendMessage(EM_SETBKGNDCOLOR,FALSE,::GetSysColor(COLOR_BTNFACE));
	if(fEnableButton)
		GetDlgItem(IDOK)->EnableWindow(TRUE);
	else
	{
		RegisterHotKey(GetSafeHwnd(),nHotKeyID,MOD_ALT,VK_F4);
		SetTimer(nTimerID,4000,NULL);
	}
	UpdateData(FALSE);

	GetDlgItem(IDCANCEL)->SetFocus();
	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return FALSE;
}

void CDlgLicense::OnBnClickedCancel()
{
	ExitProcess(666);
}

void CDlgLicense::OnBnClickedOK()
{
	OnOK();
}

void CDlgLicense::OnTimer(UINT_PTR nIDEvent)
{
	if(nIDEvent==nTimerID)
	{
		UnregisterHotKey(GetSafeHwnd(),nHotKeyID);
		KillTimer(nTimerID);
		GetDlgItem(IDOK)->EnableWindow(TRUE);
	}
	else
		CDialog::OnTimer(nIDEvent);
}