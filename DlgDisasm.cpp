#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgDisasm.h"

#include ".\\Disasm\\mediana.h"

IMPLEMENT_DYNAMIC(CDlgDisasm,CDialog)
CDlgDisasm::CDlgDisasm():CDialog(CDlgDisasm::IDD,NULL)
{
}

CDlgDisasm::~CDlgDisasm()
{
}

void CDlgDisasm::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDC_DISLIST,DisasmList);
}

void CDlgDisasm::Disasm()
{
	TCHAR cBuff[0x400];
	void *cPtr;
	INSTRUCTION Instr;
	DISASM_PARAMS Params;
	int nInstrNum=0;

	cPtr=pAddr;
	DisasmList.ResetContent();
	Params.arch=ARCH_ALL;
	Params.base=AltAddress;
	Params.options=DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP | DISASM_OPTION_COMPUTE_RIP;
	Params.sf_prefixes=NULL;
#if defined _M_AMD64
	Params.mode=DISASSEMBLE_MODE_64;
#elif defined _M_IX86
	Params.mode=DISASSEMBLE_MODE_32;
#else
!!!
#endif
	do
	{
		if(medi_disassemble((uint8_t*)cPtr,BUFSIZ_INFINITY,&Instr,&Params)!=DASM_ERR_OK)
			break;
		_stprintf_s(cBuff,_T("%I64X:"),Params.base);
		size_t nTempLen=_tcslen(cBuff);
		cBuff[nTempLen++]=_T(' ');
		cBuff[nTempLen++]=_T(' ');
		cBuff[nTempLen++]=_T(' ');
		nTempLen+=medi_dump(&Instr,cBuff+nTempLen,_countof(cBuff)-nTempLen,NULL);
		cBuff[nTempLen]=_T('\0');

		DisasmList.AddString(cBuff);
		cPtr=(BYTE*)cPtr+Instr.length;
		Params.base+=Instr.length;
		++nInstrNum;
	}
	while(nInstrNum!=INSTRS_TO_DISASM);
}

BOOL CDlgDisasm::OnInitDialog()
{
	CDialog::OnInitDialog();
	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);

	UpdateData(FALSE);
	Disasm();

	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}