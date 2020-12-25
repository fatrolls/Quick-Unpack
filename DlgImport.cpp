#include "stdafx.h"
#include "Init.h"
#include "DlgMain.h"
#include "DlgImport.h"
#include "PEFile.h"
#include "Modules.h"
#include "DlgEditImport.h"
#include "Main.h"
#include ".\\Disasm\\mediana.h"

std::vector<int> RedArray;

IMPLEMENT_DYNAMIC(CDlgImport,CDialog)

CDlgImport::CDlgImport(CImport *n_pImport,CPEFile *n_pPEMain,CModules *n_pModules,
	const TCHAR *n_szPEFileName,CMain *n_pMain):CDialog(CDlgImport::IDD,NULL),
	sImpRVAbox(_T("00000000")),
	pImport(n_pImport),
	pPEMain(n_pPEMain),
	pModules(n_pModules),
	szPEFileName(n_szPEFileName),
	pMain(n_pMain)
{
}

CDlgImport::~CDlgImport()
{
}

static WORD GetOrdinalByName(BYTE *bModule,char *szName)
{
	IMAGE_DOS_HEADER *pMZHeader=(IMAGE_DOS_HEADER*)bModule;
	IMAGE_NT_HEADERS *pPEHeader=(IMAGE_NT_HEADERS*)(bModule+pMZHeader->e_lfanew);
	DWORD dwExportTableRVA=pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if(dwExportTableRVA==0)
		return (WORD)-1;

	IMAGE_EXPORT_DIRECTORY *pExportDir=(IMAGE_EXPORT_DIRECTORY*)(bModule+dwExportTableRVA);
	WORD *pOrdinalTable=(WORD*)(bModule+pExportDir->AddressOfNameOrdinals);
	DWORD *pNameTable=(DWORD*)(bModule+pExportDir->AddressOfNames);

	for(DWORD i=0;i!=pExportDir->NumberOfNames;++i)
	{
		if(strcmp(szName,(char*)bModule+pNameTable[i])!=0)
			continue;
		return (WORD)(pExportDir->Base+pOrdinalTable[i]);
	}
	return (WORD)-1;
}

void CDlgImport::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX,IDC_IMPORTLIST,ImportList);
	DDX_Text(pDX,IDC_IMPORTRVABOX,sImpRVAbox);
}

BEGIN_MESSAGE_MAP(CDlgImport,CDialog)
	ON_BN_CLICKED(IDC_DELETEIMPORTSEL,OnBnClickedDeleteSelected)
	ON_BN_CLICKED(IDC_DELETEIMPORTINVALID,OnBnClickedDeleteInvalid)
	ON_BN_CLICKED(IDC_LOADLIBRARY,&CDlgImport::OnBnClickedImpLoadLib)
	ON_BN_CLICKED(IDC_EXPORTIMP,&CDlgImport::OnBnClickedExport)
	ON_BN_CLICKED(IDC_EDITIMPORT,&CDlgImport::OnBnClickedImpEdit)
	ON_BN_CLICKED(IDC_IMPORTIMP,&CDlgImport::OnBnClickedImport)
	ON_BN_CLICKED(IDC_USEOLDIAT,OnBnClickedUseOldIAT)
	ON_BN_CLICKED(IDC_SAVEIMPORT,OnBnClickedSaveOriginal)
	ON_BN_CLICKED(IDC_IMPORTDISASM,&CDlgImport::OnBnClickedImpDisasm)
	ON_EN_CHANGE(IDC_IMPORTRVABOX,DoUpdateData)
	ON_NOTIFY(NM_CUSTOMDRAW,IDC_IMPORTLIST,OnNMCustomdrawImportlist)
	ON_NOTIFY(LVN_ITEMCHANGED,IDC_IMPORTLIST,OnItemChangedImportlist)
	ON_BN_CLICKED(IDC_CHANGESORT,OnBnClickedChangeSort)
	ON_BN_CLICKED(IDC_PREVFORW,OnBnClickedPrevForw)
	ON_BN_CLICKED(IDC_NEXTFORW,OnBnClickedNextForw)
	ON_BN_CLICKED(IDC_PREVFUNC,OnBnClickedPrevFunc)
	ON_BN_CLICKED(IDC_NEXTFUNC,OnBnClickedNextFunc)
END_MESSAGE_MAP()

void CDlgImport::DoUpdateData()
{
	UpdateData(TRUE);
}

void CDlgImport::ChangeWndHeader()
{
	CString header=importtableheader;
	if(ImportSortType==siByName)
		header+=importtablebyname;
	else if(ImportSortType==siByRecord)
		header+=importtablebyrec;
	else if(ImportSortType==siByReference)
		header+=importtablebyref;
	if(RedArray.empty())
		header+=importtableok;
	else
		header+=importtableerror;
	SetWindowText(header);
}

void CDlgImport::FillRecord(int i)
{
	if(ImportList.GetItemCount()<=i)
		ImportList.InsertItem(LVIF_STATE,i,NULL,0,LVIS_SELECTED,0,0);
	ImportList.SetItemText(i,0,IntToStr(i,16,sizeof(i)*2));
	ImportList.SetItemText(i,1,IntToStr(i,10,sizeof(i)*2));
	ImportList.SetItemText(i,2,pImport->Records[i].sLibName.c_str());
	if(!pImport->Records[i].sApiName.empty())
	{
#ifdef UNICODE
		int nMultiLength=(int)pImport->Records[i].sApiName.length()+1;
		WCHAR *pWideArray=new WCHAR[nMultiLength];
		MultiByteToWideChar(CP_ACP,0,pImport->Records[i].sApiName.c_str(),nMultiLength,pWideArray,nMultiLength);
		ImportList.SetItemText(i,3,pWideArray);
		delete[] pWideArray;
#else
		ImportList.SetItemText(i,3,pImport->Records[i].sApiName.c_str());
#endif
	}
	else
		ImportList.SetItemText(i,3,noname);
	ImportList.SetItemText(i,4,_T("0x")+IntToStr(pImport->Records[i].dwReferenceRVA,16,sizeof(pImport->Records[0].dwReferenceRVA)*2));
	ImportList.SetItemText(i,5,_T("0x")+IntToStr(pImport->Records[i].dwRecordRVA,16,sizeof(pImport->Records[0].dwRecordRVA)*2));
	if(!pImport->Records[i].Exist())
	{
		ImportList.SetItemText(i,6,yes);
		RedArray.push_back(i);
	}
	else
		ImportList.SetItemText(i,6,no);
	ImportList.SetItemText(i,7,IntToStr(pImport->Records[i].wOrdinal,16,4));
}

void CDlgImport::FillTable()
{
	RedArray.clear();
	ImportList.DeleteAllItems();

	pImport->SortRecords(ImportSortType);
	for(int i=0;i!=(int)pImport->Records.size();++i)
		FillRecord(i);

	if(!RedArray.empty())
	{
		ImportList.EnsureVisible(RedArray[0],FALSE);
		ImportList.SetItemState(RedArray[0],LVIS_SELECTED,LVIS_SELECTED);
		ImportList.SetSelectionMark(RedArray[0]);
		ImportList.SetFocus();
	}
	ChangeWndHeader();
}

BOOL CDlgImport::OnInitDialog()
{
	CDialog::OnInitDialog();

	ImportList.SetExtendedStyle(LVS_EX_GRIDLINES|LVS_EX_FULLROWSELECT);

	CString sTemp;
	GetDlgItemText(IDC_DELETEIMPORTSEL,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_DELETEIMPORTSEL,sTemp);
	GetDlgItemText(IDC_DELETEIMPORTINVALID,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_DELETEIMPORTINVALID,sTemp);
	GetDlgItemText(IDC_EXPORTIMP,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_EXPORTIMP,sTemp);
	GetDlgItemText(IDC_IMPORTIMP,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_IMPORTIMP,sTemp);
	GetDlgItemText(IDC_IMPORTDISASM,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_IMPORTDISASM,sTemp);
	GetDlgItemText(IDC_EDITIMPORT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_EDITIMPORT,sTemp);
	GetDlgItemText(IDC_LOADLIBRARY,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_LOADLIBRARY,sTemp);
	GetDlgItemText(IDC_USEOLDIAT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_USEOLDIAT,sTemp);
	GetDlgItemText(IDC_SAVEIMPORT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_SAVEIMPORT,sTemp);
	GetDlgItemText(IDC_STATIC,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_STATIC,sTemp);
	GetDlgItemText(IDC_CHANGESORT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_CHANGESORT,sTemp);
	GetDlgItemText(IDC_PREVFORW,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_PREVFORW,sTemp);
	GetDlgItemText(IDC_NEXTFORW,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_NEXTFORW,sTemp);
	GetDlgItemText(IDC_PREVFUNC,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_PREVFUNC,sTemp);
	GetDlgItemText(IDC_NEXTFUNC,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_NEXTFUNC,sTemp);

	ImportList.InsertColumn(0,_T(""),LVCFMT_LEFT,0);
	ImportList.InsertColumn(1,_T("N"),LVCFMT_LEFT,80);
	ImportList.InsertColumn(2,library,LVCFMT_LEFT,100);
	ImportList.InsertColumn(3,function,LVCFMT_LEFT,160);
	ImportList.InsertColumn(4,referencerva,LVCFMT_LEFT,90);
	ImportList.InsertColumn(5,recordrva,LVCFMT_LEFT,90);
	ImportList.InsertColumn(6,problem,LVCFMT_LEFT,80);
	ImportList.InsertColumn(7,ordinal,LVCFMT_LEFT,45);

	ImportSortType=pImport->CheckOldIAT(*pPEMain,NULL) ? siByRecord : siByName;
	GetDlgItem(IDC_USEOLDIAT)->EnableWindow(ImportSortType==siByRecord ? FALSE : TRUE);
	FillTable();

	((CEdit*)GetDlgItem(IDC_IMPORTRVABOX))->LimitText(8);
	((CEdit*)GetDlgItem(IDC_IMPORTRVABOX))->SetWindowText(IntToStr(pMain->pInitData->dwImportRVA,16,sizeof(pMain->pInitData->dwImportRVA)*2));

	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}

void CDlgImport::OnBnClickedDeleteSelected()
{
	for(int i=0;i!=ImportList.GetItemCount();)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)==LVIS_SELECTED)
		{
			for(std::vector<int>::iterator iter(RedArray.begin());iter!=RedArray.end();)
			{
				if(i==*iter)
					iter=RedArray.erase(iter);
				else
				{
					if(i<*iter)
						--*iter;
					++iter;
				}
			}
			ImportList.DeleteItem(i);
		}
		else
			++i;
	}
	FillImport();
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		ImportList.SetItemText(i,0,IntToStr(i,16,sizeof(i)*2));
		ImportList.SetItemText(i,1,IntToStr(i,10,sizeof(i)*2));
	}

	if(!RedArray.empty())
	{
		ImportList.EnsureVisible(RedArray[0],FALSE);
		ImportList.SetItemState(RedArray[0],LVIS_SELECTED,LVIS_SELECTED);
		ImportList.SetSelectionMark(RedArray[0]);
		ImportList.SetFocus();
	}
	GetDlgItem(IDC_USEOLDIAT)->EnableWindow(pImport->CheckOldIAT(*pPEMain,NULL) ? FALSE : TRUE);
	ChangeWndHeader();
}

void CDlgImport::FillImport()
{
	CImport NewImport;
	for(int i=0;i!=ImportList.GetItemCount();++i)
		NewImport.AddRecord(pImport->Records[_tcstoul(ImportList.GetItemText(i,0),NULL,16)]);
	pImport->Clear();
	for(size_t i=0;i!=NewImport.Records.size();++i)
		pImport->AddRecord(NewImport.Records[i]);
}

void CDlgImport::OnNMCustomdrawImportlist(NMHDR *pNMHDR,LRESULT *pResult)
{
	*pResult=CDRF_DODEFAULT;
	NMLVCUSTOMDRAW *pLVCD=reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);

	if(CDDS_PREPAINT==pLVCD->nmcd.dwDrawStage)
		*pResult=CDRF_NOTIFYITEMDRAW;
	else
	{
		if(CDDS_ITEMPREPAINT==pLVCD->nmcd.dwDrawStage)
		{
			COLORREF crBkgnd,crText;

			crText=RGB(0,0,0);
			if((pLVCD->nmcd.dwItemSpec % 2)==0)
				crBkgnd=RGB(255,255,255);
			else
				crBkgnd=RGB(247,247,247);

			for(size_t i=0;i!=RedArray.size();++i)
			{
				if((int)pLVCD->nmcd.dwItemSpec==RedArray[i])
				{
					crBkgnd=RGB(255,0,0);
					crText=RGB(255,255,255);
				}
			}
			pLVCD->clrText=crText;
			pLVCD->clrTextBk=crBkgnd;

			*pResult=CDRF_DODEFAULT;
		}
	}
}

void CDlgImport::OnItemChangedImportlist(NMHDR *pNMHDR,LRESULT *pResult)
{
	pNMHDR;pResult;
	if((size_t)ImportList.GetItemCount()!=pImport->Records.size())
		return;

	BOOL fAnyPrevForw=FALSE,fAnyNextForw=FALSE,fAnyPrevFunc=FALSE,fAnyNextFunc=FALSE;
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)!=LVIS_SELECTED)
			continue;

		CImportRecord ImportRecord(pImport->Records[i]);
		if(pModules->ForwardedPrev(ImportRecord,1))
			fAnyPrevForw=TRUE;
		ImportRecord=pImport->Records[i];
		if(pModules->ForwardedNext(ImportRecord,1))
			fAnyNextForw=TRUE;
		ImportRecord=pImport->Records[i];
		if(pModules->IdentifyFunctionPrev(ImportRecord))
			fAnyPrevFunc=TRUE;
		ImportRecord=pImport->Records[i];
		if(pModules->IdentifyFunctionNext(ImportRecord))
			fAnyNextFunc=TRUE;
	}
	GetDlgItem(IDC_PREVFORW)->EnableWindow(fAnyPrevForw);
	GetDlgItem(IDC_NEXTFORW)->EnableWindow(fAnyNextForw);
	GetDlgItem(IDC_PREVFUNC)->EnableWindow(fAnyPrevFunc);
	GetDlgItem(IDC_NEXTFUNC)->EnableWindow(fAnyNextFunc);
}

void CDlgImport::OnBnClickedUseOldIAT()
{
	pMain->ChangeForwardedImport();
	pImport->RedirectToOldIAT(true,NULL,NULL);
	ImportSortType=pImport->CheckOldIAT(*pPEMain,NULL) ? siByRecord : siByName;
	GetDlgItem(IDC_USEOLDIAT)->EnableWindow(ImportSortType==siByRecord ? FALSE : TRUE);
	FillTable();
}

void CDlgImport::OnBnClickedSaveOriginal()
{
	if(pMain!=NULL)
	{
		CImport NewImport;
		pMain->pInitData->dwImportRVA=_tcstoul(sImpRVAbox.GetString(),NULL,16);
		for(int i=0;i!=ImportList.GetItemCount();++i)
		{
			if(pImport->Records[_tcstoul(ImportList.GetItemText(i,0),NULL,16)].Exist())
				NewImport.AddRecord(pImport->Records[_tcstoul(ImportList.GetItemText(i,0),NULL,16)]);
		}
		pImport->Clear();
		for(size_t i=0;i!=NewImport.Records.size();++i)
			pImport->AddRecord(NewImport.Records[i]);
	}
	AnimateWindow(AW_BLEND | AW_HIDE,500);
	OnOK();
}

void CDlgImport::OnBnClickedDeleteInvalid()
{
	if(!RedArray.empty())
	{
		for(int i=0;i<ImportList.GetItemCount();++i)
			ImportList.SetItemState(i,0,LVIS_SELECTED);
		for(size_t i=0;i!=RedArray.size();++i)
			ImportList.SetItemState(RedArray[i],LVIS_SELECTED,LVIS_SELECTED);
		OnBnClickedDeleteSelected();
	}
}

void CDlgImport::OnBnClickedExport()
{
	if(ImportList.GetItemCount()==0)
		MessageBox(importempty,exporttofile,MB_OK | MB_ICONERROR);
	else
	{
		TCHAR szCurrDir[MAX_PATH];
		GetCurrentDirectory(_countof(szCurrDir),szCurrDir);

		TCHAR szFileName[MAX_PATH];
		OPENFILENAME ofn;
		memset(&ofn,0,sizeof(ofn));
		ofn.lStructSize=sizeof(ofn);
		ofn.hwndOwner=GetSafeHwnd();
		ofn.lpstrDefExt=_T("txt");
		ofn.Flags=OFN_OVERWRITEPROMPT|OFN_HIDEREADONLY;
		ofn.lpstrFilter=_T("txt files\0*.txt\0");
		ofn.lpstrInitialDir=szCurrDir;
		ofn.lpstrFile=szFileName;
		ofn.lpstrFile[0]=_T('\0');
		ofn.nMaxFile=_countof(szFileName);

		if(GetSaveFileName(&ofn))
		{
			HANDLE hFile=CreateFile(ofn.lpstrFile,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
			if(hFile==INVALID_HANDLE_VALUE)
				MessageBox(cantopen,_T("QuickUnpack"),MB_OK);
			else
			{
				CString sExportList,sTemp;
				sTemp=szPEFileName;
				sExportList.Append(_T("; This list was generated by QuickUnpack\r\n"));
				sExportList.Append(_T("; Target: ")+sTemp+_T("\r\n\r\n"));

				sTemp=ImportList.GetItemText(0,4);
				sTemp.Replace(_T("0x"),_T(""));

				for(int i=0;i!=ImportList.GetItemCount();++i)
				{
					if(ImportList.GetItemText(i,2).IsEmpty())
						sExportList.Append(_T("0\t"));
					else
					{
						sTemp=IntToStr(pImport->Records[i].Type,10,0);							//type
						sExportList.Append(sTemp+_T("\t"));
					}
					sTemp=IntToStr(pImport->Records[i].dwReferenceRVA,16,sizeof(pImport->Records[0].dwReferenceRVA)*2);
					sExportList.Append(sTemp+_T("\t"));
					sTemp=IntToStr(pImport->Records[i].dwRecordRVA,16,sizeof(pImport->Records[0].dwRecordRVA)*2);
					sExportList.Append(sTemp+_T("\t"));
					sTemp=ImportList.GetItemText(i,2);
					if(sTemp.IsEmpty())
						sTemp=_T("?");															//no libname
					sExportList.Append(sTemp+_T("\t"));											//libname

					sTemp=ImportList.GetItemText(i,3);
					if(sTemp==noname)
						sTemp=_T("?");															//apiname

					sExportList.Append(ImportList.GetItemText(i,7)+_T("\t"));					//ordinal
					sExportList.Append(sTemp+_T("\r\n"));
				}
				DWORD dwBytesWritten;
				WriteFile(hFile,sExportList.GetString(),sExportList.GetLength()*sizeof(sExportList.GetString()[0]),&dwBytesWritten,0);
				CloseHandle(hFile);

				MessageBox(importexported1+_T("\r\n")+importexported2+IntToStr(sExportList.GetLength()*sizeof(sExportList.GetString()[0]),10,0)+bytes,exporttofile,MB_OK+MB_ICONINFORMATION);
			}
		}
		SetCurrentDirectory(szCurrDir);
	}
}

void CDlgImport::OnBnClickedImpEdit()
{
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)==LVIS_SELECTED)
		{
			CDlgEditImport DlgEditImport(pModules,&pImport->Records[i]);
			EnableWindow(FALSE);
			if(DlgEditImport.DoModal()==IDOK)
			{
				FillRecord(i);
				GetDlgItem(IDC_USEOLDIAT)->EnableWindow(pImport->CheckOldIAT(*pPEMain,NULL) ? FALSE : TRUE);
				ChangeWndHeader();
			}
			EnableWindow(TRUE);
			SetForegroundWindow();
			break;
		}
	}
}

void CDlgImport::OnBnClickedImpLoadLib()
{
	TCHAR szCurrDir[MAX_PATH];
	GetCurrentDirectory(_countof(szCurrDir),szCurrDir);

	TCHAR szFileName[MAX_PATH];
	OPENFILENAME ofn;
	memset(&ofn,0,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=GetSafeHwnd();
	ofn.Flags=OFN_HIDEREADONLY;
	ofn.lpstrFilter=_T("dll files\0*.dll\0");
	ofn.lpstrInitialDir=szCurrDir;
	ofn.lpstrFile=szFileName;
	ofn.lpstrFile[0]=_T('\0');
	ofn.nMaxFile=_countof(szFileName);

	if(GetOpenFileName(&ofn))
	{
		if(pMain->pInitData->ImportRec!=irSmartTracer && pMain->pInitData->UnpackMode==umSkipOEP)
			pMain->Attach();
		pMain->LoadExtraLibrary(ofn.lpstrFile);
		if(pMain->pInitData->ImportRec!=irSmartTracer && pMain->pInitData->UnpackMode==umSkipOEP)
			pMain->Detach();
	}
	SetCurrentDirectory(szCurrDir);
}

void CDlgImport::OnBnClickedImport()
{
	BYTE bType;
	TCHAR szCurrDir[MAX_PATH];
	GetCurrentDirectory(_countof(szCurrDir),szCurrDir);

	TCHAR szFileName[MAX_PATH];
	OPENFILENAME ofn;
	memset(&ofn,0,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=GetSafeHwnd();
	ofn.lpstrDefExt=_T("txt");
	ofn.Flags=OFN_HIDEREADONLY;
	ofn.lpstrFilter=_T("txt files\0*.txt\0");
	ofn.lpstrInitialDir=szCurrDir;
	ofn.lpstrFile=szFileName;
	ofn.lpstrFile[0]=_T('\0');
	ofn.nMaxFile=_countof(szFileName);

	if(GetOpenFileName(&ofn))
	{
		HANDLE hFile=CreateFile(ofn.lpstrFile,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if(hFile==INVALID_HANDLE_VALUE)
			MessageBox(cantopen,_T("QuickUnpack"),MB_OK);
		else
		{
			pImport->Clear();

			CString sImportList,sTemp;
			sTemp=szPEFileName;

			DWORD dwFileSize=GetFileSize(hFile,NULL);
			BYTE *bFuncList=new BYTE[dwFileSize];
			DWORD dwBytesRead;
			ReadFile(hFile,bFuncList,dwFileSize,&dwBytesRead,NULL);
			if(IsTextUnicode(bFuncList,dwFileSize,NULL) && *(WORD*)bFuncList==UNICODE_MAGIC)
			{
				dwFileSize-=sizeof(UNICODE_MAGIC);
				memmove(bFuncList,bFuncList+sizeof(UNICODE_MAGIC),dwFileSize);
			}
#ifdef UNICODE
			if(!IsTextUnicode(bFuncList,dwFileSize,NULL))
			{
				int nLen=dwFileSize;
				WCHAR *pWideArray=new WCHAR[nLen];
				MultiByteToWideChar(CP_ACP,0,(char*)bFuncList,nLen,pWideArray,nLen);
				sImportList.SetString(pWideArray,nLen);
				delete[] pWideArray;
			}
			else
				sImportList.SetString((WCHAR*)bFuncList,dwFileSize/sizeof(WCHAR));
#else
			if(IsTextUnicode(bFuncList,dwFileSize,NULL))
			{
				int nLen=dwFileSize/sizeof(WCHAR);
				char *pMultiArray=new char[nLen];
				WideCharToMultiByte(CP_ACP,0,(WCHAR*)bFuncList,nLen,pMultiArray,nLen,NULL,NULL);
				sImportList.SetString(pMultiArray,nLen);
				delete[] pMultiArray;
			}
			else
				sImportList.SetString((char*)bFuncList,dwFileSize);
#endif
			CloseHandle(hFile);
			delete[] bFuncList;

			CImportRecord ImportRecord;
			if(!sImportList.IsEmpty())
			{
				sImportList.Delete(0,sImportList.Find(_T("\xD\xA\xD\xA"),0));
				for(;;)
				{
					while(sImportList.Left(2)==_T("\xD\xA"))
						sImportList.Delete(0,2);
					if(sImportList.IsEmpty())
						break;
					bType=(BYTE)(sImportList.GetBuffer()[0]-_T('0'));							//type
					sImportList.Delete(0,sImportList.Find(_T('\x9'),0)+1);
					ImportRecord.Clear();
					ImportRecord.dwReferenceRVA=_tcstoul(sImportList.Left(8),NULL,16);			//ReferenceRVA
					ImportRecord.Type=(EImportRecordType)bType;
					sImportList.Delete(0,sImportList.Find(_T('\x9'),0)+1);
					ImportRecord.dwRecordRVA=_tcstoul(sImportList.Left(8),NULL,16);				//RecordRVA
					sImportList.Delete(0,sImportList.Find(_T('\x9'),0)+1);
					sTemp=sImportList.Left(sImportList.Find(_T('\x9'),0));						//libname
					if(sTemp==_T("?"))
						sTemp=_T("");
					ImportRecord.sLibName=sTemp;
					sImportList.Delete(0,sImportList.Find(_T('\x9'),0)+1);
					ImportRecord.wOrdinal=(WORD)_tcstoul(sImportList.Left(4),NULL,16);			//ordinal
					sImportList.Delete(0,sImportList.Find(_T('\x9'),0)+1);
					sTemp=sImportList.Left(sImportList.Find(_T("\xD\xA"),0));					//apiname
					if(sTemp==_T("?"))
						sTemp=_T("");
					sImportList.Delete(0,sImportList.Find(_T("\xD\xA"),0)+2);
#ifdef UNICODE
					int nWideLength=sTemp.GetLength()+1;
					char *pMultiArray=new char[nWideLength];
					WideCharToMultiByte(CP_ACP,0,sTemp.GetBuffer(),nWideLength,pMultiArray,nWideLength,NULL,NULL);
					ImportRecord.sApiName=pMultiArray;
					delete[] pMultiArray;
#else
					ImportRecord.sApiName=sTemp;
#endif
					pImport->AddRecord(ImportRecord);
				}
			}
			ImportSortType=pImport->CheckOldIAT(*pPEMain,NULL) ? siByRecord : siByName;
			GetDlgItem(IDC_USEOLDIAT)->EnableWindow(ImportSortType==siByRecord ? FALSE : TRUE);
			FillTable();
		}
	}
	SetCurrentDirectory(szCurrDir);
}

void CDlgImport::OnBnClickedImpDisasm()
{
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)==LVIS_SELECTED)
		{
			DWORD_PTR Temp=0;
			BYTE bBuffer[INSTRS_TO_DISASM*MAX_INSTRUCTION_LEN];
			CDlgDisasm DlgDisasm;

			pMain->ReadMem(pImport->Records[i].dwReferenceRVA-2+pMain->VictimBase,&bBuffer,sizeof(bBuffer));
			if((bBuffer[1]==0xe8 || bBuffer[1]==0xe9) && bBuffer[0]!=0xe8 && bBuffer[0]!=0xe9)
				Temp=pImport->Records[i].dwReferenceRVA+sizeof(DWORD)+pMain->VictimBase+*(DWORD*)(bBuffer+2);
			else if(bBuffer[0]==0xe8 || bBuffer[0]==0xe9)
				Temp=pImport->Records[i].dwReferenceRVA-1+sizeof(DWORD)+pMain->VictimBase+*(DWORD*)(bBuffer+1);
#if defined _M_AMD64
			else if(bBuffer[1]==0xa1)
				pMain->ReadMem(*(DWORD_PTR*)(bBuffer+2),&Temp,sizeof(Temp));
			else
				pMain->ReadMem(pImport->Records[i].dwReferenceRVA+sizeof(DWORD)+pMain->VictimBase+*(DWORD*)(bBuffer+2),&Temp,sizeof(Temp));
#elif defined _M_IX86
			else
				pMain->ReadMem(*(DWORD*)(bBuffer+2),&Temp,sizeof(Temp));
#else
!!!
#endif
			pMain->ReadMem(Temp,&bBuffer,sizeof(bBuffer));
			if(*(DWORD_PTR*)(bBuffer+TRAMPOLINE_OFFSET)==pMain->Modules.TrampolineBase)
				Temp=*(DWORD_PTR*)(bBuffer+FUNC_OFFSET);
			pMain->ReadMem(Temp,&bBuffer,sizeof(bBuffer));
			DlgDisasm.pAddr=(void*)bBuffer;
			DlgDisasm.AltAddress=Temp;
			DlgDisasm.DoModal();
			break;
		}
	}
}

void CDlgImport::OnBnClickedChangeSort()
{
	if(ImportSortType==siByName)
		ImportSortType=siByRecord;
	else if(ImportSortType==siByRecord)
		ImportSortType=siByReference;
	else if(ImportSortType==siByReference)
		ImportSortType=siByName;
	FillTable();
}

void CDlgImport::OnBnClickedPrevForw()
{
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)!=LVIS_SELECTED)
			continue;

		pModules->ForwardedPrev(pImport->Records[i],1);
		FillRecord(i);
	}
	GetDlgItem(IDC_USEOLDIAT)->EnableWindow(pImport->CheckOldIAT(*pPEMain,NULL) ? FALSE : TRUE);
}

void CDlgImport::OnBnClickedNextForw()
{
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)!=LVIS_SELECTED)
			continue;

		pModules->ForwardedNext(pImport->Records[i],1);
		FillRecord(i);
	}
	GetDlgItem(IDC_USEOLDIAT)->EnableWindow(pImport->CheckOldIAT(*pPEMain,NULL) ? FALSE : TRUE);
}

void CDlgImport::OnBnClickedPrevFunc()
{
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)!=LVIS_SELECTED)
			continue;

		pModules->IdentifyFunctionPrev(pImport->Records[i]);
		FillRecord(i);
	}
}

void CDlgImport::OnBnClickedNextFunc()
{
	for(int i=0;i!=ImportList.GetItemCount();++i)
	{
		if(ImportList.GetItemState(i,LVIS_SELECTED)!=LVIS_SELECTED)
			continue;

		pModules->IdentifyFunctionNext(pImport->Records[i]);
		FillRecord(i);
	}
}