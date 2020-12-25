#include "StdAfx.h"
#include "DlgMain.h"
#include "PEFile.h"
#include "EngineHandler.h"
#include "Imagehlp.h"

const DWORD ZEROFIND_MINZEROS=1000000;
const DWORD ZEROFIND_MINSECT=5000000;

CImportRecord::CImportRecord()
{
	Clear();
}

CImportRecord::CImportRecord(const TCHAR *szLibName,const char *szApiName,DWORD n_dwReferenceRVA,DWORD n_dwRecordRVA,EImportRecordType n_Type)
{
	Clear();
	sLibName=szLibName;
	sApiName=szApiName;
	dwReferenceRVA=n_dwReferenceRVA;
	dwRecordRVA=n_dwRecordRVA;
	Type=n_Type;
}

CImportRecord::CImportRecord(const TCHAR *szLibName,WORD n_wOrdinal,DWORD n_dwReferenceRVA,DWORD n_dwRecordRVA,EImportRecordType n_Type)
{
	Clear();
	sLibName=szLibName;
	wOrdinal=n_wOrdinal;
	dwReferenceRVA=n_dwReferenceRVA;
	dwRecordRVA=n_dwRecordRVA;
	Type=n_Type;
}

void CImportRecord::Clear()
{
	sLibName.clear();
	sApiName.clear();
	wOrdinal=0;

	dwReferenceRVA=0;
	dwRecordRVA=0;
	NameRVA=0;
	Type=itNone;

	nLib=-1;
	nApi=-1;
	nTrampoline=-1;
}

void CImport::Clear()
{
	Records.clear();
}

void CImport::AddRecord(const CImportRecord &ImportRecord)
{
	for(size_t i=0;i!=Records.size();++i)
	{
		if(Records[i].dwRecordRVA==ImportRecord.dwRecordRVA && Records[i].dwReferenceRVA==ImportRecord.dwReferenceRVA)
			return;
	}
	Records.push_back(ImportRecord);
}

void CImport::ReadFromFile(const CPEFile &File)
{
	Clear();
	CImportRecord ImportRecord;
	DWORD dwPosRVA=File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	for(;;)
	{
		IMAGE_IMPORT_DESCRIPTOR *pImports=(IMAGE_IMPORT_DESCRIPTOR*)File.RVA(dwPosRVA);
		if(pImports==NULL || File.RVA(pImports->Name)==NULL)
			return;
		DWORD dwRecRVA=pImports->OriginalFirstThunk;
		if(dwRecRVA==0)
			dwRecRVA=pImports->FirstThunk;
		if(dwRecRVA==0)
		{
			dwPosRVA+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
			continue;
		}
#ifdef UNICODE
		char *pMultiArray=(char*)File.RVA(pImports->Name);
		int nMultiLength=(int)strlen(pMultiArray)+1;
		WCHAR *pWideArray=new WCHAR[nMultiLength];
		MultiByteToWideChar(CP_ACP,0,pMultiArray,nMultiLength,pWideArray,nMultiLength);
		ImportRecord.sLibName=pWideArray;
		delete[] pWideArray;
#else
		ImportRecord.sLibName=(char*)File.RVA(pImports->Name);
#endif
		for(;;)
		{
			IMAGE_THUNK_DATA *pRecAddr=(IMAGE_THUNK_DATA*)File.RVA(dwRecRVA);
			if(pRecAddr->u1.AddressOfData==0)
				break;
			if(IMAGE_SNAP_BY_ORDINAL(pRecAddr->u1.Ordinal))
			{
				ImportRecord.sApiName.clear();
				ImportRecord.wOrdinal=IMAGE_ORDINAL(pRecAddr->u1.Ordinal);
			}
			else if(File.RVA((DWORD)(pRecAddr->u1.AddressOfData))!=NULL)
			{
				ImportRecord.sApiName=(char*)((IMAGE_IMPORT_BY_NAME*)File.RVA((DWORD)(pRecAddr->u1.AddressOfData)))->Name;
				ImportRecord.wOrdinal=0;
			}
			ImportRecord.dwRecordRVA=dwRecRVA;
			AddRecord(ImportRecord);
			dwRecRVA+=sizeof(DWORD);
		}
		dwPosRVA+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
}

bool CompareImportsByName(const CImportRecord &Import1,const CImportRecord &Import2)
{
	if(_tcsicmp(Import1.sLibName.c_str(),Import2.sLibName.c_str())!=0)
		return _tcsicmp(Import1.sLibName.c_str(),Import2.sLibName.c_str())<0;
	if(Import1.sApiName!=Import2.sApiName)
		return _stricmp(Import1.sApiName.c_str(),Import2.sApiName.c_str())<0;
	if(Import1.dwRecordRVA!=Import2.dwRecordRVA)
	{
		if(Import1.dwRecordRVA==0)
			return false;
		if(Import2.dwRecordRVA==0)
			return true;
		return Import1.dwRecordRVA<Import2.dwRecordRVA;
	}
	return Import1.dwReferenceRVA<Import2.dwReferenceRVA;
}

bool CompareImportsByRecord(const CImportRecord &Import1,const CImportRecord &Import2)
{
	if(Import1.dwRecordRVA!=Import2.dwRecordRVA)
		return Import1.dwRecordRVA<Import2.dwRecordRVA;
	return Import1.dwReferenceRVA<Import2.dwReferenceRVA;
}

bool CompareImportsByReference(const CImportRecord &Import1,const CImportRecord &Import2)
{
	return Import1.dwReferenceRVA<Import2.dwReferenceRVA;
}

void CImport::SortRecords(ESortImportType SortType)
{
	if(SortType==siByName)
		std::sort(Records.begin(),Records.end(),CompareImportsByName);
	else if(SortType==siByRecord)
		std::sort(Records.begin(),Records.end(),CompareImportsByRecord);
	else if(SortType==siByReference)
		std::sort(Records.begin(),Records.end(),CompareImportsByReference);
	CurrentSort=SortType;
}

void CImport::RedirectToOldIAT(bool fRedirectToEmpty,DWORD *pLibsNumber,DWORD *pDirectRefs)
{
	SortRecords(siByName);

	int nLib=-1,nApi=-1,nTrampoline=-1;
	size_t RecordlessNum=0;
	std::map<TSTRING,std::map<WORD,std::vector<size_t>>> Recordless;
	CImportRecord LastRecord(_T(""),(WORD)0,0,0,itNone);
	for(size_t i=0;i!=Records.size();++i)
	{
		if(_tcsicmp(Records[i].sLibName.c_str(),LastRecord.sLibName.c_str())==0 &&
			Records[i].wOrdinal==LastRecord.wOrdinal)
		{
			--nApi;
			if(Records[i].dwRecordRVA==0)
			{
				Records[i].dwRecordRVA=LastRecord.dwRecordRVA;
				if(Records[i].dwRecordRVA==0)
					Recordless[Records[i].sLibName][Records[i].wOrdinal].push_back(i);
			}
		}
		else if(Records[i].dwRecordRVA==0)
		{
			++RecordlessNum;
			Recordless[Records[i].sLibName][Records[i].wOrdinal].push_back(i);
		}

		if(_tcsicmp(Records[i].sLibName.c_str(),LastRecord.sLibName.c_str())!=0)
		{
			++nLib;
			nApi=-1;
		}
		++nApi;

		if(Records[i].IsDirectRef())
		{
			++nTrampoline;
			for(size_t j=i;j!=0;)
			{
				--j;
				if(_tcsicmp(Records[i].sLibName.c_str(),Records[j].sLibName.c_str())!=0 ||
					Records[i].wOrdinal!=Records[j].wOrdinal)
				{
					break;
				}

				if(Records[j].IsDirectRef())
				{
					--nTrampoline;
					break;
				}
			}
		}

		Records[i].nLib=nLib;
		Records[i].nApi=nApi;
		Records[i].nTrampoline=nTrampoline;

		LastRecord=Records[i];
	}
	if(pLibsNumber!=NULL)
		*pLibsNumber=nLib+1;
	if(pDirectRefs!=NULL)
		*pDirectRefs=nTrampoline+1;

	if(fRedirectToEmpty && RecordlessNum!=0)
	{
		ESortImportType OldSort=CurrentSort;
		SortRecords(siByRecord);

		std::map<TSTRING,std::vector<DWORD>> EmptySpaces;
		for(size_t i=0;i!=Records.size();++i)
		{
			if(Records[i].dwRecordRVA==0)
			{
				LastRecord.dwRecordRVA=0;
				continue;
			}
			if(LastRecord.dwRecordRVA!=0)
			{
				DWORD dwDiffNum=(Records[i].dwRecordRVA-LastRecord.dwRecordRVA)/sizeof(DWORD_PTR);
				if(dwDiffNum>1)
				{
					DWORD dwSeparator=0;
					if(_tcsicmp(Records[i].sLibName.c_str(),LastRecord.sLibName.c_str())!=0)
						dwSeparator=1;

					bool fBackwards=false;
					TSTRING sLibName(LastRecord.sLibName);
					for(DWORD j=1;j<dwDiffNum-dwSeparator;)
					{
						if(EmptySpaces[sLibName].size()==Recordless[sLibName].size())
						{
							if(dwSeparator==0)
							{
								if(!fBackwards)
									++j;
								for(;j+1<dwDiffNum;++j)
								{
									if(EmptySpaces[_T("")].size()==RecordlessNum*2)
										break;
									EmptySpaces[_T("")].push_back(LastRecord.dwRecordRVA+j*sizeof(DWORD_PTR));
								}
								break;
							}
							else
							{
								++j;
								dwSeparator=0;
								sLibName=Records[i].sLibName;
								if(EmptySpaces[sLibName].size()==Recordless[sLibName].size())
								{
									for(;j+1<dwDiffNum;++j)
									{
										if(EmptySpaces[_T("")].size()==RecordlessNum*2)
											break;
										EmptySpaces[_T("")].push_back(LastRecord.dwRecordRVA+j*sizeof(DWORD_PTR));
									}
									break;
								}
								fBackwards=true;
							}
						}
						if(fBackwards)
						{
							EmptySpaces[sLibName].push_back(LastRecord.dwRecordRVA+(dwDiffNum-1)*sizeof(DWORD_PTR));
							--dwDiffNum;
						}
						else
						{
							EmptySpaces[sLibName].push_back(LastRecord.dwRecordRVA+j*sizeof(DWORD_PTR));
							++j;
						}
					}
				}
			}
			LastRecord=Records[i];
		}
		SortRecords(OldSort);

		bool fEnoughSpaces=true;
		size_t AnyEmptyNum=0;
		for(std::map<TSTRING,std::map<WORD,std::vector<size_t>>>::iterator it_rec(Recordless.begin());it_rec!=Recordless.end();++it_rec)
		{
			if(it_rec->second.size()>EmptySpaces[it_rec->first].size())
			{
				size_t NeedSize=it_rec->second.size();
				if(AnyEmptyNum!=0 &&
					EmptySpaces[_T("")][AnyEmptyNum]-EmptySpaces[_T("")][AnyEmptyNum-1]<2*sizeof(DWORD_PTR))
				{
					++NeedSize;
				}
				if(NeedSize>EmptySpaces[it_rec->first].size()+EmptySpaces[_T("")].size()-AnyEmptyNum)
				{
					fEnoughSpaces=false;
					break;
				}
				else
					AnyEmptyNum+=NeedSize-EmptySpaces[it_rec->first].size();
			}
		}

		if(fEnoughSpaces)
		{
			AnyEmptyNum=0;
			for(std::map<TSTRING,std::map<WORD,std::vector<size_t>>>::iterator it_rec(Recordless.begin());it_rec!=Recordless.end();++it_rec)
			{
				if(AnyEmptyNum!=0 && it_rec->second.size()>EmptySpaces[it_rec->first].size() &&
					EmptySpaces[_T("")][AnyEmptyNum]-EmptySpaces[_T("")][AnyEmptyNum-1]<2*sizeof(DWORD_PTR))
				{
					++AnyEmptyNum;
				}

				size_t EmptyNum=0;
				for(std::map<WORD,std::vector<size_t>>::iterator it_func(it_rec->second.begin());it_func!=it_rec->second.end();++it_func)
				{
					if(EmptyNum>=EmptySpaces[it_rec->first].size())
					{
						for(size_t i=0;i!=it_func->second.size();++i)
							Records[it_func->second[i]].dwRecordRVA=EmptySpaces[_T("")][AnyEmptyNum];
						++AnyEmptyNum;
					}
					else
					{
						for(size_t i=0;i!=it_func->second.size();++i)
							Records[it_func->second[i]].dwRecordRVA=EmptySpaces[it_rec->first][EmptyNum];
						++EmptyNum;
					}
				}
			}
		}
	}
}

bool CImport::CheckOldIAT(const CPEFile &File,DWORD *pLibsNumber)
{
	SortRecords(siByRecord);

	int nLib=-1,nApi=-1;
	CImportRecord LastRecord(_T(""),(WORD)0,0,0,itNone);
	DWORD dwEnd=pMain->pInitData->dwCutModule!=0 ? pMain->pInitData->dwCutModule :
		File.pPEHeader->OptionalHeader.SizeOfImage;
	for(size_t i=0;i!=Records.size();++i)
	{
		if(Records[i].dwRecordRVA==0)
			return false;

		if(Records[i].dwRecordRVA>=dwEnd)
			return false;
		if(Records[i].dwRecordRVA-LastRecord.dwRecordRVA<2*sizeof(DWORD_PTR) &&
			_tcsicmp(Records[i].sLibName.c_str(),LastRecord.sLibName.c_str())!=0)
		{
			return false;
		}
		if(Records[i].dwRecordRVA==LastRecord.dwRecordRVA)
			--nApi;
		else if(Records[i].dwRecordRVA-LastRecord.dwRecordRVA!=sizeof(DWORD_PTR) ||
			_tcsicmp(Records[i].sLibName.c_str(),LastRecord.sLibName.c_str())!=0)
		{
			++nLib;
			nApi=-1;
		}
		++nApi;

		Records[i].nLib=nLib;
		Records[i].nApi=nApi;

		LastRecord=Records[i];
	}
	if(pLibsNumber!=NULL)
		*pLibsNumber=nLib+1;
	return true;
}

void CImport::SaveToIAT(CPEFile &File,DWORD dwImportRVA)
{
	bool fUseOldIAT=false;
	DWORD dwLibsNumber,dwDirectRefs;
	RedirectToOldIAT(false,&dwLibsNumber,&dwDirectRefs);
	if(CheckOldIAT(File,&dwLibsNumber))
		fUseOldIAT=true;
	else
		RedirectToOldIAT(false,&dwLibsNumber,&dwDirectRefs);

	DWORD dwTrampolineSize=pMain->pInitData->fLeaveDirectRefs && dwDirectRefs!=0 ? dwDirectRefs*6 : 0;
	DWORD dwTrampolineRVA=File.pPEHeader->OptionalHeader.SizeOfImage;
	if(dwTrampolineSize!=0)
	{
		BYTE *bTrampolineDir=new BYTE[dwTrampolineSize];
		memset(bTrampolineDir,0,dwTrampolineSize);
		File.CreateSection(".itramp",bTrampolineDir,dwTrampolineSize,IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
		delete[] bTrampolineDir;
	}

	if(dwImportRVA==0 || File.RVA(dwImportRVA)==NULL)
		dwImportRVA=File.pPEHeader->OptionalHeader.SizeOfImage;
	std::vector<IMAGE_IMPORT_DESCRIPTOR> ImportEntries;
	ImportEntries.resize(dwLibsNumber);

	DWORD dwImportSize;
	int nLastApi,nLastLib;
	for(;;)
	{
		dwImportSize=sizeof(IMAGE_IMPORT_DESCRIPTOR)*(dwLibsNumber+1);
		for(size_t i=0;i!=Records.size();)
		{
			DWORD dwLookupSize=sizeof(DWORD_PTR);

			size_t j=i+1;
			for(;j<Records.size();++j)
			{
				if(Records[j].nLib>Records[i].nLib)
					break;
			}

			if(fUseOldIAT)
			{
				ImportEntries[Records[i].nLib].OriginalFirstThunk=0;
				ImportEntries[Records[i].nLib].FirstThunk=Records[i].dwRecordRVA;
			}
			else
			{
				dwLookupSize+=sizeof(DWORD_PTR)*(Records[j-1].nApi+1);

				ImportEntries[Records[i].nLib].OriginalFirstThunk=dwImportRVA+dwImportSize;
				dwImportSize+=dwLookupSize;

				ImportEntries[Records[i].nLib].FirstThunk=dwImportRVA+dwImportSize;
				dwImportSize+=dwLookupSize;
			}
			i=j;
		}

		nLastApi=-1;
		nLastLib=-1;
		for(size_t i=0;i!=Records.size();++i)
		{
			if(Records[i].nLib>nLastLib)
			{
				ImportEntries[Records[i].nLib].Name=dwImportRVA+dwImportSize;
				dwImportSize+=(DWORD)AlignTo(Records[i].sLibName.length()+1,2);

				ImportEntries[Records[i].nLib].ForwarderChain=0;
				ImportEntries[Records[i].nLib].TimeDateStamp=0;

				nLastLib=Records[i].nLib;
				nLastApi=-1;
			}

			if(Records[i].nApi>nLastApi)
			{
				if(!Records[i].sApiName.empty())
				{
					Records[i].NameRVA=dwImportRVA+dwImportSize;
					dwImportSize+=offsetof(IMAGE_IMPORT_BY_NAME,Name)+(DWORD)AlignTo(Records[i].sApiName.length()+1,2);
				}
				else
					Records[i].NameRVA=Records[i].wOrdinal | IMAGE_ORDINAL_FLAG;
				if(fUseOldIAT)
					File.SetSectionWritable(Records[i].dwRecordRVA);

				nLastApi=Records[i].nApi;
			}
		}
		int n=File.GetSectionNumber(dwImportRVA);
		if(dwImportRVA!=File.pPEHeader->OptionalHeader.SizeOfImage && (n==-1 || dwImportRVA-File.pSectionHeader[n].VirtualAddress+dwImportSize>File.pSectionHeader[n].SizeOfRawData))
			dwImportRVA=File.pPEHeader->OptionalHeader.SizeOfImage;
		else
			break;
	}

	if(dwImportRVA==File.pPEHeader->OptionalHeader.SizeOfImage)
	{
		BYTE *bImportDir=new BYTE[dwImportSize];
		memset(bImportDir,0,dwImportSize);
		File.CreateSection(".idata",bImportDir,dwImportSize,IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA);
		delete[] bImportDir;
	}
	else
		memset(File.RVA(dwImportRVA),0,dwImportSize);

	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress=dwImportRVA;
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=dwImportSize;

	memcpy(File.RVA(dwImportRVA),&ImportEntries[0],sizeof(ImportEntries[0])*ImportEntries.size());

	WORD wPrev;
	DWORD redir1,dwRVA;
	if(!pMain->pInitData->fLeaveDirectRefs && dwDirectRefs!=0)
	{
		for(DWORD k=0;k!=File.pPEHeader->FileHeader.NumberOfSections;++k)
		{
			if(pMain->pInitData->dwCutModule!=0 && pMain->pInitData->dwCutModule<=File.pSectionHeader[k].VirtualAddress)
				break;
			for(int j=2;j<(int)(File.pSectionHeader[k].SizeOfRawData-(sizeof(DWORD)-1));++j)
			{
				dwRVA=File.pSectionHeader[k].VirtualAddress+j;

				BYTE *pFilePtr=File.RVA(dwRVA-2);
				if(pFilePtr!=NULL)
					wPrev=*(WORD*)pFilePtr;
				else
					continue;
				pFilePtr=File.RVA(dwRVA);
				if(pFilePtr!=NULL)
					redir1=*(DWORD*)pFilePtr;
				else
					continue;

				DWORD dwDest=0;
				if((wPrev>>8)==0xe8 || (wPrev>>8)==0xe9)
					dwDest=redir1+sizeof(DWORD)+dwRVA;
#if defined _M_IX86
				else if(((wPrev>>8) & 0xf8)==0xb8 || (wPrev>>8)==0x68)
					dwDest=redir1-File.pPEHeader->OptionalHeader.ImageBase;
#endif
				if(dwDest!=0)
				{
					for(size_t i=0;i!=Records.size();++i)
					{
						if(!Records[i].IsDirectRef())
							continue;

						if(Records[i].dwReferenceRVA-2==dwDest-1)
						{
							++Records[i].dwReferenceRVA;
							j+=sizeof(DWORD)-1;
							break;
						}
					}
				}
			}
		}

		ESortImportType OldSort=CurrentSort;
		SortRecords(siByReference);
		for(size_t i=1;i<Records.size();++i)
		{
			if(!Records[i].IsDirectRef())
				continue;

			if(Records[i].dwReferenceRVA-2==Records[i-1].dwReferenceRVA+sizeof(DWORD)-1)
				++Records[i].dwReferenceRVA;
		}
		SortRecords(OldSort);
	}

	nLastApi=-1;
	nLastLib=-1;
	for(size_t i=0;i!=Records.size();++i)
	{
		if(Records[i].nLib>nLastLib)
		{
			if(File.RVA(ImportEntries[Records[i].nLib].Name)!=NULL)
			{
#ifdef UNICODE
				int nWideLength=(int)Records[i].sLibName.length()+1;
				WideCharToMultiByte(CP_ACP,0,Records[i].sLibName.c_str(),nWideLength,
					(char*)File.RVA(ImportEntries[Records[i].nLib].Name),nWideLength,NULL,NULL);
#else
				strcpy_s((char*)File.RVA(ImportEntries[Records[i].nLib].Name),Records[i].sLibName.length()+1,Records[i].sLibName.c_str());
#endif
			}
			nLastLib=Records[i].nLib;
			nLastApi=-1;
		}
		if(Records[i].nApi>nLastApi)
		{
			if(!Records[i].sApiName.empty() && File.RVA((DWORD)(Records[i].NameRVA+offsetof(IMAGE_IMPORT_BY_NAME,Name)))!=NULL)
				strcpy_s((char*)File.RVA((DWORD)(Records[i].NameRVA+offsetof(IMAGE_IMPORT_BY_NAME,Name))),Records[i].sApiName.length()+1,Records[i].sApiName.c_str());
			if(!fUseOldIAT && File.RVA(ImportEntries[Records[i].nLib].OriginalFirstThunk+Records[i].nApi*sizeof(DWORD_PTR))!=NULL)
				*(DWORD_PTR*)File.RVA(ImportEntries[Records[i].nLib].OriginalFirstThunk+Records[i].nApi*sizeof(DWORD_PTR))=Records[i].NameRVA;
			if(File.RVA(ImportEntries[Records[i].nLib].FirstThunk+Records[i].nApi*sizeof(DWORD_PTR))!=NULL)
				*(DWORD_PTR*)File.RVA(ImportEntries[Records[i].nLib].FirstThunk+Records[i].nApi*sizeof(DWORD_PTR))=Records[i].NameRVA;
			if(File.RVA(ImportEntries[Records[i].nLib].FirstThunk+Records[i].nApi*sizeof(DWORD_PTR)+sizeof(DWORD_PTR))!=NULL)
				*(DWORD_PTR*)File.RVA(ImportEntries[Records[i].nLib].FirstThunk+Records[i].nApi*sizeof(DWORD_PTR)+sizeof(DWORD_PTR))=0;

			nLastApi=Records[i].nApi;
		}

		dwRVA=Records[i].dwReferenceRVA;
		if(dwRVA!=0 && File.RVA(dwRVA)!=NULL && File.RVA(dwRVA-2)!=NULL)
		{
			if(Records[i].Type==itIndirectJmp)
				*(WORD*)File.RVA(dwRVA-2)=0x25ff;
			else if(Records[i].Type==itDirectJmp && dwTrampolineSize==0)
				*(WORD*)File.RVA(dwRVA-2)=0x25ff;
			else if(Records[i].Type==itIndirectCall)
				*(WORD*)File.RVA(dwRVA-2)=0x15ff;
			else if(Records[i].Type==itDirectCall && dwTrampolineSize==0)
				*(WORD*)File.RVA(dwRVA-2)=0x15ff;
#if defined _M_IX86
			else if(Records[i].Type==itDirectOther && dwTrampolineSize==0)
			{
				wPrev=*(BYTE*)File.RVA(dwRVA-1);
				if(wPrev==0x68 && File.RVA(dwRVA+4)!=NULL)
				{
					wPrev=*(BYTE*)File.RVA(dwRVA+4);
					if(wPrev==0xc3)
						*(WORD*)File.RVA(dwRVA-2)=0x25ff;
					else
						*(WORD*)File.RVA(dwRVA-2)=0x35ff;
				}
				else if(wPrev==0xb8)
					*(WORD*)File.RVA(dwRVA-2)=0x058b;
				else if(wPrev==0xb9)
					*(WORD*)File.RVA(dwRVA-2)=0x0d8b;
				else if(wPrev==0xba)
					*(WORD*)File.RVA(dwRVA-2)=0x158b;
				else if(wPrev==0xbb)
					*(WORD*)File.RVA(dwRVA-2)=0x1d8b;
				else if(wPrev==0xbc)
					*(WORD*)File.RVA(dwRVA-2)=0x258b;
				else if(wPrev==0xbd)
					*(WORD*)File.RVA(dwRVA-2)=0x2d8b;
				else if(wPrev==0xbe)
					*(WORD*)File.RVA(dwRVA-2)=0x358b;
				else if(wPrev==0xbf)
					*(WORD*)File.RVA(dwRVA-2)=0x3d8b;
			}
#endif
			if(!fUseOldIAT || Records[i].IsDirectRef())
			{
				if(dwTrampolineSize!=0 && Records[i].IsDirectRef())
				{
					if(Records[i].Type==itDirectJmp || Records[i].Type==itDirectCall)
						*(DWORD*)File.RVA(dwRVA-1)=dwTrampolineRVA+Records[i].nTrampoline*6-sizeof(DWORD)-dwRVA+1;
					else if(Records[i].Type==itDirectOther)
					{
#if defined _M_AMD64
						*(DWORD*)File.RVA(dwRVA-1)=dwTrampolineRVA+Records[i].nTrampoline*6-sizeof(DWORD)-dwRVA+1;
#elif defined _M_IX86
						*(DWORD*)File.RVA(dwRVA-1)=File.pPEHeader->OptionalHeader.ImageBase+dwTrampolineRVA+Records[i].nTrampoline*6;
#else
!!!
#endif
					}
					dwRVA=dwTrampolineRVA+Records[i].nTrampoline*6+2;
					*(WORD*)File.RVA(dwRVA-2)=0x25ff;
				}
#if defined _M_AMD64
				*(DWORD*)File.RVA(dwRVA)=ImportEntries[Records[i].nLib].FirstThunk+Records[i].nApi*sizeof(DWORD_PTR)-sizeof(DWORD)-dwRVA;
#elif defined _M_IX86
				*(DWORD*)File.RVA(dwRVA)=File.pPEHeader->OptionalHeader.ImageBase+ImportEntries[Records[i].nLib].FirstThunk+
					Records[i].nApi*sizeof(DWORD_PTR);
				if(pMain->pInitData->fIsDll && pMain->pInitData->fRelocs)
					pMain->FixUp.AddItem(dwRVA,IMAGE_REL_BASED_HIGHLOW);
#else
!!!
#endif
			}
		}
	}
}

void CImport::SaveToFile(CPEFile &File,DWORD dwImportRVA)
{
	if(File.IsEmpty())
		return;
	if(Records.empty())
	{
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress=0;
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=0;
		return;
	}

	SaveToIAT(File,dwImportRVA);
}

void CFixUp::Clear()
{
	Items.clear();
}

int CFixUp::Compare(DWORD dwRVA) const
{
	for(size_t i=0;i!=Items.size();++i)
	{
		if(Items[i].dwRVA==dwRVA)
			return (int)i;
	}
	return -1;
}

void CFixUp::AddItem(DWORD dwRVA,DWORD dwType)
{
	if(Compare(dwRVA)!=-1)
		return;

	RELOCATION Item;

	Item.dwRVA=dwRVA;
	Item.dwType=dwType;
	Items.push_back(Item);
}

void CFixUp::ReadFromFile(const CPEFile &File)
{
	Clear();
	DWORD dwPosRVA=File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	while(dwPosRVA<File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress+
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		IMAGE_BASE_RELOCATION *pRelocs=(IMAGE_BASE_RELOCATION*)File.RVA(dwPosRVA);

		if(pRelocs==NULL)
			return;
		int nItemsNumber=(pRelocs->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

		for(int i=0;i<nItemsNumber;++i)
		{
			if(File.RVA(dwPosRVA+sizeof(IMAGE_BASE_RELOCATION)+i*sizeof(WORD))==NULL)
				continue;

			DWORD dwRVA=pRelocs->VirtualAddress+*(WORD*)File.RVA(dwPosRVA+sizeof(IMAGE_BASE_RELOCATION)+i*sizeof(WORD)) & 0x0fff;
			DWORD dwType=(*(WORD*)File.RVA(dwPosRVA+sizeof(IMAGE_BASE_RELOCATION)+i*sizeof(WORD)) & 0xf000)>>12;

			if(dwType!=IMAGE_REL_BASED_ABSOLUTE)
				AddItem(dwRVA,dwType);
		}
		dwPosRVA+=pRelocs->SizeOfBlock;
	}
}

bool CompareRelocs(const CFixUp::RELOCATION &Reloc1,const CFixUp::RELOCATION &Reloc2)
{
	return Reloc1.dwRVA<Reloc2.dwRVA;
}

void CFixUp::SaveToFile(CPEFile &File)
{
	if(File.IsEmpty())
		return;
	if(Items.empty())
	{
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=0;
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=0;
		return;
	}

	std::sort(Items.begin(),Items.end(),CompareRelocs);

	BYTE *bRelocSection=new BYTE[Items.size()*sizeof(DWORD)];
	memset(bRelocSection,0,Items.size()*sizeof(DWORD));

	BYTE *bRelocPosition=bRelocSection;

	for(size_t i=0;i!=Items.size();)
	{
		IMAGE_BASE_RELOCATION *pRelocs=(IMAGE_BASE_RELOCATION*)bRelocPosition;
		bRelocPosition+=sizeof(IMAGE_BASE_RELOCATION);

		pRelocs->VirtualAddress=Items[i].dwRVA & ~(PAGE_SIZE-1);

		for(;i!=Items.size() && pRelocs->VirtualAddress==(Items[i].dwRVA & ~(PAGE_SIZE-1));++i)
		{
			*(WORD*)(bRelocPosition)=(WORD)((Items[i].dwType << 12) | (Items[i].dwRVA & (PAGE_SIZE-1)));
			bRelocPosition+=sizeof(WORD);
		}

		if((((DWORD)(bRelocPosition-bRelocSection)) % 4)!=0)
			bRelocPosition+=sizeof(WORD);

		pRelocs->SizeOfBlock=(DWORD)(bRelocPosition-(BYTE*)pRelocs);
	}

	DWORD dwRVA,dwSize=(DWORD)(bRelocPosition-bRelocSection);

	dwRVA=File.pPEHeader->OptionalHeader.SizeOfImage;
	File.CreateSection(".reloc",bRelocSection,dwSize,IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE);
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=dwRVA;
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=dwSize;

	delete[] bRelocSection;
}

void CFixUp::ProcessToFile(CPEFile &File,DWORD dwDelta) const
{
	for(size_t i=0;i<Items.size();++i)
	{
		switch(Items[i].dwType)
		{
		case IMAGE_REL_BASED_HIGH:
			*(WORD*)(File.RVA(Items[i].dwRVA))=*(WORD*)(File.RVA(Items[i].dwRVA))+HIWORD(dwDelta);
			break;
		case IMAGE_REL_BASED_LOW:
			*(WORD*)(File.RVA(Items[i].dwRVA))=*(WORD*)(File.RVA(Items[i].dwRVA))+LOWORD(dwDelta);
			break;
		case IMAGE_REL_BASED_HIGHLOW:
			*(DWORD*)(File.RVA(Items[i].dwRVA))+=dwDelta;
			break;
		case IMAGE_REL_BASED_HIGHADJ:
			*(DWORD*)(File.RVA((Items[i].dwRVA << 16)+Items[i+1].dwRVA))+=dwDelta;
			++i;
			break;
		case IMAGE_REL_BASED_DIR64:
			*(DWORD64*)(File.RVA(Items[i].dwRVA))+=dwDelta;
			break;
		case IMAGE_REL_BASED_MIPS_JMPADDR:
			{
			DWORD dwReloc=*(DWORD*)(File.RVA(Items[i].dwRVA));
			*(DWORD*)(File.RVA(Items[i].dwRVA))=(((((dwReloc & 0x3ffffff)<<2)+dwDelta)>>2) & 0x3ffffff)+(dwReloc & ~0x3ffffff);
			break;
			}
		case IMAGE_REL_BASED_IA64_IMM64:
		default:
			MessageBox(NULL,_T("Unimplemented relocation type"),_T("QUnpack"),MB_OK);
			break;
		}
	}
}

void CTLS::Clear()
{
	bTLSSection.clear();
}

void CTLS::ReadFromFile(const CPEFile &File)
{
	Clear();
	IMAGE_TLS_DIRECTORY *pTLSDirectory=(IMAGE_TLS_DIRECTORY*)File.RVA(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	if(pTLSDirectory==NULL)
		return;

	int nSize=0;
	BYTE *bCallbacks,*bTmp;
	bCallbacks=File.RVA((DWORD)(pTLSDirectory->AddressOfCallBacks-File.pPEHeader->OptionalHeader.ImageBase));
	if(pTLSDirectory->AddressOfCallBacks!=0 && bCallbacks!=NULL)
	{
		while(*(DWORD_PTR*)(bCallbacks+nSize)!=0)
			nSize+=sizeof(DWORD_PTR);
		nSize+=sizeof(DWORD_PTR);
	}
	else
		pTLSDirectory->AddressOfCallBacks=0;

	bTLSSection.resize(nSize+sizeof(IMAGE_TLS_DIRECTORY)+pTLSDirectory->EndAddressOfRawData-pTLSDirectory->StartAddressOfRawData+sizeof(DWORD_PTR));
	memcpy(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR),bCallbacks,nSize);

	bTmp=File.RVA((DWORD)(pTLSDirectory->StartAddressOfRawData-File.pPEHeader->OptionalHeader.ImageBase));
	if(bTmp!=NULL && pTLSDirectory->StartAddressOfRawData!=0)
		memcpy(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR)+nSize,bTmp,
			pTLSDirectory->EndAddressOfRawData-pTLSDirectory->StartAddressOfRawData);
	else
		memset(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR)+nSize,0,
			pTLSDirectory->EndAddressOfRawData-pTLSDirectory->StartAddressOfRawData);
	bTmp=File.RVA((DWORD)(pTLSDirectory->AddressOfIndex-File.pPEHeader->OptionalHeader.ImageBase));
	if(bTmp!=NULL && pTLSDirectory->AddressOfIndex!=0)
		memcpy(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY),bTmp,sizeof(DWORD_PTR));
	else
		memset(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY),0,sizeof(DWORD_PTR));
	memcpy(&bTLSSection[0],pTLSDirectory,sizeof(IMAGE_TLS_DIRECTORY));
}

void CTLS::SaveToFile(CPEFile &File,bool fSaveCallbacks) const
{
	if(File.IsEmpty())
		return;
	if(bTLSSection.empty())
	{
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress=0;
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size=0;
		return;
	}

	DWORD dwRVA=File.pPEHeader->OptionalHeader.SizeOfImage;
	File.CreateSection(".tls",&bTLSSection[0],(DWORD)bTLSSection.size(),IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA);
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress=dwRVA;
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size=(DWORD)bTLSSection.size();
	IMAGE_TLS_DIRECTORY *pTLSDirectory=(IMAGE_TLS_DIRECTORY*)File.RVA(dwRVA);
	pTLSDirectory->AddressOfIndex=File.pPEHeader->OptionalHeader.ImageBase+dwRVA+sizeof(IMAGE_TLS_DIRECTORY);
	if(fSaveCallbacks && pTLSDirectory->AddressOfCallBacks!=0)
		pTLSDirectory->AddressOfCallBacks=File.pPEHeader->OptionalHeader.ImageBase+dwRVA+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR);
	else
		pTLSDirectory->AddressOfCallBacks=0;
	pTLSDirectory->StartAddressOfRawData=File.pPEHeader->OptionalHeader.ImageBase+dwRVA+bTLSSection.size()+
		((IMAGE_TLS_DIRECTORY*)&bTLSSection[0])->StartAddressOfRawData-((IMAGE_TLS_DIRECTORY*)&bTLSSection[0])->EndAddressOfRawData;
	pTLSDirectory->EndAddressOfRawData=File.pPEHeader->OptionalHeader.ImageBase+dwRVA+bTLSSection.size();

	if(pMain->pInitData->fRelocs)
	{
#if defined _M_AMD64
		DWORD dwType=IMAGE_REL_BASED_DIR64;
#elif defined _M_IX86
		DWORD dwType=IMAGE_REL_BASED_HIGHLOW;
#else
!!!
#endif
		if(pTLSDirectory->StartAddressOfRawData!=0)
			pMain->FixUp.AddItem(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress+offsetof(IMAGE_TLS_DIRECTORY,StartAddressOfRawData),dwType);
		if(pTLSDirectory->EndAddressOfRawData!=0)
			pMain->FixUp.AddItem(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress+offsetof(IMAGE_TLS_DIRECTORY,EndAddressOfRawData),dwType);
		if(pTLSDirectory->AddressOfIndex!=0)
			pMain->FixUp.AddItem(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress+offsetof(IMAGE_TLS_DIRECTORY,AddressOfIndex),dwType);
		if(pTLSDirectory->AddressOfCallBacks!=0)
		{
			pMain->FixUp.AddItem(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress+offsetof(IMAGE_TLS_DIRECTORY,AddressOfCallBacks),dwType);
			int i=0;
			while(*(DWORD_PTR*)(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR))!=0)
			{
				pMain->FixUp.AddItem((DWORD)(pTLSDirectory->AddressOfCallBacks-File.pPEHeader->OptionalHeader.ImageBase+i),dwType);
				i+=sizeof(DWORD_PTR);
			}
		}
	}
}

DWORD_PTR CTLS::GetFirstCallback() const
{
	if(!bTLSSection.empty())
	{
		IMAGE_TLS_DIRECTORY *pTLSDirectory=(IMAGE_TLS_DIRECTORY*)&bTLSSection[0];
		if(pTLSDirectory->AddressOfCallBacks!=0)
			return *(DWORD_PTR*)(&bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR));
	}
	return 0;
}

void CExport::Clear()
{
	sExportName.clear();
	Exports.clear();
}

void CExport::ReadFromFile(const CPEFile &File)
{
	Clear();
	if(File.RVA(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)==NULL)
		return;

	ExpHeader=*(IMAGE_EXPORT_DIRECTORY*)File.RVA(File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(ExpHeader.NumberOfFunctions==0)
		return;
	Exports.resize(ExpHeader.NumberOfFunctions);
	if(File.RVA(ExpHeader.Name)!=NULL)
		sExportName=(char*)File.RVA(ExpHeader.Name);

	for(DWORD i=0;i!=Exports.size();++i)
	{
		if(File.RVA(ExpHeader.AddressOfFunctions+i*sizeof(DWORD))!=NULL)
			Exports[i].dwFuncAddress=*(DWORD*)File.RVA(ExpHeader.AddressOfFunctions+i*sizeof(DWORD));
		else
			Exports[i].dwFuncAddress=0;
		Exports[i].sFuncName.clear();
		Exports[i].wFuncOrdinal=(WORD)(ExpHeader.Base+i);

		for(DWORD j=0;j!=ExpHeader.NumberOfNames;++j)
		{
			if(File.RVA(ExpHeader.AddressOfNameOrdinals+j*sizeof(WORD))!=NULL &&
				*(WORD*)File.RVA(ExpHeader.AddressOfNameOrdinals+j*sizeof(WORD))==i)
			{
				if(File.RVA(ExpHeader.AddressOfNames+j*sizeof(DWORD))!=NULL &&
					File.RVA(*(DWORD*)File.RVA(ExpHeader.AddressOfNames+j*sizeof(DWORD)))!=NULL)
					Exports[i].sFuncName=(char*)File.RVA(*(DWORD*)File.RVA(ExpHeader.AddressOfNames+j*sizeof(DWORD)));
				break;
			}
		}

		if(Exports[i].dwFuncAddress>File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			Exports[i].dwFuncAddress<File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+
			File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			if(File.RVA(Exports[i].dwFuncAddress)!=NULL)
				Exports[i].sForwardedName=(char*)File.RVA(Exports[i].dwFuncAddress);
			Exports[i].dwFuncAddress=0;
		}
	}
}

bool CompareExports(const CExport::CExportFunc &Export1,const CExport::CExportFunc &Export2)
{
	if(Export1.sFuncName!=Export2.sFuncName)
		return Export1.sFuncName<Export2.sFuncName;
	if(Export1.sForwardedName!=Export2.sForwardedName)
		return Export1.sForwardedName<Export2.sForwardedName;
	return Export1.dwFuncAddress<Export2.dwFuncAddress;
}

void CExport::SaveToFile(CPEFile &File)
{
	if(File.IsEmpty())
		return;
	if(Exports.empty())
	{
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress=0;
		File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size=0;
		return;
	}

	std::sort(Exports.begin(),Exports.end(),CompareExports);
	DWORD dwExportSize=sizeof(IMAGE_EXPORT_DIRECTORY)+(DWORD)Exports.size()*sizeof(DWORD);
	dwExportSize+=(DWORD)sExportName.length()+1;
	DWORD dwNumberOfStrings=0;
	for(size_t i=0;i!=Exports.size();++i)
	{
		if(!Exports[i].sFuncName.empty())
		{
			dwExportSize+=sizeof(DWORD)+sizeof(WORD);
			dwExportSize+=(DWORD)Exports[i].sFuncName.length()+1;
			++dwNumberOfStrings;
		}
		if(!Exports[i].sForwardedName.empty())
			dwExportSize+=(DWORD)Exports[i].sForwardedName.length()+1;
	}
	DWORD dwStrLen,dwRVA=File.pPEHeader->OptionalHeader.SizeOfImage;

	BYTE *bExportSection=new BYTE[dwExportSize];
	memset(bExportSection,0,dwExportSize);
	BYTE *bExportPosition=bExportSection+sizeof(IMAGE_EXPORT_DIRECTORY);
	BYTE *bStringPosition=bExportSection+sizeof(IMAGE_EXPORT_DIRECTORY)+Exports.size()*sizeof(DWORD)+dwNumberOfStrings*(sizeof(DWORD)+sizeof(WORD));

	if(sExportName.empty())
		ExpHeader.Name=0;
	else
	{
		dwStrLen=(DWORD)sExportName.length()+1;
		strcpy_s((char*)bStringPosition,dwStrLen,sExportName.c_str());
		bStringPosition+=dwStrLen;
		ExpHeader.Name=dwRVA+sizeof(IMAGE_EXPORT_DIRECTORY)+(DWORD)Exports.size()*sizeof(DWORD)+dwNumberOfStrings*(sizeof(DWORD)+sizeof(WORD));
	}
	ExpHeader.NumberOfFunctions=(DWORD)Exports.size();
	ExpHeader.NumberOfNames=dwNumberOfStrings;
	ExpHeader.AddressOfFunctions=dwRVA+sizeof(IMAGE_EXPORT_DIRECTORY);
	ExpHeader.AddressOfNames=dwRVA+sizeof(IMAGE_EXPORT_DIRECTORY)+(DWORD)Exports.size()*sizeof(DWORD);
	ExpHeader.AddressOfNameOrdinals=dwRVA+sizeof(IMAGE_EXPORT_DIRECTORY)+(DWORD)Exports.size()*sizeof(DWORD)+dwNumberOfStrings*sizeof(DWORD);
	*(IMAGE_EXPORT_DIRECTORY*)bExportSection=ExpHeader;

	for(size_t i=0;i!=Exports.size();++i)
	{
		if(Exports[i].sForwardedName.empty())
			*(DWORD*)(bExportPosition+(WORD)(Exports[i].wFuncOrdinal-ExpHeader.Base)*sizeof(DWORD))=Exports[i].dwFuncAddress;
		else
		{
			dwStrLen=(DWORD)Exports[i].sForwardedName.length()+1;
			strcpy_s((char*)bStringPosition,dwStrLen,Exports[i].sForwardedName.c_str());
			*(DWORD*)(bExportPosition+(WORD)(Exports[i].wFuncOrdinal-ExpHeader.Base)*sizeof(DWORD))=dwRVA+(DWORD)(bStringPosition-bExportSection);
			bStringPosition+=dwStrLen;
		}
	}
	bExportPosition+=Exports.size()*sizeof(DWORD);

	for(size_t i=0,j=0;i!=Exports.size();++i)
	{
		if(!Exports[i].sFuncName.empty())
		{
			dwStrLen=(DWORD)Exports[i].sFuncName.length()+1;
			strcpy_s((char*)bStringPosition,dwStrLen,Exports[i].sFuncName.c_str());
			*(DWORD*)bExportPosition=dwRVA+(DWORD)(bStringPosition-bExportSection);
			bStringPosition+=dwStrLen;

			*(WORD*)(bExportPosition+dwNumberOfStrings*sizeof(DWORD)-j*(sizeof(DWORD)-sizeof(WORD)))=(WORD)(Exports[i].wFuncOrdinal-ExpHeader.Base);
			bExportPosition+=sizeof(DWORD);
			++j;
		}
	}

	File.CreateSection(".edata",bExportSection,dwExportSize,IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress=dwRVA;
	File.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size=dwExportSize;

	delete[] bExportSection;
}

CPEFile::CPEFile()
{
	pMZHeader=NULL;
	pPEHeader=NULL;
	pSectionHeader=NULL;
	dwSectionsBegin=0;
	dwSectionsSize=0;
}

CPEFile::~CPEFile()
{
	Clear();
}

void CPEFile::Clear()
{
	if(!bHeader.empty())
	{
		for(DWORD i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
		{
			if(bSections[i]!=NULL)
			{
				delete[] bSections[i];
				bSections[i]=NULL;
			}
		}
		bHeader.clear();
	}
	bOverlay.clear();

	pMZHeader=NULL;
	pPEHeader=NULL;
	pSectionHeader=NULL;

	dwSectionsBegin=0;
	dwSectionsSize=0;
}

void CPEFile::Read(const TCHAR *szFileName)
{
	Clear();
	HANDLE hFile=CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
		return;

	DWORD dwBytesRead;
	IMAGE_DOS_HEADER MZHeaderTemp;
	IMAGE_NT_HEADERS PEHeaderTemp;
	ReadFile(hFile,&MZHeaderTemp,sizeof(MZHeaderTemp),&dwBytesRead,NULL);
	SetFilePointer(hFile,MZHeaderTemp.e_lfanew,NULL,FILE_BEGIN);
	ReadFile(hFile,&PEHeaderTemp,sizeof(PEHeaderTemp),&dwBytesRead,NULL);

	if(dwBytesRead!=sizeof(PEHeaderTemp) || MZHeaderTemp.e_magic!=IMAGE_DOS_SIGNATURE || PEHeaderTemp.Signature!=IMAGE_NT_SIGNATURE)
	{
		MessageBox(NULL,invalidpe,_T("QuickUnpack"),MB_OK);
		CloseHandle(hFile);
		return;
	}
#if defined _M_AMD64
	if(PEHeaderTemp.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 || PEHeaderTemp.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)
#elif defined _M_IX86
	if(PEHeaderTemp.FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 || PEHeaderTemp.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#else
!!!
#endif
	{
		MessageBox(NULL,_T("Wrong platform!"),_T("QuickUnpack"),MB_OK);
		CloseHandle(hFile);
		return;
	}
	if(PEHeaderTemp.FileHeader.NumberOfSections>MAX_SECTIONS)
	{
		MessageBox(NULL,_T("Too many sections!"),_T("QuickUnpack"),MB_OK);
		CloseHandle(hFile);
		return;
	}
	bHeader.resize(sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)+sizeof(IMAGE_SECTION_HEADER)*MAX_SECTIONS,0);

	SetFilePointer(hFile,0,NULL,FILE_BEGIN);
	ReadFile(hFile,&bHeader[0],sizeof(IMAGE_DOS_HEADER),&dwBytesRead,NULL);
	pMZHeader=(IMAGE_DOS_HEADER*)&bHeader[0];

	SetFilePointer(hFile,pMZHeader->e_lfanew,NULL,FILE_BEGIN);
	ReadFile(hFile,&bHeader[sizeof(IMAGE_DOS_HEADER)],sizeof(IMAGE_NT_HEADERS),&dwBytesRead,NULL);
	pPEHeader=(IMAGE_NT_HEADERS*)(&bHeader[sizeof(IMAGE_DOS_HEADER)]);

	SetFilePointer(hFile,pMZHeader->e_lfanew+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+pPEHeader->FileHeader.SizeOfOptionalHeader,NULL,FILE_BEGIN);
	ReadFile(hFile,&bHeader[sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)],sizeof(IMAGE_SECTION_HEADER)*pPEHeader->FileHeader.NumberOfSections,&dwBytesRead,NULL);
	pSectionHeader=(IMAGE_SECTION_HEADER*)(&bHeader[sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)]);

	DWORD dwFileSize=GetFileSize(hFile,NULL),dwFilePosition=(DWORD)bHeader.size();
	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(pSectionHeader[i].Misc.VirtualSize==0)
			pSectionHeader[i].Misc.VirtualSize=pSectionHeader[i].SizeOfRawData;
		if(pSectionHeader[i].SizeOfRawData==0)
			pSectionHeader[i].PointerToRawData=0;
		if(pSectionHeader[i].PointerToRawData==0)
			pSectionHeader[i].SizeOfRawData=0;
		if(pPEHeader->OptionalHeader.SectionAlignment>=PAGE_SIZE)
		{
			pSectionHeader[i].Misc.VirtualSize=(DWORD)AlignTo(pSectionHeader[i].Misc.VirtualSize,pPEHeader->OptionalHeader.SectionAlignment);
			DWORD dwAlignedRawPtr=(DWORD)CutTo(pSectionHeader[i].PointerToRawData,SECTOR_SIZE);
			pSectionHeader[i].SizeOfRawData=min((DWORD)AlignTo(pSectionHeader[i].PointerToRawData+pSectionHeader[i].SizeOfRawData,pPEHeader->OptionalHeader.FileAlignment)-dwAlignedRawPtr,(DWORD)AlignTo(pSectionHeader[i].SizeOfRawData,PAGE_SIZE));
			pSectionHeader[i].PointerToRawData=dwAlignedRawPtr;
		}
		if(pSectionHeader[i].SizeOfRawData>pSectionHeader[i].Misc.VirtualSize)
			pSectionHeader[i].SizeOfRawData=pSectionHeader[i].Misc.VirtualSize;
		if(pSectionHeader[i].SizeOfRawData>dwFileSize-pSectionHeader[i].PointerToRawData)
			pSectionHeader[i].SizeOfRawData=(DWORD)AlignTo(dwFileSize-pSectionHeader[i].PointerToRawData,pPEHeader->OptionalHeader.FileAlignment);

		bSections[i]=new BYTE[pSectionHeader[i].SizeOfRawData+4*sizeof(DWORD_PTR)];
		memset(bSections[i],0,pSectionHeader[i].SizeOfRawData+4*sizeof(DWORD_PTR));

		SetFilePointer(hFile,pSectionHeader[i].PointerToRawData,NULL,FILE_BEGIN);
		ReadFile(hFile,bSections[i],pSectionHeader[i].SizeOfRawData,&dwBytesRead,NULL);

		dwFilePosition=max(dwFilePosition,pSectionHeader[i].PointerToRawData+pSectionHeader[i].SizeOfRawData);
	}

	if(dwFileSize>dwFilePosition)
	{
		bOverlay.resize(dwFileSize-dwFilePosition);
		ReadFile(hFile,&bOverlay[0],(DWORD)bOverlay.size(),&dwBytesRead,NULL);
	}
	CloseHandle(hFile);
	ReBuild();
}

void CPEFile::Save(const TCHAR *szFileName)
{
	if(IsEmpty())
		return;

	pPEHeader->OptionalHeader.MajorLinkerVersion=7;
	pPEHeader->OptionalHeader.MinorLinkerVersion=0;
	pPEHeader->OptionalHeader.LoaderFlags=0;
	pPEHeader->OptionalHeader.MajorImageVersion=0;
	pPEHeader->OptionalHeader.MinorImageVersion=0;
	pPEHeader->OptionalHeader.Win32VersionValue=0;
	pPEHeader->OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	pPEHeader->FileHeader.TimeDateStamp=0;
	pPEHeader->FileHeader.NumberOfSymbols=0;
	pPEHeader->FileHeader.PointerToSymbolTable=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1].VirtualAddress=0;
	pPEHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1].Size=0;

	ReBuild();

	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,".edata");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,".idata");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,".pdata");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,".reloc");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress,".debug");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,".tls");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress,".cormeta");
	RenameSection(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,".rsrc");

	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(pSectionHeader[i].Name[0]=='\0')
		{
			memset(pSectionHeader[i].Name,0,sizeof(pSectionHeader[0].Name));
			if(pSectionHeader[i].Characteristics==(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_UNINITIALIZED_DATA))
				sprintf_s((char*)pSectionHeader[i].Name,_countof(pSectionHeader[0].Name),".bss");
			else if(pSectionHeader[i].Characteristics==(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA))
				sprintf_s((char*)pSectionHeader[i].Name,_countof(pSectionHeader[0].Name),".data");
			else if(pSectionHeader[i].Characteristics==(IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA))
				sprintf_s((char*)pSectionHeader[i].Name,_countof(pSectionHeader[0].Name),".rdata");
			else if((pSectionHeader[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))==(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
				sprintf_s((char*)pSectionHeader[i].Name,_countof(pSectionHeader[0].Name),".text");
			else
				sprintf_s((char*)pSectionHeader[i].Name,_countof(pSectionHeader[0].Name),".sect%02d",i+1);
		}
	}

	DWORD dwnHeaderSize=(DWORD)AlignTo(sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)+sizeof(IMAGE_SECTION_HEADER)*pPEHeader->FileHeader.NumberOfSections,pPEHeader->OptionalHeader.FileAlignment);

	DWORD dwPhysOffset=dwnHeaderSize;
	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
	{
		pSectionHeader[i].PointerToRawData=dwPhysOffset;
		if(bSections[i]==NULL)
		{
			pSectionHeader[i].PointerToRawData=0;
			pSectionHeader[i].SizeOfRawData=0;
		}
		dwPhysOffset+=pSectionHeader[i].SizeOfRawData;
	}
	pPEHeader->OptionalHeader.SizeOfHeaders=dwnHeaderSize;

	BYTE *bnHeader=new BYTE[dwnHeaderSize];
	memset(bnHeader,0,dwnHeaderSize);

	IMAGE_DOS_HEADER *pnMZHeader=(IMAGE_DOS_HEADER*)bnHeader;
	pnMZHeader->e_magic=IMAGE_DOS_SIGNATURE;
	pnMZHeader->e_cblp='F';
	pnMZHeader->e_cp='I';
	pnMZHeader->e_cparhdr=sizeof(IMAGE_DOS_HEADER)/BYTES_IN_PARAGRAPH;
	pnMZHeader->e_ss='R';
	pnMZHeader->e_sp='E';
	pnMZHeader->e_lfanew=sizeof(IMAGE_DOS_HEADER);

	IMAGE_NT_HEADERS *pnPEHeader=(IMAGE_NT_HEADERS*)(bnHeader+pnMZHeader->e_lfanew);
	*pnPEHeader=*pPEHeader;

	IMAGE_SECTION_HEADER *pnSectionHeader=IMAGE_FIRST_SECTION(pnPEHeader);
	memcpy(pnSectionHeader,pSectionHeader,sizeof(IMAGE_SECTION_HEADER)*pnPEHeader->FileHeader.NumberOfSections);

	HANDLE hFile=CreateFile(szFileName,GENERIC_READ | GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);

	DWORD dwBytesWritten;
	WriteFile(hFile,bnHeader,dwnHeaderSize,&dwBytesWritten,NULL);

	for(int i=0;i!=pnPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(bSections[i]!=NULL)
			WriteFile(hFile,bSections[i],pnSectionHeader[i].SizeOfRawData,&dwBytesWritten,NULL);
	}
	delete[] bnHeader;

	if(!bOverlay.empty())
		WriteFile(hFile,&bOverlay[0],(DWORD)bOverlay.size(),&dwBytesWritten,NULL);

	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);
	BYTE *bBase=(BYTE*)MapViewOfFile(hMapping,FILE_MAP_READ | FILE_MAP_WRITE,0,0,0);
	DWORD dwSize=GetFileSize(hFile,NULL);

	if(bBase!=NULL)
	{
		DWORD dwHeaderSum;
		IMAGE_NT_HEADERS *pINTH=(IMAGE_NT_HEADERS*)(bBase+((IMAGE_DOS_HEADER*)bBase)->e_lfanew);
		CheckSumMappedFile(bBase,dwSize,&dwHeaderSum,&pINTH->OptionalHeader.CheckSum);
	}
	UnmapViewOfFile(bBase);
	CloseHandle(hMapping);

	//01.01.1980, else stupid delphi sees file as non-existent
	const FILETIME DefaultTime={0xe1d58000,0x01a8e79f};
	SetFileTime(hFile,&DefaultTime,&DefaultTime,&DefaultTime);
	CloseHandle(hFile);
}

void CPEFile::Dump(HANDLE hProcess,DWORD_PTR ModuleBase,const CPEFile *pFileOnDisk,ECutSectionsType TruncateSections)
{
	if(IsProcessDying(hProcess))
		return;

	Clear();

	bHeader.resize(sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)+sizeof(IMAGE_SECTION_HEADER)*MAX_SECTIONS,0);
	pMZHeader=(IMAGE_DOS_HEADER*)&bHeader[0];
	pPEHeader=(IMAGE_NT_HEADERS*)(&bHeader[0]+sizeof(IMAGE_DOS_HEADER));

	IMAGE_DOS_HEADER TempMZHeader;
	ReadMem(hProcess,ModuleBase,&TempMZHeader,sizeof(TempMZHeader));
	if(TempMZHeader.e_magic!=IMAGE_DOS_SIGNATURE)
		return;
	IMAGE_NT_HEADERS TempPEHeader;
	ReadMem(hProcess,ModuleBase+TempMZHeader.e_lfanew,&TempPEHeader,sizeof(TempPEHeader));
	if(TempPEHeader.Signature!=IMAGE_NT_SIGNATURE)
		return;
	if(pFileOnDisk==NULL || pFileOnDisk->IsEmpty())
	{
		*pMZHeader=TempMZHeader;
		*pPEHeader=TempPEHeader;
	}
	else
	{
		*pMZHeader=*pFileOnDisk->pMZHeader;
		if(pMain!=NULL && pMain->PageLastUsed!=0 && TruncateSections==csMemoryManager)
			pFileOnDisk->pPEHeader->OptionalHeader.SizeOfImage+=(DWORD)(pMain->PageLastUsed-pMain->PagesAllocked-PAGE_SIZE*PAGES_COUNT);
		*pPEHeader=*pFileOnDisk->pPEHeader;

		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]=TempPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]=TempPEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	}
	pMZHeader->e_lfanew=sizeof(IMAGE_DOS_HEADER);
	pPEHeader->FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER);
	pPEHeader->OptionalHeader.SectionAlignment=PAGE_SIZE;
	pPEHeader->OptionalHeader.FileAlignment=SECTOR_SIZE;

	pSectionHeader=IMAGE_FIRST_SECTION(pPEHeader);

	DWORD dwOldProtect,dwSize,i=0;
	DWORD_PTR OldBase,Current;
	if(AlignTo(pPEHeader->OptionalHeader.SizeOfHeaders,pPEHeader->OptionalHeader.SectionAlignment)>AlignTo(PAGE_SIZE_STATIC,pPEHeader->OptionalHeader.SectionAlignment))
	{
		bSections[i]=NULL;
		memset(pSectionHeader[i].Name,0,sizeof(pSectionHeader[0].Name));
		sprintf_s((char*)pSectionHeader[i].Name,_countof(pSectionHeader[0].Name),".empty");
		pSectionHeader[i].Misc.VirtualSize=(DWORD)AlignTo(AlignTo(pPEHeader->OptionalHeader.SizeOfHeaders,pPEHeader->OptionalHeader.SectionAlignment)-AlignTo(PAGE_SIZE_STATIC,pPEHeader->OptionalHeader.SectionAlignment),pPEHeader->OptionalHeader.SectionAlignment);
		pSectionHeader[i].VirtualAddress=(DWORD)AlignTo(PAGE_SIZE_STATIC,pPEHeader->OptionalHeader.SectionAlignment);
		pSectionHeader[i].SizeOfRawData=0;
		pSectionHeader[i].Characteristics=0;
		++i;

		Current=ModuleBase+AlignTo(pPEHeader->OptionalHeader.SizeOfHeaders,pPEHeader->OptionalHeader.SectionAlignment);
		pPEHeader->OptionalHeader.SizeOfHeaders=(DWORD)AlignTo(PAGE_SIZE_STATIC,pPEHeader->OptionalHeader.FileAlignment);
	}
	else
		Current=ModuleBase+AlignTo(pPEHeader->OptionalHeader.SizeOfHeaders,pPEHeader->OptionalHeader.SectionAlignment);

	MEMORY_BASIC_INFORMATION MemInfo;
	VirtualQueryEx(hProcess,(void*)Current,&MemInfo,sizeof(MemInfo));
	MemInfo.Protect&=0xff;
	if(MemInfo.Protect==PAGE_EXECUTE_WRITECOPY)
		MemInfo.Protect=PAGE_EXECUTE_READWRITE;
	else if(MemInfo.Protect==PAGE_WRITECOPY)
		MemInfo.Protect=PAGE_READWRITE;
	OldBase=Current;
	dwOldProtect=MemInfo.Protect;
	Current+=MemInfo.RegionSize;
	if(pFileOnDisk==NULL || pFileOnDisk->IsEmpty())
		dwSize=pPEHeader->OptionalHeader.SizeOfImage;
	else
		dwSize=pFileOnDisk->pPEHeader->OptionalHeader.SizeOfImage;

	DWORD dwCutAt=0;
	if(pMain!=NULL)
		dwCutAt=pMain->pInitData->dwCutModule;
	dwCutAt=(DWORD)AlignTo(dwCutAt,pPEHeader->OptionalHeader.SectionAlignment);
	for(;;)
	{
		VirtualQueryEx(hProcess,(void*)Current,&MemInfo,sizeof(MemInfo));
		MemInfo.Protect&=0xff;
		if(MemInfo.Protect==PAGE_EXECUTE_WRITECOPY)
			MemInfo.Protect=PAGE_EXECUTE_READWRITE;
		else if(MemInfo.Protect==PAGE_WRITECOPY)
			MemInfo.Protect=PAGE_READWRITE;
		if(MemInfo.Protect!=dwOldProtect || Current-ModuleBase>=dwSize ||
			(dwCutAt>OldBase-ModuleBase && Current-ModuleBase>=dwCutAt))
		{
			if(Current-ModuleBase>=dwSize)
			{
				Current=ModuleBase+dwSize;
				if(Current<OldBase)
					break;
			}
			if(dwCutAt>OldBase-ModuleBase && Current-ModuleBase>=dwCutAt)
			{
				if(Current-ModuleBase>dwCutAt)
					MemInfo.RegionSize=Current-ModuleBase-dwCutAt;
				Current=ModuleBase+dwCutAt;
			}
			if(Current>OldBase)
			{
				if(pMain!=NULL && pMain->PageLastUsed!=0 && TruncateSections==csMemoryManager && OldBase>=pMain->PagesAllocked)
				{
					Current=pMain->PageLastUsed;
					dwOldProtect=PAGE_EXECUTE_READWRITE;
				}
				do
				{
					__try
					{
						bSections[i]=new BYTE[AlignTo(Current-OldBase,pPEHeader->OptionalHeader.SectionAlignment)];
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						bSections[i]=NULL;
					}
					if(bSections[i]==NULL)
					{
						MemInfo.RegionSize+=AlignTo((Current-OldBase)/2,pPEHeader->OptionalHeader.SectionAlignment);
						Current-=AlignTo((Current-OldBase)/2,pPEHeader->OptionalHeader.SectionAlignment);
					}
				}
				while(bSections[i]==NULL);
				pSectionHeader[i].Misc.VirtualSize=(DWORD)AlignTo(Current-OldBase,pPEHeader->OptionalHeader.SectionAlignment);
				pSectionHeader[i].VirtualAddress=(DWORD)(OldBase-ModuleBase);
				memset(pSectionHeader[i].Name,0,sizeof(pSectionHeader[0].Name));
				memset(bSections[i],0,pSectionHeader[i].Misc.VirtualSize);
				ReadMem(hProcess,OldBase,bSections[i],pSectionHeader[i].Misc.VirtualSize);

				if(TruncateSections!=csNone)
				{
					if(pSectionHeader[i].Misc.VirtualSize>=ZEROFIND_MINSECT)
					{
						bool fInHole=false;
						DWORD dwHoleOffset=0,dwHoleSize=0,dwTempHoleOffset=0,dwTempHoleSize=0;
						for(DWORD l=0;l<pSectionHeader[i].Misc.VirtualSize;l+=sizeof(DWORD_PTR))
						{
							if(*(DWORD_PTR*)(bSections[i]+l)==0)
							{
								if(fInHole)
									dwTempHoleSize+=sizeof(DWORD_PTR);
								else
								{
									fInHole=true;
									dwTempHoleOffset=l;
									dwTempHoleSize=sizeof(DWORD_PTR);
								}
							}
							else
							{
								if(fInHole && dwHoleSize<dwTempHoleSize)
								{
									dwHoleOffset=dwTempHoleOffset;
									dwHoleSize=dwTempHoleSize;
								}
								fInHole=false;
							}
						}

						if(dwHoleSize>=ZEROFIND_MINZEROS)
						{
							MemInfo.RegionSize+=AlignTo(pSectionHeader[i].Misc.VirtualSize-dwHoleOffset-dwHoleSize,pPEHeader->OptionalHeader.SectionAlignment);
							Current-=AlignTo(pSectionHeader[i].Misc.VirtualSize-dwHoleOffset-dwHoleSize,pPEHeader->OptionalHeader.SectionAlignment);
							pSectionHeader[i].Misc.VirtualSize=(DWORD)AlignTo(Current-OldBase,pPEHeader->OptionalHeader.SectionAlignment);

							delete[] bSections[i];
							bSections[i]=new BYTE[pSectionHeader[i].Misc.VirtualSize];
							memset(bSections[i],0,pSectionHeader[i].Misc.VirtualSize);
							ReadMem(hProcess,OldBase,bSections[i],pSectionHeader[i].Misc.VirtualSize);
						}
					}

					int m=pSectionHeader[i].Misc.VirtualSize-sizeof(DWORD_PTR);
					while(m>=0 && *(DWORD_PTR*)(bSections[i]+m)==0)
						m-=sizeof(DWORD_PTR);
					pSectionHeader[i].SizeOfRawData=(DWORD)AlignTo(m+sizeof(DWORD_PTR),pPEHeader->OptionalHeader.FileAlignment);
					if(pSectionHeader[i].SizeOfRawData<pSectionHeader[i].Misc.VirtualSize)
					{
						delete[] bSections[i];
						if(pSectionHeader[i].SizeOfRawData!=0)
						{
							bSections[i]=new BYTE[pSectionHeader[i].SizeOfRawData];
							memset(bSections[i],0,pSectionHeader[i].SizeOfRawData);
							ReadMem(hProcess,OldBase,bSections[i],pSectionHeader[i].SizeOfRawData);
						}
						else
							bSections[i]=NULL;
					}
				}
				else
					pSectionHeader[i].SizeOfRawData=pSectionHeader[i].Misc.VirtualSize;

				if(dwOldProtect==PAGE_EXECUTE)
					pSectionHeader[i].Characteristics=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
				else if(dwOldProtect==PAGE_EXECUTE_READ)
					pSectionHeader[i].Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
				else if(dwOldProtect==PAGE_EXECUTE_READWRITE || dwOldProtect==PAGE_NOACCESS)
					pSectionHeader[i].Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
				else if(dwOldProtect==PAGE_READONLY)
					pSectionHeader[i].Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
				else if(dwOldProtect==PAGE_READWRITE)
				{
					if(pSectionHeader[i].SizeOfRawData==0)
						pSectionHeader[i].Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_UNINITIALIZED_DATA;
					else
						pSectionHeader[i].Characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
				}

				++i;
				if(i>MAX_SECTIONS)
				{
					if(pMain!=NULL)
						pMain->Terminate();
					MessageBox(NULL,_T("Sections number exceeded maximum!"),_T("QuickUnpack"),MB_OK);
					return;
				}
				if(Current-ModuleBase>=dwSize)
					break;
				OldBase=Current;
				dwOldProtect=MemInfo.Protect;
			}
		}
		Current+=MemInfo.RegionSize;
	}
	pPEHeader->FileHeader.NumberOfSections=(WORD)i;
	ReBuild();
}

bool CPEFile::IsEmpty() const
{
	return pPEHeader==NULL;
}

void CPEFile::CreateEmpty()
{
	Clear();

	IMAGE_DOS_HEADER *pMZHTemp=(IMAGE_DOS_HEADER*)GetModuleHandle(NULL);
	IMAGE_NT_HEADERS *pPEHTemp=(IMAGE_NT_HEADERS*)((DWORD_PTR)pMZHTemp+pMZHTemp->e_lfanew);

	bHeader.resize(sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS)+sizeof(IMAGE_SECTION_HEADER)*MAX_SECTIONS,0);

	pMZHeader=(IMAGE_DOS_HEADER*)&bHeader[0];
	*pMZHeader=*pMZHTemp;
	pMZHeader->e_lfanew=sizeof(IMAGE_DOS_HEADER);
	pPEHeader=(IMAGE_NT_HEADERS*)(&bHeader[0]+pMZHeader->e_lfanew);
	*pPEHeader=*pPEHTemp;
	pSectionHeader=IMAGE_FIRST_SECTION(pPEHeader);

	pPEHeader->FileHeader.NumberOfSections=0;
	pPEHeader->FileHeader.TimeDateStamp=0;
	pPEHeader->FileHeader.PointerToSymbolTable=0;
	pPEHeader->FileHeader.NumberOfSymbols=0;
	pPEHeader->FileHeader.Characteristics|=IMAGE_FILE_RELOCS_STRIPPED;
	pPEHeader->OptionalHeader.MajorLinkerVersion=7;
	pPEHeader->OptionalHeader.MinorLinkerVersion=0;
	pPEHeader->OptionalHeader.SizeOfCode=0;
	pPEHeader->OptionalHeader.SizeOfInitializedData=0;
	pPEHeader->OptionalHeader.SizeOfUninitializedData=0;
	pPEHeader->OptionalHeader.AddressOfEntryPoint=0;
	pPEHeader->OptionalHeader.BaseOfCode=0;
#if defined _M_IX86
	pPEHeader->OptionalHeader.BaseOfData=0;
#endif
	pPEHeader->OptionalHeader.ImageBase=0;
	pPEHeader->OptionalHeader.SectionAlignment=PAGE_SIZE;
	pPEHeader->OptionalHeader.FileAlignment=SECTOR_SIZE;
#if defined _M_AMD64
	pPEHeader->OptionalHeader.MajorOperatingSystemVersion=5;
	pPEHeader->OptionalHeader.MinorOperatingSystemVersion=2;
	pPEHeader->OptionalHeader.MajorSubsystemVersion=5;
	pPEHeader->OptionalHeader.MinorSubsystemVersion=2;
#elif defined _M_IX86
	pPEHeader->OptionalHeader.MajorOperatingSystemVersion=4;
	pPEHeader->OptionalHeader.MinorOperatingSystemVersion=0;
	pPEHeader->OptionalHeader.MajorSubsystemVersion=4;
	pPEHeader->OptionalHeader.MinorSubsystemVersion=0;
#else
!!!
#endif
	pPEHeader->OptionalHeader.MajorImageVersion=0;
	pPEHeader->OptionalHeader.MinorImageVersion=0;
	pPEHeader->OptionalHeader.Win32VersionValue=0;
	pPEHeader->OptionalHeader.SizeOfImage=0;
	pPEHeader->OptionalHeader.CheckSum=0;
	pPEHeader->OptionalHeader.DllCharacteristics&=~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	pPEHeader->OptionalHeader.SizeOfStackReserve=0;
	pPEHeader->OptionalHeader.SizeOfStackCommit=0;
	pPEHeader->OptionalHeader.SizeOfHeapReserve=0;
	pPEHeader->OptionalHeader.SizeOfHeapCommit=0;
	pPEHeader->OptionalHeader.LoaderFlags=0;
	pPEHeader->OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	memset(pPEHeader->OptionalHeader.DataDirectory,0,sizeof(pPEHeader->OptionalHeader.DataDirectory));

	dwSectionsBegin=PAGE_SIZE;
	dwSectionsSize=0;
}

void CPEFile::CreateSection(const char *szName,const BYTE *bBody,DWORD dwSize,DWORD dwchars)
{
	if(IsEmpty())
		return;

	if(pPEHeader->FileHeader.NumberOfSections>=MAX_SECTIONS)
	{
		pMain->Terminate();
		MessageBox(NULL,_T("Too many sections!"),_T("QuickUnpack"),MB_OK);
		return;
	}

	DWORD dwVirtualSize=(DWORD)AlignTo(dwSize,pPEHeader->OptionalHeader.SectionAlignment);
	int n=pPEHeader->FileHeader.NumberOfSections;

	memset(pSectionHeader[n].Name,0,sizeof(pSectionHeader[0].Name));
	memcpy(pSectionHeader[n].Name,szName,min(sizeof(pSectionHeader[0].Name),strlen(szName)*sizeof(szName[0])));
	pSectionHeader[n].VirtualAddress=dwSectionsBegin+dwSectionsSize;
	pSectionHeader[n].Misc.VirtualSize=dwVirtualSize;
	pSectionHeader[n].SizeOfRawData=(DWORD)AlignTo(dwSize,pPEHeader->OptionalHeader.FileAlignment);

	pSectionHeader[n].Characteristics=dwchars;
	bSections[n]=NULL;

	if(bBody!=NULL)
	{
		bSections[n]=new BYTE[dwVirtualSize];
		memset(bSections[n],0,dwVirtualSize);
		memcpy(bSections[n],bBody,dwSize);
	}
	dwSectionsSize+=pSectionHeader[n].Misc.VirtualSize;

	++pPEHeader->FileHeader.NumberOfSections;
	pPEHeader->OptionalHeader.SizeOfImage=(DWORD)AlignTo(dwSectionsBegin+dwSectionsSize,pPEHeader->OptionalHeader.SectionAlignment);
}

void CPEFile::DeleteLastSection()
{
	if(IsEmpty() || pPEHeader->FileHeader.NumberOfSections==0)
		return;

	int n=pPEHeader->FileHeader.NumberOfSections-1;
	if(bSections[n]!=NULL)
	{
		delete[] bSections[n];
		bSections[n]=NULL;
	}
	dwSectionsSize-=pSectionHeader[n].Misc.VirtualSize;

	--pPEHeader->FileHeader.NumberOfSections;
	pPEHeader->OptionalHeader.SizeOfImage=(DWORD)AlignTo(dwSectionsBegin+dwSectionsSize,pPEHeader->OptionalHeader.SectionAlignment);
}

void CPEFile::ClearSection(int i)
{
	memset(bSections[i],0,pSectionHeader[i].SizeOfRawData);
}

int CPEFile::GetSectionNumber(DWORD dwRVA) const
{
	if(!bHeader.empty() && dwRVA>=dwSectionsBegin && dwRVA<dwSectionsBegin+dwSectionsSize)
	{
		for(int n=0;n!=pPEHeader->FileHeader.NumberOfSections;++n)
		{
			if(dwRVA>=pSectionHeader[n].VirtualAddress && dwRVA<(pSectionHeader[n].VirtualAddress+pSectionHeader[n].SizeOfRawData))
				return n;
		}
	}
	return -1;
}

std::string CPEFile::GetSectionName(DWORD dwRVA) const
{
	int n=GetSectionNumber(dwRVA);
	if(n!=-1 && pSectionHeader[n].Name[0]!='\0')
	{
		char cName[_countof(pSectionHeader[0].Name)+1];
		memset(cName,0,sizeof(cName));
		memcpy(cName,pSectionHeader[n].Name,sizeof(pSectionHeader[0].Name));

		return cName;
	}
	return "";
}

void CPEFile::RenameSection(DWORD dwRVA,const char *szName)
{
	int n=GetSectionNumber(dwRVA);
	if(n!=-1)
	{
		memset(pSectionHeader[n].Name,0,sizeof(pSectionHeader[0].Name));
		memcpy(pSectionHeader[n].Name,szName,min(sizeof(pSectionHeader[0].Name),strlen(szName)*sizeof(szName[0])));
	}
}

void CPEFile::SetSectionWritable(DWORD dwRvaInSection)
{
	int nSectNumber=GetSectionNumber(dwRvaInSection);
	if(nSectNumber!=-1)
		pSectionHeader[nSectNumber].Characteristics|=IMAGE_SCN_MEM_WRITE;
}

bool CompareSections(const IMAGE_SECTION_HEADER &Section1,const IMAGE_SECTION_HEADER &Section2)
{
	return Section1.VirtualAddress<Section2.VirtualAddress;
}

void CPEFile::ReBuild()
{
	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
	{
		pSectionHeader[i].Misc.VirtualSize=(DWORD)AlignTo(pSectionHeader[i].Misc.VirtualSize,pPEHeader->OptionalHeader.SectionAlignment);
		pSectionHeader[i].SizeOfRawData=(DWORD)AlignTo(pSectionHeader[i].SizeOfRawData,pPEHeader->OptionalHeader.FileAlignment);
		pSectionHeader[i].PointerToRawData=(DWORD)CutTo(pSectionHeader[i].PointerToRawData,SECTOR_SIZE);
		if(pSectionHeader[i].SizeOfRawData>pSectionHeader[i].Misc.VirtualSize)
			pSectionHeader[i].SizeOfRawData=pSectionHeader[i].Misc.VirtualSize;
	}
	std::sort(pSectionHeader,pSectionHeader+pPEHeader->FileHeader.NumberOfSections,CompareSections);

	DWORD dwOSVersion=(pPEHeader->OptionalHeader.MajorOperatingSystemVersion << 16) | pPEHeader->OptionalHeader.MinorOperatingSystemVersion;
	DWORD dwSubsystemVersion=(pPEHeader->OptionalHeader.MajorSubsystemVersion << 16) | pPEHeader->OptionalHeader.MinorSubsystemVersion;
	pPEHeader->Signature=IMAGE_NT_SIGNATURE;
#if defined _M_AMD64
	pPEHeader->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
	pPEHeader->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	dwOSVersion=max(dwOSVersion,0x0502);
	dwSubsystemVersion=max(dwSubsystemVersion,0x0502);
#elif defined _M_IX86
	pPEHeader->FileHeader.Machine=IMAGE_FILE_MACHINE_I386;
	pPEHeader->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	dwOSVersion=max(dwOSVersion,0x0400);
	dwSubsystemVersion=max(dwSubsystemVersion,0x0400);
#else
!!!
#endif
	pPEHeader->OptionalHeader.MajorOperatingSystemVersion=dwOSVersion >> 16;
	pPEHeader->OptionalHeader.MinorOperatingSystemVersion=dwOSVersion & MAXWORD;
	pPEHeader->OptionalHeader.MajorSubsystemVersion=dwSubsystemVersion >> 16;
	pPEHeader->OptionalHeader.MinorSubsystemVersion=dwSubsystemVersion & MAXWORD;

	pPEHeader->OptionalHeader.SizeOfHeaders=(DWORD)AlignTo(pPEHeader->OptionalHeader.SizeOfHeaders,pPEHeader->OptionalHeader.FileAlignment);
	dwSectionsBegin=(DWORD)AlignTo(pPEHeader->OptionalHeader.SizeOfHeaders,pPEHeader->OptionalHeader.SectionAlignment);
	pPEHeader->OptionalHeader.SizeOfImage=dwSectionsBegin;
	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
		pPEHeader->OptionalHeader.SizeOfImage+=pSectionHeader[i].Misc.VirtualSize;
	dwSectionsSize=pPEHeader->OptionalHeader.SizeOfImage-dwSectionsBegin;

#if defined _M_IX86
	pPEHeader->OptionalHeader.BaseOfData=0;
#endif
	pPEHeader->OptionalHeader.SizeOfInitializedData=0;
	pPEHeader->OptionalHeader.SizeOfUninitializedData=0;
	pPEHeader->OptionalHeader.BaseOfCode=0;
	pPEHeader->OptionalHeader.SizeOfCode=0;
	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if((pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE)==IMAGE_SCN_CNT_CODE)
		{
			if(pPEHeader->OptionalHeader.BaseOfCode==0)
				pPEHeader->OptionalHeader.BaseOfCode=pSectionHeader[i].VirtualAddress;
			pPEHeader->OptionalHeader.SizeOfCode+=pSectionHeader[i].Misc.VirtualSize;
		}
		if((pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)==IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		{
#if defined _M_IX86
			if(pPEHeader->OptionalHeader.BaseOfData==0)
				pPEHeader->OptionalHeader.BaseOfData=pSectionHeader[i].VirtualAddress;
#endif
			pPEHeader->OptionalHeader.SizeOfUninitializedData+=pSectionHeader[i].Misc.VirtualSize;
		}
		if((pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)==IMAGE_SCN_CNT_INITIALIZED_DATA)
		{
#if defined _M_IX86
			if(pPEHeader->OptionalHeader.BaseOfData==0)
				pPEHeader->OptionalHeader.BaseOfData=pSectionHeader[i].VirtualAddress;
#endif
			pPEHeader->OptionalHeader.SizeOfInitializedData+=pSectionHeader[i].Misc.VirtualSize;
		}
	}

	for(DWORD k=pPEHeader->OptionalHeader.NumberOfRvaAndSizes;k<IMAGE_NUMBEROF_DIRECTORY_ENTRIES;++k)
	{
		pPEHeader->OptionalHeader.DataDirectory[k].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[k].Size=0;
	}

	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size=0;
	}
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress>dwSectionsBegin+dwSectionsSize)
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size=0;
	}

	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress==0 &&
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size==0)
	{
#if defined _M_AMD64
		if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress!=0)
#endif
		{
			pPEHeader->FileHeader.Characteristics|=IMAGE_FILE_RELOCS_STRIPPED;
			pPEHeader->OptionalHeader.DllCharacteristics&=~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}
	}
	else
		pPEHeader->FileHeader.Characteristics&=~IMAGE_FILE_RELOCS_STRIPPED;
	if(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress==0 &&
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size==0)
		pPEHeader->OptionalHeader.DllCharacteristics&=~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
}

void CPEFile::ProcessExport()
{
	if(IsEmpty() ||
		(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress>=pPEHeader->OptionalHeader.SizeOfHeaders &&
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size<pPEHeader->OptionalHeader.SizeOfImage))
		return;

	CExport ExportDir;
	ExportDir.ReadFromFile(pMain->VictimFile);
	ExportDir.SaveToFile(*this);
}

void CPEFile::ProcessTLS()
{
	if(IsEmpty() ||
		(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress>=pPEHeader->OptionalHeader.SizeOfHeaders &&
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress+pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size<pPEHeader->OptionalHeader.SizeOfImage))
		return;

	CTLS TlsDir;
	DWORD dwTLSBase=pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	if(dwTLSBase!=0)
	{
		IMAGE_TLS_DIRECTORY TLSDirectory;
		pMain->ReadMem(pMain->VictimBase+dwTLSBase,&TLSDirectory,sizeof(TLSDirectory));

		int nSize=0;
		if(TLSDirectory.AddressOfCallBacks!=0)
		{
			DWORD_PTR TempCallback;
			while(pMain->ReadMem(TLSDirectory.AddressOfCallBacks+nSize,&TempCallback,sizeof(TempCallback))==sizeof(TempCallback) &&
				TempCallback!=0)
					nSize+=sizeof(DWORD_PTR);
			nSize+=sizeof(DWORD_PTR);
		}
		else
			TLSDirectory.AddressOfCallBacks=0;

		TlsDir.bTLSSection.resize(sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR)+nSize+TLSDirectory.EndAddressOfRawData-TLSDirectory.StartAddressOfRawData);
		pMain->ReadMem(TLSDirectory.AddressOfCallBacks,&TlsDir.bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR),nSize);

		if(TLSDirectory.StartAddressOfRawData!=0)
			pMain->ReadMem(TLSDirectory.StartAddressOfRawData,&TlsDir.bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR)+nSize,
				TLSDirectory.EndAddressOfRawData-TLSDirectory.StartAddressOfRawData);
		else
			memset(&TlsDir.bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY)+sizeof(DWORD_PTR)+nSize,0,
				TLSDirectory.EndAddressOfRawData-TLSDirectory.StartAddressOfRawData);
		if(TLSDirectory.AddressOfIndex!=0)
			pMain->ReadMem(TLSDirectory.AddressOfIndex,&TlsDir.bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY),sizeof(DWORD_PTR));
		else
			memset(&TlsDir.bTLSSection[0]+sizeof(IMAGE_TLS_DIRECTORY),0,sizeof(DWORD_PTR));
		memcpy(&TlsDir.bTLSSection[0],&TLSDirectory,sizeof(TLSDirectory));
	}
	TlsDir.SaveToFile(*this,false);
}

void CPEFile::AddResourceDelta(DWORD dwDirRVA,DWORD dwResourceBase,DWORD dwResHeadersSize)
{
	if(RVA(dwDirRVA)==NULL)
		return;

	IMAGE_RESOURCE_DIRECTORY *pResDir=(IMAGE_RESOURCE_DIRECTORY*)RVA(dwDirRVA);
	IMAGE_RESOURCE_DIRECTORY_ENTRY *pResEntry=(IMAGE_RESOURCE_DIRECTORY_ENTRY*)(RVA(dwDirRVA)+sizeof(IMAGE_RESOURCE_DIRECTORY));
	for(int i=0;i!=pResDir->NumberOfIdEntries+pResDir->NumberOfNamedEntries;++i)
	{
		if(pResEntry[i].NameIsString!=0)
			pResEntry[i].NameOffset+=dwResHeadersSize;

		if(pResEntry[i].DataIsDirectory!=0)
			AddResourceDelta(dwResourceBase+pResEntry[i].OffsetToDirectory,dwResourceBase,dwResHeadersSize);
		else
		{
			IMAGE_RESOURCE_DATA_ENTRY *pResDataEntry=(IMAGE_RESOURCE_DATA_ENTRY*)RVA(dwResourceBase+pResEntry[i].OffsetToData);
			pResDataEntry->OffsetToData+=dwResHeadersSize+dwResourceBase;
		}
	}
}

void CPEFile::AlignRes(std::vector<BYTE> &bRes,DWORD dwAlignment)
{
	bRes.resize(AlignTo(bRes.size(),dwAlignment),0);
}

bool CPEFile::AddRes(std::vector<BYTE> &bRes,DWORD dwRVA,DWORD dwSize)
{
	DWORD dwResSize=(DWORD)bRes.size();
	__try
	{
		if(dwSize>=MAXLONG || dwResSize+dwSize>=MAXLONG)
		{
			bRes.resize(dwResSize+sizeof(DWORD),0);
			return false;
		}
		else
		{
			bRes.resize(dwResSize+dwSize);
			DWORD_PTR ReadBytes=pMain->ReadMem(pMain->VictimBase+dwRVA,&bRes[0]+dwResSize,dwSize);
			if(ReadBytes!=dwSize)
			{
				bRes.resize(dwResSize+ReadBytes);
				return false;
			}
			return true;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		bRes.resize(dwResSize+sizeof(DWORD),0);
		return false;
	}
}

DWORD CPEFile::AddResource(std::vector<BYTE> &bRes,DWORD dwRVA,DWORD dwSize)
{
	DWORD dwResSize=(DWORD)bRes.size();
	if(!AddRes(bRes,dwRVA,dwSize))
		WriteEx(_T("Something is wrong with resources!"),TRUE,TRUE,RGB(255,0,0));
	return dwResSize;
}

DWORD CPEFile::RipResources(DWORD dwDirRVA,DWORD dwResourceBase,std::vector<BYTE> &bResHeaders,std::vector<BYTE> &bResources)
{
	if(IsProcessDying(pMain->hVictim))
		return 0;

	IMAGE_RESOURCE_DIRECTORY ResDir;
	pMain->ReadMem(pMain->VictimBase+dwDirRVA,&ResDir,sizeof(ResDir));
	DWORD dwDirectorySize=sizeof(IMAGE_RESOURCE_DIRECTORY)+(ResDir.NumberOfIdEntries+ResDir.NumberOfNamedEntries)*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
	DWORD dwDirectoryOffset=AddResource(bResHeaders,dwDirRVA,dwDirectorySize);
	DWORD dwEntryOffset=dwDirectoryOffset+sizeof(IMAGE_RESOURCE_DIRECTORY);

	for(int i=0;i!=ResDir.NumberOfIdEntries+ResDir.NumberOfNamedEntries;++i,dwEntryOffset+=sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))
	{
		if(IsProcessDying(pMain->hVictim))
			break;
		IMAGE_RESOURCE_DIRECTORY_ENTRY ResEntry=*(IMAGE_RESOURCE_DIRECTORY_ENTRY*)&bResHeaders[dwEntryOffset];
		if(ResEntry.NameIsString!=0)
		{
			DWORD dwRVA=dwResourceBase+ResEntry.NameOffset;
			IMAGE_RESOURCE_DIR_STRING_U ResString;
			pMain->ReadMem(pMain->VictimBase+dwRVA,&ResString,sizeof(ResString));

			DWORD dwSize=offsetof(IMAGE_RESOURCE_DIR_STRING_U,NameString)+ResString.Length*sizeof(ResString.NameString[0]);
			AlignRes(bResources,sizeof(WORD));
			((IMAGE_RESOURCE_DIRECTORY_ENTRY*)&bResHeaders[dwEntryOffset])->Name=AddResource(bResources,dwRVA,dwSize) | IMAGE_RESOURCE_NAME_IS_STRING;
		}

		if(ResEntry.DataIsDirectory!=0)
			((IMAGE_RESOURCE_DIRECTORY_ENTRY*)&bResHeaders[dwEntryOffset])->OffsetToDirectory=RipResources(dwResourceBase+ResEntry.OffsetToDirectory,dwResourceBase,bResHeaders,bResources);
		else
		{
			DWORD dwRVA=dwResourceBase+ResEntry.OffsetToData;
			IMAGE_RESOURCE_DATA_ENTRY ResDataEntry;
			pMain->ReadMem(pMain->VictimBase+dwRVA,&ResDataEntry,sizeof(ResDataEntry));

			DWORD dwDataOffset=AddResource(bResHeaders,dwRVA,sizeof(IMAGE_RESOURCE_DATA_ENTRY));
			((IMAGE_RESOURCE_DIRECTORY_ENTRY*)&bResHeaders[dwEntryOffset])->OffsetToData=dwDataOffset;
			AlignRes(bResources,sizeof(DWORD));
			((IMAGE_RESOURCE_DATA_ENTRY*)&bResHeaders[dwDataOffset])->OffsetToData=AddResource(bResources,ResDataEntry.OffsetToData,ResDataEntry.Size);
		}
	}
	return dwDirectoryOffset;
}

void CPEFile::ProcessResources()
{
	if(IsEmpty())
		return;

	DWORD dwResourceBase=pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	std::vector<BYTE> bResHeaders,bResources;
	if(dwResourceBase!=0)
		RipResources(dwResourceBase,dwResourceBase,bResHeaders,bResources);

	if(bResources.empty())
	{
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress=0;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size=0;
	}
	else
	{
		AlignRes(bResHeaders,sizeof(DWORD));

		std::vector<BYTE> bResSection;
		bResSection.resize(bResHeaders.size()+bResources.size());
		memcpy(&bResSection[0],&bResHeaders[0],bResHeaders.size());
		memcpy(&bResSection[bResHeaders.size()],&bResources[0],bResources.size());

		DWORD dwResourceBase=dwSectionsBegin+dwSectionsSize;
		CreateSection(".rsrc",&bResSection[0],(DWORD)bResSection.size(),IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress=dwResourceBase;
		pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size=(DWORD)bResSection.size();
		AddResourceDelta(dwResourceBase,dwResourceBase,(DWORD)bResHeaders.size());
	}
}

void CPEFile::CutSections()
{
	if(IsEmpty())
		return;

	DWORD dwCutAt=pMain->pInitData->dwCutModule;
	if(dwCutAt==0 || dwCutAt!=AlignTo(dwCutAt,pPEHeader->OptionalHeader.SectionAlignment))
		return;

	for(int i=pPEHeader->FileHeader.NumberOfSections-1;i>0;--i)
	{
		if(pSectionHeader[i].VirtualAddress<dwCutAt)
			break;
		else
			DeleteLastSection();
	}
}

void CPEFile::PreserveOverlay(const CPEFile &Source)
{
	ClearOverlay();
	bOverlay=Source.bOverlay;
}

void CPEFile::ClearOverlay()
{
	bOverlay.clear();
}

BYTE *CPEFile::RVA(DWORD dwRVA) const
{
	if(dwRVA==0)
		return NULL;
	if(!bHeader.empty() && dwRVA<bHeader.size())
		return (BYTE*)&bHeader[0]+dwRVA;
	if(!bHeader.empty() && dwRVA>=dwSectionsBegin && dwRVA<dwSectionsBegin+dwSectionsSize)
	{
		int n=GetSectionNumber(dwRVA);
		if(n>=0 && bSections[n]!=0)
			return bSections[n]+dwRVA-pSectionHeader[n].VirtualAddress;
	}
	return NULL;
}

DWORD_PTR ReadMem(HANDLE hProcess,DWORD_PTR Addr,void *pBuff,DWORD_PTR Size)
{
	if(Addr==0 || IsProcessDying(hProcess))
		return 0;

	MEMORY_BASIC_INFORMATION MemInfo;
	DWORD dwOld;
	DWORD_PTR dBegin=Addr,dEnd,dSize=0,sBegin,sEnd;
	DWORD_PTR sb=Addr/PAGE_SIZE;
	DWORD_PTR se=(Addr+Size)/PAGE_SIZE;
	__int64 sn=se-sb+1;

	for(__int64 i=0;i<sn;++i)
	{
		sBegin=(sb+(DWORD_PTR)i)*PAGE_SIZE;
		sEnd=sBegin+PAGE_SIZE;

		dBegin=max(Addr,sBegin);
		dEnd=min(Addr+Size,sEnd);
		dSize=dEnd-dBegin;

		if(!VirtualProtectEx(hProcess,(void*)dBegin,dSize,PAGE_READONLY,&dwOld))
		{
			if(VirtualQueryEx(hProcess,(void*)dBegin,&MemInfo,sizeof(MemInfo))==sizeof(MemInfo) &&
				MemInfo.State==MEM_RESERVE)
			{
				memset((BYTE*)pBuff+dBegin-Addr,0,dSize);
				continue;
			}
		}
		if(!ReadProcessMemory(hProcess,(void*)dBegin,(BYTE*)pBuff+dBegin-Addr,dSize,&dSize))
		{
			dSize=0;
			break;
		}
		VirtualProtectEx(hProcess,(void*)dBegin,dSize,dwOld,&dwOld);
	}
	return dBegin-Addr+dSize;
}

DWORD_PTR WriteMem(HANDLE hProcess,DWORD_PTR Addr,const void *pBuff,DWORD_PTR Size)
{
	if(Addr==0 || IsProcessDying(hProcess))
		return 0;

	DWORD dwOld;
	DWORD_PTR dBegin=Addr,dEnd,dSize=0,sBegin,sEnd;
	DWORD_PTR sb=Addr/PAGE_SIZE;
	DWORD_PTR se=(Addr+Size)/PAGE_SIZE;
	__int64 sn=se-sb+1;

	for(__int64 i=0;i<sn;++i)
	{
		sBegin=(sb+(DWORD_PTR)i)*PAGE_SIZE;
		sEnd=sBegin+PAGE_SIZE;

		dBegin=max(Addr,sBegin);
		dEnd=min(Addr+Size,sEnd);
		dSize=dEnd-dBegin;

		VirtualProtectEx(hProcess,(void*)dBegin,dSize,PAGE_READWRITE,&dwOld);
		if(!WriteProcessMemory(hProcess,(void*)dBegin,(BYTE*)pBuff+dBegin-Addr,dSize,&dSize))
		{
			dSize=0;
			break;
		}
		VirtualProtectEx(hProcess,(void*)dBegin,dSize,dwOld,&dwOld);
	}
	return dBegin-Addr+dSize;
}