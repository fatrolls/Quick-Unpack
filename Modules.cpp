#include "StdAfx.h"
#include "EngineHandler.h"
#include "Modules.h"
#include "DlgMain.h"
#include "psapi.h"
#include <strsafe.h>
#include "VersionHelpers.h"

std::vector<SCHEMA_LIBRARY> SchemaLibs;
std::vector<FORWARDED_FUNC> Forwarded;

typedef DWORD(NTAPI *cNtUnmapViewOfSection)
(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

TSTRING GetLibName(HMODULE hLibMod)
{
	size_t i;
	TCHAR szLibPath[MAX_PATH];
	GetModuleFileName(hLibMod,szLibPath,_countof(szLibPath));
	for(i=_tcslen(szLibPath)-1;i>=0 && szLibPath[i]!=_T('\\');--i);
	return szLibPath+i+1;
}

void ConvertSchemaName(TSTRING &sLibName)
{
	if(!IsWindows7OrGreater())
		return;
	if(_tcsnicmp(sLibName.c_str(),_T("api-"),4)!=0)
	{
		if(!IsWindows8OrGreater())
			return;
		if(_tcsnicmp(sLibName.c_str(),_T("ext-"),4)!=0)
			return;
	}

	if(_tcsicmp(sLibName.c_str()+sLibName.length()-4,_T(".dll"))!=0)
		sLibName.append(_T(".dll"));
	for(size_t i=0;i!=SchemaLibs.size();++i)
	{
		if(_tcsicmp(sLibName.c_str(),SchemaLibs[i].sSchemaName.c_str())!=0)
			continue;

		sLibName=SchemaLibs[i].sRealName;
		return;
	}

	SCHEMA_LIBRARY SchemaLib;
	SchemaLib.sSchemaName=sLibName;
	HMODULE hLibMod=GetModuleHandle(SchemaLib.sSchemaName.c_str());
	if(hLibMod==NULL)
	{
		hLibMod=LoadLibrary(SchemaLib.sSchemaName.c_str());
		if(hLibMod==NULL)
			return;

		SchemaLib.sRealName=GetLibName(hLibMod);
		FreeLibrary(hLibMod);
	}
	else
		SchemaLib.sRealName=GetLibName(hLibMod);
	SchemaLibs.push_back(SchemaLib);
	sLibName=SchemaLib.sRealName;
}

CModule::CModule(HANDLE n_hVictim,DWORD_PTR n_ModuleBase,const TCHAR *szModuleName,
				 const TCHAR *szFullName,const TCHAR *szImportName)
:	HookBase(0),
	dwHookSize(0),
	hVictim(n_hVictim),
	ModuleBase(n_ModuleBase),
	sModuleName(szModuleName),
	sFullName(szFullName),
	sImportName(szImportName)
{
	ReadMem(hVictim,ModuleBase+offsetof(IMAGE_DOS_HEADER,e_lfanew),&dwOffsetToPe,sizeof(dwOffsetToPe));

	CPEFile TempFile;
	TempFile.Read(sFullName.c_str());
	ModuleFile.Dump(hVictim,ModuleBase,&TempFile,csSimple);
	if(ModuleFile.IsEmpty())
		return;
	dwModuleSize=ModuleFile.pPEHeader->OptionalHeader.SizeOfImage;

	IMAGE_EXPORT_DIRECTORY *pExports=(IMAGE_EXPORT_DIRECTORY*)ModuleFile.RVA(ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if(pExports==NULL)
		return;

	if(pExports->NumberOfFunctions==0)
		return;
	Exports.resize(pExports->NumberOfFunctions);

	for(DWORD i=0;i!=Exports.size();++i)
	{
		if(ModuleFile.RVA(pExports->AddressOfFunctions+i*sizeof(DWORD))!=NULL)
			Exports[i].dwFuncAddress=*(DWORD*)ModuleFile.RVA(pExports->AddressOfFunctions+i*sizeof(DWORD));
		else
			Exports[i].dwFuncAddress=0;
		Exports[i].dwFuncAddressHook=MAXDWORD;
		Exports[i].sFuncName.clear();
		Exports[i].wFuncOrdinal=(WORD)(pExports->Base+i);

		for(DWORD j=0;j!=pExports->NumberOfNames;++j)
		{
			if(ModuleFile.RVA(pExports->AddressOfNameOrdinals+j*sizeof(WORD))!=NULL &&
				*(WORD*)ModuleFile.RVA(pExports->AddressOfNameOrdinals+j*sizeof(WORD))==i)
			{
				if(ModuleFile.RVA(pExports->AddressOfNames+j*sizeof(DWORD))!=NULL &&
					ModuleFile.RVA(*(DWORD*)ModuleFile.RVA(pExports->AddressOfNames+j*sizeof(DWORD)))!=NULL)
					Exports[i].sFuncName=(char*)ModuleFile.RVA(*(DWORD*)ModuleFile.RVA(pExports->AddressOfNames+j*sizeof(DWORD)));
				break;
			}
		}
	}
}

void CModule::FreeMemory()
{
	if(HookBase==0 || !TestVictim())
		return;

	VirtualFreeEx(hVictim,(void*)HookBase,0,MEM_RELEASE);
	HookBase=0;
	dwHookSize=0;
}

void CModule::AddForwarded()
{
	for(DWORD i=0;i!=Exports.size();++i)
	{
		if(Exports[i].dwFuncAddress>ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			Exports[i].dwFuncAddress<ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+
			ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			FORWARDED_FUNC forw;
			forw.sFromLib=sImportName;
			forw.sFromName=Exports[i].sFuncName;
			forw.wFromOrdinal=Exports[i].wFuncOrdinal;
			if(ModuleFile.RVA(Exports[i].dwFuncAddress)!=NULL)
				forw.sToName=(char*)ModuleFile.RVA(Exports[i].dwFuncAddress);
#ifdef UNICODE
			int nMultiLength=(int)forw.sToName.length()+1;
			WCHAR *pWideArray=new WCHAR[nMultiLength];
			MultiByteToWideChar(CP_ACP,0,forw.sToName.c_str(),nMultiLength,pWideArray,nMultiLength);
			forw.sToLib=pWideArray;
			delete[] pWideArray;
#else
			forw.sToLib=forw.sToName;
#endif
			if(forw.sToLib.find(_T('.'))!=std::string::npos)
			{
				forw.sToLib.erase(forw.sToLib.find(_T('.')),forw.sToLib.length()-forw.sToLib.find(_T('.')));
				forw.sToName.erase(0,forw.sToName.find('.')+1);
				if(forw.sToName[0]=='#')
				{
					forw.sToName.erase(0,1);
					forw.wToOrdinal=(WORD)StrToIntA(forw.sToName.c_str());
					forw.sToName.clear();
				}
				else
					forw.wToOrdinal=0;
				ConvertSchemaName(forw.sToLib);

				if(pMain!=NULL)
				{
					for(size_t j=0;j!=pMain->Modules.Modules.size();++j)
					{
						if(_tcsicmp(forw.sToLib.c_str(),pMain->Modules.Modules[j]->sImportName.c_str())==0 ||
							_tcsicmp((forw.sToLib+_T(".dll")).c_str(),pMain->Modules.Modules[j]->sImportName.c_str())==0)
						{
							forw.sToLib=pMain->Modules.Modules[j]->sImportName;
							for(size_t k=0;k!=pMain->Modules.Modules[j]->Exports.size();++k)
							{
								if(!forw.sToName.empty() && forw.sToName==pMain->Modules.Modules[j]->Exports[k].sFuncName)
								{
									forw.wToOrdinal=pMain->Modules.Modules[j]->Exports[k].wFuncOrdinal;
									break;
								}
								if(forw.sToName.empty() && forw.wToOrdinal==pMain->Modules.Modules[j]->Exports[k].wFuncOrdinal)
								{
									forw.sToName=pMain->Modules.Modules[j]->Exports[k].sFuncName;
									break;
								}
							}
							break;
						}
					}
				}
				Forwarded.push_back(forw);
			}
		}
	}
}

#if defined _M_AMD64
static const int SHORT_FUNC_OFFSET=14,SHORT_TRAMPOLINE_OFFSET=3;
BYTE HookBodyShort[]={
					0x50,								//push rax
					0x48,0xb8,0,0,0,0,0,0,0,0,			//mov rax,trampoline
					0x50,								//push rax
					0x48,0xb8,0,0,0,0,0,0,0,0,			//mov rax,func_addr
					0xc3};								//ret
static const int LONG_FUNC_OFFSET=14,LONG_TRAMPOLINE_OFFSET=3;
BYTE HookBodyLong[]={
					0x50,								//push rax
					0x48,0xb8,0,0,0,0,0,0,0,0,			//mov rax,trampoline
					0x50,								//push rax
					0x48,0xb8,0,0,0,0,0,0,0,0,			//mov rax,func_addr
					0xc3};								//ret
#elif defined _M_IX86
static const int SHORT_FUNC_OFFSET=8,SHORT_TRAMPOLINE_OFFSET=2;
BYTE HookBodyShort[]={
					0x50,								//push eax
					0xb8,0,0,0,0,						//mov eax,trampoline
					0x50,								//push eax
					0xb8,0,0,0,0,						//mov eax,func_addr
					0xc3};								//ret
static const int LONG_FUNC_OFFSET=10,LONG_TRAMPOLINE_OFFSET=4;
BYTE HookBodyLong[]={
					0x8b,0xff,							//mov edi,edi
					0x50,								//push eax
					0xb8,0,0,0,0,						//mov eax,trampoline
					0x50,								//push eax
					0xb8,0,0,0,0,						//mov eax,func_addr
					0xc2,0,0,							//ret 0
					0xff,0x12};							//call [edx]
#else
!!!
#endif

void CModule::HookExport()
{
	if(!TestVictim() || HookBase!=0 || Exports.empty())
		return;

	IMAGE_EXPORT_DIRECTORY *pExports=(IMAGE_EXPORT_DIRECTORY*)ModuleFile.RVA(ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD *pNewExport=new DWORD[Exports.size()];
	memcpy(pNewExport,ModuleFile.RVA(pExports->AddressOfFunctions),Exports.size()*sizeof(DWORD));

	if(pMain==NULL || pMain->pInitData->fLongImport)
	{
		dwHookSize=(DWORD)Exports.size()*sizeof(HookBodyLong);

		HookBase=0;
		DWORD_PTR i=ModuleBase+dwModuleSize;
		do
		{
			i+=PAGE_SIZE;
			HookBase=(DWORD_PTR)VirtualAllocEx(hVictim,(void*)i,dwHookSize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READ);
			if(!TestVictim())
				break;
		}
		while(HookBase==0);
	}
	else
	{
		dwHookSize=(DWORD)Exports.size()*sizeof(HookBodyShort);

		void *pTempImage=VirtualAlloc(NULL,ModuleFile.pPEHeader->OptionalHeader.SizeOfImage,MEM_COMMIT,PAGE_READWRITE);
		ReadMem(hVictim,ModuleBase,pTempImage,ModuleFile.pPEHeader->OptionalHeader.SizeOfImage);

		DWORD_PTR Current=ModuleBase;
		std::vector<DWORD> Array;
		MEMORY_BASIC_INFORMATION MemInfo;
		for(;;)
		{
			if(VirtualQueryEx(hVictim,(void*)Current,&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo))
				break;
			if((MemInfo.Protect & 0xff)==PAGE_EXECUTE_WRITECOPY)
				MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_EXECUTE_READWRITE;
			if((MemInfo.Protect & 0xff)==PAGE_WRITECOPY)
				MemInfo.Protect=(MemInfo.Protect & ~0xff) | PAGE_READWRITE;
			Current+=MemInfo.RegionSize;
			Array.push_back((DWORD)MemInfo.RegionSize);
			Array.push_back(MemInfo.Protect);
			if(Current>=ModuleBase+ModuleFile.pPEHeader->OptionalHeader.SizeOfImage)
				break;
		}

		cNtUnmapViewOfSection NtUnmapViewOfSection=(cNtUnmapViewOfSection)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),"NtUnmapViewOfSection");
		NtUnmapViewOfSection(hVictim,(void*)ModuleBase);
		if(VirtualAllocEx(hVictim,(void*)ModuleBase,AlignTo(ModuleFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE)+dwHookSize,
			MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READ)==NULL)
		{
			VirtualAllocEx(hVictim,(void*)ModuleBase,ModuleFile.pPEHeader->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READ);

			HookBase=0;
			DWORD_PTR i=ModuleBase+dwModuleSize;
			do
			{
				i+=PAGE_SIZE;
				HookBase=(DWORD_PTR)VirtualAllocEx(hVictim,(void*)i,dwHookSize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READ);
				if(!TestVictim())
					break;
			}
			while(HookBase==0);
		}
		else
			HookBase=ModuleBase+AlignTo(ModuleFile.pPEHeader->OptionalHeader.SizeOfImage,PAGE_SIZE);

		WriteMem(hVictim,ModuleBase,pTempImage,ModuleFile.pPEHeader->OptionalHeader.SizeOfImage);
		VirtualFree(pTempImage,0,MEM_RELEASE);

		Current=ModuleBase;
		for(size_t i=0;i!=Array.size();i+=2)
		{
			VirtualProtectEx(hVictim,(void*)Current,Array[i],Array[i+1],&Array[1]);
			Current+=Array[i];
		}
	}

	BYTE *bHookBody=new BYTE[dwHookSize];
	memset(bHookBody,0,dwHookSize);

	for(DWORD i=0;i!=Exports.size();++i)
	{
		DWORD dwRealFunctionAddress=Exports[i].dwFuncAddress;
		if(dwRealFunctionAddress>ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			dwRealFunctionAddress<ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress+
			ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
			dwRealFunctionAddress=0;
		MEMORY_BASIC_INFORMATION MemInfo;
		if(VirtualQueryEx(hVictim,(void*)(ModuleBase+dwRealFunctionAddress),&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo) ||
			(MemInfo.Protect & 0xff)<PAGE_EXECUTE || dwRealFunctionAddress==0)
		{
			Exports[i].dwFuncAddressHook=MAXDWORD;
			continue;
		}
		DWORD j=0;
		for(;j!=i;++j)
		{
			if(Exports[j].dwFuncAddress==Exports[i].dwFuncAddress)
			{
				Exports[i].dwFuncAddressHook=Exports[j].dwFuncAddressHook;
				pNewExport[i]=pNewExport[j];
				break;
			}
		}
		if(j!=i)
			continue;

		if(pMain==NULL || pMain->pInitData->fLongImport)
		{
			Exports[i].dwFuncAddressHook=i*sizeof(HookBodyLong);
			pNewExport[i]=(DWORD)(HookBase-ModuleBase+i*sizeof(HookBodyLong));

			*(DWORD_PTR*)(HookBodyLong+LONG_FUNC_OFFSET)=ModuleBase+dwRealFunctionAddress;
			*(DWORD_PTR*)(HookBodyLong+LONG_TRAMPOLINE_OFFSET)=pMain->Modules.TrampolineBase;

			memcpy(bHookBody+i*sizeof(HookBodyLong),HookBodyLong,sizeof(HookBodyLong));
		}
		else
		{
			Exports[i].dwFuncAddressHook=i*sizeof(HookBodyShort);
			pNewExport[i]=(DWORD)(HookBase-ModuleBase+i*sizeof(HookBodyShort));

			*(DWORD_PTR*)(HookBodyShort+SHORT_FUNC_OFFSET)=ModuleBase+dwRealFunctionAddress;
			*(DWORD_PTR*)(HookBodyShort+SHORT_TRAMPOLINE_OFFSET)=pMain->Modules.TrampolineBase;

			memcpy(bHookBody+i*sizeof(HookBodyShort),HookBodyShort,sizeof(HookBodyShort));
		}
	}
	if(_tcsstr(sModuleName.c_str(),_T("ws2_32"))!=NULL)
	{
		DWORD_PTR redir1;
		DWORD dwRVA;
		for(DWORD i=0;i!=ModuleFile.pPEHeader->FileHeader.NumberOfSections;++i)
		{
			for(int j=0;j<(int)(ModuleFile.pSectionHeader[i].SizeOfRawData-(sizeof(DWORD_PTR)-1));++j)
			{
				dwRVA=ModuleFile.pSectionHeader[i].VirtualAddress+j;
				if(ModuleFile.RVA(dwRVA)!=NULL)
					redir1=*(DWORD_PTR*)ModuleFile.RVA(dwRVA);
				else
					continue;

				if(redir1==ModuleBase+Exports[0].dwFuncAddress)
					break;
			}
			if(redir1==ModuleBase+Exports[0].dwFuncAddress)
				break;
		}
		if(redir1==ModuleBase+Exports[0].dwFuncAddress)
		{
			while(redir1!=0)
			{
				if(ModuleFile.RVA(dwRVA)!=NULL)
					redir1=*(DWORD_PTR*)ModuleFile.RVA(dwRVA);
				else
					break;
				size_t i=0;
				for(;i!=Exports.size();++i)
				{
					if(redir1==ModuleBase+Exports[i].dwFuncAddress)
						break;
				}
				if(i!=Exports.size() && Exports[i].dwFuncAddressHook!=MAXDWORD)
				{
					DWORD_PTR FuncAddressHook=HookBase+Exports[i].dwFuncAddressHook;
					WriteMem(hVictim,dwRVA+ModuleBase,&FuncAddressHook,sizeof(FuncAddressHook));
				}
				dwRVA+=sizeof(DWORD_PTR);
			}
		}
	}
	WriteMem(hVictim,HookBase,bHookBody,dwHookSize);
	delete[] bHookBody;
	WriteMem(hVictim,ModuleBase+pExports->AddressOfFunctions,pNewExport,Exports.size()*sizeof(DWORD));
	delete[] pNewExport;
	DWORD dwNewSize=(DWORD)AlignTo(HookBase-ModuleBase+dwHookSize,PAGE_SIZE);
	WriteMem(hVictim,ModuleBase+dwOffsetToPe+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+offsetof(IMAGE_OPTIONAL_HEADER,SizeOfImage),&dwNewSize,sizeof(dwNewSize));

	WriteLn(_T(""));
	WriteTime();
	WriteEx(_T(" - 0x")+IntToStr(HookBase,16,sizeof(HookBase)*2),FALSE,TRUE,RGB(0,0,0));
	Write(module);
	WriteEx(sModuleName.c_str(),FALSE,TRUE,RGB(0,127,0));
	Write(exporthooked);
}

void CModule::UnHookExport()
{
	if(!TestVictim() || HookBase==0)
		return;

	DWORD *pNewExport=new DWORD[Exports.size()];
	IMAGE_EXPORT_DIRECTORY *pExports=(IMAGE_EXPORT_DIRECTORY*)ModuleFile.RVA(ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	for(size_t i=0;i!=Exports.size();++i)
	{
		pNewExport[i]=Exports[i].dwFuncAddress;
		Exports[i].dwFuncAddressHook=MAXDWORD;
	}
	WriteMem(hVictim,ModuleBase+dwOffsetToPe+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+offsetof(IMAGE_OPTIONAL_HEADER,SizeOfImage),&dwModuleSize,sizeof(dwModuleSize));
	WriteMem(hVictim,ModuleBase+pExports->AddressOfFunctions,pNewExport,Exports.size()*sizeof(DWORD));
	delete[] pNewExport;

	WriteLn(_T(""));
	WriteTime();
	WriteEx(_T(" - 0x")+IntToStr(ModuleBase,16,sizeof(ModuleBase)*2),FALSE,TRUE,RGB(0,0,0));
	Write(module);
	WriteEx(sModuleName.c_str(),FALSE,TRUE,RGB(255,0,0));
	Write(exportunhooked);
}

bool CModule::TestVictim()
{
	if(hVictim!=NULL && IsProcessDying(hVictim))
		hVictim=NULL;
	return hVictim!=NULL;
}

CModules::CModules()
{
	Clear();
}

CModules::~CModules()
{
	Clear();
}

void CModules::Clear()
{
	if(pMain==NULL || pMain->pInitData->fLongImport)
	{
		FUNC_OFFSET=LONG_FUNC_OFFSET;
		TRAMPOLINE_OFFSET=LONG_TRAMPOLINE_OFFSET;
	}
	else
	{
		FUNC_OFFSET=SHORT_FUNC_OFFSET;
		TRAMPOLINE_OFFSET=SHORT_TRAMPOLINE_OFFSET;
	}

	VictimBase=0;
	TrampolineBase=0;
	pVictimFile=NULL;
	hVictim=NULL;
	fHookedImport=false;
	fUnhookInAction=FALSE;

	for(size_t i=0;i!=Modules.size();++i)
		delete Modules[i];
	Modules.clear();
	UnhookedBreaks.clear();
	SchemaLibs.clear();
	Forwarded.clear();
}

void CModules::AddModule(DWORD_PTR ModuleBase,bool fAddForwarded)
{
	size_t i=0;
	TCHAR szFullModuleName[MAX_PATH],*szModuleName,szImportName[MAX_PATH],szTemp[0x400];
	for(;i!=Modules.size();++i)
	{
		if(ModuleBase==Modules[i]->ModuleBase)
			break;
	}
	if(i==Modules.size() && ModuleBase!=VictimBase)
	{
		if(GetMappedFileName(hVictim,(void*)ModuleBase,szFullModuleName,_countof(szFullModuleName))!=0)
		{
			szTemp[0]=_T('\0');
			if(GetLogicalDriveStrings(_countof(szTemp)-1,szTemp)!=0)
			{
				TCHAR szName[MAX_PATH];
				TCHAR szDrive[]=_T(" :");
				bool fFound=false;
				TCHAR *p=szTemp;

				do
				{
					szDrive[0]=p[0];
					if(QueryDosDevice(szDrive,szName,_countof(szName))!=0)
					{
						size_t nNameLen=_tcslen(szName);
						if(nNameLen<_countof(szName))
						{
							fFound=(_tcsnicmp(szFullModuleName,szName,nNameLen)==0);
							if(fFound)
							{
								TCHAR szTempFile[MAX_PATH];
								_stprintf_s(szTempFile,_T("%s%s"),szDrive,szFullModuleName+nNameLen);
								_tcscpy_s(szFullModuleName,szTempFile);
							}
						}
					}
					while(p[0]!=_T('\0'))
						++p;
					++p;
				}
				while(!fFound && p[0]!=_T('\0'));
			}
			for(i=_tcslen(szFullModuleName)-1;i>=0 && szFullModuleName[i]!=_T('\\');--i);
			szModuleName=szFullModuleName+i+1;
		}
		else
		{
			_tcscpy_s(szFullModuleName,IntToStr(Modules.size(),10,1)+_T(".dll"));
			szModuleName=szFullModuleName;
		}
		_tcscpy_s(szImportName,szModuleName);
		CModule *pNewModule;
		if(pMain!=NULL && pMain->pInitData->fPathToLibs)
		{
			CPEFile ModuleFile;
			ModuleFile.Read(szFullModuleName);
			IMAGE_EXPORT_DIRECTORY *pExports=(IMAGE_EXPORT_DIRECTORY*)ModuleFile.RVA(ModuleFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if(pExports==NULL || pExports->NumberOfFunctions==0)
				pNewModule=new CModule(hVictim,ModuleBase,szModuleName,szFullModuleName,szImportName);
			else
			{
				BYTE bSection[]={0xeb,0xfe};			//jmp $
				CPEFile TempFile;
				TempFile.CreateEmpty();
				TempFile.pPEHeader->OptionalHeader.ImageBase=0x400000;
				TempFile.CreateSection(".text",bSection,sizeof(bSection),IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);
				TempFile.pPEHeader->OptionalHeader.AddressOfEntryPoint=TempFile.pSectionHeader[0].VirtualAddress;
				GetTempFileName(pMain->sWorkDir.c_str(),_T(""),0,szTemp);

				CImport Import;
				Import.AddRecord(CImportRecord(szImportName,(WORD)pExports->Base,0,0,itNone));
				Import.SaveToFile(TempFile,0);
				TempFile.Save(szTemp);

				PROCESS_INFORMATION pi;
				CreateRestrictedProcess(NULL,szTemp,NORMAL_PRIORITY_CLASS,NULL,&pi);
				DWORD dwExitCode;
				CONTEXT Context;
				Context.ContextFlags=CONTEXT_CONTROL;
				DWORD_PTR RegIp;
				do
				{
					SwitchToThread();
					GetExitCodeProcess(pi.hProcess,&dwExitCode);
					SuspendThread(pi.hThread);
					GetThreadContext(pi.hThread,&Context);
					ResumeThread(pi.hThread);
#if defined _M_AMD64
					RegIp=Context.Rip;
#elif defined _M_IX86
					RegIp=Context.Eip;
#else
!!!
#endif
				}
				while(dwExitCode==STILL_ACTIVE && RegIp!=TempFile.pPEHeader->OptionalHeader.ImageBase+TempFile.pPEHeader->OptionalHeader.AddressOfEntryPoint);

				TerminateProcess(pi.hProcess,0);
				WaitForSingleObject(pi.hProcess,INFINITE);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				while(PathFileExists(szTemp))
				{
					SwitchToThread();
					DeleteFile(szTemp);
				}

				if(dwExitCode==STILL_ACTIVE)
					pNewModule=new CModule(hVictim,ModuleBase,szModuleName,szFullModuleName,szImportName);
				else
				{
					TSTRING sImportName(pMain->pInitData->sVictimFile);
					size_t size=min(sImportName.length(),_tcslen(szFullModuleName));
					for(i=0;i!=size;++i)
					{
						if(tolower(szFullModuleName[i])!=tolower(sImportName[i]))
							break;
					}
					if(i!=0)
					{
						for(;i!=0;--i)
						{
							if(szFullModuleName[i]==_T('\\'))
								break;
						}
					}
					++i;
					sImportName.clear();
					for(size_t j=i;j!=pMain->pInitData->sVictimFile.length();++j)
					{
						if(pMain->pInitData->sVictimFile[j]==_T('\\'))
							sImportName.append(_T("..\\"));
					}
					sImportName.append(szFullModuleName+i);
					pNewModule=new CModule(hVictim,ModuleBase,szModuleName,szFullModuleName,sImportName.c_str());
				}
			}
		}
		else
			pNewModule=new CModule(hVictim,ModuleBase,szModuleName,szFullModuleName,szImportName);
		Modules.push_back(pNewModule);
		if(fAddForwarded)
			Modules.back()->AddForwarded();

		if(VictimBase!=MAX_NUM)
		{
			WriteLn(_T(""));
			WriteTime();
			WriteEx(_T(" - 0x")+IntToStr(ModuleBase,16,sizeof(ModuleBase)*2),FALSE,TRUE,RGB(0,0,0));
			Write(module);
			WriteEx(szModuleName,FALSE,TRUE,RGB(0,0,255));
			Write(loaded);
		}
	}
}

void CModules::Reload(DWORD_PTR n_VictimBase,CPEFile *n_pVictimFile,HANDLE n_hVictim)
{
	VictimBase=n_VictimBase;
	pVictimFile=n_pVictimFile;
	hVictim=n_hVictim;

	if(IsProcessDying(hVictim))
		return;

	size_t OldModulesNum(Modules.size());

	HANDLE hModuleSnap;
	do hModuleSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetProcessId(hVictim));
	while(hModuleSnap==INVALID_HANDLE_VALUE && GetLastError()==ERROR_BAD_LENGTH);
	MODULEENTRY32 me32;
	me32.dwSize=sizeof(me32);
	if(Module32First(hModuleSnap,&me32))
	{
		do AddModule((DWORD_PTR)me32.modBaseAddr,false);
		while(Module32Next(hModuleSnap,&me32));
	}
	CloseHandle(hModuleSnap);

	for(size_t i(OldModulesNum);i!=Modules.size();++i)
		Modules[i]->AddForwarded();
}

#if defined _M_AMD64
BYTE bTrampoline[]={
					0x48,0x87,0x04,0x24,				//xchg [rsp],rax
					0xed,								//in eax,dx
					0xc3};								//ret
#elif defined _M_IX86
BYTE bTrampoline[]={
					0x87,0x04,0x24,						//xchg [esp],eax
					0xed,								//in eax,dx
					0xc3};								//ret
#else
!!!
#endif

void CModules::HookExport()
{
	if(TrampolineBase==0)
	{
		TrampolineBase=(DWORD_PTR)VirtualAllocEx(hVictim,NULL,sizeof(bTrampoline),MEM_COMMIT,PAGE_EXECUTE_READ);
		WriteMem(hVictim,TrampolineBase,&bTrampoline,sizeof(bTrampoline));
	}

	for(size_t i=0;i!=Modules.size();++i)
	{
		size_t j=0;
		for(;j!=UnhookModules.size();++j)
		{
			if(_tcsstr(Modules[i]->sModuleName.c_str(),UnhookModules[j].c_str())!=NULL)
				break;
		}

		if(j==UnhookModules.size())
			Modules[i]->HookExport();
	}
}

void CModules::UnHookExport()
{
	if(TrampolineBase!=0)
	{
		BYTE bNop=0x90;
		WriteMem(hVictim,TrampolineBase+TRAMPOLINE_BREAK_OFFSET,&bNop,sizeof(bNop));
	}

	for(size_t i=0;i!=Modules.size();++i)
		Modules[i]->UnHookExport();
}

void CModules::HookImport()
{
	if(IsProcessDying(hVictim) || fHookedImport || pVictimFile->IsEmpty())
		return;

	DWORD dwImportRVA=pVictimFile->pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if(dwImportRVA==0)
		return;

	for(;;)
	{
		IMAGE_IMPORT_DESCRIPTOR *pIID=(IMAGE_IMPORT_DESCRIPTOR*)pVictimFile->RVA(dwImportRVA);
		dwImportRVA+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
		if(pIID==NULL)
			break;

		DWORD dwAddressTableRVA=pIID->OriginalFirstThunk;
		if(dwAddressTableRVA==0)
			dwAddressTableRVA=pIID->FirstThunk;
		if(dwAddressTableRVA==0)
			break;

		DWORD dwAddressTableSize=0;
		for(;;dwAddressTableSize+=sizeof(DWORD_PTR))
		{
			if(pVictimFile->RVA(dwAddressTableRVA+dwAddressTableSize)==NULL || *(DWORD_PTR*)pVictimFile->RVA(dwAddressTableRVA+dwAddressTableSize)==0)
				break;
		}

		if(dwAddressTableSize==0)
			continue;
		DWORD_PTR *pAddressTableHook=new DWORD_PTR[dwAddressTableSize/sizeof(DWORD_PTR)];
		ReadMem(hVictim,VictimBase+pIID->FirstThunk,pAddressTableHook,dwAddressTableSize);

		for(DWORD k=0;k!=dwAddressTableSize/sizeof(DWORD_PTR);++k)
		{
			DWORD_PTR FuncAddress=pAddressTableHook[k];
			DWORD_PTR FuncAddressHook=pAddressTableHook[k];

			for(size_t i=0;i!=Modules.size();++i)
			{
				if(FuncAddress>=Modules[i]->ModuleBase && FuncAddress<Modules[i]->ModuleBase+Modules[i]->dwModuleSize)
				{
					for(size_t j=0;j!=Modules[i]->Exports.size();++j)
					{
						if(Modules[i]->Exports[j].dwFuncAddress==0)
							continue;
						if(Modules[i]->Exports[j].dwFuncAddressHook==MAXDWORD)
							continue;
						if(Modules[i]->ModuleBase+Modules[i]->Exports[j].dwFuncAddress==FuncAddress)
						{
							FuncAddressHook=Modules[i]->HookBase+Modules[i]->Exports[j].dwFuncAddressHook;
							if(FuncAddressHook!=FuncAddress)
								break;
						}
					}
					break;
				}
			}
			pAddressTableHook[k]=FuncAddressHook;
		}
		WriteMem(hVictim,VictimBase+pIID->FirstThunk,pAddressTableHook,dwAddressTableSize);
		delete[] pAddressTableHook;
	}
	fHookedImport=true;
	WriteLog(importhooked);
}

void CModules::SetUnhookedBreaksBack()
{
	if(fUnhookInAction)
		return;

	BYTE bBreak=0xed;
	for(size_t i=0;i!=UnhookedBreaks.size();++i)
		WriteMem(hVictim,UnhookedBreaks[i],&bBreak,sizeof(bBreak));
	UnhookedBreaks.clear();
}

DWORD_PTR CModules::GetModHandle(const TCHAR *szModuleName) const
{
	for(size_t i=0;i!=Modules.size();++i)
	{
		if(_tcsicmp(szModuleName,Modules[i]->sModuleName.c_str())==0)
			return Modules[i]->ModuleBase;
	}
	return 0;
}

DWORD_PTR CModules::GetProcedureAddr(const TCHAR *szModuleName,const char *szFuncName,WORD wFuncOrdinal,bool fAddressHook) const
{
	for(size_t i=0;i!=Modules.size();++i)
	{
		if(_tcsicmp(szModuleName,Modules[i]->sModuleName.c_str())==0)
		{
			for(size_t j=0;j!=Modules[i]->Exports.size();++j)
			{
				if(Modules[i]->Exports[j].dwFuncAddress==0)
					continue;
				if((szFuncName[0]!='\0' && _stricmp(szFuncName,Modules[i]->Exports[j].sFuncName.c_str())==0) ||
					(wFuncOrdinal!=0 && Modules[i]->Exports[j].wFuncOrdinal==wFuncOrdinal))
				{
					if(fAddressHook)
						return Modules[i]->HookBase+Modules[i]->Exports[j].dwFuncAddressHook;
					else
						return Modules[i]->ModuleBase+Modules[i]->Exports[j].dwFuncAddress;
				}
			}
		}
	}
	return 0;
}

void CModules::IdentifyFunction(CImportRecord &ImportRecord,DWORD_PTR FuncAddress) const
{
	ImportRecord.Clear();

	for(size_t i=0;i!=Modules.size();++i)
	{
		if(FuncAddress>=Modules[i]->ModuleBase && FuncAddress<Modules[i]->ModuleBase+Modules[i]->dwModuleSize)
		{
			for(size_t j=0;j!=Modules[i]->Exports.size();++j)
			{
				if(Modules[i]->Exports[j].dwFuncAddress==0)
					continue;
				if(Modules[i]->ModuleBase+Modules[i]->Exports[j].dwFuncAddress==FuncAddress)
				{
					ImportRecord.sLibName=Modules[i]->sImportName;
					ImportRecord.sApiName=Modules[i]->Exports[j].sFuncName;
					ImportRecord.wOrdinal=Modules[i]->Exports[j].wFuncOrdinal;
					return;
				}
			}
		}
		else if(FuncAddress>=Modules[i]->HookBase && FuncAddress<Modules[i]->HookBase+Modules[i]->dwHookSize)
		{
			for(size_t j=0;j!=Modules[i]->Exports.size();++j)
			{
				if(Modules[i]->Exports[j].dwFuncAddress==0)
					continue;
				if(Modules[i]->HookBase+Modules[i]->Exports[j].dwFuncAddressHook==FuncAddress)
				{
					ImportRecord.sLibName=Modules[i]->sImportName;
					ImportRecord.sApiName=Modules[i]->Exports[j].sFuncName;
					ImportRecord.wOrdinal=Modules[i]->Exports[j].wFuncOrdinal;
					return;
				}
			}
		}
	}
}

bool CModules::IdentifyFunctionPrev(CImportRecord &ImportRecord) const
{
	for(size_t i=0;i!=Modules.size();++i)
	{
		if(_tcsicmp(ImportRecord.sLibName.c_str(),Modules[i]->sImportName.c_str())==0)
		{
			for(size_t j=0;j!=Modules[i]->Exports.size();++j)
			{
				if(Modules[i]->Exports[j].dwFuncAddress==0)
					continue;
				if(Modules[i]->Exports[j].wFuncOrdinal==ImportRecord.wOrdinal)
				{
					for(int k=(int)j-1;k>=0;--k)
					{
						if(Modules[i]->Exports[k].dwFuncAddress==Modules[i]->Exports[j].dwFuncAddress)
						{
							ImportRecord.sApiName=Modules[i]->Exports[k].sFuncName;
							ImportRecord.wOrdinal=Modules[i]->Exports[k].wFuncOrdinal;
							return true;
						}
					}
					break;
				}
			}
			break;
		}
	}
	return false;
}

bool CModules::IdentifyFunctionNext(CImportRecord &ImportRecord) const
{
	for(size_t i=0;i!=Modules.size();++i)
	{
		if(_tcsicmp(ImportRecord.sLibName.c_str(),Modules[i]->sImportName.c_str())==0)
		{
			for(size_t j=0;j!=Modules[i]->Exports.size();++j)
			{
				if(Modules[i]->Exports[j].dwFuncAddress==0)
					continue;
				if(Modules[i]->Exports[j].wFuncOrdinal==ImportRecord.wOrdinal)
				{
					for(size_t k=j+1;k!=Modules[i]->Exports.size();++k)
					{
						if(Modules[i]->Exports[k].dwFuncAddress==Modules[i]->Exports[j].dwFuncAddress)
						{
							ImportRecord.sApiName=Modules[i]->Exports[k].sFuncName;
							ImportRecord.wOrdinal=Modules[i]->Exports[k].wFuncOrdinal;
							return true;
						}
					}
					break;
				}
			}
			break;
		}
	}
	return false;
}

bool CModules::ForwardedPrev(CImportRecord &ImportRecord,DWORD dwCount) const
{
	if(dwCount==0)
		return false;
	if(!ImportRecord.Exist())
		return false;

	for(size_t i=0;i!=Forwarded.size();++i)
	{
		if(Forwarded[i].wToOrdinal==ImportRecord.wOrdinal && Forwarded[i].sToLib==ImportRecord.sLibName)
		{
			ImportRecord.sLibName=Forwarded[i].sFromLib;
			ImportRecord.sApiName=Forwarded[i].sFromName;
			ImportRecord.wOrdinal=Forwarded[i].wFromOrdinal;

			if(dwCount==INFINITE)
				ForwardedPrev(ImportRecord,dwCount);
			else
				ForwardedPrev(ImportRecord,dwCount-1);
			return true;
		}
	}
	return false;
}

bool CModules::ForwardedNext(CImportRecord &ImportRecord,DWORD dwCount) const
{
	if(dwCount==0)
		return false;
	if(!ImportRecord.Exist())
		return false;

	for(size_t i=0;i!=Forwarded.size();++i)
	{
		if(Forwarded[i].wFromOrdinal==ImportRecord.wOrdinal && Forwarded[i].sFromLib==ImportRecord.sLibName)
		{
			ImportRecord.sLibName=Forwarded[i].sToLib;
			ImportRecord.sApiName=Forwarded[i].sToName;
			ImportRecord.wOrdinal=Forwarded[i].wToOrdinal;

			if(dwCount==INFINITE)
				ForwardedNext(ImportRecord,dwCount);
			else
				ForwardedNext(ImportRecord,dwCount-1);
			return true;
		}
	}
	return false;
}