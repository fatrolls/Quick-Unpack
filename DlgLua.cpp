#include "StdAfx.h"
#include "Init.h"
#include "DlgLua.h"
#include "DlgMain.h"
#include "DlgImport.h"
#include <string>
#include ".\\LUA\\src\\lua.hpp"
#include "DlgInput.h"
#include ".\\Disasm\\mediana.h"
#ifndef DLLFILE
lua_State *L;
CDlgLua *pScript=NULL;

void CDlgLua::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX,IDC_SCRIPTTEXT,sScript);
}

BEGIN_MESSAGE_MAP(CDlgLua,CDialog)
	ON_BN_CLICKED(IDC_LOADSCRIPT,&CDlgLua::OnBnClickedLoad)
	ON_BN_CLICKED(IDC_SAVESCRIPT,&CDlgLua::OnBnClickedSave)
	ON_BN_CLICKED(IDC_RUNSCRIPT,&CDlgLua::OnBnClickedRun)
	ON_BN_CLICKED(IDC_CLOSESCRIPT,&CDlgLua::OnBnClickedClose)
	ON_BN_CLICKED(IDC_SAVEASSCRIPT,&CDlgLua::OnBnClickedSaveAs)
	ON_WM_TIMER()
	ON_WM_CLOSE()
END_MESSAGE_MAP()

TSTRING lua_toTString(lua_State *L,int nNumber)
{
#ifdef UNICODE
	const char *pMultiArray=lua_tostring(L,nNumber);
	int nMultiLength=(int)strlen(pMultiArray)+1;
	WCHAR *pWideArray=new WCHAR[nMultiLength];
	MultiByteToWideChar(CP_ACP,0,pMultiArray,nMultiLength,pWideArray,nMultiLength);
	std::wstring sResult=pWideArray;
	delete[] pWideArray;
	return sResult;
#else
	return lua_tostring(L,nNumber);
#endif
}

void lua_pushTString(lua_State *L,const TCHAR *pString)
{
#ifdef UNICODE
	int nWideLength=(int)_tcslen(pString)+1;
	char *pMultiArray=new char[nWideLength];
	WideCharToMultiByte(CP_ACP,0,pString,nWideLength,pMultiArray,nWideLength,NULL,NULL);
	lua_pushstring(L,pMultiArray);
	delete[] pMultiArray;
#else
	lua_pushstring(L,pString);
#endif
}

void l_SetVariables(lua_State *L)
{
	lua_getglobal(L,"append_overlay"); pMain->pInitData->fAppendOverlay=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"autosave_log"); pMain->pInitData->fAutosaveLog=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"break_where"); pMain->BreakWhere=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"cut_module"); pMain->pInitData->dwCutModule=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"cut_sections"); pMain->pInitData->fRemoveSect=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"delphi_init"); pMain->pInitData->fDelphiInit=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"direct_refs"); pMain->pInitData->fDirectRefs=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"execute_functions"); pMain->pInitData->fExecuteFunc=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"first_base"); pMain->FirstVictimBase=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	if(!pMain->UnpackedFile.IsEmpty())
		{lua_getglobal(L,"image_size"); if(lua_tointeger(L,-1)!=0) pMain->UnpackedFile.pPEHeader->OptionalHeader.SizeOfImage=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);}
	else if(!pMain->VictimFile.IsEmpty())
		{lua_getglobal(L,"image_size"); if(lua_tointeger(L,-1)!=0) pMain->VictimFile.pPEHeader->OptionalHeader.SizeOfImage=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);}
	lua_getglobal(L,"import_meth"); pMain->pInitData->ImportRec=(EImpRecType)(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"import_rva"); pMain->pInitData->dwImportRVA=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"jmp_to_oep"); pMain->pInitData->dwOEP=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"leave_direct_refs"); pMain->pInitData->fLeaveDirectRefs=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"long_import"); pMain->pInitData->fLongImport=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"module_end"); pMain->pInitData->dwModuleEnd=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"parameters"); pMain->pInitData->sParameters=lua_toTString(L,-1); lua_pop(L,1);
	lua_getglobal(L,"path_libs"); pMain->pInitData->fPathToLibs=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"process_relocs"); pMain->pInitData->fRelocs=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"protect_dr"); pMain->pInitData->fProtectDr=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"suspect_functions"); pMain->pInitData->fSuspectFunc=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"thread_id"); pMain->State.ThreadID=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"time_delta"); pMain->pInitData->dwTimeDelta=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"unhook_inaction"); pMain->Modules.fUnhookInAction=lua_toboolean(L,-1); lua_pop(L,1);
	if(!pMain->Modules.fUnhookInAction)
		pMain->Modules.SetUnhookedBreaksBack();
	lua_getglobal(L,"use_force"); pMain->pInitData->fForce=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"use_tf"); pMain->pInitData->fUseTf=lua_toboolean(L,-1); lua_pop(L,1);
	lua_getglobal(L,"victim_base"); pMain->VictimBase=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"victim_handle"); pMain->hVictim=(HANDLE)(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"victim_id"); pMain->dwVictimPID=(DWORD)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"EAX"); pMain->State.RegAx=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"EBX"); pMain->State.RegBx=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"ECX"); pMain->State.RegCx=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"EDX"); pMain->State.RegDx=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"EIP"); pMain->State.RegIp=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"EBP"); pMain->State.RegBp=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"ESP"); pMain->State.RegSp=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"ESI"); pMain->State.RegSi=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"EDI"); pMain->State.RegDi=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
#if defined _M_AMD64
	lua_getglobal(L,"R8"); pMain->State.Reg8=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R9"); pMain->State.Reg9=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R10"); pMain->State.Reg10=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R11"); pMain->State.Reg11=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R12"); pMain->State.Reg12=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R13"); pMain->State.Reg13=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R14"); pMain->State.Reg14=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
	lua_getglobal(L,"R15"); pMain->State.Reg15=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
#endif
	lua_getglobal(L,"EFLAGS"); pMain->State.RegFlags=(DWORD_PTR)lua_tointeger(L,-1); lua_pop(L,1);
}

void l_GetVariables(lua_State *L)
{
	lua_pushboolean(L,pMain->pInitData->fAppendOverlay); lua_setglobal(L,"append_overlay");
	lua_pushboolean(L,pMain->pInitData->fAutosaveLog); lua_setglobal(L,"autosave_log");
	lua_pushinteger(L,(lua_Unsigned)pMain->BreakWhere); lua_setglobal(L,"break_where");
	lua_pushinteger(L,pMain->pInitData->dwCutModule); lua_setglobal(L,"cut_module");
	lua_pushboolean(L,pMain->pInitData->fRemoveSect); lua_setglobal(L,"cut_sections");
	lua_pushboolean(L,pMain->pInitData->fDelphiInit); lua_setglobal(L,"delphi_init");
	lua_pushboolean(L,pMain->pInitData->fDirectRefs); lua_setglobal(L,"direct_refs");
	lua_pushboolean(L,pMain->pInitData->fExecuteFunc); lua_setglobal(L,"execute_functions");
	lua_pushTString(L,pMain->pInitData->sVictimFile.c_str()); lua_setglobal(L,"file_name");
	lua_pushinteger(L,(lua_Unsigned)pMain->FirstVictimBase); lua_setglobal(L,"first_base");
	if(!pMain->UnpackedFile.IsEmpty()) lua_pushinteger(L,pMain->UnpackedFile.pPEHeader->OptionalHeader.SizeOfImage);
	else if(!pMain->VictimFile.IsEmpty()) lua_pushinteger(L,pMain->VictimFile.pPEHeader->OptionalHeader.SizeOfImage);
	else lua_pushinteger(L,0); lua_setglobal(L,"image_size");
	lua_pushinteger(L,pMain->pInitData->ImportRec); lua_setglobal(L,"import_meth");
	lua_pushinteger(L,pMain->pInitData->dwImportRVA); lua_setglobal(L,"import_rva");
	lua_pushboolean(L,pMain->pInitData->fIsDll); lua_setglobal(L,"is_dll");
	lua_pushinteger(L,(lua_Unsigned)pMain->pInitData->dwOEP); lua_setglobal(L,"jmp_to_oep");
	lua_pushboolean(L,pMain->pInitData->fLeaveDirectRefs); lua_setglobal(L,"leave_direct_refs");
	lua_pushboolean(L,pMain->pInitData->fLongImport); lua_setglobal(L,"long_import");
	lua_pushinteger(L,pMain->pInitData->dwModuleEnd); lua_setglobal(L,"module_end");
	lua_pushTString(L,pMain->pInitData->sParameters.c_str()); lua_setglobal(L,"parameters");
	lua_pushboolean(L,pMain->pInitData->fPathToLibs); lua_setglobal(L,"path_libs");
	lua_pushinteger(L,RTL_BITS_OF(DWORD_PTR)); lua_setglobal(L,"platform");
	lua_pushboolean(L,pMain->pInitData->fRelocs); lua_setglobal(L,"process_relocs");
	lua_pushboolean(L,pMain->pInitData->fProtectDr); lua_setglobal(L,"protect_dr");
	lua_pushboolean(L,pMain->pInitData->fSuspectFunc); lua_setglobal(L,"suspect_functions");
	lua_pushinteger(L,pMain->State.ThreadID); lua_setglobal(L,"thread_id");
	lua_pushinteger(L,pMain->pInitData->dwTimeDelta); lua_setglobal(L,"time_delta");
	lua_pushboolean(L,pMain->pInitData->fForce); lua_setglobal(L,"use_force");
	lua_pushboolean(L,pMain->pInitData->fUseTf); lua_setglobal(L,"use_tf");
	lua_pushboolean(L,pMain->Modules.fUnhookInAction); lua_setglobal(L,"unhook_inaction");
	lua_pushinteger(L,40300); lua_setglobal(L,"version");
	lua_pushinteger(L,(lua_Unsigned)pMain->VictimBase); lua_setglobal(L,"victim_base");
	lua_pushinteger(L,(lua_Unsigned)(DWORD_PTR)pMain->hVictim); lua_setglobal(L,"victim_handle");
	lua_pushinteger(L,pMain->dwVictimPID); lua_setglobal(L,"victim_id");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegAx); lua_setglobal(L,"EAX");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegBx); lua_setglobal(L,"EBX");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegCx); lua_setglobal(L,"ECX");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDx); lua_setglobal(L,"EDX");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegIp); lua_setglobal(L,"EIP");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegBp); lua_setglobal(L,"EBP");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegSp); lua_setglobal(L,"ESP");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegSi); lua_setglobal(L,"ESI");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDi); lua_setglobal(L,"EDI");
#if defined _M_AMD64
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg8); lua_setglobal(L,"R8");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg9); lua_setglobal(L,"R9");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg10); lua_setglobal(L,"R10");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg11); lua_setglobal(L,"R11");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg12); lua_setglobal(L,"R12");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg13); lua_setglobal(L,"R13");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg14); lua_setglobal(L,"R14");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.Reg15); lua_setglobal(L,"R15");
#endif
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegFlags); lua_setglobal(L,"EFLAGS");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDr0); lua_setglobal(L,"DR0");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDr1); lua_setglobal(L,"DR1");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDr2); lua_setglobal(L,"DR2");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDr3); lua_setglobal(L,"DR3");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDr6); lua_setglobal(L,"DR6");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegDr7); lua_setglobal(L,"DR7");
	lua_pushinteger(L,(lua_Unsigned)pMain->State.RegCS); lua_setglobal(L,"CS");
}

int l_Terminate(lua_State *L)
{
	l_SetVariables(L);
	pMain->Modules.UnHookExport();
	pMain->Terminate();
	pMain->Modules.Clear();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_AddBreak(lua_State *L)
{
	l_SetVariables(L);
	lua_pushboolean(L,pMain->AddBreak((DWORD_PTR)lua_tointeger(L,-3),(EBreakType1)(DWORD)lua_tointeger(L,-2),(EBreakType2)(DWORD)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_AddMemoryBreak(lua_State *L)
{
	l_SetVariables(L);
	lua_pushboolean(L,pMain->AddMemoryBreak((DWORD_PTR)lua_tointeger(L,-2),(DWORD)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_AddModuleToUnhookList(lua_State *L)
{
	l_SetVariables(L);
	TSTRING sTemp(lua_toTString(L,-1));
	for(size_t i=0;i!=pMain->Modules.Modules.size();++i)
	{
		if(_tcsstr(pMain->Modules.Modules[i]->sModuleName.c_str(),sTemp.c_str())!=NULL)
		{
			pMain->Modules.Modules[i]->UnHookExport();
			break;
		}
	}
	std::vector<TSTRING>::iterator it_unhook(pMain->Modules.UnhookModules.begin());
	while(it_unhook!=pMain->Modules.UnhookModules.end())
	{
		if(_tcsstr(sTemp.c_str(),it_unhook->c_str())!=NULL)
			break;

		if(_tcsstr(it_unhook->c_str(),sTemp.c_str())!=NULL)
			it_unhook=pMain->Modules.UnhookModules.erase(it_unhook);
		else
			++it_unhook;
	}
	if(it_unhook==pMain->Modules.UnhookModules.end())
		pMain->Modules.UnhookModules.push_back(sTemp);
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_AddSection(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		BYTE *bTemp;
		__try
		{
			bTemp=new BYTE[(DWORD_PTR)lua_tointeger(L,-1)];
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			lua_pushinteger(L,-1);
			l_GetVariables(L);
			return 1;
		}
		memcpy(bTemp,lua_tolstring(L,-2,0),(DWORD_PTR)lua_tointeger(L,-1));
		pMain->UnpackedFile.CreateSection(lua_tostring(L,-3),bTemp,(DWORD)lua_tointeger(L,-1),IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);
		lua_pushinteger(L,0);
		delete[] bTemp;
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_Attach(lua_State *L)
{
	l_SetVariables(L);
	l_Terminate(L);
	lua_pop(L,1);
	pMain->Modules.UnHookExport();
	pMain->Modules.Clear();
	pMain->DeleteBreakAll();
	pDlgMain->OnBnClickedAttach();
	pMain->hVictim=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pMain->pInitData->dwPID);
	pMain->VictimBase=pMain->pInitData->ImageBase;
	pMain->Attach();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_AttachFast(lua_State *L)
{
	l_SetVariables(L);
	pMain->Modules.UnHookExport();
	pMain->Modules.Clear();
	pMain->DisableBreakAll();
	pMain->pInitData->dwPID=(DWORD)lua_tointeger(L,-2);
	pMain->pInitData->dwTID=(DWORD)lua_tointeger(L,-1);
	CloseHandle(pMain->hVictim);
	pMain->hVictim=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pMain->pInitData->dwPID);
	pMain->Attach();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_CheckMemory(lua_State *L)
{
	l_SetVariables(L);

	MEMORY_BASIC_INFORMATION MemInfo;
	if(VirtualQueryEx(pMain->hVictim,(void*)(DWORD_PTR)lua_tointeger(L,-1),&MemInfo,sizeof(MemInfo))!=sizeof(MemInfo))
		lua_pushinteger(L,0);
	else
	{
		if(MemInfo.State!=MEM_COMMIT)
			lua_pushinteger(L,0);
		else if((MemInfo.Protect & PAGE_GUARD)==PAGE_GUARD)
			lua_pushinteger(L,3);
		else if((MemInfo.Protect & 0xff)==PAGE_NOACCESS)
			lua_pushinteger(L,1);
		else
			lua_pushinteger(L,2);
	}

	l_GetVariables(L);
	return 1;
}

int l_ClearImport(lua_State *L)
{
	l_SetVariables(L);
	pMain->Import.Clear();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ClearLog(lua_State *L)
{
	l_SetVariables(L);
	ClearLog();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ClearModules(lua_State *L)
{
	l_SetVariables(L);
	pMain->Modules.Clear();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ClearRelocs(lua_State *L)
{
	l_SetVariables(L);
	pMain->FixUp.Clear();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ClearUnhookList(lua_State *L)
{
	l_SetVariables(L);
	pMain->Modules.UnhookModules.clear();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Continue(lua_State *L)
{
	l_SetVariables(L);
	do pMain->Continue();
	while(pMain->BreakWhere==bFunction && lua_toboolean(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_CutSections(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->UnpackedFile.CutSections();
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_DeleteBreak(lua_State *L)
{
	l_SetVariables(L);
	lua_pushboolean(L,pMain->DeleteBreak((DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_DeleteBreakAll(lua_State *L)
{
	l_SetVariables(L);
	pMain->DeleteBreakAll();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_DeleteLastSection(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->UnpackedFile.DeleteLastSection();
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_DeleteMemoryBreaks(lua_State *L)
{
	l_SetVariables(L);
	pMain->DeleteMemoryBreaks();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Detach(lua_State *L)
{
	l_SetVariables(L);
	pMain->Detach();
	CloseHandle(pMain->hVictim);
	pMain->hVictim=NULL;
	pMain->FirstVictimBase=pMain->VictimBase;
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_DisableBreak(lua_State *L)
{
	l_SetVariables(L);
	lua_pushboolean(L,pMain->DisableBreak((DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_DisableBreakAll(lua_State *L)
{
	l_SetVariables(L);
	pMain->DisableBreakAll();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Disasm(lua_State *L)
{
	CDlgDisasm DlgDisasm;
	BYTE bBuffer[INSTRS_TO_DISASM*MAX_INSTRUCTION_LEN];

	l_SetVariables(L);

	if(pMain->ReadMem((DWORD_PTR)lua_tointeger(L,-1),&bBuffer,sizeof(bBuffer))!=0)
	{
		DlgDisasm.pAddr=(void*)bBuffer;
		DlgDisasm.AltAddress=(DWORD_PTR)lua_tointeger(L,-1);
		if(DlgDisasm.DoModal()==IDOK)
			lua_pushinteger(L,1);
		else
			lua_pushinteger(L,2);
	}
	else
		lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Dump(lua_State *L)
{
	l_SetVariables(L);
	pMain->UnpackedFile.Clear();
	pMain->UnpackedFile.Dump(pMain->hVictim,pMain->VictimBase,&pMain->VictimFile,csMemoryManager);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->UnpackedFile.pPEHeader->OptionalHeader.ImageBase=pMain->VictimBase;
		pMain->UnpackedFile.pPEHeader->OptionalHeader.AddressOfEntryPoint=(DWORD)(pMain->State.RegIp-pMain->VictimBase);
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_DumpForRelocs(lua_State *L)
{
	l_SetVariables(L);
	pMain->FirstVictimBase=pMain->VictimBase;
	pMain->VirginVictim.Clear();
	pMain->VirginVictim.Dump(pMain->hVictim,pMain->VictimBase,&pMain->VictimFile,csSimple);
	if(!pMain->VirginVictim.IsEmpty())
	{
		pMain->VirginVictim.pPEHeader->OptionalHeader.ImageBase=pMain->VictimBase;
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_EmulateCPUID(lua_State *L)
{
	l_SetVariables(L);
	pMain->EmulateCPUID((DWORD)lua_tointeger(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_EmulateRDTSC(lua_State *L)
{
	l_SetVariables(L);
	pMain->EmulateRDTSC((DWORD)lua_tointeger(L,-2),(DWORD)lua_tointeger(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_EnableBreak(lua_State *L)
{
	l_SetVariables(L);
	lua_pushboolean(L,pMain->EnableBreak((DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_ExecuteFunction(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->ExecuteFunction(lua_toTString(L,-7).c_str(),(char*)lua_tostring(L,-6),(DWORD_PTR)lua_tointeger(L,-5),
		(DWORD_PTR)lua_tointeger(L,-4),(DWORD_PTR)lua_tointeger(L,-3),(DWORD_PTR)lua_tointeger(L,-2),(DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_Find(lua_State *L)
{
	l_SetVariables(L);
	BYTE *bTemp;
	__try
	{
		bTemp=new BYTE[(DWORD_PTR)lua_tointeger(L,-3)];
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		lua_pushinteger(L,0);
		l_GetVariables(L);
		return 1;
	}
	memcpy(bTemp,lua_tolstring(L,-4,0),(DWORD_PTR)lua_tointeger(L,-3));
	lua_pushinteger(L,(lua_Unsigned)pMain->Find(bTemp,(int)lua_tointeger(L,-3),(DWORD_PTR)lua_tointeger(L,-2),(DWORD_PTR)lua_tointeger(L,-1)));
	delete[] bTemp;
	l_GetVariables(L);
	return 1;
}

int l_FindByMask(lua_State *L)
{
	l_SetVariables(L);
	BYTE *bTemp;
	__try
	{
		bTemp=new BYTE[(DWORD_PTR)lua_tointeger(L,-3)];
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		lua_pushinteger(L,0);
		l_GetVariables(L);
		return 1;
	}
	memcpy(bTemp,lua_tolstring(L,-4,0),(DWORD_PTR)lua_tointeger(L,-3));
	lua_pushinteger(L,(lua_Unsigned)pMain->FindByMask(bTemp,(int)lua_tointeger(L,-3),(DWORD_PTR)lua_tointeger(L,-2),(DWORD_PTR)lua_tointeger(L,-1)));
	delete[] bTemp;
	l_GetVariables(L);
	return 1;
}

int l_FindOEP(lua_State *L)
{
	l_SetVariables(L);
	pDlgMain->OnBnClickedFindOEP();
	pMain->pInitData->dwOEP=_tcstoul(pDlgMain->sOEPbox.GetString(),NULL,16);
	lua_pushinteger(L,(lua_Unsigned)pMain->pInitData->dwOEP);
	l_GetVariables(L);
	return 1;
}

int l_FullUnpack(lua_State *L)
{
	l_SetVariables(L);
	if(pMain->pInitData->UnpackMode==umSkipOEP)
		pMain->UnpackSkipOEP();
	else
		pMain->FullUnpack();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_GetModuleAddress(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->GetModHandle(pMain->dwVictimPID,lua_toTString(L,-1).c_str()));
	l_GetVariables(L);
	return 1;
}

int l_GetOrdinalAddress(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->GetOrdinalAddress(lua_toTString(L,-2).c_str(),(WORD)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_GetProcAddress(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->GetProcedureAddress(lua_toTString(L,-2).c_str(),lua_tostring(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_Hook(lua_State *L)
{
	l_SetVariables(L);
	pMain->Hook((DWORD)lua_tointeger(L,-4),(DWORD)lua_tointeger(L,-3),(DWORD)lua_tointeger(L,-2),
		(DWORD)lua_tointeger(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_IdentifyAddressLib(lua_State *L)
{
	l_SetVariables(L);
	DWORD_PTR Address=(DWORD_PTR)lua_tointeger(L,-1);
	if(Address>=pMain->VictimBase && Address<pMain->VictimBase+pMain->VictimFile.pPEHeader->OptionalHeader.SizeOfImage)
		lua_pushTString(L,pMain->pInitData->sVictimName.c_str());
	else
	{
		size_t i=0;
		for(;i!=pMain->Modules.Modules.size();++i)
		{
			if(Address>=pMain->Modules.Modules[i]->ModuleBase &&
				Address<pMain->Modules.Modules[i]->ModuleBase+pMain->Modules.Modules[i]->dwModuleSize)
				break;
		}
		if(i!=pMain->Modules.Modules.size())
			lua_pushTString(L,pMain->Modules.Modules[i]->sModuleName.c_str());
		else
			lua_pushinteger(L,-1);
	}
	l_GetVariables(L);
	return 1;
}

int l_IdentifyFuncLib(lua_State *L)
{
	CImportRecord ImportRecord;

	l_SetVariables(L);
	pMain->IdentifyFunction(ImportRecord,(DWORD_PTR)lua_tointeger(L,-1));
	if(ImportRecord.Exist())
		lua_pushTString(L,ImportRecord.sLibName.c_str());
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_IdentifyFuncName(lua_State *L)
{
	CImportRecord ImportRecord;

	l_SetVariables(L);
	pMain->IdentifyFunction(ImportRecord,(DWORD_PTR)lua_tointeger(L,-1));
	if(ImportRecord.Exist())
		lua_pushstring(L,ImportRecord.sApiName.c_str());
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_IdentifyFuncOrdinal(lua_State *L)
{
	CImportRecord ImportRecord;

	l_SetVariables(L);
	pMain->IdentifyFunction(ImportRecord,(DWORD_PTR)lua_tointeger(L,-1));
	if(ImportRecord.Exist())
		lua_pushinteger(L,ImportRecord.wOrdinal);
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ImportAdd(lua_State *L)
{
	l_SetVariables(L);

	WORD wPrev=0;
	DWORD_PTR redir1=0,redir2=0;
	DWORD dwResult=0,dwRVA=(DWORD)lua_tointeger(L,-1);
	CImportRecord ImportRecord;

	if(pMain->ReadMem(dwRVA+pMain->VictimBase,&wPrev,sizeof(wPrev))==0)
		dwResult=1;
	if(pMain->ReadMem(dwRVA+pMain->VictimBase+2,&redir1,sizeof(DWORD))==0)
		dwResult=1;

	if(wPrev==0x15ff || wPrev==0x25ff)
	{
#if defined _M_AMD64
		redir1=dwRVA+2+sizeof(DWORD)+pMain->VictimBase+(LONG)redir1;
#endif
		if(pMain->ReadMem(redir1,&redir2,sizeof(redir2))==0)
			redir2=0;
		pMain->IdentifyFunction(ImportRecord,redir2);
		if(ImportRecord.Exist() || (pMain->pInitData->fSuspectFunc && redir2!=0))
		{
			ImportRecord.dwReferenceRVA=dwRVA+2;
			ImportRecord.dwRecordRVA=(DWORD)(redir1-pMain->VictimBase);
			if(wPrev==0x15ff)
				ImportRecord.Type=itIndirectCall;
			else
				ImportRecord.Type=itIndirectJmp;
			pMain->Import.AddRecord(ImportRecord);
		}
		else
			dwResult=3;
	}
	else if(wPrev==0x35ff ||
		(((wPrev>>8)==0x0d || (wPrev>>8)==0x1d || (wPrev>>8)==0x2d || (wPrev>>8)==0x3d ||
		(wPrev>>8)==0x05 || (wPrev>>8)==0x15 || (wPrev>>8)==0x25 || (wPrev>>8)==0x35) &&
		((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40)))
	{
#if defined _M_AMD64
		redir1=dwRVA+2+sizeof(DWORD)+pMain->VictimBase+(LONG)redir1;
#endif
		if(pMain->ReadMem(redir1,&redir2,sizeof(redir2))==0)
			redir2=0;
		pMain->IdentifyFunction(ImportRecord,redir2);
		if(ImportRecord.Exist() || (pMain->pInitData->fSuspectFunc && redir2!=0))
		{
			ImportRecord.dwReferenceRVA=dwRVA+2;
			ImportRecord.dwRecordRVA=(DWORD)(redir1-pMain->VictimBase);
			ImportRecord.Type=itIndirectOther;
			pMain->Import.AddRecord(ImportRecord);
		}
		else
			dwResult=3;
	}
	else if((wPrev>>8)==0xa1)
	{
		pMain->ReadMem(dwRVA+pMain->VictimBase+2,&redir1,sizeof(redir1));
		if(pMain->ReadMem(redir1,&redir2,sizeof(redir2))==0)
			redir2=0;
		pMain->IdentifyFunction(ImportRecord,redir2);
		if(ImportRecord.Exist() || (pMain->pInitData->fSuspectFunc && redir2!=0))
		{
			ImportRecord.dwReferenceRVA=dwRVA+2;
			ImportRecord.dwRecordRVA=(DWORD)(redir1-pMain->VictimBase);
			ImportRecord.Type=itIndirectAx;
			pMain->Import.AddRecord(ImportRecord);
		}
		else
			dwResult=3;
	}
	else if(pMain->pInitData->fDirectRefs && ((wPrev>>8)==0xe8 || (wPrev>>8)==0xe9))
	{
		redir1=dwRVA+pMain->VictimBase+2;
		if(pMain->ReadMem(redir1,&redir2,sizeof(DWORD))==0)
			redir2=0;
		redir2=redir1+sizeof(DWORD)+(LONG)redir2;
#if defined _M_AMD64
		if(!pMain->IsAddressInModule(redir2))
		{
			DWORD redir3;
			if(pMain->ReadMem(redir2+2,&redir3,sizeof(redir3))==0)
				redir2=0;
			redir2+=2+sizeof(DWORD)+(LONG)redir3;
			if(pMain->ReadMem(redir2,&redir2,sizeof(redir2))==0)
				redir2=0;
		}
#endif
		pMain->IdentifyFunction(ImportRecord,redir2);
		if(ImportRecord.Exist())
		{
			if(!pMain->pInitData->fLeaveDirectRefs)
			{
//				if(pMain->NextInstr(redir1+4)!=(redir1+5) && pMain->NextInstr(redir1-2)==(redir1-1))
//					--redir1;
				if(pMain->ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
					--redir1;
				else if(pMain->ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
					--redir1;
			}
			ImportRecord.dwReferenceRVA=(DWORD)(redir1-pMain->VictimBase+1);
			if((wPrev>>8)==0xe8)
				ImportRecord.Type=itDirectCall;
			else
				ImportRecord.Type=itDirectJmp;
			pMain->Import.AddRecord(ImportRecord);
		}
		else
			dwResult=3;
	}
#if defined _M_IX86
	else if(pMain->pInitData->fDirectRefs && (((wPrev>>8) & 0xf8)==0xb8 || (wPrev>>8)==0x68))
	{
		redir1=dwRVA+pMain->VictimBase+2;
		if(pMain->ReadMem(redir1,&redir2,sizeof(DWORD))==0)
			redir2=0;
		pMain->IdentifyFunction(ImportRecord,redir2);
		if(ImportRecord.Exist())
		{
			if(!pMain->pInitData->fLeaveDirectRefs)
			{
//				if(pMain->NextInstr(redir1+4)!=(redir1+5) && pMain->NextInstr(redir1-2)==(redir1-1))
//					--redir1;
				if(pMain->ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x90))
					--redir1;
				else if(pMain->ReadMem(redir1-2,&redir2,1)!=0 && ((redir2 & MAXBYTE)==0x3e))
					--redir1;
			}
			ImportRecord.dwReferenceRVA=(DWORD)(redir1-pMain->VictimBase+1);
			ImportRecord.Type=itDirectOther;
			pMain->Import.AddRecord(ImportRecord);
		}
		else
			dwResult=3;
	}
#endif
	else if(dwResult==0)
		dwResult=2;

	lua_pushinteger(L,dwResult);
	l_GetVariables(L);
	return 1;
}

int l_ImportTraceAdd(lua_State *L)
{
	l_SetVariables(L);

	EImportRecordType k;
	WORD wPrev=0;
	DWORD_PTR garb1,garb2,redir1=0;
	DWORD dwResult=0,dwRVA=(DWORD)lua_tointeger(L,-1);
	CImportRecord ImportRecord;

	pMain->SuspendAllOther();
	pMain->bLastSEH=pMain->SetLastSEH();
	pMain->bOEP=pMain->bLastSEH+16;
	pMain->AddBreak(pMain->bOEP);
	pMain->AddBreak(pMain->bLastSEH);

	if(pMain->ReadMem(dwRVA+pMain->VictimBase,&wPrev,sizeof(wPrev))==0)
		dwResult=1;
	if(pMain->ReadMem(dwRVA+pMain->VictimBase+2,&redir1,sizeof(DWORD))==0)
		dwResult=1;

	if(wPrev==0x15ff || wPrev==0x25ff)
	{
#if defined _M_AMD64
		redir1=dwRVA+2+sizeof(DWORD)+pMain->VictimBase+(LONG)redir1;
#endif
		garb1=pMain->State.RegSp;
		garb2=pMain->State.RegIp;
		if(wPrev==0x15ff)
		{
			if(pMain->FindTrace(dwRVA+2,redir1,itIndirectCall)==0)
				dwResult=3;
		}
		else
		{
			if(pMain->FindTrace(dwRVA+2,redir1,itIndirectJmp)==0)
				dwResult=3;
		}
		pMain->State.RegSp=garb1;
		pMain->State.RegIp=garb2;
	}
	else if(wPrev==0x35ff ||
		(((wPrev>>8)==0x0d || (wPrev>>8)==0x1d || (wPrev>>8)==0x2d || (wPrev>>8)==0x3d ||
		(wPrev>>8)==0x05 || (wPrev>>8)==0x15 || (wPrev>>8)==0x25 || (wPrev>>8)==0x35) &&
		((wPrev & MAXBYTE)==0x8b || (wPrev & 0xf0)==0x40)))
	{
#if defined _M_AMD64
		redir1=dwRVA+2+sizeof(DWORD)+pMain->VictimBase+(LONG)redir1;
#endif
		garb1=pMain->State.RegSp;
		garb2=pMain->State.RegIp;
		if(pMain->FindTrace(dwRVA+2,redir1,itIndirectOther)==0)
			dwResult=3;
		pMain->State.RegSp=garb1;
		pMain->State.RegIp=garb2;
	}
	else if((wPrev>>8)==0xa1)
	{
		pMain->ReadMem(dwRVA+pMain->VictimBase+2,&redir1,sizeof(redir1));
		garb1=pMain->State.RegSp;
		garb2=pMain->State.RegIp;
		if(pMain->FindTrace(dwRVA+2,redir1,itIndirectAx)==0)
			dwResult=3;
		pMain->State.RegSp=garb1;
		pMain->State.RegIp=garb2;
	}
	else if(pMain->pInitData->fDirectRefs && ((wPrev>>8)==0xe8 || (wPrev>>8)==0xe9))
	{
		if(pMain->ReadMem(dwRVA+pMain->VictimBase+2,&redir1,sizeof(DWORD))==0)
			dwResult=1;
		garb1=pMain->State.RegSp;
		garb2=pMain->State.RegIp;
		if((wPrev>>8)==0xe8)
			k=itDirectCall;
		else
			k=itDirectJmp;
		if(pMain->FindTrace(dwRVA+2,dwRVA+2,k)==0)
			dwResult=3;
		pMain->State.RegSp=garb1;
		pMain->State.RegIp=garb2;
	}
#if defined _M_IX86
	else if(pMain->pInitData->fDirectRefs && (((wPrev>>8) & 0xf8)==0xb8 || (wPrev>>8)==0x68))
	{
		if(pMain->ReadMem(dwRVA+pMain->VictimBase+2,&redir1,sizeof(DWORD))==0)
			dwResult=1;
		garb1=pMain->State.RegSp;
		garb2=pMain->State.RegIp;
		if(pMain->FindTrace(dwRVA+2,dwRVA+2,itDirectOther)==0)
			dwResult=3;
		pMain->State.RegSp=garb1;
		pMain->State.RegIp=garb2;
	}
#endif
	else if(dwResult==0)
		dwResult=2;

	pMain->DeleteBreak(pMain->bLastSEH);
	pMain->DeleteBreak(pMain->bOEP);
	pMain->RemoveLastSEH(pMain->bLastSEH);
	pMain->ResumeAllOther();

	lua_pushinteger(L,dwResult);
	l_GetVariables(L);
	return 1;
}

int l_InputValue(lua_State *L)
{
	l_SetVariables(L);
	TSTRING sValue;
	CDlgInput DlgInput(&sValue,lua_toTString(L,-2).c_str(),lua_toTString(L,-1).c_str());
	if(DlgInput.DoModal()==IDOK)
		lua_pushTString(L,sValue.c_str());
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_InputYesNo(lua_State *L)
{
	l_SetVariables(L);
	if(MessageBox(NULL,lua_toTString(L,-1).c_str(),lua_toTString(L,-2).c_str(),MB_YESNO)==IDYES)
		lua_pushinteger(L,1);
	else
		lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_IsEnabled(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,pMain->IsEnabled((DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_IsExist(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,pMain->IsExist((DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_KillTimer(lua_State *L)
{
	l_SetVariables(L);
	SetEvent(pScript->hTimerEvent);
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_LoadExtraLibrary(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->LoadExtraLibrary(lua_toTString(L,-1).c_str()));
	l_GetVariables(L);
	return 1;
}

int l_ModuleHook(lua_State *L)
{
	l_SetVariables(L);
	pMain->Modules.AddModule((DWORD_PTR)lua_tointeger(L,-1),true);
	if(pMain->pInitData->ImportRec==irSmartTracer)
		pMain->Modules.HookExport();
	else
		lua_pushinteger(L,-1);
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ModuleUnhook(lua_State *L)
{
	l_SetVariables(L);
	DWORD_PTR ModuleBase=(DWORD_PTR)lua_tointeger(L,-1);
	for(size_t i=0;i!=pMain->Modules.Modules.size();++i)
	{
		if(pMain->Modules.Modules[i]->ModuleBase==ModuleBase)
		{
			pMain->Modules.Modules[i]->UnHookExport();
			break;
		}
	}
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_NextInstr(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->NextInstr((DWORD_PTR)lua_tointeger(L,-1)));
	l_GetVariables(L);
	return 1;
}

int l_Pause(lua_State *L)
{
	l_SetVariables(L);
	MessageBox(NULL,lua_toTString(L,-1).c_str(),_T("QuickUnpack"),MB_OK);
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_PreLoad(lua_State *L)
{
	l_SetVariables(L);
	l_Terminate(L);
	lua_pop(L,1);
	pMain->pInitData->fForce=TRUE;
	if(pMain->pInitData->fIsDll)
		lua_pushinteger(L,pMain->PreLoadDLL());
	else
		lua_pushinteger(L,pMain->PreLoad());
	l_GetVariables(L);
	return 1;
}

int l_ProcessDelphiInit(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->RestoreDelphiInit(lua_toboolean(L,-1)!=FALSE);
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ProcessExport(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->UnpackedFile.ProcessExport();
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ProcessOverlay(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		if(pMain->pInitData->fAppendOverlay)
		{
			pMain->UnpackedFile.PreserveOverlay(pMain->VictimFile);
			WriteLog(overlayappended);
		}
		else if(!pMain->VictimFile.bOverlay.empty())
			WriteEx(overlayexists,TRUE,TRUE,RGB(255,0,0));
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ProcessRelocs(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->ProcessRelocation();
		pMain->FixUp.SaveToFile(pMain->UnpackedFile);
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ProcessResources(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->UnpackedFile.ProcessResources();
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ProcessTLS(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->UnpackedFile.ProcessTLS();
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_ReadMem(lua_State *L)
{
	l_SetVariables(L);
	DWORD_PTR Temp=0;
	if(0<lua_tointeger(L,-1) && lua_tointeger(L,-1)<=sizeof(DWORD_PTR) &&
		pMain->ReadMem((DWORD_PTR)lua_tointeger(L,-2),&Temp,(DWORD_PTR)lua_tointeger(L,-1))==(DWORD_PTR)lua_tointeger(L,-1))
	{
		lua_pushinteger(L,Temp);
	}
	else
	{
		WriteEx(errorreadingmem+IntToStr((DWORD_PTR)lua_tointeger(L,-2),16,sizeof(DWORD_PTR)*2),TRUE,TRUE,RGB(255,0,0));
		lua_pushinteger(L,0);
	}
	l_GetVariables(L);
	return 1;
}

int l_ReadMemDump(lua_State *L)
{
	l_SetVariables(L);
	BYTE *bRVA=pMain->UnpackedFile.RVA((DWORD)lua_tointeger(L,-2));
	if(bRVA!=0)
	{
		if(lua_tointeger(L,-1)==1)
			lua_pushinteger(L,*(BYTE*)bRVA);
		else if(lua_tointeger(L,-1)==2)
			lua_pushinteger(L,*(WORD*)bRVA);
		else if(lua_tointeger(L,-1)==4)
			lua_pushinteger(L,*(DWORD*)bRVA);
		else
			lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ReadMemLarge(lua_State *L)
{
	l_SetVariables(L);
	BYTE *bTemp;
	__try
	{
		bTemp=new BYTE[(DWORD_PTR)lua_tointeger(L,-1)];
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		lua_pushinteger(L,0);
		l_GetVariables(L);
		return 1;
	}
	memset(bTemp,0,(DWORD_PTR)lua_tointeger(L,-1));
	pMain->ReadMem((DWORD_PTR)lua_tointeger(L,-2),bTemp,(DWORD_PTR)lua_tointeger(L,-1));
	lua_pushlstring(L,(char*)bTemp,(DWORD_PTR)lua_tointeger(L,-1));
	delete[] bTemp;
	l_GetVariables(L);
	return 1;
}

int l_RemoveLastSEH(lua_State *L)
{
	l_SetVariables(L);
	pMain->RemoveLastSEH((DWORD_PTR)lua_tointeger(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_RestoreImportRelocs(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->RestoreImportRelocs();
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_Resume(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->Resume());
	l_GetVariables(L);
	return 1;
}

int l_ResumeAllOther(lua_State *L)
{
	l_SetVariables(L);
	pMain->ResumeAllOther();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_SaveFile(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		if(pMain->UnpackedFile.RVA(pMain->UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)!=NULL)
			((IMAGE_TLS_DIRECTORY*)pMain->UnpackedFile.RVA(pMain->UnpackedFile.pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress))->AddressOfCallBacks=0;
		pMain->UnpackedFile.Save(pMain->pInitData->sUnpackedFile.c_str());
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_SaveImport(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		pMain->Import.SaveToFile(pMain->UnpackedFile,pMain->pInitData->dwImportRVA);
		pMain->pInitData->sUnpackedFile=pMain->pInitData->sUnpackedLong;
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_SetLastSEH(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->SetLastSEH());
	l_GetVariables(L);
	return 1;
}

int l_SetMainBreaks(lua_State *L)
{
	l_SetVariables(L);
	pMain->SetMainBreaks();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_ShowImport(lua_State *L)
{
	l_SetVariables(L);
	if(!pMain->UnpackedFile.IsEmpty())
	{
		CDlgImport DlgImport(&pMain->Import,&pMain->UnpackedFile,&pMain->Modules,pMain->pInitData->sVictimFile.c_str(),pMain);
		pMain->ChangeForwardedImport();
		pMain->Import.RedirectToOldIAT(false,NULL,NULL);
		EnableWindow(pMain->pInitData->hMain,FALSE);
		DlgImport.DoModal();
		EnableWindow(pMain->pInitData->hMain,TRUE);
		SetForegroundWindow(pMain->pInitData->hMain);
		lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,-1);
	l_GetVariables(L);
	return 1;
}

int l_Start(lua_State *L)
{
	l_SetVariables(L);
	l_Terminate(L);
	lua_pop(L,1);
	pMain->Start(true,lua_toboolean(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Stop(lua_State *L)
{
	l_SetVariables(L);
	pMain->Stop();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Suspend(lua_State *L)
{
	l_SetVariables(L);
	lua_pushinteger(L,(lua_Unsigned)pMain->Suspend());
	l_GetVariables(L);
	return 1;
}

int l_SuspendAllOther(lua_State *L)
{
	l_SetVariables(L);
	pMain->SuspendAllOther();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_TerminateOnTimer(lua_State *L)
{
	l_SetVariables(L);
	ResetEvent(pScript->hTimerEvent);
	pScript->dwTimerTimeout=(DWORD)lua_tointeger(L,-1);
	SetEvent(pScript->hInitialEvent);
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Trace(lua_State *L)
{
	l_SetVariables(L);
	pMain->Trace();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_TraceAndReplace(lua_State *L)
{
	l_SetVariables(L);
	pMain->TraceAndReplace((DWORD_PTR)lua_tointeger(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_Wait(lua_State *L)
{
	l_SetVariables(L);
	pMain->Wait();
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_WriteEx(lua_State *L)
{
	l_SetVariables(L);
	WriteEx(lua_toTString(L,-4).c_str(),lua_toboolean(L,-3),lua_toboolean(L,-2),(COLORREF)lua_tointeger(L,-1));
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_WriteLog(lua_State *L)
{
	l_SetVariables(L);
	WriteLog(lua_toTString(L,-1).c_str());
	lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_WriteMem(lua_State *L)
{
	l_SetVariables(L);
	DWORD_PTR Temp=(DWORD_PTR)lua_tointeger(L,-2);
	if(0<lua_tointeger(L,-1) && lua_tointeger(L,-1)<=sizeof(DWORD_PTR))
		lua_pushinteger(L,(lua_Unsigned)pMain->WriteMem((DWORD_PTR)lua_tointeger(L,-3),&Temp,(DWORD_PTR)lua_tointeger(L,-1)));
	else
		lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_WriteMemDump(lua_State *L)
{
	l_SetVariables(L);
	DWORD dwValue=(DWORD)lua_tointeger(L,-2);
	BYTE *bRVA=pMain->UnpackedFile.RVA((DWORD)lua_tointeger(L,-3));
	if(bRVA!=0)
	{
		if(lua_tointeger(L,-1)==1)
		{
			*(BYTE*)bRVA=(BYTE)dwValue;
			lua_pushinteger(L,sizeof(BYTE));
		}
		else if(lua_tointeger(L,-1)==2)
		{
			*(WORD*)bRVA=(WORD)dwValue;
			lua_pushinteger(L,sizeof(WORD));
		}
		else if(lua_tointeger(L,-1)==4)
		{
			*(DWORD*)bRVA=dwValue;
			lua_pushinteger(L,sizeof(DWORD));
		}
		else
			lua_pushinteger(L,0);
	}
	else
		lua_pushinteger(L,0);
	l_GetVariables(L);
	return 1;
}

int l_WriteMemLarge(lua_State *L)
{
	l_SetVariables(L);
	BYTE *bTemp;
	__try
	{
		bTemp=new BYTE[(DWORD_PTR)lua_tointeger(L,-1)];
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		lua_pushinteger(L,0);
		l_GetVariables(L);
		return 1;
	}
	memcpy(bTemp,lua_tolstring(L,-2,0),(DWORD_PTR)lua_tointeger(L,-1));
	lua_pushinteger(L,(lua_Unsigned)pMain->WriteMem((DWORD_PTR)lua_tointeger(L,-3),bTemp,(DWORD_PTR)lua_tointeger(L,-1)));
	delete[] bTemp;
	l_GetVariables(L);
	return 1;
}

DWORD __stdcall TimerThread(void*)
{
	for(;;)
	{
		while(pScript==NULL)
			SwitchToThread();
		WaitForSingleObject(pScript->hInitialEvent,INFINITE);
		if(WaitForSingleObject(pScript->hTimerEvent,pScript->dwTimerTimeout)==WAIT_TIMEOUT)
			pMain->Stop();
	}
	return 0;
}

IMPLEMENT_DYNAMIC(CDlgLua,CDialog)
CDlgLua::CDlgLua(CInitData *pInitData):CDialog(CDlgLua::IDD,NULL)
{
	if(pMain==NULL)
		pMain=new CMain(pInitData);

	hInitialEvent=CreateEvent(NULL,FALSE,FALSE,NULL);
	hTimerEvent=CreateEvent(NULL,FALSE,FALSE,NULL);
	hTimerThread=CreateThread(NULL,0,TimerThread,NULL,0,NULL);

	L=luaL_newstate();
	if(L==NULL)
	{
		WriteEx(cantluastate,TRUE,TRUE,RGB(255,0,0));
		return;
	}
	luaL_openlibs(L);

	lua_register(L,"AddBreak",l_AddBreak);
	lua_register(L,"AddMemoryBreak",l_AddMemoryBreak);
	lua_register(L,"AddModuleToUnhookList",l_AddModuleToUnhookList);
	lua_register(L,"AddSection",l_AddSection);
	lua_register(L,"Attach",l_Attach);
	lua_register(L,"AttachFast",l_AttachFast);
	lua_register(L,"CheckMemory",l_CheckMemory);
	lua_register(L,"ClearImport",l_ClearImport);
	lua_register(L,"ClearLog",l_ClearLog);
	lua_register(L,"ClearModules",l_ClearModules);
	lua_register(L,"ClearRelocs",l_ClearRelocs);
	lua_register(L,"ClearUnhookList",l_ClearUnhookList);
	lua_register(L,"Continue",l_Continue);
	lua_register(L,"CutSections",l_CutSections);
	lua_register(L,"DeleteBreak",l_DeleteBreak);
	lua_register(L,"DeleteBreakAll",l_DeleteBreakAll);
	lua_register(L,"DeleteLastSection",l_DeleteLastSection);
	lua_register(L,"DeleteMemoryBreaks",l_DeleteMemoryBreaks);
	lua_register(L,"Detach",l_Detach);
	lua_register(L,"DisableBreak",l_DisableBreak);
	lua_register(L,"DisableBreakAll",l_DisableBreakAll);
	lua_register(L,"Disasm",l_Disasm);
	lua_register(L,"Dump",l_Dump);
	lua_register(L,"DumpForRelocs",l_DumpForRelocs);
	lua_register(L,"EmulateCPUID",l_EmulateCPUID);
	lua_register(L,"EmulateRDTSC",l_EmulateRDTSC);
	lua_register(L,"EnableBreak",l_EnableBreak);
	lua_register(L,"ExecuteFunction",l_ExecuteFunction);
	lua_register(L,"Find",l_Find);
	lua_register(L,"FindByMask",l_FindByMask);
	lua_register(L,"FindOEP",l_FindOEP);
	lua_register(L,"FullUnpack",l_FullUnpack);
	lua_register(L,"GetModuleAddress",l_GetModuleAddress);
	lua_register(L,"GetOrdinalAddress",l_GetOrdinalAddress);
	lua_register(L,"GetProcAddress",l_GetProcAddress);
	lua_register(L,"Hook",l_Hook);
	lua_register(L,"IdentifyAddressLib",l_IdentifyAddressLib);
	lua_register(L,"IdentifyFuncLib",l_IdentifyFuncLib);
	lua_register(L,"IdentifyFuncName",l_IdentifyFuncName);
	lua_register(L,"IdentifyFuncOrdinal",l_IdentifyFuncOrdinal);
	lua_register(L,"ImportAdd",l_ImportAdd);
	lua_register(L,"ImportTraceAdd",l_ImportTraceAdd);
	lua_register(L,"InputValue",l_InputValue);
	lua_register(L,"InputYesNo",l_InputYesNo);
	lua_register(L,"IsEnabled",l_IsEnabled);
	lua_register(L,"IsExist",l_IsExist);
	lua_register(L,"KillTimer",l_KillTimer);
	lua_register(L,"LoadExtraLibrary",l_LoadExtraLibrary);
	lua_register(L,"ModuleHook",l_ModuleHook);
	lua_register(L,"ModuleUnhook",l_ModuleUnhook);
	lua_register(L,"NextInstr",l_NextInstr);
	lua_register(L,"Pause",l_Pause);
	lua_register(L,"PreLoad",l_PreLoad);
	lua_register(L,"ProcessDelphiInit",l_ProcessDelphiInit);
	lua_register(L,"ProcessExport",l_ProcessExport);
	lua_register(L,"ProcessOverlay",l_ProcessOverlay);
	lua_register(L,"ProcessRelocs",l_ProcessRelocs);
	lua_register(L,"ProcessResources",l_ProcessResources);
	lua_register(L,"ProcessTLS",l_ProcessTLS);
	lua_register(L,"ReadMem",l_ReadMem);
	lua_register(L,"ReadMemDump",l_ReadMemDump);
	lua_register(L,"ReadMemLarge",l_ReadMemLarge);
	lua_register(L,"RemoveLastSEH",l_RemoveLastSEH);
	lua_register(L,"RestoreImportRelocs",l_RestoreImportRelocs);
	lua_register(L,"ResumeAllOther",l_ResumeAllOther);
	lua_register(L,"Resume",l_Resume);
	lua_register(L,"SaveFile",l_SaveFile);
	lua_register(L,"SaveImport",l_SaveImport);
	lua_register(L,"SetLastSEH",l_SetLastSEH);
	lua_register(L,"SetMainBreaks",l_SetMainBreaks);
	lua_register(L,"ShowImport",l_ShowImport);
	lua_register(L,"Start",l_Start);
	lua_register(L,"Stop",l_Stop);
	lua_register(L,"Suspend",l_Suspend);
	lua_register(L,"SuspendAllOther",l_SuspendAllOther);
	lua_register(L,"Terminate",l_Terminate);
	lua_register(L,"TerminateOnTimer",l_TerminateOnTimer);
	lua_register(L,"Trace",l_Trace);
	lua_register(L,"TraceAndReplace",l_TraceAndReplace);
	lua_register(L,"Wait",l_Wait);
	lua_register(L,"WriteEx",l_WriteEx);
	lua_register(L,"WriteLog",l_WriteLog);
	lua_register(L,"WriteMem",l_WriteMem);
	lua_register(L,"WriteMemDump",l_WriteMemDump);
	lua_register(L,"WriteMemLarge",l_WriteMemLarge);

	l_GetVariables(L);
}

CDlgLua::~CDlgLua()
{
	lua_close(L);
	if(pMain!=NULL)
	{
		StopMainThread();
		CMain *pOldMain=pMain;
		pMain=NULL;
		delete pOldMain;
	}
	TerminateThread(hTimerThread,0);
	CloseHandle(hTimerThread);
	CloseHandle(hTimerEvent);
	CloseHandle(hInitialEvent);
}

BOOL CDlgLua::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString sTemp;
	GetWindowText(sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetWindowText(sTemp);
	GetDlgItemText(IDC_SAVESCRIPT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_SAVESCRIPT,sTemp);
	GetDlgItemText(IDC_LOADSCRIPT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_LOADSCRIPT,sTemp);
	GetDlgItemText(IDC_RUNSCRIPT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_RUNSCRIPT,sTemp);
	GetDlgItemText(IDC_CLOSESCRIPT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_CLOSESCRIPT,sTemp);
	GetDlgItemText(IDC_SAVEASSCRIPT,sTemp); sTemp=pDlgMain->LocalizeString(sTemp,true); SetDlgItemText(IDC_SAVEASSCRIPT,sTemp);

	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_SETTEXTMODE,TM_SINGLECODEPAGE,0);

	UpdateData(FALSE);
	hWndTemp=pMain->pInitData->hMain;
	pMain->pInitData->hMain=m_hWnd;
	if(pDlgMain->Option.fAlwaysOnTop)
		SetWindowPos(&wndTopMost,0,0,0,0,SWP_NOMOVE | SWP_NOSIZE);
	return TRUE;
}

unsigned int __stdcall ScriptThread(void *pInitData)
{
	_set_se_translator(SeTranslator);
	if(pScript==NULL)
	{
		try
		{
			pScript=new CDlgLua((CInitData*)pInitData);
			pScript->DoModal();
			CDlgLua *pOldScript=pScript;
			pScript=NULL;
			delete pOldScript;
		}
		catch(CException *e)
		{
			if(pMain!=NULL)
				pMain->Terminate();
			delete pScript;
			if(e->IsKindOf(RUNTIME_CLASS(CMemoryException)))
				e->ReportError(MB_ICONEXCLAMATION | MB_SYSTEMMODAL,AFX_IDP_INTERNAL_FAILURE);
			else if(e->IsKindOf(RUNTIME_CLASS(CSeException)))
				theApp.HandleException((CSeException*)e);
			else if(!e->IsKindOf(RUNTIME_CLASS(CUserException)))
				e->ReportError(MB_ICONSTOP,AFX_IDP_INTERNAL_FAILURE);
		}
	}
	return 0;
}

void CDlgLua::UpdateScript()
{
	int nTemp;
	GETTEXTLENGTHEX Len;
	CHARFORMAT Format;

	Len.flags=GTL_NUMCHARS | GTL_PRECISE;
	Len.codepage=CP_ACP;
	nTemp=(int)GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_GETTEXTLENGTHEX,(WPARAM)&Len,0);
	++nTemp;

	CHARRANGE OldRange,NewRange;
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_EXGETSEL,0,(LPARAM)&OldRange);
	NewRange.cpMin=0;
	NewRange.cpMax=-1;
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_EXSETSEL,0,(LPARAM)&NewRange);

	TCHAR *szString=new TCHAR[nTemp];
	memset(szString,0,nTemp*sizeof(szString[0]));
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_GETSELTEXT,0,(LPARAM)szString);
	sScript=szString;
	delete[] szString;

	Format.cbSize=sizeof(Format);
	Format.dwMask=CFM_COLOR;
	Format.dwEffects=0;
	Format.crTextColor=0;
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_SETCHARFORMAT,SCF_SELECTION,(LPARAM)&Format);
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_EXSETSEL,0,(LPARAM)&OldRange);
}

void CDlgLua::OnBnClickedLoad()
{
	TCHAR szCurrDir[MAX_PATH],szScriptsDir[MAX_PATH];
	GetCurrentDirectory(_countof(szCurrDir),szCurrDir);

	GetModuleFileName(NULL,szScriptsDir,_countof(szScriptsDir));
	PathToDir(szScriptsDir);
	_tcscat_s(szScriptsDir,_T("\\Scripts"));

	TCHAR szFileName[MAX_PATH];
	OPENFILENAME ofn;
	memset(&ofn,0,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=GetSafeHwnd();
	ofn.Flags=OFN_HIDEREADONLY;
	ofn.lpstrFilter=_T("Lua script files\0*.lua;*.txt\0All files\0*.*\0");
	ofn.lpstrInitialDir=szScriptsDir;
	ofn.lpstrFile=szFileName;
	ofn.lpstrFile[0]=_T('\0');
	ofn.nMaxFile=_countof(szFileName);

	if(GetOpenFileName(&ofn))
	{
		pMain->pInitData->sScriptFile=ofn.lpstrFile;
		HANDLE hFile=CreateFile(ofn.lpstrFile,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if(hFile==INVALID_HANDLE_VALUE)
			MessageBox(cantopen,_T("QuickUnpack"),MB_OK);
		else
		{
			DWORD dwFileSize=GetFileSize(hFile,NULL);
			BYTE *bScript=new BYTE[dwFileSize];
			DWORD dwBytesRead;
			ReadFile(hFile,bScript,dwFileSize,&dwBytesRead,NULL);
			if(IsTextUnicode(bScript,dwFileSize,NULL) && *(WORD*)bScript==UNICODE_MAGIC)
			{
				dwFileSize-=sizeof(UNICODE_MAGIC);
				memmove(bScript,bScript+sizeof(UNICODE_MAGIC),dwFileSize);
			}
#ifdef UNICODE
			if(!IsTextUnicode(bScript,dwFileSize,NULL))
			{
				int nLen=dwFileSize;
				WCHAR *pWideArray=new WCHAR[nLen];
				MultiByteToWideChar(CP_ACP,0,(char*)bScript,nLen,pWideArray,nLen);
				sScript.SetString(pWideArray,nLen);
				delete[] pWideArray;
			}
			else
				sScript.SetString((WCHAR*)bScript,dwFileSize/sizeof(WCHAR));
#else
			if(IsTextUnicode(bScript,dwFileSize,NULL))
			{
				int nLen=dwFileSize/sizeof(WCHAR);
				char *pMultiArray=new char[nLen];
				WideCharToMultiByte(CP_ACP,0,(WCHAR*)bScript,nLen,pMultiArray,nLen,NULL,NULL);
				sScript.SetString(pMultiArray,nLen);
				delete[] pMultiArray;
			}
			else
				sScript.SetString((char*)bScript,dwFileSize);
#endif
			UpdateData(FALSE);
			CloseHandle(hFile);
			delete[] bScript;

			UpdateScript();
			POINT Top;
			Top.x=0; Top.y=0;
			GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_SETSCROLLPOS,0,(LPARAM)&Top);

			TSTRING sCaption;
			sCaption=luascripting+_T(" - ");
			sCaption.append(FileFromDir(pMain->pInitData->sScriptFile.c_str()));
			SetWindowText(sCaption.c_str());
		}
	}
	SetCurrentDirectory(szCurrDir);
}

void CDlgLua::OnBnClickedSave()
{
	if(pMain->pInitData->sScriptFile.empty())
	{
		OnBnClickedSaveAs();
		return;
	}
	UpdateScript();
	HANDLE hFile=CreateFile(pMain->pInitData->sScriptFile.c_str(),GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
		MessageBox(cantopen,_T("QuickUnpack"),MB_OK);
	else
	{
		CString sTemp=sScript;
		sTemp.Replace(_T("\xd"),_T("\xd\xa"));
		DWORD dwBytesWritten;
		WriteFile(hFile,sTemp.GetString(),sTemp.GetLength()*sizeof(sTemp.GetString()[0]),&dwBytesWritten,NULL);
		CloseHandle(hFile);
	}
}

void CDlgLua::OnBnClickedRun()
{
	int nError;
	CHARRANGE OldRange,NewRange;

	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_EXGETSEL,0,(LPARAM)&OldRange);
	NewRange.cpMin=(LONG)GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_LINEINDEX,0,0);
	NewRange.cpMax=(LONG)GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_LINEINDEX,
		GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_GETLINECOUNT,0,0)-1,0)+
		(LONG)GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_LINELENGTH,
			GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_LINEINDEX,
				GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_GETLINECOUNT,0,0)-1,0),0);
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_EXSETSEL,0,(LPARAM)&NewRange);

	DWORD dwSize=NewRange.cpMax-NewRange.cpMin+1;
	char *szString=new char[dwSize];
#ifdef UNICODE
	WCHAR *szWString=new WCHAR[dwSize];
	memset(szWString,0,dwSize*sizeof(szWString[0]));
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_GETSELTEXT,0,(LPARAM)szWString);
	WideCharToMultiByte(CP_ACP,0,szWString,dwSize,szString,dwSize,NULL,NULL);
	delete[] szWString;
#else
	memset(szString,0,dwSize*sizeof(szString[0]));
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_GETSELTEXT,0,(LPARAM)szString);
#endif
	nError=luaL_dostring(L,szString);
	if(nError!=0)
	{
		WriteEx(lua_toTString(L,-1).c_str(),TRUE,TRUE,RGB(255,0,0));
		lua_pop(L,1);
	}
	delete[] szString;
	GetDlgItem(IDC_SCRIPTTEXT)->SendMessage(EM_EXSETSEL,0,(LPARAM)&OldRange);
	WriteLog(scriptfinished);
	UpdateScript();
}

void CDlgLua::OnBnClickedClose()
{
	pMain->pInitData->sScriptFile.clear();
	pMain->pInitData->hMain=hWndTemp;
	pDlgMain->InitData.UnpackMode=umFull;
	OnOK();
}

void CDlgLua::OnClose()
{
	OnBnClickedClose();
}

void CDlgLua::OnBnClickedSaveAs()
{
	TCHAR szCurrDir[MAX_PATH],szScriptsDir[MAX_PATH];

	GetCurrentDirectory(_countof(szCurrDir),szCurrDir);

	GetModuleFileName(NULL,szScriptsDir,_countof(szScriptsDir));
	PathToDir(szScriptsDir);
	_tcscat_s(szScriptsDir,_T("\\Scripts"));

	TCHAR szFileName[MAX_PATH];
	OPENFILENAME ofn;
	memset(&ofn,0,sizeof(ofn));
	ofn.lStructSize=sizeof(ofn);
	ofn.hwndOwner=GetSafeHwnd();
	ofn.lpstrDefExt=_T("txt");
	ofn.Flags=OFN_OVERWRITEPROMPT|OFN_HIDEREADONLY;
	ofn.lpstrFilter=_T("txt files\0*.txt\0");
	ofn.lpstrInitialDir=szScriptsDir;
	ofn.lpstrFile=szFileName;
	ofn.lpstrFile[0]=_T('\0');
	ofn.nMaxFile=_countof(szFileName);

	if(GetSaveFileName(&ofn))
	{
		pMain->pInitData->sScriptFile=ofn.lpstrFile;
		OnBnClickedSave();

		TSTRING sCaption;
		sCaption=luascripting+_T(" - ");
		sCaption.append(FileFromDir(pMain->pInitData->sScriptFile.c_str()));
		SetWindowText(sCaption.c_str());
	}
	SetCurrentDirectory(szCurrDir);
}
#endif