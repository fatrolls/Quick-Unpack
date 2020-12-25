#include "stdafx.h"
#include "RegistryKey.h"

const TCHAR CMD_LINE_QU_ARG[]=_T(" \"%1\"");
const TCHAR *const szShellRegisterExt[]=
{
	_T("dllfile"),
	_T("exefile"),
	_T("ocxfile"),
	_T("scrfile"),
};

void CRegistryKey::RegisterShellExt() const
{
	LONG lRes;
	HKEY hKey[_countof(szShellRegisterExt)];

	for(int i=0;i!=_countof(szShellRegisterExt);++i)
	{
		CString sName=szShellRegisterExt[i];
		sName=sName+_T("\\shell\\")+_T("Unpack with QuickUnpack")+_T("\\command");
		lRes=RegCreateKey(HKEY_CLASSES_ROOT,sName.GetBuffer(),&hKey[i]);
		if(lRes==ERROR_SUCCESS)
		{
			TCHAR szPath[MAX_PATH];
			GetModuleFileName(NULL,szPath,_countof(szPath));
			_tcscat_s(szPath,CMD_LINE_QU_ARG);
			RegSetValue(hKey[i],NULL,REG_SZ,szPath,(DWORD)_tcslen(szPath)+1);
		}
		else
			return;
	}
}

void CRegistryKey::UnRegisterShellExt() const
{
	LONG lRes1,lRes2;
	for(int i=0;i!=_countof(szShellRegisterExt);++i)
	{
		CString sName=szShellRegisterExt[i];
		sName=sName+_T("\\shell\\")+_T("Unpack with QuickUnpack")+_T("\\command");
		lRes1=RegDeleteKey(HKEY_CLASSES_ROOT,sName.GetBuffer());
		sName=szShellRegisterExt[i];
		sName=sName+_T("\\shell\\")+_T("Unpack with QuickUnpack");
		lRes2=RegDeleteKey(HKEY_CLASSES_ROOT,sName.GetBuffer());
		if(lRes1!=ERROR_SUCCESS || lRes2!=ERROR_SUCCESS)
			return;
	}
}

bool CRegistryKey::IsShellRegisterExt() const
{
	LONG lRes;
	HKEY hKey[_countof(szShellRegisterExt)];
	for(int i=0;i!=_countof(szShellRegisterExt);++i)
	{
		CString name=szShellRegisterExt[i];
		name=name+_T("\\shell\\")+_T("Unpack with QuickUnpack");
		lRes=RegOpenKeyEx(HKEY_CLASSES_ROOT,name.GetBuffer(),0,KEY_ALL_ACCESS,&hKey[i]);
		if(lRes==ERROR_SUCCESS)
			RegCloseKey(hKey[i]);
		else
			return false;
	}
	return true;
}

void CRegistryKey::RegistryWriteStruct(const TCHAR *szKeyName,const TCHAR *szValueName,void *pStruct,DWORD dwSizeStruct) const
{
	TCHAR szIniFile[MAX_PATH]={_T('\0')};
	GetModuleFileName(NULL,szIniFile,_countof(szIniFile));
	PathToDir(szIniFile);
	_tcscat_s(szIniFile,FILE_LOCATION);

	WritePrivateProfileStruct(szKeyName,szValueName,pStruct,dwSizeStruct,szIniFile);
}

void CRegistryKey::RegistryReadStruct(const TCHAR *szKeyName,const TCHAR *szValueName,void *pStruct,DWORD dwSizeStruct) const
{
	TCHAR szIniFile[MAX_PATH]={_T('\0')};
	GetModuleFileName(NULL,szIniFile,_countof(szIniFile));
	PathToDir(szIniFile);
	_tcscat_s(szIniFile,FILE_LOCATION);

	GetPrivateProfileStruct(szKeyName,szValueName,pStruct,dwSizeStruct,szIniFile);
}