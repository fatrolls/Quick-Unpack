#pragma once

class CRegistryKey
{
public:
	virtual void RegistryReadStruct(const TCHAR *szKeyName,const TCHAR *szValueName,void *pStruct,DWORD dwSizeStruct) const;
	virtual void RegistryWriteStruct(const TCHAR *szKeyName,const TCHAR *szValueName,void *pStruct,DWORD dwSizeStruct) const;
	bool IsShellRegisterExt() const;
	void UnRegisterShellExt() const;
	void RegisterShellExt() const;
};