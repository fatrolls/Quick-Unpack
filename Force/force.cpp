#include <stddef.h>
#include <windows.h>
#include <tchar.h>

const DWORD PAGE_SIZE=0x1000;
const DWORD SECTOR_SIZE=0x200;

BYTE bSign1[]=
	{0x6a,0x00,0x68,0x00,0x00,0x00,0x00,0xe8,0x00,0x00,0x00,0x00,0xbf,0x00,0x00,0x00,
	0x00,0x8b,0xc7,0xe8,0x00,0x00,0x00,0x00,0x89,0x65,0x00,0x8b,0xf4,0x89,0x3e,0x56,
	0xff,0x15,0x00,0x00};
BYTE bSign2[]=
	{0x6a,0x70,0x68,0x00,0x00,0x00,0x00,0xe8};
BYTE bSign3[]=
	{0x55,0x8b,0xec,0x6a,0xff,0x68,0x00,0x00,0x00,0x00,0x68,0x00,0x00,0x00,0x00,0x64,
	0xa1,0x00,0x00,0x00,0x00,0x50,0x64,0x89,0x25,0x00,0x00,0x00,0x00,0x83,0x00,0x00,
	0x53,0x56,0x57,0x89,0x65,0xe8,0x00,0x00};
BYTE bSign4[]=
	{0x64,0xa1,0x00,0x00,0x00,0x00,0x55,0x8b,0xec,0x6a,0xff,0x68,0x00,0x00,0x00,0x00,
	0x68,0x00,0x00,0x00,0x00,0x50,0x64,0x89,0x25,0x00,0x00,0x00,0x00,0x83,0xec,0x00,
	0x2b,0x56,0x57,0x00};
BYTE bSign5[]=
	{0x55,0x8b,0xec,0x83,0xc4,0x00,0x00,0x00};
BYTE bSign6[]=
	{0x64,0xa1,0x00,0x00,0x00,0x00,0x55,0x89,0xe5,0x6a,0xff,0x68,0x00,0x00,0x00,0x00,
	0x68,0x9a,0x10,0x40,0x00,0x50,0x64,0x89,0x25,0x00,0x00,0x00,0x00,0x83,0x00,0x00};
BYTE bSign7[]=
	{0xa1,0x00,0x00,0x00,0x00,0xc1,0xe0,0x02,0xa3,0x00,0x00,0x00,0x00,0x57,0x51,0x33,
	0xc0,0xbf,0x00,0x00,0x00,0x00,0xb9,0x00,0x00,0x00,0x00,0x3b,0xcf,0x76,0x05,0x2b,
	0xcf,0xfc,0xf3,0xaa,0x59,0x5f,0x00,0x00};
BYTE bSign8[]=
	{0xeb,0x10,0x66,0x62,0x3a,0x43,0x2b,0x2b,0x48,0x4f,0x4f,0x4b,0x90,0xe9,0x00,0x00,
	0x00,0x00,0xa1,0x00,0x00,0x00,0x00,0xc1,0xe0,0x02,0xa3,0x00,0x00,0x00,0x00,0x52};
BYTE bSign9[]=
	{0x55,0x8b,0xec,0x83,0xec,0x44,0x56,0xff,0x15,0x00,0x00,0x00,0x00,0x8b,0xf0,0x8a,
	0x00,0x3c,0x22,0x74};
BYTE bSign10[]=
	{0x53,0x51,0x52,0x55,0x89,0xe5,0x83,0xec,0x08,0xb8,0x01,0x00,0x00,0x00,0xe8,0x00,
	0x00,0x00,0x00,0xa1,0x00,0x00,0x00,0x00,0x83,0xc0,0x03,0x2f,0x4c,0x31,0xd2,0x00};
BYTE bSign11[]=
	{0xff,0x25,0x00,0x00,0x00,0x00,0xff,0x25,0x00,0x00,0x00,0x00,0x68,0x00,0x00,0x00,
	0x00,0xe8,0x00,0x00,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x00,0x00,0x00};
BYTE bSign12[]=
	{0xff,0x25,0x00,0x00,0x00,0x00,0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x68,0x00,
	0x00,0x00,0x00,0xe8,0x00,0x00,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x00};
BYTE bSign13[]=
	{0x6a,0x00,0xe8,0x00,0x00,0x00,0x00,0xa3};

DWORD_PTR AlignTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return (Value+(Alignment-1)) & ~(Alignment-1);
}

DWORD_PTR CutTo(DWORD_PTR Value,DWORD_PTR Alignment)
{
	return Value & ~(Alignment-1);
}

DWORD RVAToOffset(DWORD dwRVA,IMAGE_NT_HEADERS *pPEHeader,IMAGE_SECTION_HEADER *pSections)
{
	if(pPEHeader->OptionalHeader.SizeOfHeaders>dwRVA)
		return dwRVA;
	for(int i=0;i!=pPEHeader->FileHeader.NumberOfSections;++i)
	{
		if(dwRVA>=pSections[i].VirtualAddress && dwRVA<pSections[i].VirtualAddress+pSections[i].SizeOfRawData)
			return dwRVA-pSections[i].VirtualAddress+pSections[i].PointerToRawData;
	}
	return dwRVA;
}

DWORD FindSign(BYTE *pImage,DWORD dwImageSize,BYTE *pSignature,DWORD dwSignSize,DWORD dwType)
{
	DWORD dwParseSize=dwImageSize-dwSignSize;
	if(dwImageSize<=dwSignSize)
		return 0;

	DWORD i,j,k;
	DWORD dwTemp=0;
	for(i=0;i<dwParseSize;++i)
	{	
		for(j=0;j<dwSignSize;++j)
		{
			if(pImage[i+j]!=pSignature[j] && pSignature[j]!=0)
				break;
		}
		if(j==dwSignSize)
		{
			if(dwType==6)
			{
				for(k=0;k!=0x50;++k)
				{
					if(pImage[i+j+k]==0xe8)
					{
						DWORD dwJmp=*(DWORD*)(pImage+i+j+k+1)+i+j+k+1+sizeof(DWORD);
						if(dwJmp<dwImageSize)
						{
							if(pImage[dwJmp]==0xe8 && *(WORD*)(pImage+dwJmp+5)==0x6a)
								return i;
							if(*(DWORD*)(pImage+dwJmp)==0xE8006A50 && pImage[dwJmp+7]==0xff && pImage[dwJmp+8]==0xba && pImage[dwJmp+13]==0x52)
								return i;
							if(*(DWORD*)(pImage+dwJmp)==0x33D88B53 && *(WORD*)(pImage+dwJmp+4)==0xA3C0)
								return i;
						}
					}
				}
			}
			else if(dwType==1)
			{
				if(pImage[i+0x26]==0xff || pImage[i+0x2d]==0xff)
					return i;
				for(k=0;k!=0x50;++k)
				{
					if(pImage[i+j+k+0x14]==0xff && pImage[i+j+k+0x15]==0x15)
						return i;
				}
			}
			else if(dwType==2)
				return i+12;
			else if(dwType==7)
				return i+14;
			else if(dwType==11)
			{
				if(i==0x1000)
					return i;
			}
			else if(dwType==3)
			{
				for(k=0x100;k!=0x10000;++k)
				{
					if(pImage[i+j-k]==0xe9)
					{
						DWORD dwJmp=*(DWORD*)(pImage+i+j-k+1)+i+j-k+1+sizeof(DWORD);
						if(dwJmp==i)
							return i+j-k;
					}
				}
				continue;
			}
			dwTemp=i;
		}
	}
	if(dwTemp==0 || dwType==1)
		return 0;
	if(dwType!=9 || dwSignSize!=8)
		return dwTemp;
	DWORD dwJmp=*(DWORD*)(pImage+offsetof(IMAGE_DOS_HEADER,e_lfanew));
	if(pImage[dwJmp+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+offsetof(IMAGE_OPTIONAL_HEADER,MajorLinkerVersion)]==7)
		return dwTemp;
	return 0;
}

DWORD __stdcall GetOEPNow(const TCHAR *szFileName)
{
	HANDLE hFile=CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
		return 0;

	DWORD dwBytesRead;
	WORD wSignature;
	ReadFile(hFile,&wSignature,sizeof(wSignature),&dwBytesRead,NULL);
	if(wSignature!=IMAGE_DOS_SIGNATURE)
	{
		CloseHandle(hFile);
		return 0;
	}
	SetFilePointer(hFile,offsetof(IMAGE_DOS_HEADER,e_lfanew),NULL,FILE_BEGIN);
	DWORD dwOffsetToPE;
	ReadFile(hFile,&dwOffsetToPE,sizeof(dwOffsetToPE),&dwBytesRead,NULL);

	SetFilePointer(hFile,dwOffsetToPE,NULL,FILE_BEGIN);
	IMAGE_NT_HEADERS PEHeader;
	ReadFile(hFile,&PEHeader,sizeof(PEHeader),&dwBytesRead,NULL);
	if(PEHeader.Signature!=IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hFile);
		return 0;
	}

	IMAGE_SECTION_HEADER *pSections=(IMAGE_SECTION_HEADER*)VirtualAlloc(NULL,PEHeader.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER),MEM_COMMIT,PAGE_READWRITE);
	SetFilePointer(hFile,dwOffsetToPE+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+PEHeader.FileHeader.SizeOfOptionalHeader,NULL,FILE_BEGIN);

	DWORD i,dwFileSize=GetFileSize(hFile,NULL);
	for(i=0;i!=PEHeader.FileHeader.NumberOfSections;++i)
	{
		ReadFile(hFile,&pSections[i],sizeof(IMAGE_SECTION_HEADER),&dwBytesRead,NULL);
		if(pSections[i].Misc.VirtualSize==0)
			pSections[i].Misc.VirtualSize=pSections[i].SizeOfRawData;
		if(pSections[i].SizeOfRawData==0)
			pSections[i].PointerToRawData=0;
		if(pSections[i].PointerToRawData==0)
			pSections[i].SizeOfRawData=0;
		if(PEHeader.OptionalHeader.SectionAlignment>=PAGE_SIZE)
		{
			pSections[i].Misc.VirtualSize=(DWORD)AlignTo(pSections[i].Misc.VirtualSize,PEHeader.OptionalHeader.SectionAlignment);
			DWORD dwAlignedRawPtr=(DWORD)CutTo(pSections[i].PointerToRawData,SECTOR_SIZE);
			pSections[i].SizeOfRawData=min((DWORD)AlignTo(pSections[i].PointerToRawData+pSections[i].SizeOfRawData,PEHeader.OptionalHeader.FileAlignment)-dwAlignedRawPtr,(DWORD)AlignTo(pSections[i].SizeOfRawData,PAGE_SIZE));
			pSections[i].PointerToRawData=dwAlignedRawPtr;
		}
		if(pSections[i].SizeOfRawData>pSections[i].Misc.VirtualSize)
			pSections[i].SizeOfRawData=pSections[i].Misc.VirtualSize;
		if(pSections[i].SizeOfRawData>dwFileSize-pSections[i].PointerToRawData)
			pSections[i].SizeOfRawData=(DWORD)AlignTo(dwFileSize-pSections[i].PointerToRawData,PEHeader.OptionalHeader.FileAlignment);
	}
	DWORD dwEP=RVAToOffset(PEHeader.OptionalHeader.AddressOfEntryPoint,&PEHeader,pSections);

	SetFilePointer(hFile,dwEP,NULL,FILE_BEGIN);
	BYTE bBuffer[1000];
	ReadFile(hFile,bBuffer,sizeof(bBuffer),&dwBytesRead,NULL);
	DWORD dwLen=dwBytesRead;

	//FSG 1.00
	if(bBuffer[0]==0xbb && bBuffer[5]==0xbf && bBuffer[10]==0xbe && bBuffer[15]==0x53)
	{
		SetFilePointer(hFile,dwEP+0xe1+2,NULL,FILE_BEGIN);
		DWORD dwJmp;
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);
		return dwJmp+PEHeader.OptionalHeader.AddressOfEntryPoint+0xe1+2+sizeof(DWORD);
	}
	//FSG 1.33
	if(bBuffer[0]==0xbe && bBuffer[1]==0xa4 && bBuffer[2]==0x01 && bBuffer[3]==0x40)
	{
		SetFilePointer(hFile,dwEP+0xa1+2,NULL,FILE_BEGIN);
		DWORD dwJmp;
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);
		return dwJmp+PEHeader.OptionalHeader.AddressOfEntryPoint+0xa1+2+sizeof(DWORD);
	}
	// ASpack
	if(bBuffer[0]==0x60 && bBuffer[1]==0xe8 && bBuffer[2]==0x03 && bBuffer[6]==0xe9 && bBuffer[7]==0xeb)
	{
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);

		for(i=0;i!=dwLen;++i)
		{
			if(bBuffer[i]==0x61 && bBuffer[i+1]==0x75 && bBuffer[i+3]==0xb8)
				break;
		}
		if(i==dwLen)
			return 0;
		return *(DWORD*)(bBuffer+i-20);
	}
	// FSG 2.0
	if(bBuffer[0]==0x87 && bBuffer[1]==0x25 && bBuffer[6]==0x61 && bBuffer[7]==0x94 && bBuffer[8]==0x55)
	{
		SetFilePointer(hFile,GetFileSize(hFile,0)-0x2d,NULL,FILE_BEGIN);
		DWORD dwJmp;
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);
		return (DWORD)(dwJmp-PEHeader.OptionalHeader.ImageBase);
	}
	// MEW 10
	if(bBuffer[0]==0x33 && bBuffer[1]==0xc0 && bBuffer[2]==0xe9)
	{
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);

		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		SecureZeroMemory(&si,sizeof(si));
		si.cb=sizeof(si);
		SecureZeroMemory(&pi,sizeof(pi));
		CreateProcess(szFileName,NULL,NULL,NULL,FALSE,NORMAL_PRIORITY_CLASS,NULL,NULL,&si,&pi);
		WaitForInputIdle(pi.hProcess,INFINITE);
		SuspendThread(pi.hThread);

		BYTE *pStub=(BYTE*)VirtualAlloc(NULL,0x2000,MEM_COMMIT,PAGE_READWRITE);
		ReadProcessMemory(pi.hProcess,(void*)(PEHeader.OptionalHeader.ImageBase+PEHeader.OptionalHeader.SizeOfImage-0x2000),pStub,0x2000,NULL);
		TerminateProcess(pi.hProcess,0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		DWORD dwJmp=(DWORD)PEHeader.OptionalHeader.ImageBase;
		for(i=0;i!=0x2000;++i)
		{
			if(pStub[i]==0x5e && pStub[i+1]==0x5f && pStub[i+2]==0x59 && pStub[i+3]==0x5a && pStub[i+4]==0xab && pStub[i+5]==0xeb && pStub[i+7]==0xc3)
			{
				dwJmp=*(DWORD*)(pStub+i-0x57);
				break;
			}
		}
		VirtualFree(pStub,0,MEM_RELEASE);
		return (DWORD)(dwJmp-PEHeader.OptionalHeader.ImageBase);
	}
	// MEW 11
	if(bBuffer[0]==0xe9 && bBuffer[5]==0x00 && bBuffer[6]==0x00 && pSections[0].Name[0]=='M' && pSections[0].Name[1]=='E' && pSections[0].Name[2]=='W')
	{
		SetFilePointer(hFile,dwEP+1,NULL,FILE_BEGIN);
		DWORD dwJmp;
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		dwJmp+=PEHeader.OptionalHeader.AddressOfEntryPoint+1+sizeof(DWORD)+1;
		SetFilePointer(hFile,RVAToOffset(dwJmp,&PEHeader,pSections),NULL,FILE_BEGIN);
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		SetFilePointer(hFile,RVAToOffset((DWORD)(dwJmp-PEHeader.OptionalHeader.ImageBase+sizeof(DWORD)),&PEHeader,pSections),NULL,FILE_BEGIN);
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);
		return (DWORD)(dwJmp-PEHeader.OptionalHeader.ImageBase);
	}
	// PECompact 1.84
	if(bBuffer[0]==0xeb && bBuffer[1]==0x06 && bBuffer[2]==0x68 && bBuffer[7]==0xc3 && bBuffer[8]==0x9c && bBuffer[9]==0x60 && bBuffer[10]==0xe8 && bBuffer[11]==0x02)
	{
		SetFilePointer(hFile,pSections[PEHeader.FileHeader.NumberOfSections-1].PointerToRawData+3,NULL,FILE_BEGIN);
		DWORD dwJmp;
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);
		return dwJmp;
	}
	// PECompact 2.32
	if(bBuffer[0]==0xb8 && bBuffer[5]==0x50 && bBuffer[6]==0x64 && bBuffer[7]==0xff && bBuffer[8]==0x35 && bBuffer[9]==0x0 && bBuffer[10]==0x0 && bBuffer[11]==0x0 && bBuffer[12]==0x0 && bBuffer[13]==0x64 && bBuffer[14]==0x89)
	{
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);

		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		SecureZeroMemory(&si,sizeof(si));
		si.cb=sizeof(si);
		SecureZeroMemory(&pi,sizeof(pi));
		CreateProcess(szFileName,NULL,NULL,NULL,FALSE,NORMAL_PRIORITY_CLASS,NULL,NULL,&si,&pi);
		WaitForInputIdle(pi.hProcess,INFINITE);
		SuspendThread(pi.hThread);

		BYTE *pStub=(BYTE*)VirtualAlloc(NULL,0x3000,MEM_COMMIT,PAGE_READWRITE);
		ReadProcessMemory(pi.hProcess,(void*)(PEHeader.OptionalHeader.ImageBase+PEHeader.OptionalHeader.SizeOfImage-0x3000),pStub,0x3000,NULL);
		TerminateProcess(pi.hProcess,0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		DWORD dwJmp=(DWORD)PEHeader.OptionalHeader.ImageBase;
		for(i=0;i!=0x3000;++i)
		{
			if(pStub[i]==0x5a && pStub[i+1]==0x5e && pStub[i+2]==0x5f && pStub[i+3]==0x59 && pStub[i+4]==0x5b && pStub[i+5]==0x5d && pStub[i+6]==0xff && pStub[i+7]==0xe0)
			{
				dwJmp=*(DWORD*)(pStub+i+8);
				break;
			}
		}
		VirtualFree(pStub,0,MEM_RELEASE);
		return (DWORD)(dwJmp-PEHeader.OptionalHeader.ImageBase);
	}
	//upx
	if(bBuffer[0]==0x60 && bBuffer[1]==0xbe && bBuffer[6]==0x8d && bBuffer[7]==0xbe)
	{
		VirtualFree(pSections,0,MEM_RELEASE);
		CloseHandle(hFile);

		for(i=0;i!=dwLen;++i)
		{
			if((bBuffer[i]==0x61 && bBuffer[i+1]==0xe9) || (bBuffer[i]==0x61 && bBuffer[i+14]==0xe9))
				break;
		}
		if(i==dwLen)
			return 0;
		if(bBuffer[i]==0x61 && bBuffer[i+14]==0xe9)
			i+=13;
		return *(DWORD*)(bBuffer+i+2)+PEHeader.OptionalHeader.AddressOfEntryPoint+i+2+sizeof(DWORD);
	}
	VirtualFree(pSections,0,MEM_RELEASE);
	CloseHandle(hFile);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SecureZeroMemory(&si,sizeof(si));
	si.cb=sizeof(si);
	SecureZeroMemory(&pi,sizeof(pi));
	CreateProcess(szFileName,NULL,NULL,NULL,FALSE,NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED,NULL,NULL,&si,&pi);

	CONTEXT Context;
	DWORD_PTR VictimBase;
	Context.ContextFlags=CONTEXT_INTEGER;
	GetThreadContext(pi.hThread,&Context);
#if defined _M_AMD64
	ReadProcessMemory(pi.hProcess,(BYTE*)Context.Rdx+0x10,&VictimBase,sizeof(VictimBase),NULL);
#elif defined _M_IX86
	ReadProcessMemory(pi.hProcess,(BYTE*)Context.Ebx+0x8,&VictimBase,sizeof(VictimBase),NULL);
#else
!!!
#endif
	ResumeThread(pi.hThread);
	WaitForInputIdle(pi.hProcess,INFINITE);
	SuspendThread(pi.hThread);

	BYTE *pStub=(BYTE*)VirtualAlloc(NULL,PEHeader.OptionalHeader.SizeOfImage,MEM_COMMIT,PAGE_READWRITE);
	ReadProcessMemory(pi.hProcess,(void*)VictimBase,pStub,PEHeader.OptionalHeader.SizeOfImage,NULL);
	TerminateProcess(pi.hProcess,0);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	if(pStub==NULL)
		return 0;

	DWORD dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign3,sizeof(bSign3),1);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign1,sizeof(bSign1),9);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign4,sizeof(bSign4),8);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign6,sizeof(bSign6),4);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign7,sizeof(bSign7),5);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign8,sizeof(bSign8),5);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign10,sizeof(bSign10),3);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign9,sizeof(bSign9),10);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign12,sizeof(bSign12),7);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign11,sizeof(bSign11),2);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign5,sizeof(bSign5),6);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign13,sizeof(bSign13),11);
	if(dwResult==0)
		dwResult=FindSign(pStub,PEHeader.OptionalHeader.SizeOfImage,bSign2,sizeof(bSign2),9);
	VirtualFree(pStub,0,MEM_RELEASE);
	return dwResult;
}

DWORD __stdcall GetDllOEPNow(const TCHAR *szFileName)
{
	HANDLE hFile=CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
		return 0;

	DWORD dwBytesRead;
	WORD wSignature;
	ReadFile(hFile,&wSignature,sizeof(wSignature),&dwBytesRead,NULL);
	if(wSignature!=IMAGE_DOS_SIGNATURE)
	{
		CloseHandle(hFile);
		return 0;
	}
	SetFilePointer(hFile,offsetof(IMAGE_DOS_HEADER,e_lfanew),NULL,FILE_BEGIN);
	DWORD dwOffsetToPE;
	ReadFile(hFile,&dwOffsetToPE,sizeof(dwOffsetToPE),&dwBytesRead,NULL);

	SetFilePointer(hFile,dwOffsetToPE,NULL,FILE_BEGIN);
	IMAGE_NT_HEADERS PEHeader;
	ReadFile(hFile,&PEHeader,sizeof(PEHeader),&dwBytesRead,NULL);
	if(PEHeader.Signature!=IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hFile);
		return 0;
	}

	IMAGE_SECTION_HEADER *pSections=(IMAGE_SECTION_HEADER*)VirtualAlloc(NULL,PEHeader.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER),MEM_COMMIT,PAGE_READWRITE);
	SetFilePointer(hFile,dwOffsetToPE+offsetof(IMAGE_NT_HEADERS,OptionalHeader)+PEHeader.FileHeader.SizeOfOptionalHeader,NULL,FILE_BEGIN);

	DWORD i,dwFileSize=GetFileSize(hFile,NULL);
	for(i=0;i!=PEHeader.FileHeader.NumberOfSections;++i)
	{
		ReadFile(hFile,&pSections[i],sizeof(IMAGE_SECTION_HEADER),&dwBytesRead,NULL);
		if(pSections[i].Misc.VirtualSize==0)
			pSections[i].Misc.VirtualSize=pSections[i].SizeOfRawData;
		if(pSections[i].SizeOfRawData==0)
			pSections[i].PointerToRawData=0;
		if(pSections[i].PointerToRawData==0)
			pSections[i].SizeOfRawData=0;
		if(PEHeader.OptionalHeader.SectionAlignment>=PAGE_SIZE)
		{
			pSections[i].Misc.VirtualSize=(DWORD)AlignTo(pSections[i].Misc.VirtualSize,PEHeader.OptionalHeader.SectionAlignment);
			DWORD dwAlignedRawPtr=(DWORD)CutTo(pSections[i].PointerToRawData,SECTOR_SIZE);
			pSections[i].SizeOfRawData=min((DWORD)AlignTo(pSections[i].PointerToRawData+pSections[i].SizeOfRawData,PEHeader.OptionalHeader.FileAlignment)-dwAlignedRawPtr,(DWORD)AlignTo(pSections[i].SizeOfRawData,PAGE_SIZE));
			pSections[i].PointerToRawData=dwAlignedRawPtr;
		}
		if(pSections[i].SizeOfRawData>pSections[i].Misc.VirtualSize)
			pSections[i].SizeOfRawData=pSections[i].Misc.VirtualSize;
		if(pSections[i].SizeOfRawData>dwFileSize-pSections[i].PointerToRawData)
			pSections[i].SizeOfRawData=(DWORD)AlignTo(dwFileSize-pSections[i].PointerToRawData,PEHeader.OptionalHeader.FileAlignment);
	}
	DWORD dwEP=RVAToOffset(PEHeader.OptionalHeader.AddressOfEntryPoint,&PEHeader,pSections);
	VirtualFree(pSections,0,MEM_RELEASE);

	SetFilePointer(hFile,dwEP,NULL,FILE_BEGIN);
	BYTE bBuffer[1000];
	ReadFile(hFile,bBuffer,sizeof(bBuffer),&dwBytesRead,NULL);
	DWORD dwLen=dwBytesRead;

	//upx dll
	if(bBuffer[0]==0x80 && bBuffer[1]==0x7c && bBuffer[2]==0x24 && bBuffer[3]==0x08 && bBuffer[4]==0x01 && bBuffer[11]==0x60 && bBuffer[12]==0xbe)
	{
		for(i=0;i!=dwLen;++i)
		{
			if((bBuffer[i]==0x61 && bBuffer[i+1]==0xe9) || (bBuffer[i]==0x83 && bBuffer[i+1]==0xec && bBuffer[i+3]==0xe9))
				break;
		}
		if(i==dwLen)
		{
			CloseHandle(hFile);
			return 0;
		}
		if(bBuffer[i]==0x83)
			i+=4;
		else
			i+=2;

		SetFilePointer(hFile,dwEP+i,NULL,FILE_BEGIN);
		DWORD dwJmp;
		ReadFile(hFile,&dwJmp,sizeof(dwJmp),&dwBytesRead,NULL);
		CloseHandle(hFile);
		return dwJmp+PEHeader.OptionalHeader.AddressOfEntryPoint+i+sizeof(DWORD);
	}
	// ASpack dll
	if(bBuffer[0]==0x60 && bBuffer[1]==0xe8 && bBuffer[2]==0x03 && bBuffer[6]==0xe9 && bBuffer[7]==0xeb)
	{
		for(i=0;i!=dwLen;++i)
		{
			if(bBuffer[i]==0x61 && bBuffer[i+1]==0x75 && bBuffer[i+3]==0xb8)
				break;
		}
		if(i==dwLen)
		{
			CloseHandle(hFile);
			return 0;
		}
		SetFilePointer(hFile,i+dwEP-20,NULL,FILE_BEGIN);
		DWORD dwOEP;
		ReadFile(hFile,&dwOEP,sizeof(dwOEP),&dwBytesRead,NULL);
		CloseHandle(hFile);
		return dwOEP;
	}
	CloseHandle(hFile);
	return 0;
}

TCHAR *__stdcall ShortFinderName()
{
	return _T("ForceOEP by Archer & Feuerrader");
}

BOOL __stdcall DllMain(HINSTANCE hInstance,DWORD,LPVOID)
{
	DisableThreadLibraryCalls((HMODULE)hInstance);
	return TRUE;
}