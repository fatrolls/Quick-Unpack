@rem Script to build Lua under "Visual Studio Command Prompt".

@setlocal
@set MYCOMPILE=cl.exe /nologo /MT /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GF /GS- /Gy /fp:fast /GR- /c /D_CRT_SECURE_NO_DEPRECATE
@set MYLINK=link.exe /nologo /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /LTCG
@set MYLIB=lib.exe /nologo

cd src
%MYCOMPILE% l*.c
del lua.obj luac.obj
%MYLIB% /out:..\lua64.lib l*.obj
del *.obj *.manifest
cd ..