cl.exe /D_CRT_SECURE_NO_WARNINGS /D "UNICODE" /D "_UNICODE" LoadDll.cpp /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /fp:fast /GR- /link /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /LTCG /NODEFAULTLIB /entry:main /subsystem:windows kernel32.lib
del *.obj
move LoadDll.exe LoadDll64.exe