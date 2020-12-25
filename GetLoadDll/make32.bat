cl.exe GetLoadDll.cpp /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /fp:fast /GR- /LD /link /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /LTCG /def:GetLoadDll.def /NODEFAULTLIB /entry:DllMain /subsystem:windows
del *.exp
del *.obj
del *.lib
move GetLoadDll.dll GetLoadDll32.dll