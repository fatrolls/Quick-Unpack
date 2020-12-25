cl.exe /D "UNICODE" /D "_UNICODE" force.cpp /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /fp:fast /GR- /LD /link /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /LTCG /def:force.def /NODEFAULTLIB /entry:DllMain kernel32.lib user32.lib
del *.obj
del *.exp
del *.lib
move Force.dll Force64.dll