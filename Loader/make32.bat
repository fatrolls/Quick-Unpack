cl.exe /D_CRT_SECURE_NO_WARNINGS loader.cpp /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /arch:SSE2 /fp:fast /GR- /link /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /LTCG
del *.obj
move loader.exe loader32.exe