cl.exe /D_CRT_SECURE_NO_WARNINGS /c mediana.c dump.c utils.c /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /arch:SSE2 /fp:fast /GR-
lib.exe /NODEFAULTLIB mediana.obj dump.obj utils.obj
del *.obj
move mediana.lib disasm32.lib

cl.exe /D_CRT_SECURE_NO_WARNINGS /D "UNICODE" /D "_UNICODE" /c mediana.c dump.c utils.c /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /arch:SSE2 /fp:fast /GR-
lib.exe /NODEFAULTLIB mediana.obj dump.obj utils.obj
del *.obj
move mediana.lib disasm32U.lib