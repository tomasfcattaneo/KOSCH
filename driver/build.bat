@echo off
setlocal

set MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207
set WDK=C:\Program Files (x86)\Windows Kits\10
set WDKVER=10.0.26100.0

set CC="%MSVC%\bin\Hostx64\x64\cl.exe"
set LD="%MSVC%\bin\Hostx64\x64\link.exe"

set INCS=/I "%MSVC%\include" /I "%WDK%\Include\%WDKVER%\km" /I "%WDK%\Include\%WDKVER%\shared" /I "%WDK%\Include\%WDKVER%\ucrt"
set LIBS=/LIBPATH:"%MSVC%\lib\x64" /LIBPATH:"%WDK%\Lib\%WDKVER%\km\x64" /LIBPATH:"%WDK%\Lib\%WDKVER%\ucrt\x64"

if not exist build mkdir build
pushd build

%CC% /kernel /std:c17 /W4 /WX /GR- /GS- /Gy /O2 /Zi /D_AMD64_ /DAMD64 %INCS% /c ..\src\*.c
if %errorlevel% neq 0 (popd & exit /b 1)

%LD% /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB %LIBS% ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib /OUT:koshchei.sys /DEBUG *.obj
if %errorlevel% neq 0 (popd & exit /b 1)

popd
echo === Built driver\build\koshchei.sys ===
