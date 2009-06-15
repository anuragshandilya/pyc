@echo off

setlocal

set CLAMAV_DEVROOT=C:\Work\Clamav\clamav-release

if "%1"=="release" goto release
if "%1"=="debug" goto debug
if "%1"=="clean" goto clean
goto usage

:release
set DLL=%CLAMAV_DEVROOT%\contrib\msvc\Release\Win32\*.dll
set PYTHON=python
echo Building Release
goto build

:debug
set DLL=%CLAMAV_DEVROOT%\contrib\msvc\Debug\Win32\*.dll
set CLAMAV_DEBUG=yes
set PYTHON=python_d
echo Building Debug
goto build

:clean
rd /s/q build 2>NUL:
goto exit

:build
%PYTHON% setup.py build
goto copylib

:copylib
for /R %%i in (*.pyd) do set destdir=%%~di%%~pi
if not exist "%destdir%" goto failed
xcopy /q/y %DLL% "%destdir%" >NUL:
if exist %destdir%\pyc.pyd.manifest mt -nologo -manifest %destdir%\pyc.pyd.manifest -outputresource:%destdir%\pyc.pyd;#2
goto exit

:usage
echo usage: %0 release debug clean
goto exit

:failed
echo build failed
goto exit

:exit
endlocal
