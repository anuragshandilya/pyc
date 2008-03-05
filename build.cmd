@echo off

setlocal

set CLAMAV_DEVROOT=C:\Work\Clamav\clamav-devel
set DISTUTILS_USE_SDK=1
set MSSdk=.

if "%1"=="release" goto release
if "%1"=="debug" goto debug
if "%1"=="clean" goto clean
goto usage

:release
rd /s/q build
set DLL=%CLAMAV_DEVROOT%\contrib\msvc\Release\Win32\*.dll
goto build

:debug
rd /s/q build
set DLL=%CLAMAV_DEVROOT%\contrib\msvc\Debug\Win32\*.dll
set CLAMAV_DEBUG=yes
goto build

:clean
rd /s/q build
goto exit

:build
python setup.py build
goto copylib

:copylib
for /R %%i in (*.pyd) do set destdir=%%~di%%~pi
if not exist "%destdir%" goto failed
xcopy /q/y %DLL% "%destdir%"
if exist %destdir%\pyc.pyd.manifest mt -nologo -manifest %destdir%\pyc.pyd.manifest -outputresource:%destdir%\pyc.pyd;#2
goto exit

:usage
echo syntax: release debug clean
goto exit

:failed
echo build failed
goto exit

:exit
endlocal
