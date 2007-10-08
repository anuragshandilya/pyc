@echo off

setlocal

set CLAMAV_DEVROOT=J:\Devel\Clamav\native-clamav\clamav-release

if "%1"=="release" goto release
if "%1"=="debug" goto debug
if "%1"=="clean" goto clean
goto usage

:release
rd /s/q build
set DLL=%CLAMAV_DEVROOT%\contrib\msvc\Release\libclamav.dll
goto build

:debug
rd /s/q build
set DLL=%CLAMAV_DEVROOT%\contrib\msvc\Debug\libclamavd.dll
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
xcopy /y %DLL% %destdir%
goto exit

:usage
echo syntax: release | debug | clean
goto exit

:exit
endlocal