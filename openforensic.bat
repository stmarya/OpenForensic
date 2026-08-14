@echo off
setlocal EnableDelayedExpansion

set "PSEXE=powershell"
set "PSOPTS=-NoProfile -ExecutionPolicy Bypass -File"

:: Tanpa argumen -> menu interaktif
if "%~1"=="" (
    "%PSEXE%" %PSOPTS% "%~dp0menu.ps1"
    exit /b %ERRORLEVEL%
)

if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
if /i "%~1"=="/?" goto usage

if /i "%~1"=="--list" (
    "%PSEXE%" %PSOPTS% "%~dp0run.ps1" -OFList
    exit /b %ERRORLEVEL%
)

:: Kumpulkan seluruh argumen dengan tanda kutip aslinya tetap utuh
set "ARGS="
:loop
if "%~1"=="" goto run
set "ARGS=!ARGS! %1"
shift
goto loop

:run
"%PSEXE%" %PSOPTS% "%~dp0run.ps1" !ARGS!
exit /b %ERRORLEVEL%

:usage
echo.
echo OpenForensic - Interactive Digital Forensics ^& CTF Toolkit
echo.
echo   openforensic.bat                    Buka menu interaktif
echo   openforensic.bat --list             Tampilkan tool yang terdaftar
echo   openforensic.bat ^<id^> ^<args...^>     Jalankan satu tool
echo.
echo Contoh:
echo   openforensic.bat vol -f memory.dmp windows.pslist
echo   openforensic.bat olevba "sample macro.xls"
echo   openforensic.bat strings evidence.png
echo.
exit /b 0
