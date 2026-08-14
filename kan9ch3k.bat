@echo off
setlocal EnableDelayedExpansion

set BIN_DIR=%~dp0bin
set TOOL=%1

:: Jika tidak ada argumen, luncurkan mode interaktif (GUI Menu)
if "%TOOL%"=="" (
    powershell -ExecutionPolicy Bypass -File "%~dp0kan9ch3k_menu.ps1"
    exit /b %ERRORLEVEL%
)

:: Mengumpulkan semua argumen setelah nama tool (Mode CLI)
set ARGS=
shift
:loop
if "%~1"=="" goto run
set ARGS=!ARGS! %1
shift
goto loop

:run
:: Eksekusi tool jika ada di dalam folder bin
if exist "%BIN_DIR%\%TOOL%.exe" (
    "%BIN_DIR%\%TOOL%.exe" !ARGS!
) else (
    echo [-] Error: Tool '%TOOL%' tidak ditemukan di dalam folder bin.
    echo Pastikan setup_tools.ps1 sudah dijalankan dengan sukses.
)
