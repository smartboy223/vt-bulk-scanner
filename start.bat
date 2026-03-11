@echo off
setlocal EnableDelayedExpansion
title VirusTotal Bulk Scanner
color 0B
echo.
echo  +=============================================+
echo  ^|     VirusTotal Bulk Scanner  -  v1          ^|
echo  +=============================================+
echo.
echo  This script will:
echo    - Check Python and install dependencies if needed
echo    - Start the web server and show the project URL
echo.
echo  ----------------------------------------
echo.

:: Check Python
where py >nul 2>nul
if %errorlevel% neq 0 (
    where python >nul 2>nul
    if %errorlevel% neq 0 (
        echo  [ERROR] Python not found.
        echo  Install Python 3.8+ from https://python.org
        echo.
        pause
        exit /b 1
    )
    set PY=python
) else (
    set PY=py
)

echo  [OK] Python found
%PY% --version
echo.

:: Create virtual environment if not exists
if not exist "venv" (
    echo  Creating virtual environment...
    %PY% -m venv venv
    if %errorlevel% neq 0 (
        echo  [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created
    echo.
)

:: Activate venv
call venv\Scripts\activate.bat

:: Install dependencies
echo  Installing dependencies...
pip install -q -r requirements.txt
if %errorlevel% neq 0 (
    echo  [WARNING] Retrying with core packages...
    pip install -q flask requests openpyxl
)
echo  [OK] Dependencies ready
echo.

:: Create data directories
if not exist "data" mkdir data
if not exist "data\scans" mkdir data\scans

:: Kill any leftover server from previous run
if exist "data\server.pid" (
    echo  Stopping previous server instance...
    set /p OLD_PID=<data\server.pid
    taskkill /F /PID !OLD_PID! >nul 2>&1
    del /q data\server.pid >nul 2>&1
    echo  [OK] Previous process cleared
    echo.
)

:: Show how to stop and what to expect
echo  +---------------------------------------------+
echo  ^|  WHEN THE SERVER IS RUNNING BELOW:          ^|
echo  ^|  To close the project, do ONE of:           ^|
echo  ^|    - Press  Ctrl+C  in this window          ^|
echo  ^|    - Close this window                      ^|
echo  +---------------------------------------------+
echo.
echo  The project URL will appear below.
echo  Open that address in your browser.
echo  Your browser may open automatically.
echo.
echo  ----------------------------------------
echo.

python web_app.py %*

:: Server has stopped - clean finish
echo.
echo  ----------------------------------------
if exist "data\server.pid" (
    set /p OLD_PID=<data\server.pid
    taskkill /F /PID !OLD_PID! >nul 2>&1
    del /q data\server.pid >nul 2>&1
)
echo  +=============================================+
echo  ^|  Project closed. Server stopped.            ^|
echo  +=============================================+
echo.
echo  You can close this window or press any key to exit.
echo.
pause
