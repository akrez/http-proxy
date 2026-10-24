@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

echo ============================================================
echo   HTTP Proxy - Setup and Run (Windows)
echo ============================================================
echo.

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "MITMDUMP=mitmproxy\mitmdump.exe"
set "CERT_PATH=%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
set "CONFIG_PATH=..\config.json"
set "CONFIG_SAMPLE=..\config.json.sample"

:: ============================================================
:: STEP 1: Download mitmproxy
:: ============================================================
if exist "%MITMDUMP%" (
    echo [STEP 1/4] mitmproxy           ... ALREADY EXISTS [SKIP]
) else (
    echo [STEP 1/4] Downloading mitmproxy...
    echo.

    :: Fetch latest version
    echo   Fetching latest version from GitHub...
    for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "(Invoke-RestMethod -Uri 'https://api.github.com/repos/mitmproxy/mitmproxy/releases/latest').tag_name"`) do set "TAG=%%i"

    if not defined TAG (
        echo   [ERROR] Failed to fetch latest version. Check your internet connection.
        pause
        exit /b 1
    )

    set "VERSION=!TAG:~1!"
    echo   Latest version: !VERSION!

    set "FILENAME=mitmproxy-!VERSION!-windows-x86_64.zip"
    set "DOWNLOAD_URL=https://github.com/mitmproxy/mitmproxy/releases/download/!TAG!/!FILENAME!"

    echo   Downloading !FILENAME!...
    echo   URL: !DOWNLOAD_URL!
    echo.

    powershell -NoProfile -Command ^
        "$ProgressPreference = 'SilentlyContinue'; " ^
        "try { " ^
        "    Invoke-WebRequest -Uri '!DOWNLOAD_URL!' -OutFile '!FILENAME!' -UseBasicParsing; " ^
        "    Write-Host '  Download completed.' " ^
        "} catch { " ^
        "    Write-Host '  [ERROR] Download failed:' $_.Exception.Message; " ^
        "    exit 1 " ^
        "}"

    if not exist "!FILENAME!" (
        echo   [ERROR] Download failed.
        echo   Download manually from: https://mitmproxy.org/downloads/
        echo   Extract into mitmproxy\ folder inside this directory.
        pause
        exit /b 1
    )

    :: Extract
    echo   Extracting...
    if exist "mitmproxy" rmdir /s /q "mitmproxy"
    mkdir "mitmproxy"

    powershell -NoProfile -Command ^
        "try { " ^
        "    Expand-Archive -Path '!FILENAME!' -DestinationPath 'mitmproxy' -Force; " ^
        "    Write-Host '  Extraction completed.' " ^
        "} catch { " ^
        "    Write-Host '  [ERROR] Extraction failed:' $_.Exception.Message; " ^
        "    exit 1 " ^
        "}"

    if not exist "%MITMDUMP%" (
        echo   [ERROR] Extraction failed or unexpected archive structure.
        pause
        exit /b 1
    )

    del /f "!FILENAME!" 2>nul
    echo   [OK] mitmproxy downloaded and extracted.
    echo.
)

:: ============================================================
:: STEP 2: Generate certificate
:: ============================================================
if exist "%CERT_PATH%" (
    echo [STEP 2/4] CA certificate      ... ALREADY EXISTS [SKIP]
) else (
    echo [STEP 2/4] Generating CA certificate...

    start /b "" "%MITMDUMP%" --set listen_port=18943
    timeout /t 3 /nobreak >nul
    taskkill /f /im mitmdump.exe >nul 2>&1

    if not exist "%CERT_PATH%" (
        echo   [ERROR] Certificate generation failed.
        echo   Try running %MITMDUMP% manually once, then re-run this script.
        pause
        exit /b 1
    )
    echo   [OK] Certificate generated at %CERT_PATH%
    echo.
)

:: ============================================================
:: STEP 3: Install certificate to trusted root store
:: ============================================================
:: Check if mitmproxy CA is already in the trusted root store
set "CERT_INSTALLED=0"
for /f %%i in ('powershell -NoProfile -Command "(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Issuer -match 'mitmproxy' }).Count"') do set "CERT_INSTALLED=%%i"

if "%CERT_INSTALLED%" GEQ "1" (
    echo [STEP 3/4] Trusted root cert   ... ALREADY INSTALLED [SKIP]
) else (
    echo [STEP 3/4] Installing certificate to trusted root store...
    echo   [NOTE] A UAC prompt will appear - please click "Yes".
    echo.

    powershell -NoProfile -Command "Start-Process 'certutil' -ArgumentList '-addstore','root','%CERT_PATH%' -Verb RunAs -Wait"

    :: Verify installation
    set "CERT_VERIFY=0"
    for /f %%i in ('powershell -NoProfile -Command "(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Issuer -match 'mitmproxy' }).Count"') do set "CERT_VERIFY=%%i"

    if "!CERT_VERIFY!" GEQ "1" (
        echo   [OK] Certificate installed successfully.
    ) else (
        echo   [WARNING] Could not verify certificate installation.
        echo   If HTTPS doesn't work, install manually:
        echo     1. Open %CERT_PATH%
        echo     2. Install Certificate ^> Local Machine
        echo     3. Trusted Root Certification Authorities
    )
    echo.
)

:: ============================================================
:: STEP 4: Run proxy
:: ============================================================
if not exist "%CONFIG_PATH%" (
    echo [STEP 4/4] config.json          ... NOT FOUND [ERROR]
    echo.
    echo   [ERROR] config.json not found in client\ folder.
    echo   Copy config.json.sample to config.json and configure your profiles:
    echo     copy "%CONFIG_SAMPLE%" "%CONFIG_PATH%"
    pause
    exit /b 1
)

echo [STEP 4/4] config.json          ... FOUND [OK]
echo.
echo ============================================================
echo   All checks passed! Starting proxy on port 8080...
echo   System proxy: 127.0.0.1:8080
echo   Press Ctrl+C to stop.
echo ============================================================
echo.

"%MITMDUMP%" -q -s ..\proxy.py --set listen_port=8080

echo.
echo [INFO] Proxy server stopped.
pause
