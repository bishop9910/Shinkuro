@echo off
setlocal
REM ============================================================================
REM  Shinkuro vault backend build script (MinGW-w64 g++, C++17)
REM
REM  Requirements:
REM    - g++ in PATH (MinGW-w64)
REM    - OpenSSL (libcrypto) headers + import library
REM      MSYS2 : pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
REM
REM  Usage:  build.bat [debug]
REM          Safe to run from any directory (e.g. `npm run build:backend` from
REM          the project root) — it switches to its own directory first.
REM ============================================================================

REM Always switch to this script's own directory so relative paths resolve,
REM no matter where the script is invoked from.
cd /d "%~dp0"

set "SRC=src\main.cpp src\vault.cpp src\crypto.cpp"
set "OUT=build"
if not exist "%OUT%" mkdir "%OUT%"

set "FLAGS=-std=c++17 -O2 -Wall -Wextra -Isrc"
if /I "%~1"=="debug" set "FLAGS=-std=c++17 -O0 -g -Wall -Wextra -Isrc"

echo Compiling vault_backend.exe ...
g++ %FLAGS% %SRC% -o "%OUT%\vault_backend.exe" -lcrypto -lws2_32 -lcrypt32

if errorlevel 1 (
  echo.
  echo Build FAILED. Make sure g++ and OpenSSL ^(libcrypto^) are installed. See README.md
  exit /b 1
)

REM Bundle the OpenSSL runtime DLL next to the exe so the app finds it without PATH setup.
set "DLL_FOUND="
for /f "delims=" %%P in ('where libcrypto-3-x64.dll 2^>nul') do if not defined DLL_FOUND set "DLL_FOUND=%%P"
if not defined DLL_FOUND for /f "delims=" %%P in ('where libcrypto-1_1-x64.dll 2^>nul') do if not defined DLL_FOUND set "DLL_FOUND=%%P"
if defined DLL_FOUND copy /Y "%DLL_FOUND%" "%OUT%\" >nul

echo.
echo Built: %OUT%\vault_backend.exe
endlocal
