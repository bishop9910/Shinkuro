@echo off
setlocal
REM ============================================================================
REM  Shinkuro vault backend build script (MinGW-w64 g++, C++17)
REM
REM  Requirements:
REM    - g++ in PATH (MinGW-w64)
REM    - OpenSSL (libcrypto) static library
REM      MSYS2 : pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
REM
REM  Usage:  build.bat [debug]
REM          Safe to run from any directory (e.g. `npm run build:backend` from
REM          the project root) — it switches to its own directory first.
REM
REM  Notes: built with -static, so the exe has NO runtime DLL dependencies
REM         (libstdc++ / libgcc / winpthread / libcrypto are all linked in).
REM ============================================================================

REM Always switch to this script's own directory so relative paths resolve.
cd /d "%~dp0"

set "SRC=src\main.cpp src\vault.cpp src\crypto.cpp"
set "OUT=build"
if not exist "%OUT%" mkdir "%OUT%"

set "FLAGS=-static -std=c++17 -O2 -Wall -Wextra -Isrc"
if /I "%~1"=="debug" set "FLAGS=-static -std=c++17 -O0 -g -Wall -Wextra -Isrc"

echo Compiling vault_backend.exe ...
g++ %FLAGS% %SRC% -o "%OUT%\vault_backend.exe" -lcrypto -lws2_32 -lcrypt32

if errorlevel 1 (
  echo.
  echo Build FAILED. Make sure g++ and OpenSSL ^(static libcrypto.a^) are installed. See README.md
  exit /b 1
)

echo.
echo Built: %OUT%\vault_backend.exe ^(static, no extra DLLs needed^)
endlocal
