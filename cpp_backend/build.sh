#!/usr/bin/env bash
# ============================================================================
#  Shinkuro vault backend build script (MinGW-w64 g++, C++17)
#
#  Requirements:
#    - g++ in PATH (MinGW-w64)
#    - OpenSSL (libcrypto): pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
#
#  Usage:  bash build.sh [debug]   (safe to run from any directory)
# ============================================================================
set -e

# Switch to this script's own directory so relative paths resolve.
cd "$(dirname "$0")"

SRC="src/main.cpp src/vault.cpp src/crypto.cpp"
OUT="build"
mkdir -p "$OUT"

FLAGS="-std=c++17 -O2 -Wall -Wextra -Isrc"
if [ "$1" = "debug" ]; then
  FLAGS="-std=c++17 -O0 -g -Wall -Wextra -Isrc"
fi

echo "Compiling vault_backend.exe ..."
g++ $FLAGS $SRC -o "$OUT/vault_backend.exe" -lcrypto -lws2_32 -lcrypt32

# Bundle the OpenSSL runtime DLL next to the exe (best effort).
DLL="$(command -v libcrypto-3-x64.dll 2>/dev/null || true)"
if [ -z "$DLL" ]; then
  DLL="$(command -v libcrypto-1_1-x64.dll 2>/dev/null || true)"
fi
if [ -n "$DLL" ]; then
  cp -f "$DLL" "$OUT/" 2>/dev/null || true
fi

echo "Built: $OUT/vault_backend.exe"
