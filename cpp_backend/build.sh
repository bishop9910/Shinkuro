#!/usr/bin/env bash
# ============================================================================
#  Shinkuro vault backend build script (MinGW-w64 g++, C++17)
#
#  Requirements:
#    - g++ in PATH (MinGW-w64)
#    - OpenSSL (libcrypto) static library:
#      pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
#
#  Usage:  bash build.sh [debug]   (safe to run from any directory)
#
#  Notes: built with -static, so the exe has NO runtime DLL dependencies.
# ============================================================================
set -e

# Switch to this script's own directory so relative paths resolve.
cd "$(dirname "$0")"

SRC="src/main.cpp src/vault.cpp src/crypto.cpp"
OUT="build"
mkdir -p "$OUT"

FLAGS="-static -std=c++17 -O2 -Wall -Wextra -Isrc"
if [ "$1" = "debug" ]; then
  FLAGS="-static -std=c++17 -O0 -g -Wall -Wextra -Isrc"
fi

echo "Compiling vault_backend.exe ..."
g++ $FLAGS $SRC -o "$OUT/vault_backend.exe" -lcrypto -lws2_32 -lcrypt32
echo "Built: $OUT/vault_backend.exe (static, no extra DLLs needed)"
