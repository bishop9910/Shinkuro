#!/usr/bin/env bash
# ============================================================================
#  Shinkuro vault backend build script (Linux, g++, C++17)
#
#  Requirements:
#    - g++ (with C++17 support)
#    - OpenSSL dev headers + libcrypto
#
#      Debian/Ubuntu:  sudo apt install build-essential libssl-dev
#      Arch:           sudo pacman -S base-devel openssl
#      Fedora:         sudo dnf install gcc-c++ openssl-devel
#
#  Usage:  bash build-linux.sh [debug]
# ============================================================================
set -e

# Switch to this script's own directory so relative paths resolve.
cd "$(dirname "$0")"

SRC="src/main.cpp src/vault.cpp src/index.cpp src/crypto.cpp"
OUT="build"
mkdir -p "$OUT"

FLAGS="-std=c++17 -O2 -Wall -Wextra -Isrc"
if [ "$1" = "debug" ]; then
  FLAGS="-std=c++17 -O0 -g -Wall -Wextra -Isrc"
fi

echo "Compiling vault_backend ..."
g++ $FLAGS $SRC -o "$OUT/vault_backend" -lcrypto -lpthread
echo "Built: $OUT/vault_backend"