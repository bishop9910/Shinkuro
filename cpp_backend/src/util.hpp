// Small helpers shared across the backend: hex, little-endian byte packing,
// constant-time comparison, and UTF-8 <-> filesystem path conversion.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace shinkuro {

using Bytes = std::vector<uint8_t>;

inline std::string to_hex(const Bytes& b) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(b.size() * 2);
  for (uint8_t x : b) {
    out.push_back(digits[x >> 4]);
    out.push_back(digits[x & 0xF]);
  }
  return out;
}

inline Bytes from_hex(const std::string& hex) {
  Bytes out;
  out.reserve(hex.size() / 2);
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    int hi = nib(hex[i]);
    int lo = nib(hex[i + 1]);
    if (hi < 0 || lo < 0) return Bytes();
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

inline void append_u32(Bytes& b, uint32_t v) {
  b.push_back(static_cast<uint8_t>(v & 0xFF));
  b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline void append_u64(Bytes& b, uint64_t v) {
  for (int i = 0; i < 8; i++) b.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

inline bool constant_time_eq(const Bytes& a, const Bytes& b) {
  if (a.size() != b.size()) return false;
  unsigned char r = 0;
  for (size_t i = 0; i < a.size(); i++) r |= a[i] ^ b[i];
  return r == 0;
}

// Convert a UTF-8 string (as received over JSON-RPC) to a filesystem path.
inline std::filesystem::path to_path(const std::string& utf8) {
  return std::filesystem::u8path(utf8);
}

// Take the trailing component of a name, stripping any directory separators.
// Used defensively so a stored filename can never escape the temp directory.
inline std::string basename_utf8(const std::string& name) {
  size_t p = name.find_last_of("/\\");
  std::string b = (p == std::string::npos) ? name : name.substr(p + 1);
  if (b.empty() || b == "." || b == "..") b = "file";
  return b;
}

}  // namespace shinkuro
