// Builds a legacy (v1, JSON-blob) vault + index using the crypto primitives,
// then opens it with the new Vault to verify backward-compatible migration to
// the encrypted B+ tree index.
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

#include "crypto.hpp"
#include "util.hpp"
#include "vault.hpp"

using namespace shinkuro;

namespace {

void put_u32(Bytes& b, uint32_t v) {
  b.push_back((uint8_t)(v & 0xFF));
  b.push_back((uint8_t)((v >> 8) & 0xFF));
  b.push_back((uint8_t)((v >> 16) & 0xFF));
  b.push_back((uint8_t)((v >> 24) & 0xFF));
}

FILE* open_w(const std::filesystem::path& p) {
#ifdef _WIN32
  return _wfopen(p.c_str(), L"wb");
#else
  return std::fopen(p.string().c_str(), "wb");
#endif
}

void build_legacy(const std::filesystem::path& vault, const std::filesystem::path& idx,
                  const std::string& password, const std::string& data) {
  const char* VLT = "SKVLT001";
  const char* IDX = "SKIDX001";
  const uint32_t VER = 1, ITER = 600000;

  Bytes salt = random_bytes(16);
  Bytes token = random_bytes(32);
  Bytes master = pbkdf2_sha256(password, salt, ITER, 32);
  Bytes sidx = {'S', 'K', 'i', 'd', 'x', 'v', '1'};
  Bytes schk = {'S', 'K', 'c', 'h', 'n', 'k', 'v', '1'};
  Bytes idx_key = hkdf_sha256(master, sidx, token, 32);
  Bytes chunk_key = hkdf_sha256(master, schk, token, 32);

  Bytes fid = random_bytes(16);
  Bytes nonce = random_bytes(12);
  Bytes aad = fid;
  append_u64(aad, data.size());
  auto [cipher, tag] = gcm_encrypt(chunk_key, nonce, aad, Bytes(data.begin(), data.end()));

  // ---- .vault ----
  FILE* vf = open_w(vault);
  fwrite(VLT, 1, 8, vf);
  Bytes h;
  put_u32(h, VER); fwrite(h.data(), 1, h.size(), vf);
  h.clear(); put_u32(h, ITER); fwrite(h.data(), 1, h.size(), vf);
  fwrite(salt.data(), 1, salt.size(), vf);
  fwrite(token.data(), 1, token.size(), vf);
  Bytes res(32, 0); fwrite(res.data(), 1, res.size(), vf);
  fwrite(nonce.data(), 1, nonce.size(), vf);
  Bytes dl;
  put_u32(dl, 0); put_u32(dl, 0);  // data_len as u64 LE (8 bytes)
  for (int i = 0; i < 8; i++) dl[i] = (uint8_t)((data.size() >> (8 * i)) & 0xFF);
  fwrite(dl.data(), 1, dl.size(), vf);
  fwrite(cipher.data(), 1, cipher.size(), vf);
  fwrite(tag.data(), 1, tag.size(), vf);
  fclose(vf);

  // ---- legacy .idx (JSON blob) ----
  std::string json = "{\"version\":1,\"pair_token\":\"" + to_hex(token) +
                     "\",\"files\":[{\"name\":\"a.txt\",\"size\":" + std::to_string(data.size()) +
                     ",\"offset\":96,\"mtime\":0,\"id\":\"" + to_hex(fid) + "\"}],\"free\":[]}";
  Bytes plain(json.begin(), json.end());
  Bytes inonce = random_bytes(12);
  Bytes iaad;
  iaad.insert(iaad.end(), IDX, IDX + 8);
  put_u32(iaad, VER);
  iaad.insert(iaad.end(), token.begin(), token.end());
  auto [icipher, itag] = gcm_encrypt(idx_key, inonce, iaad, plain);

  FILE* f = open_w(idx);
  fwrite(IDX, 1, 8, f);
  Bytes ih;
  put_u32(ih, VER); fwrite(ih.data(), 1, ih.size(), f);
  fwrite(token.data(), 1, token.size(), f);
  fwrite(inonce.data(), 1, inonce.size(), f);
  Bytes cl;
  for (int i = 0; i < 8; i++) cl.push_back((uint8_t)((icipher.size() >> (8 * i)) & 0xFF));
  fwrite(cl.data(), 1, cl.size(), f);
  fwrite(icipher.data(), 1, icipher.size(), f);
  fwrite(itag.data(), 1, itag.size(), f);
  fclose(f);
}

std::string read_magic(const std::filesystem::path& p) {
  FILE* f = nullptr;
#ifdef _WIN32
  f = _wfopen(p.c_str(), L"rb");
#else
  f = std::fopen(p.string().c_str(), "rb");
#endif
  char m[8] = {0};
  fread(m, 1, 8, f);
  fclose(f);
  return std::string(m, 8);
}

}  // namespace

int main() {
  std::filesystem::path dir = std::filesystem::temp_directory_path() /
                               std::filesystem::u8path("shinkuro_migration_test");
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  std::filesystem::create_directories(dir, ec);

  std::filesystem::path vault = dir / std::filesystem::u8path("v.vault");
  std::filesystem::path idx = dir / std::filesystem::u8path("v.vault.idx");
  std::string data = "AAAA legacy payload";

  build_legacy(vault, idx, "pw", data);

  Vault v;
  bool ok = true;
  try {
    v.open(vault, "pw");
    Json list = v.list();
    int count = (int)list["count"].as_int();
    std::string name = list["files"].as_array()[0]["name"].as_string();
    if (count != 1 || name != "a.txt") {
      std::fprintf(stderr, "list mismatch: count=%d name=%s\n", count, name.c_str());
      ok = false;
    }

    // extract and verify
    Json ex = v.extract("a.txt");
    FILE* rf = nullptr;
#ifdef _WIN32
    rf = _wfopen(std::filesystem::u8path(ex["path"].as_string()).c_str(), L"rb");
#else
    rf = std::fopen(ex["path"].as_string().c_str(), "rb");
#endif
    std::string got(data.size(), '\0');
    fread(&got[0], 1, data.size(), rf);
    fclose(rf);
    if (got != data) {
      std::fprintf(stderr, "extract mismatch\n");
      ok = false;
    }

    std::string magic = read_magic(idx);
    if (magic != "SKIDX002") {
      std::fprintf(stderr, "index not migrated, magic=%s\n", magic.c_str());
      ok = false;
    }

    v.lock();
    // reopen migrated index
    v.open(vault, "pw");
    Json list2 = v.list();
    if ((int)list2["count"].as_int() != 1) ok = false;
    v.lock();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "exception: %s\n", e.what());
    ok = false;
  }

  std::fprintf(stdout, "MIGRATION %s\n", ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
