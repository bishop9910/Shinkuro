#include "vault.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>

#ifdef _WIN32
#include <io.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace shinkuro {

namespace {

constexpr char VAULT_MAGIC[8] = {'S', 'K', 'V', 'L', 'T', '0', '0', '1'};
constexpr char INDEX_MAGIC[8] = {'S', 'K', 'I', 'D', 'X', '0', '0', '1'};  // legacy (v1) magic
constexpr uint32_t VAULT_VERSION = 1;
constexpr uint32_t KDF_ITERATIONS = 600000;  // PBKDF2-HMAC-SHA256 rounds
constexpr size_t SALT_SIZE = 16;
constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t PAIR_TOKEN_SIZE = 32;
constexpr size_t FILE_ID_SIZE = 16;
constexpr size_t VAULT_HEADER_SIZE = 96;  // magic8 + ver4 + iter4 + salt16 + token32 + reserved32
constexpr size_t VAULT_GEN_OFFSET = 64;   // generation (u64) lives at reserved[0..7]
constexpr size_t IDX_GEN_OFFSET = 48;     // generation (u64) in the v2 index header
constexpr size_t CHUNK_BUF = 1024 * 1024;
constexpr size_t INDEX_MAX = 256 * 1024 * 1024;  // sanity cap on legacy index blob

// On-disk size of one file chunk: nonce(12) + data_len(8) + ciphertext + tag(16).
constexpr uint64_t chunk_len(uint64_t data_size) {
  return NONCE_SIZE + 8 + data_size + TAG_SIZE;
}

#ifdef _WIN32
std::string win32_last_error() {
  DWORD err = GetLastError();
  if (err == 0) return "未知错误";
  char buf[512] = {0};
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err,
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), nullptr);
  std::string msg(buf);
  while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' '))
    msg.pop_back();
  return "(" + std::to_string(err) + ") " + msg;
}
#endif

void atomic_replace(const std::filesystem::path& from, const std::filesystem::path& to) {
#ifdef _WIN32
  for (int attempt = 0; attempt < 10; attempt++) {
    if (MoveFileExW(from.c_str(), to.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      return;
    }
    Sleep(150 * (attempt + 1));
  }
  throw VaultError("IO_ERROR", "替换保险柜文件失败: " + win32_last_error());
#else
  std::error_code ec;
  std::filesystem::remove(to, ec);
  std::filesystem::rename(from, to, ec);
  if (ec) throw VaultError("IO_ERROR", "替换保险柜文件失败: " + ec.message());
#endif
}

void atomic_rename(const std::filesystem::path& from, const std::filesystem::path& to) {
#ifdef _WIN32
  for (int attempt = 0; attempt < 10; attempt++) {
    if (MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH)) return;
    Sleep(150 * (attempt + 1));
  }
  throw VaultError("IO_ERROR", "重命名保险柜文件失败: " + win32_last_error());
#else
  std::error_code ec;
  std::filesystem::rename(from, to, ec);
  if (ec) throw VaultError("IO_ERROR", "重命名保险柜文件失败: " + ec.message());
#endif
}

void remove_if_exists(const std::filesystem::path& p) {
  std::error_code ec;
  std::filesystem::remove(p, ec);
}

void fsync_file(FILE* f) {
  if (std::fflush(f) != 0) throw VaultError("IO_ERROR", "刷新文件失败");
#ifdef _WIN32
  if (_commit(_fileno(f)) != 0) throw VaultError("IO_ERROR", "同步文件失败");
#else
  if (::fsync(fileno(f)) != 0) throw VaultError("IO_ERROR", "同步文件失败");
#endif
}

#ifdef _WIN32
// 打开并持有文件句柄，且不共享删除权限（FILE_SHARE_DELETE），
// 从而在保险柜打开期间阻止用户删除 .vault / .idx。
void* acquire_delete_lock(const std::filesystem::path& p) {
  HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  return (h == INVALID_HANDLE_VALUE) ? nullptr : h;
}
void release_delete_lock(void* h) {
  if (h) CloseHandle(h);
}
#endif

// ---- Unicode-safe file opening ----
FILE* fopen_path(const std::filesystem::path& p, const char* mode) {
#ifdef _WIN32
  std::wstring wm;
  for (const char* c = mode; *c; c++)
    wm.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*c)));
  return _wfopen(p.c_str(), wm.c_str());
#else
  return std::fopen(p.string().c_str(), mode);
#endif
}

int file_seek(FILE* f, uint64_t off) {
#ifdef _WIN32
  return _fseeki64(f, static_cast<int64_t>(off), SEEK_SET);
#else
  return fseeko(f, static_cast<off_t>(off), SEEK_SET);
#endif
}

void write_bytes(FILE* f, const void* data, size_t n) {
  if (n > 0 && std::fwrite(data, 1, n, f) != n) throw VaultError("IO_ERROR", "写入失败");
}
void read_bytes(FILE* f, void* data, size_t n) {
  if (n > 0 && std::fread(data, 1, n, f) != n) throw VaultError("IO_ERROR", "读取失败");
}

void write_u32(FILE* f, uint32_t v) {
  uint8_t b[4] = {static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF),
                  static_cast<uint8_t>((v >> 16) & 0xFF), static_cast<uint8_t>((v >> 24) & 0xFF)};
  write_bytes(f, b, 4);
}
uint32_t read_u32(FILE* f) {
  uint8_t b[4];
  read_bytes(f, b, 4);
  return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
         (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}
void write_u64(FILE* f, uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; i++) b[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
  write_bytes(f, b, 8);
}
uint64_t read_u64(FILE* f) {
  uint8_t b[8];
  read_bytes(f, b, 8);
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
  return v;
}

void copy_bytes(FILE* in, FILE* out, uint64_t n) {
  std::vector<uint8_t> buf(CHUNK_BUF);
  while (n > 0) {
    size_t want = static_cast<size_t>(n < CHUNK_BUF ? n : CHUNK_BUF);
    size_t got = std::fread(buf.data(), 1, want, in);
    if (got == 0) throw VaultError("IO_ERROR", "复制时读取失败");
    std::fwrite(buf.data(), 1, got, out);
    n -= got;
  }
}

int64_t last_write_time_unix(const std::filesystem::path& p) {
  auto ftime = std::filesystem::last_write_time(p);
  auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
      ftime - decltype(ftime)::clock::now() + std::chrono::system_clock::now());
  return std::chrono::duration_cast<std::chrono::seconds>(sctp.time_since_epoch()).count();
}

std::string random_hex(size_t n) { return to_hex(random_bytes(n)); }

void shred_file(const std::filesystem::path& p) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(p, ec)) {
    std::filesystem::remove(p, ec);
    return;
  }
  uint64_t sz = std::filesystem::file_size(p, ec);
  FILE* f = fopen_path(p, "rb+");
  if (!f) {
    std::filesystem::remove(p, ec);
    return;
  }
  std::vector<uint8_t> zeros(CHUNK_BUF, 0);
  uint64_t left = sz;
  while (left > 0) {
    size_t n = static_cast<size_t>(left < CHUNK_BUF ? left : CHUNK_BUF);
    std::fwrite(zeros.data(), 1, n, f);
    left -= n;
  }
  std::fflush(f);
  std::fclose(f);
  std::filesystem::remove(p, ec);
}

// Build a complete v2 index file from an in-memory file/free table.
void build_index_file(const std::filesystem::path& dest, const Bytes& key,
                      const Bytes& pair_token, uint64_t gen,
                      const std::vector<FileEntry>& files,
                      const std::vector<FreeRange>& frees) {
  Index fresh;
  fresh.create(dest, key, pair_token, gen);
  for (const auto& e : files) fresh.insert_file(e);
  fresh.set_free(frees);
  fresh.commit();
  fresh.close();
}

}  // namespace

// ---------------------------------------------------------------------------

FileEntry* Vault::find(const std::string& name) {
  for (auto& e : files_)
    if (e.name == name) return &e;
  return nullptr;
}

const FileEntry* Vault::find(const std::string& name) const {
  for (const auto& e : files_)
    if (e.name == name) return &e;
  return nullptr;
}

void Vault::derive_keys(const std::string& password, const Bytes& salt, uint32_t iterations) {
  master_key_ = pbkdf2_sha256(password, salt, iterations, KEY_SIZE);
  Bytes salt_idx = {'S', 'K', 'i', 'd', 'x', 'v', '1'};
  Bytes salt_chk = {'S', 'K', 'c', 'h', 'n', 'k', 'v', '1'};
  // Bind both derived keys to the pair token so a swapped vault/index fails.
  idx_key_ = hkdf_sha256(master_key_, salt_idx, pair_token_, KEY_SIZE);
  chunk_key_ = hkdf_sha256(master_key_, salt_chk, pair_token_, KEY_SIZE);
}

void Vault::clear_keys() {
  release_locks();
  index_.close();
  secure_zero(master_key_);
  secure_zero(idx_key_);
  secure_zero(chunk_key_);
  for (auto& e : files_) secure_zero(e.file_id);
  secure_zero(pair_token_);
  secure_zero(salt_);
  iterations_ = 0;
  generation_ = 0;
  files_.clear();
  free_.clear();
}

void Vault::lock() {
  wipe_temp_dir();
  clear_keys();
  open_ = false;
}

std::filesystem::path Vault::make_temp_dir() {
  auto base = std::filesystem::temp_directory_path() / std::filesystem::u8path("shinkuro-vault");
  std::error_code ec;
  std::filesystem::create_directories(base, ec);
  std::filesystem::path d = base / std::filesystem::u8path(random_hex(16));
  std::filesystem::create_directory(d, ec);
  return d;
}

void Vault::wipe_temp_dir() {
  if (temp_dir_.empty()) return;
  std::error_code ec;
  if (std::filesystem::exists(temp_dir_, ec)) {
    std::filesystem::directory_iterator it(temp_dir_, ec);
    std::filesystem::directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
      shred_file(it->path());
    }
    std::filesystem::remove_all(temp_dir_, ec);
  }
  temp_dir_.clear();
}

void Vault::acquire_locks() {
#ifdef _WIN32
  release_locks();
  vault_lock_ = acquire_delete_lock(vault_path_);
  idx_lock_ = acquire_delete_lock(index_path_);
#endif
}

void Vault::release_locks() {
#ifdef _WIN32
  release_delete_lock(vault_lock_);
  release_delete_lock(idx_lock_);
  vault_lock_ = nullptr;
  idx_lock_ = nullptr;
#endif
}

void Vault::release_vault_lock() {
#ifdef _WIN32
  release_delete_lock(vault_lock_);
  vault_lock_ = nullptr;
#endif
}

void Vault::acquire_vault_lock() {
#ifdef _WIN32
  vault_lock_ = acquire_delete_lock(vault_path_);
#endif
}

void Vault::release_idx_lock() {
#ifdef _WIN32
  release_delete_lock(idx_lock_);
  idx_lock_ = nullptr;
#endif
}

void Vault::acquire_idx_lock() {
#ifdef _WIN32
  idx_lock_ = acquire_delete_lock(index_path_);
#endif
}

// ---------------------------------------------------------------------------

void Vault::write_vault_header(FILE* f, uint64_t gen) {
  write_bytes(f, VAULT_MAGIC, 8);
  write_u32(f, VAULT_VERSION);
  write_u32(f, iterations_);
  write_bytes(f, salt_.data(), salt_.size());
  write_bytes(f, pair_token_.data(), pair_token_.size());
  Bytes reserved(32, 0);
  for (int i = 0; i < 8; i++) reserved[i] = static_cast<uint8_t>((gen >> (i * 8)) & 0xFF);
  write_bytes(f, reserved.data(), reserved.size());
}

void Vault::read_vault_header() {
  FILE* f = fopen_path(vault_path_, "rb");
  if (!f) throw VaultError("IO_ERROR", "无法打开保险柜文件");
  try {
    char magic[8];
    read_bytes(f, magic, 8);
    if (std::memcmp(magic, VAULT_MAGIC, 8) != 0)
      throw VaultError("CORRUPT", "不是有效的保险柜文件");
    uint32_t version = read_u32(f);
    if (version != VAULT_VERSION) throw VaultError("CORRUPT", "不支持的保险柜版本");
    iterations_ = read_u32(f);
    Bytes salt(SALT_SIZE);
    read_bytes(f, salt.data(), salt.size());
    salt_ = salt;
    Bytes token(PAIR_TOKEN_SIZE);
    read_bytes(f, token.data(), token.size());
    pair_token_ = token;
    Bytes reserved(32);
    read_bytes(f, reserved.data(), reserved.size());
    uint64_t gen = 0;
    for (int i = 0; i < 8; i++) gen |= static_cast<uint64_t>(reserved[i]) << (i * 8);
    generation_ = gen;
  } catch (...) {
    std::fclose(f);
    throw;
  }
  std::fclose(f);
}

void Vault::create(const std::filesystem::path& vault_path, const std::string& password) {
  if (open_) throw VaultError("ALREADY_OPEN", "已有打开的保险柜");
  if (password.empty()) throw VaultError("INVALID", "密码不能为空");

  vault_path_ = vault_path;
  index_path_ = vault_path_;
  index_path_ += ".idx";

  if (std::filesystem::exists(vault_path_) || std::filesystem::exists(index_path_))
    throw VaultError("ALREADY_EXISTS", "目标文件已存在");

  auto parent = vault_path_.parent_path();
  if (!parent.empty() && !std::filesystem::exists(parent)) {
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) throw VaultError("IO_ERROR", "无法创建目标目录");
  }

  salt_ = random_bytes(SALT_SIZE);
  iterations_ = KDF_ITERATIONS;
  pair_token_ = random_bytes(PAIR_TOKEN_SIZE);
  generation_ = 1;
  derive_keys(password, salt_, KDF_ITERATIONS);

  FILE* f = fopen_path(vault_path_, "wb");
  if (!f) {
    clear_keys();
    throw VaultError("IO_ERROR", "无法创建保险柜文件");
  }
  try {
    write_vault_header(f, generation_);
  } catch (...) {
    std::fclose(f);
    clear_keys();
    std::error_code ec;
    std::filesystem::remove(vault_path_, ec);
    throw;
  }
  std::fclose(f);

  files_.clear();
  free_.clear();
  open_ = true;
  try {
    index_.create(index_path_, idx_key_, pair_token_, generation_);
  } catch (...) {
    lock();
    throw;
  }
  temp_dir_ = make_temp_dir();
  acquire_locks();
}

// ---------------------------------------------------------------------------

std::string Vault::read_index_magic() const {
  FILE* f = fopen_path(index_path_, "rb");
  if (!f) throw VaultError("IO_ERROR", "无法打开索引文件");
  char magic[8] = {0};
  size_t n = std::fread(magic, 1, 8, f);
  std::fclose(f);
  if (n < 8) throw VaultError("CORRUPT", "索引文件格式错误");
  return std::string(magic, 8);
}

void Vault::rebuild_mirrors() {
  files_.clear();
  std::vector<FileEntry> fs;
  index_.iterate_files([&](const FileEntry& e) { fs.push_back(e); });
  std::sort(fs.begin(), fs.end(), [](const FileEntry& a, const FileEntry& b) {
    return a.seq < b.seq;
  });
  files_ = std::move(fs);

  free_.clear();
  std::vector<FreeRange> fr;
  index_.iterate_free([&](const FreeRange& r) { fr.push_back(r); });
  std::sort(fr.begin(), fr.end(),
            [](const FreeRange& a, const FreeRange& b) { return a.offset < b.offset; });
  free_ = std::move(fr);
}

void Vault::load_index_v2() {
  index_.open(index_path_, idx_key_, pair_token_, generation_);
  rebuild_mirrors();
}

void Vault::load_index_legacy() {
  FILE* f = fopen_path(index_path_, "rb");
  if (!f) throw VaultError("IO_ERROR", "无法打开索引文件");

  char magic[8];
  uint32_t version = 0;
  Bytes token(PAIR_TOKEN_SIZE);
  Bytes nonce(NONCE_SIZE);
  uint64_t clen = 0;
  Bytes cipher, tag;
  try {
    read_bytes(f, magic, 8);
    if (std::memcmp(magic, INDEX_MAGIC, 8) != 0) throw VaultError("CORRUPT", "索引文件格式错误");
    version = read_u32(f);
    if (version != VAULT_VERSION) throw VaultError("CORRUPT", "索引版本不支持");
    read_bytes(f, token.data(), token.size());
    if (!constant_time_eq(token, pair_token_))
      throw VaultError("MISMATCHED_PAIR", "保险柜与索引文件不匹配（强绑定校验失败）");
    read_bytes(f, nonce.data(), nonce.size());
    clen = read_u64(f);
    if (clen > INDEX_MAX) throw VaultError("CORRUPT", "索引文件损坏");
    cipher.resize(clen);
    read_bytes(f, cipher.data(), cipher.size());
    tag.resize(TAG_SIZE);
    read_bytes(f, tag.data(), tag.size());
  } catch (...) {
    std::fclose(f);
    throw;
  }
  std::fclose(f);

  Bytes aad;
  aad.insert(aad.end(), INDEX_MAGIC, INDEX_MAGIC + 8);
  append_u32(aad, version);
  aad.insert(aad.end(), pair_token_.begin(), pair_token_.end());

  Bytes plain;
  try {
    plain = gcm_decrypt(idx_key_, nonce, aad, cipher, tag);
  } catch (const AuthError&) {
    throw VaultError("WRONG_PASSWORD", "密码错误");
  }

  Json root;
  try {
    root = Json::parse(std::string(plain.begin(), plain.end()));
  } catch (const std::exception&) {
    secure_zero(plain);
    throw VaultError("CORRUPT", "索引解析失败");
  }

  if (root["pair_token"].as_string() != to_hex(pair_token_)) {
    secure_zero(plain);
    throw VaultError("CORRUPT", "索引校验失败");
  }

  files_.clear();
  free_.clear();
  uint64_t seq = 0;
  for (const auto& item : root["files"].as_array()) {
    FileEntry e;
    e.name = item["name"].as_string();
    e.size = static_cast<uint64_t>(item["size"].as_int());
    e.offset = static_cast<uint64_t>(item["offset"].as_int());
    e.mtime = item["mtime"].as_int();
    e.file_id = from_hex(item["id"].as_string());
    e.seq = seq++;
    files_.push_back(std::move(e));
  }
  if (root.has("free")) {
    for (const auto& item : root["free"].as_array()) {
      FreeRange r;
      r.offset = static_cast<uint64_t>(item["offset"].as_int());
      r.size = static_cast<uint64_t>(item["size"].as_int());
      if (r.size > 0 && r.offset >= VAULT_HEADER_SIZE) free_.push_back(r);
    }
    std::sort(free_.begin(), free_.end(),
              [](const FreeRange& a, const FreeRange& b) { return a.offset < b.offset; });
  }
  secure_zero(plain);
}

void Vault::migrate_legacy_index() {
  std::filesystem::path tmp = index_path_;
  tmp += ".tmp";
  build_index_file(tmp, idx_key_, pair_token_, generation_, files_, free_);
  atomic_replace(tmp, index_path_);
  index_.open(index_path_, idx_key_, pair_token_, generation_);
}

void Vault::commit_index() {
  index_.set_free(free_);
  index_.commit();
}

void Vault::reload_index_state() {
  index_.reopen(generation_);
  rebuild_mirrors();
}

void Vault::recover_files() {
  std::error_code ec;
  std::filesystem::path vault_old = vault_path_;
  vault_old += ".old";
  std::filesystem::path idx_old = index_path_;
  idx_old += ".old";
  std::filesystem::path vault_tmp = vault_path_;
  vault_tmp += ".tmp";
  std::filesystem::path idx_tmp = index_path_;
  idx_tmp += ".tmp";

  bool has_vault_old = std::filesystem::exists(vault_old, ec);
  bool has_idx_old = std::filesystem::exists(idx_old, ec);
  bool has_vault_tmp = std::filesystem::exists(vault_tmp, ec);
  bool has_idx_tmp = std::filesystem::exists(idx_tmp, ec);
  if (!has_vault_old && !has_idx_old && !has_vault_tmp && !has_idx_tmp) return;

  bool vault_exists = std::filesystem::exists(vault_path_, ec);
  bool idx_exists = std::filesystem::exists(index_path_, ec);

  // A missing live file is restored from its backup via rename (dest is absent).
  if (!vault_exists && has_vault_old) {
    atomic_rename(vault_old, vault_path_);
    vault_exists = true;
    has_vault_old = false;
  }
  if (!idx_exists && has_idx_old) {
    atomic_rename(idx_old, index_path_);
    idx_exists = true;
    has_idx_old = false;
  }

  if (!vault_exists || !idx_exists) {
    // Cannot fully recover here; drop temporaries and let normal load report it.
    remove_if_exists(vault_tmp);
    remove_if_exists(idx_tmp);
    return;
  }

  // Plaintext generation comparison (no key material needed): if both files
  // carry the same generation the pair committed cleanly; otherwise it is a
  // torn compact/change_password and we roll back to the backups.
  uint64_t gv = 0;
  {
    FILE* f = fopen_path(vault_path_, "rb");
    if (!f) return;  // let normal load surface the error
    file_seek(f, VAULT_GEN_OFFSET);
    gv = read_u64(f);
    std::fclose(f);
  }

  bool consistent = false;
  std::string magic = read_index_magic();
  if (magic == "SKIDX002") {
    FILE* f = fopen_path(index_path_, "rb");
    if (f) {
      file_seek(f, IDX_GEN_OFFSET);
      consistent = (read_u64(f) == gv);
      std::fclose(f);
    }
  } else if (magic == "SKIDX001") {
    consistent = (gv == 0);  // legacy index has no generation
  }

  if (consistent) {
    remove_if_exists(vault_old);
    remove_if_exists(idx_old);
    remove_if_exists(vault_tmp);
    remove_if_exists(idx_tmp);
    return;
  }

  // Torn state -> roll back to the backup pair.
  if (has_vault_old) atomic_replace(vault_old, vault_path_);
  if (has_idx_old) atomic_replace(idx_old, index_path_);
  remove_if_exists(vault_tmp);
  remove_if_exists(idx_tmp);
}

void Vault::swap_pair_in() {
  std::filesystem::path vault_tmp = vault_path_;
  vault_tmp += ".tmp";
  std::filesystem::path idx_tmp = index_path_;
  idx_tmp += ".tmp";
  std::filesystem::path vault_old = vault_path_;
  vault_old += ".old";
  std::filesystem::path idx_old = index_path_;
  idx_old += ".old";

  release_vault_lock();
  release_idx_lock();
  index_.close();

  std::exception_ptr err;
  try {
    remove_if_exists(vault_old);
    remove_if_exists(idx_old);
    atomic_rename(vault_path_, vault_old);
    atomic_rename(index_path_, idx_old);
    atomic_rename(vault_tmp, vault_path_);
    atomic_rename(idx_tmp, index_path_);
    remove_if_exists(vault_old);
    remove_if_exists(idx_old);
  } catch (...) {
    err = std::current_exception();
  }

  acquire_vault_lock();
  acquire_idx_lock();

  if (err) {
    // Best-effort reopen of whatever is on disk; recovery at next open() heals
    // any remaining torn state from the .old backups.
    try {
      index_.open(index_path_, idx_key_, pair_token_, generation_);
    } catch (...) {
      index_.close();
    }
    std::rethrow_exception(err);
  }
}

void Vault::trim_trailing_garbage() {
  // Reclaim the holes that reach EOF in the in-memory table first, so the commit
  // below persists a table that never points past EOF; the file is shrunk last
  // (a crash in between only leaves unreferenced trailing bytes).
  const uint64_t shrink_to = reclaim_trailing_free();
  const uint64_t vsize = vault_file_size();
  uint64_t end = VAULT_HEADER_SIZE;
  for (const auto& e : files_) {
    uint64_t eend = e.offset + NONCE_SIZE + 8 + e.size + TAG_SIZE;
    if (eend > end) end = eend;
  }
  for (const auto& r : free_) {
    uint64_t rend = r.offset + r.size;
    if (rend > end) end = rend;
  }
  if (end > vsize) end = vsize;
  if (shrink_to != 0) commit_index();
  if (end < vsize) truncate_vault(end);
}

void Vault::maybe_auto_reindex() {
  uint64_t next = index_.next_page();
  uint64_t live = index_.live_page_count();
  if (next < 64 || next < 2 * (live + 1)) return;
  release_idx_lock();
  try {
    index_.reindex(files_, free_, generation_);
  } catch (...) {
    acquire_idx_lock();
    try {
      index_.open(index_path_, idx_key_, pair_token_, generation_);
    } catch (...) {
      index_.close();
    }
    throw;
  }
  acquire_idx_lock();
}

void Vault::open(const std::filesystem::path& vault_path, const std::string& password) {
  if (open_) lock();
  vault_path_ = vault_path;
  index_path_ = vault_path_;
  index_path_ += ".idx";

  if (!std::filesystem::exists(vault_path_)) throw VaultError("NOT_FOUND", "保险柜文件不存在");
  if (!std::filesystem::exists(index_path_))
    throw VaultError("NOT_FOUND", "索引文件不存在，无法验证保险柜完整性");

  read_vault_header();  // salt_ / iterations_ / pair_token_ / generation_
  try {
    derive_keys(password, salt_, iterations_);
  } catch (...) {
    clear_keys();
    throw;
  }

  try {
    recover_files();      // heal interrupted compact/change_password
    read_vault_header();  // re-read generation_ after any rollback

    std::string magic = read_index_magic();
    if (magic == "SKIDX002") {
      load_index_v2();
    } else if (magic == "SKIDX001") {
      load_index_legacy();
      migrate_legacy_index();
    } else {
      throw VaultError("CORRUPT", "索引文件格式错误");
    }
  } catch (...) {
    clear_keys();
    throw;
  }

  // Sanity: every referenced chunk must live inside the vault file.
  uint64_t vsize = vault_file_size();
  for (const auto& e : files_) {
    uint64_t need = e.offset + NONCE_SIZE + 8 + e.size + TAG_SIZE;
    if (e.offset < VAULT_HEADER_SIZE || need > vsize)
      throw VaultError("CORRUPT", "索引与保险柜数据不一致");
  }
  // Holes reaching past EOF are not corruption: an interrupted delete/reindex
  // can leave them behind, and builds before the delete-order fix committed a
  // hole and then shrank the file, so a vault emptied by that build carries one.
  // Drop/clamp them here and persist the repaired table, so such a vault opens
  // as the (smaller or empty) vault it really is instead of as "corrupt".
  bool free_repaired = false;
  for (size_t i = 0; i < free_.size();) {
    FreeRange& r = free_[i];
    if (r.size == 0 || r.offset < VAULT_HEADER_SIZE)
      throw VaultError("CORRUPT", "索引与保险柜数据不一致");
    if (r.offset >= vsize) {  // wholly past EOF
      free_.erase(free_.begin() + static_cast<std::ptrdiff_t>(i));
      free_repaired = true;
      continue;
    }
    if (r.size > vsize - r.offset) {  // reaches past EOF
      r.size = vsize - r.offset;
      free_repaired = true;
    }
    i++;
  }
  if (free_repaired) {
    try {
      commit_index();
    } catch (const std::exception& e) {
      std::fprintf(stderr, "[shinkuro] index repair failed: %s\n", e.what());
    }
  }

  open_ = true;
  // Reclaim trailing garbage / trailing free and persist the result.
  try {
    trim_trailing_garbage();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[shinkuro] trim failed: %s\n", e.what());
  }
  try {
    if (should_auto_compact()) compact();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "[shinkuro] auto-compact failed: %s\n", e.what());
  }
  temp_dir_ = make_temp_dir();
  acquire_locks();
}

// ---------------------------------------------------------------------------

Json Vault::list() const {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  Json arr = Json::Array();
  for (const auto& e : files_) {
    Json o = Json::Object();
    o["name"] = e.name;
    o["size"] = static_cast<int64_t>(e.size);
    o["mtime"] = e.mtime;
    arr.push_back(std::move(o));
  }
  Json res = Json::Object();
  res["path"] = vault_path_.u8string();
  res["count"] = static_cast<int64_t>(files_.size());
  res["physical_size"] = static_cast<int64_t>(vault_file_size());
  res["free_bytes"] = static_cast<int64_t>(free_bytes());
  res["files"] = std::move(arr);
  return res;
}

Json Vault::add(const std::filesystem::path& src_path) {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  std::error_code ec;
  if (!std::filesystem::exists(src_path, ec)) throw VaultError("NOT_FOUND", "源文件不存在");
  if (!std::filesystem::is_regular_file(src_path, ec))
    throw VaultError("INVALID", "只能添加普通文件");

  // 拒绝把保险柜自身或其索引加进去（避免自引用破坏）
  {
    std::error_code c1, c2, c3;
    auto canon_src = std::filesystem::weakly_canonical(src_path, c1);
    auto canon_vault = std::filesystem::weakly_canonical(vault_path_, c2);
    auto canon_idx = std::filesystem::weakly_canonical(index_path_, c3);
    if (!c1 && !c2 && !c3 && (canon_src == canon_vault || canon_src == canon_idx))
      throw VaultError("INVALID", "不能把保险柜文件本身添加进去");
  }

  std::string name = src_path.filename().u8string();
  if (find(name)) throw VaultError("EXISTS", "已存在同名文件: " + name);

  uint64_t src_size = std::filesystem::file_size(src_path, ec);
  int64_t mtime = last_write_time_unix(src_path);
  Bytes file_id = random_bytes(FILE_ID_SIZE);
  Bytes nonce = random_bytes(NONCE_SIZE);

  uint64_t need = chunk_len(src_size);
  uint64_t offset = 0;
  size_t reuse_idx = free_.size();
  bool reuse = find_free_fit(need, offset, reuse_idx);

  FILE* in = fopen_path(src_path, "rb");
  if (!in) throw VaultError("IO_ERROR", "无法读取源文件");

  FILE* vf = nullptr;
  if (reuse) {
    vf = fopen_path(vault_path_, "rb+");
    if (vf && file_seek(vf, offset) != 0) {
      std::fclose(vf);
      vf = nullptr;
    }
  } else {
    offset = vault_file_size();
    vf = fopen_path(vault_path_, "ab");
  }
  if (!vf) {
    std::fclose(in);
    throw VaultError("IO_ERROR", reuse ? "无法定位保险柜中的空闲空间" : "无法打开保险柜文件");
  }

  Bytes aad = file_id;
  append_u64(aad, src_size);

  report("encrypt", 0, src_size);
  try {
    write_bytes(vf, nonce.data(), nonce.size());
    write_u64(vf, src_size);
    gcm_encrypt_stream(chunk_key_, nonce, aad, in, vf,
                       [&](uint64_t done) { report("encrypt", done, src_size); });
  } catch (...) {
    std::fclose(in);
    std::fclose(vf);
    throw;
  }
  std::fclose(in);
  std::fclose(vf);

  if (reuse) consume_free(reuse_idx, need);

  FileEntry e;
  e.name = name;
  e.size = src_size;
  e.offset = offset;
  e.mtime = mtime;
  e.file_id = std::move(file_id);
  e.seq = files_.empty() ? 0 : files_.back().seq + 1;
  files_.push_back(e);
  index_.insert_file(e);

  try {
    commit_index();
  } catch (...) {
    // Re-sync in-memory state with whatever actually persisted on disk.
    try {
      reload_index_state();
    } catch (...) {
    }
    throw;
  }
  maybe_auto_reindex();

  Json o = Json::Object();
  o["name"] = name;
  o["size"] = static_cast<int64_t>(src_size);
  o["mtime"] = mtime;
  return o;
}

void Vault::decrypt_to(const FileEntry& e, const std::filesystem::path& out_path) {
  FILE* vf = fopen_path(vault_path_, "rb");
  if (!vf) throw VaultError("IO_ERROR", "无法打开保险柜文件");

  Bytes nonce(NONCE_SIZE);
  uint64_t data_len = 0;
  FILE* out = nullptr;
  try {
    if (file_seek(vf, e.offset) != 0) throw VaultError("IO_ERROR", "定位数据失败");
    read_bytes(vf, nonce.data(), nonce.size());
    data_len = read_u64(vf);
    if (data_len != e.size) throw VaultError("CORRUPT", "数据长度不一致");
    out = fopen_path(out_path, "wb");
    if (!out) throw VaultError("IO_ERROR", "无法写入文件");

    Bytes aad = e.file_id;
    append_u64(aad, e.size);
    try {
      gcm_decrypt_stream(chunk_key_, nonce, aad, vf, out, data_len);
    } catch (const AuthError&) {
      throw VaultError("CORRUPT", "数据校验失败，保险柜可能被篡改");
    }
  } catch (...) {
    if (out) std::fclose(out);
    std::fclose(vf);
    std::error_code ec;
    std::filesystem::remove(out_path, ec);
    throw;
  }
  std::fclose(out);
  std::fclose(vf);
}

Json Vault::extract(const std::string& name) {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  const FileEntry* e = find(name);
  if (!e) throw VaultError("NOT_FOUND", "文件不存在: " + name);

  std::string base = basename_utf8(name);
  std::filesystem::path out_path = temp_dir_ / std::filesystem::u8path(base);
  decrypt_to(*e, out_path);

  Json o = Json::Object();
  o["path"] = out_path.u8string();
  o["name"] = base;
  o["size"] = static_cast<int64_t>(e->size);
  return o;
}

Json Vault::extract_to(const std::string& name, const std::filesystem::path& dest) {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  const FileEntry* e = find(name);
  if (!e) throw VaultError("NOT_FOUND", "文件不存在: " + name);

  decrypt_to(*e, dest);

  Json o = Json::Object();
  o["path"] = dest.u8string();
  o["name"] = e->name;
  o["size"] = static_cast<int64_t>(e->size);
  return o;
}

uint64_t Vault::remove(const std::string& name) {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  size_t idx = files_.size();
  for (size_t i = 0; i < files_.size(); i++) {
    if (files_[i].name == name) {
      idx = i;
      break;
    }
  }
  if (idx == files_.size()) throw VaultError("NOT_FOUND", "文件不存在: " + name);

  // O(1) lazy delete: mark the chunk as free instead of rewriting the whole
  // vault. The index commit happens FIRST (atomic) and already carries the
  // reclaimed tail, so the persisted table never describes bytes past EOF; the
  // trailing truncation is an idempotent post-step, so a crash between the two
  // is self-healed at open.
  uint64_t len = chunk_len(files_[idx].size);
  uint64_t off = files_[idx].offset;
  files_.erase(files_.begin() + static_cast<std::ptrdiff_t>(idx));
  index_.erase_file(name);
  add_free(off, len);
  const uint64_t shrink_to = reclaim_trailing_free();

  try {
    commit_index();
  } catch (...) {
    try {
      reload_index_state();
    } catch (...) {
    }
    throw;
  }
  if (shrink_to != 0 && shrink_to < vault_file_size()) {
    try {
      truncate_vault(shrink_to);
    } catch (const std::exception& e) {
      // The delete is already durable; leftover trailing bytes are trimmed at
      // the next open().
      std::fprintf(stderr, "[shinkuro] trim failed: %s\n", e.what());
    }
  }
  maybe_auto_reindex();
  return len;
}

// ---- Free-space management ----

uint64_t Vault::free_bytes() const {
  uint64_t total = 0;
  for (const auto& r : free_) total += r.size;
  return total;
}

uint64_t Vault::vault_file_size() const {
  std::error_code ec;
  uint64_t sz = std::filesystem::file_size(vault_path_, ec);
  if (ec) throw VaultError("IO_ERROR", "读取保险柜文件大小失败: " + ec.message());
  return sz;
}

void Vault::add_free(uint64_t offset, uint64_t size) {
  if (size == 0) return;
  FreeRange r{offset, size};
  auto it = std::lower_bound(free_.begin(), free_.end(), r,
                             [](const FreeRange& a, const FreeRange& b) {
                               return a.offset < b.offset;
                             });
  free_.insert(it, r);
  // Coalesce overlapping/adjacent ranges so free_ stays minimal and sorted.
  for (size_t i = 0; i + 1 < free_.size();) {
    FreeRange& a = free_[i];
    FreeRange& b = free_[i + 1];
    if (a.offset + a.size >= b.offset) {
      uint64_t end = std::max(a.offset + a.size, b.offset + b.size);
      a.size = end - a.offset;
      free_.erase(free_.begin() + static_cast<std::ptrdiff_t>(i + 1));
    } else {
      i++;
    }
  }
}

bool Vault::find_free_fit(uint64_t need, uint64_t& out_offset, size_t& out_idx) const {
  out_idx = free_.size();
  out_offset = 0;
  int64_t best = -1;
  for (size_t i = 0; i < free_.size(); i++) {
    if (free_[i].size >= need) {
      if (best < 0 || free_[i].size < free_[static_cast<size_t>(best)].size)
        best = static_cast<int64_t>(i);
    }
  }
  if (best < 0) return false;
  out_idx = static_cast<size_t>(best);
  out_offset = free_[out_idx].offset;
  return true;
}

void Vault::consume_free(size_t idx, uint64_t need) {
  FreeRange& r = free_[idx];
  r.offset += need;
  r.size -= need;
  if (r.size == 0) free_.erase(free_.begin() + static_cast<std::ptrdiff_t>(idx));
}

uint64_t Vault::reclaim_trailing_free() {
  uint64_t vsize = vault_file_size();
  uint64_t live_end = VAULT_HEADER_SIZE;
  for (const auto& e : files_) {
    uint64_t eend = e.offset + NONCE_SIZE + 8 + e.size + TAG_SIZE;
    if (eend > live_end) live_end = eend;
  }
  uint64_t target = 0;
  while (!free_.empty()) {
    const FreeRange& last = free_.back();
    if (last.offset + last.size < vsize) break;  // interior hole, keep it
    if (last.offset >= vsize) {                  // defensive: fully past EOF
      free_.pop_back();
      continue;
    }
    // A hole overlapping live data can only come from a damaged index, and
    // truncating there would destroy that file: keep the tail instead.
    if (last.offset < live_end) break;
    target = last.offset;
    vsize = last.offset;
    free_.pop_back();
  }
  return target;
}

void Vault::truncate_vault(uint64_t size) {
#ifdef _WIN32
  HANDLE h = CreateFileW(vault_path_.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    throw VaultError("IO_ERROR", "无法打开保险柜文件以截断: " + win32_last_error());
  LARGE_INTEGER li;
  li.QuadPart = static_cast<LONGLONG>(size);
  BOOL ok1 = SetFilePointerEx(h, li, nullptr, FILE_BEGIN);
  BOOL ok2 = SetEndOfFile(h);
  DWORD err = GetLastError();
  CloseHandle(h);
  if (!ok1 || !ok2)
    throw VaultError("IO_ERROR", "截断保险柜文件失败: (" + std::to_string(err) + ")");
#else
  if (::truncate(vault_path_.c_str(), static_cast<off_t>(size)) != 0)
    throw VaultError("IO_ERROR", "截断保险柜文件失败");
#endif
}

void Vault::report(const std::string& phase, uint64_t done, uint64_t total) {
  if (progress_) progress_(phase, done, total);
}

bool Vault::should_auto_compact() const {
  uint64_t free = free_bytes();
  uint64_t vsize = vault_file_size();
  constexpr uint64_t MIN_FREE = 64ull * 1024 * 1024;  // 64 MiB
  if (free < MIN_FREE || vsize == 0) return false;
  return free >= vsize / 4;  // fragmentation >= 25% of the file
}

Json Vault::compact() {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  uint64_t before = vault_file_size();
  uint64_t new_gen = generation_ + 1;

  std::filesystem::path vault_tmp = vault_path_;
  vault_tmp += ".tmp";
  std::filesystem::path idx_tmp = index_path_;
  idx_tmp += ".tmp";

  // Sort kept files by their current offset, then pack them left.
  std::vector<size_t> order(files_.size());
  for (size_t i = 0; i < order.size(); i++) order[i] = i;
  std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
    return files_[a].offset < files_[b].offset;
  });

  std::vector<uint64_t> new_offsets(files_.size(), 0);
  uint64_t after = VAULT_HEADER_SIZE;
  uint64_t total = 0;
  for (const auto& e : files_) total += chunk_len(e.size);
  report("compact", 0, total);
  uint64_t done = 0;

  // 1) Write the tightly-packed vault into vault.tmp (raw chunk copy, no re-encrypt).
  {
    FILE* oldf = fopen_path(vault_path_, "rb");
    if (!oldf) throw VaultError("IO_ERROR", "无法打开保险柜文件");
    FILE* newf = fopen_path(vault_tmp, "wb");
    if (!newf) {
      std::fclose(oldf);
      throw VaultError("IO_ERROR", "无法创建临时文件");
    }
    std::exception_ptr err;
    try {
      write_vault_header(newf, new_gen);
      for (size_t i : order) {
        const FileEntry& e = files_[i];
        uint64_t len = chunk_len(e.size);
        if (file_seek(oldf, e.offset) != 0) throw VaultError("IO_ERROR", "定位数据失败");
        copy_bytes(oldf, newf, len);
        new_offsets[i] = after;
        after += len;
        done += len;
        report("compact", done, total);
      }
      fsync_file(newf);
    } catch (...) {
      err = std::current_exception();
    }
    std::fclose(newf);
    std::fclose(oldf);
    if (err) {
      remove_if_exists(vault_tmp);
      std::rethrow_exception(err);
    }
  }

  // 2) Build the new index (new offsets, empty free list, new generation).
  std::vector<FileEntry> nf = files_;
  for (size_t i = 0; i < nf.size(); i++) nf[i].offset = new_offsets[i];
  build_index_file(idx_tmp, idx_key_, pair_token_, new_gen, nf, /*frees=*/{});

  // 3) Atomically swap the pair in (backup + rename + fsync'd temporaries).
  swap_pair_in();

  // 4) Adopt the new in-memory state.
  files_ = std::move(nf);
  free_.clear();
  generation_ = new_gen;
  index_.open(index_path_, idx_key_, pair_token_, generation_);

  Json o = Json::Object();
  o["before"] = static_cast<int64_t>(before);
  o["after"] = static_cast<int64_t>(after);
  o["freed"] = static_cast<int64_t>(before - after);
  return o;
}

void Vault::change_password(const std::string& old_password, const std::string& new_password) {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  if (new_password.empty()) throw VaultError("INVALID", "新密码不能为空");

  // 校验当前密码（常数时间比较）
  Bytes old_master = pbkdf2_sha256(old_password, salt_, iterations_, KEY_SIZE);
  bool ok = constant_time_eq(old_master, master_key_);
  secure_zero(old_master);
  if (!ok) throw VaultError("WRONG_PASSWORD", "当前密码错误");

  // 派生新密钥（沿用 salt / iterations / pair_token，只换密码）
  Bytes new_master = pbkdf2_sha256(new_password, salt_, iterations_, KEY_SIZE);
  Bytes salt_idx = {'S', 'K', 'i', 'd', 'x', 'v', '1'};
  Bytes salt_chk = {'S', 'K', 'c', 'h', 'n', 'k', 'v', '1'};
  Bytes new_idx_key = hkdf_sha256(new_master, salt_idx, pair_token_, KEY_SIZE);
  Bytes new_chunk_key = hkdf_sha256(new_master, salt_chk, pair_token_, KEY_SIZE);

  uint64_t new_gen = generation_ + 1;
  std::filesystem::path vault_tmp = vault_path_;
  vault_tmp += ".tmp";
  std::filesystem::path idx_tmp = index_path_;
  idx_tmp += ".tmp";

  // 1) Re-encrypt every chunk (same layout) into vault.tmp.
  {
    FILE* oldf = fopen_path(vault_path_, "rb");
    if (!oldf) {
      secure_zero(new_master);
      secure_zero(new_idx_key);
      secure_zero(new_chunk_key);
      throw VaultError("IO_ERROR", "无法打开保险柜文件");
    }
    FILE* newf = fopen_path(vault_tmp, "wb");
    if (!newf) {
      std::fclose(oldf);
      secure_zero(new_master);
      secure_zero(new_idx_key);
      secure_zero(new_chunk_key);
      throw VaultError("IO_ERROR", "无法创建临时文件");
    }
    std::exception_ptr err;
    try {
      write_vault_header(newf, new_gen);
      uint64_t total = 0;
      for (const auto& e : files_) total += e.size;
      report("reencrypt", 0, total);
      uint64_t processed = 0;
      for (const auto& e : files_) {
        if (file_seek(oldf, e.offset) != 0) throw VaultError("IO_ERROR", "定位数据失败");
        Bytes nonce(NONCE_SIZE);
        read_bytes(oldf, nonce.data(), nonce.size());
        uint64_t data_len = read_u64(oldf);
        if (data_len != e.size) throw VaultError("CORRUPT", "数据长度不一致");
        Bytes aad = e.file_id;
        append_u64(aad, e.size);
        Bytes new_nonce = random_bytes(NONCE_SIZE);
        write_bytes(newf, new_nonce.data(), new_nonce.size());
        write_u64(newf, data_len);
        try {
          uint64_t base = processed;
          gcm_reencrypt_stream(chunk_key_, nonce, aad, new_chunk_key, new_nonce, oldf, newf,
                               data_len,
                               [&](uint64_t d) { report("reencrypt", base + d, total); });
          processed += data_len;
        } catch (const AuthError&) {
          throw VaultError("CORRUPT", "数据校验失败，保险柜可能被篡改");
        }
      }
      fsync_file(newf);
    } catch (...) {
      err = std::current_exception();
    }
    std::fclose(newf);
    std::fclose(oldf);
    if (err) {
      remove_if_exists(vault_tmp);
      secure_zero(new_master);
      secure_zero(new_idx_key);
      secure_zero(new_chunk_key);
      std::rethrow_exception(err);
    }
  }

  // 2) Build the new index with the new idx_key (same metadata, same free list).
  build_index_file(idx_tmp, new_idx_key, pair_token_, new_gen, files_, free_);

  // 3) Atomically swap both files in.
  swap_pair_in();

  // 4) Adopt new keys + generation, reopen the index with the new key.
  secure_zero(master_key_);
  master_key_ = std::move(new_master);
  secure_zero(idx_key_);
  idx_key_ = std::move(new_idx_key);
  secure_zero(chunk_key_);
  chunk_key_ = std::move(new_chunk_key);
  generation_ = new_gen;
  index_.open(index_path_, idx_key_, pair_token_, generation_);
}

}  // namespace shinkuro
