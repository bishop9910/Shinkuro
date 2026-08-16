#include "vault.hpp"

#include <chrono>
#include <cstddef>
#include <cstring>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace shinkuro {

namespace {

constexpr char VAULT_MAGIC[8] = {'S', 'K', 'V', 'L', 'T', '0', '0', '1'};
constexpr char INDEX_MAGIC[8] = {'S', 'K', 'I', 'D', 'X', '0', '0', '1'};
constexpr uint32_t VAULT_VERSION = 1;
constexpr uint32_t KDF_ITERATIONS = 600000;  // PBKDF2-HMAC-SHA256 rounds
constexpr size_t SALT_SIZE = 16;
constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t PAIR_TOKEN_SIZE = 32;
constexpr size_t FILE_ID_SIZE = 16;
constexpr size_t VAULT_HEADER_SIZE = 96;  // magic8 + ver4 + iter4 + salt16 + token32 + reserved32
constexpr size_t CHUNK_BUF = 1024 * 1024;
constexpr size_t INDEX_MAX = 256 * 1024 * 1024;  // sanity cap on index blob

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

uint64_t file_tell(FILE* f) {
#ifdef _WIN32
  return static_cast<uint64_t>(_ftelli64(f));
#else
  return static_cast<uint64_t>(ftello(f));
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

}  // namespace

// ---------------------------------------------------------------------------

Vault::FileEntry* Vault::find(const std::string& name) {
  for (auto& e : files_)
    if (e.name == name) return &e;
  return nullptr;
}

const Vault::FileEntry* Vault::find(const std::string& name) const {
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
  secure_zero(master_key_);
  secure_zero(idx_key_);
  secure_zero(chunk_key_);
  for (auto& e : files_) secure_zero(e.file_id);
  secure_zero(pair_token_);
  secure_zero(salt_);
  iterations_ = 0;
  files_.clear();
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

// ---------------------------------------------------------------------------

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

  Bytes salt = random_bytes(SALT_SIZE);
  salt_ = salt;
  iterations_ = KDF_ITERATIONS;
  pair_token_ = random_bytes(PAIR_TOKEN_SIZE);
  derive_keys(password, salt, KDF_ITERATIONS);

  FILE* f = fopen_path(vault_path_, "wb");
  if (!f) {
    clear_keys();
    throw VaultError("IO_ERROR", "无法创建保险柜文件");
  }
  try {
    write_bytes(f, VAULT_MAGIC, 8);
    write_u32(f, VAULT_VERSION);
    write_u32(f, KDF_ITERATIONS);
    write_bytes(f, salt.data(), salt.size());
    write_bytes(f, pair_token_.data(), pair_token_.size());
    Bytes reserved(32, 0);
    write_bytes(f, reserved.data(), reserved.size());
  } catch (...) {
    std::fclose(f);
    clear_keys();
    std::error_code ec;
    std::filesystem::remove(vault_path_, ec);
    throw;
  }
  std::fclose(f);

  files_.clear();
  open_ = true;
  try {
    write_index();
  } catch (...) {
    lock();
    throw;
  }
  temp_dir_ = make_temp_dir();
  acquire_locks();
}

void Vault::open(const std::filesystem::path& vault_path, const std::string& password) {
  if (open_) lock();
  vault_path_ = vault_path;
  index_path_ = vault_path_;
  index_path_ += ".idx";

  if (!std::filesystem::exists(vault_path_)) throw VaultError("NOT_FOUND", "保险柜文件不存在");
  if (!std::filesystem::exists(index_path_))
    throw VaultError("NOT_FOUND", "索引文件不存在，无法验证保险柜完整性");

  uint32_t version = 0;
  uint32_t iterations = 0;
  Bytes salt(SALT_SIZE);

  FILE* f = fopen_path(vault_path_, "rb");
  if (!f) throw VaultError("IO_ERROR", "无法打开保险柜文件");
  try {
    char magic[8];
    read_bytes(f, magic, 8);
    if (std::memcmp(magic, VAULT_MAGIC, 8) != 0)
      throw VaultError("CORRUPT", "不是有效的保险柜文件");
    version = read_u32(f);
    if (version != VAULT_VERSION) throw VaultError("CORRUPT", "不支持的保险柜版本");
    iterations = read_u32(f);
    read_bytes(f, salt.data(), salt.size());
    salt_ = salt;
    iterations_ = iterations;
    pair_token_.resize(PAIR_TOKEN_SIZE);
    read_bytes(f, pair_token_.data(), pair_token_.size());
    Bytes reserved(32);
    read_bytes(f, reserved.data(), reserved.size());
  } catch (...) {
    std::fclose(f);
    clear_keys();
    throw;
  }
  std::fclose(f);

  try {
    derive_keys(password, salt, iterations);
    load_index();
  } catch (...) {
    clear_keys();
    throw;
  }

  // Sanity: every referenced chunk must live inside the vault file.
  uint64_t vsize = std::filesystem::file_size(vault_path_);
  for (const auto& e : files_) {
    uint64_t need = e.offset + NONCE_SIZE + 8 + e.size + TAG_SIZE;
    if (e.offset < VAULT_HEADER_SIZE || need > vsize)
      throw VaultError("CORRUPT", "索引与保险柜数据不一致");
  }

  open_ = true;
  temp_dir_ = make_temp_dir();
  acquire_locks();
}

// ---------------------------------------------------------------------------

void Vault::write_index() {
  Json root = Json::Object();
  root["version"] = static_cast<int64_t>(VAULT_VERSION);
  root["pair_token"] = to_hex(pair_token_);
  Json arr = Json::Array();
  for (const auto& e : files_) {
    Json o = Json::Object();
    o["name"] = e.name;
    o["size"] = static_cast<int64_t>(e.size);
    o["offset"] = static_cast<int64_t>(e.offset);
    o["mtime"] = e.mtime;
    o["id"] = to_hex(e.file_id);
    arr.push_back(std::move(o));
  }
  root["files"] = std::move(arr);

  std::string plain = root.dump();
  Bytes nonce = random_bytes(NONCE_SIZE);
  Bytes aad;
  aad.insert(aad.end(), INDEX_MAGIC, INDEX_MAGIC + 8);
  append_u32(aad, VAULT_VERSION);
  aad.insert(aad.end(), pair_token_.begin(), pair_token_.end());

  auto [cipher, tag] = gcm_encrypt(idx_key_, nonce, aad, Bytes(plain.begin(), plain.end()));
  secure_zero_string(plain);

  FILE* f = fopen_path(index_path_, "wb");
  if (!f) throw VaultError("IO_ERROR", "无法写入索引文件");
  try {
    write_bytes(f, INDEX_MAGIC, 8);
    write_u32(f, VAULT_VERSION);
    write_bytes(f, pair_token_.data(), pair_token_.size());
    write_bytes(f, nonce.data(), nonce.size());
    write_u64(f, static_cast<uint64_t>(cipher.size()));
    write_bytes(f, cipher.data(), cipher.size());
    write_bytes(f, tag.data(), tag.size());
  } catch (...) {
    std::fclose(f);
    throw;
  }
  std::fclose(f);
}

void Vault::load_index() {
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
  for (const auto& item : root["files"].as_array()) {
    FileEntry e;
    e.name = item["name"].as_string();
    e.size = static_cast<uint64_t>(item["size"].as_int());
    e.offset = static_cast<uint64_t>(item["offset"].as_int());
    e.mtime = item["mtime"].as_int();
    e.file_id = from_hex(item["id"].as_string());
    files_.push_back(std::move(e));
  }
  secure_zero(plain);
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

  uint64_t offset = std::filesystem::file_size(vault_path_, ec);

  FILE* in = fopen_path(src_path, "rb");
  if (!in) throw VaultError("IO_ERROR", "无法读取源文件");
  FILE* vf = fopen_path(vault_path_, "ab");
  if (!vf) {
    std::fclose(in);
    throw VaultError("IO_ERROR", "无法打开保险柜文件");
  }

  Bytes aad = file_id;
  append_u64(aad, src_size);

  try {
    write_bytes(vf, nonce.data(), nonce.size());
    write_u64(vf, src_size);
    gcm_encrypt_stream(chunk_key_, nonce, aad, in, vf);
  } catch (...) {
    std::fclose(in);
    std::fclose(vf);
    throw;
  }
  std::fclose(in);
  std::fclose(vf);

  FileEntry e;
  e.name = name;
  e.size = src_size;
  e.offset = offset;
  e.mtime = mtime;
  e.file_id = std::move(file_id);
  files_.push_back(std::move(e));

  try {
    write_index();
  } catch (...) {
    files_.pop_back();
    throw;
  }

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

void Vault::remove(const std::string& name) {
  if (!open_) throw VaultError("NOT_OPEN", "保险柜未打开");
  size_t idx = files_.size();
  for (size_t i = 0; i < files_.size(); i++) {
    if (files_[i].name == name) {
      idx = i;
      break;
    }
  }
  if (idx == files_.size()) throw VaultError("NOT_FOUND", "文件不存在: " + name);

  std::vector<size_t> keep;
  keep.reserve(files_.size() - 1);
  for (size_t i = 0; i < files_.size(); i++)
    if (i != idx) keep.push_back(i);

  compact(keep);  // rewrites vault + updates offsets of kept entries
  files_.erase(files_.begin() + static_cast<std::ptrdiff_t>(idx));
  write_index();
}

void Vault::compact(const std::vector<size_t>& keep) {
  std::filesystem::path tmp = vault_path_;
  tmp += ".tmp" + random_hex(8);

  FILE* oldf = fopen_path(vault_path_, "rb");
  if (!oldf) throw VaultError("IO_ERROR", "无法打开保险柜文件");
  FILE* newf = fopen_path(tmp, "wb");
  if (!newf) {
    std::fclose(oldf);
    throw VaultError("IO_ERROR", "无法创建临时文件");
  }

  std::vector<uint64_t> new_offsets(files_.size(), 0);
  std::exception_ptr err;
  try {
    copy_bytes(oldf, newf, VAULT_HEADER_SIZE);  // header verbatim
    for (size_t i : keep) {
      const FileEntry& e = files_[i];
      if (file_seek(oldf, e.offset) != 0) throw VaultError("IO_ERROR", "定位数据失败");
      new_offsets[i] = file_tell(newf);
      copy_bytes(oldf, newf, NONCE_SIZE + 8 + e.size + TAG_SIZE);
    }
  } catch (...) {
    err = std::current_exception();
  }
  std::fclose(newf);
  std::fclose(oldf);

  if (err) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    std::rethrow_exception(err);
  }

  release_vault_lock();
  try {
    atomic_replace(tmp, vault_path_);
  } catch (...) {
    acquire_vault_lock();
    std::error_code ec2;
    std::filesystem::remove(tmp, ec2);
    throw;
  }
  acquire_vault_lock();

  for (size_t i : keep) files_[i].offset = new_offsets[i];
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

  // 重写保险柜：每块旧密钥解密 → 新密钥加密（GCM 等长，偏移不变）
  std::filesystem::path tmp = vault_path_;
  tmp += ".tmp" + random_hex(8);

  FILE* oldf = fopen_path(vault_path_, "rb");
  if (!oldf) {
    secure_zero(new_master);
    secure_zero(new_idx_key);
    secure_zero(new_chunk_key);
    throw VaultError("IO_ERROR", "无法打开保险柜文件");
  }
  FILE* newf = fopen_path(tmp, "wb");
  if (!newf) {
    std::fclose(oldf);
    secure_zero(new_master);
    secure_zero(new_idx_key);
    secure_zero(new_chunk_key);
    throw VaultError("IO_ERROR", "无法创建临时文件");
  }

  std::exception_ptr err;
  try {
    copy_bytes(oldf, newf, VAULT_HEADER_SIZE);  // header verbatim（salt/iterations 不变）
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
        gcm_reencrypt_stream(chunk_key_, nonce, aad, new_chunk_key, new_nonce, oldf, newf,
                             data_len);
      } catch (const AuthError&) {
        throw VaultError("CORRUPT", "数据校验失败，保险柜可能被篡改");
      }
    }
  } catch (...) {
    err = std::current_exception();
  }
  std::fclose(newf);
  std::fclose(oldf);

  if (err) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    secure_zero(new_master);
    secure_zero(new_idx_key);
    secure_zero(new_chunk_key);
    std::rethrow_exception(err);
  }

  release_vault_lock();
  try {
    atomic_replace(tmp, vault_path_);
  } catch (...) {
    acquire_vault_lock();
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    secure_zero(new_master);
    secure_zero(new_idx_key);
    secure_zero(new_chunk_key);
    throw;
  }
  acquire_vault_lock();

  // 换密钥
  secure_zero(master_key_);
  master_key_ = std::move(new_master);
  secure_zero(idx_key_);
  idx_key_ = std::move(new_idx_key);
  secure_zero(chunk_key_);
  chunk_key_ = std::move(new_chunk_key);

  write_index();
}

}  // namespace shinkuro
