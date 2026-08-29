#include "index.hpp"

#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace shinkuro {

namespace {

constexpr char INDEX_MAGIC[8] = {'S', 'K', 'I', 'D', 'X', '0', '0', '2'};
constexpr uint32_t INDEX_VERSION = 2;
constexpr size_t PAGE_SIZE = 4096;      // plaintext page payload
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t PAGE_SLOT = NONCE_SIZE + PAGE_SIZE + TAG_SIZE;  // 4124
constexpr size_t SUPER_PAYLOAD = 64;
constexpr size_t SUPER_SLOT = NONCE_SIZE + SUPER_PAYLOAD + TAG_SIZE + 4;  // 96 (padded)
constexpr size_t HEADER_SIZE = 64;  // magic8 + ver4 + token32 + page_size4 + reserved16
constexpr size_t DATA_START = HEADER_SIZE + 2 * SUPER_SLOT;              // 256
constexpr size_t FILE_ID_SIZE = 16;
constexpr size_t PAIR_TOKEN_SIZE = 32;
constexpr uint64_t MAX_PAGES = (1ull << 40) / PAGE_SLOT;  // sanity cap on page ids

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

// ---- Unicode-safe binary file opening ----
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

void file_seek(FILE* f, uint64_t off) {
#ifdef _WIN32
  if (_fseeki64(f, static_cast<int64_t>(off), SEEK_SET) != 0)
#else
  if (fseeko(f, static_cast<off_t>(off), SEEK_SET) != 0)
#endif
    throw VaultError("IO_ERROR", "索引文件定位失败");
}

void write_bytes(FILE* f, const void* data, size_t n) {
  if (n > 0 && std::fwrite(data, 1, n, f) != n) throw VaultError("IO_ERROR", "索引写入失败");
}
void read_bytes(FILE* f, void* data, size_t n) {
  if (n > 0 && std::fread(data, 1, n, f) != n) throw VaultError("IO_ERROR", "索引读取失败");
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

void atomic_replace(const std::filesystem::path& from, const std::filesystem::path& to) {
#ifdef _WIN32
  for (int attempt = 0; attempt < 10; attempt++) {
    if (MoveFileExW(from.c_str(), to.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      return;
    }
    Sleep(150 * (attempt + 1));
  }
  throw VaultError("IO_ERROR", "替换索引文件失败: " + win32_last_error());
#else
  std::error_code ec;
  std::filesystem::remove(to, ec);
  std::filesystem::rename(from, to, ec);
  if (ec) throw VaultError("IO_ERROR", "替换索引文件失败: " + ec.message());
#endif
}

// ---- little-endian byte-buffer helpers ----
void put_u32(Bytes& b, uint32_t v) {
  b.push_back(static_cast<uint8_t>(v & 0xFF));
  b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}
void put_u64(Bytes& b, uint64_t v) {
  for (int i = 0; i < 8; i++) b.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
void put_i64(Bytes& b, int64_t v) { put_u64(b, static_cast<uint64_t>(v)); }

uint32_t get_u32(const uint8_t* p, size_t& off) {
  uint32_t v = static_cast<uint32_t>(p[off]) | (static_cast<uint32_t>(p[off + 1]) << 8) |
               (static_cast<uint32_t>(p[off + 2]) << 16) | (static_cast<uint32_t>(p[off + 3]) << 24);
  off += 4;
  return v;
}
uint64_t get_u64(const uint8_t* p, size_t& off) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | p[off + i];
  off += 8;
  return v;
}
int64_t get_i64(const uint8_t* p, size_t& off) {
  return static_cast<int64_t>(get_u64(p, off));
}

// ---- entry serialization ----
Bytes encode_file_value(const FileEntry& e) {
  Bytes v;
  put_u64(v, e.size);
  put_u64(v, e.offset);
  put_i64(v, e.mtime);
  v.insert(v.end(), e.file_id.begin(), e.file_id.end());  // 16 bytes
  put_u64(v, e.seq);
  return v;  // 8+8+8+16+8 = 48
}
FileEntry decode_file_entry(const Bytes& key, const Bytes& value) {
  FileEntry e;
  e.name.assign(key.begin(), key.end());
  const uint8_t* d = value.data();
  size_t off = 0;
  e.size = get_u64(d, off);
  e.offset = get_u64(d, off);
  e.mtime = get_i64(d, off);
  e.file_id.assign(d + off, d + off + FILE_ID_SIZE);
  off += FILE_ID_SIZE;
  e.seq = get_u64(d, off);
  return e;
}

// Free-tree key is the hole offset encoded big-endian so bytewise order == numeric order.
Bytes encode_free_key(uint64_t offset) {
  Bytes k(8);
  for (int i = 0; i < 8; i++) k[i] = static_cast<uint8_t>((offset >> (8 * (7 - i))) & 0xFF);
  return k;
}
uint64_t decode_free_key(const Bytes& k) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | k[i];
  return v;
}
Bytes encode_free_value(uint64_t size) {
  Bytes v;
  put_u64(v, size);
  return v;
}

// ---- superblock serialization ----
Bytes encode_superblock(const Index::Superblock& sb) {
  Bytes b;
  put_u64(b, sb.seq);
  put_u64(b, sb.root_files);
  put_u64(b, sb.root_free);
  put_u64(b, sb.next_page);
  put_u64(b, sb.file_count);
  put_u64(b, sb.free_count);
  put_u64(b, sb.generation);
  put_u64(b, sb.reserved);
  return b;  // 64 bytes
}
Index::Superblock decode_superblock(const Bytes& b) {
  Index::Superblock sb;
  const uint8_t* d = b.data();
  size_t off = 0;
  sb.seq = get_u64(d, off);
  sb.root_files = get_u64(d, off);
  sb.root_free = get_u64(d, off);
  sb.next_page = get_u64(d, off);
  sb.file_count = get_u64(d, off);
  sb.free_count = get_u64(d, off);
  sb.generation = get_u64(d, off);
  sb.reserved = get_u64(d, off);
  return sb;
}

// ---- page (node) serialization ----
size_t page_measure(const Index::Page& p) {
  size_t n = 1 + 4;  // type + count
  if (p.type == Index::PageType::LEAF) {
    for (const auto& kv : p.kv) n += 4 + kv.first.size() + 4 + kv.second.size();
  } else {
    n += p.children.size() * 8;
    for (const auto& k : p.keys) n += 4 + k.size();
  }
  return n;
}

Bytes encode_page(const Index::Page& p) {
  Bytes b;
  b.reserve(PAGE_SIZE);
  b.push_back(static_cast<uint8_t>(p.type));
  uint32_t count = p.type == Index::PageType::LEAF ? static_cast<uint32_t>(p.kv.size())
                                                   : static_cast<uint32_t>(p.keys.size());
  put_u32(b, count);
  if (p.type == Index::PageType::LEAF) {
    for (const auto& kv : p.kv) {
      put_u32(b, static_cast<uint32_t>(kv.first.size()));
      b.insert(b.end(), kv.first.begin(), kv.first.end());
      put_u32(b, static_cast<uint32_t>(kv.second.size()));
      b.insert(b.end(), kv.second.begin(), kv.second.end());
    }
  } else {
    for (uint64_t c : p.children) put_u64(b, c);
    for (const auto& k : p.keys) {
      put_u32(b, static_cast<uint32_t>(k.size()));
      b.insert(b.end(), k.begin(), k.end());
    }
  }
  if (b.size() > PAGE_SIZE) throw VaultError("INTERNAL", "索引页溢出");
  b.resize(PAGE_SIZE, 0);
  return b;
}

Index::Page decode_page(const Bytes& b) {
  Index::Page p;
  const uint8_t* d = b.data();
  size_t off = 0;
  if (b.size() < 5) throw VaultError("CORRUPT", "索引页损坏");
  uint8_t t = d[off++];
  p.type = (t == 0) ? Index::PageType::LEAF : Index::PageType::INTERNAL;
  uint32_t count = get_u32(d, off);
  if (p.type == Index::PageType::LEAF) {
    p.kv.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
      uint32_t kl = get_u32(d, off);
      if (off + kl > b.size()) throw VaultError("CORRUPT", "索引页损坏");
      Bytes k(d + off, d + off + kl);
      off += kl;
      uint32_t vl = get_u32(d, off);
      if (off + vl > b.size()) throw VaultError("CORRUPT", "索引页损坏");
      Bytes v(d + off, d + off + vl);
      off += vl;
      p.kv.emplace_back(std::move(k), std::move(v));
    }
  } else {
    if (off + static_cast<size_t>(count + 1) * 8 > b.size())
      throw VaultError("CORRUPT", "索引页损坏");
    p.children.resize(count + 1);
    for (uint32_t i = 0; i < count + 1; i++) p.children[i] = get_u64(d, off);
    p.keys.resize(count);
    for (uint32_t i = 0; i < count; i++) {
      uint32_t kl = get_u32(d, off);
      if (off + kl > b.size()) throw VaultError("CORRUPT", "索引页损坏");
      p.keys[i] = Bytes(d + off, d + off + kl);
      off += kl;
    }
  }
  return p;
}

// ---- AAD builders ----
Bytes page_aad(const Bytes& pair_token, uint64_t page_id) {
  Bytes aad;
  aad.insert(aad.end(), INDEX_MAGIC, INDEX_MAGIC + 8);
  Bytes ver;
  put_u32(ver, INDEX_VERSION);
  aad.insert(aad.end(), ver.begin(), ver.end());
  aad.insert(aad.end(), pair_token.begin(), pair_token.end());
  Bytes pid;
  put_u64(pid, page_id);
  aad.insert(aad.end(), pid.begin(), pid.end());
  return aad;
}
Bytes super_aad(const Bytes& pair_token, int slot) {
  Bytes aad;
  aad.insert(aad.end(), INDEX_MAGIC, INDEX_MAGIC + 8);
  Bytes ver;
  put_u32(ver, INDEX_VERSION);
  aad.insert(aad.end(), ver.begin(), ver.end());
  aad.insert(aad.end(), pair_token.begin(), pair_token.end());
  Bytes sid;
  put_u64(sid, static_cast<uint64_t>(slot));
  aad.insert(aad.end(), sid.begin(), sid.end());
  return aad;
}

}  // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

void Index::create(const std::filesystem::path& path, const Bytes& idx_key, const Bytes& pair_token,
                   uint64_t generation) {
  close();
  path_ = path;
  idx_key_ = idx_key;
  pair_token_ = pair_token;
  generation_ = generation;

  f_ = fopen_path(path_, "w+b");
  if (!f_) throw VaultError("IO_ERROR", "无法创建索引文件");

  try {
    write_header();

    Superblock sb;
    sb.seq = 1;
    sb.root_files = 0;
    sb.root_free = 0;
    sb.next_page = 1;
    sb.file_count = 0;
    sb.free_count = 0;
    sb.generation = generation;
    sb.reserved = 0;
    write_superblock(0, sb);
    write_superblock_zeros(1);
    flush();
    sb_ = sb;
    active_slot_ = 0;
  } catch (...) {
    std::fclose(f_);
    f_ = nullptr;
    open_ = false;
    std::error_code ec;
    std::filesystem::remove(path_, ec);
    throw;
  }

  reset_state();
  open_ = true;
}

void Index::open(const std::filesystem::path& path, const Bytes& idx_key, const Bytes& pair_token,
                 uint64_t expected_generation) {
  close();
  path_ = path;
  pair_token_ = pair_token;
  idx_key_ = idx_key;

  f_ = fopen_path(path_, "r+b");
  if (!f_) throw VaultError("IO_ERROR", "无法打开索引文件");

  try {
    uint64_t header_gen = read_header();  // verifies magic/version/pair_token/page_size

    auto sb0 = read_superblock(0);
    auto sb1 = read_superblock(1);

    Superblock chosen;
    int slot = -1;
    if (sb0 && sb1) {
      if (sb0->seq >= sb1->seq) {
        chosen = *sb0;
        slot = 0;
      } else {
        chosen = *sb1;
        slot = 1;
      }
    } else if (sb0) {
      chosen = *sb0;
      slot = 0;
    } else if (sb1) {
      chosen = *sb1;
      slot = 1;
    } else {
      // Both slots failed GCM authentication: either wrong password or a
      // completely torn/corrupt index.
      throw VaultError("WRONG_PASSWORD", "密码错误");
    }

    if (chosen.generation != header_gen)
      throw VaultError("CORRUPT", "索引头与超块不一致");
    if (chosen.generation != expected_generation)
      throw VaultError("MISMATCHED_PAIR", "保险柜与索引文件不匹配（代际校验失败）");

    sb_ = chosen;
    active_slot_ = slot;
    reset_state();
    open_ = true;
  } catch (...) {
    std::fclose(f_);
    f_ = nullptr;
    open_ = false;
    secure_zero(idx_key_);
    secure_zero(pair_token_);
    throw;
  }
}

void Index::close() {
  if (f_) {
    std::fclose(f_);
    f_ = nullptr;
  }
  secure_zero(idx_key_);
  secure_zero(pair_token_);
  cache_.clear();
  dirty_.clear();
  open_ = false;
}

void Index::reopen(uint64_t expected_generation) {
  std::filesystem::path p = path_;
  Bytes key = idx_key_;
  Bytes token = pair_token_;
  close();
  open(p, key, token, expected_generation);
}

void Index::reset_state() {
  root_files_ = sb_.root_files;
  root_free_ = sb_.root_free;
  next_page_ = sb_.next_page;
  file_count_ = sb_.file_count;
  free_count_ = sb_.free_count;
  generation_ = sb_.generation;
  cache_.clear();
  dirty_.clear();
}

// ---------------------------------------------------------------------------
// Header / superblock I/O
// ---------------------------------------------------------------------------

void Index::write_header() {
  file_seek(f_, 0);
  write_bytes(f_, INDEX_MAGIC, 8);
  write_u32(f_, INDEX_VERSION);
  write_bytes(f_, pair_token_.data(), pair_token_.size());
  write_u32(f_, static_cast<uint32_t>(PAGE_SIZE));
  write_u64(f_, generation_);
  Bytes reserved(8, 0);
  write_bytes(f_, reserved.data(), reserved.size());
}

uint64_t Index::read_header() {
  file_seek(f_, 0);
  char magic[8];
  read_bytes(f_, magic, 8);
  if (std::memcmp(magic, INDEX_MAGIC, 8) != 0) throw VaultError("CORRUPT", "索引文件格式错误");
  uint32_t version = read_u32(f_);
  if (version != INDEX_VERSION) throw VaultError("CORRUPT", "索引版本不支持");
  Bytes token(PAIR_TOKEN_SIZE);
  read_bytes(f_, token.data(), token.size());
  if (!constant_time_eq(token, pair_token_))
    throw VaultError("MISMATCHED_PAIR", "保险柜与索引文件不匹配（强绑定校验失败）");
  uint32_t page_size = read_u32(f_);
  if (page_size != PAGE_SIZE) throw VaultError("CORRUPT", "索引页大小不支持");
  uint64_t gen = read_u64(f_);
  Bytes reserved(8);
  read_bytes(f_, reserved.data(), reserved.size());
  return gen;
}

uint64_t Index::slot_offset(uint64_t id) const { return DATA_START + (id - 1) * PAGE_SLOT; }

void Index::write_superblock(int slot, const Superblock& sb) {
  Bytes payload = encode_superblock(sb);
  Bytes nonce = random_bytes(NONCE_SIZE);
  Bytes aad = super_aad(pair_token_, slot);
  auto [cipher, tag] = gcm_encrypt(idx_key_, nonce, aad, payload);

  file_seek(f_, HEADER_SIZE + static_cast<uint64_t>(slot) * SUPER_SLOT);
  write_bytes(f_, nonce.data(), nonce.size());
  write_bytes(f_, cipher.data(), cipher.size());
  write_bytes(f_, tag.data(), tag.size());
  Bytes pad(SUPER_SLOT - NONCE_SIZE - SUPER_PAYLOAD - TAG_SIZE, 0);
  write_bytes(f_, pad.data(), pad.size());
}

void Index::write_superblock_zeros(int slot) {
  Bytes z(SUPER_SLOT, 0);
  file_seek(f_, HEADER_SIZE + static_cast<uint64_t>(slot) * SUPER_SLOT);
  write_bytes(f_, z.data(), z.size());
}

std::optional<Index::Superblock> Index::read_superblock(int slot) {
  file_seek(f_, HEADER_SIZE + static_cast<uint64_t>(slot) * SUPER_SLOT);
  Bytes nonce(NONCE_SIZE);
  Bytes cipher(SUPER_PAYLOAD);
  Bytes tag(TAG_SIZE);
  read_bytes(f_, nonce.data(), nonce.size());
  read_bytes(f_, cipher.data(), cipher.size());
  read_bytes(f_, tag.data(), tag.size());

  Bytes aad = super_aad(pair_token_, slot);
  try {
    Bytes plain = gcm_decrypt(idx_key_, nonce, aad, cipher, tag);
    return decode_superblock(plain);
  } catch (const AuthError&) {
    return std::nullopt;  // torn/inactive/zeroed slot
  }
}

void Index::flush() {
  if (std::fflush(f_) != 0) throw VaultError("IO_ERROR", "刷新索引文件失败");
#ifdef _WIN32
  if (_commit(_fileno(f_)) != 0) throw VaultError("IO_ERROR", "同步索引文件失败");
#else
  if (::fsync(fileno(f_)) != 0) throw VaultError("IO_ERROR", "同步索引文件失败");
#endif
}

// ---------------------------------------------------------------------------
// Page cache / allocator
// ---------------------------------------------------------------------------

Index::Page Index::get_page(uint64_t id) const {
  auto it = cache_.find(id);
  if (it != cache_.end()) return it->second;
  Page p = read_page_from_disk(id);
  cache_.emplace(id, p);
  return p;
}

uint64_t Index::new_page(const Page& p) {
  if (next_page_ >= MAX_PAGES) throw VaultError("INTERNAL", "索引页数超限");
  uint64_t id = next_page_++;
  cache_[id] = p;
  dirty_.insert(id);
  return id;
}

Index::Page Index::read_page_from_disk(uint64_t id) const {
  file_seek(f_, slot_offset(id));
  Bytes nonce(NONCE_SIZE);
  Bytes cipher(PAGE_SIZE);
  Bytes tag(TAG_SIZE);
  read_bytes(f_, nonce.data(), nonce.size());
  read_bytes(f_, cipher.data(), cipher.size());
  read_bytes(f_, tag.data(), tag.size());
  Bytes aad = page_aad(pair_token_, id);
  Bytes plain;
  try {
    plain = gcm_decrypt(idx_key_, nonce, aad, cipher, tag);
  } catch (const AuthError&) {
    throw VaultError("CORRUPT", "索引页认证失败，索引可能被篡改");
  }
  return decode_page(plain);
}

void Index::write_page(uint64_t id, const Page& p) {
  Bytes plain = encode_page(p);
  Bytes nonce = random_bytes(NONCE_SIZE);
  Bytes aad = page_aad(pair_token_, id);
  auto [cipher, tag] = gcm_encrypt(idx_key_, nonce, aad, plain);
  file_seek(f_, slot_offset(id));
  write_bytes(f_, nonce.data(), nonce.size());
  write_bytes(f_, cipher.data(), cipher.size());
  write_bytes(f_, tag.data(), tag.size());
}

// ---------------------------------------------------------------------------
// B+ tree algorithms (copy-on-write)
// ---------------------------------------------------------------------------

uint64_t Index::insert_rec(uint64_t id, const Bytes& key, const Bytes& value, bool& did_split,
                           Bytes& up_key, uint64_t& up_right) {
  if (id == 0) {
    Page leaf;
    leaf.type = PageType::LEAF;
    leaf.kv.emplace_back(key, value);
    did_split = false;
    return new_page(leaf);
  }

  Page p = get_page(id);
  if (p.type == PageType::LEAF) {
    auto it = std::lower_bound(p.kv.begin(), p.kv.end(), key,
                               [](const std::pair<Bytes, Bytes>& a, const Bytes& k) {
                                 return a.first < k;
                               });
    if (it != p.kv.end() && it->first == key)
      throw VaultError("INTERNAL", "索引键冲突");  // caller must enforce uniqueness
    p.kv.insert(it, {key, value});

    if (page_measure(p) > PAGE_SIZE) {
      // split at ~half the entries
      size_t n = p.kv.size();
      size_t mid = n / 2;
      if (mid == 0) mid = 1;
      Page right;
      right.type = PageType::LEAF;
      right.kv.assign(p.kv.begin() + static_cast<std::ptrdiff_t>(mid), p.kv.end());
      p.kv.resize(mid);
      up_key = right.kv[0].first;
      up_right = new_page(right);
      did_split = true;
      return new_page(p);
    }
    did_split = false;
    return new_page(p);
  }

  // internal node
  size_t idx = static_cast<size_t>(std::upper_bound(p.keys.begin(), p.keys.end(), key) -
                                   p.keys.begin());
  bool child_split = false;
  Bytes child_key;
  uint64_t child_right = 0;
  uint64_t new_child = insert_rec(p.children[idx], key, value, child_split, child_key, child_right);
  p.children[idx] = new_child;
  if (child_split) {
    p.keys.insert(p.keys.begin() + static_cast<std::ptrdiff_t>(idx), child_key);
    p.children.insert(p.children.begin() + static_cast<std::ptrdiff_t>(idx + 1), child_right);
  }

  if (page_measure(p) > PAGE_SIZE) {
    size_t n = p.keys.size();
    size_t mid = n / 2;
    Page right;
    right.type = PageType::INTERNAL;
    right.keys.assign(p.keys.begin() + static_cast<std::ptrdiff_t>(mid + 1), p.keys.end());
    right.children.assign(p.children.begin() + static_cast<std::ptrdiff_t>(mid + 1),
                          p.children.end());
    up_key = p.keys[mid];
    p.keys.resize(mid);
    p.children.resize(mid + 1);
    up_right = new_page(right);
    did_split = true;
    return new_page(p);
  }
  did_split = false;
  return new_page(p);
}

Index::EraseOut Index::erase_rec(uint64_t id, const Bytes& key) {
  if (id == 0) return {0, false};
  Page p = get_page(id);
  if (p.type == PageType::LEAF) {
    auto it = std::lower_bound(p.kv.begin(), p.kv.end(), key,
                               [](const std::pair<Bytes, Bytes>& a, const Bytes& k) {
                                 return a.first < k;
                               });
    if (it == p.kv.end() || it->first != key) return {id, false};
    p.kv.erase(it);
    return {new_page(p), true};
  }
  size_t idx = static_cast<size_t>(std::upper_bound(p.keys.begin(), p.keys.end(), key) -
                                   p.keys.begin());
  EraseOut c = erase_rec(p.children[idx], key);
  if (!c.found) return {id, false};
  p.children[idx] = c.id;
  return {new_page(p), true};
}

std::optional<Bytes> Index::find_rec(uint64_t id, const Bytes& key) const {
  if (id == 0) return std::nullopt;
  Page p = get_page(id);
  if (p.type == PageType::LEAF) {
    auto it = std::lower_bound(p.kv.begin(), p.kv.end(), key,
                               [](const std::pair<Bytes, Bytes>& a, const Bytes& k) {
                                 return a.first < k;
                               });
    if (it != p.kv.end() && it->first == key) return it->second;
    return std::nullopt;
  }
  size_t idx = static_cast<size_t>(std::upper_bound(p.keys.begin(), p.keys.end(), key) -
                                   p.keys.begin());
  return find_rec(p.children[idx], key);
}

void Index::iterate_rec(uint64_t id,
                        const std::function<void(const Bytes&, const Bytes&)>& cb) const {
  if (id == 0) return;
  Page p = get_page(id);
  if (p.type == PageType::LEAF) {
    for (const auto& kv : p.kv) cb(kv.first, kv.second);
    return;
  }
  for (uint64_t c : p.children) iterate_rec(c, cb);
}

void Index::count_reachable(uint64_t id, std::unordered_set<uint64_t>& seen) const {
  if (id == 0) return;
  if (!seen.insert(id).second) return;
  Page p = get_page(id);
  if (p.type == PageType::INTERNAL) {
    for (uint64_t c : p.children) count_reachable(c, seen);
  }
}

// ---------------------------------------------------------------------------
// Public tree operations
// ---------------------------------------------------------------------------

void Index::insert_into_tree(uint64_t& root, const Bytes& key, const Bytes& value) {
  bool did_split = false;
  Bytes up_key;
  uint64_t up_right = 0;
  uint64_t nr = insert_rec(root, key, value, did_split, up_key, up_right);
  if (did_split) {
    Page np;
    np.type = PageType::INTERNAL;
    np.keys.push_back(up_key);
    np.children.push_back(nr);
    np.children.push_back(up_right);
    root = new_page(np);
  } else {
    root = nr;
  }
}

void Index::insert_file(const FileEntry& e) {
  Bytes key(e.name.begin(), e.name.end());
  insert_into_tree(root_files_, key, encode_file_value(e));
  file_count_++;
}

bool Index::erase_file(const std::string& name) {
  Bytes key(name.begin(), name.end());
  EraseOut o = erase_rec(root_files_, key);
  root_files_ = o.id;
  if (o.found && file_count_ > 0) file_count_--;
  return o.found;
}

std::optional<FileEntry> Index::find_file(const std::string& name) const {
  Bytes key(name.begin(), name.end());
  auto v = find_rec(root_files_, key);
  if (!v) return std::nullopt;
  return decode_file_entry(key, *v);
}

void Index::iterate_files(const std::function<void(const FileEntry&)>& cb) const {
  iterate_rec(root_files_, [&](const Bytes& k, const Bytes& v) { cb(decode_file_entry(k, v)); });
}

void Index::set_free(const std::vector<FreeRange>& ranges) {
  root_free_ = 0;
  free_count_ = 0;
  for (const auto& r : ranges) {
    if (r.size == 0) continue;
    insert_into_tree(root_free_, encode_free_key(r.offset), encode_free_value(r.size));
    free_count_++;
  }
}

void Index::iterate_free(const std::function<void(const FreeRange&)>& cb) const {
  iterate_rec(root_free_, [&](const Bytes& k, const Bytes& v) {
    const uint8_t* d = v.data();
    size_t off = 0;
    FreeRange r;
    r.offset = decode_free_key(k);
    r.size = get_u64(d, off);
    cb(r);
  });
}

uint64_t Index::live_page_count() const {
  std::unordered_set<uint64_t> seen;
  count_reachable(root_files_, seen);
  count_reachable(root_free_, seen);
  return seen.size();
}

// ---------------------------------------------------------------------------
// Commit / reindex
// ---------------------------------------------------------------------------

void Index::commit() {
  if (!open_) throw VaultError("NOT_OPEN", "索引未打开");

  Superblock nsb;
  nsb.seq = sb_.seq + 1;
  nsb.root_files = root_files_;
  nsb.root_free = root_free_;
  nsb.next_page = next_page_;
  nsb.file_count = file_count_;
  nsb.free_count = free_count_;
  nsb.generation = generation_;
  nsb.reserved = 0;

  int slot = 1 - active_slot_;

  // 1) write all freshly allocated pages to their (never-before-used) slots
  for (uint64_t id : dirty_) write_page(id, cache_[id]);
  // 2) flip the inactive superblock slot (the commit point)
  write_superblock(slot, nsb);
  // 3) make it durable
  flush();

  sb_ = nsb;
  active_slot_ = slot;
  dirty_.clear();
}

void Index::reindex(const std::vector<FileEntry>& files, const std::vector<FreeRange>& frees,
                    uint64_t generation) {
  if (!open_) throw VaultError("NOT_OPEN", "索引未打开");
  std::filesystem::path tmp = path_;
  tmp += ".tmp";

  Bytes key = idx_key_;
  Bytes token = pair_token_;

  Index fresh;
  fresh.create(tmp, key, token, generation);
  try {
    for (const auto& e : files) fresh.insert_file(e);
    fresh.set_free(frees);
    fresh.commit();
  } catch (...) {
    fresh.close();
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    throw;
  }
  fresh.close();

  close();  // release our handle so the rename can proceed
  try {
    atomic_replace(tmp, path_);
  } catch (...) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    open(path_, key, token, generation);
    throw;
  }
  open(path_, key, token, generation);
}

}  // namespace shinkuro
