// Encrypted vault engine.
//
// A vault is a pair of files:
//   <name>.vault     encrypted file content (header + AES-256-GCM chunks)
//   <name>.vault.idx authenticated, encrypted index (AES-256-GCM)
//
// The two files are strongly bound by a random 32-byte pair token stored in both
// headers, and both are keyed off the master password. A mismatched or swapped
// index will fail authentication.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "json.hpp"
#include "util.hpp"

namespace shinkuro {

struct VaultError : std::runtime_error {
  std::string code;
  VaultError(std::string c, const std::string& msg) : std::runtime_error(msg), code(std::move(c)) {}
};

// Phase names: "encrypt" (add), "compact" (defrag), "reencrypt" (change password).
using ProgressFn = std::function<void(const std::string& phase, uint64_t done, uint64_t total)>;

class Vault {
public:
  struct FileEntry {
    std::string name;
    uint64_t size = 0;
    uint64_t offset = 0;
    int64_t mtime = 0;
    Bytes file_id;  // 16 random bytes; used as chunk AAD
  };

  // A reusable hole in the vault file (in bytes, offset relative to file start).
  struct FreeRange {
    uint64_t offset = 0;
    uint64_t size = 0;
  };

  Vault() = default;
  ~Vault() { lock(); }

  Vault(const Vault&) = delete;
  Vault& operator=(const Vault&) = delete;

  bool is_open() const { return open_; }
  const std::filesystem::path& vault_path() const { return vault_path_; }
  const std::filesystem::path& index_path() const { return index_path_; }

  void create(const std::filesystem::path& vault_path, const std::string& password);
  void open(const std::filesystem::path& vault_path, const std::string& password);
  void lock();  // wipes keys, temp files and clears state

  Json list() const;
  Json add(const std::filesystem::path& src_path);
  Json extract(const std::string& name);  // returns {path, name, size} (to temp dir)
  Json extract_to(const std::string& name,
                  const std::filesystem::path& dest);  // returns {path, name, size}
  uint64_t remove(const std::string& name);  // O(1) lazy delete; returns bytes reclaimed
  Json compact();                            // defrag/shrink: returns {before, after, freed}
  void change_password(const std::string& old_password, const std::string& new_password);

  // Optional progress reporting for long-running ops (add/compact/change_password).
  void set_progress_callback(ProgressFn fn) { progress_ = std::move(fn); }

private:
  bool open_ = false;
  std::filesystem::path vault_path_;
  std::filesystem::path index_path_;
  Bytes master_key_, idx_key_, chunk_key_;
  Bytes pair_token_;
  Bytes salt_;
  uint32_t iterations_ = 0;
  std::vector<FileEntry> files_;
  std::vector<FreeRange> free_;  // sorted-by-offset, coalesced reusable holes
  std::filesystem::path temp_dir_;
  ProgressFn progress_;

#ifdef _WIN32
  void* vault_lock_ = nullptr;  // denies deletion of the vault file while open
  void* idx_lock_ = nullptr;    // denies deletion of the index file while open
#endif

  void derive_keys(const std::string& password, const Bytes& salt, uint32_t iterations);
  void clear_keys();
  void write_index();
  void load_index();
  void decrypt_to(const FileEntry& e, const std::filesystem::path& out_path);
  std::filesystem::path make_temp_dir();
  void wipe_temp_dir();

  // Free-space management (lazy delete / reuse).
  void add_free(uint64_t offset, uint64_t size);
  bool find_free_fit(uint64_t need, uint64_t& out_offset, size_t& out_idx) const;
  void consume_free(size_t idx, uint64_t need);
  void trim_trailing_free();
  uint64_t free_bytes() const;
  uint64_t vault_file_size() const;
  void truncate_vault(uint64_t size);
  bool should_auto_compact() const;
  void report(const std::string& phase, uint64_t done, uint64_t total);

  void acquire_locks();
  void release_locks();
  void release_vault_lock();
  void acquire_vault_lock();

  FileEntry* find(const std::string& name);
  const FileEntry* find(const std::string& name) const;
};

}  // namespace shinkuro
