// Encrypted vault engine.
//
// A vault is a pair of files:
//   <name>.vault     encrypted file content (header + AES-256-GCM chunks)
//   <name>.vault.idx authenticated, encrypted B+ tree index
//
// The two files are strongly bound by a random 32-byte pair token stored in both
// headers, and both are keyed off the master password. A mismatched or swapped
// index will fail authentication. A monotonic `generation` stored in both files
// lets open() detect and recover from an interrupted compact/change_password.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "index.hpp"
#include "json.hpp"
#include "util.hpp"

namespace shinkuro {

// Phase names: "encrypt" (add), "compact" (defrag), "reencrypt" (change password).
using ProgressFn = std::function<void(const std::string& phase, uint64_t done, uint64_t total)>;

class Vault {
public:
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
  uint64_t generation_ = 0;
  std::vector<FileEntry> files_;
  std::vector<FreeRange> free_;  // sorted-by-offset, coalesced reusable holes
  Index index_;
  std::filesystem::path temp_dir_;
  ProgressFn progress_;

#ifdef _WIN32
  void* vault_lock_ = nullptr;  // denies deletion of the vault file while open
  void* idx_lock_ = nullptr;    // denies deletion of the index file while open
#endif

  void derive_keys(const std::string& password, const Bytes& salt, uint32_t iterations);
  void clear_keys();
  void read_vault_header();
  void load_index_v2();
  void load_index_legacy();
  void rebuild_mirrors();
  void commit_index();
  void reload_index_state();
  void write_vault_header(FILE* f, uint64_t gen);
  void migrate_legacy_index();
  std::string read_index_magic() const;
  void recover_files();
  void swap_pair_in();
  void trim_trailing_garbage();
  void maybe_auto_reindex();
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
  void release_idx_lock();
  void acquire_idx_lock();

  FileEntry* find(const std::string& name);
  const FileEntry* find(const std::string& name) const;
};

}  // namespace shinkuro
