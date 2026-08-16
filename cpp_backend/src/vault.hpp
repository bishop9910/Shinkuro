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

class Vault {
public:
  struct FileEntry {
    std::string name;
    uint64_t size = 0;
    uint64_t offset = 0;
    int64_t mtime = 0;
    Bytes file_id;  // 16 random bytes; used as chunk AAD
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
  Json extract(const std::string& name);  // returns {path, name, size}
  void remove(const std::string& name);   // deletes + compacts (shrinks) the vault

private:
  bool open_ = false;
  std::filesystem::path vault_path_;
  std::filesystem::path index_path_;
  Bytes master_key_, idx_key_, chunk_key_;
  Bytes pair_token_;
  std::vector<FileEntry> files_;
  std::filesystem::path temp_dir_;

  void derive_keys(const std::string& password, const Bytes& salt, uint32_t iterations);
  void clear_keys();
  void write_index();
  void load_index();
  void compact(const std::vector<size_t>& keep);
  std::filesystem::path make_temp_dir();
  void wipe_temp_dir();

  FileEntry* find(const std::string& name);
  const FileEntry* find(const std::string& name) const;
};

}  // namespace shinkuro
