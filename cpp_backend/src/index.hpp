// Encrypted, paged B+ tree index for the vault's file table.
//
// The index file is a sequence of fixed-size slots. Every tree page is encrypted
// individually with AES-256-GCM (idx_key) and is addressed by its slot id
// (physical location), so pages are never overwritten in place: a mutation
// copy-on-write's the root->leaf path and allocates fresh slot ids. The whole
// mutation is made atomic by a dual-slot superblock carrying a monotonic
// sequence number; commit flips the inactive slot and fsyncs. A crash at any
// point leaves either the old or the new tree fully intact.
//
// This module owns only the *index file*; it is independent of the .vault
// content file and of the RPC layer.
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "crypto.hpp"
#include "util.hpp"

namespace shinkuro {

struct VaultError : std::runtime_error {
  std::string code;
  VaultError(std::string c, const std::string& msg) : std::runtime_error(msg), code(std::move(c)) {}
};

// One indexed file. `seq` preserves insertion order so list() can keep the
// historical ordering regardless of the tree's lexicographic key order.
struct FileEntry {
  std::string name;
  uint64_t size = 0;
  uint64_t offset = 0;
  int64_t mtime = 0;
  Bytes file_id;     // 16 random bytes; used as chunk AAD
  uint64_t seq = 0;  // insertion sequence (monotonic)
};

// A reusable hole in the vault content file (offset + length, in bytes).
struct FreeRange {
  uint64_t offset = 0;
  uint64_t size = 0;
};

class Index {
public:
  Index() = default;
  ~Index() { close(); }

  Index(const Index&) = delete;
  Index& operator=(const Index&) = delete;

  bool is_open() const { return open_; }

  // ---- lifecycle ----
  // Create a brand-new empty index (overwrites path).
  void create(const std::filesystem::path& path, const Bytes& idx_key, const Bytes& pair_token,
              uint64_t generation);
  // Open an existing index. Throws VaultError (WRONG_PASSWORD / MISMATCHED_PAIR /
  // CORRUPT / IO_ERROR) on failure. `expected_generation` must match the on-disk
  // superblock (used by the two-file consistency check).
  void open(const std::filesystem::path& path, const Bytes& idx_key, const Bytes& pair_token,
            uint64_t expected_generation);
  // Close handle and wipe key material. Does not touch the file on disk.
  void close();
  // Reload from disk, discarding any uncommitted in-memory mutations. Used to
  // roll back after a failed commit (the on-disk superblock is still the old one).
  void reopen(uint64_t expected_generation);

  // ---- tree operations (buffered; not durable until commit()) ----
  void insert_file(const FileEntry& e);
  bool erase_file(const std::string& name);  // returns false if not present
  std::optional<FileEntry> find_file(const std::string& name) const;
  void iterate_files(const std::function<void(const FileEntry&)>& cb) const;
  uint64_t file_count() const { return file_count_; }

  void set_free(const std::vector<FreeRange>& ranges);  // replaces the whole free tree
  void iterate_free(const std::function<void(const FreeRange&)>& cb) const;
  uint64_t free_count() const { return free_count_; }

  // Atomically persist all buffered mutations (copy-on-write pages + superblock
  // flip + fsync). On exception the on-disk state is unchanged (old superblock
  // still active); callers may reopen() to reset in-memory state.
  void commit();

  uint64_t generation() const { return generation_; }
  void set_generation(uint64_t g) { generation_ = g; }
  uint64_t next_page() const { return next_page_; }
  uint64_t live_page_count() const;  // reachable pages from both roots

  // Rebuild the index compactly into a temp file and atomically replace it,
  // reclaiming leaked append-only slots and empty leaves. Takes the canonical
  // in-memory state (owned by Vault) as source of truth.
  void reindex(const std::vector<FileEntry>& files, const std::vector<FreeRange>& frees,
               uint64_t generation);

  // On-disk / in-memory representations. Public so the serialization helpers in
  // index.cpp (free functions) can use them.
  struct Superblock {
    uint64_t seq = 0;
    uint64_t root_files = 0;  // 0 = empty
    uint64_t root_free = 0;   // 0 = empty
    uint64_t next_page = 1;   // next unallocated slot id (high-water mark)
    uint64_t file_count = 0;
    uint64_t free_count = 0;
    uint64_t generation = 0;
    uint64_t reserved = 0;
  };

  enum class PageType : uint8_t { LEAF = 0, INTERNAL = 1 };

  struct Page {
    PageType type = PageType::LEAF;
    std::vector<std::pair<Bytes, Bytes>> kv;  // leaf: sorted by key
    std::vector<uint64_t> children;           // internal: size = keys.size()+1
    std::vector<Bytes> keys;                  // internal: separator keys
  };

private:
  bool open_ = false;
  std::filesystem::path path_;
  FILE* f_ = nullptr;
  Bytes idx_key_;
  Bytes pair_token_;

  // Committed superblock (last durable state) + active slot index.
  Superblock sb_;
  int active_slot_ = 0;

  // Working tree state (may diverge from sb_ between commit() calls).
  uint64_t root_files_ = 0;
  uint64_t root_free_ = 0;
  uint64_t next_page_ = 1;
  uint64_t file_count_ = 0;
  uint64_t free_count_ = 0;
  uint64_t generation_ = 0;

  mutable std::unordered_map<uint64_t, Page> cache_;
  std::unordered_set<uint64_t> dirty_;  // slot ids allocated since last commit

  // ---- page/disk helpers ----
  Page get_page(uint64_t id) const;
  uint64_t new_page(const Page& p);
  Page read_page_from_disk(uint64_t id) const;
  void write_page(uint64_t id, const Page& p);
  void write_superblock(int slot, const Superblock& sb);
  void write_superblock_zeros(int slot);
  std::optional<Superblock> read_superblock(int slot);
  void flush();
  void write_header();
  uint64_t read_header();  // returns the plaintext header generation
  uint64_t slot_offset(uint64_t id) const;

  // ---- B+ tree algorithms (recursive, copy-on-write) ----
  void insert_into_tree(uint64_t& root, const Bytes& key, const Bytes& value);
  uint64_t insert_rec(uint64_t id, const Bytes& key, const Bytes& value, bool& did_split,
                      Bytes& up_key, uint64_t& up_right);
  struct EraseOut {
    uint64_t id;
    bool found;
  };
  EraseOut erase_rec(uint64_t id, const Bytes& key);
  std::optional<Bytes> find_rec(uint64_t id, const Bytes& key) const;
  void iterate_rec(uint64_t id, const std::function<void(const Bytes&, const Bytes&)>& cb) const;
  void count_reachable(uint64_t id, std::unordered_set<uint64_t>& seen) const;

  void reset_state();
};

}  // namespace shinkuro
