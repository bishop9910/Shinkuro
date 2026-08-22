// OpenSSL libcrypto wrappers: secure random, PBKDF2, HKDF, AES-256-GCM.
#pragma once

#include <cstdint>
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "util.hpp"

namespace shinkuro {

struct CryptoError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// Thrown when AES-GCM authentication fails (wrong key or tampered data).
struct AuthError : CryptoError {
  AuthError() : CryptoError("authentication failed") {}
};

// Progress callback for the streaming encrypt/re-encrypt functions: reports the
// number of plaintext bytes processed so far (callers know the total themselves).
using Progress = std::function<void(uint64_t done)>;

Bytes random_bytes(size_t n);
void secure_zero(Bytes& b);
void secure_zero_string(std::string& s);

Bytes pbkdf2_sha256(const std::string& password, const Bytes& salt, uint32_t iterations,
                   size_t key_len);
Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t out_len);

// Single-shot AES-256-GCM (for the small encrypted index blob).
// Returns {ciphertext, tag}.
std::pair<Bytes, Bytes> gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                    const Bytes& plaintext);
// Throws AuthError on failure.
Bytes gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& ciphertext,
                  const Bytes& tag);

// Streaming AES-256-GCM for file contents (1 MiB chunks, no full buffering).
// gcm_encrypt_stream reads all of `in`, writes ciphertext to `out`, then appends
// the 16-byte GCM tag to `out`. `progress` (optional) reports bytes processed.
void gcm_encrypt_stream(const Bytes& key, const Bytes& nonce, const Bytes& aad, FILE* in,
                        FILE* out, Progress progress = {});
// gcm_decrypt_stream reads exactly `cipher_len` bytes of ciphertext from `in`,
// writes plaintext to `out`, then reads the 16-byte tag from `in` and verifies
// it (throws AuthError on failure).
void gcm_decrypt_stream(const Bytes& key, const Bytes& nonce, const Bytes& aad, FILE* in,
                        FILE* out, uint64_t cipher_len);

// Re-encrypt a chunk in-place-pipeline: reads `cipher_len` bytes of ciphertext +
// 16-byte tag from `in` (encrypted with old_key/old_nonce), decrypts in memory,
// re-encrypts with new_key/new_nonce, and writes the new ciphertext + new tag to
// `out`. No plaintext ever touches disk. Throws AuthError if the old tag fails.
// `progress` (optional) reports plaintext bytes processed within this chunk.
void gcm_reencrypt_stream(const Bytes& old_key, const Bytes& old_nonce, const Bytes& aad,
                          const Bytes& new_key, const Bytes& new_nonce, FILE* in, FILE* out,
                          uint64_t cipher_len, Progress progress = {});

}  // namespace shinkuro
