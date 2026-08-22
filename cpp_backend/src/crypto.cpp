#include "crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <vector>

namespace shinkuro {

namespace {
constexpr size_t CHUNK = 1024 * 1024;  // 1 MiB
constexpr size_t TAG_SIZE = 16;
constexpr int AES_GCM_IV_LEN = 12;

struct CtxGuard {
  EVP_CIPHER_CTX* p;
  explicit CtxGuard(EVP_CIPHER_CTX* ctx) : p(ctx) {}
  ~CtxGuard() {
    if (p) EVP_CIPHER_CTX_free(p);
  }
};
}  // namespace

Bytes random_bytes(size_t n) {
  Bytes b(n);
  if (n > 0 && RAND_bytes(b.data(), static_cast<int>(n)) != 1) {
    throw CryptoError("RAND_bytes failed");
  }
  return b;
}

void secure_zero(Bytes& b) {
  if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
  b.clear();
  b.shrink_to_fit();
}

void secure_zero_string(std::string& s) {
  if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
  s.clear();
  s.shrink_to_fit();
}

Bytes pbkdf2_sha256(const std::string& password, const Bytes& salt, uint32_t iterations,
                    size_t key_len) {
  Bytes out(key_len);
  if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt.data(),
                        static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(),
                        static_cast<int>(key_len), out.data()) != 1) {
    throw CryptoError("PBKDF2 failed");
  }
  return out;
}

static Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
           static_cast<int>(data.size()), md, &mdlen) == nullptr) {
    throw CryptoError("HMAC failed");
  }
  return Bytes(md, md + mdlen);
}

Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t out_len) {
  Bytes prk = hmac_sha256(salt, ikm);  // extract (32 bytes)
  Bytes okm;
  Bytes t;
  uint8_t counter = 1;
  while (okm.size() < out_len) {
    Bytes data = t;
    data.push_back(counter++);
    data.insert(data.end(), info.begin(), info.end());
    t = hmac_sha256(prk, data);
    okm.insert(okm.end(), t.begin(), t.end());
  }
  okm.resize(out_len);
  return okm;
}

std::pair<Bytes, Bytes> gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                    const Bytes& plaintext) {
  EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
  if (!raw) throw CryptoError("EVP_CIPHER_CTX_new failed");
  CtxGuard guard(raw);

  if (EVP_EncryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw CryptoError("EVP_EncryptInit_ex failed");
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr) != 1)
    throw CryptoError("set ivlen failed");
  if (EVP_EncryptInit_ex(raw, nullptr, nullptr, key.data(), nonce.data()) != 1)
    throw CryptoError("EVP_EncryptInit_ex(key) failed");

  int len = 0;
  if (!aad.empty() && EVP_EncryptUpdate(raw, nullptr, &len, aad.data(),
                                        static_cast<int>(aad.size())) != 1)
    throw CryptoError("AAD update failed");

  Bytes out(plaintext.size() + 16);
  int out_len = 0;
  if (!plaintext.empty() &&
      EVP_EncryptUpdate(raw, out.data(), &out_len, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1)
    throw CryptoError("encrypt update failed");
  int final_len = 0;
  if (EVP_EncryptFinal_ex(raw, out.data() + out_len, &final_len) != 1)
    throw CryptoError("encrypt final failed");
  out.resize(out_len + final_len);

  Bytes tag(TAG_SIZE);
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
    throw CryptoError("get tag failed");
  return {std::move(out), std::move(tag)};
}

Bytes gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& ciphertext,
                  const Bytes& tag) {
  EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
  if (!raw) throw CryptoError("EVP_CIPHER_CTX_new failed");
  CtxGuard guard(raw);

  if (EVP_DecryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw CryptoError("EVP_DecryptInit_ex failed");
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr) != 1)
    throw CryptoError("set ivlen failed");
  if (EVP_DecryptInit_ex(raw, nullptr, nullptr, key.data(), nonce.data()) != 1)
    throw CryptoError("EVP_DecryptInit_ex(key) failed");

  int len = 0;
  if (!aad.empty() && EVP_DecryptUpdate(raw, nullptr, &len, aad.data(),
                                        static_cast<int>(aad.size())) != 1)
    throw CryptoError("AAD update failed");

  Bytes out(ciphertext.size() + 16);
  int out_len = 0;
  if (!ciphertext.empty() &&
      EVP_DecryptUpdate(raw, out.data(), &out_len, ciphertext.data(),
                        static_cast<int>(ciphertext.size())) != 1)
    throw CryptoError("decrypt update failed");

  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                          const_cast<uint8_t*>(tag.data())) != 1)
    throw CryptoError("set tag failed");

  int final_len = 0;
  if (EVP_DecryptFinal_ex(raw, out.data() + out_len, &final_len) != 1) {
    throw AuthError();
  }
  out.resize(out_len + final_len);
  return out;
}

void gcm_encrypt_stream(const Bytes& key, const Bytes& nonce, const Bytes& aad, FILE* in,
                        FILE* out, Progress progress) {
  EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
  if (!raw) throw CryptoError("EVP_CIPHER_CTX_new failed");
  CtxGuard guard(raw);

  if (EVP_EncryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw CryptoError("EVP_EncryptInit_ex failed");
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr) != 1)
    throw CryptoError("set ivlen failed");
  if (EVP_EncryptInit_ex(raw, nullptr, nullptr, key.data(), nonce.data()) != 1)
    throw CryptoError("EVP_EncryptInit_ex(key) failed");

  int len = 0;
  if (!aad.empty() && EVP_EncryptUpdate(raw, nullptr, &len, aad.data(),
                                        static_cast<int>(aad.size())) != 1)
    throw CryptoError("AAD update failed");

  std::vector<uint8_t> inbuf(CHUNK), outbuf(CHUNK + 16);
  uint64_t done = 0;
  while (true) {
    size_t n = std::fread(inbuf.data(), 1, CHUNK, in);
    if (n == 0) break;
    int out_len = 0;
    if (EVP_EncryptUpdate(raw, outbuf.data(), &out_len, inbuf.data(), static_cast<int>(n)) != 1)
      throw CryptoError("encrypt update failed");
    if (out_len > 0) std::fwrite(outbuf.data(), 1, out_len, out);
    done += n;
    if (progress) progress(done);
    if (n < CHUNK) break;  // EOF
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(raw, outbuf.data(), &final_len) != 1)
    throw CryptoError("encrypt final failed");
  if (final_len > 0) std::fwrite(outbuf.data(), 1, final_len, out);

  Bytes tag(TAG_SIZE);
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
    throw CryptoError("get tag failed");
  std::fwrite(tag.data(), 1, tag.size(), out);
}

void gcm_decrypt_stream(const Bytes& key, const Bytes& nonce, const Bytes& aad, FILE* in,
                        FILE* out, uint64_t cipher_len) {
  EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
  if (!raw) throw CryptoError("EVP_CIPHER_CTX_new failed");
  CtxGuard guard(raw);

  if (EVP_DecryptInit_ex(raw, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw CryptoError("EVP_DecryptInit_ex failed");
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr) != 1)
    throw CryptoError("set ivlen failed");
  if (EVP_DecryptInit_ex(raw, nullptr, nullptr, key.data(), nonce.data()) != 1)
    throw CryptoError("EVP_DecryptInit_ex(key) failed");

  int len = 0;
  if (!aad.empty() && EVP_DecryptUpdate(raw, nullptr, &len, aad.data(),
                                        static_cast<int>(aad.size())) != 1)
    throw CryptoError("AAD update failed");

  std::vector<uint8_t> inbuf(CHUNK), outbuf(CHUNK + 16);
  uint64_t remaining = cipher_len;
  while (remaining > 0) {
    size_t want = static_cast<size_t>(remaining < CHUNK ? remaining : CHUNK);
    size_t n = std::fread(inbuf.data(), 1, want, in);
    if (n == 0) throw CryptoError("unexpected EOF in ciphertext");
    int out_len = 0;
    if (EVP_DecryptUpdate(raw, outbuf.data(), &out_len, inbuf.data(), static_cast<int>(n)) != 1)
      throw CryptoError("decrypt update failed");
    if (out_len > 0) std::fwrite(outbuf.data(), 1, out_len, out);
    remaining -= n;
  }

  Bytes tag(TAG_SIZE);
  if (std::fread(tag.data(), 1, TAG_SIZE, in) != TAG_SIZE)
    throw CryptoError("missing GCM tag");
  if (EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1)
    throw CryptoError("set tag failed");

  int final_len = 0;
  if (EVP_DecryptFinal_ex(raw, outbuf.data(), &final_len) != 1) {
    throw AuthError();
  }
  if (final_len > 0) std::fwrite(outbuf.data(), 1, final_len, out);
}

void gcm_reencrypt_stream(const Bytes& old_key, const Bytes& old_nonce, const Bytes& aad,
                          const Bytes& new_key, const Bytes& new_nonce, FILE* in, FILE* out,
                          uint64_t cipher_len, Progress progress) {
  EVP_CIPHER_CTX* d_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();
  if (!d_ctx || !e_ctx) {
    if (d_ctx) EVP_CIPHER_CTX_free(d_ctx);
    if (e_ctx) EVP_CIPHER_CTX_free(e_ctx);
    throw CryptoError("EVP_CIPHER_CTX_new failed");
  }
  CtxGuard gd(d_ctx);
  CtxGuard ge(e_ctx);

  // ---- decrypt side (old key) ----
  if (EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw CryptoError("EVP_DecryptInit_ex failed");
  if (EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr) != 1)
    throw CryptoError("set ivlen failed");
  if (EVP_DecryptInit_ex(d_ctx, nullptr, nullptr, old_key.data(), old_nonce.data()) != 1)
    throw CryptoError("EVP_DecryptInit_ex(key) failed");
  int len = 0;
  if (!aad.empty() &&
      EVP_DecryptUpdate(d_ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
    throw CryptoError("AAD update failed");

  // ---- encrypt side (new key) ----
  if (EVP_EncryptInit_ex(e_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    throw CryptoError("EVP_EncryptInit_ex failed");
  if (EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, nullptr) != 1)
    throw CryptoError("set ivlen failed");
  if (EVP_EncryptInit_ex(e_ctx, nullptr, nullptr, new_key.data(), new_nonce.data()) != 1)
    throw CryptoError("EVP_EncryptInit_ex(key) failed");
  if (!aad.empty() &&
      EVP_EncryptUpdate(e_ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
    throw CryptoError("AAD update failed");

  std::vector<uint8_t> inbuf(CHUNK), plain(CHUNK + 16), outbuf(CHUNK + 16);
  uint64_t remaining = cipher_len;
  uint64_t done = 0;
  while (remaining > 0) {
    size_t want = static_cast<size_t>(remaining < CHUNK ? remaining : CHUNK);
    size_t n = std::fread(inbuf.data(), 1, want, in);
    if (n == 0) throw CryptoError("unexpected EOF in ciphertext");
    int plain_len = 0;
    if (EVP_DecryptUpdate(d_ctx, plain.data(), &plain_len, inbuf.data(), static_cast<int>(n)) != 1)
      throw CryptoError("decrypt update failed");
    int out_len = 0;
    if (EVP_EncryptUpdate(e_ctx, outbuf.data(), &out_len, plain.data(), plain_len) != 1)
      throw CryptoError("encrypt update failed");
    if (out_len > 0) std::fwrite(outbuf.data(), 1, out_len, out);
    remaining -= n;
    done += n;
    if (progress) progress(done);
  }

  // verify old tag
  Bytes old_tag(TAG_SIZE);
  if (std::fread(old_tag.data(), 1, TAG_SIZE, in) != TAG_SIZE)
    throw CryptoError("missing GCM tag");
  if (EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, old_tag.data()) != 1)
    throw CryptoError("set tag failed");
  int final_plain = 0;
  if (EVP_DecryptFinal_ex(d_ctx, plain.data(), &final_plain) != 1) {
    throw AuthError();
  }
  if (final_plain > 0) {
    int out_len = 0;
    if (EVP_EncryptUpdate(e_ctx, outbuf.data(), &out_len, plain.data(), final_plain) != 1)
      throw CryptoError("encrypt update failed");
    if (out_len > 0) std::fwrite(outbuf.data(), 1, out_len, out);
  }

  // finalize encrypt + write new tag
  int final_cipher = 0;
  if (EVP_EncryptFinal_ex(e_ctx, outbuf.data(), &final_cipher) != 1)
    throw CryptoError("encrypt final failed");
  if (final_cipher > 0) std::fwrite(outbuf.data(), 1, final_cipher, out);
  Bytes new_tag(TAG_SIZE);
  if (EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, new_tag.data()) != 1)
    throw CryptoError("get tag failed");
  std::fwrite(new_tag.data(), 1, new_tag.size(), out);
}

}  // namespace shinkuro
