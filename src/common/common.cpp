#include "common.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include <vector>
#include <cstdint>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <vector>
#include <stdexcept>

#include <string>

using namespace std;

using byte_vec = std::vector<unsigned char>;

byte_vec& get_shared_key();

void error(const char *msg)
{
    memzero(get_shared_key());
    throw std::runtime_error(msg);
}

void genRandomBytes(byte_vec &data, size_t size)
{
    data.resize(size);
    if (RAND_bytes(data.data(), size) != 1)
        error("Failed to generate random bytes");
}

string byte_vec_to_hex(const byte_vec &data)
{
    std::ostringstream oss;
    for (unsigned char byte : data)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

void ffdhe2048GenMsgAndKeys(byte_vec &public_msg, EVP_PKEY *&keypair)
{
    EVP_PKEY *dh_params = NULL;
    EVP_PKEY_CTX *param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!param_ctx)
        error("Failed to create DH param context");

    if (EVP_PKEY_paramgen_init(param_ctx) <= 0)
        error("Failed to initialize DH paramgen");

    if (EVP_PKEY_CTX_set_dh_nid(param_ctx, NID_ffdhe2048) <= 0)
        error("Failed to set DH params to ffdhe2048");

    if (EVP_PKEY_paramgen(param_ctx, &dh_params) <= 0)
        error("Failed to generate DH parameters");

    EVP_PKEY_CTX_free(param_ctx);

    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_free(dh_params);
    if (!key_ctx)
        error("Failed to create DH key context");

    if (EVP_PKEY_keygen_init(key_ctx) <= 0)
        error("Failed to initialize DH keygen");

    if (EVP_PKEY_keygen(key_ctx, &keypair) <= 0)
        error("Failed to generate DH keypair");

    EVP_PKEY_CTX_free(key_ctx);

    // Export public key only
    unsigned char *pubkey_buf = NULL;
    int pubkey_len = i2d_PUBKEY(keypair, &pubkey_buf);
    if (pubkey_len <= 0)
        error("Failed to encode DH public key");

    public_msg.assign(pubkey_buf, pubkey_buf + pubkey_len);
    OPENSSL_free(pubkey_buf);
}

/**
 * Given a peer's DER-encoded DH public key (`peer_pubkey_msg`) and your private key (`privkey`),
 * compute the shared secret and return it in `shared_secret`.
 */
void ffdhe2048ComputeSharedSecret(const byte_vec &peer_pubkey_msg, EVP_PKEY *privkey, byte_vec &shared_secret)
{
    const unsigned char *p = peer_pubkey_msg.data();

    // Decode peer's public key from DER format
    EVP_PKEY *peer_pubkey = d2i_PUBKEY(NULL, &p, (int)peer_pubkey_msg.size());
    if (!peer_pubkey)
        error("Failed to decode peer's public key");

    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!derive_ctx)
    {
        EVP_PKEY_free(peer_pubkey);
        error("Failed to create derive context");
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        error("Failed to initialize derive context");
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        error("Failed to set peer public key");
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx, NULL, &secret_len) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        error("Failed to determine secret length");
    }

    shared_secret.resize(secret_len);
    if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        error("Failed to derive shared secret");
    }

    shared_secret.resize(secret_len); // adjust size if smaller

    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_CTX_free(derive_ctx);
}

void aes256gcm_encrypt(const byte_vec &plaintext,
                       const byte_vec &key,
                       byte_vec &iv,
                       byte_vec &ciphertext,
                       byte_vec &tag)
{
    if (key.size() != 32)
        error("Key must be 32 bytes for AES-256-GCM");

    // Generate random 12-byte IV if iv is empty
    if (iv.empty())
    {
        iv.resize(12);
        if (!RAND_bytes(iv.data(), (int)iv.size()))
            error("Failed to generate IV");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        error("Failed to create EVP_CIPHER_CTX");
    // TODO: nei lab dice di usare EVP_EncryptInit senza _ex
    // ma EVP_EncryptInit_ex è la versione corretta per AES-GCM (non deprecated)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), NULL) != 1)
        error("EVP_CIPHER_CTX_ctrl set IV length failed");

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1)
        error("EVP_EncryptInit_ex set key/iv failed");

    int len = 0;
    ciphertext.resize(plaintext.size());

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1)
        error("EVP_EncryptUpdate failed");

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        error("EVP_EncryptFinal_ex failed");

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
        error("EVP_CIPHER_CTX_ctrl get tag failed");

    EVP_CIPHER_CTX_free(ctx);
}

/**
 * AES-256-GCM decryption.
 * @param ciphertext Input encrypted data.
 * @param key 32-byte symmetric key.
 * @param iv IV used for encryption (12 bytes typically).
 * @param tag 16-byte authentication tag.
 * @param plaintext Output decrypted data.
 */
void aes256gcm_decrypt(const byte_vec &ciphertext,
                       const byte_vec &key,
                       const byte_vec &iv,
                       const byte_vec &tag,
                       byte_vec &plaintext)
{
    if (key.size() != 32)
        error("Key must be 32 bytes for AES-256-GCM");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        error("Failed to create EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        error("EVP_DecryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), NULL) != 1)
        error("EVP_CIPHER_CTX_ctrl set IV length failed");

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1)
        error("EVP_DecryptInit_ex set key/iv failed");

    int len = 0;
    plaintext.resize(ciphertext.size());

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1)
        error("EVP_DecryptUpdate failed");

    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void *)tag.data()) != 1)
        error("EVP_CIPHER_CTX_ctrl set tag failed");

    // Finalize decryption: returns 1 if tag verification succeeds
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1)
        error("Decryption failed: tag verification failed");

    plaintext_len += len;
    plaintext.resize(plaintext_len);
}

void readPEMPrivateKey(string filename, EVP_PKEY **privkey, string passphrase)
{
    FILE *file = fopen(filename.c_str(), "r");
    if (!file)
        error("Failed to open PEM file");

    *privkey = PEM_read_PrivateKey(file, NULL, NULL, passphrase.empty() ? NULL : (void *)passphrase.c_str());

    fclose(file);

    if (!*privkey)
        error("Failed to read private key from PEM file");

    return;
}

void readPEMPublicKey(string filename, EVP_PKEY **pubkey)
{
    FILE *file = fopen(filename.c_str(), "r");
    if (!file)
        error("Failed to open PEM file");

    *pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    if (!*pubkey)
        error("Failed to read public key from PEM file");

    return;
}

void signRsaSha256(byte_vec &signature, const byte_vec &data, EVP_PKEY *privkey)
{
    // Create the context for signing
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignUpdate failed");
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignFinal (get length) failed");
    }

    signature.resize(sig_len);

    // Get the signature
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignFinal failed");
    }

    signature.resize(sig_len);

    EVP_MD_CTX_free(ctx);

    return;
}

bool verifyRsaSha256(const byte_vec &data, const byte_vec &signature, EVP_PKEY *pubkey)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        error("Failed to create EVP_MD_CTX for verification");

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestVerifyInit failed");
    }

    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestVerifyUpdate failed");
    }

    int ret = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);

    if (ret == 1)
    {
        return true; // Signature is valid
    }
    else if (ret == 0)
    {
        return false; // Signature is invalid
    }
    else
        error("EVP_DigestVerifyFinal failed");

    return false;
}

logLevel log_level = WARN;

// ANSI color codes for log levels
static const char *level_colors[] = {
    "\033[36m", // DEBUG - Cyan
    "\033[32m", // INFO - Green
    "\033[33m", // WARN - Yellow
    "\033[31m"  // ERROR - Red
};
static const char *level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"};
#define COLOR_RESET "\033[0m"


void set_log_level(char* level)
{
    if (strcmp(level, "debug") == 0)
        log_level = DEBUG;
    else if (strcmp(level, "info") == 0)
        log_level = INFO;
    else if (strcmp(level, "warn") == 0)
        log_level = WARN;
    else if (strcmp(level, "error") == 0)
        log_level = ERROR;
}

void LOG(logLevel level, const char *format, ...)
{
    if (level < log_level)
        return;
    va_list args;
    va_start(args, format);
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    printf("%s[%s] [%s]%s ", level_colors[level], buf, level_names[level], COLOR_RESET);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

// TODO usare due chiavi simmetriche??#include <openssl/kdf.h> // For HKDF

bool derive_shared_secret_and_key(EVP_PKEY *my_privkey,
                                  EVP_PKEY *peer_pubkey,
                                  byte_vec &shared_secret,
                                  byte_vec &symmetric_key)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_privkey, nullptr);
    if (!ctx)
        error("Failed to create EVP_PKEY_CTX for shared secret derivation");

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        error("EVP_PKEY_derive init/set_peer failed");
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        error("EVP_PKEY_derive (get length) failed");
    }

    shared_secret.resize(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        error("EVP_PKEY_derive (compute secret) failed");
    }
    shared_secret.resize(secret_len);
    EVP_PKEY_CTX_free(ctx);

    // Derive a 32-byte symmetric key using HKDF with SHA256
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!kctx)
        error("Failed to create HKDF context");

    if (EVP_PKEY_derive_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_mode(kctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kctx, nullptr, 0) <= 0 || // Optional: add salt
        EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret.data(), shared_secret.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            kctx,
            reinterpret_cast<const unsigned char *>("ffdhe2048 handshake"),
            strlen("ffdhe2048 handshake")) <= 0)
    {
        EVP_PKEY_CTX_free(kctx);
        error("HKDF parameter setup failed");
    }

    symmetric_key.resize(32); // AES-256 key size
    size_t len = 32;
    if (EVP_PKEY_derive(kctx, symmetric_key.data(), &len) <= 0)
    {
        EVP_PKEY_CTX_free(kctx);
        error("HKDF derive failed");
    }

    symmetric_key.resize(len);
    EVP_PKEY_CTX_free(kctx);
    return true;
}


void sha256(const string &password, const byte_vec &salt, byte_vec &hashed_password)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        error("Failed to create EVP_MD_CTX for SHA-256 hashing");

    unsigned int digest_len = EVP_MD_size(EVP_sha256());
    hashed_password.resize(digest_len);

    if (1 != EVP_DigestInit(ctx, EVP_sha256())) {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestInit failed");
    }
    if (1 != EVP_DigestUpdate(ctx, password.data(), password.size())) {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestUpdate failed");
    }
    if (1 != EVP_DigestUpdate(ctx, salt.data(), salt.size())) {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestUpdate failed");
    }
    if (1 != EVP_DigestFinal(ctx, hashed_password.data(), &digest_len)) {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestFinal failed");
    }
    hashed_password.resize(digest_len); // Resize to actual digest length
    EVP_MD_CTX_free(ctx);
}

bool verify_sha256(const string& password, const byte_vec &salt, const byte_vec &hashed_password) {
    byte_vec computed_hash;
    sha256(password, salt, computed_hash);
    
    return (CRYPTO_memcmp(computed_hash.data(), hashed_password.data(), EVP_MD_size(EVP_sha256())) == 0);
}

void genRSAKeyPair(EVP_PKEY **pubkey, EVP_PKEY **privkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        error("Failed to create RSA context");

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        error("Failed to initialize RSA keygen");

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        error("Failed to set RSA key size");

    if (EVP_PKEY_keygen(ctx, privkey) <= 0)
        error("Failed to generate RSA private key");

    *pubkey = EVP_PKEY_dup(*privkey);
    if (!*pubkey)
    {
        EVP_PKEY_free(*privkey);
        error("Failed to duplicate RSA public key");
    }

    EVP_PKEY_CTX_free(ctx);
}

void __attribute__((optimize("O0"))) memzero(string &str)
{
    if (str.empty())
        return;
    fill(str.begin(), str.end(), 0);
}

void __attribute__((optimize("O0"))) memzero(byte_vec &data)
{   
    if (data.empty())
        return;
    fill(data.begin(), data.end(), 0);
}
