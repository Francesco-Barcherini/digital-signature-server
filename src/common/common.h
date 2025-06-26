#pragma once

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
#include <vector>
#include <stdexcept>

#include <string>

using namespace std;

typedef enum
{
    DEBUG,
    INFO,
    WARN,
    ERROR
} logLevel;

extern logLevel log_level;

using byte_vec = std::vector<uint8_t>;

const string DATA_PATH = "data/";
const int MAX_CMD_SIZE = 20;
const int MAX_TEXT_SIZE = 100;
const int SALT_SIZE = 8;

void error(const char *msg);

void genRandomBytes(byte_vec &data, size_t size);

void ffdhe2048GenMsgAndKeys(byte_vec &public_msg, EVP_PKEY *&keypair);
void ffdhe2048ComputeSharedSecret(const byte_vec &peer_pubkey_msg, EVP_PKEY *privkey, byte_vec &shared_secret);

void aes256gcm_decrypt(const byte_vec &ciphertext,
                       const byte_vec &key,
                       const byte_vec &iv,
                       const byte_vec &tag,
                       byte_vec &plaintext);
void aes256gcm_encrypt(const byte_vec &plaintext,
                       const byte_vec &key,
                       byte_vec &iv,
                       byte_vec &ciphertext,
                       byte_vec &tag);

void readPEMPrivateKey(string filename, EVP_PKEY **pkey);
void readPEMPublicKey(string filename, EVP_PKEY **pubkey);
void signRsaSha256(byte_vec &signature, const byte_vec &data, EVP_PKEY *pkey);
bool verifyRsaSha256(const byte_vec &data, const byte_vec &signature, EVP_PKEY *pkey);



bool derive_shared_secret_and_key(EVP_PKEY *my_privkey,
                          EVP_PKEY *peer_pubkey,
                          byte_vec &shared_secret, byte_vec &symmetric_key);

void sha256(const string& password, const byte_vec &salt, byte_vec &hashed_password);
bool verify_sha256(const string& password, const byte_vec &salt, const byte_vec &hashed_password);

void LOG(logLevel level, const char *format, ...);
