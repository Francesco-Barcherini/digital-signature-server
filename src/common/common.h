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
#include <vector>
#include <stdexcept>

#include <string>

using namespace std;


typedef enum {
    DEBUG,
    INFO,
    WARN,
    ERROR
} logLevel;

extern logLevel log_level;

using byte_vec = std::vector<uint8_t>;


void error(const char *msg);

void readPEMPrivateKey(string filename, EVP_PKEY **pkey);
void readPEMPublicKey(string filename, EVP_PKEY **pubkey);
void signRsaSha256(byte_vec &signature, const byte_vec &data, EVP_PKEY* pkey);
bool verifyRsaSha256(const byte_vec &data, const byte_vec &signature, EVP_PKEY *pkey);

void LOG(logLevel level, const char* format, ...);
