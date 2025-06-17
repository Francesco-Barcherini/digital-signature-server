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
#include <vector>
#include <stdexcept>

#include <string>

using namespace std;

// void sendSocket(int sock, const byte_vec& data) {
// }

using byte_vec = std::vector<unsigned char>;

void error(const char *msg)
{
    throw std::runtime_error(msg);
}

void readPEMPrivateKey(string filename, EVP_PKEY **privkey)
{
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) error("Failed to open PEM file");

    *privkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);

    if (!*privkey) error("Failed to read private key from PEM file");

    return;
}

void readPEMPublicKey(string filename, EVP_PKEY **pubkey)
{
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) error("Failed to open PEM file");

    *pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    if (!*pubkey) error("Failed to read public key from PEM file");

    return;
}

void signRsaSha256(byte_vec &signature, const byte_vec &data, EVP_PKEY* privkey)
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
    if (!ctx) error("Failed to create EVP_MD_CTX for verification");

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
    else error("EVP_DigestVerifyFinal failed");

    return false;
}


logLevel log_level = DEBUG;

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
    va_end(args);
}
