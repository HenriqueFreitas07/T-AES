#include <openssl/evp.h>
#include <cstdint>
#include <cstring>
#include "AES.hpp"   // optional if you want to call T-AES here
#include "utils.hpp" // optional

constexpr size_t BUFFER_SIZE = 4096;

// i have to use this part and compare with and without hardware acceleration
// my cpu has to support AES-NI instructions
// OpenSSL will automatically use AES-NI if available
// TODO: Check if its actually using AES-NI
// TODO: Benchmark with and without AES-NI both my implementation of AES, and OpenSSL XTS
// I can use other libraries too like Botan or Crypto++ if needed

bool openssl_xts_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t full_key[32]; // AES-128 XTS needs 256-bit key
    memcpy(full_key, key1, 16);
    memcpy(full_key + 16, key2, 16);

    EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, full_key, nullptr);
    int outlen;
    uint8_t outbuf[BUFFER_SIZE];

    EVP_EncryptUpdate(ctx, outbuf, &outlen, buffer, size);
    memcpy(buffer, outbuf, size);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool openssl_xts_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t full_key[32]; // AES-128 XTS needs 256-bit key
    memcpy(full_key, key1, 16);
    memcpy(full_key + 16, key2, 16);

    EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, full_key, nullptr);
    int outlen;
    uint8_t outbuf[BUFFER_SIZE];

    EVP_DecryptUpdate(ctx, outbuf, &outlen, buffer, size);
    memcpy(buffer, outbuf, size);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
