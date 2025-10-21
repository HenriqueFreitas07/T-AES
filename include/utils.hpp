#ifndef UTILS_HPP
#define UTILS_HPP

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <vector>

namespace utils {

/// @brief Conversion from char to uint8_t for encryption operations
/// @param block Input character block
/// @return 128 bits of 16 bytes of 8 bit integers
std::vector<uint8_t> convertToBlock(char *block, size_t size) {
  // assure that a block only has a max of 16 bytes
  assert(size <= 16);
  std::vector<uint8_t> bformatted;
  for (size_t i = 0; i < size; i++) {
    bformatted.push_back(static_cast<uint8_t>(block[i]));
  }
  return bformatted;
}

uint8_t xtime(uint8_t x) { return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00); }

/// @brief Print a vector of any integer type
/// @param v Vector to print
template <typename T> void printVector(const std::vector<T> &v) {
  for (const auto &element : v) {
    std::cout << static_cast<int>(element) << " ";
  }
  std::cout << std::endl;
}

int handleErrors(std::string section) {
  printf("Unexpected error occured!\n");
  printf("Error in section %s\n", section.c_str());
  return 1;
}
/// @brief digest_message generation for tweak and passwords passed as textual
/// arguments
/// @param message Input password
/// @param message_len length of the message
/// @param digest the pointer where to store the message digest after generation
/// @param digest_len digest length
void digest_message(const unsigned char *message, size_t message_len,
                    unsigned char **digest, unsigned int *digest_len) {
  EVP_MD_CTX *mdctx;

  if ((mdctx = EVP_MD_CTX_new()) == NULL)
    handleErrors("context creation");

  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    handleErrors("digest_initialization");

  if (1 != EVP_DigestUpdate(mdctx, message, message_len))
    handleErrors("digest_generation");

  if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) ==
      NULL)
    handleErrors("storing_digest");

  if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
    handleErrors("finalizing_digest");

  EVP_MD_CTX_free(mdctx);
}

} // namespace utils

#endif // UTILS_HPP
