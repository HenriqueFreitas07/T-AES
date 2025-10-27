#include "../include/AESNI.hpp"
#include "../include/utils.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <vector>

using namespace std;

bool TWEAK = false;

int main(int argc, char *argv[]) {

  if (argc < 3) {
    cout << "Required arguments: <aes_size (128 | 192 | 256)> <password> "
            "<tweak_password?>"
         << endl;
    return 1;
  }

  int size = atoi(argv[1]);
  if (size != 128 && size != 192 && size != 256) {
    cout << "AES size must be 128, 192 or 256" << endl;
    return 1;
  }

  if (argc == 4) {
    TWEAK = true;
  }

  // pwd parsing
  const unsigned char *password =
      reinterpret_cast<const unsigned char *>(argv[2]);
  const unsigned long int password_length = strlen(argv[2]);

  // tweak parsing
  const unsigned char *tweak_pwd =
      TWEAK ? reinterpret_cast<const unsigned char *>(argv[3]) : nullptr;
  const unsigned long int tweak_length = TWEAK ? strlen(argv[3]) : 0;

  vector<vector<uint8_t>> all_blocks;

  // A block has 128bit = 128/8 => 16 bytes or 16 chars
  char block[16]{};
  int current_block_size = 0;
  // read all the bytes from the stdin until EOF
  while (true) {
    cin.read(block, 16);
    current_block_size = static_cast<size_t>(cin.gcount());
    if (current_block_size == 0)
      break;
    vector<uint8_t> converted =
        utils::convertToBlock(block, current_block_size);
    all_blocks.push_back(converted);
    if (current_block_size < 16)
      break; // EOF reached or last block
  }

  unsigned int key_size, n_rounds;

  switch (size) {
  case 128:
    key_size = 128;
    n_rounds = 10;
    break;
  case 192:
    key_size = 192;
    n_rounds = 12;
    break;
  case 256:
    key_size = 256;
    n_rounds = 14;
    break;
  default:
    key_size = 128;
    n_rounds = 10;
    break;
  }
  unsigned char *digest = NULL;
  unsigned int digest_len = 0;
  utils::digest_message(password, password_length, &digest, &digest_len);

  unsigned int key_bytes = key_size / 8; // Convert bits to bytes
  vector<uint8_t> key(digest, digest + key_bytes);
  OPENSSL_free(digest); // Free the digest memory

  // utils::printVector(key); // COMMENT THIS OUT

  vector<uint8_t> tweak;
  if (TWEAK) {
    unsigned char *tweak_digest = NULL;
    unsigned int tweak_digest_len = 0;
    utils::digest_message(tweak_pwd, tweak_length, &tweak_digest,
                          &tweak_digest_len);
    tweak.assign(tweak_digest,
                 tweak_digest + 16); 
    OPENSSL_free(tweak_digest);      
  }

  // Create AESNI instance with hardware acceleration
  // Constructor will throw runtime_error if CPU doesn't support AES-NI
  AESNI aes_ni(key_size, n_rounds, key, tweak);

  // tweak part added
  vector<vector<uint8_t>> cipherBlocks;
  vector<uint8_t> tweak_for_block = tweak;

  for (size_t i = 0; i < all_blocks.size(); i++) {
    vector<uint8_t> current_block = all_blocks.at(i);
    vector<uint8_t> ciphertext_block;
    if (current_block.size() < 16) {
      // ciphertext stealing
      size_t steal_size = 16 - current_block.size();
      vector<uint8_t> previous_encrypted_block = cipherBlocks.at(i - 1);
      // this is the last bytes that are copied from the cipher of the Cn-1 block to append to the plaintext of the Pn block
      vector<uint8_t> cipher_to_append(previous_encrypted_block.end() -
                                           steal_size,
                                       previous_encrypted_block.end());

      current_block.insert(current_block.end(), cipher_to_append.begin(),
                           cipher_to_append.end());
      // new last block (leftover of the ciphertext of the previous block n-1 )
      vector<uint8_t> new_last_block(previous_encrypted_block.begin(),
                                     previous_encrypted_block.end() -
                                         steal_size);
      ciphertext_block = aes_ni.encrypt_block(current_block);
      cipherBlocks[i - 1] = new_last_block;  // Replace C(n-1) with truncated version
      cipherBlocks.push_back(ciphertext_block);  // Add Cn at the end

    } else {
      ciphertext_block = aes_ni.encrypt_block(current_block);
      cipherBlocks.push_back(ciphertext_block);
    }

    if (TWEAK) {
      utils::increment_tweak(tweak_for_block);
    }
  }

  // cout << endl << "Encrypted bytes:" << endl; // COMMENT THIS OUT
  for (size_t i = 0; i < cipherBlocks.size(); i++) {
    // utils::printVector(cipherBlocks[i]); // COMMENT THIS OUT
    cout.write(reinterpret_cast<const char *>(cipherBlocks[i].data()),
               cipherBlocks[i].size());
  }

  return 0;
}

// Hardware-accelerated AES using AES-NI instructions
// Requires CPU with AES-NI support (Intel 2010+ / AMD 2011+)

// To test without tweak - normal AES-ECB with hardware acceleration
// # Encrypt
// ./encrypt_aesni 128 mypassword < plaintext.bin > ciphertext.bin

// # Decrypt
// ./decrypt_aesni 128 mypassword < ciphertext.bin > decrypted.bin

// To test with tweak - T-AES counter mode with hardware acceleration
// # Encrypt
// ./encrypt_aesni 128 mypassword mytweak < plaintext.bin > ciphertext.bin

// # Decrypt
// ./decrypt_aesni 128 mypassword mytweak < ciphertext.bin > decrypted.bin

// Use to check if files are identical
// diff plaintext.bin decrypted.bin
// # or
// cmp plaintext.bin decrypted.bin

// Performance comparison with software version:
// # Encrypt with software
// time ./encrypt 128 mypassword < largefile.bin > cipher_sw.bin
// # Encrypt with hardware
// time ./encrypt_aesni 128 mypassword < largefile.bin > cipher_hw.bin
