#include "../include/AES.hpp"
#include "../include/utils.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
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
    tweak.assign(tweak_digest, tweak_digest + 16); // same mistake we were doin g before
    OPENSSL_free(tweak_digest); // Free the tweak digest memory
  }

  AES aes = AES(key_size, n_rounds, key, tweak);

  // tweak part added
  vector<vector<uint8_t>> cipherBlocks;
  vector<uint8_t> tweak_for_block = tweak;

  for (size_t i = 0; i < all_blocks.size(); i++) {
    vector<uint8_t> current_block = all_blocks.at(i);



    // are we supposed to rotate?
    // if it isnt the first block, get the previous one, if the size of this block is not 16, meaning its the last block
    if (current_block != all_blocks.front()) {
        if (current_block.size() < 16) {
            vector<uint8_t> previous_block = all_blocks.at(i - 1);
            // ciphertext stealing
            size_t steal_size = 16 - current_block.size();
            // take last steal_size bytes from previous_block
            vector<uint8_t> stolen_bytes(previous_block.end() - steal_size, previous_block.end
());
            // append stolen bytes to current_block
            current_block.insert(current_block.end(), stolen_bytes.begin(), stolen_bytes.end());
            // resize previous_block
            previous_block.resize(previous_block.size() - steal_size);
            // update the previous block in all_blocks
            all_blocks.at(i - 1) = previous_block;
        }
    }

    AES aes(key_size, n_rounds, key, tweak_for_block);

    // cout << "Encrypting the following block (size " << current_block.size()
    //      << " bytes)" << endl; // COMMENT THIS OUT
    // utils::printVector(current_block); // COMMENT THIS OUT

    // // test alteration for now 
    // if (current_block.size() < 16) {
    //   // padding with zeros
    //   current_block.resize(16, 0x00);
    // }

    cipherBlocks.push_back(aes.encrypt_block(current_block));

    if (TWEAK) {
        utils::increment_tweak(tweak_for_block);
    }
  }

  // cout << endl << "Encrypted bytes:" << endl; // COMMENT THIS OUT
  for (size_t i = 0; i < cipherBlocks.size(); i++) {
    // utils::printVector(cipherBlocks[i]); // COMMENT THIS OUT
    cout.write(reinterpret_cast<const char*>(cipherBlocks[i].data()), cipherBlocks[i].size());
  }

  return 0;
}

// TODO: Do ciphertext stealing next, not padding

// To test without tweak - normal AES-ECB
// # Encrypt
// ./encrypt 128 mypassword < plaintext.bin > ciphertext.bin

// # Decrypt
// ./decrypt 128 mypassword < ciphertext.bin > decrypted.bin

// To test with tweak - T-AES counter mode
// # Encrypt
// ./encrypt 128 mypassword mytweak < plaintext.bin > ciphertext.bin

// # Decrypt
// ./decrypt 128 mypassword mytweak < ciphertext.bin > decrypted.bin

// Use to check if fies are identical
// diff plaintext.bin decrypted.bin
// # or
// cmp plaintext.bin decrypted.bin