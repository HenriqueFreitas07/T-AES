#pragma once

#include "utils.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;
using namespace utils;
// Helper function for Galois Field multiplication

// AES works on 128 bit blocks
// 128 bits = 16 bytes
// 4x4 matrix = 16 positions = 16 bytes
// each byte is a state

class AES {
  int key_size;
  int n_rounds;
  vector<uint8_t> key;
  vector<uint8_t> tweak_key;

  // Round keys storage
  vector<vector<uint8_t>> round_keys;

  // AES S-box (substitution box) for SubBytes operation
  // inline header definition (C++17). Keep ONLY this, remove any other
  // definition.
  inline static constexpr uint8_t sbox[256] = {
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
      0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
      0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
      0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
      0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
      0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
      0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
      0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
      0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
      0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
      0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
      0xb0, 0x54, 0xbb, 0x16};

  inline static constexpr uint8_t inv_sbox[256] = {
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
      0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
      0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
      0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
      0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
      0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
      0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
      0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
      0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
      0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
      0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
      0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
      0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
      0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
      0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
      0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
      0x55, 0x21, 0x0c, 0x7d};

private:
    
// tweak operations for encryption and decryption


    // XOR the round key with the tweak - this is the standard approach for AES tweaks
    // it returns a vector because the result is a new round key
  vector<uint8_t> xor_tweak(const vector<uint8_t>& round_key, const vector<uint8_t>& tweak) {
    assert(round_key.size() == 16 && tweak.size() == 16);
    vector<uint8_t> result(16);
    for (int i = 0; i < 16; ++i) {
        result[i] = round_key[i] ^ tweak[i];
    }
    return result;
}


// goes to utils?
// inline void increment_tweak(vector<uint8_t>& tweak) {
//     assert(tweak.size() == 16);
//     for (int i = 15; i >= 0; --i) {
//         if (++tweak[i] != 0) break; // stop if no carry
//     }
// }


int get_tweak_round() const {
  // Apply tweak in the middle rounds for better security
  // AES-128: 10 rounds (0-10), apply tweak at round 5
  // AES-192: 12 rounds (0-12), apply tweak at round 6  
  // AES-256: 14 rounds (0-14), apply tweak at round 7
  if (key_size == 128) return 5;
  else if (key_size == 192) return 6;
  else if (key_size == 256) return 7;
  else throw invalid_argument("Invalid key size for tweak rounds");
}


  // AES Operations

  void ShiftRows(vector<vector<uint8_t>> &matrix) {
    assert(matrix.size() == 4 && matrix[0].size() == 4);
    // The objective of ShiftRows is to cyclically shift the rows of the state
    // matrix So that each byte is moved to a different position Row 0 is not
    // shifted Row 1 is shifted left by 1 Row 2 is shifted left by 2 Row 3 is
    // shifted left by 3
    for (size_t r = 1; r < matrix.size(); ++r) {
      rotate(matrix[r].begin(), matrix[r].begin() + r, matrix[r].end());
    }
  }

  void MixColumns(vector<vector<uint8_t>> &matrix) {
    assert(matrix.size() == 4 && matrix[0].size() == 4);

    for (int c = 0; c < 4; ++c) {
      uint8_t s0 = matrix[0][c];
      uint8_t s1 = matrix[1][c];
      uint8_t s2 = matrix[2][c];
      uint8_t s3 = matrix[3][c];

      // for each column, we perform the matrix multiplication
      // we apply xtime to each byte
      // and use xor for addition in GF(2^8)
      matrix[0][c] =
          xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3; // 2*s0 + 3*s1 + s2 + s3
      matrix[1][c] =
          s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3; // s0 + 2*s1 + 3*s2 + s3
      matrix[2][c] =
          s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3); // s0 + s1 + 2*s2 + 3*s3
      matrix[3][c] =
          (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3); // 3*s0 + s1 + s2 + 2*s3
    }
  }

  void SubBytes(vector<vector<uint8_t>> &matrix) {
    // here im basically traversing the matrix and substituting each byte using
    // the sbox
    for (size_t r = 0; r < matrix.size(); ++r) {
      for (size_t c = 0; c < matrix[r].size(); ++c) {
        uint8_t v = matrix[r][c];
        matrix[r][c] = sbox[v];
      }
    }
  }


  void AddRoundKey(vector<vector<uint8_t>> &matrix,
                 const vector<uint8_t> &round_key) {
    assert(matrix.size() == 4 && matrix[0].size() == 4);
    assert(round_key.size() == 16); // Only 16 bytes allowed
    
    for (size_t r = 0; r < matrix.size(); ++r) {
      for (size_t c = 0; c < matrix[r].size(); ++c) {
        matrix[r][c] ^= round_key[r + 4 * c];
      }
    }
}

  void KeyExpansion(const vector<uint8_t> &key) {
    // key size must be 128-bits or 192-bits or 256-bits long
    assert(key.size() == 16 || key.size() == 24 || key.size() == 32);

    int Nk = key.size() / 4; // Number of 32-bit words in key (4, 6, or 8)
    int Nr = n_rounds;       // Number of rounds (10, 12, or 14)
    int total_words = 4 * (Nr + 1); // Total words needed (44, 52, or 60)

    // Rcon table: round constants
    const uint8_t Rcon[15] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                              0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};

    // Create a flat word array (each word is 4 bytes)
    vector<vector<uint8_t>> words(total_words, vector<uint8_t>(4));

    // Step 1: First Nk words come from the original key
    for (int i = 0; i < Nk; i++) {
      words[i][0] = key[4 * i];
      words[i][1] = key[4 * i + 1];
      words[i][2] = key[4 * i + 2];
      words[i][3] = key[4 * i + 3];
    }

    // Step 2: Generate remaining words
    for (int i = Nk; i < total_words; i++) {
      // Start with previous word
      vector<uint8_t> temp = words[i - 1];

      if (i % Nk == 0) {
        // Every Nk-th word: RotWord, SubWord, XOR with Rcon

        // RotWord: rotate left by 1 byte
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;

        // SubWord: apply S-box to each byte
        temp[0] = sbox[temp[0]];
        temp[1] = sbox[temp[1]];
        temp[2] = sbox[temp[2]];
        temp[3] = sbox[temp[3]];

        // XOR with Rcon
        temp[0] ^= Rcon[i / Nk];
      } else if (Nk > 6 && i % Nk == 4) {
        // ONLY for AES-256: apply SubWord on every 4th word within a key
        temp[0] = sbox[temp[0]];
        temp[1] = sbox[temp[1]];
        temp[2] = sbox[temp[2]];
        temp[3] = sbox[temp[3]];
      }

      // XOR with word from Nk positions back
      words[i][0] = words[i - Nk][0] ^ temp[0];
      words[i][1] = words[i - Nk][1] ^ temp[1];
      words[i][2] = words[i - Nk][2] ^ temp[2];
      words[i][3] = words[i - Nk][3] ^ temp[3];
    }

    // Step 3: Group every 4 words into a 16-byte round key
    round_keys.clear();
    for (int round = 0; round <= Nr; round++) {
      vector<uint8_t> round_key(16);
      for (int word = 0; word < 4; word++) {
        round_key[4 * word] = words[round * 4 + word][0];
        round_key[4 * word + 1] = words[round * 4 + word][1];
        round_key[4 * word + 2] = words[round * 4 + word][2];
        round_key[4 * word + 3] = words[round * 4 + word][3];
      }
      round_keys.push_back(round_key);
    }
  }

public:
  AES(int size, int rounds, vector<uint8_t> key, vector<uint8_t> tweak_key)
      : key_size(size), n_rounds(rounds), key(key), tweak_key(tweak_key) {
    // Convert key string to vector<uint8_t> and perform key expansion
    // Pad or truncate to 16 bytes for AES-128
    KeyExpansion(key);
  }

  /// @brief Gets the raw block
  /// @param block vector<uint8_t>
  /// @return Returns the encrypted block after transformations
  vector<uint8_t> encrypt_block(vector<uint8_t> block) {
    // Ensure block is exactly 16 bytes, just for safety
    if (block.size() != 16) {
      throw invalid_argument("Block must be exactly 16 bytes");
    }

    // Convert 16 bytes to 4x4 matrix (AES state)
    vector<vector<uint8_t>> matrix(4, vector<uint8_t>(4));
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        matrix[i][j] = block[i + 4 * j];
      }
    }

    AddRoundKey(matrix, round_keys[0]); // initial round key


    // here we add the tweak 
    int tweak_round = get_tweak_round();

    for (int round = 1; round < n_rounds; ++round) {
      SubBytes(matrix);
      ShiftRows(matrix);
      MixColumns(matrix);

      // add tweak at specified round
      if (!tweak_key.empty() && round == tweak_round) {
        AddRoundKey(matrix, xor_tweak(round_keys[round], tweak_key));
      } else {
        AddRoundKey(matrix, round_keys[round]);
      }
    }
    // #############################

    // final round (no MixColumns)
    SubBytes(matrix);
    ShiftRows(matrix);
    AddRoundKey(matrix, round_keys[n_rounds]);

    // Convert matrix back to 16 bytes
    vector<uint8_t> result(16);
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        result[i + 4 * j] = matrix[i][j];
      }
    }

    return result;
  }

  // ############# Decryption #############

  /// @brief
  /// @param block
  /// @return
  vector<uint8_t> decrypt_block(vector<uint8_t> block) {
    if (block.size() != 16) {
      throw invalid_argument("Block must be exactly 16 bytes");
    }

    // convert 16 bytes to 4x4 matrix (AES state)
    vector<vector<uint8_t>> matrix(4, vector<uint8_t>(4));
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        matrix[i][j] = block[i + 4 * j];
      }
    }

    // initial add round key will be the same? or we go from the lasound and do
    // the opposite
    AddRoundKey(matrix, round_keys[n_rounds]); // initial round key


    // here we subtract the tweak at the specified round
    int tweak_round = get_tweak_round();

    for (int round = n_rounds - 1; round >= 1; --round) {
      InvShiftRows(matrix);
      InvSubBytes(matrix);

      // tweak subtraction at specified round (apply before InvMixColumns to match encryption order)
      if (!tweak_key.empty() && round == tweak_round) {
        AddRoundKey(matrix, xor_tweak(round_keys[round], tweak_key));
      } else {
        AddRoundKey(matrix, round_keys[round]);
      }
      
      InvMixColumns(matrix);
    }

    // final round (no InvMixColumns)
    InvShiftRows(matrix);
    InvSubBytes(matrix);
    AddRoundKey(matrix, round_keys[0]);

    // covnert matrix back to 16 btyes
    vector<uint8_t> result(16);
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        result[i + 4 * j] = matrix[i][j];
      }
    }
    return result;
  }

  void InvShiftRows(vector<vector<uint8_t>> &matrix) {
    assert(matrix.size() == 4 && matrix[0].size() == 4);
    // Inverse of ShiftRows: cyclically shift rows to the right
    for (size_t r = 1; r < matrix.size(); ++r) {
      rotate(matrix[r].rbegin(), matrix[r].rbegin() + r, matrix[r].rend());
    }
  }

  void InvSubBytes(vector<vector<uint8_t>> &matrix) {
    // Inverse of SubBytes: substitute each byte using inverse S-box
    for (size_t r = 0; r < matrix.size(); ++r) {
      for (size_t c = 0; c < matrix[r].size(); ++c) {
        uint8_t v = matrix[r][c];
        matrix[r][c] = inv_sbox[v];
      }
    }
  }
  void InvMixColumns(vector<vector<uint8_t>> &matrix) {
    // standard AES inverse MixColumns
    assert(matrix.size() == 4 && matrix[0].size() == 4);
    for (int c = 0; c < 4; ++c) {
      uint8_t s0 = matrix[0][c];
      uint8_t s1 = matrix[1][c];
      uint8_t s2 = matrix[2][c];
      uint8_t s3 = matrix[3][c];

      matrix[0][c] = GMul(s0, 14) ^ GMul(s1, 11) ^ GMul(s2, 13) ^ GMul(s3, 9);
      matrix[1][c] = GMul(s0, 9) ^ GMul(s1, 14) ^ GMul(s2, 11) ^ GMul(s3, 13);
      matrix[2][c] = GMul(s0, 13) ^ GMul(s1, 9) ^ GMul(s2, 14) ^ GMul(s3, 11);
      matrix[3][c] = GMul(s0, 11) ^ GMul(s1, 13) ^ GMul(s2, 9) ^ GMul(s3, 14);
    }
  }

  // helper for multiplication in GF(2^8)
  uint8_t GMul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
      if (b & 1)
        p ^= a;
      bool hi_bit_set = (a & 0x80);
      a <<= 1;
      if (hi_bit_set)
        a ^= 0x1b;
      b >>= 1;
    }
    return p;
  }
};
