#include "../include/AES.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

// AES works on 128 bit blocks
// 128 bits = 16 bytes
// 4x4 matrix = 16 positions = 16 bytes
// each byte is a state

void AES::ShiftRows(vector<vector<uint8_t>> &matrix) {

  assert(matrix.size() == 4 && matrix[0].size() == 4);
  // The objective of ShiftRows is to cyclically shift the rows of the state
  // matrix So that each byte is moved to a different position Row 0 is not
  // shifted Row 1 is shifted left by 1 Row 2 is shifted left by 2 Row 3 is
  // shifted left by 3
  for (size_t r = 1; r < matrix.size(); ++r) {
    rotate(matrix[r].begin(), matrix[r].begin() + r,
           matrix[r].end()); // can use rotate instead
  }
}

// #####################################################################################

// fast operation that multiplies a byte by 2 in GF(2^8)
static inline uint8_t xtime(uint8_t x) {
  return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

// #####################################################################################

void AES::MixColumns(vector<vector<uint8_t>> &matrix) {
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

void AES::AddRoundKey(vector<vector<uint8_t>> &matrix, const vector<uint8_t> &round_key) {
  assert(matrix.size() == 4 && matrix[0].size() == 4);
  assert(round_key.size() == 16);

  for (size_t r = 0; r < matrix.size(); ++r) {
    for (size_t c = 0; c < matrix[r].size(); ++c) {
      matrix[r][c] ^= round_key[r + 4 * c];
    }
  }
}

void AES::SubBytes(vector<vector<uint8_t>> &matrix) {
  // here im basically traversing the matrix and substituting each byte using
  // the sbox
  for (size_t r = 0; r < matrix.size(); ++r) {
    for (size_t c = 0; c < matrix[r].size(); ++c) {
      uint8_t v = matrix[r][c];
      matrix[r][c] = AES::sbox[v];
    }
  }
}
//
// AES-128 has 10 rounds of transformation on each 16-byte block.
// Each round uses a different 16-byte round key derived from the original key.
// This makes the encryption much more secure because the data is mixed and transformed differently in every round.

void AES::KeyExpansion(const vector<uint8_t> &key) {
    // 1. Initialize the round keys vector with the original key as round 0 key
    // AES-128 requires 11 round keys (0..10)
    assert(key.size() == 16); // make sure original key is 16 bytes
    round_keys.clear();
    round_keys.push_back(key); // round_keys[0] = original key

    // 2. Rcon table: round constants used in key expansion
    // Rcon means "Round Constant"
    // Only the first byte of the transformed word is XORed with Rcon
    const uint8_t Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

    // 3. Generate remaining 10 round keys
    for (int round = 1; round <= 10; ++round) {
        vector<uint8_t> prev_key = round_keys[round - 1]; // previous round key
        vector<uint8_t> new_key(16); // placeholder for new round key

        // ---- Step A: take last 4 bytes of previous key ----
        uint8_t temp[4];
        temp[0] = prev_key[12];
        temp[1] = prev_key[13];
        temp[2] = prev_key[14];
        temp[3] = prev_key[15];

        // ---- Step B: rotate left by 1 (RotWord) ----
        uint8_t t0 = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t0;

        // ---- Step C: substitute each byte using S-box (SubWord) ----
        for (int i = 0; i < 4; ++i) {
            temp[i] = AES::sbox[temp[i]];
        }

        // ---- Step D: XOR first byte with round constant ----
        temp[0] ^= Rcon[round - 1];

        // ---- Step E: generate new key ----
        // first 4 bytes: XOR transformed word with first 4 bytes of previous key
        for (int i = 0; i < 4; ++i) {
            new_key[i] = prev_key[i] ^ temp[i];
        }

        // remaining bytes: each 4-byte block is XORed with corresponding block of previous key
        for (int i = 4; i < 16; ++i) {
            new_key[i] = prev_key[i] ^ new_key[i - 4];
        }

        // ---- Step F: store the new round key ----
        round_keys.push_back(new_key);
    }

    // At the end, round_keys[0..10] are all ready for use in encryption
}


/// @brief Gets the raw block
/// @param block vector<uint8_t>
/// @return Returns the encrypted block after trasnformations 
vector<uint8_t> AES::encrypt_block(vector<uint8_t> block) {
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

  AddRoundKey(matrix, round_keys[0]);        // initial round key
  for (int round = 1; round <= 9; ++round) {
      SubBytes(matrix);
      ShiftRows(matrix);
      MixColumns(matrix);
      AddRoundKey(matrix, round_keys[round]);
  }
  // final round (no MixColumns)
  SubBytes(matrix);
  ShiftRows(matrix);
  AddRoundKey(matrix, round_keys[10]);

  // Convert matrix back to 16 bytes
  vector<uint8_t> result(16);
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      result[i + 4 * j] = matrix[i][j];
    }
  }

  return result;
}


// make GF(2^8) multiplication function
// GMUL or XTIME
// mul tables
// Or precomputed tables for multiplication by 2,3,9,11,13,14
