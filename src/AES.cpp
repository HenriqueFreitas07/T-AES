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
    // vector<uint8_t> temp = matrix[r]; // copy of the current row
    // size_t shift = r; // number of positions to shift
    // for (size_t c = 0; c < matrix[r].size(); ++c) {
    //     matrix[r][c] = temp[(c + shift) % matrix[r].size()];
    // }
    rotate(matrix[r].begin(), matrix[r].begin() + r,
           matrix[r].end()); // can use rotate instead
  }
}

// #####################################################################################

// Galois Field (2^8) multiplication
// support function for MixColumns
// multiplies two bytes in GF(2^8)
// static inline uint8_t gmul(uint8_t a, uint8_t b) {
//   uint8_t p = 0; // product
//   for (int counter = 0; counter < 8; counter++) {
//     if (b & 1) {
//       p ^= a;
//     }
//     bool hi_bit_set = (a & 0x80);
//     a <<= 1;
//     if (hi_bit_set) {
//       a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
//     }
//     b >>= 1;
//   }
//   return p;
// }

// fast opreation that multiplies a byte by 2 in GF(2^8)
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

void AES::AddRoundKey(vector<vector<uint8_t>> &matrix) {}

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

// Key expansion - generates round keys from main key
void AES::KeyExpansion() {
  // Expands the main key into multiple round keys
}

// takes 16 bytes, returns 16 bytes
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

  // Apply AES operations
  SubBytes(matrix);
  ShiftRows(matrix);
  MixColumns(matrix);
  AddRoundKey(matrix);

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
