#include "../include/AES.hpp"

#include <iostream>
#include <string>
#include <vector>

// AES works on 128 bit blocks
// 128 bits = 16 bytes
// 4x4 matrix = 16 positions = 16 bytes
// each byte is a state

void AES::ShiftRows(vector<vector<uint8_t>> &matrix) {}

void AES::MixColumns(vector<vector<uint8_t>> &matrix) {}

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
