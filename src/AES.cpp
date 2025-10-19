#include "../include/AES.hpp"
#include <vector>
#include <string>
#include <iostream>

// AES works on 128 bit blocks
// 128 bits = 16 bytes
// 4x4 matrix = 16 positions = 16 bytes
// each byte is a state

void AES::ShiftRows(vector<vector<unsigned char>>& matrix) {
}

void AES::MixColumns(vector<vector<unsigned char>>& matrix) {
}

void AES::AddRoundKey(vector<vector<unsigned char>>& matrix) {
}

// SubBytes - replaces each byte with S-box value
void AES::SubBytes(vector<vector<unsigned char>>& matrix) {
    // Uses the S-box to substitute each byte in the state
}

// Key expansion - generates round keys from main key
void AES::KeyExpansion() {
    // Expands the main key into multiple round keys
}


// takes 16 bytes, returns 16 bytes
vector<uint8_t> AES::encrypt_block(vector<uint8_t> block) {
    // Ensure block is exactly 16 bytes, just for safety
    if(block.size() != 16) {
        throw invalid_argument("Block must be exactly 16 bytes");
    }
    
    // Convert 16 bytes to 4x4 matrix (AES state)
    vector<vector<uint8_t>> matrix(4, vector<uint8_t>(4));
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            matrix[i][j] = block[i + 4*j];
        }
    }
    
    // Apply AES operations
    SubBytes(matrix);
    ShiftRows(matrix);
    MixColumns(matrix);
    AddRoundKey(matrix);
    
    // Convert matrix back to 16 bytes
    vector<uint8_t> result(16);
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            result[i + 4*j] = matrix[i][j];
        }
    }
    
    return result;
}

// string AES::encrypt(string plaintext) {
//     string result = "";
    
//     for(int i = 0; i < plaintext.length(); i += 16) {
//         vector<uint8_t> block(16, 0); // Initialize with zeros (padding)
//         int block_size = min(16, (int)plaintext.length() - i);
        
//         for(int j = 0; j < block_size; j++) {
//             block[j] = (uint8_t)plaintext[i + j];
//         }
        
//         vector<uint8_t> encrypted_block = encrypt_block(block);
        
//         for(uint8_t byte : encrypted_block) {
//             result += (char)byte;
//         }
//     }
    
//     return result;
// }

string AES::decrypt(string ciphertext) {
    return ciphertext; 
}
