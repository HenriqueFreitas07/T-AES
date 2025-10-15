#include "../include/AES.hpp"

// AES works on 128 bit blocks
// 128 bits = 16 bytes
// 4x4 matrix = 16 positions = 16 bytes
// each byte is a state

void AES::ShiftRows() {
}

void AES::MixColumns() {
}

void AES::AddRoundKey() {
}

// SubBytes - replaces each byte with S-box value
void AES::SubBytes() {
    // Uses the S-box to substitute each byte in the state
}

// Key expansion - generates round keys from main key
void AES::KeyExpansion() {
    // Expands the main key into multiple round keys
}


// this is used per block
string AES::encrypt(string plaintext) {
    string result = "";
    
    // process plaintext in 16-byte blocks
    for(int i = 0; i < plaintext.length(); i += 16) {
        // get 16-byte block (or remaining bytes)
        string block = plaintext.substr(i, 16);
        
        // pad if less than 16 bytes
        while(block.length() < 16) {
            block += '\0'; // null padding
        }
        
        // first convert string to bytes
        vector<unsigned char> bytes;
        for(char c : block) {
            bytes.push_back((unsigned char)c);
        }
        
        // second convert bytes to 4x4 matrix (AES state)
        // aes works on a 4x4 matrix
        // state[0] = [byte, byte, byte, byte]  ← Row 0 (4 bytes)
        // state[1][0] Row 1, Column 0 (2nd row, 1st column)

        vector<vector<unsigned char>> matrix(4, vector<unsigned char>(4));
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                matrix[i][j] = bytes[i + 4*j];
            }
        }
        
        // (SubBytes, ShiftRows, MixColumns, AddRoundKey)
        SubBytes(matrix);
        ShiftRows(matrix);
        MixColumns(matrix);
        AddRoundKey(matrix);

        // fourth convert matrix back to string
        string ciphertext_block;
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                ciphertext_block += matrix[i][j];
            }
        }
        result += ciphertext_block;
    }
    
    return result; 
}

string AES::decrypt(string ciphertext) {
    return ciphertext; 
}
