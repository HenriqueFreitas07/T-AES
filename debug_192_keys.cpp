#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <wmmintrin.h>
#include <smmintrin.h>

using namespace std;

// Print __m128i in hex
void print_m128i(const char* label, __m128i val) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i*)bytes, val);
    cout << label << ": ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0') << (int)bytes[i] << " ";
    }
    cout << dec << endl;
}

// Print byte vector
void print_vec(const char* label, const vector<uint8_t>& vec) {
    cout << label << ": ";
    for (size_t i = 0; i < vec.size(); i++) {
        cout << hex << setw(2) << setfill('0') << (int)vec[i] << " ";
    }
    cout << dec << endl;
}

// Software key expansion for AES-192
vector<vector<uint8_t>> software_key_expansion_192(const vector<uint8_t>& key) {
    const uint8_t sbox[256] = {
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
        0xb0, 0x54, 0xbb, 0x16
    };
    
    const uint8_t Rcon[15] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                              0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};
    
    int Nk = 6;  // 192-bit = 6 words
    int Nr = 12; // 12 rounds
    int total_words = 4 * (Nr + 1); // 52 words
    
    vector<vector<uint8_t>> words(total_words, vector<uint8_t>(4));
    
    // First Nk words from key
    for (int i = 0; i < Nk; i++) {
        words[i][0] = key[4 * i];
        words[i][1] = key[4 * i + 1];
        words[i][2] = key[4 * i + 2];
        words[i][3] = key[4 * i + 3];
    }
    
    // Generate remaining words
    for (int i = Nk; i < total_words; i++) {
        vector<uint8_t> temp = words[i - 1];
        
        if (i % Nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            // XOR with Rcon
            temp[0] ^= Rcon[i / Nk];
        }
        
        words[i][0] = words[i - Nk][0] ^ temp[0];
        words[i][1] = words[i - Nk][1] ^ temp[1];
        words[i][2] = words[i - Nk][2] ^ temp[2];
        words[i][3] = words[i - Nk][3] ^ temp[3];
    }
    
    // Convert to round keys
    vector<vector<uint8_t>> round_keys;
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
    
    return round_keys;
}

// Hardware key expansion (current AESNI implementation)
void aes_192_assist(__m128i* temp1, __m128i* temp2, __m128i* temp3) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0x55);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, *temp2);
}

vector<__m128i> hardware_key_expansion_192(const vector<uint8_t>& key_bytes) {
    vector<__m128i> round_keys;
    round_keys.reserve(13);
    
    __m128i temp1, temp2, temp3;
    
    temp1 = _mm_loadu_si128((__m128i*)key_bytes.data());
    temp3 = _mm_loadu_si128((__m128i*)(key_bytes.data() + 8));
    
    round_keys.push_back(temp1);
    round_keys.push_back(_mm_castps_si128(_mm_shuffle_ps(
        _mm_castsi128_ps(temp3), 
        _mm_castsi128_ps(temp1), 
        0x4e
    )));
    
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
    aes_192_assist(&temp1, &temp2, &temp3);
    round_keys.push_back(_mm_castps_si128(_mm_shuffle_ps(
        _mm_castsi128_ps(temp1), 
        _mm_castsi128_ps(temp3), 
        0x4e
    )));
    round_keys.push_back(temp3);
    
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
    aes_192_assist(&temp1, &temp2, &temp3);
    round_keys.push_back(temp1);
    round_keys.push_back(_mm_castps_si128(_mm_shuffle_ps(
        _mm_castsi128_ps(temp3), 
        _mm_castsi128_ps(temp1), 
        0x4e
    )));
    
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
    aes_192_assist(&temp1, &temp2, &temp3);
    round_keys.push_back(_mm_castps_si128(_mm_shuffle_ps(
        _mm_castsi128_ps(temp1), 
        _mm_castsi128_ps(temp3), 
        0x4e
    )));
    round_keys.push_back(temp3);
    
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
    aes_192_assist(&temp1, &temp2, &temp3);
    round_keys.push_back(temp1);
    round_keys.push_back(_mm_castps_si128(_mm_shuffle_ps(
        _mm_castsi128_ps(temp3), 
        _mm_castsi128_ps(temp1), 
        0x4e
    )));
    
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
    aes_192_assist(&temp1, &temp2, &temp3);
    round_keys.push_back(_mm_castps_si128(_mm_shuffle_ps(
        _mm_castsi128_ps(temp1), 
        _mm_castsi128_ps(temp3), 
        0x4e
    )));
    round_keys.push_back(temp3);
    
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
    aes_192_assist(&temp1, &temp2, &temp3);
    round_keys.push_back(temp1);
    
    return round_keys;
}

// Software key expansion for AES-128
vector<vector<uint8_t>> software_key_expansion_128(const vector<uint8_t>& key) {
    const uint8_t sbox[256] = {
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
        0xb0, 0x54, 0xbb, 0x16
    };
    
    const uint8_t Rcon[15] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                              0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};
    
    int Nk = 4;  // 128-bit = 4 words
    int Nr = 10; // 10 rounds
    int total_words = 4 * (Nr + 1); // 44 words
    
    vector<vector<uint8_t>> words(total_words, vector<uint8_t>(4));
    
    // First Nk words from key
    for (int i = 0; i < Nk; i++) {
        words[i][0] = key[4 * i];
        words[i][1] = key[4 * i + 1];
        words[i][2] = key[4 * i + 2];
        words[i][3] = key[4 * i + 3];
    }
    
    // Generate remaining words
    for (int i = Nk; i < total_words; i++) {
        vector<uint8_t> temp = words[i - 1];
        
        if (i % Nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            // XOR with Rcon
            temp[0] ^= Rcon[i / Nk];
        }
        
        words[i][0] = words[i - Nk][0] ^ temp[0];
        words[i][1] = words[i - Nk][1] ^ temp[1];
        words[i][2] = words[i - Nk][2] ^ temp[2];
        words[i][3] = words[i - Nk][3] ^ temp[3];
    }
    
    // Convert to round keys
    vector<vector<uint8_t>> round_keys;
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
    
    return round_keys;
}

// Hardware AES-128 key expansion
void aes_128_assist(__m128i* temp1, __m128i* temp2) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

vector<__m128i> hardware_key_expansion_128(const vector<uint8_t>& key_bytes) {
    vector<__m128i> round_keys;
    round_keys.reserve(11);
    
    __m128i temp1 = _mm_loadu_si128((__m128i*)key_bytes.data());
    __m128i temp2;
    
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    aes_128_assist(&temp1, &temp2);
    round_keys.push_back(temp1);
    
    return round_keys;
}

int main() {
    // Test AES-128
    vector<uint8_t> key128 = {
        0x91, 0x6e, 0x88, 0x7e, 0xde, 0x30, 0xab, 0x89,
        0xf7, 0x1b, 0x3c, 0x4e, 0x10, 0x46, 0x15, 0xd2
    };
    
    cout << "=== Testing AES-128 Key Expansion ===" << endl;
    print_vec("Input Key (16 bytes)", key128);
    cout << endl;
    
    auto sw_keys_128 = software_key_expansion_128(key128);
    auto hw_keys_128 = hardware_key_expansion_128(key128);
    
    cout << "Software Round Keys:" << endl;
    for (size_t i = 0; i < sw_keys_128.size(); i++) {
        char label[32];
        snprintf(label, sizeof(label), "Round %2zu", i);
        print_vec(label, sw_keys_128[i]);
    }
    cout << endl;
    
    cout << "Hardware Round Keys:" << endl;
    for (size_t i = 0; i < hw_keys_128.size(); i++) {
        char label[32];
        snprintf(label, sizeof(label), "Round %2zu", i);
        print_m128i(label, hw_keys_128[i]);
    }
    cout << endl;
    
    cout << "AES-128 Comparison:" << endl;
    bool all_match_128 = true;
    for (size_t i = 0; i < sw_keys_128.size(); i++) {
        uint8_t hw_bytes[16];
        _mm_storeu_si128((__m128i*)hw_bytes, hw_keys_128[i]);
        bool match = true;
        for (int j = 0; j < 16; j++) {
            if (sw_keys_128[i][j] != hw_bytes[j]) {
                match = false;
                all_match_128 = false;
                break;
            }
        }
        if (!match) {
            cout << "Round " << i << ": MISMATCH" << endl;
        }
    }
    if (all_match_128) {
        cout << "✓ All AES-128 round keys match!" << endl;
    }
    cout << endl << endl;
    
    // Test AES-192
    vector<uint8_t> key192 = {
        0x91, 0x6e, 0x88, 0x7e, 0xde, 0x30, 0xab, 0x89,
        0xf7, 0x1b, 0x3c, 0x4e, 0x10, 0x46, 0x15, 0xd2,
        0x4d, 0xa0, 0x8d, 0xfe, 0xf2, 0xde, 0x14, 0x64
    };
    
    cout << "=== Testing AES-192 Key Expansion ===" << endl;
    print_vec("Input Key (24 bytes)", key192);
    cout << endl;
    
    // Get software-generated keys
    auto sw_keys = software_key_expansion_192(key192);
    
    cout << "Software Round Keys:" << endl;
    for (size_t i = 0; i < sw_keys.size(); i++) {
        char label[32];
        snprintf(label, sizeof(label), "Round %2zu", i);
        print_vec(label, sw_keys[i]);
    }
    cout << endl;
    
    // Get hardware-generated keys
    auto hw_keys = hardware_key_expansion_192(key192);
    
    cout << "Hardware Round Keys:" << endl;
    for (size_t i = 0; i < hw_keys.size(); i++) {
        char label[32];
        snprintf(label, sizeof(label), "Round %2zu", i);
        print_m128i(label, hw_keys[i]);
    }
    cout << endl;
    
    // Compare
    cout << "Comparison:" << endl;
    bool all_match = true;
    for (size_t i = 0; i < sw_keys.size(); i++) {
        uint8_t hw_bytes[16];
        _mm_storeu_si128((__m128i*)hw_bytes, hw_keys[i]);
        bool match = true;
        for (int j = 0; j < 16; j++) {
            if (sw_keys[i][j] != hw_bytes[j]) {
                match = false;
                all_match = false;
                break;
            }
        }
        if (!match) {
            cout << "Round " << i << ": MISMATCH" << endl;
        }
    }
    
    if (all_match) {
        cout << "All round keys match!" << endl;
    } else {
        cout << "Some round keys don't match!" << endl;
    }
    
    return 0;
}
