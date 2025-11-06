#pragma once

#include "./utils.hpp"
#include <cassert>
#include <cstdint>
#include <smmintrin.h> // SSE4.1 intrinsics
#include <stdexcept>
#include <vector>
#include <wmmintrin.h> // AES-NI intrinsics

using namespace std;
using namespace utils;

#define cpuid(func, ax, bx, cx, dx)                                            \
  __asm__ __volatile__("cpuid"                                                 \
                       : "=a"(ax), "=b"(bx), "=c"(cx), "=d"(dx)                \
                       : "a"(func));

int Check_CPU_support_AES() {
  unsigned int a, b, c, d;
  cpuid(1, a, b, c, d);
  return (c & 0x2000000);
}

// Suppress GCC's ignored-attributes warning for using __m128i as a template
// argument (it carries vector attributes that std::vector ignores). This is
// harmless, but we silence it to keep builds warning-free.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
#endif
using m128i_vec = vector<__m128i>;
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

class AESNI {
  int key_size;
  int n_rounds;
  vector<uint8_t> key;
  vector<uint8_t> tweak_key;

  // Round keys storage using __m128i for hardware acceleration
  m128i_vec round_keys;

private:
  // Helper function to load 16 bytes into __m128i register
  __m128i load_block(const vector<uint8_t> &block) {
    assert(block.size() == 16);
    return _mm_loadu_si128((__m128i *)block.data());
  }

  // Helper function to store __m128i register into 16 bytes
  void store_block(__m128i data, vector<uint8_t> &block) {
    block.resize(16);
    _mm_storeu_si128((__m128i *)block.data(), data);
  }

  // Arithmetic addition (mod 2^128) of tweak to round key
  __m128i add_tweak(const __m128i &round_key, const __m128i &tweak) {
    // Extract bytes from both operands
    alignas(16) uint8_t rk_bytes[16];
    alignas(16) uint8_t tw_bytes[16];
    alignas(16) uint8_t result_bytes[16];

    _mm_store_si128((__m128i *)rk_bytes, round_key);
    _mm_store_si128((__m128i *)tw_bytes, tweak);

    // Perform 128-bit addition with carry (little-endian: byte 0 is LSB)
    uint16_t carry = 0;
    for (int i = 0; i < 16; ++i) {
      uint16_t sum = static_cast<uint16_t>(rk_bytes[i]) +
                     static_cast<uint16_t>(tw_bytes[i]) + carry;
      result_bytes[i] = static_cast<uint8_t>(sum & 0xFF);
      carry = sum >> 8;
    }

    return _mm_load_si128((__m128i *)result_bytes);
  }

  int get_tweak_round() const {
    // Apply tweak in the middle rounds for better security
    // AES-128: 10 rounds (0-10), apply tweak at round 5
    // AES-192: 12 rounds (0-12), apply tweak at round 6
    // AES-256: 14 rounds (0-14), apply tweak at round 7
    if (key_size == 128)
      return 5;
    else if (key_size == 192)
      return 6;
    else if (key_size == 256)
      return 7;
    else
      throw invalid_argument("Invalid key size for tweak rounds");
  }

  // AES-128 key expansion helper
  __m128i aes_128_key_expansion(__m128i key, __m128i keygenlast) {
    keygenlast = _mm_shuffle_epi32(keygenlast, 0xFF);
    // xor with the previous 4 bytes 4 times and the keygenlast once
    // keygenlast contains the last 4 words generated in the previous round
    // then xor's with the first 4 bytes of the current key to be generated
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygenlast);
  }

  // AES S-box for SubWord operation
  static constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };

  uint32_t SubWord_HW(uint32_t word) {
    uint8_t b0 = sbox[(word >> 24) & 0xFF];
    uint8_t b1 = sbox[(word >> 16) & 0xFF];
    uint8_t b2 = sbox[(word >> 8) & 0xFF];
    uint8_t b3 = sbox[word & 0xFF];
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  }

  uint32_t RotWord_HW(uint32_t word) {
    return (word << 8) | (word >> 24);
  }
  void aes_128_key_expansion_schedule(const vector<uint8_t> &key_bytes) {
    assert(key_bytes.size() == 16);
    round_keys.clear();
    round_keys.reserve(11);

    __m128i temp = _mm_loadu_si128((__m128i *)key_bytes.data());
    round_keys.push_back(temp);

    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x01));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x02));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x04));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x08));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x10));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x20));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x40));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x80));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x1B));
    round_keys.push_back(temp);
    temp = aes_128_key_expansion(temp, _mm_aeskeygenassist_si128(temp, 0x36));
    round_keys.push_back(temp);
  }

  // AES-192 key expansion schedule - word-based approach (mirrors software implementation)
  void aes_192_key_expansion_schedule(const vector<uint8_t> &key_bytes) {
    assert(key_bytes.size() == 24);
    round_keys.clear();
    round_keys.reserve(13);

    const int Nk = 6;  // 6 words for 192-bit key
    const int total_words = 52;  // 13 rounds × 4 words

    // Work with 32-bit words
    uint32_t words[52];

    // Initialize first 6 words from the 24-byte key
    for (int i = 0; i < 6; i++) {
      words[i] = (static_cast<uint32_t>(key_bytes[i * 4]) << 24) |
                 (static_cast<uint32_t>(key_bytes[i * 4 + 1]) << 16) |
                 (static_cast<uint32_t>(key_bytes[i * 4 + 2]) << 8) |
                 static_cast<uint32_t>(key_bytes[i * 4 + 3]);
    }

    // Rcon values for AES-192 (need 8: 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
    uint32_t rcon[] = {0x01000000, 0x02000000, 0x04000000, 0x08000000,
                       0x10000000, 0x20000000, 0x40000000, 0x80000000};

    // Generate remaining 46 words
    for (int i = 6; i < total_words; i++) {
      uint32_t temp = words[i - 1];

      if (i % Nk == 0) {
        // Every 6th word: apply RotWord, SubWord, and XOR with Rcon
        temp = SubWord_HW(RotWord_HW(temp)) ^ rcon[(i / Nk) - 1];
      }

      words[i] = words[i - Nk] ^ temp;
    }

    // Pack words into 13 round keys (each round key = 4 words = 16 bytes)
    for (int r = 0; r < 13; r++) {
      alignas(16) uint8_t round_key_bytes[16];
      for (int w = 0; w < 4; w++) {
        uint32_t word = words[r * 4 + w];
        round_key_bytes[w * 4] = (word >> 24) & 0xFF;
        round_key_bytes[w * 4 + 1] = (word >> 16) & 0xFF;
        round_key_bytes[w * 4 + 2] = (word >> 8) & 0xFF;
        round_key_bytes[w * 4 + 3] = word & 0xFF;
      }
      round_keys.push_back(_mm_load_si128((__m128i *)round_key_bytes));
    }
  }

  // AES-256 key expansion helpers
  void aes_256_assist_1(__m128i *temp1, __m128i *temp2) {
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

  void aes_256_assist_2(__m128i *temp1, __m128i *temp3) {
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
  }

  void aes_256_key_expansion_schedule(const vector<uint8_t> &key_bytes) {
    assert(key_bytes.size() == 32);
    round_keys.clear();
    round_keys.reserve(15);

    __m128i temp1 = _mm_loadu_si128((__m128i *)key_bytes.data());
    __m128i temp2;
    __m128i temp3 = _mm_loadu_si128((__m128i *)(key_bytes.data() + 16));

    round_keys.push_back(temp1);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
    aes_256_assist_2(&temp1, &temp3);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
    aes_256_assist_2(&temp1, &temp3);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
    aes_256_assist_2(&temp1, &temp3);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
    aes_256_assist_2(&temp1, &temp3);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
    aes_256_assist_2(&temp1, &temp3);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
    aes_256_assist_2(&temp1, &temp3);
    round_keys.push_back(temp3);

    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    aes_256_assist_1(&temp1, &temp2);
    round_keys.push_back(temp1);
  }

  void KeyExpansion(const vector<uint8_t> &key_bytes) {
    if (key_size == 128) {
      aes_128_key_expansion_schedule(key_bytes);
    } else if (key_size == 192) {
      aes_192_key_expansion_schedule(key_bytes);
    } else if (key_size == 256) {
      aes_256_key_expansion_schedule(key_bytes);
    } else {
      throw invalid_argument("Invalid key size. Must be 128, 192, or 256 bits");
    }
  }

public:
  AESNI(int size, int rounds, vector<uint8_t> key_vec,
        vector<uint8_t> tweak_key_vec)
      : key_size(size), n_rounds(rounds), key(key_vec),
        tweak_key(tweak_key_vec) {

    // Verify CPU support for AES-NI
    if (!Check_CPU_support_AES()) {
      throw runtime_error("CPU does not support AES-NI instructions");
    }

    // Perform key expansion
    KeyExpansion(key);
  }

  /// @brief Encrypts a single 16-byte block using AES-NI hardware acceleration
  /// @param block vector<uint8_t> of exactly 16 bytes
  /// @return Returns the encrypted block
  vector<uint8_t> encrypt_block(vector<uint8_t> block) {
    if (block.size() != 16) {
      throw invalid_argument("Block must be exactly 16 bytes");
    }

    // Load block into __m128i register
    __m128i state = load_block(block);

    // Load tweak if present (initialize to zero to avoid uninitialized warnings)
    __m128i tweak = _mm_setzero_si128();
    bool has_tweak = !tweak_key.empty();
    int tweak_round = 0;
    if (has_tweak) {
      tweak = load_block(tweak_key);
      tweak_round = get_tweak_round();
    }

    // Initial round - add round key
    state = _mm_xor_si128(state, round_keys[0]);

    // Main rounds (n_rounds - 1 rounds with full transformations)
    for (int round = 1; round < n_rounds; ++round) {
      // Check if we need to apply tweak at this round
      if (has_tweak && round == tweak_round) {
        __m128i tweaked_key = add_tweak(round_keys[round], tweak);
        state = _mm_aesenc_si128(state, tweaked_key);
      } else {
        state = _mm_aesenc_si128(state, round_keys[round]);
      }
    }

    // Final round (no MixColumns)
    state = _mm_aesenclast_si128(state, round_keys[n_rounds]);

    // Store result back to vector
    vector<uint8_t> result;
    store_block(state, result);
    return result;
  }

  /// @brief Decrypts a single 16-byte block using AES-NI hardware acceleration
  /// @param block vector<uint8_t> of exactly 16 bytes
  /// @return Returns the decrypted block
  vector<uint8_t> decrypt_block(vector<uint8_t> block) {
    if (block.size() != 16) {
      throw invalid_argument("Block must be exactly 16 bytes");
    }

    // Load block into __m128i register
    __m128i state = load_block(block);

    // Load tweak if present (initialize to zero to avoid uninitialized warnings)
    __m128i tweak = _mm_setzero_si128();
    bool has_tweak = !tweak_key.empty();
    int tweak_round = 0;
    if (has_tweak) {
      tweak = load_block(tweak_key);
      tweak_round = get_tweak_round();
    }

    // For decryption, we need to use the inverse mix columns transformation
    // on all round keys except the first and last
  m128i_vec dec_round_keys = round_keys;
    for (int i = 1; i < n_rounds; ++i) {
      dec_round_keys[i] = _mm_aesimc_si128(round_keys[i]);
    }

    // Initial round - add last round key
    state = _mm_xor_si128(state, round_keys[n_rounds]);

    // Main rounds (n_rounds - 1 rounds with full transformations)
    for (int round = n_rounds - 1; round >= 1; --round) {
      // Check if we need to apply tweak at this round
      if (has_tweak && round == tweak_round) {
        // Apply InvMixColumns to (round_key + tweak) combination
        // Not to round_key and tweak separately!
        __m128i tweaked_key = add_tweak(round_keys[round], tweak);
        tweaked_key = _mm_aesimc_si128(tweaked_key);
        state = _mm_aesdec_si128(state, tweaked_key);
      } else {
        state = _mm_aesdec_si128(state, dec_round_keys[round]);
      }
    }

    // Final round (no InvMixColumns)
    state = _mm_aesdeclast_si128(state, round_keys[0]);

    // Store result back to vector
    vector<uint8_t> result;
    store_block(state, result);
    return result;
  }
};
