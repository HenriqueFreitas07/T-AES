#pragma once

#include "utils.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <wmmintrin.h>  // AES-NI intrinsics
#include <smmintrin.h>  // SSE4.1 intrinsics

using namespace std;
using namespace utils;

#define cpuid(func, ax, bx, cx, dx)                                            \
    __asm__ __volatile__("cpuid" : "=a"(ax), "=b"(bx), "=c"(cx), "=d"(dx) : "a"(func));

int Check_CPU_support_AES()
{
    unsigned int a, b, c, d;
    cpuid(1, a, b, c, d);
    return (c & 0x2000000);
}

class AESNI
{
    int key_size;
    int n_rounds;
    vector<uint8_t> key;
    vector<uint8_t> tweak_key;

    // Round keys storage using __m128i for hardware acceleration
    vector<__m128i> round_keys;

private:
    // Helper function to load 16 bytes into __m128i register
    __m128i load_block(const vector<uint8_t>& block) {
        assert(block.size() == 16);
        return _mm_loadu_si128((__m128i*)block.data());
    }

    // Helper function to store __m128i register into 16 bytes
    void store_block(__m128i data, vector<uint8_t>& block) {
        block.resize(16);
        _mm_storeu_si128((__m128i*)block.data(), data);
    }

    // XOR the round key with the tweak
    __m128i xor_tweak(const __m128i& round_key, const __m128i& tweak) {
        return _mm_xor_si128(round_key, tweak);
    }

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

    void aes_128_key_expansion_schedule(const vector<uint8_t>& key_bytes) {
        assert(key_bytes.size() == 16);
        round_keys.clear();
        round_keys.reserve(11);

        __m128i temp = _mm_loadu_si128((__m128i*)key_bytes.data());
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

    // AES-192 key expansion helpers
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

    void aes_192_key_expansion_schedule(const vector<uint8_t>& key_bytes) {
        assert(key_bytes.size() == 24);
        round_keys.clear();
        round_keys.reserve(13);

        __m128i temp1 = _mm_loadu_si128((__m128i*)key_bytes.data());
        __m128i temp2 = _mm_loadu_si128((__m128i*)(key_bytes.data() + 8));
        __m128i temp3 = _mm_setzero_si128();
        __m128i temp4;

        round_keys.push_back(temp1);

        temp4 = temp2;
        temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp3), _mm_castsi128_ps(temp2), 0x44));
        round_keys.push_back(temp3);

        temp2 = _mm_aeskeygenassist_si128(temp4, 0x1);
        aes_192_assist(&temp1, &temp2, &temp4);
        round_keys.push_back(temp1);
        temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp3), _mm_castsi128_ps(temp1), 0x4e));
        round_keys.push_back(temp3);

        temp2 = _mm_aeskeygenassist_si128(temp4, 0x2);
        aes_192_assist(&temp1, &temp2, &temp4);
        round_keys.push_back(temp1);
        temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp3), _mm_castsi128_ps(temp1), 0x4e));
        round_keys.push_back(temp3);

        temp2 = _mm_aeskeygenassist_si128(temp4, 0x4);
        aes_192_assist(&temp1, &temp2, &temp4);
        round_keys.push_back(temp1);
        temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp3), _mm_castsi128_ps(temp1), 0x4e));
        round_keys.push_back(temp3);

        temp2 = _mm_aeskeygenassist_si128(temp4, 0x8);
        aes_192_assist(&temp1, &temp2, &temp4);
        round_keys.push_back(temp1);
        temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp3), _mm_castsi128_ps(temp1), 0x4e));
        round_keys.push_back(temp3);

        temp2 = _mm_aeskeygenassist_si128(temp4, 0x10);
        aes_192_assist(&temp1, &temp2, &temp4);
        round_keys.push_back(temp1);
        temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp3), _mm_castsi128_ps(temp1), 0x4e));
        round_keys.push_back(temp3);

        temp2 = _mm_aeskeygenassist_si128(temp4, 0x20);
        aes_192_assist(&temp1, &temp2, &temp4);
        round_keys.push_back(temp1);
    }

    // AES-256 key expansion helpers
    void aes_256_assist_1(__m128i* temp1, __m128i* temp2) {
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

    void aes_256_assist_2(__m128i* temp1, __m128i* temp3) {
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

    void aes_256_key_expansion_schedule(const vector<uint8_t>& key_bytes) {
        assert(key_bytes.size() == 32);
        round_keys.clear();
        round_keys.reserve(15);

        __m128i temp1 = _mm_loadu_si128((__m128i*)key_bytes.data());
        __m128i temp2;
        __m128i temp3 = _mm_loadu_si128((__m128i*)(key_bytes.data() + 16));

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

    void KeyExpansion(const vector<uint8_t>& key_bytes) {
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
    AESNI(int size, int rounds, vector<uint8_t> key_vec, vector<uint8_t> tweak_key_vec)
        : key_size(size), n_rounds(rounds), key(key_vec), tweak_key(tweak_key_vec) {

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

        // Load tweak if present
        __m128i tweak;
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
                __m128i tweaked_key = xor_tweak(round_keys[round], tweak);
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

        // Load tweak if present
        __m128i tweak;
        bool has_tweak = !tweak_key.empty();
        int tweak_round = 0;
        if (has_tweak) {
            tweak = load_block(tweak_key);
            tweak_round = get_tweak_round();
        }

        // For decryption, we need to use the inverse mix columns transformation
        // on all round keys except the first and last
        vector<__m128i> dec_round_keys = round_keys;
        for (int i = 1; i < n_rounds; ++i) {
            dec_round_keys[i] = _mm_aesimc_si128(round_keys[i]);
        }

        // Initial round - add last round key
        state = _mm_xor_si128(state, round_keys[n_rounds]);

        // Main rounds (n_rounds - 1 rounds with full transformations)
        for (int round = n_rounds - 1; round >= 1; --round) {
            // Check if we need to apply tweak at this round
            if (has_tweak && round == tweak_round) {
                // Apply InvMixColumns to (round_key XOR tweak) combination
                // Not to round_key and tweak separately!
                __m128i tweaked_key = xor_tweak(round_keys[round], tweak);
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
