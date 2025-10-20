#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <random>
#include <algorithm>
#include <cstdint>
#include <cassert>
#include <iomanip>
#include "../include/AES.hpp"

using namespace std;

// Helper to generate a random 16-byte block
vector<uint8_t> random_block() {
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dis(0, 255);
    vector<uint8_t> block(16);
    for (int i = 0; i < 16; ++i) {
        block[i] = dis(gen);
    }
    return block;
}

// Convert incrementing integer tweak to a 16-byte (little endian; rest zeros)
// Not sure if its like this tho
vector<uint8_t> int_to_tweak(uint64_t tweak) {
    vector<uint8_t> block(16, 0);
    for (int i = 0; i < 8; ++i) block[i] = (tweak >> (i*8)) & 0xFF;
    return block;
}

// Count differing bits (Hamming distance)
int hamming_distance(const vector<uint8_t>& a, const vector<uint8_t>& b) {
    assert(a.size() == b.size());
    int dist = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        dist += __builtin_popcount(a[i] ^ b[i]);
    }
    return dist;
}

int main() {
    // Measurement parameters
    const int NUM_MEASUREMENTS = 100000;  // can increase for finer chart
    const uint64_t MAX_TWEAK = 256; // one chain per experiment; each experiment starts at 0

    // Histogram (Hamming distance -> count)
    map<int, int> histogram;

    // Setup: random block/plaintext and random key (key and tweak sizes per AES-128)
    for (int exp = 0; exp < NUM_MEASUREMENTS; ++exp) {
        vector<uint8_t> plaintext = random_block();
        vector<uint8_t> key      = random_block();
        AES aes(128, 10, key, vector<uint8_t>(16, 0)); // 16-byte tweak (set to 0, will be set below)
        // Encrypt with tweak=0 as first
        vector<uint8_t> last_cipher = aes.encrypt_block(plaintext);
        for (uint64_t t = 1; t < MAX_TWEAK; ++t) {
            // Create tweak
            vector<uint8_t> tweak = int_to_tweak(t);
            // the tweak is the incrementing integer
            // so we need to create a new AES object with the new tweak
            // and encrypt the plaintext with the new tweak
            // and store the cipher in the histogram
            // and update the last cipher to the new cipher
            // and repeat for all the tweaks
            // and then we can plot the histogram
            // and see the distribution of the hamming distances
            // and see the average hamming distance
            aes = AES(128, 10, key, tweak);
            vector<uint8_t> cipher = aes.encrypt_block(plaintext);
            int dist = hamming_distance(cipher, last_cipher);
            histogram[dist] += 1;
            last_cipher = cipher;
        }
    }
    // Output CSV
    cout << "hamming_distance,count\n";
    for (auto& pair : histogram) {
        cout << pair.first << "," << pair.second << "\n";
    }
    return 0;
}
