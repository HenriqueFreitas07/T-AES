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
    const int NUM_MEASUREMENTS = 10000;  // Large number for statistical significance
    const uint64_t MAX_TWEAK = 256; // tweaks per experiment (0 to 255)

    // Histogram (Hamming distance -> count)
    map<int, int> histogram;

    // Setup: random block/plaintext and random key (key and tweak sizes per AES-128)
    cerr << "Running " << NUM_MEASUREMENTS << " experiments with " << MAX_TWEAK << " tweaks each..." << endl;
    cerr << "Total Hamming distance measurements: " << (NUM_MEASUREMENTS * (MAX_TWEAK - 1)) << endl;
    for (int exp = 0; exp < NUM_MEASUREMENTS; ++exp) {
        if (exp % 500 == 0) {
            double progress = (100.0 * exp) / NUM_MEASUREMENTS;
            cerr << "Progress: " << exp << "/" << NUM_MEASUREMENTS << " (" 
                 << fixed << setprecision(1) << progress << "%)\r" << flush;
        }
        vector<uint8_t> plaintext = random_block();
        vector<uint8_t> key      = random_block();
        
        // Start with tweak=0
        vector<uint8_t> tweak = int_to_tweak(0);
        AES aes(128, 10, key, tweak);
        vector<uint8_t> last_cipher = aes.encrypt_block(plaintext);
        
        // Increment tweak and measure Hamming distance
        for (uint64_t t = 1; t < MAX_TWEAK; ++t) {
            // Create new tweak
            tweak = int_to_tweak(t);
            // Create new AES with new tweak (key expansion happens here, but measurement is only for encryption)
            AES aes_new(128, 10, key, tweak);
            vector<uint8_t> cipher = aes_new.encrypt_block(plaintext);
            
            // Measure Hamming distance from previous cipher
            int dist = hamming_distance(cipher, last_cipher);
            histogram[dist] += 1;
            
            last_cipher = cipher;
        }
    }
    
    cerr << "\nCompleted!" << endl;
    
    // Output CSV
    cout << "hamming_distance,count\n";
    for (auto& pair : histogram) {
        cout << pair.first << "," << pair.second << "\n";
    }
    
    // Calculate statistics
    long long total = 0;
    long long sum_dist = 0;
    for (auto& pair : histogram) {
        total += pair.second;
        sum_dist += (long long)pair.first * pair.second;
    }
    double avg = (double)sum_dist / total;
    
    cerr << "Total measurements: " << total << endl;
    cerr << "Average Hamming distance: " << avg << " bits (out of 128)" << endl;
    cerr << "Expected for random: 64 bits" << endl;
    
    return 0;
}
