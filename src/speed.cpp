#include <iostream>
#include <cstdint>
#include <chrono>
#include <climits>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include "../include/AES.hpp" // include your T-AES implementation

using namespace std;

// Number of iterations for benchmarking
const int ITERATIONS = 100000;

// 4 KB buffer
const size_t BUFFER_SIZE = 4096;

// Generate random buffer using /dev/urandom
void generate_random_buffer(uint8_t* buffer, size_t size) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(buffer, 1, size, urandom);
        fclose(urandom);
    } else {
        cerr << "Failed to open /dev/urandom" << endl;
    }
}

// Generate random key (16 bytes)
void generate_random_key(uint8_t* key, size_t size=16) {
    generate_random_buffer(key, size);
}

// -----------------------------
// Wrappers for T-AES encrypt/decrypt in counter mode
// -----------------------------
void tAES_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    AES aes(vector<uint8_t>(key1, key1+16), vector<uint8_t>(key2, key2+16));
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    AES aes(vector<uint8_t>(key1, key1+16), vector<uint8_t>(key2, key2+16));
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes.decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Benchmarking function
// -----------------------------
void benchmark(void (*encrypt)(uint8_t*, size_t, const uint8_t*, const uint8_t*),
               void (*decrypt)(uint8_t*, size_t, const uint8_t*, const uint8_t*),
               const string& name) 
{
    uint8_t buffer[BUFFER_SIZE];
    long min_encrypt_time = LONG_MAX;
    long min_decrypt_time = LONG_MAX;

    for (int i = 0; i < ITERATIONS; ++i) {
        // Generate new random buffer for each iteration
        generate_random_buffer(buffer, BUFFER_SIZE);

        // Generate new random keys for each iteration
        uint8_t key1[16];
        uint8_t key2[16];
        generate_random_key(key1);
        generate_random_key(key2);

        // Encryption timing
        auto start = chrono::high_resolution_clock::now();
        encrypt(buffer, BUFFER_SIZE, key1, key2);
        auto end = chrono::high_resolution_clock::now();
        long encrypt_time = chrono::duration_cast<chrono::nanoseconds>(end - start).count();
        if (encrypt_time < min_encrypt_time) min_encrypt_time = encrypt_time;

        // Decryption timing
        start = chrono::high_resolution_clock::now();
        decrypt(buffer, BUFFER_SIZE, key1, key2);
        end = chrono::high_resolution_clock::now();
        long decrypt_time = chrono::duration_cast<chrono::nanoseconds>(end - start).count();
        if (decrypt_time < min_decrypt_time) min_decrypt_time = decrypt_time;
    }

    // Calculate throughput in MB/s
    double encrypt_throughput = (BUFFER_SIZE / (min_encrypt_time / 1e9)) / (1024.0 * 1024.0);
    double decrypt_throughput = (BUFFER_SIZE / (min_decrypt_time / 1e9)) / (1024.0 * 1024.0);

    // Output results
    cout << name << " Encryption Throughput: " << encrypt_throughput << " MB/s" << endl;
    cout << name << " Decryption Throughput: " << decrypt_throughput << " MB/s" << endl;

    // Optional: output CSV format
    ofstream csv("benchmark_results.csv", ios::app);
    csv << name << ",Encrypt," << encrypt_throughput << endl;
    csv << name << ",Decrypt," << decrypt_throughput << endl;
    csv.close();
}

// -----------------------------
// Main function
// -----------------------------
int main() {
    // -----------------------------
    // Example usage with T-AES
    // -----------------------------
    benchmark(tAES_encrypt, tAES_decrypt, "T-AES");

    // -----------------------------
    // TODO: Add library AES-XTS benchmark
    // Example:
    // benchmark(libXTS_encrypt, libXTS_decrypt, "Library-XTS");
    // -----------------------------

    // -----------------------------
    // TODO: run benchmarks with AES-NI enabled/disabled
    // -----------------------------

    return 0;
}



// We can tweak iterations for speed and precision 
// We can add optional compilation flags to enable/disable AES-NI