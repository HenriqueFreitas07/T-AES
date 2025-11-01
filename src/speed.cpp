#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <time.h>
#include "../include/AES.hpp" // include your T-AES implementation
#include "../include/AESNI.hpp" // include your T-AES AES-NI implementation

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

// Get time in nanoseconds using clock_gettime
long get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

// -----------------------------
// Wrappers for T-AES (128-bit)
// -----------------------------
void tAES_128_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+16);
    vector<uint8_t> tweak(key2, key2+16);
    AES aes(128, 10, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_128_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+16);
    vector<uint8_t> tweak(key2, key2+16);
    AES aes(128, 10, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes.decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Wrappers for T-AES (192-bit)
// -----------------------------
void tAES_192_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+24);
    vector<uint8_t> tweak(key2, key2+16);
    AES aes(192, 12, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_192_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+24);
    vector<uint8_t> tweak(key2, key2+16);
    AES aes(192, 12, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes.decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Wrappers for T-AES (256-bit)
// -----------------------------
void tAES_256_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+32);
    vector<uint8_t> tweak(key2, key2+16);
    AES aes(256, 14, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_256_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+32);
    vector<uint8_t> tweak(key2, key2+16);
    AES aes(256, 14, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes.decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Wrappers for T-AES with AES-NI (128-bit)
// -----------------------------
void tAES_NI_128_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+16);
    vector<uint8_t> tweak(key2, key2+16);
    AESNI aes(128, 10, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_NI_128_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+16);
    vector<uint8_t> tweak(key2, key2+16);
    AESNI aes(128, 10, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes.decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Wrappers for T-AES with AES-NI (192-bit)
// -----------------------------
void tAES_NI_192_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+24);
    vector<uint8_t> tweak(key2, key2+16);
    AESNI aes(192, 12, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_NI_192_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+24);
    vector<uint8_t> tweak(key2, key2+16);
    AESNI aes(192, 12, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes.decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Wrappers for T-AES with AES-NI (256-bit)
// -----------------------------
void tAES_NI_256_encrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+32);
    vector<uint8_t> tweak(key2, key2+16);
    AESNI aes(256, 14, key, tweak);
    
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes.encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_NI_256_decrypt(uint8_t* buffer, size_t size, const uint8_t* key1, const uint8_t* key2){
    vector<uint8_t> key(key1, key1+32);
    vector<uint8_t> tweak(key2, key2+16);
    AESNI aes(256, 14, key, tweak);
    
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
               const string& name,
               size_t key_size = 16) 
{
    uint8_t buffer[BUFFER_SIZE];
    vector<long> encrypt_times;
    vector<long> decrypt_times;
    encrypt_times.reserve(ITERATIONS);
    decrypt_times.reserve(ITERATIONS);

    for (int i = 0; i < ITERATIONS; ++i) {
        // Generate new random buffer for each iteration
        generate_random_buffer(buffer, BUFFER_SIZE);

        // Generate new random keys for each iteration (key_size bytes for key1, 16 for tweak)
        uint8_t key1[32]; // Max size for AES-256
        uint8_t key2[16]; // Tweak is always 16 bytes
        generate_random_key(key1, key_size);
        generate_random_key(key2, 16);

        // Encryption timing (excluding key setup - that's done inside the wrapper)
        long start = get_time_ns();
        encrypt(buffer, BUFFER_SIZE, key1, key2);
        long end = get_time_ns();
        long encrypt_time = end - start;
        encrypt_times.push_back(encrypt_time);

        // Decryption timing (excluding key setup - that's done inside the wrapper)
        start = get_time_ns();
        decrypt(buffer, BUFFER_SIZE, key1, key2);
        end = get_time_ns();
        long decrypt_time = end - start;
        decrypt_times.push_back(decrypt_time);
    }

    // Calculate statistics for encryption
    sort(encrypt_times.begin(), encrypt_times.end());
    long min_enc = encrypt_times.front();
    long max_enc = encrypt_times.back();
    double avg_enc = 0;
    for (auto t : encrypt_times) avg_enc += t;
    avg_enc /= ITERATIONS;

    // Calculate statistics for decryption
    sort(decrypt_times.begin(), decrypt_times.end());
    long min_dec = decrypt_times.front();
    long max_dec = decrypt_times.back();
    double avg_dec = 0;
    for (auto t : decrypt_times) avg_dec += t;
    avg_dec /= ITERATIONS;

    // Calculate throughput using minimum time (best performance)
    double encrypt_throughput = (BUFFER_SIZE / (min_enc / 1e9)) / (1024.0 * 1024.0);
    double decrypt_throughput = (BUFFER_SIZE / (min_dec / 1e9)) / (1024.0 * 1024.0);
    
    // Calculate latency (average time)
    double encrypt_latency_us = avg_enc / 1000.0;
    double decrypt_latency_us = avg_dec / 1000.0;

    // Output results
    cout << name << " Encryption:" << endl;
    cout << "  Throughput:      " << fixed << setprecision(2) << encrypt_throughput << " MB/s" << endl;
    cout << "  Latency (avg):   " << fixed << setprecision(2) << encrypt_latency_us << " μs" << endl;
    cout << "  Min time:        " << min_enc << " ns" << endl;
    cout << "  Avg time:        " << (long)avg_enc << " ns" << endl;
    cout << "  Max time:        " << max_enc << " ns" << endl;
    
    cout << name << " Decryption:" << endl;
    cout << "  Throughput:      " << fixed << setprecision(2) << decrypt_throughput << " MB/s" << endl;
    cout << "  Latency (avg):   " << fixed << setprecision(2) << decrypt_latency_us << " μs" << endl;
    cout << "  Min time:        " << min_dec << " ns" << endl;
    cout << "  Avg time:        " << (long)avg_dec << " ns" << endl;
    cout << "  Max time:        " << max_dec << " ns" << endl;

    // Output CSV format
    ofstream csv("benchmark_results.csv", ios::app);
    csv << name << ",Encrypt,Throughput," << encrypt_throughput << endl;
    csv << name << ",Encrypt,Latency," << encrypt_latency_us << endl;
    csv << name << ",Encrypt,Min," << min_enc << endl;
    csv << name << ",Encrypt,Avg," << (long)avg_enc << endl;
    csv << name << ",Encrypt,Max," << max_enc << endl;
    csv << name << ",Decrypt,Throughput," << decrypt_throughput << endl;
    csv << name << ",Decrypt,Latency," << decrypt_latency_us << endl;
    csv << name << ",Decrypt,Min," << min_dec << endl;
    csv << name << ",Decrypt,Avg," << (long)avg_dec << endl;
    csv << name << ",Decrypt,Max," << max_dec << endl;
    csv.close();
}

// -----------------------------
// Main function
// -----------------------------
int main() {
    cout << "=== T-AES Performance Benchmarking ===" << endl;
    cout << "Buffer Size: " << BUFFER_SIZE << " bytes" << endl;
    cout << "Iterations: " << ITERATIONS << endl;
    cout << "Using minimum time from " << ITERATIONS << " runs" << endl << endl;
    
    // -----------------------------
    // Benchmark AES-128
    // -----------------------------
    cout << "========================================" << endl;
    cout << "           AES-128 (10 rounds)          " << endl;
    cout << "========================================" << endl;
    cout << "--- Software Implementation ---" << endl;
    benchmark(tAES_128_encrypt, tAES_128_decrypt, "T-AES-128-Software", 16);
    cout << endl;
    
    cout << "--- Hardware Implementation (AES-NI) ---" << endl;
    benchmark(tAES_NI_128_encrypt, tAES_NI_128_decrypt, "T-AES-128-AESNI", 16);
    cout << endl << endl;
    
    // -----------------------------
    // Benchmark AES-192
    // -----------------------------
    cout << "========================================" << endl;
    cout << "           AES-192 (12 rounds)          " << endl;
    cout << "========================================" << endl;
    cout << "--- Software Implementation ---" << endl;
    benchmark(tAES_192_encrypt, tAES_192_decrypt, "T-AES-192-Software", 24);
    cout << endl;
    
    cout << "--- Hardware Implementation (AES-NI) ---" << endl;
    benchmark(tAES_NI_192_encrypt, tAES_NI_192_decrypt, "T-AES-192-AESNI", 24);
    cout << endl << endl;
    
    // -----------------------------
    // Benchmark AES-256
    // -----------------------------
    cout << "========================================" << endl;
    cout << "           AES-256 (14 rounds)          " << endl;
    cout << "========================================" << endl;
    cout << "--- Software Implementation ---" << endl;
    benchmark(tAES_256_encrypt, tAES_256_decrypt, "T-AES-256-Software", 32);
    cout << endl;
    
    cout << "--- Hardware Implementation (AES-NI) ---" << endl;
    benchmark(tAES_NI_256_encrypt, tAES_NI_256_decrypt, "T-AES-256-AESNI", 32);
    cout << endl << endl;

    // -----------------------------
    // TODO: Add library AES-XTS benchmark
    // Example:
    // benchmark(libXTS_encrypt, libXTS_decrypt, "Library-XTS");
    // -----------------------------
    
    cout << "========================================" << endl;
    cout << "Results also saved to benchmark_results.csv" << endl;

    return 0;
}



// We can tweak iterations for speed and precision 
// We can add optional compilation flags to enable/disable AES-NI