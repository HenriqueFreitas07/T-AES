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
#include "../include/AES.hpp"
#include "../include/AESNI.hpp"

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

// Generate random key
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
// Wrappers that accept pre-initialized AES objects (key expansion already done)
// -----------------------------
void tAES_encrypt_no_keygen(uint8_t* buffer, size_t size, AES* aes){
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes->encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_decrypt_no_keygen(uint8_t* buffer, size_t size, AES* aes){
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes->decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

void tAES_NI_encrypt_no_keygen(uint8_t* buffer, size_t size, AESNI* aes){
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto enc = aes->encrypt_block(block);
        copy(enc.begin(), enc.end(), buffer+offset);
    }
}

void tAES_NI_decrypt_no_keygen(uint8_t* buffer, size_t size, AESNI* aes){
    for(size_t offset=0; offset<size; offset+=16){
        vector<uint8_t> block(buffer+offset, buffer+offset+16);
        auto dec = aes->decrypt_block(block);
        copy(dec.begin(), dec.end(), buffer+offset);
    }
}

// -----------------------------
// Benchmarking function - key expansion excluded from timing
// -----------------------------
void benchmark_software(const string& name, int key_bits, int rounds, size_t key_size) 
{
    uint8_t buffer[BUFFER_SIZE];
    vector<long> encrypt_times;
    vector<long> decrypt_times;
    encrypt_times.reserve(ITERATIONS);
    decrypt_times.reserve(ITERATIONS);

    for (int i = 0; i < ITERATIONS; ++i) {
        // Generate new random buffer for each iteration
        generate_random_buffer(buffer, BUFFER_SIZE);

        // Generate new random keys for each iteration
        uint8_t key1[32]; // Max size for AES-256
        uint8_t key2[16]; // Tweak is always 16 bytes
        generate_random_key(key1, key_size);
        generate_random_key(key2, 16);

        // KEY EXPANSION (NOT TIMED)
        vector<uint8_t> key(key1, key1+key_size);
        vector<uint8_t> tweak(key2, key2+16);
        AES aes(key_bits, rounds, key, tweak);

        // Encryption timing (ONLY encrypt/decrypt operations, NO key setup)
        long start = get_time_ns();
        tAES_encrypt_no_keygen(buffer, BUFFER_SIZE, &aes);
        long end = get_time_ns();
        encrypt_times.push_back(end - start);

        // Decryption timing (ONLY encrypt/decrypt operations, NO key setup)
        start = get_time_ns();
        tAES_decrypt_no_keygen(buffer, BUFFER_SIZE, &aes);
        end = get_time_ns();
        decrypt_times.push_back(end - start);
    }

    // Calculate statistics
    sort(encrypt_times.begin(), encrypt_times.end());
    long min_enc = encrypt_times.front();
    long max_enc = encrypt_times.back();
    double avg_enc = 0;
    for (auto t : encrypt_times) avg_enc += t;
    avg_enc /= ITERATIONS;

    sort(decrypt_times.begin(), decrypt_times.end());
    long min_dec = decrypt_times.front();
    long max_dec = decrypt_times.back();
    double avg_dec = 0;
    for (auto t : decrypt_times) avg_dec += t;
    avg_dec /= ITERATIONS;

    // Calculate throughput and latency
    double encrypt_throughput = (BUFFER_SIZE / (min_enc / 1e9)) / (1024.0 * 1024.0);
    double decrypt_throughput = (BUFFER_SIZE / (min_dec / 1e9)) / (1024.0 * 1024.0);
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

    // Output CSV
    ofstream csv("benchmark_results_v2.csv", ios::app);
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

void benchmark_hardware(const string& name, int key_bits, int rounds, size_t key_size) 
{
    uint8_t buffer[BUFFER_SIZE];
    vector<long> encrypt_times;
    vector<long> decrypt_times;
    encrypt_times.reserve(ITERATIONS);
    decrypt_times.reserve(ITERATIONS);

    for (int i = 0; i < ITERATIONS; ++i) {
        generate_random_buffer(buffer, BUFFER_SIZE);

        uint8_t key1[32];
        uint8_t key2[16];
        generate_random_key(key1, key_size);
        generate_random_key(key2, 16);

        // KEY EXPANSION (NOT TIMED)
        vector<uint8_t> key(key1, key1+key_size);
        vector<uint8_t> tweak(key2, key2+16);
        AESNI aes(key_bits, rounds, key, tweak);

        // Encryption timing (ONLY encrypt/decrypt operations, NO key setup)
        long start = get_time_ns();
        tAES_NI_encrypt_no_keygen(buffer, BUFFER_SIZE, &aes);
        long end = get_time_ns();
        encrypt_times.push_back(end - start);

        start = get_time_ns();
        tAES_NI_decrypt_no_keygen(buffer, BUFFER_SIZE, &aes);
        end = get_time_ns();
        decrypt_times.push_back(end - start);
    }

    // Calculate statistics
    sort(encrypt_times.begin(), encrypt_times.end());
    long min_enc = encrypt_times.front();
    long max_enc = encrypt_times.back();
    double avg_enc = 0;
    for (auto t : encrypt_times) avg_enc += t;
    avg_enc /= ITERATIONS;

    sort(decrypt_times.begin(), decrypt_times.end());
    long min_dec = decrypt_times.front();
    long max_dec = decrypt_times.back();
    double avg_dec = 0;
    for (auto t : decrypt_times) avg_dec += t;
    avg_dec /= ITERATIONS;

    double encrypt_throughput = (BUFFER_SIZE / (min_enc / 1e9)) / (1024.0 * 1024.0);
    double decrypt_throughput = (BUFFER_SIZE / (min_dec / 1e9)) / (1024.0 * 1024.0);
    double encrypt_latency_us = avg_enc / 1000.0;
    double decrypt_latency_us = avg_dec / 1000.0;

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

    ofstream csv("benchmark_results_v2.csv", ios::app);
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

int main() {
    cout << "=== T-AES Performance Benchmarking (Key Expansion Excluded) ===" << endl;
    cout << "Buffer Size: " << BUFFER_SIZE << " bytes" << endl;
    cout << "Iterations: " << ITERATIONS << endl;
    cout << "NOTE: Key expansion time is NOT included in measurements" << endl << endl;
    
    // AES-128
    cout << "========================================" << endl;
    cout << "           AES-128 (10 rounds)          " << endl;
    cout << "========================================" << endl;
    cout << "--- Software Implementation ---" << endl;
    benchmark_software("T-AES-128-Software", 128, 10, 16);
    cout << endl;
    
    cout << "--- Hardware Implementation (AES-NI) ---" << endl;
    benchmark_hardware("T-AES-128-AESNI", 128, 10, 16);
    cout << endl << endl;
    
    // AES-192
    cout << "========================================" << endl;
    cout << "           AES-192 (12 rounds)          " << endl;
    cout << "========================================" << endl;
    cout << "--- Software Implementation ---" << endl;
    benchmark_software("T-AES-192-Software", 192, 12, 24);
    cout << endl;
    
    cout << "--- Hardware Implementation (AES-NI) ---" << endl;
    benchmark_hardware("T-AES-192-AESNI", 192, 12, 24);
    cout << endl << endl;
    
    // AES-256
    cout << "========================================" << endl;
    cout << "           AES-256 (14 rounds)          " << endl;
    cout << "========================================" << endl;
    cout << "--- Software Implementation ---" << endl;
    benchmark_software("T-AES-256-Software", 256, 14, 32);
    cout << endl;
    
    cout << "--- Hardware Implementation (AES-NI) ---" << endl;
    benchmark_hardware("T-AES-256-AESNI", 256, 14, 32);
    cout << endl << endl;

    cout << "========================================" << endl;
    cout << "Results saved to benchmark_results_v2.csv" << endl;

    return 0;
}
