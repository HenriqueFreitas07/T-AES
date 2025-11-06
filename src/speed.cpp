// Speed benchmark comparing T-AES vs OpenSSL XTS
// Measurements exclude key setup as per assignment requirements

#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <limits>
#include <time.h>
#include <random>
#include <algorithm>
#include <openssl/evp.h>
#include "../include/AES.hpp"
#include "../include/AESNI.hpp"
#include "../include/utils.hpp"

using namespace std;

constexpr size_t BUFFER_SIZE = 4096;  // 4KB buffer (one memory page)
constexpr int ITERATIONS = 100000;     // At least 100k measurements per spec

// Generate random data from /dev/urandom
void generate_random_buffer(uint8_t* buffer, size_t size) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t read = fread(buffer, 1, size, urandom);
        fclose(urandom);
        if (read < size) {
            std::random_device rd;
            for (size_t i = read; i < size; ++i) buffer[i] = static_cast<uint8_t>(rd());
        }
    }
}

void generate_random_key(uint8_t* key, size_t size) {
    generate_random_buffer(key, size);
}

// High-precision timing using clock_gettime (nanosecond precision)
uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// ============= T-AES Software Wrappers (key setup excluded from timing) =============
void tAES_SW_encrypt_no_keygen(uint8_t* buffer, size_t size, AES* aes) {
    for (size_t i = 0; i < size; i += 16) {
        vector<uint8_t> block(buffer + i, buffer + i + 16);
        vector<uint8_t> encrypted = aes->encrypt_block(block);
        memcpy(buffer + i, encrypted.data(), 16);
    }
}

void tAES_SW_decrypt_no_keygen(uint8_t* buffer, size_t size, AES* aes) {
    for (size_t i = 0; i < size; i += 16) {
        vector<uint8_t> block(buffer + i, buffer + i + 16);
        vector<uint8_t> decrypted = aes->decrypt_block(block);
        memcpy(buffer + i, decrypted.data(), 16);
    }
}

// ============= T-AES AES-NI Wrappers (key setup excluded from timing) =============
void tAES_NI_encrypt_no_keygen(uint8_t* buffer, size_t size, AESNI* aes_ni) {
    for (size_t i = 0; i < size; i += 16) {
        vector<uint8_t> block(buffer + i, buffer + i + 16);
        vector<uint8_t> encrypted = aes_ni->encrypt_block(block);
        memcpy(buffer + i, encrypted.data(), 16);
    }
}

void tAES_NI_decrypt_no_keygen(uint8_t* buffer, size_t size, AESNI* aes_ni) {
    for (size_t i = 0; i < size; i += 16) {
        vector<uint8_t> block(buffer + i, buffer + i + 16);
        vector<uint8_t> decrypted = aes_ni->decrypt_block(block);
        memcpy(buffer + i, decrypted.data(), 16);
    }
}

// ============= OpenSSL XTS Wrappers (key setup excluded from timing) =============
void openssl_xts_encrypt_no_keygen(uint8_t* buffer, size_t size, EVP_CIPHER_CTX* ctx) {
    int outlen;
    uint8_t outbuf[BUFFER_SIZE];
    EVP_EncryptUpdate(ctx, outbuf, &outlen, buffer, size);
    memcpy(buffer, outbuf, size);
}

void openssl_xts_decrypt_no_keygen(uint8_t* buffer, size_t size, EVP_CIPHER_CTX* ctx) {
    int outlen;
    uint8_t outbuf[BUFFER_SIZE];
    EVP_DecryptUpdate(ctx, outbuf, &outlen, buffer, size);
    memcpy(buffer, outbuf, size);
}

// ============= Benchmark Function =============
struct BenchmarkResult {
    uint64_t min_ns;
    uint64_t max_ns;
    uint64_t total_ns;
    int iterations;
    
    double avg_ns() const { return (double)total_ns / iterations; }
    double throughput_gbps() const {
        // Throughput based on single operation (avg time for one 4KB buffer)
        double seconds = avg_ns() / 1e9;
        double gb = BUFFER_SIZE / (1024.0 * 1024.0 * 1024.0);
        return gb / seconds;
    }
    double latency_us() const { return avg_ns() / 1000.0; }
};

template<typename SetupFunc, typename OpFunc>
BenchmarkResult benchmark_operation(const string& name, SetupFunc setup, OpFunc operation) {
    BenchmarkResult result;
    result.min_ns = UINT64_MAX;
    result.max_ns = 0;
    result.total_ns = 0;
    result.iterations = ITERATIONS;
    
    cout << "Benchmarking " << name << " (" << ITERATIONS << " iterations)..." << flush;
    
    for (int i = 0; i < ITERATIONS; i++) {
        // Generate random data and key for this iteration
        uint8_t buffer[BUFFER_SIZE];
        generate_random_buffer(buffer, BUFFER_SIZE);
        
        // Setup (not timed)
        auto ctx = setup();
        
        // Measure only the operation (not key setup)
        uint64_t start = get_time_ns();
        operation(buffer, BUFFER_SIZE, ctx);
        uint64_t end = get_time_ns();
        
        uint64_t elapsed = end - start;
        result.min_ns = min(result.min_ns, elapsed);
        result.max_ns = max(result.max_ns, elapsed);
        result.total_ns += elapsed;
        
        // Progress indicator every 10k iterations
        if ((i + 1) % 10000 == 0) {
            cout << "." << flush;
        }
    }
    
    cout << " Done!" << endl;
    return result;
}

// ============= Main =============
int main() {
    cout << "=============================================================\n";
    cout << "  T-AES vs OpenSSL XTS Performance Benchmark\n";
    cout << "=============================================================\n";
    cout << "Configuration:\n";
    cout << "  Buffer size: " << BUFFER_SIZE << " bytes (4KB)\n";
    cout << "  Iterations: " << ITERATIONS << " per operation\n";
    cout << "  Key sizes: AES-128/192/256 (SW & AES-NI)\n";
    cout << "  Tweak modes: with-tweak and no-tweak\n";
    cout << "  XTS: 128-bit and 256-bit\n";
    cout << "  Timing: clock_gettime (nanosecond precision)\n";
    cout << "  Note: Key setup excluded from measurements\n";
    cout << "=============================================================\n\n";

    vector<pair<string, BenchmarkResult>> results;

    // ==================================================================
    // T-AES Software and AES-NI for 128/192/256, with and without tweak
    // ==================================================================
    auto add_taes_sw_suite = [&](int bits, int rounds) {
        // no-tweak Encrypt
        cout << "\n[T-AES SW] Encrypt " << bits << " no-tweak\n";
        auto enc_no_tweak = benchmark_operation(
            string("T-AES SW Encrypt ") + to_string(bits) + " no-tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                generate_random_key(key_vec.data(), key_vec.size());
                vector<uint8_t> tweak_empty; // no tweak
                return new AES(bits, rounds, key_vec, tweak_empty);
            },
            [](uint8_t* buf, size_t sz, AES* aes) {
                tAES_SW_encrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES SW Encrypt ") + to_string(bits) + " no-tweak", enc_no_tweak});

        // no-tweak Decrypt
        cout << "\n[T-AES SW] Decrypt " << bits << " no-tweak\n";
        auto dec_no_tweak = benchmark_operation(
            string("T-AES SW Decrypt ") + to_string(bits) + " no-tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                generate_random_key(key_vec.data(), key_vec.size());
                vector<uint8_t> tweak_empty;
                return new AES(bits, rounds, key_vec, tweak_empty);
            },
            [](uint8_t* buf, size_t sz, AES* aes) {
                tAES_SW_decrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES SW Decrypt ") + to_string(bits) + " no-tweak", dec_no_tweak});

        // with-tweak Encrypt
        cout << "\n[T-AES SW] Encrypt " << bits << " tweak\n";
        auto enc_tweak = benchmark_operation(
            string("T-AES SW Encrypt ") + to_string(bits) + " tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                vector<uint8_t> tweak(16);
                generate_random_key(key_vec.data(), key_vec.size());
                generate_random_key(tweak.data(), tweak.size());
                return new AES(bits, rounds, key_vec, tweak);
            },
            [](uint8_t* buf, size_t sz, AES* aes) {
                tAES_SW_encrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES SW Encrypt ") + to_string(bits) + " tweak", enc_tweak});

        // with-tweak Decrypt
        cout << "\n[T-AES SW] Decrypt " << bits << " tweak\n";
        auto dec_tweak = benchmark_operation(
            string("T-AES SW Decrypt ") + to_string(bits) + " tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                vector<uint8_t> tweak(16);
                generate_random_key(key_vec.data(), key_vec.size());
                generate_random_key(tweak.data(), tweak.size());
                return new AES(bits, rounds, key_vec, tweak);
            },
            [](uint8_t* buf, size_t sz, AES* aes) {
                tAES_SW_decrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES SW Decrypt ") + to_string(bits) + " tweak", dec_tweak});
    };

    auto add_taes_ni_suite = [&](int bits, int rounds) {
        // no-tweak Encrypt
        cout << "\n[T-AES NI] Encrypt " << bits << " no-tweak\n";
        auto enc_no_tweak = benchmark_operation(
            string("T-AES NI Encrypt ") + to_string(bits) + " no-tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                generate_random_key(key_vec.data(), key_vec.size());
                vector<uint8_t> tweak_empty;
                return new AESNI(bits, rounds, key_vec, tweak_empty);
            },
            [](uint8_t* buf, size_t sz, AESNI* aes) {
                tAES_NI_encrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES NI Encrypt ") + to_string(bits) + " no-tweak", enc_no_tweak});

        // no-tweak Decrypt
        cout << "\n[T-AES NI] Decrypt " << bits << " no-tweak\n";
        auto dec_no_tweak = benchmark_operation(
            string("T-AES NI Decrypt ") + to_string(bits) + " no-tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                generate_random_key(key_vec.data(), key_vec.size());
                vector<uint8_t> tweak_empty;
                return new AESNI(bits, rounds, key_vec, tweak_empty);
            },
            [](uint8_t* buf, size_t sz, AESNI* aes) {
                tAES_NI_decrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES NI Decrypt ") + to_string(bits) + " no-tweak", dec_no_tweak});

        // with-tweak Encrypt
        cout << "\n[T-AES NI] Encrypt " << bits << " tweak\n";
        auto enc_tweak = benchmark_operation(
            string("T-AES NI Encrypt ") + to_string(bits) + " tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                vector<uint8_t> tweak(16);
                generate_random_key(key_vec.data(), key_vec.size());
                generate_random_key(tweak.data(), tweak.size());
                return new AESNI(bits, rounds, key_vec, tweak);
            },
            [](uint8_t* buf, size_t sz, AESNI* aes) {
                tAES_NI_encrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES NI Encrypt ") + to_string(bits) + " tweak", enc_tweak});

        // with-tweak Decrypt
        cout << "\n[T-AES NI] Decrypt " << bits << " tweak\n";
        auto dec_tweak = benchmark_operation(
            string("T-AES NI Decrypt ") + to_string(bits) + " tweak",
            [&]() {
                vector<uint8_t> key_vec(bits/8);
                vector<uint8_t> tweak(16);
                generate_random_key(key_vec.data(), key_vec.size());
                generate_random_key(tweak.data(), tweak.size());
                return new AESNI(bits, rounds, key_vec, tweak);
            },
            [](uint8_t* buf, size_t sz, AESNI* aes) {
                tAES_NI_decrypt_no_keygen(buf, sz, aes);
                delete aes;
            }
        );
        results.push_back({string("T-AES NI Decrypt ") + to_string(bits) + " tweak", dec_tweak});
    };

    // Add all suites
    add_taes_sw_suite(128, 10);
    add_taes_ni_suite(128, 10);
    add_taes_sw_suite(192, 12);
    add_taes_ni_suite(192, 12);
    add_taes_sw_suite(256, 14);
    add_taes_ni_suite(256, 14);

    // ================================
    // OpenSSL XTS-128 and XTS-256 only
    // ================================
    cout << "\n[OpenSSL] XTS-128 Encryption\n";
    auto result_xts128_enc = benchmark_operation(
        "OpenSSL XTS-128 Encryption",
        []() {
            uint8_t key1[16], key2[16];
            generate_random_key(key1, 16);
            generate_random_key(key2, 16);
            uint8_t full_key[32];
            memcpy(full_key, key1, 16);
            memcpy(full_key + 16, key2, 16);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            uint8_t iv[16] = {0}; // XTS requires an IV (tweak)
            EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, full_key, iv);
            return ctx;
        },
        [](uint8_t* buf, size_t sz, EVP_CIPHER_CTX* ctx) {
            openssl_xts_encrypt_no_keygen(buf, sz, ctx);
            EVP_CIPHER_CTX_free(ctx);
        }
    );
    results.push_back({"OpenSSL XTS-128 Encrypt", result_xts128_enc});

    cout << "\n[OpenSSL] XTS-128 Decryption\n";
    auto result_xts128_dec = benchmark_operation(
        "OpenSSL XTS-128 Decryption",
        []() {
            uint8_t key1[16], key2[16];
            generate_random_key(key1, 16);
            generate_random_key(key2, 16);
            uint8_t full_key[32];
            memcpy(full_key, key1, 16);
            memcpy(full_key + 16, key2, 16);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            uint8_t iv[16] = {0};
            EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, full_key, iv);
            return ctx;
        },
        [](uint8_t* buf, size_t sz, EVP_CIPHER_CTX* ctx) {
            openssl_xts_decrypt_no_keygen(buf, sz, ctx);
            EVP_CIPHER_CTX_free(ctx);
        }
    );
    results.push_back({"OpenSSL XTS-128 Decrypt", result_xts128_dec});

    cout << "\n[OpenSSL] XTS-256 Encryption\n";
    auto result_xts256_enc = benchmark_operation(
        "OpenSSL XTS-256 Encryption",
        []() {
            uint8_t key1[32], key2[32];
            generate_random_key(key1, 32);
            generate_random_key(key2, 32);
            uint8_t full_key[64];
            memcpy(full_key, key1, 32);
            memcpy(full_key + 32, key2, 32);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            uint8_t iv[16] = {0}; // XTS requires an IV (tweak)
            EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), nullptr, full_key, iv);
            return ctx;
        },
        [](uint8_t* buf, size_t sz, EVP_CIPHER_CTX* ctx) {
            openssl_xts_encrypt_no_keygen(buf, sz, ctx);
            EVP_CIPHER_CTX_free(ctx);
        }
    );
    results.push_back({"OpenSSL XTS-256 Encrypt", result_xts256_enc});

    cout << "\n[OpenSSL] XTS-256 Decryption\n";
    auto result_xts256_dec = benchmark_operation(
        "OpenSSL XTS-256 Decryption",
        []() {
            uint8_t key1[32], key2[32];
            generate_random_key(key1, 32);
            generate_random_key(key2, 32);
            uint8_t full_key[64];
            memcpy(full_key, key1, 32);
            memcpy(full_key + 32, key2, 32);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            uint8_t iv[16] = {0};
            EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), nullptr, full_key, iv);
            return ctx;
        },
        [](uint8_t* buf, size_t sz, EVP_CIPHER_CTX* ctx) {
            openssl_xts_decrypt_no_keygen(buf, sz, ctx);
            EVP_CIPHER_CTX_free(ctx);
        }
    );
    results.push_back({"OpenSSL XTS-256 Decrypt", result_xts256_dec});

    // ========== Print Results Table ==========
    cout << "\n=============================================================\n";
    cout << "  BENCHMARK RESULTS (Peak Speed = Minimum Time)\n";
    cout << "=============================================================\n";
    const int NAME_W = 34;     // width for operation name
    const int NUM_W  = 14;     // width for numeric columns
    cout << left << setw(NAME_W) << "Operation"
        << right << setw(NUM_W) << "Min (μs)"
        << setw(NUM_W) << "Avg (μs)"
        << setw(NUM_W) << "Max (μs)"
        << setw(NUM_W) << "Throughput (GB/s)"
        << endl;
    cout << string(NAME_W + 4*NUM_W, '-') << endl;

    for (const auto& [name, res] : results) {
       cout << left << setw(NAME_W) << name
           << right << setw(NUM_W) << fixed << setprecision(2) << (res.min_ns / 1000.0)
           << setw(NUM_W) << fixed << setprecision(2) << res.latency_us()
           << setw(NUM_W) << fixed << setprecision(2) << (res.max_ns / 1000.0)
           << setw(NUM_W) << fixed << setprecision(3) << res.throughput_gbps()
           << endl;
    }
    cout << "=============================================================\n";

    // ========== Write CSV ==========
    ofstream csv("benchmark_results_comparison.csv");
    csv << "Operation,Min_ns,Avg_ns,Max_ns,Throughput_GBps,Latency_us\n";
    for (const auto& [name, res] : results) {
        csv << name << ","
            << res.min_ns << ","
            << res.avg_ns() << ","
            << res.max_ns << ","
            << res.throughput_gbps() << ","
            << res.latency_us() << "\n";
    }
    csv.close();
    cout << "\nResults saved to: benchmark_results_comparison.csv\n";

    // ========== Speed Comparison ==========
    cout << "\n=============================================================\n";
    cout << "  RELATIVE PERFORMANCE (Based on Peak Speed = Min Time)\n";
    cout << "=============================================================\n";
    auto get_speed = [&](const string& name) -> double {
        for (const auto& p : results) if (p.first == name) return 1.0 / p.second.min_ns;
        return 0.0;
    };
    string baseline_name = "T-AES SW Encrypt 128 no-tweak";
    double base = get_speed(baseline_name);
    if (base == 0.0) {
        cout << "Baseline '" << baseline_name << "' not found.\n";
    } else {
        cout << "Baseline: " << baseline_name << "\n";
        struct Row { string name; string label; } rows[] = {
            {"T-AES NI Encrypt 128 no-tweak", "T-AES AES-NI 128 (no-tweak)"},
            {"T-AES SW Encrypt 128 tweak",    "T-AES SW 128 (tweak)"},
            {"OpenSSL XTS-128 Encrypt",       "OpenSSL XTS-128"},
            {"OpenSSL XTS-256 Encrypt",       "OpenSSL XTS-256"}
        };
        for (const auto& r : rows) {
            double sp = get_speed(r.name);
            if (sp > 0) {
                cout << "  " << setw(NAME_W-2) << left << r.label << right << fixed << setprecision(2)
                     << (sp / base) << "x\n";
            }
        }
    }
    cout << "=============================================================\n";

    return 0;
}
