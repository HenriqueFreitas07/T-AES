#include "../include/AES.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>

using namespace std;

// Helper function to convert hex string to vector<uint8_t>
vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to convert vector<uint8_t> to hex string
string bytesToHex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t byte : bytes) {
        ss << setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

struct TestVector {
    string name;
    int keySize;
    int rounds;
    string key;
    string plaintext;
    string expectedCiphertext;
};

int main() {
    // NIST test vectors
    vector<TestVector> testVectors = {
        // AES-128 (NIST FIPS 197 Appendix C.1)
        {
            "AES-128",
            128,
            10,
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97"
        },
        // AES-192 (NIST FIPS 197 Appendix C.2)
        {
            "AES-192",
            192,
            12,
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "6bc1bee22e409f96e93d7e117393172a",
            "bd334f1d6e45f25ff712a214571fa5cc"
        },
        // AES-256 (NIST FIPS 197 Appendix C.3)
        {
            "AES-256",
            256,
            14,
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8"
        }
    };

    cout << "Running NIST AES Test Vectors Verification\n";
    cout << "==========================================\n\n";

    int passed = 0;
    int failed = 0;

    for (const auto& test : testVectors) {
        cout << "Testing " << test.name << "...\n";
        cout << "  Key:       " << test.key << "\n";
        cout << "  Plaintext: " << test.plaintext << "\n";
        cout << "  Expected:  " << test.expectedCiphertext << "\n";

        // Convert hex strings to bytes
        vector<uint8_t> key = hexToBytes(test.key);
        vector<uint8_t> plaintext = hexToBytes(test.plaintext);
        vector<uint8_t> expectedCiphertext = hexToBytes(test.expectedCiphertext);

        // Create AES instance with empty tweak
        vector<uint8_t> emptyTweak;
        AES aes(test.keySize, test.rounds, key, emptyTweak);

        // Encrypt
        vector<uint8_t> ciphertext = aes.encrypt_block(plaintext);

        // Convert result to hex
        string resultHex = bytesToHex(ciphertext);
        cout << "  Got:       " << resultHex << "\n";

        // Compare
        bool testPassed = (ciphertext == expectedCiphertext);
        if (testPassed) {
            cout << "  ✓ ENCRYPTION PASSED\n";
            passed++;
        } else {
            cout << "  ✗ ENCRYPTION FAILED\n";
            failed++;
        }

        // Now test decryption
        vector<uint8_t> decrypted = aes.decrypt_block(ciphertext);
        string decryptedHex = bytesToHex(decrypted);
        cout << "  Decrypted: " << decryptedHex << "\n";
        cout << "  Expected:  " << test.plaintext << "\n";
        bool decryptPassed = (decrypted == plaintext);
        if (decryptPassed) {
            cout << "  ✓ DECRYPTION PASSED\n";
        } else {
            cout << "  ✗ DECRYPTION FAILED\n";
            failed++;
        }

        cout << "\n";
    }

    cout << "==========================================\n";
    cout << "Results: " << passed << " encryption passed, " << failed << " failed (encryption or decryption)\n";

    return (failed == 0) ? 0 : 1;
}
