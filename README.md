# T-AES: Tweakable AES Implementation

**T-AES** is a software and hardware-accelerated implementation of the Advanced Encryption Standard (AES) featuring a tweakable design with ciphertext stealing for handling non-block-aligned data.

## Overview

T-AES implements a variant of AES where a **tweak** (a 128-bit non-secret value) is combined via arithmetic addition (mod 2^128) with the middle round key during encryption. This enables deterministic variation across encrypted blocks without requiring key changes. The implementation supports:

- **AES-128, AES-192, and AES-256** encryption
- **Software** (pure C++) and **Hardware-accelerated** (Intel AES-NI) versions
- **Counter mode** with automatic tweak increment per block
- **Ciphertext stealing** for data not aligned to 16-byte boundaries
- Complete **encrypt/decrypt** command-line tools
- Comprehensive **benchmarking and statistical analysis** tools

### Key Features

- **Tweakable Encryption**: Optional tweak parameter provides block-to-block variation
- **No Padding Required**: Ciphertext stealing preserves exact input length
- **Hardware Acceleration**: AES-NI implementation provides 10-15x speedup
- **Cryptographic Equivalence**: Software and hardware versions produce identical outputs
- **Stream Processing**: Processes data via stdin/stdout for arbitrary file sizes
- **Comprehensive Testing**: 150+ test cases validate all modes and configurations

---

## Build Instructions

### Requirements

- **Compiler**: GCC with C++17 support
- **Libraries**: OpenSSL (libssl-dev, libcrypto)
- **CPU**: x86-64 processor (AES-NI support recommended for hardware acceleration)

### Compilation

Build all programs:
```bash
make
```

Individual targets:
```bash
make encrypt           # Software encryption
make decrypt           # Software decryption
make encrypt_aesni     # Hardware-accelerated encryption
make decrypt_aesni     # Hardware-accelerated decryption
make speed             # Performance benchmark
make stat              # Statistical analysis tool
```

Clean build artifacts:
```bash
make clean
```

All binaries are placed in `bin/` directory.

---

## Usage

### Command-Line Interface

Both software and hardware versions use identical command syntax:

```bash
./bin/encrypt <aes_size> <password> [tweak_password] < plaintext > ciphertext
./bin/decrypt <aes_size> <password> [tweak_password] < ciphertext > plaintext
```

**Parameters**:
- `<aes_size>`: Key size (128, 192, or 256)
- `<password>`: Encryption password (hashed via SHA-256)
- `[tweak_password]`: Optional tweak (enables counter mode)

### Examples

**Basic encryption/decryption** (software, AES-128):
```bash
./bin/encrypt 128 mypassword < plaintext.bin > ciphertext.bin
./bin/decrypt 128 mypassword < ciphertext.bin > decrypted.bin
```

**Hardware-accelerated with tweak** (AES-256):
```bash
./bin/encrypt_aesni 256 password1 password2 < plaintext.bin > cipher.bin
./bin/decrypt_aesni 256 password1 password2 < cipher.bin > plaintext.bin
```

**Cross-validation** (encrypt with software, decrypt with hardware):
```bash
./bin/encrypt 192 mykey mytweak < data.bin > cipher.bin
./bin/decrypt_aesni 192 mykey mytweak < cipher.bin > data.bin
```

---

## How It Works

### Tweak Mechanism

The tweak is a 128-bit value that modifies encryption without requiring a key change:

1. **Injection Point**: Tweak is added (mod 2^128) to the middle round key
   - AES-128: Round 5
   - AES-192: Round 6
   - AES-256: Round 7

2. **Counter Mode**: When `[tweak_password]` is provided:
   - Initial tweak derived from password via SHA-256
   - Tweak increments (big-endian) after each block
   - Ensures unique encryption per block

3. **Decryption**: Same tweak value is added (addition is symmetric in mod 2^128)

### Ciphertext Stealing (CTS)

Handles data not aligned to 16-byte blocks without padding:

**Encryption** (partial block Pn of M < 16 bytes):
1. Encrypt all full blocks normally: `P0 → C0, P1 → C1, ..., P(n-1) → C(n-1)`
2. Steal last `(16-M)` bytes from `C(n-1)`
3. Concatenate `Pn` with stolen bytes and encrypt: `(Pn || tail(C(n-1))) → Cn`
4. Truncate `C(n-1)` to first M bytes

**Output**: `C0, C1, ..., truncated_C(n-1), Cn` (same length as plaintext)

**Decryption**:
1. Detect partial final block
2. Reconstruct full `Cn` from merged data
3. Decrypt `Cn` to extract `Pn` and stolen bytes
4. Reconstruct and decrypt `C(n-1)`

**Result**: Perfect plaintext recovery without padding overhead

---

## Performance Benchmarks

Run comprehensive speed tests:
```bash
./bin/speed
```

**Typical Results** (AMD Ryzen 5 8645HS, 4KB blocks):

| Implementation | AES-128 Encrypt | AES-128 Decrypt | Speedup |
|----------------|-----------------|-----------------|---------|
| Software       | 0.041 GB/s      | 0.028 GB/s      | 1x      |
| AES-NI         | 0.461 GB/s      | 0.313 GB/s      | **11x** |
| OpenSSL XTS    | 8.687 GB/s      | 8.770 GB/s      | **21x** |

**Key Findings**:
- Hardware acceleration provides **10-15x speedup** over software
- Tweak overhead: ~3-4% (software), ~18-23% (hardware)
- Key size impact: Minimal for AES-NI (~1-3%), significant for software (~30%)

---

## Statistical Validation

Validate cryptographic properties of tweak mechanism:
```bash
./bin/stat
```

This measures Hamming distance distributions across 2.5M+ comparisons, confirming:
- Mean Hamming distance: **~64 bits** (50% diffusion)
- Distribution centered at 64 bits (expected for good diffusion)
- Tweak variations produce cryptographically strong block differentiation

Visualize results:
```bash
python3 plot_stat_histogram.py
```

---

## Testing

### Comprehensive Test Suite

Run all 150+ validation tests:
```bash
./test_comprehensive.sh
```

**Test Coverage**:
- All key sizes (128, 192, 256 bits)
- Multiple plaintext sizes (16, 32, 64, 128, 256, 1024 bytes)
- Software and AES-NI implementations
- Tweaked and non-tweaked modes
- Cross-implementation validation
- Edge cases (empty files, non-aligned data)

### Manual Testing

**Round-trip test**:
```bash
echo "Hello, T-AES!" | ./bin/encrypt 128 password | ./bin/decrypt 128 password
```

**Cross-implementation**:
```bash
./bin/encrypt 256 key tweak < data.bin | ./bin/decrypt_aesni 256 key tweak > out.bin
cmp data.bin out.bin && echo "PASS"
```

---

## Project Structure

```
T-AES/
├── src/
│   ├── encrypt.cpp          # Software encryption
│   ├── decrypt.cpp          # Software decryption
│   ├── encrypt_aesni.cpp    # Hardware encryption
│   ├── decrypt_aesni.cpp    # Hardware decryption
│   ├── speed.cpp            # Performance benchmarks
│   ├── stat.cpp             # Statistical analysis
│   └── verify_aes.cpp       # Validation utility
├── include/
│   ├── AES.hpp              # Software AES implementation
│   ├── AESNI.hpp            # Hardware AES-NI implementation
│   └── utils.hpp            # Utility functions (tweak increment, SHA-256)
├── bin/                     # Compiled binaries (generated)
├── Makefile                 # Build system
├── test_comprehensive.sh    # Test suite
└── report.tex               # Technical report
```

---

## Technical Details

### Implementation Highlights

**Software Version** (`AES.hpp`):
- Pure C++ implementation using lookup tables
- S-box substitution, ShiftRows, MixColumns, AddRoundKey
- Galois Field (GF(2^8)) arithmetic for MixColumns
- Key expansion via NIST FIPS 197 algorithm

**Hardware Version** (`AESNI.hpp`):
- Intel AES-NI intrinsics (`wmmintrin.h`)
- Single-instruction round operations (`_mm_aesenc_si128`)
- Constant-time execution (resistant to timing attacks)
- XMM register operations (128-bit SIMD)

**Key Derivation**:
- User password → SHA-256 hash → extract first 16/24/32 bytes
- Deterministic and reproducible across executions

---

## Security Considerations

- **No ECB weaknesses**: Counter-mode tweak ensures block uniqueness
- **Timing resistance**: AES-NI version provides constant-time execution
- **No padding oracle**: Ciphertext stealing eliminates padding
- **Standard compliance**: Follows NIST FIPS 197 AES specification

**Note**: This is an educational/research implementation. For production use, consider established libraries like OpenSSL or libsodium.

---

## References

- NIST FIPS 197 - Advanced Encryption Standard (AES)
- NIST SP 800-38A - Block Cipher Modes (Ciphertext Stealing)
- Intel AES-NI White Paper (2010)
- Daemen & Rijmen - "The Design of Rijndael" (2002)

---

## License

MIT License - See `LICENSE` file for details.

---

## Author

Applied Cryptography Project
Computer Architecture
University of Aveiro, November 2025