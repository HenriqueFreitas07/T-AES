# T-AES


## Requirements
- Read from binary file from stdin
- Input & Output is in binary
- Ciphertext Stealing approach for the last two blocks if the input is not block aligned

## Ciphertext Stealing Implementation

When the plaintext is not a multiple of 16 bytes (block size), we use ciphertext stealing to avoid padding.

### Encryption

Given plaintext blocks: `P0, P1, ..., P(n-1), Pn` where Pn is partial (size M < 16 bytes):

1. Encrypt all full blocks normally: `P0 → C0, P1 → C1, ..., P(n-1) → C(n-1)`
2. Steal the last (16-M) bytes from C(n-1)
3. Append stolen bytes to Pn and encrypt: `(Pn || tail(C(n-1))) → Cn` (full 16 bytes)
4. Replace C(n-1) with its truncated version (first M bytes only)

**Output ciphertext:** `C0, C1, ..., truncated_C(n-1), Cn`

The ciphertext length equals the plaintext length (no padding added).

### Decryption

When reading ciphertext with fixed 16-byte reads, blocks get merged:
- Read blocks: `[C0, ..., merged_data, tail]` where tail is partial

Process:
1. Skip decrypting the merged block (detected when next block is partial)
2. When reaching the last partial block:
   - Reconstruct full Cn from merged data + tail
   - Decrypt Cn → extract Pn (first M bytes) and stolen bytes (last 16-M bytes)
   - Reconstruct full C(n-1) from truncated part + stolen bytes
   - Decrypt C(n-1) → get P(n-1)

**Output plaintext:** `P0, P1, ..., P(n-1), Pn` (original data recovered)