#!/bin/bash

# Comprehensive AES Test Script
# Tests all combinations of key sizes, with/without tweak, software vs hardware

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test results array
declare -a FAILED_TEST_NAMES

# Print header
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Print test result
print_result() {
    local test_name="$1"
    local result="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓${NC} $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗${NC} $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
    fi
}

# Create test input file
create_test_file() {
    echo "This is a test message for AES encryption testing. It contains multiple blocks to test ciphertext stealing." > /tmp/test_input.txt
}

# Build all programs
build_all() {
    print_header "Building all programs"
    echo "Building software versions..."
    make encrypt decrypt > /dev/null 2>&1
    echo "Building hardware-accelerated versions..."
    make encrypt_aesni decrypt_aesni > /dev/null 2>&1
    echo -e "${GREEN}✓ All programs built successfully${NC}\n"
}

# Test basic encryption/decryption round-trip
test_roundtrip() {
    local impl="$1"      # "software" or "hardware"
    local size="$2"      # 128, 192, or 256
    local password="$3"
    local tweak="$4"     # empty string for no tweak
    local input_file="$5"

    local encrypt_bin="./bin/encrypt"
    local decrypt_bin="./bin/decrypt"

    if [ "$impl" = "hardware" ]; then
        encrypt_bin="./bin/encrypt_aesni"
        decrypt_bin="./bin/decrypt_aesni"
    fi

    local test_name="AES-$size $impl"
    if [ -n "$tweak" ]; then
        test_name="$test_name with tweak"
        cat "$input_file" | $encrypt_bin $size "$password" "$tweak" | $decrypt_bin $size "$password" "$tweak" > /tmp/output.txt 2>/dev/null
    else
        test_name="$test_name without tweak"
        cat "$input_file" | $encrypt_bin $size "$password" | $decrypt_bin $size "$password" > /tmp/output.txt 2>/dev/null
    fi

    if cmp -s "$input_file" /tmp/output.txt; then
        print_result "$test_name" "PASS"
    else
        print_result "$test_name" "FAIL"
    fi
}

# Test with wrong decryption key (should fail to produce original plaintext)
test_wrong_key() {
    local impl="$1"
    local size="$2"
    local correct_password="$3"
    local wrong_password="$4"
    local tweak="$5"
    local input_file="$6"

    local encrypt_bin="./bin/encrypt"
    local decrypt_bin="./bin/decrypt"

    if [ "$impl" = "hardware" ]; then
        encrypt_bin="./bin/encrypt_aesni"
        decrypt_bin="./bin/decrypt_aesni"
    fi

    local test_name="AES-$size $impl wrong key"
    if [ -n "$tweak" ]; then
        test_name="$test_name with tweak"
        cat "$input_file" | $encrypt_bin $size "$correct_password" "$tweak" | $decrypt_bin $size "$wrong_password" "$tweak" > /tmp/output.txt 2>/dev/null
    else
        test_name="$test_name without tweak"
        cat "$input_file" | $encrypt_bin $size "$correct_password" | $decrypt_bin $size "$wrong_password" > /tmp/output.txt 2>/dev/null
    fi

    # This should FAIL to match (wrong key should not decrypt correctly)
    if ! cmp -s "$input_file" /tmp/output.txt; then
        print_result "$test_name (correctly fails)" "PASS"
    else
        print_result "$test_name (incorrectly succeeds!)" "FAIL"
    fi
}

# Test with wrong tweak (should fail to produce original plaintext)
test_wrong_tweak() {
    local impl="$1"
    local size="$2"
    local password="$3"
    local correct_tweak="$4"
    local wrong_tweak="$5"
    local input_file="$6"

    local encrypt_bin="./bin/encrypt"
    local decrypt_bin="./bin/decrypt"

    if [ "$impl" = "hardware" ]; then
        encrypt_bin="./bin/encrypt_aesni"
        decrypt_bin="./bin/decrypt_aesni"
    fi

    local test_name="AES-$size $impl wrong tweak"
    cat "$input_file" | $encrypt_bin $size "$password" "$correct_tweak" | $decrypt_bin $size "$password" "$wrong_tweak" > /tmp/output.txt 2>/dev/null

    # This should FAIL to match (wrong tweak should not decrypt correctly)
    if ! cmp -s "$input_file" /tmp/output.txt; then
        print_result "$test_name (correctly fails)" "PASS"
    else
        print_result "$test_name (incorrectly succeeds!)" "FAIL"
    fi
}

# Test software vs hardware produce same ciphertext
test_sw_hw_match() {
    local size="$1"
    local password="$2"
    local tweak="$3"
    local input_file="$4"

    local test_name="AES-$size software vs hardware ciphertext match"
    if [ -n "$tweak" ]; then
        test_name="$test_name with tweak"
        cat "$input_file" | ./bin/encrypt $size "$password" "$tweak" > /tmp/cipher_sw.bin 2>/dev/null
        cat "$input_file" | ./bin/encrypt_aesni $size "$password" "$tweak" > /tmp/cipher_hw.bin 2>/dev/null
    else
        test_name="$test_name without tweak"
        cat "$input_file" | ./bin/encrypt $size "$password" > /tmp/cipher_sw.bin 2>/dev/null
        cat "$input_file" | ./bin/encrypt_aesni $size "$password" > /tmp/cipher_hw.bin 2>/dev/null
    fi

    if cmp -s /tmp/cipher_sw.bin /tmp/cipher_hw.bin; then
        print_result "$test_name" "PASS"
    else
        print_result "$test_name" "FAIL"
    fi
}

# Test with irregular file size (ciphertext stealing)
test_irregular_size() {
    local impl="$1"
    local size="$2"
    local password="$3"
    local tweak="$4"

    # Create file with non-block-aligned size (23 bytes)
    echo -n "Irregular size test!!" > /tmp/irregular.txt

    local encrypt_bin="./bin/encrypt"
    local decrypt_bin="./bin/decrypt"

    if [ "$impl" = "hardware" ]; then
        encrypt_bin="./bin/encrypt_aesni"
        decrypt_bin="./bin/decrypt_aesni"
    fi

    local test_name="AES-$size $impl irregular size (ciphertext stealing)"
    if [ -n "$tweak" ]; then
        test_name="$test_name with tweak"
        cat /tmp/irregular.txt | $encrypt_bin $size "$password" "$tweak" | $decrypt_bin $size "$password" "$tweak" > /tmp/output.txt 2>/dev/null
    else
        test_name="$test_name without tweak"
        cat /tmp/irregular.txt | $encrypt_bin $size "$password" | $decrypt_bin $size "$password" > /tmp/output.txt 2>/dev/null
    fi

    if cmp -s /tmp/irregular.txt /tmp/output.txt; then
        print_result "$test_name" "PASS"
    else
        print_result "$test_name" "FAIL"
    fi
}

# Main test execution
main() {
    print_header "AES Encryption/Decryption Test Suite"
    echo "Testing software and hardware implementations"
    echo "Key sizes: 128, 192, 256 bits"
    echo "Modes: with/without tweak"
    echo ""

    # Build programs
    build_all

    # Create test input
    create_test_file

    # Test parameters
    KEY_SIZES=(128 192 256)
    PASSWORD="testpassword123"
    WRONG_PASSWORD="wrongpassword456"
    TWEAK="tweakkey"
    WRONG_TWEAK="wrongtweak"
    INPUT_FILE="/tmp/test_input.txt"

    # ==========================
    # Test 1: Basic Round-trips
    # ==========================
    print_header "Test 1: Basic Encryption/Decryption Round-trips"

    for size in "${KEY_SIZES[@]}"; do
        # Software without tweak
        test_roundtrip "software" "$size" "$PASSWORD" "" "$INPUT_FILE"

        # Software with tweak
        test_roundtrip "software" "$size" "$PASSWORD" "$TWEAK" "$INPUT_FILE"

        # Hardware without tweak
        test_roundtrip "hardware" "$size" "$PASSWORD" "" "$INPUT_FILE"

        # Hardware with tweak
        test_roundtrip "hardware" "$size" "$PASSWORD" "$TWEAK" "$INPUT_FILE"
    done
    echo ""

    # ==========================
    # Test 2: Wrong Key
    # ==========================
    print_header "Test 2: Decryption with Wrong Key (should fail)"

    for size in "${KEY_SIZES[@]}"; do
        # Software without tweak
        test_wrong_key "software" "$size" "$PASSWORD" "$WRONG_PASSWORD" "" "$INPUT_FILE"

        # Software with tweak
        test_wrong_key "software" "$size" "$PASSWORD" "$WRONG_PASSWORD" "$TWEAK" "$INPUT_FILE"

        # Hardware without tweak
        test_wrong_key "hardware" "$size" "$PASSWORD" "$WRONG_PASSWORD" "" "$INPUT_FILE"

        # Hardware with tweak
        test_wrong_key "hardware" "$size" "$PASSWORD" "$WRONG_PASSWORD" "$TWEAK" "$INPUT_FILE"
    done
    echo ""

    # ==========================
    # Test 3: Wrong Tweak
    # ==========================
    print_header "Test 3: Decryption with Wrong Tweak (should fail)"

    for size in "${KEY_SIZES[@]}"; do
        # Software
        test_wrong_tweak "software" "$size" "$PASSWORD" "$TWEAK" "$WRONG_TWEAK" "$INPUT_FILE"

        # Hardware
        test_wrong_tweak "hardware" "$size" "$PASSWORD" "$TWEAK" "$WRONG_TWEAK" "$INPUT_FILE"
    done
    echo ""

    # ==========================
    # Test 4: Software vs Hardware
    # ==========================
    print_header "Test 4: Software vs Hardware Ciphertext Comparison"

    for size in "${KEY_SIZES[@]}"; do
        # Without tweak
        test_sw_hw_match "$size" "$PASSWORD" "" "$INPUT_FILE"

        # With tweak
        test_sw_hw_match "$size" "$PASSWORD" "$TWEAK" "$INPUT_FILE"
    done
    echo ""

    # ==========================
    # Test 5: Irregular File Sizes
    # ==========================
    print_header "Test 5: Irregular File Sizes (Ciphertext Stealing)"

    for size in "${KEY_SIZES[@]}"; do
        # Software without tweak
        test_irregular_size "software" "$size" "$PASSWORD" ""

        # Software with tweak
        test_irregular_size "software" "$size" "$PASSWORD" "$TWEAK"

        # Hardware without tweak
        test_irregular_size "hardware" "$size" "$PASSWORD" ""

        # Hardware with tweak
        test_irregular_size "hardware" "$size" "$PASSWORD" "$TWEAK"
    done
    echo ""

    # ==========================
    # Test 6: Use existing irregular file if present
    # ==========================
    if [ -f "plaintext_irregular.bin" ]; then
        print_header "Test 6: Testing with plaintext_irregular.bin"

        for size in "${KEY_SIZES[@]}"; do
            # Software with tweak
            test_roundtrip "software" "$size" "$PASSWORD" "$TWEAK" "plaintext_irregular.bin"

            # Hardware with tweak
            test_roundtrip "hardware" "$size" "$PASSWORD" "$TWEAK" "plaintext_irregular.bin"
        done
        echo ""
    fi

    # ==========================
    # Summary
    # ==========================
    print_header "Test Summary"
    echo -e "Total tests:  $TOTAL_TESTS"
    echo -e "${GREEN}Passed tests: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed tests: $FAILED_TESTS${NC}"
    echo ""

    if [ $FAILED_TESTS -gt 0 ]; then
        echo -e "${RED}Failed test cases:${NC}"
        for test_name in "${FAILED_TEST_NAMES[@]}"; do
            echo -e "  ${RED}✗${NC} $test_name"
        done
        echo ""
        exit 1
    else
        echo -e "${GREEN}All tests passed successfully!${NC}"
        exit 0
    fi
}

# Run main
main
