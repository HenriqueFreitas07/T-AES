#!/bin/bash

# Comprehensive AES Testing Script
# Tests all combinations of AES implementations with different key sizes and text sizes
# Includes cross-compatibility testing between implementations

# make encrypt decrypt encrypt_aesni decrypt_aesni      

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
PASSWORD="testpassword123"
TWEAK_PASSWORD="tweakpassword456"
AES_SIZES=(128 192 256)
TEXT_SIZES=(16 32 64 128 256 1024)  # Different text sizes in bytes
TEST_DIR="test_results"

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo -e "${BLUE}=== Comprehensive AES Testing Script ===${NC}"
echo "Testing AES implementations with different configurations"
echo "Password: $PASSWORD"
echo "Tweak Password: $TWEAK_PASSWORD"
echo "AES Key Sizes: ${AES_SIZES[*]}"
echo "Text Sizes: ${TEXT_SIZES[*]} bytes"
echo ""

# Create test directory
mkdir -p $TEST_DIR
cd $TEST_DIR

# Function to create test files of different sizes
create_test_file() {
    local size=$1
    local filename=$2
    
    if [ $size -eq 16 ]; then
        echo "This is 16 bytes." > $filename
    elif [ $size -eq 32 ]; then
        echo "This is exactly 32 bytes long!!" > $filename
    elif [ $size -eq 64 ]; then
        echo "This is a 64-byte test file that contains some text for testing." > $filename
    elif [ $size -eq 128 ]; then
        echo "This is a 128-byte test file that contains quite a bit more text for comprehensive testing of the AES encryption system." > $filename
    elif [ $size -eq 256 ]; then
        python3 -c "print('A' * 256, end='')" > $filename
    elif [ $size -eq 1024 ]; then
        python3 -c "print('B' * 1024, end='')" > $filename
    fi
}

# Function to run a test and check result
run_test() {
    local test_name="$1"
    local encrypt_cmd="$2"
    local decrypt_cmd="$3"
    local input_file="$4"
    local expected_file="$5"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -n "Testing $test_name... "
    
    # Create temporary files
    local cipher_file="cipher_${TOTAL_TESTS}.bin"
    local output_file="output_${TOTAL_TESTS}.bin"
    
    # Run encryption
    if ! eval "$encrypt_cmd < $input_file > $cipher_file" 2>/dev/null; then
        echo -e "${RED}FAILED${NC} - Encryption failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Run decryption
    if ! eval "$decrypt_cmd < $cipher_file > $output_file" 2>/dev/null; then
        echo -e "${RED}FAILED${NC} - Decryption failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Compare results
    if cmp -s "$expected_file" "$output_file"; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}FAILED${NC} - Output doesn't match input"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Expected size: $(wc -c < $expected_file) bytes"
        echo "  Got size: $(wc -c < $output_file) bytes"
        return 1
    fi
    
    # Clean up temporary files
    rm -f "$cipher_file" "$output_file"
    return 0
}

# Build all programs
echo -e "${YELLOW}Building programs...${NC}"
cd ..
make clean > /dev/null 2>&1
make encrypt > /dev/null 2>&1
make decrypt > /dev/null 2>&1
make encrypt_aesni > /dev/null 2>&1
make decrypt_aesni > /dev/null 2>&1

if [ ! -f "bin/encrypt" ] || [ ! -f "bin/decrypt" ] || [ ! -f "bin/encrypt_aesni" ] || [ ! -f "bin/decrypt_aesni" ]; then
    echo -e "${RED}Error: Failed to build programs${NC}"
    exit 1
fi

cd $TEST_DIR

echo -e "${GREEN}Build successful!${NC}"
echo ""

# Create test files
echo -e "${YELLOW}Creating test files...${NC}"
for size in "${TEXT_SIZES[@]}"; do
    create_test_file $size "input_${size}.txt"
    echo "Created input_${size}.txt ($(wc -c < input_${size}.txt) bytes)"
done
echo ""

# Test 1: Same implementation encryption/decryption (without tweak)
echo -e "${BLUE}=== Test 1: Same Implementation (No Tweak) ===${NC}"
for aes_size in "${AES_SIZES[@]}"; do
    for text_size in "${TEXT_SIZES[@]}"; do
        input_file="input_${text_size}.txt"
        
        # AES -> AES
        run_test "AES-${aes_size} ${text_size}B" \
                "../bin/encrypt $aes_size $PASSWORD" \
                "../bin/decrypt $aes_size $PASSWORD" \
                "$input_file" "$input_file"
        
        # AES-NI -> AES-NI
        run_test "AES-NI-${aes_size} ${text_size}B" \
                "../bin/encrypt_aesni $aes_size $PASSWORD" \
                "../bin/decrypt_aesni $aes_size $PASSWORD" \
                "$input_file" "$input_file"
    done
done
echo ""

# Test 2: Same implementation encryption/decryption (with tweak)
echo -e "${BLUE}=== Test 2: Same Implementation (With Tweak) ===${NC}"
for aes_size in "${AES_SIZES[@]}"; do
    for text_size in "${TEXT_SIZES[@]}"; do
        input_file="input_${text_size}.txt"
        
        # AES+Tweak -> AES+Tweak
        run_test "AES+T-${aes_size} ${text_size}B" \
                "../bin/encrypt $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "../bin/decrypt $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "$input_file" "$input_file"
        
        # AES-NI+Tweak -> AES-NI+Tweak
        run_test "AES-NI+T-${aes_size} ${text_size}B" \
                "../bin/encrypt_aesni $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "../bin/decrypt_aesni $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "$input_file" "$input_file"
    done
done
echo ""

# Test 3: Cross-implementation compatibility (without tweak)
echo -e "${BLUE}=== Test 3: Cross-Implementation (No Tweak) ===${NC}"
for aes_size in "${AES_SIZES[@]}"; do
    for text_size in "${TEXT_SIZES[@]}"; do
        input_file="input_${text_size}.txt"
        
        # AES encrypt -> AES-NI decrypt
        run_test "AES→AES-NI-${aes_size} ${text_size}B" \
                "../bin/encrypt $aes_size $PASSWORD" \
                "../bin/decrypt_aesni $aes_size $PASSWORD" \
                "$input_file" "$input_file"
        
        # AES-NI encrypt -> AES decrypt
        run_test "AES-NI→AES-${aes_size} ${text_size}B" \
                "../bin/encrypt_aesni $aes_size $PASSWORD" \
                "../bin/decrypt $aes_size $PASSWORD" \
                "$input_file" "$input_file"
    done
done
echo ""

# Test 4: Cross-implementation compatibility (with tweak)
echo -e "${BLUE}=== Test 4: Cross-Implementation (With Tweak) ===${NC}"
for aes_size in "${AES_SIZES[@]}"; do
    for text_size in "${TEXT_SIZES[@]}"; do
        input_file="input_${text_size}.txt"
        
        # AES+Tweak encrypt -> AES-NI+Tweak decrypt
        run_test "AES+T→AES-NI+T-${aes_size} ${text_size}B" \
                "../bin/encrypt $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "../bin/decrypt_aesni $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "$input_file" "$input_file"
        
        # AES-NI+Tweak encrypt -> AES+Tweak decrypt
        run_test "AES-NI+T→AES+T-${aes_size} ${text_size}B" \
                "../bin/encrypt_aesni $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "../bin/decrypt $aes_size $PASSWORD $TWEAK_PASSWORD" \
                "$input_file" "$input_file"
    done
done
echo ""

# Test 5: Edge cases and error conditions
echo -e "${BLUE}=== Test 5: Edge Cases ===${NC}"

# Test with empty file
touch empty.txt
for aes_size in "${AES_SIZES[@]}"; do
    run_test "AES-${aes_size} Empty File" \
            "../bin/encrypt $aes_size $PASSWORD" \
            "../bin/decrypt $aes_size $PASSWORD" \
            "empty.txt" "empty.txt"
    
    run_test "AES-NI-${aes_size} Empty File" \
            "../bin/encrypt_aesni $aes_size $PASSWORD" \
            "../bin/decrypt_aesni $aes_size $PASSWORD" \
            "empty.txt" "empty.txt"
done

# # Test with single byte
# echo -n "A" > single_byte.txt
# for aes_size in "${AES_SIZES[@]}"; do
#     run_test "AES-${aes_size} 1 Byte" \
#             "../bin/encrypt $aes_size $PASSWORD" \
#             "../bin/decrypt $aes_size $PASSWORD" \
#             "single_byte.txt" "single_byte.txt"
    
#     run_test "AES-NI-${aes_size} 1 Byte" \
#             "../bin/encrypt_aesni $aes_size $PASSWORD" \
#             "../bin/decrypt_aesni $aes_size $PASSWORD" \
#             "single_byte.txt" "single_byte.txt"
# done

# # Test with 15 bytes (one less than block size)
# python3 -c "print('A' * 15, end='')" > fifteen_bytes.txt
# for aes_size in "${AES_SIZES[@]}"; do
#     run_test "AES-${aes_size} 15 Bytes" \
#             "../bin/encrypt $aes_size $PASSWORD" \
#             "../bin/decrypt $aes_size $PASSWORD" \
#             "fifteen_bytes.txt" "fifteen_bytes.txt"
    
#     run_test "AES-NI-${aes_size} 15 Bytes" \
#             "../bin/encrypt_aesni $aes_size $PASSWORD" \
#             "../bin/decrypt_aesni $aes_size $PASSWORD" \
#             "fifteen_bytes.txt" "fifteen_bytes.txt"
# done

# Test with 17 bytes (one more than block size)
python3 -c "print('A' * 17, end='')" > seventeen_bytes.txt
for aes_size in "${AES_SIZES[@]}"; do
    run_test "AES-${aes_size} 17 Bytes" \
            "../bin/encrypt $aes_size $PASSWORD" \
            "../bin/decrypt $aes_size $PASSWORD" \
            "seventeen_bytes.txt" "seventeen_bytes.txt"
    
    run_test "AES-NI-${aes_size} 17 Bytes" \
            "../bin/encrypt_aesni $aes_size $PASSWORD" \
            "../bin/decrypt_aesni $aes_size $PASSWORD" \
            "seventeen_bytes.txt" "seventeen_bytes.txt"
done

echo ""

# Test 6: Performance comparison (optional)
echo -e "${BLUE}=== Test 6: Performance Comparison ===${NC}"
large_file="large_test.txt"
python3 -c "print('X' * 10240, end='')" > $large_file  # 10KB file

echo "Measuring performance on 10KB file..."
for aes_size in "${AES_SIZES[@]}"; do
    echo -n "AES-${aes_size}: "
    time_output=$(time (../bin/encrypt $aes_size $PASSWORD < $large_file > /dev/null) 2>&1)
    echo "$time_output" | grep real | awk '{print $2}'
    
    echo -n "AES-NI-${aes_size}: "
    time_output=$(time (../bin/encrypt_aesni $aes_size $PASSWORD < $large_file > /dev/null) 2>&1)
    echo "$time_output" | grep real | awk '{print $2}'
done

echo ""

# Final results
echo -e "${BLUE}=== Test Results Summary ===${NC}"
echo "Total tests run: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed! 🎉${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed! ❌${NC}"
    exit 1
fi