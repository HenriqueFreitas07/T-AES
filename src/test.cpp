#include "../include/AES.hpp"
#include <iomanip>
#include <iostream>

int main() {
  AES a("0123456789abcdef0123456789abcdef", "tweak");
  // sample 16 bytes (0x00..0x0f)
  std::vector<uint8_t> block(16);
  for (int i = 0; i < 16; i++)
    block[i] = i;
  auto out = a.encrypt_block(block);
  for (auto b : out)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  std::cout << std::endl;
  return 0;
}

// compile with: g++ -std=c++17 -I./include ./src/AES.cpp ./src/AES_sbox.cpp
// ./src/test.cpp -o test_aes run with: ./test_aes or had to alter Makefile, so
// i decided to wait on your cousin to do it # create output dirs mkdir -p build
// bin

// # compile AES objects (use -Iinclude so headers are found)
// g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/AES.cpp -o build/AES.o
// g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -c src/AES_sbox.cpp -o
// build/AES_sbox.o g++ build/AES.o build/AES_sbox.o src/test.cpp -o bin/test
// ./bin/test

// or use the provided Makefile with 'make' command
