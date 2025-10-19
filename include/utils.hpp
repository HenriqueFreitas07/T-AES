#ifndef UTILS_HPP
#define UTILS_HPP

#include <cassert>
#include <cstring>
#include <cstdint>
#include <vector>
#include <iostream>

namespace utils {

    /// @brief Conversion from char to uint8_t for encryption operations
    /// @param block Input character block
    /// @return 128 bits of 16 bytes of 8 bit integers
    std::vector<uint8_t> convertToBlock(char* block,size_t size){
        // assure that a block only has a max of 16 bytes
        assert(size <=16);
        std::vector<uint8_t> bformatted;
        for (size_t i = 0; i < size; i++)
        {
            bformatted.push_back(static_cast<uint8_t>(block[i]));
        }
        return bformatted;
    }

    /// @brief Print a vector of any integer type
    /// @param v Vector to print
    template<typename T>
    void printVector(const std::vector<T>& v) {
        for (const auto& element : v) {
            std::cout << static_cast<int>(element) << " ";
        }
        std::cout << std::endl;
    }

}

#endif // UTILS_HPP
