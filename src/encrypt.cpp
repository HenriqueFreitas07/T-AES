#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include "../include/utils.hpp"
#include "../include/AES.hpp"


using namespace std;

bool TWEAK = false;

int main(int argc, char* argv[]){

    if (argc < 3)
    {
        cout << "Required arguments: <aes_size (128 | 192 | 256)> <password> <tweak_password?>" << endl;
        return 1;
    }

    int size = atoi(argv[1]);
    if (size != 128 && size != 192 && size != 256)
    {
        cout << "AES size must be 128, 192 or 256" << endl;
        return 1;
    }
    
    const char* password = argv[2];
    const char* tweak_pwd = (argc == 4) ? argv[3] : nullptr;
    if(argc == 4){
        TWEAK=true;
    }

    vector<vector<uint8_t>> all_blocks;

    // A block has 128bit = 128/8 => 16 bytes or 16 chars
    char block[16]{};
    int current_block_size=0;
    // read all the bytes from the stdin until EOF
    while(true){
        // Use read() 
        cin.read(block, 16);
        current_block_size = static_cast<size_t>(cin.gcount());
        if(current_block_size == 0) break;
        // Process the block (even if partial)
        vector<uint8_t> converted = utils::convertToBlock(block,current_block_size);
        all_blocks.push_back(converted);
        if(current_block_size <16) break;  // EOF reached
    }

    // Set AES size
    switch (size)
    {
    case 128:
        #ifndef SIZE  
            #define SIZE 128
            #define ROUNDS 10
        #endif
        break;
    case 192:
        #ifndef SIZE 
            #define SIZE 192
            #define ROUNDS 12 
        #endif
        break;
    case 256:
        #ifndef SIZE 
            #define SIZE 256
            #define ROUNDS 14
        #endif
        break;
    default:
        break;
    }
    // Create AES object
    // Convert char* to vector<uint8_t> using vector constructor (single line!)
    vector<uint8_t> key(password, password + strlen(password));
    vector<uint8_t> tweak(tweak_pwd ? tweak_pwd : "",
                          tweak_pwd ? tweak_pwd + strlen(tweak_pwd) : nullptr);

    AES aes(SIZE, ROUNDS, key, tweak);
    vector<vector<uint8_t>> cipherBlocks;
    for (size_t i = 0; i < all_blocks.size(); i++)
    {

        vector<uint8_t> current_block= all_blocks.at(i);
        cout <<"Encrypting the following block (size "<< current_block.size() << " bytes)"<< endl;
        utils::printVector(all_blocks[i]);
        cipherBlocks.push_back(aes.encrypt_block(current_block));
    }

    cout << endl<< "Encrypted bytes:" << endl;
    for (size_t i = 0; i < cipherBlocks.size(); i++)
    {
        utils::printVector(cipherBlocks[i]);
    }
    
    return 0;
}