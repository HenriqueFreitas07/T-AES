#pragma once

#include <iostream>

using namespace std;

class AES {
   string key;
   string tweak_key;


    // k_size and n_rounds not included
    public: 
    AES(string key, string tweak_key): key(key), tweak_key(tweak_key){}
    
    string encrypt(string plaintext);
    string decrypt(string ciphertext);

    private:
    string round(string input){


        return input;
    }

    // AES Operations
    void ShiftRows();
    void MixColumns();
    void AddRoundKey();
    void SubBytes();
    void KeyExpansion();
    


};