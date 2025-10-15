#pragma once

#include <iostream>

using namespace std;

class AES {
   string key;
   string tweak_key;


    // k_size and n_rounds not included
    public: 
    AES(string key, string tweak_key): key(key), tweak_key(tweak_key){}

    private:
    string round(string input){
        
    }

    void ShiftRows();

    void MixColumns();

    void AddRoundKey();


};