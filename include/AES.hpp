#pragma once

#include <iostream>
#include <vector>
#include <string>   

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
    // Do they all need the state matrix as input?
    void ShiftRows(vector<vector<unsigned char>>& matrix);
    void MixColumns(vector<vector<unsigned char>>& matrix);
    void AddRoundKey(vector<vector<unsigned char>>& matrix);
    void SubBytes(vector<vector<unsigned char>>& matrix);
    void KeyExpansion();
    


};