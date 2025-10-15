#pragma once

#include <iostream>

using namespace std;

class AES {
   char * key;
   int b_size;

    // k_size and n_rounds not included
    public: 
    AES(char* key, int b_size): key(key), b_size(b_size) {}

    private:
    string round(string input){
        
    }


};