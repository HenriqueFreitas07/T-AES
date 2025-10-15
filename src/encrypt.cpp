#include <iostream>

using namespace std;

int main(int argc, char* argv[]){

    if (argc < 4)
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
    
    string password = argv[2];
    string tweak_pwd = argv[3];

    string content; 
    cin >> content;

    cout << content;
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
    
    return 0;
}