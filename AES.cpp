#include <iostream>
#include <cstring>
#include "AES.h"
#include "CNG.h"
#include "Padding.h"
#include "Cipher.h"
#include <memory>

using namespace std;
int block_size = 16;
unsigned char key[16];
unsigned char IV[16];
unsigned char expandedKeys[176];
int global_size=0;
int main() {

    //INITIALISE KEYS AND MESSAGES

   
    const int MAX_SIZE = 50; // maximum size of the static array
   
    int size = 0; // size of the input message
    int max_size = MAX_SIZE; // this is our buffer. as to solve the buffer overflow issue with user-input

    unsigned char message_s[50]; // dynamic array to hold the input message
    cout << "fill your array, press enter when done: ";
    // fill the static array with the input message
    int c;

    try {
        int i = 0;
        while ((c = cin.get()) != EOF && c != '\n' && size < max_size) {
            size++;
            global_size++;
            if (size >= max_size) {
                throw std::runtime_error("Message size error, do not attempt buffer overflow.");
            }
            message_s[i] = c;
            i += 1;
        }
    }
    
  
    catch (const std::runtime_error& e) { //catch the thrown error
        cout << endl << e.what() << endl;
        std::exit(1);
    }
   

  
    unique_ptr<unsigned char[]> message(new unsigned char[global_size]);

    memcpy(message.get(), message_s, global_size);

 



    generate_random_16_Byte(key);
    generate_random_16_Byte(IV);
    KeyExpansion(key, expandedKeys);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // I: Padding the message

    //int message_length = sizeof(message);
    int message_length = size;
    int padded_length = message_length + block_size - (message_length % block_size);
    //unsigned char* padded_message = new unsigned char[padded_length];
    unique_ptr<unsigned char[]> padded_message(new unsigned char[padded_length]);
    PKCS_7(message.get(), message_length, block_size, padded_length, padded_message.get());

    // Padding done!

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //printing initial information

    cout << "You entered: ";
    for (int i = 0; i < size; i++) {
        cout << message[i];
    }
    cout << endl;

    cout << endl << "Original Generated Random key before expansion: ";
    print_hex(key, sizeof(key));
    cout << "\n" << endl;

    cout << endl << "Generated Random IV                           : ";
    print_hex(IV, sizeof(IV));
    cout << "\n" << endl;

    cout << endl;
    cout << "Message with no padding : ";
    print_hex(message.get(), size);
    cout << "\n" << endl;
    cout << "Message with padding    : ";
    print_hex(padded_message.get(), padded_length);
    cout << "\n" << endl;

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // II: Encryption
    
    unsigned char temp[16];

    generate_random_16_Byte(IV);
    unique_ptr<unsigned char[]> blinding_factor(new unsigned char[padded_length]);
    generate_random_16_Byte(blinding_factor.get());

    for (int i = 0; i < 16; i++)
    {
        temp[i] = padded_message[i] ^ IV[i];                          // temp = m[1] ⊕ IV 
        temp[i] = temp[i] ^ blinding_factor[i];
    }

    //unsigned char* encrypted_message = new unsigned char[padded_length];
    unique_ptr<unsigned char[]> encrypted_message(new unsigned char[padded_length]);

    Cipher(temp, encrypted_message.get(), expandedKeys);
    // Flush the cache for the entire array
    FlushInstructionCache(GetCurrentProcess(), encrypted_message.get(), padded_length);
    FlushInstructionCache(GetCurrentProcess(), expandedKeys, 176);
    
    if (padded_length > 16)
    {
        for (int j = 0; j < 16; j++)                                          // take C1 to propagate it forward
        
            temp[j] = padded_message[j + 16] ^ encrypted_message[j] ^ blinding_factor[j + 16];        // ADDED BLINDING 

        
    }
    for (int i = 16; i < padded_length; i += 16)
    {
        Cipher(temp, encrypted_message.get() + i, expandedKeys);            // c[i] = encrypted_message[i]  
        FlushInstructionCache(GetCurrentProcess(), encrypted_message.get(), padded_length);
        FlushInstructionCache(GetCurrentProcess(), expandedKeys, 176);
        for (int j = 0; j < 16; j++)
        {
            temp[j] = padded_message[i + j + 16] ^ encrypted_message[i + j];  // temp = m[3] ⊕ c[2] ...  
            temp[j] = blinding_factor[j + i] ^ temp[j];//add blinding
        }


    }

    cout << "Encrpyted message       : ";
    print_hex(encrypted_message.get(), padded_length);
    cout << "\n" << endl;

    // Encryption done!

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

     // III: Decryption:

    //unsigned char* decrypted_message = new unsigned char[padded_length];
    unique_ptr<unsigned char[]> decrypted_message(new unsigned char[padded_length]);

    InvCipher(encrypted_message.get(), temp, expandedKeys);


    for (int i = 0; i < 16; i++)
        decrypted_message[i] = temp[i] ^ IV[i] ^ blinding_factor[i]; //added blinding

    for (int i = 0; i < padded_length-16; i += 16)
    {
        InvCipher(encrypted_message.get() + i + 16, decrypted_message.get() + i + 16, expandedKeys);      //c[i] = encrypted_message[i]
        FlushInstructionCache(GetCurrentProcess(), decrypted_message.get(), padded_length);
        FlushInstructionCache(GetCurrentProcess(), expandedKeys, 176);
        for (int j = 0; j < 16; j++)
            decrypted_message[i + 16 + j] = decrypted_message[i + 16 + j] ^ encrypted_message[i + j] ^ blinding_factor[i+j+16];

    }

    cout << "Decrypted message       : ";
    print_hex(decrypted_message.get(), padded_length);
    cout << "\n" << endl;

    cout << "Decrypted message that you entered: ";
    for (int i = 0; i < size; i++) {
        cout << hex<< decrypted_message[i];
    }
    cout << endl;

    // Decryption done!

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
   



   
    


    return 0;
}

//unsigned char message[] = "This is a test for AES with CBC that requirs padding. Padding can be done in various ways, but the most secure way of padding in CBC is using the PKCS#7 padding scheme";
//unsigned char key[16]   = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
//unsigned char IV [16]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
// unsigned char message[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
//                            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
//                            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
//                            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };