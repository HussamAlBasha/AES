#include <iostream>
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
int global_size = 0;
const int MAX_SIZE = 1024; // Maximum size of the static array

void clearInputBuffer()
{
    while (std::cin.get() != '\n')
    {
        continue;
    }
}

int main() {

    cout << "Type your message. Should not exceed " << MAX_SIZE << " characters. Press enter when done." << endl;
    cout << "Note that spaces and '.' and ',' are counted as characters as well." << endl;
    cout << "\n";

    while (true) {
        start_of_loop:
        //INITIALISE KEYS AND MESSAGES           
        int size = 0;                                 // Size of the input message
        int max_size = MAX_SIZE;                      // This is our buffer. As to solve the buffer overflow issue with user-input

        //unsigned char message_s[50]; // Array to hold the input message
        // We should initialize
        unsigned char message_s[MAX_SIZE] = { 0 };

        cout <<"\n" <<">> ";
        // Fill the static array with the input message
        unsigned char c;
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
            //std::exit(1);
            clearInputBuffer();
            cout << "Try to type your message again with a size within the boundary."<< endl;
            goto start_of_loop;
        }

        // Advantages of unique_ptr  stated below
        unique_ptr<unsigned char[]> message(new unsigned char[global_size]);
        //Copy efficiently the input message block of memoryto a destination location allocated using the smart unique_ptr
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
        // Advantages of unique_ptr  stated below
        unique_ptr<unsigned char[]> padded_message(new unsigned char[padded_length]);
        PKCS_7(message.get(), message_length, block_size, padded_length, padded_message.get());

        // Padding done!

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        //printing initial information
        cout << endl;
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

        // We should initialize
        unsigned char temp[16] = { 0 };

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
            {
                temp[j] = padded_message[j + 16] ^ encrypted_message[j] ^ blinding_factor[j + 16];        // ADDED BLINDING
            }

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

        for (int i = 0; i < padded_length - 16; i += 16)
        {
            InvCipher(encrypted_message.get() + i + 16, decrypted_message.get() + i + 16, expandedKeys);      //c[i] = encrypted_message[i]
            FlushInstructionCache(GetCurrentProcess(), decrypted_message.get(), padded_length);
            FlushInstructionCache(GetCurrentProcess(), expandedKeys, 176);
            for (int j = 0; j < 16; j++)
                decrypted_message[i + 16 + j] = decrypted_message[i + 16 + j] ^ encrypted_message[i + j] ^ blinding_factor[i + j + 16];
        }

        cout << "Decrypted message       : ";
        print_hex(decrypted_message.get(), padded_length);
        cout << "\n" << endl;

        cout << "Decrypted message that you entered: ";
        for (int i = 0; i < size; i++) {
            cout << hex << decrypted_message[i];
        }
        cout << "\n" << endl;

        // Decryption done!

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        cout << "If you want to continue type 'yes' or 'y'. If you type anything else you will exit. \n" << endl;
        cout << ">> ";
        string input;
        cin >> input;

        if (input == "yes" or input=="y") {
            clearInputBuffer();
            continue;
        }
        else {
            break;
        }

    }
}

// Using unique_ptr in encryption implementations can provide several advantages over raw pointers :
//
// Memory safety: unique_ptr provides automatic memory management, which ensures that the allocated memory is automatically released when it is no longer needed.
// This can help prevent memory leaks and other memory - related errors that can occur when using raw pointers.
//
// Exception safety: unique_ptr supports exception - safe programming, which means that in case of an exception, the allocated memory is automatically released.
// This can help prevent memory leaks and other errors that can occur when an exception is thrown.
//
// Improved readability: unique_ptr can improve the readability of code by making it easier to understand the ownership semantics of a pointer.
// By explicitly stating that a pointer is unique and that it manages the lifetime of the allocated memory, it can make the code more self - documenting.
//
// Avoidance of dangling pointers : unique_ptr can help avoid the use of dangling pointers.
// Dangling pointers are pointers that point to an object that has been deleted, or to memory that has been deallocated.
// Using unique_ptr ensures that the memory is automatically deleted when the unique_ptr goes out of scope or is explicitly deleted.