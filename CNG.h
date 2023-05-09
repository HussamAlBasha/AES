#include <windows.h>
#include <bcrypt.h>
using namespace std;

//   https://learn.microsoft.com/en-us/windows/win32/seccng/typical-cng-programming 
//   The typical steps involved in using the CNG API for cryptographic primitive operations are as follows :
//1) Opening the Algorithm Provider
//2) Getting or Setting Algorithm Properties
//3) Creating or Importing a Key
//4) Performing Cryptographic Operations
//5) Closing the Algorithm Provider

#pragma comment (lib, "Bcrypt.lib")
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

void generate_random_16_Byte(unsigned char key[16])
{
    BCRYPT_ALG_HANDLE hProvider;
    NTSTATUS status;
    //DWORD dwDataLen = 16; // 128-bit key length

    status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        // This might tell the adversery where is the error
        //cerr << "Error opening algorithm provider: " << hex << status << endl;
        cerr << "Error!" << endl;
        return;
    }

    status = BCryptGenRandom(hProvider, key, 16, 0);
    if (!NT_SUCCESS(status))
    {
        // This might tell the adversery where is the error
        //cerr << "Error generating random data: " << hex << status << endl;
        cerr << "Error!" << endl;
    }
    BCryptCloseAlgorithmProvider(hProvider, 0);
}


// Link: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
//The BCryptGenRandom function generates a random number.

//NTSTATUS BCryptGenRandom(
//    [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
//    [in, out] PUCHAR            pbBuffer,
//    [in]      ULONG             cbBuffer,
//    [in]      ULONG             dwFlags
//);


//Parameters:

//[in, out] hAlgorithm
//  The handle of an algorithm provider created by using the BCryptOpenAlgorithmProvider function.
//  The algorithm that was specified when the provider was created must support the random number generator interface.

//[in, out] pbBuffer
//  The address of a buffer that receives the random number
//  The size of this buffer is specified by the cbBuffer parameter.

//[in] cbBuffer
//The size, in bytes, of the pbBuffer buffer.

//[in] dwFlags
//A set of flags that modify the behavior of this function.This parameter can be zero or other values spacified on microsoft website.


//Return value

//Returns a status code that indicates the success or failure of the function.
//Possible return codes include, but are not limited to, the following.
//
//    Return code	                     Description
//    STATUS_SUCCESS                     The function was successful.
//    STATUS_INVALID_HANDLE              The handle in the hAlgorithm parameter is not valid.
//    STATUS_INVALID_PARAMETER           One or more parameters are not valid.

//BCryptGenRandom is a Windows API function used for generating random bytes using a cryptographically secure pseudo - random number generator(CSPRNG) algorithm.
//The function generates random bytes by using the CryptGenRandom function, which is a CSPRNG provided by Microsoft.
//
//A CSPRNG is a type of algorithm that generates a sequence of random numbers that appear to be random but are generated using a deterministic algorithm.
//In other words, given the same seed, a CSPRNG will always generate the same sequence of random numbers.
//However, CSPRNGs are designed in such a way that even if an attacker knows the seed, they cannot predict the next number in the sequence.
//
//CryptGenRandom uses the operating system's entropy pool as the seed to generate random numbers. 
//The entropy pool is a collection of random data collected from various sources, such as keyboard and mouse input, disk activity, and other hardware events. 
//This ensures that the generated random bytes are not predictable and are suitable for cryptographic applications.
//
//BCryptGenRandom is similar to CryptGenRandom, but it is part of the Windows Cryptography API : Next Generation(CNG) framework.
//CNG provides a unified interface to various cryptographic algorithms and services in Windows, and BCryptGenRandom is one of the many functions provided by CNG.

//Unfortunately, the source code for the BCryptGenRandom function is not publicly available.
//It is part of the Windows operating system and provided as a binary file.
//However, Microsoft provides a Software Development Kit(SDK) that includes header files and libraries necessary for developers to use the function in their applications.

