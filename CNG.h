#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <ntstatus.h>
using namespace std;

//https://learn.microsoft.com/en-us/windows/win32/seccng/typical-cng-programming 
// 
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

    if (NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RNG_ALGORITHM, NULL, 0)))
    {
        status = BCryptGenRandom(hProvider, key, 16, 0);
        BCryptCloseAlgorithmProvider(hProvider, 0);
    }
    else
    {
        cerr << "Error opening algorithm provider: " << hex << status << endl;
    }
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
//A set of flags that modify the behavior of this function.This parameter can be zero or the following value.