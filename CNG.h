#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <ntstatus.h>
using namespace std;
#pragma comment (lib, "Bcrypt.lib")
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

void generate_random_16_Byte(unsigned char key[16])
{
    BCRYPT_ALG_HANDLE hProvider;
    NTSTATUS status;
    DWORD dwDataLen = 16; // 128-bit key length

    if (NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RNG_ALGORITHM, NULL, 0)))
    {
        status = BCryptGenRandom(hProvider, key, dwDataLen, 0);
        BCryptCloseAlgorithmProvider(hProvider, 0);
    }
    else
    {
        cerr << "Error opening algorithm provider: " << hex << status << endl;
    }
}