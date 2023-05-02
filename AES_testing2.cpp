//note
/*
Copies "numBytes" bytes from address "from" to address "to"
void * memcpy(void *to, const void *from, size_t numBytes);*/
#include <iostream>
#include <cstring>
#include "AES.h"
//#include "CNG.h"
#include "Padding.h"
//#include "GenRandom.h"
#include "Cipher.h"
using namespace std;
unsigned char expandedKeys[176];

void monte_carlo_test(unsigned char key[16], unsigned char iv[16], unsigned char plaintext[16], int keylen) {
    unsigned char pt[1001][16], ct[1001][16];//plain and cypher text holders

    //below are place holders for final cypher text values because the index j goes out of scope
    unsigned char final_ct [16];//last cypher text (indexed ct[999])
    unsigned char before_final_ct[16];//before last cypher text (indexed ct[998])

    unsigned char pt_iv[16];//place holder for iv xor plain text

    memcpy(pt[0], plaintext, 16);//copy plaintext into pt[0]
    

    for (int i = 0; i < 3; i++) {
        cout<<"key: ";print_hex(key, 16 );cout<<endl;
        cout<<"iv:  ";print_hex(iv, 16);cout<<endl;
        cout<<"pt:  ";print_hex(pt[0], 16);cout<<endl;
        KeyExpansion(key, expandedKeys);
        for (int j = 0; j < 1000; ++j) {

            if (j == 0) {

                for (int p = 0; p < 16; p++)

                   { 
                    pt_iv[p] = pt[0][p] ^ iv[p]; 
                   } 

                Cipher(pt_iv, ct[j], expandedKeys);//CT[j] = AES(Key[i], IV[i], PT[j])

                memcpy(pt[j+1], iv, 16);//PT[j+1] = IV[i]
            } 
            else {

                iv=ct[j-1];

                for (int p = 0; p < 16; p++)

                  {
                    pt_iv[p] = pt[j][p] ^ iv[p]; 
                  }  

                Cipher(pt_iv, ct[j],expandedKeys);
               
                memcpy(pt[j+1], ct[j-1], 16);
               

            }
            if (j==999) 

                memcpy(final_ct,ct[999],16);

            if (j==998) 

                memcpy(before_final_ct,ct[998],16);    

        }
        cout<<"ct:  ";print_hex(final_ct, 16);cout<<endl<<endl;

            if (keylen == 128) {
                for (int k = 0; k < 16; ++k) {
                    key[k] =key[k]^final_ct[k];
                    
                }

             memcpy(iv,final_ct,16);//IV[i+1] = CT[j]
             
             memcpy(pt[0],before_final_ct,16);//PT[0] = CT[j-1]
        }
        
    }

}
int main() {
    //for cummulative testing of 3 phases
    unsigned char key[16] = {0x9d, 0xc2, 0xc8, 0x4a, 0x37, 0x85, 0x0c, 0x11, 0x69, 0x98, 0x18, 0x60, 0x5f, 0x47, 0x95, 0x8c};
    unsigned char iv[16] = {0x25, 0x69, 0x53, 0xb2, 0xfe, 0xab, 0x2a, 0x04, 0xae, 0x01, 0x80, 0xd8, 0x33, 0x5b, 0xbe, 0xd6};
    unsigned char plaintext[16] = {0x2e, 0x58, 0x66, 0x92, 0xe6, 0x47, 0xf5,0x02,0x8e,0xc6,0xfa,0x47,0xa5,0x5a,0x2a,0xab};
    monte_carlo_test(key,iv,plaintext,128);


    // //for cumulative testing of 100 phases
    // unsigned char key[16] = {0x88,0x09,0xe7,0xdd,0x3a,0x95,0x9e,0xe5,0xd8,0xdb,0xb1,0x3f,0x50,0x1f,0x22,0x74};
    // unsigned char iv[16] = {0xe5,0xc0,0xbb,0x53,0x5d,0x7d,0x54,0x57,0x2a,0xd0,0x6d,0x17,0x0a,0x0e,0x58,0xae};
    // unsigned char plaintext[16] = {0x1f,0xd4,0xee,0x65,0x60,0x3e,0x61,0x30,0xcf,0xc2,0xa8,0x2a,0xb3,0xd5,0x6c,0x24};
    // monte_carlo_test(key,iv,plaintext,128);
}