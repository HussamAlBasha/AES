// Nb = 4 words(16 bytes/unsigned chars). 
// Number of columns (32-bit words) comprising the State.
// Nr = 10
// Number of rounds.

//   Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])

void Cipher(unsigned char in[16], unsigned char out[16], unsigned char w[176])
{
    // We encrypt in blocks. Copy  the content of the first 16 blocks to our state variable
    unsigned char state[16];
    unsigned char temp_w[16];

    // state = in
    for (int i = 0; i < 16; i++) {
        state[i] = in[i];
    }

    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[i];
    }

    AddRoundKey(state, temp_w);             // AddRoundKey(state, w[0, Nb - 1])

    // For round = 1 to 1 to round = 9
    for (int i = 1; i < 10; i++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        for (int j = 0; j < 16; j++) {
            temp_w[j] = w[16 * i + j];
        }
        AddRoundKey(state, temp_w);         // AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
    }

    // Last round. Round =10
    SubBytes(state);
    ShiftRows(state);
    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[160 + i];
    }
    AddRoundKey(state, temp_w);             // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    
    for (int i = 0; i < 16; i++)
        out[i] = state[i];
}

//   InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])

void InvCipher(unsigned char in[16], unsigned char out[16], unsigned char w[176]) {

    unsigned char state[16];
    unsigned char temp_w[16];

    //state = in
    for (int i = 0; i < 16; i++) {
        state[i] = in[i];
    }

    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[160 + i];
    }

    AddRoundKey(state, temp_w);          // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) 

    for (int i = 9; i >= 1; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        for (int j = 0; j < 16; j++) {
            temp_w[j] = w[16 * i + j];
        }
        AddRoundKey(state, temp_w);
        InvMixColumns(state);            // AddRoundKey(state, w[round*Nb, (round+1)*Nb-1]);
    }

    // Last round
    InvShiftRows(state);
    InvSubBytes(state);
    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[i];
    }
    AddRoundKey(state, temp_w);          // AddRoundKey(state, w[0, Nb-1])

    for (int i = 0; i < 16; i++) {
        out[i] = state[i];
    }
}