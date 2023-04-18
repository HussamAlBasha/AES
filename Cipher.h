
void Cipher(unsigned char in[16], unsigned char out[16], unsigned char w[176])
{
    //we encrypt in blocks, copy content first 16 blocks to our state variable
    unsigned char state[16];
    unsigned char temp_w[16];

    //state = in
    for (int i = 0; i < 16; i++) {
        state[i] = in[i];
    }

    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[i];
    }

    AddRoundKey(state, temp_w);

    for (int i = 1; i < 10; i++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        for (int j = 0; j < 16; j++) {
            temp_w[j] = w[16 * i + j];
        }
        AddRoundKey(state, temp_w);
    }

    //last rounds
    SubBytes(state);
    ShiftRows(state);
    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[160 + i];
    }
    AddRoundKey(state, temp_w);

    for (int i = 0; i < 16; i++)
        out[i] = state[i];
}

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

    AddRoundKey(state, temp_w);      //AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) 

    for (int i = 9; i >= 1; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        for (int j = 0; j < 16; j++) {
            temp_w[j] = w[16 * i + j];
        }
        AddRoundKey(state, temp_w);
        InvMixColumns(state);            //AddRoundKey(state, w[round*Nb, (round+1)*Nb-1]);
    }

    //last rounds
    InvShiftRows(state);
    InvSubBytes(state);
    for (int i = 0; i < 16; i++) {
        temp_w[i] = w[i];
    }
    AddRoundKey(state, temp_w);        //AddRoundKey(state, w[0, Nb-1])

    for (int i = 0; i < 16; i++) {
        out[i] = state[i];
    }
}