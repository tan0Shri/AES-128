//For AES algorithm, irreducible polynomial is: x^8 + x^4 + x^3 + x +1

#include<stdio.h>
#include<stdint.h>
#define Nb 4 // Number of columns (32-bit words) comprising the State
#define Nr 10 // Number of rounds, for 128-bit key it's 10
#define Nk 4  // Number of 32-bit keywords 

typedef uint8_t byte;

//defining structure for 32-bit (= 4bytes) word as an array of 4 bytes
typedef struct{
    byte bytes[4];
    }word;
    
#include"utilities.h"
    
//KeyExpansion(): Function that generates a total Nb(Nr+1) words: Nb words for initital key and for each Nr rounds Nb words   
void KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)]){
    word temp;
    int i=0;
    
    //Initial key setup
    while (i < Nk) {
        w[i].bytes[0] = key[4*i];
        w[i].bytes[1] = key[4*i+1];
        w[i].bytes[2] = key[4*i+2];
        w[i].bytes[3] = key[4*i+3];
        i++;
    }
    
    //Key Expansion for next Nr rounds
    i=Nk;
    while(i < Nb*(Nr+1)){
        temp = w[i-1];
        if(i % Nk == 0){
            temp = SubWord(RotWord(temp));
            XorWords(&temp, &Rcon[i/Nk], &temp);
        }
        else if (Nk > 6 && i % Nk == 4)
            temp = SubWord(temp);
        XorWords(&w[i-Nk], &temp, &w[i]);
        i++;
    }
    
}

// Cipher function
void Cipher(byte in[4 * Nb], byte out[4 * Nb], const word w[Nb * (Nr + 1)]){
    byte state[4][Nb];
    
    //copy input to state array
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            state[i][j] = in[i + 4 * j];
    }
    
    // Initial round key addition
    AddRoundKey(state, w);
    
    //Nr-1 rounds
    for (int round = 1; round < Nr; round++){
        SubBytes(state);
        ShiftRows(state);
        Mixcolumns(state);
        AddRoundKey(state, w + round * Nb);
    }
    
    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w + Nr * Nb);
    
    // Copy state array to output
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            out[i + 4 * j] = state[i][j];
    }
    
}

// Inverse Cipher function
void InvCipher(byte in[4 * Nb], byte out[4 * Nb], const word w[Nb * (Nr + 1)]){
    byte state[4][Nb];
    
    //copy input to state array
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            state[i][j] = in[i + 4 * j];
    }
    
    // Initial round key addition
    AddRoundKey(state, w + Nr * Nb);
    
    //Nr-1 rounds
    for (int round = Nr - 1; round >= 1; round--){
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w + round * Nb);
        InvMixcolumns(state);
    }
    
    // Final round (no MixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w);
    
    // Copy state array to output
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            out[i + 4 * j] = state[i][j];
    }
    
}

int main() {
    byte msg[4 * Nb] = {0x32, 0x43, 0xf6, 0xa8,
        		0x88, 0x5a, 0x30, 0x8d,
        		0x31, 0x31, 0x98, 0xa2, 
        		0xe0, 0x37, 0x07, 0x34};
    byte cipher[4 * Nb];
    byte key[4 * Nk] = {0x2b, 0x7e, 0x15, 0x16,
        		0x28, 0xae, 0xd2, 0xa6,
        		0xab, 0xf7, 0x15, 0x88,
        		0x09, 0xcf, 0x4f, 0x3c};

    word w[Nb * (Nr + 1)];
    KeyExpansion(key, w);

    /*// Print expanded keys for testing
    for (int i = 0; i < Nb * (Nr + 1); i++) {
        printf("w[%d] = %02hhx%02hhx%02hhx%02hhx\n", i, w[i].bytes[0], w[i].bytes[1], w[i].bytes[2], w[i].bytes[3]);
    }
    */
    Cipher(msg, cipher, w);
    
    // Output the encrypted data
    printf("Encrypted Cipher: ");
    for (int i = 0; i < 4 * Nb; ++i) {
        printf("%02x ", cipher[i]);
    }
    printf("\n");
    
    byte Dec_msg[4 * Nb];
    InvCipher(cipher, Dec_msg, w);
    
    // Output the decrypted cipher
    printf("Decrypted message: ");
    for (int i = 0; i < 4 * Nb; ++i) {
        printf("%02x ", Dec_msg[i]);
    }
    printf("\n");
    

    return 0;
}
