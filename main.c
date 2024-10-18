#include<stdio.h>

// Include AES-128 header file containing required functions
#include "header.h"

int main() {
//---------Key Generation Process---------------------------------------------
    byte key[4 * Nk] = {0x2a, 0x7e, 0x15, 0x16,
        		0x28, 0xae, 0xd2, 0xa6,
        		0xab, 0xf7, 0x15, 0x88,
        		0x09, 0xcf, 0x4f, 0x3c}; 
    // Initialize the key schedule (expanded keys)
    word w[Nb * (Nr + 1)];
    KeyExpansion(key, w);
    
//---------Encryption Process (ECB mode)-----------------------------------------------------
    // Open input and output files for encryption
    FILE* in = fopen("example.pdf", "r");
    if (in == NULL) {
        printf("Error: Unable to open input file.\n");
        return 1;
    }

    FILE* out = fopen("cipher.txt", "w");
    if (out == NULL) {
        printf("Error: Unable to open output file.\n");
        fclose(in);
        return 1;
    }
    
    
    ecb_enc(in, w, out);

    fclose(in);
    fclose(out);
    
//----------Decryption Process---------------------------------------------
    // Open input and output files for decryption
    in = fopen("cipher.txt", "r");
    if (in == NULL) {
        printf("Error: Unable to open input file.\n");
        return 1;
    }
    out = fopen("out.pdf", "w");
    if (out == NULL) {
        printf("Error: Unable to open output file.\n");
        fclose(in);
        return 1;
    }
    
    ecb_dec(in, w, out);
    

    fclose(in);
    fclose(out);
    
    return 0;
}

