#include<stdio.h>
#include "utility.h"

int main() {
//---------Key Generation Process---------------------------------------------
    byte key[4 * Nk] = {0x2a, 0x7e, 0x15, 0x16,
        		0x28, 0xae, 0xd2, 0xa6,
        		0xab, 0xf7, 0x15, 0x88,
        		0x09, 0xcf, 0x4f, 0x3c}; 
    // Initialize the key schedule (expanded keys)
    word w[Nb * (Nr + 1)];
    KeyExpansion(key, w);
    
    int mode;
    printf("Enter the index of mode of operations which you want to apply for encryption, decryption:\n\
    		1. ECB: Electronic Codebook mode\n\
    		2. CBC: Cipher Block Chaining mode\n\
		3. OFB: Output Feedback mode\n\
		4. CFB: Cipher Feedback\n\
		(type the number only)");
    scanf("%d",&mode);
    
    void (*enc_ptr[4])(FILE*, word*, FILE*) = {ecb_enc, cbc_enc, ofb_enc, cfb_enc};
    void (*dec_ptr[4])(FILE*, word*, FILE*) = {ecb_dec, cbc_dec, ofb_dec, cfb_dec};
    
//---------Encryption Process (ECB mode)-----------------------------------------------------
    // Open input and output files for encryption
    FILE* in = fopen("nist.fips.197.pdf", "r");
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
    
    //Caling encryption function for chosen mode
    enc_ptr[mode-1](in, w, out);

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
    
    //calling decryption function for chosen mode
    dec_ptr[mode-1](in, w, out);
    
    fclose(in);
    fclose(out);
    
    return 0;
}

