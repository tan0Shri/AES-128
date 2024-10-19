#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include "utility.h"

FILE* FileOpening(char *mode){
    char file[100];
    scanf("%s", file);    
    
    FILE *f = fopen(file, mode);
    if (f == NULL) {
        printf("Error: Unable to open the file.\n");
        fclose(f);
        exit(1);
    }
    return f;
}

int main() {
//---------Key Generation Process---------------------------------------------
    byte key[4 * Nb]; 	// Initialization vector
    // Generate a random IV
    srand((unsigned int)time(NULL));  // Seed for random number generation
    for (int i = 0; i < 4 * Nb; i++) {
        key[i] = (byte)(rand() % 256);  // Random byte between 0 and 255
    }
    
    /*byte key[4 * Nk] = {0x2a, 0x7e, 0x15, 0x16,
        		0x28, 0xae, 0xd2, 0xa6,
        		0xab, 0xf7, 0x15, 0x88,
        		0x09, 0xcf, 0x4f, 0x3c}; */
        		
    // Initialize the key schedule (expanded keys)
    word w[Nb * (Nr + 1)];
    KeyExpansion(key, w);
    
    int mode;
    printf("Enter the index of mode of operations which you want to apply for encryption, decryption:\n\
    		1. ECB: Electronic Codebook mode\n\
    		2. CBC: Cipher Block Chaining mode\n\
		3. OFB: Output Feedback mode\n\
		4. CFB: Cipher Feedback\n\
		(type the index_number only)");
    scanf("%d",&mode);
    
    void (*enc_ptr[4])(FILE*, word*, FILE*) = {ecb_enc, cbc_enc, ofb_enc, cfb_enc};
    void (*dec_ptr[4])(FILE*, word*, FILE*) = {ecb_dec, cbc_dec, ofb_dec, cfb_dec};
    
//---------Encryption Process (ECB mode)-----------------------------------------------------
    // Open input and output files for encryption
    printf("Enter the filename which you want to encrypt: ");
    FILE* in = FileOpening("rb");
    
    printf("Enter filename to which you want to store the cipher text (encrypted text): ");
    FILE* out = FileOpening("wb");
    
    //Caling encryption function for chosen mode
    enc_ptr[mode-1](in, w, out);

    fclose(in);
    fclose(out);
    
//----------Decryption Process---------------------------------------------
    // Open input and output files for decryption
    printf("Enter filename which you want to decrypt: ");
    in = FileOpening("rb");
    
    printf("Enter filename which you want to store the decrypted text: ");
    out = FileOpening("wb");
    
    //calling decryption function for chosen mode
    dec_ptr[mode-1](in, w, out);
    
    fclose(in);
    fclose(out);
    
    return 0;
}

