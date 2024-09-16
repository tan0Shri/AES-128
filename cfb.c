#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "AES128.h"  // Include the AES-128 header file containing required functions

// Function to XOR two blocks
void xorBlocks(byte *a, byte *b, byte *result, int length) {
    for (int i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}

int main() {
    //---------Key Generation Process---------------------------------------------
    byte key[4 * Nk] = {0x2, 0x7e, 0x15, 0x16,
                        0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c}; 
    // Initialize the key schedule (expanded keys)
    word w[Nb * (Nr + 1)];
    KeyExpansion(key, w);
    
//---------Encryption Process (CFB mode)-------------------------------------
    byte iv[4 * Nb]; 	// Initialization vector
    // Generate a random IV
    srand((unsigned int)time(NULL));  // Seed for random number generation
    for (int i = 0; i < 4 * Nb; i++) {
        iv[i] = (byte)(rand() % 256);  // Random byte between 0 and 255
    }

    // Open input and output files for encryption
    FILE* in = fopen("example.pdf", "rb");
    if (in == NULL) {
        printf("Error: Unable to open input file.\n");
        return 1;
    }

    FILE* out = fopen("cipher.txt", "wb");
    if (out == NULL) {
        printf("Error: Unable to open output file.\n");
        fclose(in);
        return 1;
    }
    
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)
    byte cipher[4 * Nb];   // Buffer for the encrypted block
    byte feedback[4 * Nb]; // Buffer to store the feedback block
    
    // Initialize feedback with the IV
    memcpy(feedback, iv, 4 * Nb);
    fwrite(iv, 1, 4 * Nb, out);
    
    int bytesRead;
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        AES_Encrypt(feedback, cipher, w);  // Encrypt the feedback block
        
        // XOR the block with the cipher (output of encryption)
        xorBlocks(block, cipher, block, bytesRead);
        
        // Update the feedback block with the ciphertext (the current block)
        memcpy(feedback, block, 4 * Nb);
        
        fwrite(block, 1, bytesRead, out);
    }

    fclose(in);
    fclose(out);
    
//----------Decryption Process (CFB mode)-------------------------------------
    // Open input and output files for decryption
    in = fopen("cipher.txt", "rb");
    if (in == NULL) {
        printf("Error: Unable to open input file.\n");
        return 1;
    }
    out = fopen("out.pdf", "wb");
    if (out == NULL) {
        printf("Error: Unable to open output file.\n");
        fclose(in);
        return 1;
    }
    
    fread(feedback, 1, 4 * Nb, in);  // Initialize feedback block with the IV
    
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        AES_Encrypt(feedback, cipher, w);  // Encrypt the feedback block
        
        // Update the feedback block with the ciphertext (the current block)
        memcpy(feedback, block, 4 * Nb);
        
        // XOR the block with the cipher (output of encryption)
        xorBlocks(block, cipher, block, bytesRead);
        
        fwrite(block, 1, bytesRead, out);
    }

    fclose(in);
    fclose(out);
    
    return 0;
}

