#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "AES128.h"  // Include the AES-128 header file containing required functions

// Function to apply padding for the last block
void pad(byte block[4 * Nb], int bytesRead) {
    int padding = 4 * Nb - bytesRead;
    padding = padding == 0 ? 4 * Nb : padding; //if last blcok is full length, padding = 4 * Nb
    for (int i = bytesRead; i < 4 * Nb; i++) {
        block[i] = padding;
    }
}

// Function to remove padding after decryption
int unpad(byte block[4 * Nb]) {
    int padding = block[4 * Nb - 1];
    int valid = 0;

    // Validate padding
    for (int i = 1; i <= padding; i++) {
        valid |= block[4 * Nb - i] ^ padding;
    }

    // If valid == 0, padding is correct; otherwise, it's incorrect
    return padding * (valid == 0);
}


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
    
//---------Encryption Process (CBC mode)-------------------------------------
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
        printf("Error: Unable to open cipher file for encryption.\n");
        fclose(in);
        return 1;
    }
    
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)    
    byte cipher[4 * Nb];   // Buffer for the encrypted block
    byte previousBlock[4 * Nb];  // Buffer to store the previous block for chaining
    
    // Initialize previousBlock with the IV
    memcpy(previousBlock, iv, 4 * Nb);
    fwrite(iv, 1, 4 * Nb, out);
    
    int bytesRead;
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        if (bytesRead < 4 * Nb) {
            pad(block, bytesRead);  // Apply padding for the last block
        }
        
        // XOR the block with the previous block (or IV for the first block)
        xorBlocks(block, previousBlock, block, 4 * Nb);
        
        AES_Encrypt(block, cipher, w);  // Encrypt the block
        memcpy(previousBlock, cipher, 4 * Nb);  // Store current cipher block for the next XOR
        
        fwrite(cipher, 1, 4 * Nb, out);
    }

    fclose(in);
    fclose(out);
    
//----------Decryption Process (CBC mode)-------------------------------------
    // Open input and output files for decryption
    in = fopen("cipher.txt", "rb");
    if (in == NULL) {
        printf("Error: Unable to open cipher file for decryption.\n");
        return 1;
    }
    out = fopen("out.pdf", "wb");
    if (out == NULL) {
        printf("Error: Unable to open output file.\n");
        fclose(in);
        return 1;
    }
    
    
    fread(previousBlock, 1, 4 * Nb, in);  // Initialize previous block with the first block of cipher (i.e, IV)
    
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        byte decipher[4 * Nb];
        
        AES_Decrypt(block, decipher, w);  // Decrypt the block
        
        // XOR with the previous cipher block or IV for the first block
        xorBlocks(decipher, previousBlock, decipher, 4 * Nb);
        
        if (feof(in)) {
            int padding = unpad(decipher);  // Remove padding from the last block
            fwrite(decipher, 1, 4 * Nb - padding, out);
        } else {
            fwrite(decipher, 1, 4 * Nb, out);
        }
        
        memcpy(previousBlock, block, 4 * Nb);  // Store current cipher block for the next XOR
    }

    fclose(in);
    fclose(out);
    
    return 0;
}

