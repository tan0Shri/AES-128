#include<stdio.h>
// Include AES-128 header file containing required functions
#include "AES128.h"

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

int main() {
//---------Key Generation Process---------------------------------------------
    byte key[4 * Nk] = {0x2, 0x7e, 0x15, 0x16,
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
    
    
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)    
    byte cipher[4 * Nb];   // Buffer for the encrypted block
    
    // Encrypt each block
    int bytesRead;
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        if (bytesRead < 4 * Nb) {
            pad(block, bytesRead);  // Apply padding for the last block
        }
        AES_Encrypt(block, cipher, w);  // Encrypt the block
        fwrite(cipher, 1, 4 * Nb, out);
    }

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
    

    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        byte decipher[4 * Nb];
        AES_Decrypt(block, decipher, w);  // Decrypt the block
        
        // Remove padding if end of file and adjust the number of bytes to write
        if (feof(in)) {
            int padding = unpad(decipher);  // Remove padding from the last block
            fwrite(decipher, 1, 4 * Nb - padding, out);
        } else {
            fwrite(decipher, 1, 4 * Nb, out);
        }
    }

    fclose(in);
    fclose(out);
    
    return 0;
}

