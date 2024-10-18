#include"header.h"

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

void ecb_enc(FILE* in, word *w, FILE* out){
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)    
    byte cipher[4 * Nb];   // Buffer for the encrypted block

    int bytesRead;
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        if (bytesRead < 4 * Nb) {
            pad(block, bytesRead);  // Apply padding for the last block
        }
        AES_Encrypt(block, cipher, w);  // Encrypt the block
        fwrite(cipher, 1, 4 * Nb, out);
    }
}

void ecb_dec(FILE* in, word *w, FILE* out){
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)    
    
    int bytesRead;
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
}