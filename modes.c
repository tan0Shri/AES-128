#include<stdlib.h>
#include<string.h>
#include<time.h>
#include"utility.h"

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

//ECB mode------------------------------------------------------------------------------------------------------------------------------------------
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

//CBC mode-------------------------------------------------------------------------------------------------------------------------------------------
// Function to XOR two blocks
void xorBlocks(byte *a, byte *b, byte *result, int length) {
    for (int i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void cbc_enc(FILE *in, word *w, FILE *out){
    byte iv[4 * Nb]; 	// Initialization vector
    // Generate a random IV
    srand((unsigned int)time(NULL));  // Seed for random number generation
    for (int i = 0; i < 4 * Nb; i++) {
        iv[i] = (byte)(rand() % 256);  // Random byte between 0 and 255
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
}

void cbc_dec(FILE *in, word *w, FILE *out){
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)  
    byte previousBlock[4 * Nb];  // Buffer to store the previous block for chaining
    
    fread(previousBlock, 1, 4 * Nb, in);  // Initialize previous block with the first block of cipher (i.e, IV)
    
    int bytesRead;
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
}

//OFB mode-------------------------------------------------------------------------------------------------------------------------------------------
void ofb_enc(FILE *in, word *w, FILE *out){
    byte iv[4 * Nb]; 	// Initialization vector
    // Generate a random IV
    srand((unsigned int)time(NULL));  // Seed for random number generation
    for (int i = 0; i < 4 * Nb; i++) {
        iv[i] = (byte)(rand() % 256);  // Random byte between 0 and 255
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
        
        xorBlocks(block, cipher, block, bytesRead);  // XOR the block with the cipher (output of encryption)
        memcpy(feedback, cipher, 4 * Nb);  // Update the feedback block
        
        fwrite(block, 1, bytesRead, out);
    }
}

void ofb_dec(FILE *in, word *w, FILE *out){
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)    
    byte cipher[4 * Nb];   // Buffer for the encrypted block
    byte feedback[4 * Nb]; // Buffer to store the feedback block
    fread(feedback, 1, 4 * Nb, in);  // Initialize feedback block with the IV
    
    int bytesRead;
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        AES_Encrypt(feedback, cipher, w);  // Encrypt the feedback block
        
        xorBlocks(block, cipher, block, bytesRead);  // XOR the block with the cipher (output of encryption)
        memcpy(feedback, cipher, 4 * Nb);  // Update the feedback block
        
        fwrite(block, 1, bytesRead, out);
    }
}

//CFB mode-----------------------------------------------------------------------------------------------------
void cfb_enc(FILE *in, word *w, FILE *out){
    byte iv[4 * Nb]; 	// Initialization vector
    // Generate a random IV
    srand((unsigned int)time(NULL));  // Seed for random number generation
    for (int i = 0; i < 4 * Nb; i++) {
        iv[i] = (byte)(rand() % 256);  // Random byte between 0 and 255
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
}

void cfb_dec(FILE *in, word *w, FILE *out){
    byte block[4 * Nb];    // Buffer for reading each block (16 bytes)
    byte cipher[4 * Nb];   // Buffer for the encrypted block
    byte feedback[4 * Nb]; // Buffer to store the feedback block
    
    fread(feedback, 1, 4 * Nb, in);  // Initialize feedback block with the IV
    
    int bytesRead;
    while ((bytesRead = fread(block, 1, 4 * Nb, in)) > 0) {
        AES_Encrypt(feedback, cipher, w);  // Encrypt the feedback block
        
        // Update the feedback block with the ciphertext (the current block)
        memcpy(feedback, block, 4 * Nb);
        
        // XOR the block with the cipher (output of encryption)
        xorBlocks(block, cipher, block, bytesRead);
        
        fwrite(block, 1, bytesRead, out);
    }
}


