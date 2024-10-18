#include"header.h"
    
//AES S-box: array containing substitution values for the byte xy (in hex format)
const byte SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

//AES inverse S-box
const byte InvSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//KeyExpansion

//RotWord() : Function that performs a cyclic permutation i.e., on input [a_i, a_i+1, a_i+2, a_i+3] ouputs [a_i+1, a_i+2, a_i+3, a_i]
word RotWord(word w) {
    word result;
    result.bytes[0] = w.bytes[1];
    result.bytes[1] = w.bytes[2];
    result.bytes[2] = w.bytes[3];
    result.bytes[3] = w.bytes[0];
    return result;
}

//SubWord(): Function on four-byte input word, it applies the S-box
word SubWord(word w) {
    word result;
    result.bytes[0] = SBox[w.bytes[0]];
    result.bytes[1] = SBox[w.bytes[1]];
    result.bytes[2] = SBox[w.bytes[2]];
    result.bytes[3] = SBox[w.bytes[3]];
    return result;
}

//Rcon: Round Constant word-array containing [x^(i-1),{00},{00},{00}] with x^(i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
word Rcon[] = {
    {0x00, 0x00, 0x00, 0x00}, {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00}, {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00}, {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00}, {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00}, {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00}
};

//XorWords(): Function that produce XOR between two 32-bit words
void XorWords(word *a, word *b, word *result) {
    for (int i = 0; i < 4; i++) {
        result->bytes[i] = a->bytes[i] ^ b->bytes[i];
    }
}

//KeyExpansion(): Function that generates a total Nb(Nr+1) words: Nb words for initital key and for each Nr rounds Nb words   
void KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)]){
    word temp;  // Temporary variable for intermediate calculations
    int i=0; 	// Index for traversing through the key and expanded key array
    
    //Initial key setup: copying the initial key into the first Nk words of the expanded key array w[]
    while (i < Nk) {
        w[i].bytes[0] = key[4*i];	// Set the first byte of the ith word
        w[i].bytes[1] = key[4*i+1];	// Set the second byte of the ith word
        w[i].bytes[2] = key[4*i+2];	// Set the third byte of the ith word
        w[i].bytes[3] = key[4*i+3];	// Set the fourth byte of the ith word
        i++; // Move to the next word
    }
    
    //Key Expansion for next Nr rounds
    i=Nk;
    while(i < Nb*(Nr+1)){
        temp = w[i-1];	// Copy the previous word
        
        // Check if we need to apply the Rcon and SubWord transformations
        if(i % Nk == 0){
            temp = SubWord(RotWord(temp));
            XorWords(&temp, &Rcon[i/Nk], &temp);
        }
        // If Nk > 6 and the word index is at a specific position, apply SubWord transformation
        else if (Nk > 6 && i % Nk == 4){
            temp = SubWord(temp);
        }
        // XOR the word with the word Nk steps before it and store it in the expanded key array
        XorWords(&w[i-Nk], &temp, &w[i]);
        i++; // Move to the next word
    }
    
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------

//AddRoundKey function:
void AddRoundKey( byte state[4][Nb], const word roundKey[Nb]){
    for (int c = 0; c <Nb; c++){
        for(int r = 0; r < 4; r++)
            state[r][c] ^= roundKey[c].bytes[r];
        }
}
//Function to multiply a 8-bits number by {02}
byte xtimes(byte num) {
    byte result = num << 1;  // Shift left by 1 (equivalent to multiplying by 2)
    
    // Mask for the most significant bit (MSB) and compute conditional XOR
    byte msb_mask = (num & 0x80) >> 7;  // Extract MSB and shift it to the LSB position
    byte xor_value = msb_mask * 0x1B;   // If MSB is 1, xor_value is 0x1B, else it's 0x00
    
    result ^= xor_value;  // Apply the XOR operation if needed
    
    return result;
}

//---------------------------------------------------------------------------------------------------------------------------------------------------------------
//Encryption
//SubBytes(): Function on four-byte input word, it applies the S-box
word SubBytes(byte state[4][Nb]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            state[r][c] = SBox[state[r][c]];	// Substitute each byte using the S-Box
        }
    }
}

//ShiftRows():
void ShiftRows(byte state[4][Nb]){
    byte temp[4];
    for (int r = 1; r < 4; r++){
        for (int c = 0; c < Nb; c++)
            temp[c] = state[r][(c + r) % Nb];	// Shift row elements based on row index
        for (int c = 0; c < Nb; c++)
            state[r][c] = temp[c];	// Write shifted values back to the state matrix
         } 
}

//Mixcolumns(): 
void Mixcolumns(byte state[4][Nb]){
    byte temp[4];
    for (int c = 0; c < Nb; c++) {
        // Perform the MixColumns operation for each column
        temp[0] = xtimes(state[0][c]) ^ ((state[1][c]) ^ xtimes(state[1][c])) ^ state[2][c] ^ state[3][c];
        temp[1] = state[0][c] ^ xtimes(state[1][c]) ^ (state[2][c] ^ xtimes(state[2][c])) ^ state[3][c];
        temp[2] = state[0][c] ^ state[1][c] ^ xtimes(state[2][c]) ^ (state[3][c] ^ xtimes(state[3][c]));
        temp[3] = (state[0][c] ^ xtimes(state[0][c])) ^ state[1][c] ^ state[2][c] ^ xtimes(state[3][c]);
        
        // Copy the mixed column back to the state matrix
        for (int i = 0; i < 4; i++) {
            state[i][c] = temp[i];
        }
    }
}

// Encryption function
void AES_Encrypt(byte in[4 * Nb], byte out[4 * Nb], const word w[Nb * (Nr + 1)]){
    byte state[4][Nb];	// 4xNb matrix to hold the state of the AES algorithm
    
    //copy input to state array
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            state[i][j] = in[i + 4 * j];  // Map input bytes to state matrix
    }
    
    // Initial round key addition
    AddRoundKey(state, w);
    
    //Main Nr-1 rounds
    for (int round = 1; round < Nr; round++){
        SubBytes(state);	// Substitute bytes using the S-Box
        ShiftRows(state);	// Perform row shifts
        Mixcolumns(state);	// Mix columns (provide diffusion)
        AddRoundKey(state, w + round * Nb);	// XOR state with the round key
    }
    
    // Final round (no MixColumns)
    SubBytes(state);	// Substitute bytes using the S-Box
    ShiftRows(state);	// Perform row shifts
    AddRoundKey(state, w + Nr * Nb);	// XOR state with the final round key
    
    // Copy state array to output
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            out[i + 4 * j] = state[i][j];  // Map state matrix to output block
    }
    
}

//---------------------------------------------------------------------------------------------------------------------------------------------------------

//Decryption

//InvSubBytes(): Function on four-byte input word, it applies the Inv S-box (this step reverses the byte substitution done during encryption )
word InvSubBytes(byte state[4][Nb]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            state[r][c] = InvSBox[state[r][c]];	//// Substitute each byte in the state with its inverse S-box value
        }
    }
}

//InvShiftRows(): Reverses the row shifts applied during encryption (this step undoes the row shifting done in encryption by shifting the rows to the right instead of the left)
void InvShiftRows(byte state[4][Nb]){
    byte temp[4];	// Temporary buffer to hold shifted row values
    for (int r = 1; r < 4; r++)	//Row 0 remains unchanged
    {
        for (int c = 0; c < Nb; c++)
            // Shift row r to the right by r positions
            temp[c] = state[r][(c - r + Nb) % Nb];
        
        // Copy the shifted row back to the state
        for (int c = 0; c < Nb; c++)
            state[r][c] = temp[c];
         } 
}


//Function to multiply a 8-bits number by {09} in GF(2^8)
byte MultBy_09(byte num){
    return xtimes(xtimes(xtimes(num))) ^ num;
}

//Function to multiply a 8-bits number by {0b} in GF(2^8)
byte MultBy_0b(byte num){
    return xtimes(xtimes(xtimes(num))) ^ xtimes(num) ^ num;
}

//Function to multiply a 8-bits number by {0d} in GF(2^8)
byte MultBy_0d(byte num){
    return xtimes(xtimes(xtimes(num))) ^ xtimes(xtimes(num)) ^ num;
}

//Function to multiply a 8-bits number 08by {0e} in GF(2^8)
byte MultBy_0e(byte num){
    return xtimes(xtimes(xtimes(num))) ^ xtimes(xtimes(num)) ^ xtimes(num);
}


//InvMixcolumns(): Performs the inverse MixColumns transformation
void InvMixcolumns(byte state[4][Nb]){
    byte temp[4]; 	// Temporary buffer to store the transformed values
    for (int c = 0; c < Nb; c++) {
        // Multiply the column's bytes by {0e}, {0b}, {0d}, and {09} as defined in AES for inverse MixColumns
        temp[0] = MultBy_0e(state[0][c]) ^ MultBy_0b(state[1][c]) ^ MultBy_0d(state[2][c]) ^ MultBy_09(state[3][c]);
        temp[1] = MultBy_09(state[0][c]) ^ MultBy_0e(state[1][c]) ^ MultBy_0b(state[2][c]) ^ MultBy_0d(state[3][c]);
        temp[2] = MultBy_0d(state[0][c]) ^ MultBy_09(state[1][c]) ^ MultBy_0e(state[2][c]) ^ MultBy_0b(state[3][c]);
        temp[3] = MultBy_0b(state[0][c]) ^ MultBy_0d(state[1][c]) ^ MultBy_09(state[2][c]) ^ MultBy_0e(state[3][c]);
        
        // Store the transformed column back into the state
        for (int i = 0; i < 4; i++) {
            state[i][c] = temp[i];
        }
    }
}

// Decryption function
void AES_Decrypt(byte in[4 * Nb], byte out[4 * Nb], const word w[Nb * (Nr + 1)]){
    byte state[4][Nb];
    
    //copy input to state array
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            state[i][j] = in[i + 4 * j];
    }
    
    // Initial round key addition: the inverse of the final AddRoundKey step in encryption
    AddRoundKey(state, w + Nr * Nb);
    
    //Perform Nr-1 rounds of decryption
    for (int round = Nr - 1; round >= 1; round--){
        InvShiftRows(state);	//Inverse ShiftRows - Undoing the row shifting
        InvSubBytes(state);	//Inverse SubBytes - Applying the inverse S-Box to each byte
        AddRoundKey(state, w + round * Nb);	// Add the round key for this round
        InvMixcolumns(state);	//Inverse MixColumns - Undoing the column mixing (not in final round)
    }
    
    // Final round (no MixColumns)
    InvShiftRows(state); 	// Undo ShiftRows for final round
    InvSubBytes(state);		// Apply inverse S-Box for final round
    AddRoundKey(state, w);	// Add the initial round key
    
    // Copy state array to output
    for( int i = 0; i < 4; i++){
        for (int j = 0; j < Nb; j++)
            out[i + 4 * j] = state[i][j];
    }
    
}
//---------------------------------------------------------------------------------------------------------------------------------------------------------

