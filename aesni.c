#include<stdio.h>
#include<wmmintrin.h> // For Intel AES-NI intrinsics

#define Nb 4 // Number of columns (32-bit words) comprising the State
#define Nr 10 // Number of rounds, for 128-bit key it's 10
#define Nk 4  // Number of 32-bit keywords 

//Function protoypes
void KeyExpansion(unsigned char *key, __m128i *key_schedule);
void Encrypt(const unsigned char *plaintext, unsigned char *cipher, const __m128i *key_schedule);
void Decrypt(const unsigned char *cipher, unsigned char *decipher, const __m128i *key_schedule);

//Main body
int main()
{
    // 128-bit key (16 bytes)
    unsigned char key[4 * Nk] = {0x2b, 0x7e, 0x15, 0x16, 
    			       	 0x28, 0xae, 0xd2, 0xa6,
    			       	 0xab, 0xf7, 0x15, 0x88, 
    			       	 0x09, 0xcf, 0x4f, 0x3c
    				};
    
    // register to hold the round keys (Nr+1 keys)
    __m128i key_schedule[Nr + 1];
    // Generate the key schedule
    KeyExpansion(key, key_schedule);
    
    // 128-bit plaintext block (16 bytes)
    unsigned char plaintext[4 * Nb] = {0x32, 0x43, 0xf6, 0xa8, 
    			      	       0x88, 0x5a, 0x30, 0x8d,
    			      	       0x31, 0x31, 0x98, 0xa2, 
    			      	       0xe0, 0x37, 0x07, 0x34
    					};
    unsigned char cipher[16];
    unsigned char decipher[16];
    
    // Encrypt the plaintext				
    Encrypt(plaintext, cipher, key_schedule);
    printf("Encrypted text: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", cipher[i]);
    }
    printf("\n");
    
    // Decrypt the ciphertext
    Decrypt(cipher, decipher, key_schedule);
    
    printf("Decrypted text: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decipher[i]);
    }
    printf("\n");

    
    return 0;
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Key expansion function using AES-NI intrinsics to generate all 10 round keys
void KeyExpansion(unsigned char *key, __m128i *key_schedule) {
    // Load the original key into the first (0th) key schedule
    key_schedule[0] = _mm_loadu_si128((__m128i*)key);

    // Generate all subsequent 10 round keys using 'AESkeygenassist' instruction
    for (int i = 1; i <= 10; i++) {
        __m128i temp;
        
        // AES keygen assist intrinsic requires a different round constant for each round as an immediate
        switch (i) {
            case 1: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x01); break;
            case 2: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x02); break;
            case 3: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x04); break;
            case 4: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x08); break;
            case 5: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x10); break;
            case 6: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x20); break;
            case 7: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x40); break;
            case 8: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x80); break;
            case 9: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x1B); break;
            case 10: temp = _mm_aeskeygenassist_si128(key_schedule[i-1], 0x36); break;
            default: return; 
        }
        //replacing all 4 32-bits chunks of the 128-bit register 'temp' with the Most Significant 32-bits of temp (aeskeygenassist function output) 
        temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3, 3, 3, 3));
        
        // XOR temp with the previous key shifhiting it left 
        temp = _mm_xor_si128(temp, _mm_slli_si128(key_schedule[i-1], 4)); 	//shift previous key left by 4 bytes (= 32-bits)
        temp = _mm_xor_si128(temp, _mm_slli_si128(key_schedule[i-1], 8)); 	//shift previous key left by 8 bytes (= 64-bits)
        temp = _mm_xor_si128(temp, _mm_slli_si128(key_schedule[i-1], 12));	//shift previous key left by 12 bytes (= 96-bits)
        
        // Store the new round key after XOR temp with previous key
        key_schedule[i] = _mm_xor_si128(temp, key_schedule[i-1]);
        }
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
// AES encryption function using AES-NI intrinsics
void Encrypt(const unsigned char *plaintext, unsigned char *cipher, const __m128i *key_schedule) {
    // Load plaintext into a 128-bit block
    __m128i block = _mm_loadu_si128((__m128i*)plaintext);  
    
    // Initial round key addition (key whitening)
    block = _mm_xor_si128(block, key_schedule[0]);         

    // Perform 9 AES rounds with AESENC (AES encryption)
    for (int i = 1; i < 10; i++) {
        block = _mm_aesenc_si128(block, key_schedule[i]);
    }

    // Final AES round with AESENCLAST (final round without MixColumns)
    block = _mm_aesenclast_si128(block, key_schedule[10]);

    // Store the encrypted block back into the output
    _mm_storeu_si128((__m128i*)cipher, block);
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
// AES decryption function using AES-NI intrinsics
void Decrypt(const unsigned char *cipher, unsigned char *decipher, const __m128i *key_schedule) {
    // Load ciphertext into a 128-bit block
    __m128i block = _mm_loadu_si128((__m128i*)cipher);  
    
    // Add the last round key first
    block = _mm_xor_si128(block, key_schedule[10]);         

    // Perform 9 AES decryption rounds with AESDEC, but use the inverse key schedule
    for (int i = 9; i > 0; i--) {
        block = _mm_aesdec_si128(block, _mm_aesimc_si128(key_schedule[i]));
    }

    // Final AES round with AESDECLAST (final round without Inverse MixColumns)
    block = _mm_aesdeclast_si128(block, key_schedule[0]);

    // Store the decrypted block back into the output
    _mm_storeu_si128((__m128i*)decipher, block);
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------


