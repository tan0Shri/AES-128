#include<stdio.h>

//For AES algorithm, irreducible polynomial is: x^8 + x^4 + x^3 + x +1
#define Nb 4 // Block Size: Number of columns (32-bit words) comprising the State
#define Nr 10 // Number of rounds, for 128-bit key it's 10
#define Nk 4  // Key length: Number of 32-bit keywords 

typedef unsigned char byte;

//defining structure for 32-bit (= 4bytes) word as an array of 4 bytes
typedef struct{
    byte bytes[4];
    }word;
    
//AES S-box
extern const byte SBox[256]; 
//AES inverse S-box
extern const byte InvSBox[256]; 

//------------------------------------------------------------------------------------------------------------------------------------------------------------------
//AES KeyExpansion function Declaration
word RotWord(word w);
word SubWord(word w);
extern word Rcon[11]; 
void XorWords(word *a, word *b, word *result); 
void KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)]);  

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
//AddRoundKey function:
void AddRoundKey( byte state[4][Nb], const word roundKey[Nb]);
byte xtimes(byte num);

//---------------------------------------------------------------------------------------------------------------------------------------------------------------
//AES Encryption
word SubBytes(byte state[4][Nb]); 
void ShiftRows(byte state[4][Nb]);
void Mixcolumns(byte state[4][Nb]);
void AES_Encrypt(byte in[4 * Nb], byte out[4 * Nb], const word w[Nb * (Nr + 1)]);

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//AES Decryption
word InvSubBytes(byte state[4][Nb]); 
void InvShiftRows(byte state[4][Nb]);
byte MultBy_09(byte num);
byte MultBy_0b(byte num);
byte MultBy_0d(byte num);
byte MultBy_0e(byte num);
void InvMixcolumns(byte state[4][Nb]);
void AES_Decrypt(byte in[4 * Nb], byte out[4 * Nb], const word w[Nb * (Nr + 1)]);

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//ECB mode 
void pad(byte block[4 * Nb], int bytesRead);
int unpad(byte block[4 * Nb]);
void ecb_enc(FILE *in, word *w, FILE *out);
void ecb_dec(FILE *in, word *w, FILE *out);
