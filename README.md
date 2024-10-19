# AES-128
This project implements the AES-128 Encryption and Decryption in C, supporting different modes of operation. Follow the steps below to run and interact with the program.

How to Run
1. Setting up the Program
    1. Open main.c.
    2. Enter the key in 128-bit Hex String format (Default: YELLOW SUBMARINE).
    3. Initialization Vector (IV) is generated randomly for each encryption, so you have no control over it.
    4. You can modify the file_name of input file (plaintext) which you want to encrypt and file_names where you want to save your ciphertext, deciphered_text.
           (Default: For Plaintext - "test.pdf"
                     For ciphertext - "cipher.txt"
                     For decipher_text - "out.pdf")
       (Disclaimer:  Any file extension can be used)       
    5. For verification, check the same plaintext file has been decrypted in deciphered_text file.
       
2. Running the Program
    1. Ensure that gcc and make are installed on your system.
    2. Open a terminal and navigate to the project directory.
    3. compile to build the program using "gcc -o main main.c AES128.c modes.c"
    4. Run the program using ./main
  When prompted:
    - Enter the name of the file you want to encrypt.
    - Select the mode of operation for encryption.
    - Select the mode of operation for decryption.
