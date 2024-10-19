# AES-128
This project implements the AES-128 Encryption and Decryption in C, supporting different modes of operation. Follow the steps below to run and interact with the program.

## 'How to Run'
### 1. Setting up the Program
    1. Open main.c.
    2. Key (128-bit) is auto generated format, but you can also put your chosen key manually in 'main.c' (put 16 bytes hex string).
    3. Initialization Vector (IV) is generated randomly for each encryption, so you have no control over it.      
    5. For verification, check the same plaintext file has been decrypted in deciphered_text file.
       
### 2. Running the Program
    1. Ensure that '''gcc''' is installed on your system.
    2. Open a terminal and navigate to the project directory.
    3. compile to build the program using "gcc -o main main.c AES128.c modes.c"
    4. Run the program using ./main
    
 #### When prompted:
    - Select the mode of operation for encryption, decryption.
    - Enter the names of the files.
    
