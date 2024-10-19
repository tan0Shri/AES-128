## AES-128 Encryption and Decryption in C

This project implements the AES-128 Encryption and Decryption in C, supporting different modes of operation. Follow the steps below to run and interact with the program.

### **How to Run**

#### 1. Setting up the Program

1. Open `main.c`.
2. The key (128-bit) is auto-generated, but you can also manually input your chosen key in `main.c` (enter a 16-byte hex string).
3. The Initialization Vector (IV) is randomly generated for each encryption, so you have no control over it.
4. After decryption, verify that the same plaintext file has been restored in the `deciphered_text` file.

#### 2. Running the Program

1. Ensure that `gcc` is installed on your system.
2. Open a terminal and navigate to the project directory.
3. Compile the program using:
   ```bash
   gcc -o main main.c AES128.c modes.c
4. Run the program using:
   `./main`

#### When prompted:
- Select the mode of operation for encryption, decryption.
- Enter the names of the files. 
