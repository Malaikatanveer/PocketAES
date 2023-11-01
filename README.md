# PocketAES
CLI programs in  Python:
1. A program that demonstrates the working of individual PocketAES encryption stages. Prompts the user for text block and key inputs, in the form of 16-bit hexadecimal numbers. Computes and shows the outputs of applying SubNibbles, ShiftRow, MixColumns and Generated Round Keys.
2. A program for decrypting one block of ciphertext according to PocketAES algorithm. Receives the ciphertext and key as hex inputs from user. Decrypted block is outputted in the same hex format.
3.  Implements the ASCII text decryption scheme. It reads encrypted text from a file ‘secret.txt’, decrypts it and creates an output file ‘plain.txt’. Key is obtained from user input. Input will contain a series of ciphertext blocks in hex. Consult the sample file in the repository. Output data is in ASCII text. Null padding has been taken care of that may be present in the ciphertext.
4.  Analyzation of the Pocket AES encryption scheme and the security flaws it possesses


