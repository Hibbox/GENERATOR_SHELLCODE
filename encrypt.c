#include <stdio.h>
#include <stdlib.h>

unsigned char shellcode[] = "";
int len = sizeof(shellcode) - 1;

void XOR_encrypt_decrypt(unsigned char *shellcode, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        shellcode[i] = shellcode[i] ^ key;
    }
}
