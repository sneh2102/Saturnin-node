#include <stdio.h>
#include <string.h>
#include "internal-saturnin.h"

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Plaintext to be encrypted (32 bytes)
    unsigned char plaintext[SATURNIN_BLOCK_SIZE] = "This is a test message!!!";
    
    // If the input is shorter than 32 bytes, pad it
    size_t len = strlen((const char *)plaintext);
    if (len < SATURNIN_BLOCK_SIZE) {
        memset(plaintext + len, 0, SATURNIN_BLOCK_SIZE - len);
    }

    // Output buffer for encrypted and decrypted text (32 bytes)
    unsigned char ciphertext[SATURNIN_BLOCK_SIZE];
    unsigned char decryptedtext[SATURNIN_BLOCK_SIZE];

    // Key for encryption and decryption (32 bytes)
    unsigned char key[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    // Domain for encryption (can be SATURNIN_DOMAIN_10_1, etc.)
    unsigned domain = SATURNIN_DOMAIN_10_1;

    // Key schedule setup
    saturnin_key_schedule_t ks;
    saturnin_setup_key(&ks, key);

    // Encrypt the plaintext
    saturnin_encrypt_block(&ks, ciphertext, plaintext, domain);

    // Decrypt the ciphertext
    saturnin_decrypt_block(&ks, decryptedtext, ciphertext, domain);

    // Output results
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    print_hex(ciphertext, SATURNIN_BLOCK_SIZE);
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
