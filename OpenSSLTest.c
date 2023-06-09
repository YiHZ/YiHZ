#include <openssl/aes.h>
#include <string.h>

unsigned char * encrypt_aes(unsigned char * plaintext, int plaintext_len, unsigned char * key, unsigned char * iv) {
    AES_KEY aes_key;
    unsigned char * ciphertext = (unsigned char *)malloc(plaintext_len + AES_BLOCK_SIZE);
    memset(ciphertext, 0, plaintext_len + AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 256, &aes_key);
    AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &aes_key, iv, AES_ENCRYPT);
    return ciphertext;
}

unsigned char * decrypt_aes(unsigned char * ciphertext, int ciphertext_len, unsigned char * key, unsigned char * iv) {
    AES_KEY aes_key;
    unsigned char * plaintext = (unsigned char *)malloc(ciphertext_len);
    memset(plaintext, 0, ciphertext_len);
    AES_set_decrypt_key(key, 256, &aes_key);
    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, AES_DECRYPT);
    return plaintext;
}

int main() {
    unsigned char * plaintext = "Hello World!";
    int plaintext_len = strlen((char *)plaintext);
    unsigned char key[16] = "0123456789abcdef";
    unsigned char iv[16] = "fedcba9876543210";
    unsigned char * ciphertext = encrypt_aes(plaintext, plaintext_len, key, iv);
    int ciphertext_len = strlen((char *)ciphertext);
    unsigned char * decrypted = decrypt_aes(ciphertext, ciphertext_len, key, iv);
    printf("Plaintext: %s\n", (char *)plaintext);
    printf("Ciphertext: %s\n", (char *)ciphertext);
    printf("Decrypted: %s\n", (char *)decrypted);
    free(ciphertext);
    free(decrypted);
    return 0;
}
