// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
/*
#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}
*/
// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

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
