// seed.h
#ifndef SEED_H
#define SEED_H

// �ʿ��� ��� ���� ����
#include <stddef.h>
#include <stdint.h>

// ������ Ÿ�� ����
#if defined(__alpha)
typedef unsigned int        DWORD;      // 4����Ʈ
typedef unsigned short      WORD;       // 2����Ʈ
#else
typedef unsigned long int   DWORD;      // 4����Ʈ
typedef unsigned short int  WORD;       // 2����Ʈ
#endif
typedef unsigned char       BYTE;   // 1����Ʈ

// ��� ũ�� ����
#define BUFFER_SIZE 16          // SEED ��� ũ��

// �Լ� ����

// AES ���� �Լ�
void AES_KeyTransform(unsigned char *key);

// SEED ���� �Լ�
void SEED_Encrypt(BYTE *pbData, DWORD *pdwRoundKey);
void SEED_Decrypt(BYTE *pbData, DWORD *pdwRoundKey);
void SEED_KeySchedKeyTransformed(DWORD *pdwRoundKey, BYTE *pbTransformedKey);

// Ű ���� �� ���� �Լ�
void generateRandomKey(BYTE *key, size_t keyLength);
void transformKeyWithAES(BYTE *key, size_t keyLength);
void generateAndTransformKey(BYTE *transformedKey, size_t keyLength);

// ���� ��ȣȭ/��ȣȭ �Լ�
void encrypt_file(const char *input_filename, BYTE *user_key);
void decrypt_file(const char *input_filename, BYTE *user_key);

// ��Ÿ ��ƿ��Ƽ �Լ�
#ifdef __cplusplus
extern "C" {
#endif

int openFileDialog(char *filename, size_t filenameSize);

#ifdef __cplusplus
}
#endif
void generateKeyFromText(const char *textKey, BYTE *seedKey, size_t keyLength);

#endif // SEED_H