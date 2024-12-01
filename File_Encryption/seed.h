// seed.h
#ifndef SEED_H
#define SEED_H

// 필요한 헤더 파일 포함
#include <stddef.h>
#include <stdint.h>

// 데이터 타입 정의
#if defined(__alpha)
typedef unsigned int        DWORD;      // 4바이트
typedef unsigned short      WORD;       // 2바이트
#else
typedef unsigned long int   DWORD;      // 4바이트
typedef unsigned short int  WORD;       // 2바이트
#endif
typedef unsigned char       BYTE;   // 1바이트

// 블록 크기 정의
#define BUFFER_SIZE 16          // SEED 블록 크기

// 함수 선언

// AES 관련 함수
void AES_KeyTransform(unsigned char *key);

// SEED 관련 함수
void SEED_Encrypt(BYTE *pbData, DWORD *pdwRoundKey);
void SEED_Decrypt(BYTE *pbData, DWORD *pdwRoundKey);
void SEED_KeySchedKeyTransformed(DWORD *pdwRoundKey, BYTE *pbTransformedKey);

// 키 생성 및 변형 함수
void generateRandomKey(BYTE *key, size_t keyLength);
void transformKeyWithAES(BYTE *key, size_t keyLength);
void generateAndTransformKey(BYTE *transformedKey, size_t keyLength);

// 파일 암호화/복호화 함수
void encrypt_file(const char *input_filename, BYTE *user_key);
void decrypt_file(const char *input_filename, BYTE *user_key);

// 기타 유틸리티 함수
#ifdef __cplusplus
extern "C" {
#endif

int openFileDialog(char *filename, size_t filenameSize);

#ifdef __cplusplus
}
#endif
void generateKeyFromText(const char *textKey, BYTE *seedKey, size_t keyLength);

#endif // SEED_H