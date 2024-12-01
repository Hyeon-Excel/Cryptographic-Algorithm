#pragma once
#ifndef RSA_H
#define RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>

	/* 상수 정의 */

#define SEED_KEY_SIZE 16          // SEED 키의 크기 (16바이트)
#define RSA_ENCRYPTED_KEY_SIZE 128 // RSA 암호화된 데이터 크기 (1024비트 키의 경우 128바이트)
#define BLOCK_SIZE RSA_ENCRYPTED_KEY_SIZE

#define m    1024			// 모듈러 n의 비트 수
#define mp   512			// 비밀 소수 p의 비트 수
#define mq   512			// 비밀 소수 q의 비트 수
#define HASH 128
#define LEN_PS 8			// 패딩 스트링의 크기
#define DHEX 32
#define OCT  8
#define Char_NUM 8
#define B_S  (m / Char_NUM)
#define DATA_LEN	(B_S - LEN_PS - 3)		// 평문 블록 길이
#define mb   (m / DHEX)
#define hmb  (mb / 2)
#define mpb  (mp / DHEX)
#define mqb  (mq / DHEX)
#define E_LENGTH 16

#define rdx  0x100000000

/* 타입 정의 */
	typedef unsigned long int ULINT;
	typedef unsigned long long RSA_INT64; // 기존 INT64 대신 RSA_INT64 사용
	typedef unsigned int RSA_INT32;       // 기존 INT32 대신 RSA_INT32 사용

	/* 전역 변수 */
	extern RSA_INT32 LAND;
	extern RSA_INT64 N[mb];
	extern RSA_INT64 E[mb];
	extern RSA_INT64 D[mb];

	// 서명과 검증에 사용되는 버퍼(이진(binary) 형태)
	extern short  s[m];				// 암호문(암호)
	extern short  h[DATA_LEN * 8];		// 평문
	extern short  v_h[m];				// 복호문(패딩 포함)
	extern short  d_d[DATA_LEN * 8];		// 복호문(패딩 제외)
	extern short  ps[LEN_PS * 8];		// 패딩 스트링

	// 암호와 복호에 사용되는 버퍼(Radix와 octet 형태)
	extern RSA_INT64 S[mb];				// 암호문
	extern RSA_INT64 H[mb];				// 복호문(Radix)
	extern RSA_INT64 DATA[DATA_LEN];		// 평문(octet)
	extern RSA_INT64 EB[mb * 4];				// 암호문 블록(8 bit)
	extern RSA_INT64 EB1[mb];				// 암호문 블록(16 bit)
	extern RSA_INT64 D_EB[mb * 4];			// 복호문 블록(8 bit)
	extern RSA_INT64 D_DATA[DATA_LEN];		// 복호 데이터(octet)		
	extern RSA_INT64 O_PS[OCT];			// 패딩 스트링(octet)

	/* 함수 선언 */
	void RSA_Enc(unsigned char *p_text, unsigned char *result, const char *key_filename);
	void RSA_Dec(unsigned char *c_text, unsigned char *result, const char *key_filename);
	int  get_from_message(unsigned char *msg, short *a, short mn);		// 메시지 버퍼에서 데이터를 읽어서 이진 형태로 저장하는 함수
	void put_to_message(unsigned char *msg, short *a, short mn);		// 이진 형태의 데이터를 메시지 버퍼에 저장하는 함수
	void CONV_O_to_B(RSA_INT64 *A, short *B, short mn);					// octet을 binary로 변환하는 함수
	void CONV_B_to_O(short *A, RSA_INT64 *B, short mn);					// binary를 octet로 변환하는 함수
	void CONV_R_to_B(RSA_INT64 *A, short *B, short mn);					// Radix를 binary로 변환하는 함수
	void CONV_B_to_R(short *A, RSA_INT64 *B, short mn);					// binary를 Radix로 변환하는 함수
	void rand_g(short *out, short n);									// 랜덤 수를 생성하는 함수
	void Modular(RSA_INT64 *X, RSA_INT64 *N, short mn);								// 모듈러 연산을 수행하는 함수
	void Conv_mma(RSA_INT64 *A, RSA_INT64 *B, RSA_INT64 *C, RSA_INT64 *N, short mn);				// 고전적인 모듈러 감소 연산을 수행하는 함수
	void LeftTORight_Pow(RSA_INT64 *A, RSA_INT64 *E, RSA_INT64 *C, RSA_INT64 *N, short mn);		// Left to Right 멱승을 수행하는 함수
	void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex);
	void hex_to_bin(const char *hex, unsigned char *bin);
	void add_padding(unsigned char *data, const unsigned char *p_text, size_t data_len, size_t block_size);
	int remove_padding(unsigned char *data, size_t block_size, size_t *data_len);

#ifdef __cplusplus
}
#endif

#endif // RSA_H
