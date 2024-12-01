#pragma once
#ifndef RSA_H
#define RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>

	/* ��� ���� */

#define SEED_KEY_SIZE 16          // SEED Ű�� ũ�� (16����Ʈ)
#define RSA_ENCRYPTED_KEY_SIZE 128 // RSA ��ȣȭ�� ������ ũ�� (1024��Ʈ Ű�� ��� 128����Ʈ)
#define BLOCK_SIZE RSA_ENCRYPTED_KEY_SIZE

#define m    1024			// ��ⷯ n�� ��Ʈ ��
#define mp   512			// ��� �Ҽ� p�� ��Ʈ ��
#define mq   512			// ��� �Ҽ� q�� ��Ʈ ��
#define HASH 128
#define LEN_PS 8			// �е� ��Ʈ���� ũ��
#define DHEX 32
#define OCT  8
#define Char_NUM 8
#define B_S  (m / Char_NUM)
#define DATA_LEN	(B_S - LEN_PS - 3)		// �� ��� ����
#define mb   (m / DHEX)
#define hmb  (mb / 2)
#define mpb  (mp / DHEX)
#define mqb  (mq / DHEX)
#define E_LENGTH 16

#define rdx  0x100000000

/* Ÿ�� ���� */
	typedef unsigned long int ULINT;
	typedef unsigned long long RSA_INT64; // ���� INT64 ��� RSA_INT64 ���
	typedef unsigned int RSA_INT32;       // ���� INT32 ��� RSA_INT32 ���

	/* ���� ���� */
	extern RSA_INT32 LAND;
	extern RSA_INT64 N[mb];
	extern RSA_INT64 E[mb];
	extern RSA_INT64 D[mb];

	// ����� ������ ���Ǵ� ����(����(binary) ����)
	extern short  s[m];				// ��ȣ��(��ȣ)
	extern short  h[DATA_LEN * 8];		// ��
	extern short  v_h[m];				// ��ȣ��(�е� ����)
	extern short  d_d[DATA_LEN * 8];		// ��ȣ��(�е� ����)
	extern short  ps[LEN_PS * 8];		// �е� ��Ʈ��

	// ��ȣ�� ��ȣ�� ���Ǵ� ����(Radix�� octet ����)
	extern RSA_INT64 S[mb];				// ��ȣ��
	extern RSA_INT64 H[mb];				// ��ȣ��(Radix)
	extern RSA_INT64 DATA[DATA_LEN];		// ��(octet)
	extern RSA_INT64 EB[mb * 4];				// ��ȣ�� ���(8 bit)
	extern RSA_INT64 EB1[mb];				// ��ȣ�� ���(16 bit)
	extern RSA_INT64 D_EB[mb * 4];			// ��ȣ�� ���(8 bit)
	extern RSA_INT64 D_DATA[DATA_LEN];		// ��ȣ ������(octet)		
	extern RSA_INT64 O_PS[OCT];			// �е� ��Ʈ��(octet)

	/* �Լ� ���� */
	void RSA_Enc(unsigned char *p_text, unsigned char *result, const char *key_filename);
	void RSA_Dec(unsigned char *c_text, unsigned char *result, const char *key_filename);
	int  get_from_message(unsigned char *msg, short *a, short mn);		// �޽��� ���ۿ��� �����͸� �о ���� ���·� �����ϴ� �Լ�
	void put_to_message(unsigned char *msg, short *a, short mn);		// ���� ������ �����͸� �޽��� ���ۿ� �����ϴ� �Լ�
	void CONV_O_to_B(RSA_INT64 *A, short *B, short mn);					// octet�� binary�� ��ȯ�ϴ� �Լ�
	void CONV_B_to_O(short *A, RSA_INT64 *B, short mn);					// binary�� octet�� ��ȯ�ϴ� �Լ�
	void CONV_R_to_B(RSA_INT64 *A, short *B, short mn);					// Radix�� binary�� ��ȯ�ϴ� �Լ�
	void CONV_B_to_R(short *A, RSA_INT64 *B, short mn);					// binary�� Radix�� ��ȯ�ϴ� �Լ�
	void rand_g(short *out, short n);									// ���� ���� �����ϴ� �Լ�
	void Modular(RSA_INT64 *X, RSA_INT64 *N, short mn);								// ��ⷯ ������ �����ϴ� �Լ�
	void Conv_mma(RSA_INT64 *A, RSA_INT64 *B, RSA_INT64 *C, RSA_INT64 *N, short mn);				// �������� ��ⷯ ���� ������ �����ϴ� �Լ�
	void LeftTORight_Pow(RSA_INT64 *A, RSA_INT64 *E, RSA_INT64 *C, RSA_INT64 *N, short mn);		// Left to Right ����� �����ϴ� �Լ�
	void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex);
	void hex_to_bin(const char *hex, unsigned char *bin);
	void add_padding(unsigned char *data, const unsigned char *p_text, size_t data_len, size_t block_size);
	int remove_padding(unsigned char *data, size_t block_size, size_t *data_len);

#ifdef __cplusplus
}
#endif

#endif // RSA_H
