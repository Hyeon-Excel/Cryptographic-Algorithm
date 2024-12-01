#define _CRT_SECURE_NO_WARNINGS
#include "rsa.h"
#include "seed.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <io.h>
#include <dos.h>
#include <fcntl.h>
#include <sys/stat.h>

// ���� ���� ����
RSA_INT32 LAND = 0xFFFFFFFF;
RSA_INT64 N[mb];
RSA_INT64 E[mb];
RSA_INT64 D[mb];

// ����� ������ ���Ǵ� ����(����(binary) ����)
short  s[m] = { 0 };				// ��ȣ��(��ȣ)
short  h[DATA_LEN * 8] = { 0 };		// ��
short  v_h[m] = { 0 };				// ��ȣ��(�е� ����)
short  d_d[DATA_LEN * 8] = { 0 };		// ��ȣ��(�е� ����)
short  ps[LEN_PS * 8] = { 0 };		// �е� ��Ʈ��

// ��ȣ�� ��ȣ�� ���Ǵ� ����(Radix�� octet ����)
RSA_INT64 S[mb] = { 0 };				// ��ȣ��
RSA_INT64 H[mb] = { 0 };				// ��ȣ��(Radix)
RSA_INT64 DATA[DATA_LEN] = { 0 };		// ��(octet)
RSA_INT64 EB[mb * 4] = { 0 };			// ��ȣ�� ���(8 bit)
RSA_INT64 EB1[mb] = { 0 };			// ��ȣ�� ���(16 bit)
RSA_INT64 D_EB[mb * 4] = { 0 };		// ��ȣ�� ���(8 bit)
RSA_INT64 D_DATA[DATA_LEN] = { 0 };	// ��ȣ ������(octet)		
RSA_INT64 O_PS[OCT] = { 0 };			// �е� ��Ʈ��(octet)


/********************************************************************/
/***********   Function name :  CONV_B_to_R (a,B,mn)       **********/
/***********   Description   :  convert bin. into radix    **********/
/********************************************************************/
RSA_INT64 mask[DHEX] = { 0x80000000, 0x40000000, 0x20000000, 0x10000000,0x8000000,
				  0x4000000,0x2000000, 0x1000000, 0x800000,0x400000, 0x200000,
				  0x100000, 0x080000,0x040000, 0x020000, 0x010000,
				  0x8000, 0x4000, 0x2000, 0x1000,0x800,
				  0x400,0x200, 0x100, 0x80,0x40, 0x20,
				  0x10, 0x08,0x04, 0x02, 0x01
};

void CONV_B_to_R(short *A, RSA_INT64 *B, short mn)
{
	register i, j, k;

	for (i = mn - 1; i >= 0; i--)  B[i] = 0x00;

	i = mn * DHEX - 1;
	for (k = 0; k <= mn - 1; k++) {
		B[k] = 0x00;
		for (j = DHEX - 1; j >= 0; j--) {
			B[k] += A[i--] * mask[j];
			if (i < 0)  break;
		}
		if (i < 0) break;
	}
}

/********************************************************************/
/***********   Function name :  CONV_R_to_B (A,b,mn)       **********/
/***********   Description   :  convert radix into bin.    **********/
/********************************************************************/
void CONV_R_to_B(RSA_INT64 *A, short *B, short mn)
{
	register i, j, k;

	for (i = 0; i < mn * DHEX; i++)  B[i] = 0;
	k = mn * DHEX - 1;
	for (i = 0; i <= mn - 1; i++) {
		for (j = 0; j <= DHEX - 1; j++) {
			B[k--] = (A[i] >> j) & 0x01;
			if (k < 0)  break;
		}
		if (k < 0) break;
	}
}

/********************************************************************/
/***********   Function name :  rand_g (a,n)               **********/
/***********   Description   : n-bits random               **********/
/***********                   number generator.           **********/
/********************************************************************/
void rand_g(short *out, short n)
{
	register  j, k;
	short x;
	long t;

	srand((unsigned)(time(NULL)));
	//delay(100);

	j = 0;
	while (1) {
		x = rand();
		for (k = 0; k < 15; k++) {
			out[n - 1 - j] = (x >> k) & 0x01;
			j++;
			if (j >= n)   return;
		}
	}
}

/********************************************************************/
/*****     Function name : Modular(C, N mn)                     *****/
/*****     Description   : C = C mod N                          *****/
/********************************************************************/
void Modular(RSA_INT64 *X, RSA_INT64 *N, short mn)
{
	int i, j, k;
	short shift, posit;
	RSA_INT64 arryA[2 * mb + 1] = { 0, }, arryN[2 * mb + 1] = { 0, };
	RSA_INT64 acumA, acumB, acumN, acumQ;
	RSA_INT32 acumC;

	acumN = N[mn - 1] + 0x01;

	while (1) {
		for (k = 2 * mn - 1; k >= 0; k--)
			if (X[k] > 0x00)
				break;
		if (k <= mn - 1)
			break;

		acumA = X[k] * rdx + X[k - 1];
		acumQ = acumA / acumN;

		if (acumQ > (rdx - 1))
			acumQ = rdx - 1;

		shift = k - mn;   /**  shift number **/

		acumC = 0x00;
		for (k = 0; k <= mn - 1; k++) {
			acumA = N[k] * acumQ + acumC;
			acumC = acumA >> DHEX;
			acumA = acumA & LAND;
			j = k + shift;
			if (X[j] < acumA) {
				X[j] += rdx;
				posit = j;
				while ((X[j + 1]) == 0 && (j < (mn + shift))) {
					X[j + 1] += rdx - 1;
					j++;
				}
				X[j + 1] -= 0x01;
				j = posit;
			}
			X[j] = (X[j] - acumA) & LAND;
		}
		X[mn + shift] = X[mn + shift] - acumC;
	}

	while (1) {
		for (i = mn - 1; i >= 0; i--) {
			if ((X[i] & LAND) != (N[i] & LAND)) {
				if ((X[i] & LAND) > (N[i] & LAND))
					break;
				else
					return; // void �Լ������� ���� ��ȯ���� ����
			}
		}

		acumA = X[mn - 1];
		acumA = acumA / acumN;

		if (acumA == 0x00) {
			for (i = 0; i <= mn - 1; i++) {
				if (X[i] < N[i]) {
					X[i] += rdx;
					posit = i;
					while ((X[i + 1] == 0) && (i < mn)) {
						X[i + 1] += rdx - 1;
						i++;
					}
					X[i + 1] -= 0x01;
					i = posit;
				}
				X[i] = (X[i] - N[i]) & LAND;
			}
		}
		else {
			acumC = 0x00;
			for (i = 0; i <= mn - 1; i++) {
				acumB = N[i] * acumA + acumC;
				acumC = acumB >> DHEX;
				acumB = acumB & LAND;
				if (X[i] < acumB) {
					X[i] += rdx;
					posit = i;
					while ((X[i + 1] == 0) && (i < mn)) {
						X[i + 1] += rdx - 1;
						i++;
					}
					X[i + 1] -= 0x01;
					i = posit;
				}
				X[i] = (X[i] - acumB) & LAND;
			}
		}
	}
}

/********************************************************************/
/*****     Function name : Conv_mma(A,B,C,N,mn) (Conventional)  *****/
/*****     Description   : C= A*B mod N                         *****/
/********************************************************************/
void Conv_mma(RSA_INT64 *A, RSA_INT64 *B, RSA_INT64 *C, RSA_INT64 *N, short mn)
{
	register  i, j, k;
	RSA_INT64 arryC[mb * 2], X[mb * 2];         /** temporary arrys **/
	RSA_INT64 acumA;                     /** temporary acumulators **/
	RSA_INT32 acumC;

	for (k = 2 * mn - 1; k >= 0; k--)  arryC[k] = 0x00;

	for (i = 0; i <= mn - 1; i++) {
		if (A[i] > 0x00) {
			acumC = 0x00;
			for (j = 0; j <= mn - 1; j++) {
				acumA = A[i] * B[j] + arryC[i + j] + acumC;
				arryC[i + j] = acumA & LAND;
				acumC = acumA >> DHEX;
			}
			arryC[i + j] = acumC;
		}
	}

	for (i = 2 * mn - 1; i >= 0; i--)
		X[i] = arryC[i];

	Modular(X, N, mn);

	for (i = 0; i <= mn - 1; i++)
		C[i] = X[i];
}

/********************************************************************/
/***********   Function name :  CONV_B_to_O (a,B,mn)       **********/
/***********   Description   :  convert bin. into octet    **********/
/********************************************************************/
RSA_INT64  o_mask[8] = { 0x80,0x40, 0x20, 0x10, 0x08,0x04, 0x02, 0x01 };

void CONV_B_to_O(short *A, RSA_INT64 *B, short mn)
{
	register i, j, k;

	i = mn * OCT - 1;
	for (k = 0; k <= mn - 1; k++) {
		B[k] = 0x00;
		for (j = 7; j >= 0; j--) {
			B[k] += A[i--] * o_mask[j];
			if (i < 0)  break;
		}
		if (i < 0) break;
	}
}

/********************************************************************/
/***********   Function name :  CONV_O_to_B (A,b,mn)       **********/
/***********   Description   :  convert octet into bin.    **********/
/********************************************************************/
void CONV_O_to_B(RSA_INT64 *A, short *B, short mn)
{
	register i, j, k;

	for (i = 0; i < mn * OCT; i++)  B[i] = 0;
	k = mn * OCT - 1;
	for (i = 0; i <= mn - 1; i++) {
		for (j = 0; j <= 7; j++) {
			B[k--] = (A[i] >> j) & 0x01;
			if (k < 0)  break;
		}
		if (k < 0) break;
	}
}

/********************************************************************/
/*****     Function name : WM_Left_Pow(A,E,C,N,mn)              *****/
/*****     Description   : C= A^E mod N                         *****/
/********************************************************************/
void LeftTORight_Pow(RSA_INT64 *A, RSA_INT64 *E, RSA_INT64 *C, RSA_INT64 *N, short mn)
{
	register i;
	RSA_INT64 arryC[mb] = { 0, };
	short e[m * DHEX] = { 0, }; // Adjusted to match bits_padded size

	for (i = 0; i < mn; i++)
		C[i] = 0x00;

	// E is in Radix; convert to bit array
	CONV_R_to_B(E, e, mn);

	arryC[0] = 0x01;

	for (i = 0; i < mn * DHEX; i++)
	{
		// Square step
		Conv_mma(arryC, arryC, arryC, N, mn);

		// Multiply step
		if (e[i] == 1)
			Conv_mma(arryC, A, arryC, N, mn);
	}

	for (i = 0; i < mn; i++)
		C[i] = arryC[i];
}

/**
 * ����Ʈ �迭�� ��Ʈ �迭�� ��ȯ�ϴ� �Լ�
 * @param bytes ����Ʈ �迭
 * @param bits ��µ� ��Ʈ �迭 (����Ʈ�� 8��Ʈ)
 * @param byte_len ����Ʈ �迭�� ����
 */
void bytes_to_bits(const unsigned char *bytes, short *bits, size_t byte_len) {
	size_t i, j;
	for (i = 0; i < byte_len; i++) {
		for (j = 0; j < 8; j++) {
			bits[i * 8 + j] = (bytes[i] >> (7 - j)) & 0x01; // MSB���� ����
		}
	}
}

/**
 * ��Ʈ �迭�� ����Ʈ �迭�� ��ȯ�ϴ� �Լ�
 * @param bits ��Ʈ �迭
 * @param bytes ��µ� ����Ʈ �迭
 * @param byte_len ����Ʈ �迭�� ����
 */
void bits_to_bytes(const short *bits, unsigned char *bytes, size_t byte_len) {
	size_t i, j;
	for (i = 0; i < byte_len; i++) {
		bytes[i] = 0;
		for (j = 0; j < 8; j++) {
			bytes[i] = (bytes[i] << 1) | (bits[i * 8 + j] & 0x01);
		}
	}
}

// RSA ��ȣȭ
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>

// RSA ��ȣȭ
void RSA_Enc(unsigned char *p_text, unsigned char *result, const char *key_filename) {
	FILE *fptr;
	int i;
	size_t encrypted_len;
	char *encrypted_hex;

	// RSA ����Ű ���� ����
	printf("RSA ����Ű ���� ����: %s\n", key_filename);
	if ((fptr = fopen(key_filename, "rb")) == NULL) {
		printf("RSA ����Ű ������ �� �� �����ϴ�: %s\n", key_filename);
		exit(1);
	}

	// ����Ű N�� E �б�
	for (i = mb - 1; i >= 0; i--) {
		if (fscanf(fptr, "%I64x ", &N[i]) != 1) {
			printf("��ⷯ N �б� ����\n");
			fclose(fptr);
			exit(1);
		}
	}
	for (i = mb - 1; i >= 0; i--) {
		if (fscanf(fptr, "%I64x ", &E[i]) != 1) {
			printf("����Ű E �б� ����\n");
			fclose(fptr);
			exit(1);
		}
	}
	fclose(fptr);

	printf("����Ű �б� ����\n");
	printf("N: ");
	for (i = 0; i < mb; i++) printf("%I64X ", N[i]);
	printf("\nE: ");
	for (i = 0; i < mb; i++) printf("%I64X ", E[i]);
	printf("\n");

	// �Է� ������ Ȯ��
	printf("��ȣȭ�� ������(SEED Ű): ");
	for (i = 0; i < SEED_KEY_SIZE; i++) {
		printf("%02X ", p_text[i]);
	}
	printf("\n");

	// �򹮿� �е� �߰�
	unsigned char padded_data[BLOCK_SIZE] = { 0 };
	add_padding(padded_data, p_text, SEED_KEY_SIZE, BLOCK_SIZE);

	// �е��� �����͸� ���
	printf("�е��� ������: ");
	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02X ", padded_data[i]);
	}
	printf("\n");

	// �е��� �����͸� ��Ʈ �迭�� ��ȯ
	short bits_padded[mb * DHEX] = { 0 };
	bytes_to_bits(padded_data, bits_padded, BLOCK_SIZE);

	// Radix ���·� ��ȯ
	memset(S, 0, sizeof(S));
	CONV_B_to_R(bits_padded, S, mb);

	// RSA ��ȣȭ ����
	memset(H, 0, sizeof(H));
	LeftTORight_Pow(S, E, H, N, mb);

	// Radix ����� ��Ʈ �迭�� ��ȯ
	short bits_encrypted[mb * DHEX] = { 0 };
	CONV_R_to_B(H, bits_encrypted, mb);

	// ��Ʈ �迭�� ����Ʈ �迭�� ��ȯ
	unsigned char encrypted_bytes[BLOCK_SIZE] = { 0 };
	bits_to_bytes(bits_encrypted, encrypted_bytes, BLOCK_SIZE);

	// ����� ���
	printf("��ȣȭ�� ������: ");
	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02X ", encrypted_bytes[i]);
	}
	printf("\n");

	// 16���� ���ڵ�
	encrypted_len = BLOCK_SIZE;
	encrypted_hex = (char *)malloc(encrypted_len * 2 + 1);
	if (encrypted_hex == NULL) {
		printf("�޸� �Ҵ� ����\n");
		exit(1);
	}
	bin_to_hex(encrypted_bytes, encrypted_len, encrypted_hex);
	printf("��ȣȭ�� SEED Ű (16����): %s\n", encrypted_hex);

	// ����� 16���� ���ڿ��� ����
	FILE *hex_file = fopen("secured_key_hex.txt", "w");
	if (hex_file == NULL) {
		printf("��ȣȭ�� Ű�� 16������ �����ϴ� ������ �� �� �����ϴ�.\n");
		free(encrypted_hex);
		exit(1);
	}
	fprintf(hex_file, "%s", encrypted_hex);
	fclose(hex_file);
	printf("��ȣȭ�� SEED Ű�� 16���� �������� secured_key_hex.txt�� ����Ǿ����ϴ�.\n");

	free(encrypted_hex);
}

// RSA ��ȣȭ
// RSA ��ȣȭ
void RSA_Dec(unsigned char *c_text, unsigned char *result, const char *key_filename) {
	FILE *fptr;
	int i;

	// RSA ����Ű ���� ����
	printf("RSA ����Ű ���� ����: %s\n", key_filename);
	if ((fptr = fopen(key_filename, "rb")) == NULL) {
		printf("RSA ����Ű ������ �� �� �����ϴ�: %s\n", key_filename);
		exit(1);
	}

	// ����Ű �б�
	for (i = mb - 1; i >= 0; i--) {
		if (fscanf(fptr, "%I64x ", &N[i]) != 1) {
			printf("��ⷯ N �б� ����\n");
			fclose(fptr);
			exit(1);
		}
	}
	for (i = mb - 1; i >= 0; i--) {
		if (fscanf(fptr, "%I64x ", &D[i]) != 1) {
			printf("����Ű D �б� ����\n");
			fclose(fptr);
			exit(1);
		}
	}
	fclose(fptr);

	printf("����Ű �б� ����\n");
	printf("N: ");
	for (i = 0; i < mb; i++) {
		printf("%I64X ", N[i]);
	}
	printf("\n");
	printf("D: ");
	for (i = 0; i < mb; i++) {
		printf("%I64X ", D[i]);
	}
	printf("\n");

	// ��ȣȭ�� �����͸� 16���� ���ڿ��κ��� ����Ʈ �迭�� ��ȯ
	unsigned char encrypted_bytes[BLOCK_SIZE];
	hex_to_bin((const char *)c_text, encrypted_bytes);

	// ��ȣȭ�� �����͸� ��� (�����)
	printf("��ȣȭ�� SEED Ű (����Ʈ): ");
	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02X ", encrypted_bytes[i]);
	}
	printf("\n");

	// ��ȣȭ�� �����͸� ��Ʈ �迭�� ��ȯ
	short bits_encrypted[mb * DHEX] = { 0 };
	// �ߺ��� hex_to_bin ȣ�� ����
	bytes_to_bits(encrypted_bytes, bits_encrypted, BLOCK_SIZE);

	// Radix ���·� ��ȯ
	memset(S, 0, sizeof(S));
	CONV_B_to_R(bits_encrypted, S, mb);

	// ��ȣȭ ���� ����: m = c^d mod n
	memset(H, 0, sizeof(H));
	LeftTORight_Pow(S, D, H, N, mb);

	// Radix ����� ��Ʈ �迭�� ��ȯ
	short bits_decrypted[mb * DHEX] = { 0 };
	CONV_R_to_B(H, bits_decrypted, mb);

	// ��Ʈ �迭�� ����Ʈ �迭�� ��ȯ
	unsigned char decrypted_bytes[BLOCK_SIZE] = { 0 };
	bits_to_bytes(bits_decrypted, decrypted_bytes, BLOCK_SIZE);

	// ��ȣȭ�� �����͸� ��� (�����)
	printf("��ȣȭ�� ������ (�е� ����): ");
	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02X ", decrypted_bytes[i]);
	}
	printf("\n");

	// �е� ���� ����
	if (decrypted_bytes[0] != 0x00 || decrypted_bytes[1] != 0x02) {
		printf("�е� ���� ����: %02X %02X\n", decrypted_bytes[0], decrypted_bytes[1]);
		printf("�е� ���� ����: �ùٸ��� ���� PKCS#1 v1.5 �е�\n");
		exit(1);
	}

	// ��ȣȭ�� �����͸� PKCS#1 v1.5 �е� ����
	size_t plain_len;
	unsigned char padded_decrypted_data[BLOCK_SIZE];
	memcpy(padded_decrypted_data, decrypted_bytes, BLOCK_SIZE);

	if (remove_padding(padded_decrypted_data, BLOCK_SIZE, &plain_len) != 0) {
		printf("�е� ���� ����: �ùٸ��� ���� PKCS#1 v1.5 �е�\n");
		exit(1);
	}

	// ��ȣȭ�� SEED Ű ����
	memcpy(result, padded_decrypted_data, plain_len);

	// ��ȣȭ�� ������ ���
	printf("��ȣȭ�� ������ (SEED Ű): ");
	for (i = 0; i < plain_len; i++) {
		printf("%02X ", result[i]);
	}
	printf("\n");
}


/**
 * ���� �����͸� 16���� ���ڿ��� ��ȯ�ϴ� �Լ�
 * @param bin ���� ������
 * @param bin_len ���� �������� ����
 * @param hex ��µ� 16���� ���ڿ� (�ּ� 2 * bin_len + 1 ����Ʈ)
 */
void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
	const char hex_chars[] = "0123456789ABCDEF";
	size_t i;
	for (i = 0; i < bin_len; i++) {
		hex[i * 2] = hex_chars[(bin[i] >> 4) & 0xF];
		hex[i * 2 + 1] = hex_chars[bin[i] & 0xF];
	}
	hex[bin_len * 2] = '\0';
}

/**
 * 16���� ���ڿ��� ���� �����ͷ� ��ȯ�ϴ� �Լ�
 * @param hex 16���� ���ڿ�
 * @param bin ��µ� ���� ������ ���� (�ּ� strlen(hex)/2 ����Ʈ)
 */
void hex_to_bin(const char *hex, unsigned char *bin) {
	size_t len = strlen(hex);
	size_t i;
	for (i = 0; i < len / 2; i++) {
		sscanf(hex + 2 * i, "%2hhx", &bin[i]);
	}
}

// �޽����� �о� ���� ���·� ����
int get_from_message(unsigned char *msg, short *a, short mn)
{
	register  i, j;
	short flag = 1, cnt = 0, mm;
	unsigned char b[m / Char_NUM] = { 0, };

	mm = mn * Char_NUM;

	for (i = 0; i < mm; i++)
		a[i] = 0;

	// �޽��� ���ۿ��� �� ����Ʈ�� �д´�
	for (i = 0; i < mn; i++)
	{
		if (msg[i] == '\0')
		{
			if (i == 0)
				return -1;

			if (mn < B_S)
			{
				flag = 0;
				break;
			}
		}

		b[i] = msg[i];
	}

	cnt = 0;
	// ����Ʈ ������ �����͸� ���� ���·� ��ȯ
	for (i = mn - 1; i >= 0; i--)
	{
		for (j = 0; j < Char_NUM; j++)
		{
			a[cnt++] = (b[i] >> j) & 0x01;
		}
	}

	return(flag);
}

// ���� ������ �����͸� ����Ʈ ���·� ����
void put_to_message(unsigned char *msg, short *a, short mn)
{
	register i, j;
	short cnt = 0;
	unsigned char b[m / Char_NUM] = { 0, };
	unsigned char mask[Char_NUM] = { 0x01,0x02,0x04,0x08,
									0x10,0x20,0x40,0x80 };

	cnt = 0;
	// ���� ������ �����͸� ����Ʈ ���·� ��ȯ�Ѵ�
	for (i = mn - 1; i >= 0; i--)
	{
		for (j = 0; j < Char_NUM; j++)
		{
			b[i] = b[i] + a[cnt++] * mask[j];
		}
	}
	// ��ȯ�� �����͸� �޽��� ���ۿ� �����Ѵ�
	for (i = 0; i < mn; i++)
		msg[i] = b[i];
}

// �е� �߰� (PKCS#1 v1.5)
void add_padding(unsigned char *data, const unsigned char *p_text, size_t data_len, size_t block_size) {
	if (data_len > block_size - 11) { // PKCS#1 v1.5������ �ּ� 11����Ʈ �е� �ʿ�
		printf("�е� �߰� ����: �� �����Ͱ� �ʹ� Ů�ϴ�.\n");
		exit(1);
	}

	memset(data, 0, block_size);              // ������ �ʱ�ȭ
	data[0] = 0x00;                           // ���� ����Ʈ
	data[1] = 0x02;                           // PKCS#1 v1.5 �е�

	// ���� �е� ��Ʈ��(0x01~0xFF)
	size_t i;
	for (i = 2; i < block_size - data_len - 1; i++) {
		unsigned char rnd;
		do {
			rnd = (unsigned char)(rand() % 256);
		} while (rnd == 0x00); // PS�� 0x00�� �ƴϾ�� ��
		data[i] = rnd;
	}

	data[block_size - data_len - 1] = 0x00;   // ������
	memcpy(&data[block_size - data_len], p_text, data_len); // �� ����
}

// �е� ����
int remove_padding(unsigned char *data, size_t block_size, size_t *data_len) {
	if (data[0] != 0x00 || data[1] != 0x02) {
		printf("�е� ���� ����: �ùٸ��� ���� ���� ����Ʈ\n");
		return -1;  // �е� ������ �ùٸ��� ����
	}

	// �е� ��Ʈ�� Ž��
	size_t i = 2;
	while (i < block_size && data[i] != 0x00) {
		i++;
	}

	if (i >= block_size) {
		printf("�е� ���� ����: ������ ������(0x00) ����\n");
		return -1;  // �е� ���� ����
	}

	// ������ �������� �� ������
	size_t plain_start = i + 1;
	*data_len = block_size - plain_start;

	// �� ������ ����
	memmove(data, &data[plain_start], *data_len);

	return 0;  // ����
}
