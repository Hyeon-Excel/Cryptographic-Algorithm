#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seed.h"
#include "rsa.h"

// �ֿ� ��� ����
#define MAX_FILENAME_SIZE 260
#define SEED_KEY_SIZE 16
#define RSA_ENCRYPTED_KEY_SIZE 128 // rsa.h�� ��ġ�ϵ��� ����
#define HEX_STR_SIZE (RSA_ENCRYPTED_KEY_SIZE * 2 + 1)

int main() {
    char input_filename[MAX_FILENAME_SIZE] = { 0 };
    char key_filename[MAX_FILENAME_SIZE] = { 0 };
    char secured_key_filename[MAX_FILENAME_SIZE] = { 0 };
    unsigned char pbUserKey[SEED_KEY_SIZE] = { 0 };
    unsigned char encrypted[RSA_ENCRYPTED_KEY_SIZE] = { 0 };
    int choice;

    printf("���̺긮�� ���� �Ϻ�ȣȭ ���α׷�\n");
    printf("------------------------------------------------------------------------------\n");

    while (1) {
        printf("�۾� ����:\n");
        printf(" 1. ���� ��ȣȭ\n");
        printf(" 2. ���� ��ȣȭ\n");
        printf(" 3. ����\n");
        printf(" >> ");
        scanf("%d", &choice);
        getchar(); // ���� ���� ����

        switch (choice) {
        case 1: {
            // ��ȣȭ�� ���� ����
            printf("��ȣȭ�� ������ �����ϼ���:\n");
            if (!openFileDialog(input_filename, sizeof(input_filename))) {
                printf("���� ������ ��ҵǾ����ϴ�.\n");
                break;
            }

            // SEED Ű ����
            printf("SEED Ű�� �ڵ����� �����մϴ�...\n");
            generateAndTransformKey(pbUserKey, sizeof(pbUserKey));
            printf("SEED Ű�� �����Ǿ����ϴ�: ");
            for (int i = 0; i < sizeof(pbUserKey); i++) {
                printf("%02X ", pbUserKey[i]);
            }
            printf("\n");

            // SEED�� ���� ��ȣȭ
            encrypt_file(input_filename, pbUserKey);

            // RSA ����Ű ���� ����
            printf("RSA ����Ű ������ �����ϼ���:\n");
            if (!openFileDialog(key_filename, sizeof(key_filename))) {
                printf("����Ű ���� ������ ��ҵǾ����ϴ�.\n");
                break;
            }

            // RSA�� SEED Ű ��ȣȭ
            printf("RSA ��ȣȭ�� �����մϴ�...\n");
            RSA_Enc(pbUserKey, encrypted, key_filename);

            printf("���� ��ȣȭ �Ϸ�.\n");
            break;
        }

        case 2: {
            // ��ȣȭ�� ���� ����
            printf("��ȣȭ�� ������ �����ϼ���:\n");
            if (!openFileDialog(input_filename, sizeof(input_filename))) {
                printf("���� ������ ��ҵǾ����ϴ�.\n");
                break;
            }

            // ��ȣȭ�� SEED Ű ���� ���� (���� Ž���⸦ ���� ����)
            printf("��ȣȭ�� SEED Ű ������ �����ϼ���:\n");
            if (!openFileDialog(secured_key_filename, sizeof(secured_key_filename))) {
                printf("��ȣȭ�� Ű ���� ������ ��ҵǾ����ϴ�.\n");
                break;
            }

            // RSA ����Ű ���� ����
            printf("RSA ����Ű ���� ��θ� �����ϼ���:\n");
            if (!openFileDialog(key_filename, sizeof(key_filename))) {
                printf("����Ű ���� ������ ��ҵǾ����ϴ�.\n");
                break;
            }

            // ��ȣȭ�� SEED Ű �б�
            FILE *hex_file = fopen(secured_key_filename, "r");
            if (hex_file == NULL) {
                printf("��ȣȭ�� Ű ������ �� �� �����ϴ�. ��θ� Ȯ���ϼ���: %s\n", secured_key_filename);
                break;
            }

            // Read the entire hex string from the file
            char *encrypted_hex = NULL;
            size_t hex_len = 0;
            fseek(hex_file, 0, SEEK_END);
            long file_size = ftell(hex_file);
            fseek(hex_file, 0, SEEK_SET);

            if (file_size <= 0) {
                printf("��ȣȭ�� Ű ������ ��� �ֽ��ϴ�.\n");
                fclose(hex_file);
                break;
            }

            encrypted_hex = (char *)malloc(file_size + 1);
            if (encrypted_hex == NULL) {
                printf("�޸� �Ҵ翡 �����߽��ϴ�.\n");
                fclose(hex_file);
                break;
            }

            size_t read_len = fread(encrypted_hex, 1, file_size, hex_file);
            encrypted_hex[read_len] = '\0';
            fclose(hex_file);

            // Remove any trailing newline characters
            while (read_len > 0 && (encrypted_hex[read_len - 1] == '\n' || encrypted_hex[read_len - 1] == '\r')) {
                encrypted_hex[read_len - 1] = '\0';
                read_len--;
            }

            // RSA�� SEED Ű ��ȣȭ
            unsigned char decrypted_key[SEED_KEY_SIZE] = { 0 };
            printf("RSA�� �̿��� SEED Ű�� ��ȣȭ�մϴ�...\n");
            RSA_Dec((unsigned char *)encrypted_hex, decrypted_key, key_filename);
            free(encrypted_hex);

            printf("��ȣȭ�� SEED Ű: ");
            for (int i = 0; i < sizeof(decrypted_key); i++) {
                printf("%02X ", decrypted_key[i]);
            }
            printf("\n");

            // SEED�� ���� ��ȣȭ
            decrypt_file(input_filename, decrypted_key);
            printf("��ȣȭ�� �Ϸ�Ǿ����ϴ�. ��� ����: decrypted_plane.txt\n");
            break;
        }

        case 3:
            printf("���α׷��� �����մϴ�.\n");
            return 0;

        default:
            printf("�߸��� �����Դϴ�. �ٽ� �Է��ϼ���.\n");
            break;
        }
    }

    return 0;
}
