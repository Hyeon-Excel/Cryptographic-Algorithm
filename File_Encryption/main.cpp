#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seed.h"
#include "rsa.h"

// 주요 상수 정의
#define MAX_FILENAME_SIZE 260
#define SEED_KEY_SIZE 16
#define RSA_ENCRYPTED_KEY_SIZE 128 // rsa.h와 일치하도록 수정
#define HEX_STR_SIZE (RSA_ENCRYPTED_KEY_SIZE * 2 + 1)

int main() {
    char input_filename[MAX_FILENAME_SIZE] = { 0 };
    char key_filename[MAX_FILENAME_SIZE] = { 0 };
    char secured_key_filename[MAX_FILENAME_SIZE] = { 0 };
    unsigned char pbUserKey[SEED_KEY_SIZE] = { 0 };
    unsigned char encrypted[RSA_ENCRYPTED_KEY_SIZE] = { 0 };
    int choice;

    printf("하이브리드 파일 암복호화 프로그램\n");
    printf("------------------------------------------------------------------------------\n");

    while (1) {
        printf("작업 선택:\n");
        printf(" 1. 파일 암호화\n");
        printf(" 2. 파일 복호화\n");
        printf(" 3. 종료\n");
        printf(" >> ");
        scanf("%d", &choice);
        getchar(); // 개행 문자 제거

        switch (choice) {
        case 1: {
            // 암호화할 파일 선택
            printf("암호화할 파일을 선택하세요:\n");
            if (!openFileDialog(input_filename, sizeof(input_filename))) {
                printf("파일 선택이 취소되었습니다.\n");
                break;
            }

            // SEED 키 생성
            printf("SEED 키를 자동으로 생성합니다...\n");
            generateAndTransformKey(pbUserKey, sizeof(pbUserKey));
            printf("SEED 키가 생성되었습니다: ");
            for (int i = 0; i < sizeof(pbUserKey); i++) {
                printf("%02X ", pbUserKey[i]);
            }
            printf("\n");

            // SEED로 파일 암호화
            encrypt_file(input_filename, pbUserKey);

            // RSA 공개키 파일 선택
            printf("RSA 공개키 파일을 선택하세요:\n");
            if (!openFileDialog(key_filename, sizeof(key_filename))) {
                printf("공개키 파일 선택이 취소되었습니다.\n");
                break;
            }

            // RSA로 SEED 키 암호화
            printf("RSA 암호화를 시작합니다...\n");
            RSA_Enc(pbUserKey, encrypted, key_filename);

            printf("파일 암호화 완료.\n");
            break;
        }

        case 2: {
            // 복호화할 파일 선택
            printf("복호화할 파일을 선택하세요:\n");
            if (!openFileDialog(input_filename, sizeof(input_filename))) {
                printf("파일 선택이 취소되었습니다.\n");
                break;
            }

            // 암호화된 SEED 키 파일 선택 (파일 탐색기를 통해 선택)
            printf("암호화된 SEED 키 파일을 선택하세요:\n");
            if (!openFileDialog(secured_key_filename, sizeof(secured_key_filename))) {
                printf("암호화된 키 파일 선택이 취소되었습니다.\n");
                break;
            }

            // RSA 개인키 파일 선택
            printf("RSA 개인키 파일 경로를 선택하세요:\n");
            if (!openFileDialog(key_filename, sizeof(key_filename))) {
                printf("개인키 파일 선택이 취소되었습니다.\n");
                break;
            }

            // 암호화된 SEED 키 읽기
            FILE *hex_file = fopen(secured_key_filename, "r");
            if (hex_file == NULL) {
                printf("암호화된 키 파일을 열 수 없습니다. 경로를 확인하세요: %s\n", secured_key_filename);
                break;
            }

            // Read the entire hex string from the file
            char *encrypted_hex = NULL;
            size_t hex_len = 0;
            fseek(hex_file, 0, SEEK_END);
            long file_size = ftell(hex_file);
            fseek(hex_file, 0, SEEK_SET);

            if (file_size <= 0) {
                printf("암호화된 키 파일이 비어 있습니다.\n");
                fclose(hex_file);
                break;
            }

            encrypted_hex = (char *)malloc(file_size + 1);
            if (encrypted_hex == NULL) {
                printf("메모리 할당에 실패했습니다.\n");
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

            // RSA로 SEED 키 복호화
            unsigned char decrypted_key[SEED_KEY_SIZE] = { 0 };
            printf("RSA를 이용해 SEED 키를 복호화합니다...\n");
            RSA_Dec((unsigned char *)encrypted_hex, decrypted_key, key_filename);
            free(encrypted_hex);

            printf("복호화된 SEED 키: ");
            for (int i = 0; i < sizeof(decrypted_key); i++) {
                printf("%02X ", decrypted_key[i]);
            }
            printf("\n");

            // SEED로 파일 복호화
            decrypt_file(input_filename, decrypted_key);
            printf("복호화가 완료되었습니다. 출력 파일: decrypted_plane.txt\n");
            break;
        }

        case 3:
            printf("프로그램을 종료합니다.\n");
            return 0;

        default:
            printf("잘못된 선택입니다. 다시 입력하세요.\n");
            break;
        }
    }

    return 0;
}
