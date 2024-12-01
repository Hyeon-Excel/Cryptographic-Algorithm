// seed.cpp
#define _CRT_SECURE_NO_WARNINGS
#include "seed.h"

// 필요한 헤더 파일 포함
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <windows.h>    // 윈도우 API 사용
#include <commdlg.h>    // 대화 상자
#include <time.h>       // for srand and rand
#include <tchar.h>      // _T를 사용하기 위한 헤더 파일

// 엔디안 정의
#if __alpha__   ||  __alpha ||  __i386__    ||  i386    ||  _M_I86  ||  _M_IX86 ||  \
    __OS2__     ||  sun386  ||  __TURBOC__  ||  vax     ||  vms     ||  VMS     ||  __VMS || __linux__
#define LITTLE_ENDIAN
#else
#define BIG_ENDIAN
#endif

// SEED 상수 및 매크로 정의
#define NoRounds         16          // 라운드 수
#define NoRoundKeys      (NoRounds*2) // 라운드 키 수
#define SeedBlockSize    16          // 블록 크기 (바이트)
#define SeedBlockLen     128         // 블록 크기 (비트)

// 키 스케줄 상수
#define KC0     0x9e3779b9UL
#define KC1     0x3c6ef373UL
#define KC2     0x78dde6e6UL
#define KC3     0xf1bbcdccUL
#define KC4     0xe3779b99UL
#define KC5     0xc6ef3733UL
#define KC6     0x8dde6e67UL
#define KC7     0x1bbcdccfUL
#define KC8     0x3779b99eUL
#define KC9     0x6ef3733cUL
#define KC10    0xdde6e678UL
#define KC11    0xbbcdccf1UL
#define KC12    0x779b99e3UL
#define KC13    0xef3733c6UL
#define KC14    0xde6e678dUL
#define KC15    0xbcdccf1bUL

// 비트 회전 매크로
#if defined(_MSC_VER)
#define ROTL(x, n)     (_lrotl((x), (n)))  // 왼쪽 회전
#define ROTR(x, n)     (_lrotr((x), (n)))  // 오른쪽 회전
#else
#define ROTL(x, n)     (((x) << (n)) | ((x) >> (32-(n))))  // 왼쪽 회전
#define ROTR(x, n)     (((x) >> (n)) | ((x) << (32-(n))))  // 오른쪽 회전
#endif

// 엔디안 전환 매크로
#define EndianChange(dwS)( (ROTL((dwS),  8) & (DWORD)0x00ff00ff) | (ROTL((dwS), 24) & (DWORD)0xff00ff00) )

// 암호화 라운드 함수 매크로
#define GetB0(A)  ( (BYTE)((A)    ) )
#define GetB1(A)  ( (BYTE)((A)>> 8) )
#define GetB2(A)  ( (BYTE)((A)>>16) )
#define GetB3(A)  ( (BYTE)((A)>>24) )

// 키 스케줄 매크로
#define SEED_KeySched(L0, L1, R0, R1, K) {      \
    T0 = R0 ^ (K)[0];                           \
    T1 = R1 ^ (K)[1];                           \
    T1 ^= T0;                                   \
    T1 = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^      \
         SS2[GetB2(T1)] ^ SS3[GetB3(T1)];       \
    T0 = (T0 + T1) & 0xffffffff;                \
    T0 = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^      \
         SS2[GetB2(T0)] ^ SS3[GetB3(T0)];       \
    T1 = (T1 + T0) & 0xffffffff;                \
    T1 = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^      \
         SS2[GetB2(T1)] ^ SS3[GetB3(T1)];       \
    T0 = (T0 + T1) & 0xffffffff;                \
    L0 ^= T0; L1 ^= T1;                         \
}

#define RoundKeyUpdate0(K, A, B, C, D, KC) {    \
    T0 = A + C - KC;                            \
    T1 = B + KC - D;                            \
    (K)[0] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^  \
             SS2[GetB2(T0)] ^ SS3[GetB3(T0)];   \
    (K)[1] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^  \
             SS2[GetB2(T1)] ^ SS3[GetB3(T1)];   \
    T0 = A;                                     \
    A = (A>>8) ^ (B<<24);                       \
    B = (B>>8) ^ (T0<<24);                      \
}

#define RoundKeyUpdate1(K, A, B, C, D, KC) {    \
    T0 = A + C - KC;                            \
    T1 = B + KC - D;                            \
    (K)[0] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^  \
             SS2[GetB2(T0)] ^ SS3[GetB3(T0)];   \
    (K)[1] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^  \
             SS2[GetB2(T1)] ^ SS3[GetB3(T1)];   \
    T0 = C;                                     \
    C = (C<<8) ^ (D>>24);                       \
    D = (D<<8) ^ (T0>>24);                      \
}

// S-Box 테이블
static DWORD SS0[256] = {
0x2989a1a8, 0x05858184, 0x16c6d2d4, 0x13c3d3d0, 0x14445054, 0x1d0d111c, 0x2c8ca0ac, 0x25052124,
0x1d4d515c, 0x03434340, 0x18081018, 0x1e0e121c, 0x11415150, 0x3cccf0fc, 0x0acac2c8, 0x23436360,
0x28082028, 0x04444044, 0x20002020, 0x1d8d919c, 0x20c0e0e0, 0x22c2e2e0, 0x08c8c0c8, 0x17071314,
0x2585a1a4, 0x0f8f838c, 0x03030300, 0x3b4b7378, 0x3b8bb3b8, 0x13031310, 0x12c2d2d0, 0x2ecee2ec,
0x30407070, 0x0c8c808c, 0x3f0f333c, 0x2888a0a8, 0x32023230, 0x1dcdd1dc, 0x36c6f2f4, 0x34447074,
0x2ccce0ec, 0x15859194, 0x0b0b0308, 0x17475354, 0x1c4c505c, 0x1b4b5358, 0x3d8db1bc, 0x01010100,
0x24042024, 0x1c0c101c, 0x33437370, 0x18889098, 0x10001010, 0x0cccc0cc, 0x32c2f2f0, 0x19c9d1d8,
0x2c0c202c, 0x27c7e3e4, 0x32427270, 0x03838380, 0x1b8b9398, 0x11c1d1d0, 0x06868284, 0x09c9c1c8,
0x20406060, 0x10405050, 0x2383a3a0, 0x2bcbe3e8, 0x0d0d010c, 0x3686b2b4, 0x1e8e929c, 0x0f4f434c,
0x3787b3b4, 0x1a4a5258, 0x06c6c2c4, 0x38487078, 0x2686a2a4, 0x12021210, 0x2f8fa3ac, 0x15c5d1d4,
0x21416160, 0x03c3c3c0, 0x3484b0b4, 0x01414140, 0x12425250, 0x3d4d717c, 0x0d8d818c, 0x08080008,
0x1f0f131c, 0x19899198, 0x00000000, 0x19091118, 0x04040004, 0x13435350, 0x37c7f3f4, 0x21c1e1e0,
0x3dcdf1fc, 0x36467274, 0x2f0f232c, 0x27072324, 0x3080b0b0, 0x0b8b8388, 0x0e0e020c, 0x2b8ba3a8,
0x2282a2a0, 0x2e4e626c, 0x13839390, 0x0d4d414c, 0x29496168, 0x3c4c707c, 0x09090108, 0x0a0a0208,
0x3f8fb3bc, 0x2fcfe3ec, 0x33c3f3f0, 0x05c5c1c4, 0x07878384, 0x14041014, 0x3ecef2fc, 0x24446064,
0x1eced2dc, 0x2e0e222c, 0x0b4b4348, 0x1a0a1218, 0x06060204, 0x21012120, 0x2b4b6368, 0x26466264,
0x02020200, 0x35c5f1f4, 0x12829290, 0x0a8a8288, 0x0c0c000c, 0x3383b3b0, 0x3e4e727c, 0x10c0d0d0,
0x3a4a7278, 0x07474344, 0x16869294, 0x25c5e1e4, 0x26062224, 0x00808080, 0x2d8da1ac, 0x1fcfd3dc,
0x2181a1a0, 0x30003030, 0x37073334, 0x2e8ea2ac, 0x36063234, 0x15051114, 0x22022220, 0x38083038,
0x34c4f0f4, 0x2787a3a4, 0x05454144, 0x0c4c404c, 0x01818180, 0x29c9e1e8, 0x04848084, 0x17879394,
0x35053134, 0x0bcbc3c8, 0x0ecec2cc, 0x3c0c303c, 0x31417170, 0x11011110, 0x07c7c3c4, 0x09898188,
0x35457174, 0x3bcbf3f8, 0x1acad2d8, 0x38c8f0f8, 0x14849094, 0x19495158, 0x02828280, 0x04c4c0c4,
0x3fcff3fc, 0x09494148, 0x39093138, 0x27476364, 0x00c0c0c0, 0x0fcfc3cc, 0x17c7d3d4, 0x3888b0b8,
0x0f0f030c, 0x0e8e828c, 0x02424240, 0x23032320, 0x11819190, 0x2c4c606c, 0x1bcbd3d8, 0x2484a0a4,
0x34043034, 0x31c1f1f0, 0x08484048, 0x02c2c2c0, 0x2f4f636c, 0x3d0d313c, 0x2d0d212c, 0x00404040,
0x3e8eb2bc, 0x3e0e323c, 0x3c8cb0bc, 0x01c1c1c0, 0x2a8aa2a8, 0x3a8ab2b8, 0x0e4e424c, 0x15455154,
0x3b0b3338, 0x1cccd0dc, 0x28486068, 0x3f4f737c, 0x1c8c909c, 0x18c8d0d8, 0x0a4a4248, 0x16465254,
0x37477374, 0x2080a0a0, 0x2dcde1ec, 0x06464244, 0x3585b1b4, 0x2b0b2328, 0x25456164, 0x3acaf2f8,
0x23c3e3e0, 0x3989b1b8, 0x3181b1b0, 0x1f8f939c, 0x1e4e525c, 0x39c9f1f8, 0x26c6e2e4, 0x3282b2b0,
0x31013130, 0x2acae2e8, 0x2d4d616c, 0x1f4f535c, 0x24c4e0e4, 0x30c0f0f0, 0x0dcdc1cc, 0x08888088,
0x16061214, 0x3a0a3238, 0x18485058, 0x14c4d0d4, 0x22426260, 0x29092128, 0x07070304, 0x33033330,
0x28c8e0e8, 0x1b0b1318, 0x05050104, 0x39497178, 0x10809090, 0x2a4a6268, 0x2a0a2228, 0x1a8a9298
};

static DWORD SS1[256] = {
0x38380830, 0xe828c8e0, 0x2c2d0d21, 0xa42686a2, 0xcc0fcfc3, 0xdc1eced2, 0xb03383b3, 0xb83888b0,
0xac2f8fa3, 0x60204060, 0x54154551, 0xc407c7c3, 0x44044440, 0x6c2f4f63, 0x682b4b63, 0x581b4b53,
0xc003c3c3, 0x60224262, 0x30330333, 0xb43585b1, 0x28290921, 0xa02080a0, 0xe022c2e2, 0xa42787a3,
0xd013c3d3, 0x90118191, 0x10110111, 0x04060602, 0x1c1c0c10, 0xbc3c8cb0, 0x34360632, 0x480b4b43,
0xec2fcfe3, 0x88088880, 0x6c2c4c60, 0xa82888a0, 0x14170713, 0xc404c4c0, 0x14160612, 0xf434c4f0,
0xc002c2c2, 0x44054541, 0xe021c1e1, 0xd416c6d2, 0x3c3f0f33, 0x3c3d0d31, 0x8c0e8e82, 0x98188890,
0x28280820, 0x4c0e4e42, 0xf436c6f2, 0x3c3e0e32, 0xa42585a1, 0xf839c9f1, 0x0c0d0d01, 0xdc1fcfd3,
0xd818c8d0, 0x282b0b23, 0x64264662, 0x783a4a72, 0x24270723, 0x2c2f0f23, 0xf031c1f1, 0x70324272,
0x40024242, 0xd414c4d0, 0x40014141, 0xc000c0c0, 0x70334373, 0x64274763, 0xac2c8ca0, 0x880b8b83,
0xf437c7f3, 0xac2d8da1, 0x80008080, 0x1c1f0f13, 0xc80acac2, 0x2c2c0c20, 0xa82a8aa2, 0x34340430,
0xd012c2d2, 0x080b0b03, 0xec2ecee2, 0xe829c9e1, 0x5c1d4d51, 0x94148490, 0x18180810, 0xf838c8f0,
0x54174753, 0xac2e8ea2, 0x08080800, 0xc405c5c1, 0x10130313, 0xcc0dcdc1, 0x84068682, 0xb83989b1,
0xfc3fcff3, 0x7c3d4d71, 0xc001c1c1, 0x30310131, 0xf435c5f1, 0x880a8a82, 0x682a4a62, 0xb03181b1,
0xd011c1d1, 0x20200020, 0xd417c7d3, 0x00020202, 0x20220222, 0x04040400, 0x68284860, 0x70314171,
0x04070703, 0xd81bcbd3, 0x9c1d8d91, 0x98198991, 0x60214161, 0xbc3e8eb2, 0xe426c6e2, 0x58194951,
0xdc1dcdd1, 0x50114151, 0x90108090, 0xdc1cccd0, 0x981a8a92, 0xa02383a3, 0xa82b8ba3, 0xd010c0d0,
0x80018181, 0x0c0f0f03, 0x44074743, 0x181a0a12, 0xe023c3e3, 0xec2ccce0, 0x8c0d8d81, 0xbc3f8fb3,
0x94168692, 0x783b4b73, 0x4c505c1c, 0x82a2a022, 0x81a1a021, 0x43636023, 0x03232023, 0x4d414c0d,
0xc8c0c808, 0x8e929c1e, 0x8c909c1c, 0x0a32383a, 0x0c000c0c, 0x0e222c2e, 0x8ab2b83a, 0x4e626c2e,
0x8f939c1f, 0x4a52581a, 0xc2f2f032, 0x82929012, 0xc3f3f033, 0x49414809, 0x48707838, 0xccc0cc0c,
0x05111415, 0xcbf3f83b, 0x40707030, 0x45717435, 0x4f737c3f, 0x05313435, 0x00101010, 0x03030003,
0x44606424, 0x4d616c2d, 0xc6c2c406, 0x44707434, 0xc5d1d415, 0x84b0b434, 0xcae2e82a, 0x09010809,
0x46727436, 0x09111819, 0xcef2fc3e, 0x40404000, 0x02121012, 0xc0e0e020, 0x8db1bc3d, 0x05010405,
0xcaf2f83a, 0x01010001, 0xc0f0f030, 0x0a22282a, 0x4e525c1e, 0x89a1a829, 0x46525416, 0x43434003,
0x85818405, 0x04101414, 0x89818809, 0x8b93981b, 0x80b0b030, 0xc5e1e425, 0x48404808, 0x49717839,
0x87939417, 0xccf0fc3c, 0x0e121c1e, 0x82828002, 0x01212021, 0x8c808c0c, 0x0b13181b, 0x4f535c1f,
0x47737437, 0x44505414, 0x82b2b032, 0x0d111c1d, 0x05212425, 0x4f434c0f, 0x00000000, 0x46424406,
0xcde1ec2d, 0x48505818, 0x42525012, 0xcbe3e82b, 0x4e727c3e, 0xcad2d81a, 0xc9c1c809, 0xcdf1fc3d,
0x00303030, 0x85919415, 0x45616425, 0x0c303c3c, 0x86b2b436, 0xc4e0e424, 0x8bb3b83b, 0x4c707c3c,
0x0e020c0e, 0x40505010, 0x09313839, 0x06222426, 0x02323032, 0x84808404, 0x49616829, 0x83939013,
0x07333437, 0xc7e3e427, 0x04202424, 0x84a0a424, 0xcbc3c80b, 0x43535013, 0x0a02080a, 0x87838407,
0xc9d1d819, 0x4c404c0c, 0x83838003, 0x8f838c0f, 0xcec2cc0e, 0x0b33383b, 0x4a42480a, 0x87b3b437
};

static DWORD SS2[256] = {
0xa1a82989, 0x81840585, 0xd2d416c6, 0xd3d013c3, 0x50541444, 0x111c1d0d, 0xa0ac2c8c, 0x21242505,
0x515c1d4d, 0x43400343, 0x10181808, 0x121c1e0e, 0x51501141, 0xf0fc3ccc, 0xc2c80aca, 0x63602343,
0x20282808, 0x40440444, 0x20202000, 0x919c1d8d, 0xe0e020c0, 0xe2e022c2, 0xc0c808c8, 0x13141707,
0xa1a42585, 0x838c0f8f, 0x03030303, 0x73783b4b, 0xb3b83b8b, 0x13101303, 0xd2d012c2, 0xe2ec2ece,
0x70703040, 0x808c0c8c, 0x333c3f0f, 0xa0a82888, 0x32303202, 0xd1dc1dcd, 0xf2f436c6, 0x70743444,
0xe0ec2ccc, 0x91941585, 0x03080b0b, 0x53541747, 0x505c1c4c, 0x53581b4b, 0xb1bc3d8d, 0x01000101,
0x20242404, 0x101c1c0c, 0x73703343, 0x90981888, 0x10101000, 0xc0cc0ccc, 0xf2f032c2, 0xd1d819c9,
0x202c2c0c, 0xe3e427c7, 0x72703242, 0x83800383, 0x93981b8b, 0xd1d011c1, 0x82840686, 0xc1c809c9,
0x60602040, 0x50501040, 0xa3a02383, 0xe3e82bcb, 0x010c0d0d, 0xb2b43686, 0x929c1e8e, 0x434c0f4f,
0xb3b43787, 0x52581a4a, 0xc2c406c6, 0x70783848, 0xa2a42686, 0x12101202, 0xa3ac2f8f, 0xd1d415c5,
0x61602141, 0xc3c003c3, 0xb0b43484, 0x41400141, 0x52501242, 0x717c3d4d, 0x818c0d8d, 0x00080808,
0x131c1f0f, 0x91981989, 0x00000000, 0x11181909, 0x00040404, 0x53501343, 0xf3f437c7, 0xe1e021c1,
0xf1fc3dcd, 0x72743646, 0x232c2f0f, 0x23242707, 0xb0b03080, 0x83880b8b, 0x020c0e0e, 0xa3a82b8b,
0xa2a02282, 0x626c2e4e, 0x93901383, 0x414c0d4d, 0x61682949, 0x707c3c4c, 0x01080909, 0x02080a0a,
0xb3bc3f8f, 0xe3ec2fcf, 0xf3f033c3, 0xc1c405c5, 0x83840787, 0x10141404, 0xf2fc3ece, 0x60642444,
0xd2dc1ece, 0x222c2e0e, 0x43480b4b, 0x12181a0a, 0x02040606, 0x21202101, 0x63682b4b, 0x62642646,
0x02000202, 0xf1f435c5, 0x92901282, 0x82880a8a, 0x000c0c0c, 0xb3b03383, 0x727c3e4e, 0xd0d010c0,
0x72783a4a, 0x43440747, 0x92941686, 0xe1e425c5, 0x22242606, 0x80800080, 0xa1ac2d8d, 0xd3dc1fcf,
0xa1a02181, 0x30303000, 0x33343707, 0xa2ac2e8e, 0x32343606, 0x11141505, 0x22202202, 0x30383808,
0xf0f434c4, 0xa3a42787, 0x41440545, 0x404c0c4c, 0x81800181, 0xe1e829c9, 0x80840484, 0x93941787,
0x31343505, 0xc3c80bcb, 0xc2cc0ece, 0x303c3c0c, 0x71703141, 0x11101101, 0xc3c407c7, 0x81880989,
0x71743545, 0xf3f83bcb, 0xd2d81aca, 0xf0f838c8, 0x90941484, 0x51581949, 0x82800282, 0xc0c404c4,
0xf3fc3fcf, 0x41480949, 0x31383909, 0x63642747, 0xc0c000c0, 0xc3cc0fcf, 0xd3d417c7, 0xb0b83888,
0x030c0f0f, 0x828c0e8e, 0x42400242, 0x23202303, 0x91901181, 0x606c2c4c, 0xd3d81bcb, 0xa0a42484,
0x30343404, 0xf1f031c1, 0x40480848, 0xc2c002c2, 0x636c2f4f, 0x313c3d0d, 0x212c2d0d, 0x40400040,
0xb2bc3e8e, 0x323c3e0e, 0xb0bc3c8c, 0xc1c001c1, 0xa2a82a8a, 0xb2b83a8a, 0x424c0e4e, 0x51541545,
0x33383b0b, 0xd0dc1ccc, 0x60682848, 0x737c3f4f, 0x909c1c8c, 0xd0d818c8, 0x42480a4a, 0x52541646,
0x73743747, 0xa0a02080, 0xe1ec2dcd, 0x42440646, 0xb1b43585, 0x23282b0b, 0x61642545, 0xf2f83aca,
0xe3e023c3, 0xb1b83989, 0xb1b03181, 0x939c1f8f, 0x525c1e4e, 0xf1f839c9, 0xe2e426c6, 0xb2b03282,
0x31303101, 0xe2e82aca, 0x616c2d4d, 0x535c1f4f, 0xe0e424c4, 0xf0f030c0, 0xc1cc0dcd, 0x80880888,
0x12141606, 0x32383a0a, 0x50581848, 0xd0d414c4, 0x62602242, 0x21282909, 0x03040707, 0x33303303,
0xe0e828c8, 0x13181b0b, 0x01040505, 0x71783949, 0x90901080, 0x62682a4a, 0x22282a0a, 0x92981a8a
};

static DWORD SS3[256] = {
0x08303838, 0xc8e0e828, 0x0d212c2d, 0x86a2a426, 0xcfc3cc0f, 0xced2dc1e, 0x83b3b033, 0x88b0b838,
0x8fa3ac2f, 0x40606020, 0x45515415, 0xc7c3c407, 0x44404404, 0x4f636c2f, 0x4b63682b, 0x4b53581b,
0xc3c3c003, 0x42626022, 0x03333033, 0x85b1b435, 0x09212829, 0x80a0a020, 0xc2e2e022, 0x87a3a427,
0xc3d3d013, 0x81919011, 0x01111011, 0x06020406, 0x0c101c1c, 0x8cb0bc3c, 0x06323436, 0x4b43480b,
0xcfe3ec2f, 0x88808808, 0x4c606c2c, 0x88a0a828, 0x07131417, 0xc4c0c404, 0x06121416, 0xc4f0f434,
0xc2c2c002, 0x45414405, 0xc1e1e021, 0xc6d2d416, 0x0f333c3f, 0x0d313c3d, 0x8e828c0e, 0x88909818,
0x08202828, 0x4e424c0e, 0xc6f2f436, 0x0e323c3e, 0x85a1a425, 0xc9f1f839, 0x0c0d0d01, 0xdc1fcfd3,
0xd818c8d0, 0x0b23282b, 0x46626426, 0x783a4a72, 0x24270723, 0x2c2f0f23, 0xf031c1f1, 0x70324272,
0x42424002, 0xc4d0d414, 0x41414001, 0xc0c0c000, 0x43737033, 0x47636427, 0x8ca0ac2c, 0x8b83880b,
0xc7f3f437, 0x8da1ac2d, 0x80808000, 0x0f131c1f, 0xcac2c80a, 0x0c202c2c, 0x8aa2a82a, 0x04303434,
0xc2d2d012, 0x0b03080b, 0xcee2ec2e, 0xc9e1e829, 0x4d515c1d, 0x84909414, 0x08101818, 0xc8f0f838,
0x47535417, 0x8ea2ac2e, 0x08080808, 0xc5c1c405, 0x03131013, 0xcdc1cc0d, 0x86868284, 0x89b1b839,
0xcff3fc3f, 0x4d717c3d, 0xc1c1c001, 0x01313031, 0xc5f1f435, 0x8a82880a, 0x4a62682a, 0x81b1b031,
0xc1d1d011, 0x00202020, 0xc7d3d417, 0x02020002, 0x02222022, 0x04000404, 0x48606828, 0x41717031,
0x07030407, 0xcbd3d81b, 0x8d919c1d, 0x89919819, 0x41616021, 0x8eb2bc3e, 0xc6e2e426, 0x49515819,
0xcdd1dc1d, 0x41515011, 0x80909010, 0xccd0dc1c, 0x8a92981a, 0x83a3a023, 0x8ba3a82b, 0xc0d0d010,
0x81818001, 0x0f030c0f, 0x47434407, 0x0a12181a, 0xc3e3e023, 0xcce0ec2c, 0x8d818c0d, 0x8fb3bc3f,
0x86929416, 0x4b73783b, 0x4c505c1c, 0x82a2a022, 0x81a1a021, 0x43636023, 0x03232023, 0x4d414c0d,
0xc8c0c808, 0x8e929c1e, 0x8c909c1c, 0x0a32383a, 0x0c000c0c, 0x0e222c2e, 0x8ab2b83a, 0x4e626c2e,
0x8f939c1f, 0x4a52581a, 0xc2f2f032, 0x82929012, 0xc3f3f033, 0x49414809, 0x48707838, 0xccc0cc0c,
0x05111415, 0xcbf3f83b, 0x40707030, 0x45717435, 0x4f737c3f, 0x05313435, 0x00101010, 0x03030003,
0x44606424, 0x4d616c2d, 0xc6c2c406, 0x44707434, 0xc5d1d415, 0x84b0b434, 0xcae2e82a, 0x09010809,
0x46727436, 0x09111819, 0xcef2fc3e, 0x40404000, 0x02121012, 0xc0e0e020, 0x8db1bc3d, 0x05010405,
0xcaf2f83a, 0x01010001, 0xc0f0f030, 0x0a22282a, 0x4e525c1e, 0x89a1a829, 0x46525416, 0x43434003,
0x85818405, 0x04101414, 0x89818809, 0x8b93981b, 0x80b0b030, 0xc5e1e425, 0x48404808, 0x49717839,
0x87939417, 0xccf0fc3c, 0x0e121c1e, 0x82828002, 0x01212021, 0x8c808c0c, 0x0b13181b, 0x4f535c1f,
0x47737437, 0x44505414, 0x82b2b032, 0x0d111c1d, 0x05212425, 0x4f434c0f, 0x00000000, 0x46424406,
0xcde1ec2d, 0x48505818, 0x42525012, 0xcbe3e82b, 0x4e727c3e, 0xcad2d81a, 0xc9c1c809, 0xcdf1fc3d,
0x00303030, 0x85919415, 0x45616425, 0x0c303c3c, 0x86b2b436, 0xc4e0e424, 0x8bb3b83b, 0x4c707c3c,
0x0e020c0e, 0x40505010, 0x09313839, 0x06222426, 0x02323032, 0x84808404, 0x49616829, 0x83939013,
0x07333437, 0xc7e3e427, 0x04202424, 0x84a0a424, 0xcbc3c80b, 0x43535013, 0x0a02080a, 0x87838407,
0xc9d1d819, 0x4c404c0c, 0x83838003, 0x8f838c0f, 0xcec2cc0e, 0x0b33383b, 0x4a42480a, 0x87b3b437
};

// AES S-box
const unsigned char AES_SBOX[256] = {
    // 0x00 - 0x0F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    // 0x10 - 0x1F
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // 0x20 - 0x2F
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    // 0x30 - 0x3F
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    // 0x40 - 0x4F
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    // 0x50 - 0x5F
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    // 0x60 - 0x6F
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    // 0x70 - 0x7F
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    // 0x80 - 0x8F
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    // 0x90 - 0x9F
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    // 0xA0 - 0xAF
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    // 0xB0 - 0xBF
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    // 0xC0 - 0xCF
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    // 0xD0 - 0xDF
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    // 0xE0 - 0xEF
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    // 0xF0 - 0xFF
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Rcon
const unsigned char AES_RCON[11] = {
    0x00, // Rcon[0] is not used
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};

// GF(2^8) multiplication
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// AES Key Expansion
void AES_KeyExpansion(const unsigned char *key, unsigned char *expanded_key) {
    // AES-128: 16-byte key, 176-byte expanded key
    memcpy(expanded_key, key, 16);

    unsigned char temp[4];
    int bytes_generated = 16;
    int rcon_iteration = 1;

    while (bytes_generated < 176) {
        // Copy last 4 bytes
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_key[bytes_generated - 4 + i];
        }

        // Every 16 bytes, perform key schedule core
        if (bytes_generated % 16 == 0) {
            // Rotate word
            unsigned char k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // Substitute bytes using S-box
            for (int i = 0; i < 4; i++) {
                temp[i] = AES_SBOX[temp[i]];
            }

            // XOR with Rcon
            temp[0] ^= AES_RCON[rcon_iteration++];
        }

        // XOR with 16 bytes ago
        for (int i = 0; i < 4; i++) {
            expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ temp[i];
            bytes_generated++;
        }
    }
}

// AES SubBytes
void AES_SubBytes(unsigned char *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

// AES ShiftRows
void AES_ShiftRows(unsigned char *state) {
    unsigned char temp[16];

    // Copy state to temp with shifted rows
    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];

    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];

    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];

    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];

    // Copy temp back to state
    memcpy(state, temp, 16);
}

// AES MixColumns
void AES_MixColumns(unsigned char *state) {
    unsigned char temp_state[16];
    for (int i = 0; i < 4; i++) {
        int idx = i * 4;
        temp_state[idx] = gmul(state[idx], 2) ^ gmul(state[idx + 1], 3) ^ state[idx + 2] ^ state[idx + 3];
        temp_state[idx + 1] = state[idx] ^ gmul(state[idx + 1], 2) ^ gmul(state[idx + 2], 3) ^ state[idx + 3];
        temp_state[idx + 2] = state[idx] ^ state[idx + 1] ^ gmul(state[idx + 2], 2) ^ gmul(state[idx + 3], 3);
        temp_state[idx + 3] = gmul(state[idx], 3) ^ state[idx + 1] ^ state[idx + 2] ^ gmul(state[idx + 3], 2);
    }
    memcpy(state, temp_state, 16);
}

// AES AddRoundKey
void AES_AddRoundKey(unsigned char *state, const unsigned char *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// AES Round
void AES_Round(unsigned char *state, const unsigned char *round_key) {
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_MixColumns(state);
    AES_AddRoundKey(state, round_key);
}

// AES Final Round (no MixColumns)
void AES_FinalRound(unsigned char *state, const unsigned char *round_key) {
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_AddRoundKey(state, round_key);
}

// AES Encryption (for key transformation)
void AES_Encrypt(unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    unsigned char state[16];
    memcpy(state, plaintext, 16);

    unsigned char expanded_key[176];
    AES_KeyExpansion(key, expanded_key);

    // Initial AddRoundKey
    AES_AddRoundKey(state, expanded_key);

    // 9 rounds
    for (int round = 1; round < 10; round++) {
        AES_Round(state, expanded_key + (round * 16));
    }

    // Final round
    AES_FinalRound(state, expanded_key + 160);

    memcpy(ciphertext, state, 16);
}

// AES Key Transformation: 10 rounds of AES encryption
void AES_KeyTransform(unsigned char *key) {
    unsigned char transformed_key[16];
    unsigned char temp[16];
    memcpy(temp, key, 16);

    for (int round = 0; round < 10; round++) {
        AES_Encrypt(temp, key, transformed_key);
        memcpy(temp, transformed_key, 16);
    }

    memcpy(key, transformed_key, 16); // Update key with transformed key
}

// SEED 암호화 함수
void SEED_Encrypt(BYTE *pbData, DWORD *pdwRoundKey)			// 암호화 데이터, 라운드 키 입력
{
    DWORD L0, L1, R0, R1;		// 라운드 별 입/출력 데이터
    DWORD T0, T1;				// 임시 변수
    DWORD *K = pdwRoundKey;		// 라운드 키 포인터

    L0 = ((DWORD)pbData[3] << 24) | ((DWORD)pbData[2] << 16) | ((DWORD)pbData[1] << 8) | ((DWORD)pbData[0]);
    L1 = ((DWORD)pbData[7] << 24) | ((DWORD)pbData[6] << 16) | ((DWORD)pbData[5] << 8) | ((DWORD)pbData[4]);
    R0 = ((DWORD)pbData[11] << 24) | ((DWORD)pbData[10] << 16) | ((DWORD)pbData[9] << 8) | ((DWORD)pbData[8]);
    R1 = ((DWORD)pbData[15] << 24) | ((DWORD)pbData[14] << 16) | ((DWORD)pbData[13] << 8) | ((DWORD)pbData[12]);

#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif
    SEED_KeySched(L0, L1, R0, R1, K);
    SEED_KeySched(R0, R1, L0, L1, K + 2);
    SEED_KeySched(L0, L1, R0, R1, K + 4);
    SEED_KeySched(R0, R1, L0, L1, K + 6);
    SEED_KeySched(L0, L1, R0, R1, K + 8);
    SEED_KeySched(R0, R1, L0, L1, K + 10);
    SEED_KeySched(L0, L1, R0, R1, K + 12);
    SEED_KeySched(R0, R1, L0, L1, K + 14);
    SEED_KeySched(L0, L1, R0, R1, K + 16);
    SEED_KeySched(R0, R1, L0, L1, K + 18);
    SEED_KeySched(L0, L1, R0, R1, K + 20);
    SEED_KeySched(R0, R1, L0, L1, K + 22);
    SEED_KeySched(L0, L1, R0, R1, K + 24);
    SEED_KeySched(R0, R1, L0, L1, K + 26);
    SEED_KeySched(L0, L1, R0, R1, K + 28);
    SEED_KeySched(R0, R1, L0, L1, K + 30);

#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif
    pbData[0] = (BYTE)((R0) & 0xFF);
    pbData[1] = (BYTE)((R0 >> 8) & 0xFF);
    pbData[2] = (BYTE)((R0 >> 16) & 0xFF);
    pbData[3] = (BYTE)((R0 >> 24) & 0xFF);

    pbData[4] = (BYTE)((R1) & 0xFF);
    pbData[5] = (BYTE)((R1 >> 8) & 0xFF);
    pbData[6] = (BYTE)((R1 >> 16) & 0xFF);
    pbData[7] = (BYTE)((R1 >> 24) & 0xFF);

    pbData[8] = (BYTE)((L0) & 0xFF);
    pbData[9] = (BYTE)((L0 >> 8) & 0xFF);
    pbData[10] = (BYTE)((L0 >> 16) & 0xFF);
    pbData[11] = (BYTE)((L0 >> 24) & 0xFF);

    pbData[12] = (BYTE)((L1) & 0xFF);
    pbData[13] = (BYTE)((L1 >> 8) & 0xFF);
    pbData[14] = (BYTE)((L1 >> 16) & 0xFF);
    pbData[15] = (BYTE)((L1 >> 24) & 0xFF);
}

// 복호화 함수
void SEED_Decrypt(BYTE *pbData, DWORD *pdwRoundKey)
{
    DWORD L0, L1, R0, R1;
    DWORD T0, T1;
    DWORD *K = pdwRoundKey;


    L0 = ((DWORD)pbData[3] << 24) | ((DWORD)pbData[2] << 16) | ((DWORD)pbData[1] << 8) | ((DWORD)pbData[0]);
    L1 = ((DWORD)pbData[7] << 24) | ((DWORD)pbData[6] << 16) | ((DWORD)pbData[5] << 8) | ((DWORD)pbData[4]);
    R0 = ((DWORD)pbData[11] << 24) | ((DWORD)pbData[10] << 16) | ((DWORD)pbData[9] << 8) | ((DWORD)pbData[8]);
    R1 = ((DWORD)pbData[15] << 24) | ((DWORD)pbData[14] << 16) | ((DWORD)pbData[13] << 8) | ((DWORD)pbData[12]);

#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif
    SEED_KeySched(L0, L1, R0, R1, K + 30);
    SEED_KeySched(R0, R1, L0, L1, K + 28);
    SEED_KeySched(L0, L1, R0, R1, K + 26);
    SEED_KeySched(R0, R1, L0, L1, K + 24);
    SEED_KeySched(L0, L1, R0, R1, K + 22);
    SEED_KeySched(R0, R1, L0, L1, K + 20);
    SEED_KeySched(L0, L1, R0, R1, K + 18);
    SEED_KeySched(R0, R1, L0, L1, K + 16);
    SEED_KeySched(L0, L1, R0, R1, K + 14);
    SEED_KeySched(R0, R1, L0, L1, K + 12);
    SEED_KeySched(L0, L1, R0, R1, K + 10);
    SEED_KeySched(R0, R1, L0, L1, K + 8);
    SEED_KeySched(L0, L1, R0, R1, K + 6);
    SEED_KeySched(R0, R1, L0, L1, K + 4);
    SEED_KeySched(L0, L1, R0, R1, K + 2);
    SEED_KeySched(R0, R1, L0, L1, K + 0);

#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif
    pbData[0] = (BYTE)((R0) & 0xFF);
    pbData[1] = (BYTE)((R0 >> 8) & 0xFF);
    pbData[2] = (BYTE)((R0 >> 16) & 0xFF);
    pbData[3] = (BYTE)((R0 >> 24) & 0xFF);

    pbData[4] = (BYTE)((R1) & 0xFF);
    pbData[5] = (BYTE)((R1 >> 8) & 0xFF);
    pbData[6] = (BYTE)((R1 >> 16) & 0xFF);
    pbData[7] = (BYTE)((R1 >> 24) & 0xFF);

    pbData[8] = (BYTE)((L0) & 0xFF);
    pbData[9] = (BYTE)((L0 >> 8) & 0xFF);
    pbData[10] = (BYTE)((L0 >> 16) & 0xFF);
    pbData[11] = (BYTE)((L0 >> 24) & 0xFF);

    pbData[12] = (BYTE)((L1) & 0xFF);
    pbData[13] = (BYTE)((L1 >> 8) & 0xFF);
    pbData[14] = (BYTE)((L1 >> 16) & 0xFF);
    pbData[15] = (BYTE)((L1 >> 24) & 0xFF);
}

// 파일 선택 대화창 함수
int openFileDialog(char *filename, size_t filenameSize) {
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = filename;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = filenameSize;
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE) {
        return 1; // 성공
    }
    return 0; // 실패
}


// 키 스케쥴 함수
void SEED_KeySchedKey(
    DWORD *pdwRoundKey,			// 암/복호화를 하기 위한 라운드 키
    BYTE *pbUserKey)			// 전체 키
{
    DWORD A, B, C, D;				// 라운드별 입/출력 값
    DWORD T0, T1;					// 임시 변수
    DWORD *K = pdwRoundKey;			// 라운드 키 포인터

    A = ((DWORD)pbUserKey[3] << 24) | ((DWORD)pbUserKey[2] << 16) | ((DWORD)pbUserKey[1] << 8) | ((DWORD)pbUserKey[0]);
    B = ((DWORD)pbUserKey[7] << 24) | ((DWORD)pbUserKey[6] << 16) | ((DWORD)pbUserKey[5] << 8) | ((DWORD)pbUserKey[4]);
    C = ((DWORD)pbUserKey[11] << 24) | ((DWORD)pbUserKey[10] << 16) | ((DWORD)pbUserKey[9] << 8) | ((DWORD)pbUserKey[8]);
    D = ((DWORD)pbUserKey[15] << 24) | ((DWORD)pbUserKey[14] << 16) | ((DWORD)pbUserKey[13] << 8) | ((DWORD)pbUserKey[12]);

#ifndef BIG_ENDIAN
    A = EndianChange(A);
    B = EndianChange(B);
    C = EndianChange(C);
    D = EndianChange(D);
#endif
    RoundKeyUpdate0(K, A, B, C, D, KC0);	    // K_1,0 and K_1,1
    RoundKeyUpdate1(K + 2, A, B, C, D, KC1);	// K_2,0 and K_2,1
    RoundKeyUpdate0(K + 4, A, B, C, D, KC2);	// K_3,0 and K_3,1
    RoundKeyUpdate1(K + 6, A, B, C, D, KC3);	// K_4,0 and K_4,1
    RoundKeyUpdate0(K + 8, A, B, C, D, KC4);	// K_5,0 and K_5,1
    RoundKeyUpdate1(K + 10, A, B, C, D, KC5);	// K_6,0 and K_6,1
    RoundKeyUpdate0(K + 12, A, B, C, D, KC6);	// K_7,0 and K_7,1
    RoundKeyUpdate1(K + 14, A, B, C, D, KC7);	// K_8,0 and K_8,1
    RoundKeyUpdate0(K + 16, A, B, C, D, KC8);	// K_9,0 and K_9,1
    RoundKeyUpdate1(K + 18, A, B, C, D, KC9);	// K_10,0 and K_10,1
    RoundKeyUpdate0(K + 20, A, B, C, D, KC10);	// K_11,0 and K_11,1
    RoundKeyUpdate1(K + 22, A, B, C, D, KC11);	// K_12,0 and K_12,1
    RoundKeyUpdate0(K + 24, A, B, C, D, KC12);	// K_13,0 and K_13,1
    RoundKeyUpdate1(K + 26, A, B, C, D, KC13);	// K_14,0 and K_14,1
    RoundKeyUpdate0(K + 28, A, B, C, D, KC14);	// K_15,0 and K_15,1

    T0 = A + C - KC15;
    T1 = B - D + KC15;
    K[30] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^	// K_16,0
        SS2[GetB2(T0)] ^ SS3[GetB3(T0)];
    K[31] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^	// K_16,1
        SS2[GetB2(T1)] ^ SS3[GetB3(T1)];
}

// SEED 암호화에 변형된 키 사용
void SEED_KeySchedKeyTransformed(
    DWORD *pdwRoundKey,			// 암/복호화를 하기 위한 라운드 키
    BYTE *pbTransformedKey)			// AES 변형된 전체 키
{
    SEED_KeySchedKey(pdwRoundKey, pbTransformedKey);
}

// 파일 암호화 함수
void encrypt_file(const char *input_filename, BYTE *user_key) {
    FILE *in_file = fopen(input_filename, "rb");
    FILE *out_file = fopen("encrypted_plane.txt", "wb"); // 바이너리 모드

    if (!in_file || !out_file) {
        printf("파일 열기 실패\n");
        return;
    }

    // 입력 파일 이름에서 경로 제거
    const char *file_name = strrchr(input_filename, '\\');
    if (file_name) {
        file_name++;                // '/' 또는 '\' 이후가 파일 이름
    }
    else {
        file_name = input_filename; // 경로가 없으면 입력 파일 이름 전체가 파일 이름
    }

    // 출력 파일 이름 생성
    char output_filename[260];
    snprintf(output_filename, sizeof(output_filename), "encrypted_%s", file_name);

    // 출력 파일 열기
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        printf("출력 파일을 열 수 없습니다. 파일 이름: %s\n", output_filename);
        fclose(in_file);
        return;
    }

    // 파일 확장자 추출 및 헤더 기록
    const char *ext = strrchr(file_name, '.'); // 확장자 추출
    fwrite(ext, 1, strlen(ext) + 1, output_file); // 확장자를 헤더로 기록

    // Round keys
    DWORD round_keys[32];
    SEED_KeySchedKeyTransformed(round_keys, user_key);

    BYTE buffer[BUFFER_SIZE];
    size_t read_bytes;

    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, in_file)) > 0) {
        if (read_bytes < BUFFER_SIZE) {
            // 패딩 추가
            BYTE padding_size = BUFFER_SIZE - read_bytes;
            memset(buffer + read_bytes, padding_size, padding_size);
        }
        SEED_Encrypt(buffer, round_keys); // 암호화 수행
        fwrite(buffer, 1, BUFFER_SIZE, output_file); // 암호문 출력
    }

    fclose(in_file);
    fclose(output_file);
}

// 파일 복호화 함수
void decrypt_file(const char *input_filename, BYTE *user_key) {
    // 입력 파일 열기
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        printf("입력 파일을 열 수 없습니다.\n");
        return;
    }

    // 입력 파일 이름에서 경로 제거
    const char *file_name = strrchr(input_filename, '\\');
    if (file_name) {
        file_name++;                // '/' 또는 '\' 이후가 파일 이름
    }
    else {
        file_name = input_filename; // 경로가 없으면 입력 파일 이름 전체가 파일 이름
    }

    // 헤더에서 확장자 읽기
    char ext[10] = { 0 }; // 초기화하여 버퍼를 비웁니다.
    if (fread(ext, 1, sizeof(ext) - 1, input_file) <= 0) { // 헤더 읽기
        printf("확장자를 읽을 수 없습니다.\n");
        fclose(input_file);
        return;
    }

    // 출력 파일 이름 생성
    char output_filename[260];
    snprintf(output_filename, sizeof(output_filename), "decrypted_%s", file_name);

    // 출력 파일 열기
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        printf("출력 파일을 열 수 없습니다.\n");
        fclose(input_file);
        return;
    }

    // 라운드 키 설정
    DWORD round_keys[32];
    SEED_KeySchedKeyTransformed(round_keys, user_key);

    BYTE buffer[BUFFER_SIZE];
    size_t read_bytes;

    // 파일 크기 계산
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    rewind(input_file);

    // 암호화 헤더를 건너뜀
    fseek(input_file, strlen(ext) + 1, SEEK_SET); // 확장자 길이 + NULL 문자

    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        SEED_Decrypt(buffer, round_keys);  // 복호화 수행

        // 마지막 블록 패딩 제거
        if (ftell(input_file) == file_size) { // EOF
            BYTE padding_size = buffer[BUFFER_SIZE - 1];
            if (padding_size < BUFFER_SIZE) {
                fwrite(buffer, 1, BUFFER_SIZE - padding_size, output_file);
            }
            else {
                fwrite(buffer, 1, BUFFER_SIZE, output_file);
            }
        }
        else {
            fwrite(buffer, 1, BUFFER_SIZE, output_file);
        }
    }

    fclose(input_file);
    fclose(output_file);
}

// 랜덤 키 생성 함수
void generateRandomKey(BYTE *key, size_t keyLength) {
    for (size_t i = 0; i < keyLength; i++) {
        key[i] = rand() % 256; // 0~255 사이의 값
    }
}

// AES 키 변형 함수
void transformKeyWithAES(BYTE *key, size_t keyLength) {
    // AES requires 16-byte keys
    if (keyLength != 16) {
        printf("키 길이가 16바이트가 아닙니다.\n");
        return;
    }

    AES_KeyTransform(key);
}

// 키 생성 및 변형 함수
void generateAndTransformKey(BYTE *transformedKey, size_t keyLength) {
    generateRandomKey(transformedKey, keyLength); // 랜덤 키 생성
    transformKeyWithAES(transformedKey, keyLength); // AES 기반 키 변형
    printf("SEED 암호 키가 생성 되었습니다.\n");
}

// 일반 텍스트를 16진수 키로 변환하는 함수 (이전 키 설정 옵션을 유지하려면 필요)
void generateKeyFromText(const char *textKey, BYTE *seedKey, size_t keyLength) {
    size_t textLength = strlen(textKey);

    // 초기화
    memset(seedKey, 0x00, keyLength);

    if (textLength >= keyLength) {
        // 키가 충분히 길면 앞에서 keyLength만큼 복사
        memcpy(seedKey, textKey, keyLength);
    }
    else {
        // 키가 짧으면 전체를 복사하고 나머지는 0x00으로 패딩
        memcpy(seedKey, textKey, textLength);
    }
}