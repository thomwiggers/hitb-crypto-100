#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include <stdlib.h>

const int rand_bytes = 16;

SHA1Context copy_context(SHA1Context src) {
    SHA1Context dest;
    SHA1Reset(&dest);
    dest = src;
    for (int i = 0; i < 5; i++) {
        dest.Message_Digest[i] = src.Message_Digest[i];
    }
    dest.Length_Low = src.Length_Low;
    dest.Length_High = src.Length_High;
    for (int i = 0; i < 64; i++) {
        dest.Message_Block[i] = src.Message_Block[i];
    }
    dest.Message_Block_Index = src.Message_Block_Index;
    dest.Computed = src.Computed;
    dest.Corrupted = src.Corrupted;
    return dest;
}

void getrand(FILE* fp, void* buf, size_t len) {
  if (fread(buf, 1, len, fp) == -1)
    puts("ERROR");
}

int main() {
    FILE *fp;
    fp = fopen("/dev/urandom", "r");

    SHA1Context sha;

    const unsigned char P[] =
        "\x25\x50\x44\x46\x2d\x31\x2e\x33\x0a\x25\xe2\xe3\xcf\xd3\x0a\x0a"
        "\x0a\x31\x20\x30\x20\x6f\x62\x6a\x0a\x3c\x3c\x2f\x57\x69\x64\x74"
        "\x68\x20\x32\x20\x30\x20\x52\x2f\x48\x65\x69\x67\x68\x74\x20\x33"
        "\x20\x30\x20\x52\x2f\x54\x79\x70\x65\x20\x34\x20\x30\x20\x52\x2f"
        "\x53\x75\x62\x74\x79\x70\x65\x20\x35\x20\x30\x20\x52\x2f\x46\x69"
        "\x6c\x74\x65\x72\x20\x36\x20\x30\x20\x52\x2f\x43\x6f\x6c\x6f\x72"
        "\x53\x70\x61\x63\x65\x20\x37\x20\x30\x20\x52\x2f\x4c\x65\x6e\x67"
        "\x74\x68\x20\x38\x20\x30\x20\x52\x2f\x42\x69\x74\x73\x50\x65\x72"
        "\x43\x6f\x6d\x70\x6f\x6e\x65\x6e\x74\x20\x38\x3e\x3e\x0a\x73\x74"
        "\x72\x65\x61\x6d\x0a\xff\xd8\xff\xfe\x00\x24\x53\x48\x41\x2d\x31"
        "\x20\x69\x73\x20\x64\x65\x61\x64\x21\x21\x21\x21\x21\x85\x2f\xec"
        "\x09\x23\x39\x75\x9c\x39\xb1\xa1\xc6\x3c\x4c\x97\xe1\xff\xfe\x01";

    const unsigned char M1_1[] =
        "\x7f\x46\xdc\x93\xa6\xb6\x7e\x01\x3b\x02\x9a\xaa\x1d\xb2\x56\x0b"
        "\x45\xca\x67\xd6\x88\xc7\xf8\x4b\x8c\x4c\x79\x1f\xe0\x2b\x3d\xf6"
        "\x14\xf8\x6d\xb1\x69\x09\x01\xc5\x6b\x45\xc1\x53\x0a\xfe\xdf\xb7"
        "\x60\x38\xe9\x72\x72\x2f\xe7\xad\x72\x8f\x0e\x49\x04\xe0\x46\xc2";

    const unsigned char M2_1[] =
        "\x30\x57\x0f\xe9\xd4\x13\x98\xab\xe1\x2e\xf5\xbc\x94\x2b\xe3\x35"
        "\x42\xa4\x80\x2d\x98\xb5\xd7\x0f\x2a\x33\x2e\xc3\x7f\xac\x35\x14"
        "\xe7\x4d\xdc\x0f\x2c\xc1\xa8\x74\xcd\x0c\x78\x30\x5a\x21\x56\x64"
        "\x61\x30\x97\x89\x60\x6b\xd0\xbf\x3f\x98\xcd\xa8\x04\x46\x29\xa1";

    const unsigned char M1_2[] =
        "\x73\x46\xdc\x91\x66\xb6\x7e\x11\x8f\x02\x9a\xb6\x21\xb2\x56\x0f"
        "\xf9\xca\x67\xcc\xa8\xc7\xf8\x5b\xa8\x4c\x79\x03\x0c\x2b\x3d\xe2"
        "\x18\xf8\x6d\xb3\xa9\x09\x01\xd5\xdf\x45\xc1\x4f\x26\xfe\xdf\xb3"
        "\xdc\x38\xe9\x6a\xc2\x2f\xe7\xbd\x72\x8f\x0e\x45\xbc\xe0\x46\xd2";

    const unsigned char M2_2[] =
        "\x3c\x57\x0f\xeb\x14\x13\x98\xbb\x55\x2e\xf5\xa0\xa8\x2b\xe3\x31"
        "\xfe\xa4\x80\x37\xb8\xb5\xd7\x1f\x0e\x33\x2e\xdf\x93\xac\x35\x00"
        "\xeb\x4d\xdc\x0d\xec\xc1\xa8\x64\x79\x0c\x78\x2c\x76\x21\x56\x60"
        "\xdd\x30\x97\x91\xd0\x6b\xd0\xaf\x3f\x98\xcd\xa4\xbc\x46\x29\xb1";

    const unsigned char S[] =
        "\xC6\x70\xED\x96\xC3\x1F\x19\xA2\x9E\x8E\x1C\x27\x13\xF6\xE0\x8B";

    SHA1Reset(&sha);
    SHA1Input(&sha, P, sizeof(P)-1);
    SHA1Input(&sha, M1_1, sizeof(M1_1)-1);
    SHA1Input(&sha, M2_1, sizeof(M2_1)-1);
    SHA1Input(&sha, S, sizeof(S)-1);
    SHA1Result(&sha);
    for (int i = 0; i < 5; i++) {
        printf("%08X ", sha.Message_Digest[i]);
    }
    puts("");

    SHA1Context collision;
    SHA1Reset(&collision);
    SHA1Input(&collision, P, sizeof(P)-1);
    SHA1Input(&collision, M1_2, sizeof(M1_2)-1);
    SHA1Input(&collision, M2_2, sizeof(M2_2)-1);
    SHA1Result(&collision);
    for (int i = 0; i < 5; i++) {
        printf("%02X ", collision.Message_Digest[i]);
    }
    puts("");
    SHA1Reset(&collision);
    SHA1Input(&collision, P, sizeof(P)-1);
    SHA1Input(&collision, M1_2, sizeof(M1_2)-1);
    SHA1Input(&collision, M2_2, sizeof(M2_2)-1);

    //SHA1Context attempt = copy_context(sha);
    SHA1Context attempt = sha;

    SHA1Result(&attempt);
    for (int i = 0; i < 5; i++) {
        printf("%02X ", attempt.Message_Digest[i]);
    }
    puts("");


    unsigned char buf[16];
    getrand(fp, buf, rand_bytes);

    long long attempts = 0;
    do {
        SHA1Reset(&attempt);
        SHA1Input(&attempt, P, sizeof(P)-1);
        SHA1Input(&attempt, M1_1, sizeof(M1_1)-1);
        SHA1Input(&attempt, M2_1, sizeof(M2_1)-1);
        attempts += 1;
        if (attempts % 10000L == 0) {
            printf("Attempt %lld\n", attempts);
        }
        getrand(fp, buf, rand_bytes);
        SHA1Input(&attempt, buf, 16);
        SHA1Result(&attempt);
    } while((attempt.Message_Digest[4] & 0xFFFFFFFF) != 0);
    printf("Needed %lld attempts\n", attempts);

    printf("S = 0x");
    for (int i = 0; i < 16; i++) {
        printf("%02X", (unsigned int) buf[i]);
    }
    puts("");

    for (int i = 0; i < 5; i++) {
        printf("%08X ", attempt.Message_Digest[i]);
    }

    puts("");

    puts("verifying");
    SHA1Input(&collision, buf, 16);
    SHA1Result(&collision);
    for (int i = 0; i < 5; i++) {
        printf("%02X ", collision.Message_Digest[i]);
    }
    puts("");

    //int r = system("killall sha1collision");
    return 0;
}
