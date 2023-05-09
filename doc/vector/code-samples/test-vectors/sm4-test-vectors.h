#ifndef _SM4_TEST_VECTORS_
#define _SM4_TEST_VECTORS_

#include <stdint.h>

#include "../sm4-test.h"

#define SM4_BLOCK_SIZE 4

static uint32_t gbt32907k1[SM4_BLOCK_SIZE] = {
    0x01234567, 0x89abcdef,
    0xfedcba98, 0x76543210};

static uint32_t gbt32907m1[SM4_BLOCK_SIZE] = {
    0x01234567, 0x89abcdef,
    0xfedcba98, 0x76543210};

static uint32_t gbt32907e1[SM4_BLOCK_SIZE] = {
    0x681edf34, 0xd206965e,
    0x86b3e94f, 0x536e4246};

static uint32_t gbt32907e2[SM4_BLOCK_SIZE] = {
    0x595298c7, 0xc6fd271f,
    0x0402f804, 0xc33d3f66};

static struct sm4_test_vector sm4_vectors[] = {
    {
        .message = gbt32907m1,
        .output=gbt32907e1,
        .master_key=gbt32907k1,
        .message_len=sizeof(gbt32907m1),
        .iterations=1,
        .encrypt=true
    },
    {
        .message = gbt32907m1,
        .output=gbt32907e2,
        .master_key=gbt32907k1,
        .message_len=sizeof(gbt32907m1),
        .iterations=1e6,
        .encrypt=true
    },
    {
        .message = gbt32907e1,
        .output=gbt32907m1,
        .master_key=gbt32907k1,
        .message_len=sizeof(gbt32907e1),
        .iterations=1,
        .encrypt=false
    },
    {
        .message = gbt32907e2,
        .output=gbt32907m1,
        .master_key=gbt32907k1,
        .message_len=sizeof(gbt32907e2),
        .iterations=1e6,
        .encrypt=false
    },
};

static struct sm4_test_suite sm4_suites[] = {
    {
        .name="Plain SM4",
        .vectors=sm4_vectors,
        .tests_count=sizeof(sm4_vectors)/ sizeof(sm4_vectors[0])
    }
};

#endif
