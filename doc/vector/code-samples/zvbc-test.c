// Copyright 2022 Rivos Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <byteswap.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "vlen-bits.h"

//
// Assembly routine signatures.
//

// VCLMUL

extern uint64_t
zvbc_vclmul_vv(
    uint64_t* dest,
    const uint64_t* src2,
    const uint64_t* src1,
    uint64_t n
);

extern uint64_t
zvbc_vclmul_vx(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t rs1,
    uint64_t n
);

// VCLMULH

extern uint64_t
zvbc_vclmulh_vv(
    uint64_t* dest,
    const uint64_t* src2,
    const uint64_t* src1,
    uint64_t n
);

extern uint64_t
zvbc_vclmulh_vx(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t rs1,
    uint64_t n
);


void
Assert(bool predicate, int lineno, const char* filename)
{
    if (predicate) {
        return;
    }
    fprintf(stderr, "\n%s: %d: Failed assertion.\n", filename, lineno);
    abort();
}

#define ASSERT(PREDICATE) Assert(PREDICATE, __LINE__, __FILE__)

typedef __uint128_t uint128_t;

// @brief Return a 64-bit randomly generated number using rand()
//
// @return uint64_t
//
uint64_t
rand64()
{
    return rand() | ((uint64_t)rand() << 32);
}

uint128_t
carryless_multiply_64x64(uint64_t a64, uint64_t b64)
{
    const size_t kInputBits = 64;
    const uint128_t b128 = b64;

    uint128_t accumulator = 0;
    for (size_t i = 0; i < kInputBits; ++i) {
        // If the i-th bit is set, then "add" (xor) a left-shifted
        // version of b to the accumulator.
        if (((a64 >> i) & 1) != 0) {
            accumulator ^= b128 << i;
        }
    }
    return accumulator;
}

// @brief A helper function used to test the vclmul_vv instruction.
//
// This function inputs two vectors consisting of 64-bit scalars and outputs a
// vector such that c[i] is the low 64 bits of the 64x64->128 bit carryless
// multiplication of a[i] and b[i].
//
// @param a: The first vector we are multiplying
// @param b: The second vector we are multiplying
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
carryless_multiply64vv_low(const uint64_t* a,
                           const uint64_t* b,
                           size_t n,
                           uint64_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        const uint128_t result128 = carryless_multiply_64x64(a[i], b[i]);
        c[i] = (uint64_t)result128;
    }
}

// @brief A helper function used to test the vclmul_vx/vclmul_vi instructions.
//
// This function inputs a vectors consisting of 64-bit scalars and a scalar.
// Outputs a vector such that c[i] is the low 64 bits of the 64x64->128 bit
// carryless multiplication of a[i] and b.
//
// @param a: The first vector we are multiplying
// @param b: The scalar we are multiplying
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
carryless_multiply64vx_low(const uint64_t* a,
                           const uint64_t b,
                           size_t n,
                           uint64_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        const uint128_t result128 = carryless_multiply_64x64(a[i], b);
        c[i] = (uint64_t)result128;
    }
}

// @brief A helper function used to test the vclmul_vv instruction.
//
// This function inputs two vectors consisting of 64-bit scalars and outputs a
// vector such that c[i] is the high 64 bits of the 64x64->128 bit carryless
// multiplication of a[i] and b[i].
//
// @param a: The first vector we are multiplying
// @param b: The second vector we are multiplying
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
carryless_multiply64vv_high(const uint64_t* a,
                            const uint64_t* b,
                            size_t n,
                            uint64_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        const uint128_t result128 = carryless_multiply_64x64(a[i], b[i]);
        c[i] = (uint64_t)(result128 >> 64);
    }
}

// @brief A helper function used to test the vclmul_vx/vclmul_vi instructions.
//
// This function inputs a vectors consisting of 64-bit scalars and a scalar.
// Outputs a vector such that c[i] is the high 64 bits of the 64x64->128 bit
// carryless multiplication of a[i] and b.
//
// @param a: The first vector we are multiplying
// @param b: The scalar we are multiplying
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
carryless_multiply64vx_high(const uint64_t* a,
                            const uint64_t b,
                            size_t n,
                            uint64_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        const uint128_t result128 = carryless_multiply_64x64(a[i], b);
        c[i] = (uint64_t)(result128 >> 64);
    }
}

// @brief Tests vectorized carryless multiply intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vclmul()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs1[kNumElements];
    uint64_t vs2[kNumElements];

    LOG("--- Testing Vectorized Carryless Multiply (vector vector)");

    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs1[i] = rand64();
            vs2[i] = rand64();
        }
        uint64_t expected[kNumElements];
        carryless_multiply64vv_low(vs2, vs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed =
          zvbc_vclmul_vv(actual, vs2, vs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            for (size_t i = 0; i < kNumElements; ++i) {
                LOG("expected[%3zd]: 0x%016" PRIx64
                    ", actual[%3zd]: 0x%016" PRIx64,
                    i, expected[i], i, actual[i]);
            }
            return 1;
        }
    }

    LOG("--- Testing Vectorized Carryless Multiply (vector scalar)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        const uint64_t rs1 = rand64();
        uint64_t expected[kNumElements];
        carryless_multiply64vx_low(vs2, rs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed =
          zvbc_vclmul_vx(actual, vs2, rs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            LOG(" - round    : %zu", round);
            LOG(" - processed: %" PRIu64, processed);
            for (size_t i = 0; i < kNumElements; ++i) {
                const uint64_t ac = actual[i];
                const uint64_t ex = expected[i];
                LOG("expected[%3zd]: 0x%016" PRIx64
                    ", actual[%3zd]: 0x%016" PRIx64 " %s",
                    i, ex, i, ac, (ac == ex ? "==" : "!="));
            }
            return 1;
        }
    }

    return 0;
}

// @brief Tests vectorized carryless multiply high intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vclmulh()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs1[kNumElements];
    uint64_t vs2[kNumElements];

    LOG("--- Testing Vectorized Carryless Multiply High (vector vector)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs1[i] = rand64();
            vs2[i] = rand64();
        }
        uint64_t expected[kNumElements];
        carryless_multiply64vv_high(vs2, vs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed =
          zvbc_vclmulh_vv(actual, vs2, vs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            for (size_t i = 0; i < kNumElements; ++i) {
                LOG("expected[%3zd]: 0x%016" PRIx64
                    ", actual[%3zd]: 0x%016" PRIx64,
                    i, expected[i], i, actual[i]);
            }
            return 1;
        }
    }

    LOG("--- Testing Vectorized Carryless Multiply High (vector scalar)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        const uint64_t rs1 = rand64();

        uint64_t expected[kNumElements];
        carryless_multiply64vx_high(vs2, rs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed =
          zvbc_vclmulh_vx(actual, vs2, rs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            LOG(" - round    : %zu", round);
            LOG(" - processed: %" PRIu64, processed);
            for (size_t i = 0; i < kNumElements; ++i) {
                const uint64_t ac = actual[i];
                const uint64_t ex = expected[i];
                LOG("expected[%3zd]: 0x%016" PRIx64
                    ", actual[%3zd]: 0x%016" PRIx64 " %s",
                    i, ex, i, ac, (ac == ex ? "==" : "!="));
            }
            return 1;
        }
    }

    return 0;
}

// @brief Calls test functions for our intrinsics
//
// @return int
//
int
main()
{
    const uint64_t vlen = vlen_bits();
    LOG("VLEN = %" PRIu64, vlen);

    int res = 0;

    res = test_rand_vclmul();
    if (res != 0) {
        return res;
    }

    res = test_rand_vclmulh();
    if (res != 0) {
        return res;
    }

    return 0;
}
