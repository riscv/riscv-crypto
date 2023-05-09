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

// VANDN

extern uint64_t
zvbb_vandn8_vv(
    uint8_t* dest,      // a0
    const uint8_t* vs2, // a1
    const uint8_t* vs1, // a2
    uint64_t n          // a3
);

extern uint64_t
zvbb_vandn8_vx(
    uint8_t* dest,      // a0
    const uint8_t* vs2, // a1
    const uint64_t rs1, // a2
    uint64_t n          // a3
);

// VROL

extern uint64_t
zvbb_vrol_vv(
    uint64_t* dest,
    const uint64_t* src2,
    const uint64_t* src1,
    uint64_t n
);

extern uint64_t
zvbb_vrol_vx(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t src1,
    uint64_t n
);

// VROR

extern uint64_t
zvbb_vror_vv(
    uint64_t* dest,
    const uint64_t* src2,
    const uint64_t* src1,
    uint64_t n
);

extern uint64_t
zvbb_vror_vx(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t src1,
    uint64_t n
);

extern uint64_t
zvbb_vror_vi56(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t n
);

extern uint64_t
zvbb_vbrev_v(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t n,
    uint64_t sew
);

extern uint64_t
zvbb_vrev8_v(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t n,
    uint64_t sew
);

extern uint64_t
zvbb_vbrev8_v(
    uint64_t* dest,
    const uint64_t* src2,
    uint64_t n
);

extern uint64_t
zvbb_vclz_v(
    uint64_t* dest,
    const uint64_t* src2,
    size_t n
);

extern uint64_t
zvbb_vctz_v(
    uint64_t* dest,
    const uint64_t* src2,
    size_t n
);

extern uint64_t
zvbb_vcpop_v(
    uint64_t* dest,
    const uint64_t* src2,
    size_t n
);

extern uint64_t
zvbb_vwsll32_vv(
    uint64_t* dest,
    const uint32_t* vs2,
    const uint32_t* vs1,
    size_t n
);

extern uint64_t
zvbb_vwsll32_vx(
    uint64_t* dest,
    const uint32_t* vs2,
    uint64_t rs1,
    size_t n
);

extern uint64_t
zvbb_vwsll32_vi15(
    uint64_t* dest,
    const uint32_t* src2,
    size_t n
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

// @brief A helper function used to test the vandn_vv intrinsic.
//
// This function inputs two vectors consisting of N-bit unsigned scalars and
// outputs a vector such that c[i] = a[i] & ~b[i].
//
// @param a: The first vector (to be inverted)
// @param b: The second vector
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
and_not_8_vv(const uint8_t* a, const uint8_t* b, size_t n, uint8_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        c[i] = a[i] & (~b[i]);
    }
}

// @brief A helper function used to test the vandn_vx intrinsic.
//
// This function inputs a scalar and a vector consisting
// of N-bit unsigned scalars and outputs a vector such that c[i] is the and-not
// of a[i] and b.
//
// @param a: The first vector we are multiplying
// @param b: The scalar we are multiplying
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
and_not_8_vx(uint8_t* a, uint8_t b, size_t n, uint8_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        c[i] = a[i] & (~b);
    }
}

uint64_t
ror64(uint64_t x, uint64_t shift)
{
    // Users must ensure that the shift value is in [0, 63].
    ASSERT(shift < 64);
    // We must check for shift-by-0 to avoid UB (x << 64 is UB).
    return (shift == 0 ? x : ((x >> shift) | (x << (64 - shift))));
}

uint64_t
rol64(uint64_t x, uint64_t shift)
{
    // Users must ensure that the shift value is in [0, 63].
    ASSERT(shift < 64);
    // We must check for shift-by-0 to avoid UB (x >> 64 is UB).
    return (shift == 0 ? x : ((x << shift) | (x >> (64 - shift))));
}

// @brief A helper function used to test the vror_vv intrinsic.
//
// This function inputs two vectors consisting of 64-bit scalars and outputs a
// vector such that c[i] is a[i] rotated right by b[i].
//
// @param a: The first vector we are rotating
// @param b: The second vector we rotate the first vector by
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
rotate_right64vv(uint64_t* a, uint64_t* b, size_t n, uint64_t* c)
{
    for (size_t i = 0; i < n; ++i) {
        const uint64_t shift = b[i] % 64;
        c[i] = ror64(a[i], shift);
    }
}

// @brief A helper function used to test the vror_vx intrinsic.
//
// This function inputs one vectors consisting of 64-bit scalars and a 64-bit
// scalar. This function outputs a vector such that c[i] is a[i] rotated right
// by b[i].
//
// @param a: The first vector we are rotating
// @param b: The scalar we rotate the first vector by
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
rotate_right64vx(uint64_t* a, uint64_t b, size_t n, uint64_t* c)
{
    const uint64_t shift = b % 64;
    for (size_t i = 0; i < n; i++) {
        c[i] = ror64(a[i], shift);
    }
}

// @brief A helper function used to test the vrol_vv intrinsic.
//
// This function inputs two vectors consisting of 64-bit scalars and outputs a
// vector such that c[i] is a[i] rotated left by b[i].
//
// @param a: The first vector we are rotating
// @param b: The second vector we rotate the first vector by
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
rotate_left64vv(uint64_t* a, uint64_t* b, size_t n, uint64_t* c)
{
    for (size_t i = 0; i < n; i++) {
        const uint64_t shift = b[i] % 64;
        c[i] = rol64(a[i], shift);
    }
}

// @brief A helper function used to test the vrol_vx intrinsic.
//
// This function inputs one vectors consisting of 64-bit scalars and a 64-bit
// scalar. This function outputs a vector such that c[i] is a[i] rotated left by
// b[i].
//
// @param a: The first vector we are rotating
// @param b: The scalar we rotate the first vector by
// @param n: Size of a, b and c vectors
// @param c: The output vector
//
void
rotate_left64vx(uint64_t* a, uint64_t b, size_t n, uint64_t* c)
{
    const uint64_t shift = b % 64;
    for (size_t i = 0; i < n; i++) {
        c[i] = rol64(a[i], shift);
    }
}

enum VSEW
{
    VSEW8 = 8,
    VSEW16 = 16,
    VSEW32 = 32,
    VSEW64 = 64,
};

// @brief byteswap_v is a helper function used to test
// the vrev8_v intrinsic. This function inputs a vector consisting of 64-bit
// scalars and outputs a vector whose elements have their bytes swapped. The
// element size is specified in the last parameter.
//
// @param a: The vector we are byte-swapping
// @param n: Number of uint64_t vector elements
// @param sew: width of the element to byte-swap.
//
void
byteswap_v(uint64_t* a, size_t n, enum VSEW sew)
{
    for (size_t i = 0; i < n; ++i) {
        if (sew == VSEW16) {
            uint16_t* elem = (uint16_t*)(a + i);
            elem[0] = bswap_16(elem[0]);
            elem[1] = bswap_16(elem[1]);
            elem[2] = bswap_16(elem[2]);
            elem[3] = bswap_16(elem[3]);
        } else if (sew == VSEW32) {
            uint32_t* elem = (uint32_t*)(a + i);
            elem[0] = bswap_32(elem[0]);
            elem[1] = bswap_32(elem[1]);
        } else if (sew == VSEW64)
            a[i] = bswap_64(a[i]);
    }
}

#define BIT(x, i) (((x) >> (i)) & 0x1)
#define SET_BIT(x, i, v) (((x) & ~(0x1UL << (i))) | (((v)&0x1UL) << (i)))
// @brief bitswap_in_bytes_v is a helper function used to test
// the vbrev8_v intrinsic. This function inputs a vector consisting of 64-bit
// scalars and outputs a vector whose bytes have their bit order swapped.
//
// @param a: The vector we are byte-swapping
// @param n: Number of uint64_t vector elements
//
void
bitswap_in_bytes_v(uint64_t* a, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        for (int j = 0; j < 8; j++) {
            for (int k = 0; k < 4; k++) {
                int b1_pos = 8 * j + k;
                int b2_pos = 8 * j + (7 - k);
                int b1 = BIT(a[i], b1_pos);
                a[i] = SET_BIT(a[i], b1_pos, BIT(a[i], b2_pos));
                a[i] = SET_BIT(a[i], b2_pos, b1);
            }
        }
    }
}

// @brief bitswap_in_element_v is a helper function used to test
// the vbrev_v intrinsic. This function inputs a vector consisting of 64-bit
// scalars and outputs a vector whose elements have their bit order swapped.
//
// @param a: The vector we are bit-swapping
// @param n: Number of uint64_t vector elements
// @param sew: width of the element to byte-swap.
//
void
bitswap_in_element_v(uint64_t* a, size_t n, enum VSEW sew)
{
    char* const base = (char*)a;
    for (size_t offset = 0; offset < (n * sizeof(uint64_t)); offset += (sew / 8)) {
        char* const elt_ptr = base + offset;
        switch (sew) {
        case VSEW8: {
            const size_t nbits = 8 * sizeof(uint8_t);
            uint8_t* const elt = (uint8_t*)(elt_ptr);
            const uint8_t orig = *elt;
            uint8_t swapped = 0;
            for (size_t i = 0; i < nbits; ++i) {
                swapped |= ((orig >> (nbits - 1 -i)) & 0x1) << i;
            }
            *elt = swapped;
            break;
        }

        case VSEW16: {
            const size_t nbits = 8 * sizeof(uint16_t);
            uint16_t* const elt = (uint16_t*)(elt_ptr);
            const uint16_t orig = *elt;
            uint16_t swapped = 0;
            for (size_t i = 0; i < nbits; ++i) {
                swapped |= ((orig >> (nbits - 1 -i)) & 0x1) << i;
            }
            *elt = swapped;
            break;
        }

        case VSEW32: {
            const size_t nbits = 8 * sizeof(uint32_t);
            uint32_t* const elt = (uint32_t*)(elt_ptr);
            const uint32_t orig = *elt;
            uint32_t swapped = 0;
            for (size_t i = 0; i < nbits; ++i) {
                swapped |= ((orig >> (nbits - 1 -i)) & 0x1) << i;
            }
            *elt = swapped;
            break;
        }

        case VSEW64: {
            const size_t nbits = 8 * sizeof(uint64_t);
            uint64_t* const elt = (uint64_t*)(elt_ptr);
            const uint64_t orig = *elt;
            uint64_t swapped = 0;
            for (size_t i = 0; i < nbits; ++i) {
                swapped |= ((orig >> (nbits - 1 -i)) & 0x1) << i;
            }
            *elt = swapped;
            break;
        }
        }
    }
}

// @brief A function counting the number of leading zeros in a uint64_t.
//
// @param x: The input integer.
//
uint64_t
clz64(uint64_t x) {
    for (int i = 63; i >= 0; i--) {
        if ((x >> i) & 0x1) {
            return 63 - i;
        }
    }
    return 64;
}

// @brief A helper function used to test the vclz intrinsic.
//
// dest[i] = clz64(a[i])  for i in [0, n)
//
// @param dest: The vector receiving the counts of zeroes.
// @param a: The input vector
// @param n: Size of dest and a vectors
//
void
clz64_v(uint64_t* dest, const uint64_t* a, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        dest[i] = clz64(a[i]);
    }
}

// @brief A function counting the number of trailing zeros in a uint64_t.
//
// @param x: The input integer.
//
uint64_t
ctz64(uint64_t x) {
    for (int i = 0; i < 64; i++) {
        if ((x >> i) & 0x1) {
            return i;
        }
    }
    return 64;
}

// @brief A helper function used to test the vctz intrinsic.
//
// dest[i] = ctz64(a[i])  for i in [0, n)
//
// @param dest: The vector receiving the counts of zeroes.
// @param a: The input vector
// @param n: Size of dest and a vectors
//
void
ctz64_v(uint64_t* dest, const uint64_t* a, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        dest[i] = ctz64(a[i]);
    }
}

// @brief A function counting the number ones in a uint64_t.
//
// @param x: The input integer.
//
uint64_t
cpop64(uint64_t x) {
    uint64_t count = 0;
    for (int i = 0; i < 64; i++) {
        if ((x >> i) & 0x1) {
            count++;
        }
    }
    return count;
}

// @brief A helper function used to test the vcpop intrinsic.
//
// dest[i] = cpop64(a[i])  for i in [0, n)
//
// @param dest: The vector receiving the counts of ones.
// @param a: The input vector
// @param n: Size of dest and a vectors
//
void
cpop64_v(uint64_t* dest, const uint64_t* a, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        dest[i] = cpop64(a[i]);
    }
}

uint64_t
wsll32(uint32_t x, uint32_t shift) {
    // Shift amount is maked by (2*SEW - 1).
    return ((uint64_t)x) << (shift & 63);
}

void
vwsll32_vv(uint64_t* dest, const uint32_t* a, const uint32_t* shifts, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        dest[i] = wsll32(a[i], shifts[i]);
    }
}

void
vwsll32_vx(uint64_t* dest, const uint32_t* a, const uint32_t shift, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        dest[i] = wsll32(a[i], shift);
    }
}

// @brief Return a 8-bit randomly generated number using rand()
//
// @return uint8_t
//
uint8_t
rand8()
{
    return rand() / ((RAND_MAX + 1u) / 256);
}

// @brief Return a 32-bit randomly generated number using rand()
//
// @return uint32_t
//
uint32_t
rand32()
{
    return rand();
}

// @brief Return a 64-bit randomly generated number using rand()
//
// @return uint64_t
//
uint64_t
rand64()
{
    return rand() | ((uint64_t)rand() << 32);
}

// @brief Tests vectorized and-not intrinsic in assembly using randomly
// generated test vectors of uint8_t.
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vandn8()
{
#define kNumElements 33
#define kRounds 1000

    // Using a std::vector<> to get implicit conversion to std::span<>.
    // We don't need varying size, but
    uint8_t vs1[kNumElements] = { 0 };
    uint8_t vs2[kNumElements] = { 0 };

    LOG("--- Testing Vectorized AND-NOT (8b, vector-vector)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs1[i] = rand8();
            vs2[i] = rand8();
        }
        // vs2 gets inverted (expected[i] = vs1[i] &~ vs2[i]).
        uint8_t expected[kNumElements];
        and_not_8_vv(vs2, vs1, kNumElements, expected);

        uint8_t actual[kNumElements] = { 0 };
        const uint64_t processed =
          zvbb_vandn8_vv(actual, vs2, vs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            for (size_t i = 0; i < kNumElements; ++i) {
                LOG("expected[%3zd]: 0x%02x, actual[%3zd]: 0x%02x",
                    i, expected[i], i, actual[i]);
            }
            return 1;
        }
    }

    LOG("--- Testing Vectorized AND-NOT (8b, vector-scalar)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand8();
        }
        const uint8_t rs1 = rand8();
        uint8_t expected[kNumElements];
        and_not_8_vx(vs2, rs1, kNumElements, expected);

        uint8_t actual[kNumElements] = { 0 };
        const uint64_t processed =
          zvbb_vandn8_vx(actual, vs2, rs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            for (size_t i = 0; i < kNumElements; ++i) {
                LOG("expected[%3zd]: 0x%02x, actual[%3zd]: 0x%02x",
                    i, expected[i], i, actual[i]);
            }
            return 1;
        }
    }

    return 0;
}

// @brief Tests vectorized rotate left intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vrol()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs1[kNumElements];
    uint64_t vs2[kNumElements];

    LOG("--- Testing Vectorized Rotate Left (vector vector)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs1[i] = rand64();
            vs2[i] = rand64();
        }
        uint64_t expected[kNumElements];
        rotate_left64vv(vs2, vs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vrol_vv(actual, vs2, vs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            return 1;
        }
    }

    LOG("--- Testing Vectorized Rotate Left (vector scalar)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t rs1 = rand64();
        uint64_t expected[kNumElements];
        rotate_left64vx(vs2, rs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vrol_vx(actual, vs2, rs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            return 1;
        }
    }

    return 0;
}

// @brief Tests vectorized rotate right intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vror()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs1[kNumElements];
    uint64_t vs2[kNumElements];

    LOG("--- Testing Vectorized Rotate Right (vector vector)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs1[i] = rand64();
            vs2[i] = rand64();
        }
        uint64_t expected[kNumElements];
        rotate_right64vv(vs2, vs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vror_vv(actual, vs2, vs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            return 1;
        }
    }

    LOG("--- Testing Vectorized Rotate Right (vector scalar)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t rs1 = rand64();
        uint64_t expected[kNumElements];
        rotate_right64vx(vs2, rs1, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vror_vx(actual, vs2, rs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            LOG(" - round    : %zu", round);
            LOG(" - processed: %" PRIu64 "\n", processed);
            for (size_t i = 0; i < kNumElements; ++i) {
                const uint64_t ac = actual[i];
                const uint64_t ex = expected[i];
                LOG("expected[%3zu]: 0x%016" PRIx64
                    ", actual[%3zu]: 0x%016" PRIx64 " %s",
                    i, ex, i, ac, (ac == ex ? "==" : "!="));
            }
            return 1;
        }
    }

    LOG("--- Testing Vectorized Rotate Right (vector immediate == 56)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t expected[kNumElements];
        rotate_right64vx(vs2, 56, kNumElements, expected);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vror_vi56(actual, vs2, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            LOG(" - round    : %zu", round);
            LOG(" - kNumElements: %u", kNumElements);
            LOG(" - processed: %" PRIu64, processed);
            for (size_t i = 0; i < kNumElements; ++i) {
                const uint64_t ac = actual[i];
                const uint64_t ex = expected[i];
                LOG("expected[%3zu]: 0x%016" PRIx64
                    ", actual[%3zu]: 0x%016" PRIx64 " %s",
                    i, ex, i, ac, (ac == ex ? "==" : "!="));
            }
            return 1;
        }
    }

    return 0;
}

// @brief Tests vectorized bit reversal in element intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vbrev(enum VSEW sew)
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs2[kNumElements];

    LOG("Running Vectorized Bit-Reversal-in-Element test suite for SEW %d... ", sew);
    size_t round = 0;
    for (; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t original[kNumElements];
        uint64_t expected[kNumElements];
        memcpy(expected, vs2, sizeof(expected));
        memcpy(original, vs2, sizeof(expected));
        bitswap_in_element_v(expected, kNumElements, sew);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vbrev_v(actual, vs2, kNumElements, sew);

        int res = memcmp(actual, expected, sizeof(expected));
        if (processed != kNumElements || res) {
            LOG("failure,\n'actual' does NOT match 'expected', round=%zu",
                round);
            LOG("    original           | expected           | actual");
            for (size_t i = 0; i < kNumElements; i++) {
                LOG("%2zu: 0x%016lx | 0x%016lx | 0x%016lx",
                    i, original[i], expected[i], actual[i]);
            }
            return 1;
        }
    }
    LOG("success, %zu test rounds were run.", round);
    return 0;
}

// @brief Tests vectorized byte reversal intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vrev8(enum VSEW sew)
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs2[kNumElements];

    LOG("Running Vectorized Byte Reversal test suite for SEW %d... ", sew);
    size_t round = 0;
    for (; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t original[kNumElements];
        uint64_t expected[kNumElements];
        memcpy(expected, vs2, sizeof(expected));
        memcpy(original, vs2, sizeof(expected));
        byteswap_v(expected, kNumElements, sew);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vrev8_v(actual, vs2, kNumElements, sew);

        int res = memcmp(actual, expected, sizeof(expected));
        if (processed != kNumElements || res) {
            LOG("failure,\n'actual' does NOT match 'expected', round=%zu",
                round);
            LOG("    original           | expected           | actual");
            for (size_t i = 0; i < kNumElements; i++) {
                LOG("%2zu: 0x%016lx | 0x%016lx | 0x%016lx",
                    i, original[i], expected[i], actual[i]);
            }
            return 1;
        }
    }
    LOG("success, %zu test rounds were run.", round);
    return 0;
}

// @brief Tests vectorized bits in byte reversal intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vbrev8(void)
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs2[kNumElements];

    LOG("Running Vectorized Bits in Byte Reversal test suite... ");
    size_t round = 0;
    for (; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t original[kNumElements];
        uint64_t expected[kNumElements];
        memcpy(expected, vs2, sizeof(expected));
        memcpy(original, vs2, sizeof(expected));
        bitswap_in_bytes_v(expected, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vbrev8_v(actual, vs2, kNumElements);

        int res = memcmp(actual, expected, sizeof(expected));
        if (processed != kNumElements || res) {
            LOG("failure,\n'actual' does NOT match 'expected', round=%zu",
                round);
            LOG("    original           | expected           | actual");
            for (size_t i = 0; i < kNumElements; i++) {
                LOG("%2zu: 0x%016lx | 0x%016lx | 0x%016lx",
                    i, original[i], expected[i], actual[i]);
            }
            return 1;
        }
    }
    LOG("success, %zu test rounds were run.", round);
    return 0;
}

// @brief Tests vectorized count of leading zeros in elements intrinsic
// in assembly using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vclz()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs2[kNumElements];

    LOG("Running Vectorized Leading Zeros test suite for SEW 64... ");
    size_t round = 0;
    for (; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
            // A random bit stream is unlikely to cover the whole
            // range. Force a random number of leading bits to 0.
            const uint8_t num_leading = rand() / (RAND_MAX / 65 + 1);
            if (num_leading >= 64) {
                vs2[i] = 0;
            } else {
                vs2[i] &= ((uint64_t)1 << (63 - num_leading)) - 1;
            }
        }
        uint64_t original[kNumElements];
        memcpy(original, vs2, sizeof(vs2));
        uint64_t expected[kNumElements];
        clz64_v(expected, vs2, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vclz_v(actual, vs2, kNumElements);

        int res = memcmp(actual, expected, sizeof(expected));
        if (processed != kNumElements || res) {
            LOG("failure,\n'actual' does NOT match 'expected', round=%zu",
                round);
            LOG("    original           | expected           | actual");
            for (size_t i = 0; i < kNumElements; i++) {
                LOG("%2zu: 0x%016lx | 0x%016lx | 0x%016lx",
                    i, original[i], expected[i], actual[i]);
            }
            return 1;
        }
    }
    LOG("success, %zu test rounds were run.", round);
    return 0;
}

// @brief Tests vectorized count of trailing zeros in elements intrinsic
// in assembly using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vctz()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs2[kNumElements];

    LOG("Running Vectorized Trailing Zeros test suite for SEW 64... ");
    size_t round = 0;
    for (; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
            // A random bit stream is unlikely to cover the whole
            // range. Force a random number of leading bits to 0.
            const uint8_t num_trailing = rand() / (RAND_MAX / 65 + 1);
            if (num_trailing >= 64) {
                vs2[i] = 0;
            } else {
                vs2[i] &= ~(((uint64_t)1 << num_trailing) - 1);
            }
        }
        uint64_t original[kNumElements];
        memcpy(original, vs2, sizeof(vs2));
        uint64_t expected[kNumElements];
        ctz64_v(expected, vs2, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vctz_v(actual, vs2, kNumElements);

        int res = memcmp(actual, expected, sizeof(expected));
        if (processed != kNumElements || res) {
            LOG("failure,\n'actual' does NOT match 'expected', round=%zu",
                round);
            LOG("    original           | expected           | actual");
            for (size_t i = 0; i < kNumElements; i++) {
                LOG("%2zu: 0x%016lx | 0x%016lx | 0x%016lx",
                    i, original[i], expected[i], actual[i]);
            }
            return 1;
        }
    }
    LOG("success, %zu test rounds were run.", round);
    return 0;
}

// @brief Tests vectorized population count of elements intrinsic
// in assembly using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vcpop()
{
#define kNumElements 33
#define kRounds 1000

    uint64_t vs2[kNumElements];

    LOG("Running Vectorized Population Count test suite for SEW 64... ");
    size_t round = 0;
    for (; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand64();
        }
        uint64_t original[kNumElements];
        memcpy(original, vs2, sizeof(vs2));
        uint64_t expected[kNumElements];
        cpop64_v(expected, vs2, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vcpop_v(actual, vs2, kNumElements);

        int res = memcmp(actual, expected, sizeof(expected));
        if (processed != kNumElements || res) {
            LOG("failure,\n'actual' does NOT match 'expected', round=%zu",
                round);
            LOG("    original           | expected           | actual");
            for (size_t i = 0; i < kNumElements; i++) {
                LOG("%2zu: 0x%016lx | 0x%016lx | 0x%016lx",
                    i, original[i], expected[i], actual[i]);
            }
            return 1;
        }
    }
    LOG("success, %zu test rounds were run.", round);
    return 0;
}

// @brief Tests vectorized widening shift left intrinsic in assembly
// using randomly generated test vectors
//
// @return int 0 if intrinsics worked, 1 if they failed
//
int
test_rand_vwsll32()
{
#define kNumElements 33
#define kRounds 1000

    uint32_t vs1[kNumElements];
    uint32_t vs2[kNumElements];

    LOG("--- Testing Vectorized Rotate Left (vector vector)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs1[i] = rand32();
            vs2[i] = rand32();
        }
        uint64_t expected[kNumElements];
        vwsll32_vv(expected, vs2, vs1, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vwsll32_vv(actual, vs2, vs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            for (size_t i = 0; i < kNumElements; ++i) {
                LOG("expected[%3zd]: 0x%016lx, actual[%3zd]: 0x%016lx  %s",
                    i, expected[i], i, actual[i],
                    (expected[i] == actual[i] ? "==" : "!="));
            }
            return 1;
        }
    }

    LOG("--- Testing Vectorized Rotate Left (vector scalar)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand32();
        }
        uint32_t rs1 = rand32();
        uint64_t expected[kNumElements];
        vwsll32_vx(expected, vs2, rs1, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vwsll32_vx(actual, vs2, rs1, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            return 1;
        }
    }

    LOG("--- Testing Vectorized Rotate Left (vector immediate)");
    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            vs2[i] = rand32();
        }
        uint64_t expected[kNumElements];
        vwsll32_vx(expected, vs2, 15, kNumElements);

        uint64_t actual[kNumElements] = { 0 };
        const uint64_t processed = zvbb_vwsll32_vi15(actual, vs2, kNumElements);

        if (processed != kNumElements ||
            memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
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

    res = test_rand_vandn8();
    if (res != 0) {
        return res;
    }

    res = test_rand_vrol();
    if (res != 0) {
        return res;
    }

    res = test_rand_vror();
    if (res != 0) {
        return res;
    }

    res = test_rand_vbrev(VSEW8);
    if (res != 0) {
        return res;
    }

    res = test_rand_vbrev(VSEW16);
    if (res != 0) {
        return res;
    }

    res = test_rand_vbrev(VSEW32);
    if (res != 0) {
        return res;
    }

    res = test_rand_vbrev(VSEW64);
    if (res != 0) {
        return res;
    }

    res = test_rand_vrev8(VSEW8);
    if (res != 0) {
        return res;
    }

    res = test_rand_vrev8(VSEW16);
    if (res != 0) {
        return res;
    }

    res = test_rand_vrev8(VSEW32);
    if (res != 0) {
        return res;
    }

    res = test_rand_vrev8(VSEW64);
    if (res != 0) {
        return res;
    }

    res = test_rand_vbrev8();
    if (res != 0) {
        return res;
    }

    res = test_rand_vclz();
    if (res != 0) {
        return res;
    }

    res = test_rand_vctz();
    if (res != 0) {
        return res;
    }

    res = test_rand_vcpop();
    if (res != 0) {
        return res;
    }

    res = test_rand_vwsll32();
    if (res != 0) {
        return res;
    }

    return 0;
}
