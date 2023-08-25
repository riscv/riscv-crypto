// Copyright 2023 Rivos Inc.
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
#include "zvkg.h"

// @brief Return a 32-bit randomly generated number using rand()
//
// @return uint32_t
//
uint32_t
rand32()
{
    return rand();
}

// @brief Tests vectorized multiply in Galois Field instruction vgmul
// using randomly generated test vectors.
//
// 'vghsh.vv' is used to generate the "golden" outputs that we check vgmul
// against. The correctness of vghsh is established in the test 'aes-gcm-test'.
//
int
test_rand_vgmul()
{
#define kNumGroups 113
#define kNumElements (4 * (kNumGroups))
#define kRounds 100

    uint32_t y[kNumElements];
    uint32_t z[kNumElements];
    uint32_t expected[kNumElements];
    uint32_t actual[kNumElements];

    LOG("--- Testing vgmul against vghsh");

    for (size_t round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < kNumElements; ++i) {
            actual[i] = expected[i] = rand32();
            y[i] = rand32();
            z[i] = 0;
        }

        // The reference (expected) output is produced by vghsh
        zvkg_vghsh_vv(expected, z, y, kNumGroups);

        // The tested (actual) output is produced by vgmul
        zvkg_vgmul_vv(actual, y, kNumGroups);

        if (memcmp(actual, expected, sizeof(actual))) {
            LOG("FAILURE: 'actual' does NOT match 'expected'");
            for (size_t i = 0; i < kNumElements; ++i) {
                const uint32_t exp = expected[i];
                const uint32_t act = actual[i];
                LOG("expected[%3zd]: 0x%08" PRIx32
                    ", actual[%3zd]: 0x%08" PRIx32
                    "  %s", i, exp, i, act, (exp == act ? "==" : "!="));
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

    // The correctness of 'vghsh.vv' is established in the test 'aes-gcm-test',
    // so this test is only there to validate 'vgmul.vv'.
    res = test_rand_vgmul();
    if (res != 0) {
        return res;
    }

    return 0;
}
