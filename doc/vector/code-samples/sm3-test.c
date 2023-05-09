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
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "vlen-bits.h"

#include "zvksh.h"

// 'sm3-test.h' needs to be included before sme-test-vectors.h.
#include "sm3-test.h"
#include "test-vectors/sm3-test-vectors.h"

// SM3 produces a 256 bits / 32 bytes hash.
#define SM3_HASH_BYTES (32)

typedef void (*hash_fn_t)(
    void* dest,
    const void* src,
    uint64_t length
);

struct sm3_routine {
    const char* name;
    // Minimum VLEN (bits) required to run this hash routine.
    size_t min_vlen;
    // Function pointer to the block hashing routine.
    hash_fn_t hash_fn;
};

// SM3 block hashing routines.
#define NUM_SM3_ROUTINES (3)
const struct sm3_routine sm3_routines[NUM_SM3_ROUTINES] = {
    {
        .name = "zvksh_sm3_encode_lmul1",
        .min_vlen = 256,
        .hash_fn = zvksh_sm3_encode_lmul1,
    },
    {
        .name = "zvksh_sm3_encode_lmul2",
        .min_vlen = 128,
        .hash_fn = zvksh_sm3_encode_lmul2,
    },
    {
        .name = "zvksh_sm3_encode_lmul4",
        .min_vlen = 64,
        .hash_fn = zvksh_sm3_encode_lmul4,
    },
};

// Pad input to block size, append delimiter and length.
static size_t
sm3_pad(uint8_t* output, const uint8_t* input, size_t len)
{
    const size_t blen = 8 * len;
    memcpy(output, input, len);
    output[len++] |= 0x80;

    // Calculate the padding size.
    // Message size is appended at the end of the last block,
    // take that into account.
    size_t padding = 64 - (len % 64);
    if (padding < sizeof(uint64_t)) {
        padding += 64;
    }

    bzero(output + len, padding);
    len += padding;

    uint32_t* ptr = (uint32_t*)(output + len - sizeof(uint64_t));

    *ptr = __bswap_32(blen >> 32);
    *(++ptr) = __bswap_32(blen & UINT32_MAX);

    return len;
}

static int run_sm3_test_against(
    const struct sm3_test_vector* vector,
    const struct sm3_routine* const routine
) {
    LOG("- Testing routine '%s'", routine->name);

    __attribute__((aligned(16)))
    uint32_t buf[128] = {0};

    assert((vector->message_len + 128) < sizeof(buf));

    const size_t len = sm3_pad((uint8_t*)buf, (uint8_t*)vector->message, vector->message_len);
    routine->hash_fn(buf, buf, len);

    return memcmp(buf, vector->expected, SM3_HASH_BYTES) == 0 ? 0 : 1;
}


static int run_sm3_test(const struct sm3_test_vector* vector)
{
    const uint64_t vlen = vlen_bits();
    static bool previously_skipped[NUM_SM3_ROUTINES] = { false };
    bool one_passed = false;

    for (size_t i = 0; i < NUM_SM3_ROUTINES; ++i) {
        const struct sm3_routine* const routine = &sm3_routines[i];
        if (vlen < routine->min_vlen) {
            if (!previously_skipped[i]) {
                LOG("Skipping '%s' due to VLEN < min_vlen (%zu < %zu)",
                    routine->name, vlen, routine->min_vlen);
                previously_skipped[i] = true;
            }
            continue;
        }
        const int rc = run_sm3_test_against(vector, routine);
        if (rc != 0) {
            LOG("**** Test failed when running against '%s'", routine->name);
            return rc;
        }
        one_passed = true;
    }
    if (!one_passed) {
        LOG("*** No tests were run, every routine was skipped.");
        return 1;
    }
    return 0;
}

int main()
{
    const uint64_t vlen = vlen_bits();
    LOG("VLEN = %" PRIu64, vlen);

    LOG("--- Running SM3 test suite...");
    const size_t vector_count = sizeof(sm3_test_vectors) / sizeof(sm3_test_vectors[0]);
    for (size_t i = 0; i < vector_count; ++i) {
        LOG("- Testing test #%zu", i);
        int rc = run_sm3_test(&sm3_test_vectors[i]);
        if (rc != 0) {
            LOG("** Test vector #%zu failed", i);
            exit(1);
        }
    }

    LOG("--- Success, %zu tests were run.", vector_count);
    return 0;
}
