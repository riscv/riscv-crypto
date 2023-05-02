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
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zvknh.h"
#include "log.h"
#include "vlen-bits.h"

// 'sha-test.h' must be included before the test vector headers.
#include "sha-test.h"
// The vector headers are auto-generated.
#include "test-vectors/sha256-vectors.h"
#include "test-vectors/sha512-vectors.h"

typedef void (*block_fn_t)(uint8_t* hash, const void* block);

struct sha_routine {
    const char* name;
    // Minimum VLEN (bits) required to run this hash routine.
    size_t min_vlen;
    // Function pointer to the block hashing routine.
    block_fn_t hash_fn;
};

// SHA-256 block hashing routines.
#define NUM_SHA256_ROUTINES (2)
const struct sha_routine sha256_routines[NUM_SHA256_ROUTINES] = {
    {
        .name = "sha256_block_lmul1",
        .min_vlen = 128,
        .hash_fn = sha256_block_lmul1,
    },
    {
        .name = "sha256_block_vslide_lmul1",
        .min_vlen = 128,
        .hash_fn = sha256_block_vslide_lmul1,
    },
};

// SHA-512 block hashing routines.
#define NUM_SHA512_ROUTINES (2)
const struct sha_routine sha512_routines[NUM_SHA512_ROUTINES] = {
    {
        .name = "sha512_block_lmul1",
        .min_vlen = 256,
        .hash_fn = sha512_block_lmul1,
    },
    {
        .name = "sha512_block_lmul2",
        .min_vlen = 128,
        .hash_fn = sha512_block_lmul2,
    },
};


struct sha_params {
    size_t digest_size;
    size_t block_size;
    size_t size_field_len;
    size_t initial_hash_size;
    const void* initial_hash;
    size_t num_routines;
    const struct sha_routine* routines;
};

const struct sha_params sha256_params = {
    .digest_size = SHA256_DIGEST_SIZE,
    .block_size = SHA256_BLOCK_SIZE,
    .size_field_len = sizeof(uint64_t),
    .initial_hash = kSha256InitialHash,
    .initial_hash_size = sizeof(kSha256InitialHash),
    .num_routines = NUM_SHA256_ROUTINES,
    .routines = sha256_routines,
};


const struct sha_params sha512_params = {
    .digest_size = SHA512_DIGEST_SIZE,
    .block_size = SHA512_BLOCK_SIZE,
    .size_field_len = 16,    // sizeof(uint128_t)
    .initial_hash = kSha512InitialHash,
    .initial_hash_size = sizeof(kSha512InitialHash),
    .num_routines = NUM_SHA512_ROUTINES,
    .routines = sha512_routines,
};

static void
final_bswap_32(uint32_t* hash)
{
    const uint32_t f = __builtin_bswap32(hash[0]);
    const uint32_t e = __builtin_bswap32(hash[1]);
    const uint32_t b = __builtin_bswap32(hash[2]);
    const uint32_t a = __builtin_bswap32(hash[3]);

    const uint32_t h = __builtin_bswap32(hash[4]);
    const uint32_t g = __builtin_bswap32(hash[5]);
    const uint32_t d = __builtin_bswap32(hash[6]);
    const uint32_t c = __builtin_bswap32(hash[7]);

    hash[0] = a;
    hash[1] = b;
    hash[2] = c;
    hash[3] = d;

    hash[4] = e;
    hash[5] = f;
    hash[6] = g;
    hash[7] = h;
}

static void
final_bswap_64(uint64_t* hash)
{
    const uint64_t f = __builtin_bswap64(hash[0]);
    const uint64_t e = __builtin_bswap64(hash[1]);
    const uint64_t b = __builtin_bswap64(hash[2]);
    const uint64_t a = __builtin_bswap64(hash[3]);

    const uint64_t h = __builtin_bswap64(hash[4]);
    const uint64_t g = __builtin_bswap64(hash[5]);
    const uint64_t d = __builtin_bswap64(hash[6]);
    const uint64_t c = __builtin_bswap64(hash[7]);

    hash[0] = a;
    hash[1] = b;
    hash[2] = c;
    hash[3] = d;

    hash[4] = e;
    hash[5] = f;
    hash[6] = g;
    hash[7] = h;
}


// Runs a particular sha_test with the given
static int
run_test_against_routine(
    const struct sha_test* test,
    const struct sha_params* params,
    block_fn_t hash_block_fn
) {
    uint8_t hash[SHA512_DIGEST_SIZE];
    uint8_t buf[2 * SHA512_BLOCK_SIZE];

    int len = test->msglen;
    const uint8_t* block = test->msg;

    memcpy(hash, params->initial_hash, params->initial_hash_size);

    while (len >= params->block_size) {
        hash_block_fn(hash, block);
        block += params->block_size;
        len -= params->block_size;
    }

    // Handle partial last block.
    memcpy(buf, block, len);
    // Add delimiter.
    buf[len++] = 0x80;
    // Calculate padding size.
    int padding = params->block_size - len;
    // Can we fit message length into padding?
    if (padding < params->size_field_len) {
        padding += params->block_size;
    }

    padding -= params->size_field_len;
    bzero(&buf[len], padding);
    len += padding;

    uint64_t* ptr = (uint64_t *)&buf[len];
    switch (params->size_field_len) {
      case 8:
        *ptr = __builtin_bswap64(8 * test->msglen);
        break;
      case 16:
        // Message length of a test is stored in an int, so it will
        // always fit into 64 bits.
        *ptr = 0;
        ptr++;
        *ptr = __builtin_bswap64(8 * test->msglen);
        break;
      default:
        assert(false);
    };

    hash_block_fn(hash, buf);
    if (len > params->block_size) {
        hash_block_fn(hash, buf + params->block_size);
    }

    // Following the last block, convert from the "native" representation
    // of 'H' to the NIST order/endianness.
    switch (params->size_field_len) {
      case 8:
        final_bswap_32((uint32_t*)hash);
        break;
      case 16:
        final_bswap_64((uint64_t*)hash);
        break;
      default:
        assert(false);
    };

    return memcmp(test->md, hash, params->digest_size);
}


static int
run_test(const struct sha_test* test, const struct sha_params* params)
{
    const uint64_t vlen = vlen_bits();
    for (size_t i = 0; i < params->num_routines; ++i) {
        const struct sha_routine* const routine = &params->routines[i];
        if (vlen < routine->min_vlen) {
            LOG("Skipping '%s' due to VLEN < min_vlen (%zu < %zu)",
                routine->name, vlen, routine->min_vlen);
            continue;
        }
        LOG("Running against routine '%s'", routine->name);
        int rc = run_test_against_routine(test, params, routine->hash_fn);
        if (rc != 0) {
            LOG("*** Test failed against routine '%s'", routine->name);
            return rc;
        }
    }
    return 0;
}

static void
run_suite(
    const struct sha_test_suite* suite,
    const struct sha_params* params
) {
    LOG("--- Running %s test suite... ", suite->name);
    for (size_t i = 0; i < suite->count; i++) {
        LOG("--- Running %s test %zu", suite->name, i);
        const struct sha_test* const test = &suite->tests[i];
        int rc = run_test(test, params);
        if (rc != 0) {
            LOG("*** test %zu failed in suite '%s'", i, suite->name);
            exit(1);
        }
    }

    LOG("Success, %d tests were run.", suite->count);
}

int
main()
{
    const uint64_t vlen = vlen_bits();
    LOG("VLEN = %" PRIu64, vlen);

    if (true) {
        const size_t num_tests256 = sizeof(sha256_suites) / sizeof(*sha256_suites);
        for (size_t i = 0; i < num_tests256; i++) {
            LOG("*** Running suite %zu for SHA-256", i);
            run_suite(&sha256_suites[i], &sha256_params);
        }
    }

    if (true) {
        const size_t num_tests512 = sizeof(sha512_suites) / sizeof(*sha512_suites);
        for (size_t i = 0; i < num_tests512; i++) {
            LOG("*** Running suite %zu for SHA-512", i);
            run_suite(&sha512_suites[i], &sha512_params);
        }
    }

    return 0;
}
