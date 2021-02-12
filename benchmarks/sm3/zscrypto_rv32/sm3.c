
#include <stdio.h>
#include <string.h>

#include "riscvcrypto/share/riscv-crypto-intrinsics.h"
#include "riscvcrypto/sm3/api_sm3.h"
#include "rvintrin.h"

// The block size in bytes
#define SM3_BLOCK_SIZE (16 * sizeof(uint32_t))

// Reverses the byte order of `V`
#define REVERSE_BYTES_32(V) (_rv32_grev((V), 0x18))

// Rotates `V` by `N` bits to the left
#define SM3_ROTATE_32(V, N) (_rv32_rol((V), (N)))

// The two permutation functions
#define SM3_P0(X) _sm3p0((X))
#define SM3_P1(X) _sm3p1((X))

// Expands state values and returns the result
#define SM3_EXPAND_STEP(W0, W3, W7, W10, W13)                                  \
  (SM3_P1((W0) ^ (W7) ^ SM3_ROTATE_32((W13), 15)) ^ SM3_ROTATE_32((W3), 7) ^   \
   (W10))

// Performs a compression step with permutation constant T, iteration I
// and expanded words W1 and W2
#define SM3_COMPRESS_STEP(I, W1, W2)                                           \
  {                                                                            \
    uint32_t t = (I) < 16 ? 0x79CC4519 : 0x7A879D8A;                           \
    uint32_t rot = SM3_ROTATE_32(x[0], 12);                                    \
    uint32_t ss1 = SM3_ROTATE_32(rot + x[4] + SM3_ROTATE_32(t, (I)), 7);       \
                                                                               \
    uint32_t tt1, tt2;                                                         \
    /* optimized out by the compiler */                                        \
    if ((I) < 16) {                                                            \
      tt1 = (x[0] ^ x[1] ^ x[2]) + x[3] + (ss1 ^ rot) + ((W1) ^ (W2));         \
      tt2 = (x[4] ^ x[5] ^ x[6]) + x[7] + ss1 + (W1);                          \
    } else {                                                                   \
      tt1 = ((x[0] & x[1]) | (x[0] & x[2]) | (x[1] & x[2])) + x[3] +           \
            (ss1 ^ rot) + ((W1) ^ (W2));                                       \
      tt2 = ((x[4] & x[5]) | (~x[4] & x[6])) + x[7] + ss1 + (W1);              \
    }                                                                          \
                                                                               \
    x[3] = x[2];                                                               \
    x[2] = SM3_ROTATE_32(x[1], 9);                                             \
    x[1] = x[0];                                                               \
    x[0] = tt1;                                                                \
    x[7] = x[6];                                                               \
    x[6] = SM3_ROTATE_32(x[5], 19);                                            \
    x[5] = x[4];                                                               \
    x[4] = SM3_P0(tt2);                                                        \
  }

// Compresses `s` in place
static void sm3_compress(uint32_t s[24]) {
  // The IV and iteration state
  uint32_t x[8];
  for (int i = 0; i < 8; ++i) {
    x[i] = s[i];
  }

  // `w` contains 16 of the expanded words.
  uint32_t w[16];
  for (int i = 0; i < 16; ++i) {
    w[i] = REVERSE_BYTES_32(s[i + 8]);
  }

  // Compress first 12 words.
  for (int i = 0; i < 12; ++i) {
    SM3_COMPRESS_STEP(i, w[i], w[i + 4]);
  }
  // Compress and expand the remaining 4 words.
  for (int i = 0; i < 4; ++i) {
    w[i] =
        SM3_EXPAND_STEP(w[i], w[3 + i], w[7 + i], w[10 + i], w[(13 + i) % 16]);
    SM3_COMPRESS_STEP(i + 12, w[i + 12], w[i]);
  }

  // Rounds 16 to 64
  for (int j = 16; j < 64; j += 16) {
    // Expand and then compress the first 12 words as the remaining 4 need to be
    // handled differently in this implementation.
    for (int i = 0; i < 12; ++i) {
      w[4 + i] = SM3_EXPAND_STEP(w[4 + i], w[(7 + i) % 16], w[(11 + i) % 16],
                                 w[(14 + i) % 16], w[(1 + i) % 16]);
    }
    for (int i = 0; i < 12; ++i) {
      SM3_COMPRESS_STEP(i + j, w[i], w[i + 4]);
    }

    // Now expand and compress the remaining 4 words.
    for (int i = 0; i < 4; ++i) {
      w[i] = SM3_EXPAND_STEP(w[i], w[3 + i], w[7 + i], w[10 + i],
                             w[(13 + i) % 16]);
      SM3_COMPRESS_STEP(i + j + 12, w[i + 12], w[i]);
    }
  }

  // Xor `s` with `x`
  for (int i = 0; i < 8; ++i) {
    s[i] ^= x[i];
  }
}

// Hashes `message` with `len` bytes with SM3 and stores it to `hash`
void sm3_hash(uint8_t hash[32], const uint8_t *message, size_t len) {
  uint32_t s[24] = {
      0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
  };
  uint8_t *b = (uint8_t *)&s[8];
  const uint8_t *m = message;
  size_t remaining = len;

  // Hash complete blocks first
  while (remaining >= SM3_BLOCK_SIZE) {
    for (int i = 0; i < SM3_BLOCK_SIZE; ++i) {
      b[i] = m[i];
    }
    sm3_compress(s);
    remaining -= SM3_BLOCK_SIZE;
    m += SM3_BLOCK_SIZE;
  }

  // Hash the last block with padding
  for (int i = 0; i < remaining; ++i) {
    b[i] = m[i];
  }
  // Append bit 1 after the message
  b[remaining] = 0b10000000;
  ++remaining;
  if (remaining > SM3_BLOCK_SIZE - sizeof(uint64_t)) {
    sm3_compress(s);
    remaining = 0;
  }

  // Pad everything between the message and the length with zeros
  memset(&b[remaining], 0x00, SM3_BLOCK_SIZE - 8 - remaining);
  // Append the length of the message in bits
  uint64_t bitlen = 8 * (uint64_t)len;
  s[22] = REVERSE_BYTES_32((uint32_t)(bitlen >> 32));
  s[23] = REVERSE_BYTES_32((uint32_t)bitlen);
  sm3_compress(s);

  // stores `s` in `hash` in big-endian
  for (size_t i = 0; i < 8; ++i) {
    hash[i * 4 + 0] = (uint8_t)(s[i] >> 24);
    hash[i * 4 + 1] = (uint8_t)(s[i] >> 16);
    hash[i * 4 + 2] = (uint8_t)(s[i] >> 8);
    hash[i * 4 + 3] = (uint8_t)(s[i] >> 0);
  }
}
