
#include <stdio.h>
#include <string.h>

#include "riscvcrypto/sm3/api_sm3.h"

// The block size in bytes
#define SM3_BLOCK_SIZE (16 * sizeof(uint32_t))

// Reverses the byte order of `V`
#define REVERSE_BITS_32(V)                                                     \
  (((V & 0x000000FF) << 24) | (((V)&0x0000FF00) << 8) |                        \
   (((V)&0x00FF0000) >> 8) | (((V)&0xFF000000) >> 24))

// Rotates `V` by `N` bits to the left
#define SM3_ROTATE_32(V, N) (((V) << (N)) | ((V) >> (32 - (N))))

// The two permutation functions
#define SM3_P0(X) ((X) ^ SM3_ROTATE_32((X), 9) ^ SM3_ROTATE_32((X), 17))
#define SM3_P1(X) ((X) ^ SM3_ROTATE_32((X), 15) ^ SM3_ROTATE_32((X), 23))

// Expands the state `s` to `w`
static void sm3_expand(uint32_t w[68], uint32_t s[24]) {
  for (int i = 0; i < 16; ++i) {
    w[i] = REVERSE_BITS_32(s[i + 8]);
  }

  for (int i = 16; i < 68; ++i) {
    w[i] = SM3_P1(w[i - 16] ^ w[i - 9] ^ SM3_ROTATE_32(w[i - 3], 15)) ^
           SM3_ROTATE_32(w[i - 13], 7) ^ w[i - 6];
  }
}

// Compresses `s` in place
static void sm3_compress(uint32_t s[24]) {
  uint32_t w[68];
  sm3_expand(w, s);

  // The IV and iteration state
  uint32_t x[8];
  memcpy(x, s, 8 * sizeof(uint32_t));

  // The state update transformation below uses and modifies `x`
  // depending on the expansion `w` and the current iteration `i`
  for (int i = 0; i < 64; ++i) {
    // The round constant `t` provides additional randomness
    uint32_t t = (i < 16) ? 0x79CC4519 : 0x7A879D8A;
    uint32_t rot = SM3_ROTATE_32(x[0], 12);
    uint32_t ss1 = SM3_ROTATE_32(rot + x[4] + SM3_ROTATE_32(t, i % 32), 7);
    uint32_t ss2 = ss1 ^ rot;
    uint32_t w_i = w[i] ^ w[i + 4];

    uint32_t tt1, tt2;
    if (i < 16) {
      tt1 = (x[0] ^ x[1] ^ x[2]) + x[3] + ss2 + w_i;
      tt2 = (x[4] ^ x[5] ^ x[6]) + x[7] + ss1 + w[i];
    } else {
      tt1 = ((x[0] & x[1]) | (x[0] & x[2]) | (x[1] & x[2])) + x[3] + ss2 + w_i;
      tt2 = ((x[4] & x[5]) | (~x[4] & x[6])) + x[7] + ss1 + w[i];
    }

    x[3] = x[2];
    x[2] = SM3_ROTATE_32(x[1], 9);
    x[1] = x[0];
    x[0] = tt1;
    x[7] = x[6];
    x[6] = SM3_ROTATE_32(x[5], 19);
    x[5] = x[4];
    x[4] = SM3_P0(tt2);
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
    memcpy(&s[8], m, SM3_BLOCK_SIZE);
    sm3_compress(s);
    remaining -= SM3_BLOCK_SIZE;
    m += SM3_BLOCK_SIZE;
  }

  // Hash the last block with padding
  memcpy(b, m, remaining);
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
  s[22] = REVERSE_BITS_32((uint32_t)(bitlen >> 32));
  s[23] = REVERSE_BITS_32((uint32_t)bitlen);
  sm3_compress(s);

  // stores `s` in `hash` in big-endian
  for (size_t i = 0; i < 8; ++i) {
    hash[i * 4 + 0] = (uint8_t)(s[i] >> 24);
    hash[i * 4 + 1] = (uint8_t)(s[i] >> 16);
    hash[i * 4 + 2] = (uint8_t)(s[i] >> 8);
    hash[i * 4 + 3] = (uint8_t)(s[i] >> 0);
  }
}
