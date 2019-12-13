#include <stdint.h>

#define index(x,y) ((x%5) + 5*(y%5))

#define ROL64(a, offset) ((offset != 0) ? \
        ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset))) : a)

extern const unsigned int KeccakP1600RhoOffsets[25];
extern const uint64_t KeccakP1600RoundConstants[24];

void KeccakP1600Round(uint64_t *A, unsigned int indexRound)
{
  unsigned int x, y;
  uint64_t C[5];
  uint64_t tempA[25];
  uint64_t D;
  // Theta / Rho / Pi
  for(x=0; x<5; x++) {
    C[x] = A[index(x, 0)] ^ A[index(x, 1)] ^ A[index(x, 2)] ^
           A[index(x, 3)] ^ A[index(x, 4)] ;
  }
  for(x=0; x<5; x++) {
    D = ROL64(C[(x+1)%5], 1) ^ C[(x+4)%5];
    for(y=0; y<5; y++) {
      tempA[index(0*x+1*y, 2*x+3*y)] =
        ROL64 (A[index(x, y)] ^ D, KeccakP1600RhoOffsets[index(x, y)]);
    }
  }
  // Chi
  for(y=0; y<5; y++) {
    for(x=0; x<5; x++) {
      A[index(x, y)] = tempA[index(x, y)] ^
                          ((~tempA[index(x+1, y)]) &
                             tempA[index(x+2, y)]);
    }
  }
  // Iota
  A[index(0, 0)] ^= KeccakP1600RoundConstants[indexRound];
}
