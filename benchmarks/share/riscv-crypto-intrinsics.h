
#include <stdint.h>
#include <stddef.h>

#include "riscvcrypto/share/util.h"

#ifndef __RISCV_CRYPTO_INTRINSICS__
#define __RISCV_CRYPTO_INTRINSICS__

#ifdef __ZSCRYPTO
#define EMULATE_ZSCRYPTO
#endif

#if __riscv_xlen == 32
#  define RISCV_CRYPTO_RV32
#endif

#if __riscv_xlen == 64
#  define RISCV_CRYPTO_RV64
#endif

//
// SHA2
//

#if defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32) || defined(RISCV_CRYPTO_RV64)
static inline uint32_t _ssha256_s0 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.s0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha256_s1 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.s1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha256_s2 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.s2  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha256_s3 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.s3  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#else 
static inline uint32_t _ssha256_s0 (uint32_t rs1) {return (ROTR32(rs1, 2) ^ ROTR32(rs1,13) ^ ROTR32(rs1,22));}
static inline uint32_t _ssha256_s1 (uint32_t rs1) {return (ROTR32(rs1, 6) ^ ROTR32(rs1,11) ^ ROTR32(rs1,25));}
static inline uint32_t _ssha256_s2 (uint32_t rs1) {return (ROTR32(rs1, 7) ^ ROTR32(rs1,18) ^    SHR(rs1, 3));}
static inline uint32_t _ssha256_s3 (uint32_t rs1) {return (ROTR32(rs1,17) ^ ROTR32(rs1,19) ^    SHR(rs1,10));}
#endif

#if defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64)
static inline uint32_t _ssha512_s0 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha512.s0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha512_s1 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha512.s1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha512_s2 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha512.s2  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha512_s3 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha512.s3  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

#endif

