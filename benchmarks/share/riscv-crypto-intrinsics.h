
#include <stdint.h>
#include <stddef.h>

#include "riscvcrypto/share/util.h"

#ifndef __RISCV_CRYPTO_INTRINSICS__
#define __RISCV_CRYPTO_INTRINSICS__

#ifdef __ZSCRYPTO
#define EMULATE_ZSCRYPTO
#endif

#if __riscv_xlen == 32
#define RISCV_CRYPTO_RV32
#endif

#if __riscv_xlen == 64
#define RISCV_CRYPTO_RV64
#endif

//
// SHA256
//

#if (defined(__ZSCRYPTO) && (defined(RISCV_CRYPTO_RV32) || defined(RISCV_CRYPTO_RV64)))
static inline uint32_t _sha256sig0 (uint32_t rs1) {uint32_t rd; __asm__ ("sha256sig0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _sha256sig1 (uint32_t rs1) {uint32_t rd; __asm__ ("sha256sig1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _sha256sum0 (uint32_t rs1) {uint32_t rd; __asm__ ("sha256sum0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _sha256sum1 (uint32_t rs1) {uint32_t rd; __asm__ ("sha256sum1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// SHA512
//

#if defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32)
static inline uint32_t _sha512sig0l(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("sha512sig0l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _sha512sig0h(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("sha512sig0h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _sha512sig1l(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("sha512sig1l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _sha512sig1h(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("sha512sig1h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _sha512sum0r(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("sha512sum0r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _sha512sum1r(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("sha512sum1r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#elif defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64)
static inline uint64_t _sha512sig0 (uint64_t rs1) {uint64_t rd; __asm__ ("sha512sig0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint64_t _sha512sig1 (uint64_t rs1) {uint64_t rd; __asm__ ("sha512sig1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint64_t _sha512sum0 (uint64_t rs1) {uint64_t rd; __asm__ ("sha512sum0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint64_t _sha512sum1 (uint64_t rs1) {uint64_t rd; __asm__ ("sha512sum1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// AES
//

#if (defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32))
static inline uint32_t _aes32esi (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("aes32esi  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _aes32esmi(uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("aes32esmi %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _aes32dsi (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("aes32dsi  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _aes32dsmi(uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("aes32dsmi %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
#endif

#if (defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64))
static inline uint64_t _aes64ks1i  (uint64_t rs1, int      rcon) {uint64_t rd; __asm__("aes64ks1i %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rcon)); return rd;}
static inline uint64_t _aes64ks2   (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("aes64ks2  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _aes64im    (uint64_t rs1               ) {uint64_t rd; __asm__("aes64im   %0, %1    " : "=r"(rd) : "r"(rs1)           ); return rd;}
static inline uint64_t _aes64esm   (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("aes64esm  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _aes64es    (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("aes64es   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _aes64dsm   (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("aes64dsm  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _aes64ds    (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("aes64ds   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
#endif

//
// SM4
//

#if (defined(__ZSCRYPTO))
static inline uint32_t _sm4ks (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("sm4ks %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _sm4ed (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("sm4ed %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
#endif

//
// SM3
//

#if (defined(__ZSCRYPTO))
static inline uint32_t _sm3p0 (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("sm3p0 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _sm3p1 (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("sm3p1 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#endif

//
// pollentropy
//

#if (defined(__ZSCRYPTO))
static inline volatile uint32_t _pollentropy() {uint32_t rd; __asm__ volatile ("pollentropy %0" : "=r"(rd)); return rd;}
#endif

//
// Bitmanip Instruction Intrinsics
//

#if (defined(__ZSCRYPTO))
static inline uint32_t _pack  (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("pack  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _packu (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("packu %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _packh (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("packh %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#endif

#endif // __RISCV_CRYPTO_INTRINSICS__

