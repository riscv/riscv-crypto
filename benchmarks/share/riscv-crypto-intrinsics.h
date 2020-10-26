
#include <stdint.h>
#include <stddef.h>

#ifndef __RISCV_CRYPTO_INTRINSICS__
#define __RISCV_CRYPTO_INTRINSICS__

#ifdef __ZSCRYPTO
#define EMULATE_ZSCRYPTO
#endif

#if __riscv_xlen == 32
#define RISCV_CRYPTO_RV32
typedef uint32_t uint_xlen_t;
#endif

#if __riscv_xlen == 64
#define RISCV_CRYPTO_RV64
typedef uint64_t uint_xlen_t;
#endif

//
// SHA256
//

#if (defined(__ZSCRYPTO) && (defined(RISCV_CRYPTO_RV32) || defined(RISCV_CRYPTO_RV64)))
static inline uint_xlen_t _sha256sig0 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha256sig0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sha256sig1 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha256sig1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sha256sum0 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha256sum0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sha256sum1 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha256sum1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// SHA512
//

#if defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32)
static inline uint_xlen_t _sha512sig0l(uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__ ("sha512sig0l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _sha512sig0h(uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__ ("sha512sig0h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _sha512sig1l(uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__ ("sha512sig1l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _sha512sig1h(uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__ ("sha512sig1h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _sha512sum0r(uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__ ("sha512sum0r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _sha512sum1r(uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__ ("sha512sum1r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#elif defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64)
static inline uint_xlen_t _sha512sig0 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha512sig0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sha512sig1 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha512sig1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sha512sum0 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha512sum0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sha512sum1 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__ ("sha512sum1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// AES
//

#if (defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32))
static inline uint_xlen_t _aes32esi (uint_xlen_t rs1, uint_xlen_t rs2, int bs) {uint_xlen_t rd; __asm__("aes32esi  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint_xlen_t _aes32esmi(uint_xlen_t rs1, uint_xlen_t rs2, int bs) {uint_xlen_t rd; __asm__("aes32esmi %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint_xlen_t _aes32dsi (uint_xlen_t rs1, uint_xlen_t rs2, int bs) {uint_xlen_t rd; __asm__("aes32dsi  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint_xlen_t _aes32dsmi(uint_xlen_t rs1, uint_xlen_t rs2, int bs) {uint_xlen_t rd; __asm__("aes32dsmi %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
#endif

#if (defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64))
static inline uint_xlen_t _aes64ks1i  (uint_xlen_t rs1, int      rcon) {uint_xlen_t rd; __asm__("aes64ks1i %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rcon)); return rd;}
static inline uint_xlen_t _aes64ks2   (uint_xlen_t rs1, uint_xlen_t rs2 ) {uint_xlen_t rd; __asm__("aes64ks2  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint_xlen_t _aes64im    (uint_xlen_t rs1               ) {uint_xlen_t rd; __asm__("aes64im   %0, %1    " : "=r"(rd) : "r"(rs1)           ); return rd;}
static inline uint_xlen_t _aes64esm   (uint_xlen_t rs1, uint_xlen_t rs2 ) {uint_xlen_t rd; __asm__("aes64esm  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint_xlen_t _aes64es    (uint_xlen_t rs1, uint_xlen_t rs2 ) {uint_xlen_t rd; __asm__("aes64es   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint_xlen_t _aes64dsm   (uint_xlen_t rs1, uint_xlen_t rs2 ) {uint_xlen_t rd; __asm__("aes64dsm  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint_xlen_t _aes64ds    (uint_xlen_t rs1, uint_xlen_t rs2 ) {uint_xlen_t rd; __asm__("aes64ds   %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
#endif

//
// SM4
//

#if (defined(__ZSCRYPTO))
static inline uint_xlen_t _sm4ks (uint_xlen_t rs1, uint_xlen_t rs2, int bs) {uint_xlen_t rd; __asm__("sm4ks %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint_xlen_t _sm4ed (uint_xlen_t rs1, uint_xlen_t rs2, int bs) {uint_xlen_t rd; __asm__("sm4ed %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
#endif

//
// SM3
//

#if (defined(__ZSCRYPTO))
static inline uint_xlen_t _sm3p0 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__("sm3p0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint_xlen_t _sm3p1 (uint_xlen_t rs1) {uint_xlen_t rd; __asm__("sm3p1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// pollentropy / getnoise
//

#if (defined(__ZSCRYPTO))
static inline volatile uint_xlen_t _pollentropy() {uint_xlen_t rd; __asm__ volatile ("pollentropy %0" : "=r"(rd)); return rd;}
static inline volatile uint_xlen_t _getnoise()    {uint_xlen_t rd; __asm__ volatile ("getnoise    %0" : "=r"(rd)); return rd;}
#endif

//
// Bitmanip Instruction Intrinsics
//

#if (defined(__ZSCRYPTO))
static inline uint_xlen_t _pack  (uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__("pack  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _packu (uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__("packu %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint_xlen_t _packh (uint_xlen_t rs1, uint_xlen_t rs2) {uint_xlen_t rd; __asm__("packh %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#endif

#endif // __RISCV_CRYPTO_INTRINSICS__

