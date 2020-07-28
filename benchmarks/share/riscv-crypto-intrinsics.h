
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
static inline uint32_t _ssha256_sig0 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.sig0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha256_sig1 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.sig1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha256_sum0 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.sum0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _ssha256_sum1 (uint32_t rs1) {uint32_t rd; __asm__ ("ssha256.sum1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// SHA512
//

#if defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32)
static inline uint32_t _ssha512_sig0l(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("ssha512.sig0l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _ssha512_sig0h(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("ssha512.sig0h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _ssha512_sig1l(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("ssha512.sig1l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _ssha512_sig1h(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("ssha512.sig1h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _ssha512_sum0r(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("ssha512.sum0r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _ssha512_sum1r(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__ ("ssha512.sum1r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#elif defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64)
static inline uint64_t _ssha512_sig0 (uint64_t rs1) {uint64_t rd; __asm__ ("ssha512.sig0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint64_t _ssha512_sig1 (uint64_t rs1) {uint64_t rd; __asm__ ("ssha512.sig1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint64_t _ssha512_sum0 (uint64_t rs1) {uint64_t rd; __asm__ ("ssha512.sum0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint64_t _ssha512_sum1 (uint64_t rs1) {uint64_t rd; __asm__ ("ssha512.sum1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//
// AES
//

#if (defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV32))
static inline uint32_t _saes32_encs (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes32.encs  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes32_encsm(uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes32.encsm %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes32_decs (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes32.decs  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes32_decsm(uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes32.decsm %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
#endif

#if (defined(__ZSCRYPTO) && defined(RISCV_CRYPTO_RV64))
static inline uint64_t _saes64_ks1     (uint64_t rs1, int      rcon) {uint64_t rd; __asm__("saes64.ks1      %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rcon)); return rd;}
static inline uint64_t _saes64_ks2     (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.ks2      %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_imix    (uint64_t rs1               ) {uint64_t rd; __asm__("saes64.imix     %0, %1    " : "=r"(rd) : "r"(rs1)           ); return rd;}
static inline uint64_t _saes64_encsm_lo(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.encsm.lo %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_encsm_hi(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.encsm.hi %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_encs_lo (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.encs.lo  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_encs_hi (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.encs.hi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_decsm_lo(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.decsm.lo %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_decsm_hi(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.decsm.hi %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_decs_lo (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.decs.lo  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes64_decs_hi (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes64.decs.hi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
#endif

//
// SM4
//

#if (defined(__ZSCRYPTO))
static inline uint32_t _ssm4_ks (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("ssm4.ks %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _ssm4_ed (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("ssm4.ed %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
#endif

//
// SM3
//

#if (defined(__ZSCRYPTO))
static inline uint32_t _ssm3_p0 (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("ssm3.p0 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _ssm3_p1 (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("ssm3.p1 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
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

