
/*
 * Some demonstrations of using the Bitmanip permutation instructions
 * to perform useful cryptographic operations.
 * Examples re-produced from Claire's SVN repository:
 * - http://svn.clairexen.net/handicraft/2020/lut4perm/
 */

#include <stdint.h>

#ifndef __PERMUTATION_H__
#define __PERMUTATION_H__

/*!
@brief Implements 4 -> 4 bit SBox, applying the SBox to each nibble in a
    64-bit input word.
@param sbox - The 16 nibbles which make up the SBox.
@param in   - The input nibbles to the SBox.
@returns The applied SBox.
*/
uint64_t sbox_4bit(uint64_t sbox, uint64_t in);


typedef struct {
    uint64_t packed[32];
} sbox_8bit_t;

/*
@brief Pack a 256-element 8-bit sbox appropriately for use with
the xperm instructions.
@param in - 256-element array
@param out - 64-element array
*/
void     pack_8bit_sbox(sbox_8bit_t * out, uint8_t * in);

//! Apply the given sbox to each byte in the supplied 64-bit word.
uint64_t sbox_8bit     (sbox_8bit_t * sbox, uint64_t in);

/*!
@brief Apply the given sbox to each byte in the supplied 64-bit words.
*/
void     sbox_8bit_x4  (
    uint64_t        out[2]  ,
    sbox_8bit_t *   sbox    ,
    uint64_t        in [2]
);

#endif


