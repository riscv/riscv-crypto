
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

#endif


