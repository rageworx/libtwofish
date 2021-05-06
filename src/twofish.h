#ifndef __LIBTWOFISH_H__
#define __LIBTWOFISH_H__

/**
* libblowfish
* ========================================================
* Based on Bruce Schneier's TwoFish..
* Reference on https://www.schneier.com/academic/twofish/
* 
* (C)2021, Raphael Kim
**/

#include <cstdint>

namespace TwoFish
{
    bool   Initialize( uint8_t* key = NULL, uint8_t* iv = NULL, size_t keylen = 0, size_t ivlen = 0 );
    size_t GetEncodeLength( size_t srclen );
    size_t GetBlockSize( bool isbit = true );
    size_t Encode( uint8_t* pInput, uint8_t* pOutput, size_t inpsz );
    size_t Decode( uint8_t* pInput, uint8_t* pOutput, size_t inpsz );
};


#endif // of __LIBTWOFISH_H__

