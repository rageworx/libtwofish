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

class TwoFish
{
    public:
        /* iv and ivlen should be skipped for ECB encoding.
        */
        TwoFish( uint8_t* key = NULL, size_t keylen = 0, const char* iv = NULL, size_t ivlen = 0 );
        ~TwoFish();
        
    public:
        bool   SetKey( uint8_t* key = NULL, size_t keylen = 0, const char* iv = NULL, size_t ivlen = 0 );
        size_t GetEncodeLength( size_t srclen );
        size_t GetBlockSize( bool isbit = true );
        size_t Encode( uint8_t* pInput, uint8_t*& pOutput, size_t inpsz );
        size_t Decode( uint8_t* pInput, uint8_t*& pOutput, size_t inpsz );
        
    public:
        void* context;
};

#endif // of __LIBTWOFISH_H__

