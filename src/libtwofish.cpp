#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cstdint>

#include "twofish.h"
#include "tfish.h"

static bool             initstate   = false;
static keyInstance      keyinst     = {0};
static cipherInstance   cipherinst  = {0};
static uint8_t          enc_mode    = MODE_ECB;
static uint8_t*         usr_key     = NULL;
static size_t           usr_keylen  = 0;
static uint8_t*         usr_iv      = NULL;   
static size_t           usr_ivlen   = 0;

bool TwoFish::Initialize( uint8_t* key, uint8_t* iv, size_t keylen, size_t ivlen )
{
    srand((unsigned) time(NULL));
    // it must be rebuild MDS at once.
    BuildMDS();

    if ( ( key == NULL ) && ( iv == NULL ) )
    {
        // reset all.
        memset( &keyinst, 0, sizeof( keyInstance ) );
        memset( &cipherinst, 0, sizeof( cipherInstance ) );
        enc_mode = MODE_ECB;
        initstate = false;
        
        return true;
    }

    if ( usr_key != NULL )
    {
        delete[] usr_key;
        usr_key = NULL;
        usr_keylen = 0;
    }
    
    if ( usr_iv != NULL )
    {
        delete[] usr_iv;
        usr_iv = NULL;
        usr_ivlen = 0;
    }
    
    usr_key = new uint8_t[ keylen ];
    usr_iv  = new uint8_t[ ivlen ];
    
    if ( usr_key != NULL )
    {
        memcpy( usr_key, key, keylen );
    }
    
    if ( iv != NULL )
    {
        if ( usr_iv != NULL )
        {
            memcpy( usr_iv, iv, ivlen );
        }
        enc_mode = MODE_CBC;
    }
   
    initstate = true;
    
    return initstate;
}

size_t TwoFish::GetEncodeLength( size_t srclen )
{
    size_t padsz = srclen % BLOCK_SIZE;
    
    if ( padsz > 0 )
    {
        srclen += BLOCK_SIZE - padsz;
    }
    
    return srclen;
}

size_t TwoFish::Encode( uint8_t* pInput, uint8_t* pOutput, size_t inpsz )
{
    if ( initstate == false )
        return 0;
    
    if ( makeKey( &keyinst, DIR_ENCRYPT, usr_keylen, (const char*)usr_key ) != TF_SUCCESS )
        return 0;
    
    
    if ( usr_iv != NULL )
    {
        size_t rivlen = usr_ivlen;
        
        if ( rivlen > (BLOCK_SIZE/8) )
        {
            rivlen = BLOCK_SIZE/8;
        }
        
        memcpy( cipherinst.iv32, usr_iv, rivlen );
    }
    
    size_t rsz = GetEncodeLength( inpsz );
    
    if ( rsz > 0 )
    {
        pOutput = new uint8_t[ rsz ];
        
        if ( pOutput != NULL )
        {
            memset( pOutput, 0, rsz );
            memcpy( pOutput, pInput, inpsz );
            return blockEncrypt( &cipherinst, &keyinst, pOutput, rsz, pOutput  );
        }
    }
    
    return 0;
}

size_t TwoFish::Decode( uint8_t* pInput, uint8_t* pOutput, size_t inpsz )
{
    if ( initstate == false )
        return 0;

    if ( makeKey( &keyinst, DIR_DECRYPT, usr_keylen, (const char*)usr_key ) != TF_SUCCESS )
        return 0;
    
    if ( usr_iv != NULL )
    {
        size_t rivlen = usr_ivlen;
        
        if ( rivlen > (BLOCK_SIZE/8) )
        {
            rivlen = BLOCK_SIZE/8;
        }
        
        memcpy( cipherinst.iv32, usr_iv, rivlen );
    }

    pOutput = new uint8_t[ inpsz ];
    
    if ( pOutput != NULL )
        return blockDecrypt( &cipherinst, &keyinst, pOutput, inpsz, pOutput );

    return 0;
}

