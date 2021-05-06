#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cstdint>

#include "twofish.h"
#include "tfish.h"

static bool             initstat    = false;
static keyInstance      keyinst     = {0};
static cipherInstance   cipherinst  = {0};
static uint8_t          enc_mode    = MODE_ECB;
static uint8_t*         usr_key     = NULL;
static size_t           usr_keylen  = 0;
static uint8_t*         usr_iv      = NULL;   
static size_t           usr_ivlen   = 0;

static const char* str2hex( const char* p )
{
    static char sstr[128] = {0};
    memset( sstr, 0, 128 );
    size_t q = 0;

    while( *p > 0 )
    {
        snprintf( &sstr[q],3,"%02X", (uint8_t) *p );
        q+=2;
        p++;
        if( q > 127 )
            break;
    }

    return sstr;
}

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
        initstat = false;
        
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
    
    // allocate memory for string, zero end for +1.
    usr_key = new uint8_t[ MAX_KEY_BITS/8 + 1 ];
    usr_iv  = new uint8_t[ MAX_KEY_BITS/8 + 1 ];
    
    if ( usr_key != NULL )
    {
        if ( keylen > MAX_KEY_BITS/8 )
            keylen = MAX_KEY_BITS/8;
        
        memset( usr_key, 0, MAX_KEY_BITS/8 + 1 );
        memcpy( usr_key, key, keylen );
        usr_keylen = keylen;
        
        if ( usr_keylen < MIN_KEY_BITS/8 )
            usr_keylen = MIN_KEY_BITS/8;
    }
    
    if ( iv != NULL )
    {
        if ( usr_iv != NULL )
        {
            if ( ivlen > MAX_KEY_BITS/8 )
                ivlen = MAX_KEY_BITS/8;
            
            memset( usr_iv, 0, MAX_KEY_BITS/8 + 1 );
            memcpy( usr_iv, iv, ivlen );
            
            usr_ivlen = ivlen;
            
            if ( usr_ivlen < MIN_KEY_BITS/8 )
                usr_ivlen = MIN_KEY_BITS/8;
        }
        enc_mode = MODE_CBC;
    }

    cipherInit( &cipherinst, enc_mode, NULL );
   
    initstat = true;
    
    return initstat;
}

size_t TwoFish::GetEncodeLength( size_t srclen )
{
    size_t padsz = srclen%(BLOCK_SIZE/8);
    
    if ( padsz > 0 )
    {
        return srclen + ( (BLOCK_SIZE/8) - padsz);
    }
    
    return srclen;
}
    
size_t TwoFish::GetBlockSize( bool isbit )
{
    if ( isbit == true )
        return BLOCK_SIZE;

    return BLOCK_SIZE/8;
}

size_t TwoFish::Encode( uint8_t* pInput, uint8_t* pOutput, size_t inpsz )
{
    if ( initstat == false )
        return 0;
    
    if ( ( pInput == NULL ) || ( pOutput == NULL ) )
        return 0;

    const char* convkey = str2hex( (const char*)usr_key );
    size_t convkeylen = strlen( convkey ) * 2;
 
    int reti = makeKey( &keyinst, DIR_ENCRYPT, convkeylen, convkey );
    
    if ( reti != TF_SUCCESS )
    {
#ifdef DEBUG_LIBTWOFISH
        printf( "makeKey() failure : %d, keylen = %lu(%lu bits), %s\n", 
                reti, usr_keylen, usr_keylen*8, (const char*)usr_key );
#endif
        return 0;
    }
    
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

    if ( pInput != pOutput )
    {
        memset( pOutput, 0, rsz );
        memcpy( pOutput, pInput, inpsz );
    }

    size_t loops = rsz / ( BLOCK_SIZE/8 );
    size_t bQ = 0;
    uint32_t* pBin  = (uint32_t*)pOutput;
    uint32_t* pBout = (uint32_t*)pOutput;
    for( size_t cnt=0; cnt<loops; cnt++ )
    {
        int reti = blockEncrypt( &cipherinst, &keyinst, 
                                 (uint8_t*)pBin,
                                 BLOCK_SIZE, 
                                 (uint8_t*)pBout );
        if ( reti > 0 )
        {
            pBin += reti/8/sizeof(uint32_t);
            pBout += reti/8/sizeof(uint32_t);
            bQ += (size_t)reti/8;
        }
        else
            break;
    }

    if ( bQ > 0 )
        return bQ;
    
    return 0;
}

size_t TwoFish::Decode( uint8_t* pInput, uint8_t* pOutput, size_t inpsz )
{
    if ( initstat == false )
        return 0;

    if ( ( pInput == NULL ) || ( pOutput == NULL ) )
        return 0;

    const char* convkey = str2hex( (const char*)usr_key );
    size_t convkeylen = strlen( convkey ) * 2;
    
    int reti = makeKey( &keyinst, DIR_ENCRYPT, convkeylen, convkey );
    
    if ( reti != TF_SUCCESS )
    {
#ifdef DEBUG_LIBTWOFISH
        printf( "makeKey() failure : %d, keylen = %lu(%lu bits), %s\n", 
                reti, usr_keylen, usr_keylen*8, (const char*)usr_key );
#endif
        return 0;
    }
    
    if ( usr_iv != NULL )
    {
        size_t rivlen = usr_ivlen;
        
        if ( rivlen > (BLOCK_SIZE/8) )
        {
            rivlen = BLOCK_SIZE/8;
        }
        
        memcpy( cipherinst.iv32, usr_iv, rivlen );
    }
    
    if ( pInput != pOutput )
    {
        memset( pOutput, 0, inpsz );
        memcpy( pOutput, pInput, inpsz );
    }

    size_t loops = inpsz / ( BLOCK_SIZE/8 );
    size_t bQ = 0;
    uint32_t* pBin  = (uint32_t*)pOutput;
    uint32_t* pBout = (uint32_t*)pOutput;
    for( size_t cnt=0; cnt<loops; cnt++ )
    {
        int reti = blockDecrypt( &cipherinst, &keyinst, 
                                 (uint8_t*)pBin,
                                 BLOCK_SIZE, 
                                 (uint8_t*)pBout );
        if ( reti > 0 )
        {
            pBin  += reti/8/sizeof(uint32_t);
            pBout += reti/8/sizeof(uint32_t);
            bQ    += (size_t)reti/8;
        }
        else
            break;
    }
    
    return bQ;
}

