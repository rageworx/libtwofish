#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cstdint>

#include "twofish.h"
#include "tfish.h"

////////////////////////////////////////////////////////////////////////////////

typedef struct
{
    bool             initstat;
    keyInstance      keyinst;
    cipherInstance   cipherinst;
    uint8_t          enc_mode;
    uint8_t*         usr_key;
    size_t           usr_keylen;
    char*            usr_iv;
    size_t           usr_ivlen;
    char*            usr_keyref;
    char*            usr_ivref;
}libTwoFishContext;

#define MAX_KEY_BLEN    256
#define L2FCTX          libTwoFishContext
#define TOCTX(_x_)      L2FCTX* _x_ = (L2FCTX*)context

// default key references -
static char hexTab[]   = "0123456789ABCDEF";
static char hexString[]= "0123456789ABCDEFFEDCBA987654321000112233445566778899"
                         "AABBCCDDEEFF";
// -

////////////////////////////////////////////////////////////////////////////////

void str2hex( const uint8_t* p, char*& o )
{
    if ( p == NULL )
        return;
    
    size_t l = strlen( (const char*)p );

    o = new char[ l * 2 + 1 ];
    
    if ( o != NULL )
    {
        memset( o, 0, l * 2 + 1 );
        
        for( size_t cnt=0; cnt<l; cnt++ )
        {
            snprintf( &o[cnt*2], 3, "%02X", (uint8_t)p[cnt] );
        }                
    }
}

void key2hex( const uint8_t* p, size_t l, keyInstance* ki )
{
    if ( ( p == NULL ) || ( l == 0 ) || ( ki == NULL ) )
        return;
        
    //char* sstr = new char[ MAX_KEY_SIZE + 1 ];
    char* sstr = new char[ l*2 + 1 ];
    
    if ( sstr != NULL )
    {
        //memset( sstr, 0, MAX_KEY_SIZE + 1 );
        memset( sstr, 0, l*2 + 1 );
        
        for( size_t cnt=0; cnt<l; cnt++ )
        {
            snprintf( &sstr[cnt*2], 3, "%02X", (uint8_t) p[cnt] );
        }
                
        for( size_t cnt=0; cnt<(MAX_KEY_BITS/32); cnt++ )
        {
            char tmps[16] = {0};
            snprintf( tmps, 16, "0xFF000000" );
            memcpy( &tmps[2], &sstr[(cnt*8)%8], 8 );
            ki->key32[cnt] = (uint32_t)strtoul( tmps, NULL, 0 );
        }
        
        delete[] sstr;
    }
}

void iv2hex( const char* p, size_t l, cipherInstance* ci )
{
    if ( ( p == NULL ) || ( l == 0 ) )
        return;
        
    //char* sstr = new char[ MAX_IV_SIZE + 1 ];
    char* sstr = new char[ l*2 + 1 ];
    
    if ( sstr != NULL )
    {
        //memset( sstr, 0, MAX_IV_SIZE + 1 );
        memset( sstr, 0, l*2 + 1 );
        
        for( size_t cnt=0; cnt<l; cnt++ )
        {
            snprintf( &sstr[cnt*2], 3, "%02X", (uint8_t) p[cnt] );
        }
        
        for( size_t cnt=0; cnt<BLOCK_SIZE/32; cnt++ )
        {
            char tmps[16] = {0};
            snprintf( tmps, 16, "0xFF000000" );
            memcpy( &tmps[2], &sstr[(cnt*8)%8], 8 );
            ci->iv32[cnt] = (uint32_t)strtoul( tmps, NULL, 0 );
        }
        
        delete[] sstr;
    }
}


////////////////////////////////////////////////////////////////////////////////

TwoFish::TwoFish( uint8_t* key, size_t keylen, const char* iv, size_t ivlen )
 : context( NULL )
{
    // it must be rebuild MDS at once.
    BuildMDS();

    L2FCTX* tfcontext = new L2FCTX;
    if ( tfcontext != NULL )
    {
        memset( tfcontext, 0, sizeof( L2FCTX ) );
        context = (void*)tfcontext;
#ifdef DEBUG_LIBTWOFISH
        bool retb = Initialize( key, keylen, iv, ivlen );
        if ( retb == false )
        {
            printf( "(warning : Initialize() failure.\n" );
        }
#else
        Initialize( key, keylen, iv, ivlen );
#endif
    }
}

TwoFish::~TwoFish()
{
    TOCTX( tfctx );
    
    if ( tfctx != NULL )
    {
        context = NULL;
        
        if ( tfctx->usr_key != NULL )
            delete[] tfctx->usr_key;
        
        if ( tfctx->usr_iv != NULL )
            delete[] tfctx->usr_iv;
        
        if ( tfctx->usr_keyref != NULL )
            delete[] tfctx->usr_keyref;
        
        if ( tfctx->usr_ivref != NULL )
            delete[] tfctx->usr_ivref;
        
        delete tfctx;
    }
}

bool TwoFish::Initialize( uint8_t* key, size_t keylen, const char* iv, size_t ivlen )
{
    TOCTX( tfctx );
    
    if ( tfctx != NULL )
    {       
        /// let initailize cipher.
        int rinit = TF_SUCCESS;

        // allocate memory for string, zero end for +1.
        if ( tfctx->usr_key == NULL )
        {
            tfctx->usr_key = new uint8_t[ MAX_KEY_SIZE + 1 ];
        }
        
        if ( tfctx->usr_iv == NULL )
        {
            tfctx->usr_iv  = new char[ MAX_IV_SIZE + 1 ];
        }
        
        if ( tfctx->usr_key != NULL )
        {
            memset( tfctx->usr_key, 0, MAX_KEY_SIZE + 1 );
            tfctx->usr_keylen = 0;
            
            if ( key != NULL )
            {
                // key size cannot be over than (MAX_KEY_BITS/8). 
                if ( keylen > MAX_KEY_SIZE )
                    keylen = MAX_KEY_SIZE;
                
                // this key is plain text/data.
                memcpy( tfctx->usr_key, key, keylen );
                
                // key size each 128, or 192, or 256 bits.
                if ( keylen < MIN_KEY_BITS/8 )
                    tfctx->usr_keylen = MIN_KEY_BITS/8;
                else
                    tfctx->usr_keylen = MAX_KEY_BITS/8;
            }
            
            if ( tfctx->usr_keyref != NULL )
            {
                delete[] tfctx->usr_keyref;
                tfctx->usr_keyref = NULL;
            }
            
            str2hex( tfctx->usr_key, tfctx->usr_keyref );
            
            tfctx->enc_mode = MODE_ECB;
        }
        
        // then CBC 
        if ( tfctx->usr_iv != NULL )
        {
            memset( tfctx->usr_iv, 0, MAX_IV_SIZE + 1 );
            tfctx->usr_ivlen = 0;

            if ( ( iv != NULL ) && ( ivlen > 0 ) )
            {
                if ( ivlen > MAX_IV_SIZE )
                    ivlen = MAX_IV_SIZE;

                memcpy( tfctx->usr_iv, iv, ivlen );
                tfctx->usr_ivlen = ivlen;
                // it need to debug.
                iv2hex( tfctx->usr_iv, tfctx->usr_ivlen, &tfctx->cipherinst );
                
                if ( tfctx->usr_ivref != NULL )
                {
                    delete[] tfctx->usr_ivref;
                    tfctx->usr_ivref = NULL;
                }
                
                str2hex( (const uint8_t*)tfctx->usr_iv, tfctx->usr_ivref );
            }
            
            tfctx->enc_mode = MODE_CBC;
        }
        
        rinit = cipherInit( &tfctx->cipherinst, tfctx->enc_mode, tfctx->usr_ivref );
            
#ifdef DEBUG_LIBTWOFISH        
        if ( rinit != TF_SUCCESS )
        {
            printf( "cipherInit failure by : %d\n", rinit );
            return false;
        }
#endif /// of DEBUG_LIBTWOFISH        
        return true;
    }
    
    return false;
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

size_t TwoFish::Encode( uint8_t* pInput, uint8_t*& pOutput, size_t inpsz )
{
    if ( context == NULL )
        return 0;
    
    if ( pInput == NULL )
        return 0;
    
    TOCTX( tfctx );

    key2hex( tfctx->usr_key, tfctx->usr_keylen, &tfctx->keyinst );

    cipherInit( &tfctx->cipherinst, tfctx->enc_mode, tfctx->usr_ivref );

    int reti = makeKey( &tfctx->keyinst, DIR_ENCRYPT, 
                        tfctx->usr_keylen * 8, hexString );
    
    if ( reti != TF_SUCCESS )
    {
#ifdef DEBUG_LIBTWOFISH
        printf( "makeKey() failure : %d\n", reti );
#endif
        return 0;
    }
        
    size_t rsz = GetEncodeLength( inpsz );

    if ( pOutput == NULL )
    {
        pOutput = new uint8_t[ rsz ];
        
        if ( pOutput == NULL )
            return 0;
    }
    
    // copy to output, by align TwoFish block size.
    memset( pOutput, 0, rsz );
    memcpy( pOutput, pInput, inpsz );

    size_t    loops = rsz / ( BLOCK_SIZE/8 );
    size_t    bQ    = 0;
    uint32_t* pBin  = (uint32_t*)pOutput;
    uint32_t* pBout = (uint32_t*)pOutput;
    
    for( size_t cnt=0; cnt<loops; cnt++ )
    {
        int reti = blockEncrypt( &tfctx->cipherinst, 
                                 &tfctx->keyinst, 
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

    if ( bQ > 0 )
        return bQ;
    
    return 0;
}

size_t TwoFish::Decode( uint8_t* pInput, uint8_t*& pOutput, size_t inpsz )
{
    if ( context == NULL )
        return 0;

    if ( pInput == NULL )
        return 0;

    TOCTX( tfctx );

    key2hex( tfctx->usr_key, tfctx->usr_keylen, &tfctx->keyinst );
    
    cipherInit( &tfctx->cipherinst, tfctx->enc_mode, tfctx->usr_ivref );
     
    int reti = makeKey( &tfctx->keyinst, DIR_DECRYPT, 
                        //tfctx->usr_keylen * 8, tfctx->usr_keyref );
                        tfctx->usr_keylen * 8, hexString );
     
    if ( reti != TF_SUCCESS )
    {
#ifdef DEBUG_LIBTWOFISH
        printf( "makeKey() failure : \n", reti );
#endif
        return 0;
    }

    if ( pOutput == NULL )
    {
        pOutput = new uint8_t[inpsz];

        if ( pOutput == NULL )
            return 0;
    }

    memset( pOutput, 0, inpsz );

    size_t loops = inpsz / ( BLOCK_SIZE/8 );
    size_t bQ = 0;
    uint32_t* pBin  = (uint32_t*)pInput;
    uint32_t* pBout = (uint32_t*)pOutput;
    for( size_t cnt=0; cnt<loops; cnt++ )
    {
        int reti = blockDecrypt( &tfctx->cipherinst, 
                                 &tfctx->keyinst, 
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

