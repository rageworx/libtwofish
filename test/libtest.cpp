#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdint>
#include <cctype>

#include "twofish.h"

void prtHex( const uint8_t* p, size_t len )
{
    if ( p == NULL )
        return;

    for( size_t cnt=0; cnt<len; cnt++ )
    {
        printf( "%02X", p[cnt] );
    }
}

void genKey( uint8_t* p, size_t len )
{
    for( size_t cnt=0; cnt<len; cnt++ )
    {
        p[cnt] = 1 + cnt;
    }
}

void genRand( uint8_t* p, size_t len )
{
    srand( time(NULL) );
    size_t s = rand()%0x0F;

    for( size_t cnt=0; cnt<len; cnt++ )
    {
        //p[cnt] = rand()%0xFE + 1;
        p[cnt] = (s+cnt)%0XFF + 1;
    }
}

int main( int argc, char** argv )
{
    size_t  testkeylen = 32;
    uint8_t*testkey = new uint8_t[testkeylen];
    size_t  testivlen = 32;
    uint8_t*testiv = new uint8_t[testivlen];
    uint8_t testsrc[] = "This words will be encrypted, and cannot seen before decrypted.";
    uint8_t* encbuff  = NULL;
    size_t   encbuffsz = 0;
    uint8_t* decbuff  = NULL;
    size_t   decbuffsz = 0;
    
    printf( "libtwofish library testing, Rapahael Kim\n" );

    printf( "generating keys ... " );
    genKey( testkey, testkeylen );
    genRand( testiv,  testivlen );
    printf( "Ok.\n" );
    fflush( stdout );

    printf( " key : " );
    prtHex( testkey, testkeylen );
    printf( "\n" );

    printf( " iv  : " );
    prtHex( testiv, testivlen );
    printf( "\n" );
    fflush( stdout );

    printf( " src : %s\n", testsrc );
    fflush( stdout );

    printf( "Initializing ... " );

    bool retb = \
        TwoFish::Initialize( testkey, testiv, testkeylen, testivlen );
    if ( retb == false )
    {
        printf( "Failure.\n" );

        delete[] testkey;
        delete[] testiv;
        return -1;
    }
    printf( "Ok.\n" );
    fflush( stdout );
    
    printf( "Encoding ... " );
    size_t buffsz = TwoFish::GetEncodeLength( sizeof( testsrc ) );
    encbuff = new uint8_t[ buffsz ];
    encbuffsz = TwoFish::Encode( testsrc, encbuff, sizeof( testsrc ) );
    printf( "%lu bytes from %lu bytes.\n", encbuffsz, sizeof( testsrc ) );
    if ( encbuffsz == 0 )
    {
        printf( "Failed to encoding !\n" );
        delete[] testkey;
        delete[] testiv;
        return -1;
    }
    printf( "Ok.\n" );
    fflush( stdout );

    printf( "Encoded:\n" );
    prtHex( encbuff, encbuffsz );
    printf( "\n" );
    fflush( stdout );
    
    printf( "Decoding ... " );
    decbuff = new uint8_t[ encbuffsz ];
    decbuffsz = TwoFish::Decode( encbuff, decbuff, encbuffsz );
    printf( "%lu bytes from %lu bytes.\n", decbuffsz, encbuffsz );
    if ( decbuffsz == 0 )
    {
        printf( "Failed to decoding !\n" );
        delete[] testkey;
        delete[] testiv;
        delete[] encbuff;
        return -1;
    }
    
    printf( "Decoded : %s\n", decbuff );
    
    delete[] testkey;
    delete[] testiv;
    delete[] encbuff;
    delete[] decbuff;
    
    return 0;
}
