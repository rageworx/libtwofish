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

    uint8_t* pp = (uint8_t*)p;
    for( size_t cnt=0; cnt<len; cnt++ )
    {
        printf( "%02X", *pp );
        pp++;
    }
    printf( "\n" );
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
    for( size_t cnt=0; cnt<len; cnt++ )
    {
        p[cnt] = rand()%0xFF;
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
    
    genKey( testkey, testkeylen );
    genRand( testiv,  testivlen );

    printf( "Test word : %s\n", testsrc );
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

    prtHex( encbuff, encbuffsz );
    
    printf( "Decoding ... " );
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
