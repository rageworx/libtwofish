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

void genRand( char* p, size_t len )
{
    srand( time(NULL) );
    size_t s = rand()%0x0F + 'A';

    for( size_t cnt=0; cnt<len; cnt++ )
    {
        p[cnt] = (s+cnt)%0XFF + 1;
    }
}

int main( int argc, char** argv )
{
    uint8_t  testkey[]  = "encrypt key set 1";
    size_t   testkeylen = strlen( (const char*)testkey );
    char     testiv[]   = "iv set 1";
    size_t   testivlen  = strlen( (const char*)testiv );
    uint8_t  testsrc[]  = "This words will be encrypted, and cannot seen before decrypted.";
    uint8_t* encbuff    = NULL;
    size_t   encbuffsz  = 0;
    uint8_t* decbuff    = NULL;
    size_t   decbuffsz  = 0;
    
    printf( "libtwofish testing suit, Rapahael Kim, (C)2021\n" );

    printf( " key : " );
    prtHex( testkey, testkeylen );
    printf( "\n" );

    printf( " iv  : " );
    prtHex( (const uint8_t*)testiv, testivlen );
    printf( "\n" );
    fflush( stdout );

    printf( " src : %s\n", testsrc );
    fflush( stdout );

    printf( "Initializing ... " );
    TwoFish* tf = new TwoFish();
    if ( tf == NULL )
    {
        printf( "Failure.\n" );

        return -1;
    }
    printf( "Ok.\n" );
    fflush( stdout );
    
    tf->Initialize( testkey, testkeylen, testiv, testivlen );
    
    printf( "Encoding ... " );
    encbuffsz = tf->Encode( testsrc, encbuff, sizeof( testsrc ) );
    printf( "%lu bytes from %lu bytes, ", encbuffsz, sizeof( testsrc ) );
    fflush( stdout );
    if ( encbuffsz == 0 )
    {
        printf( "Failed to encoding !\n" );
        delete tf;
        return -1;
    }
    printf( "Ok.\n" );
    fflush( stdout );
    
    printf( "Encoded:\n" );
    prtHex( encbuff, encbuffsz );
    printf( "\n" );
    fflush( stdout );
    
    printf( "Decoding ... " );
    decbuffsz = tf->Decode( encbuff, decbuff, encbuffsz );
    printf( "%lu bytes from %lu bytes.\n", decbuffsz, encbuffsz );
    if ( decbuffsz == 0 )
    {
        printf( "Failed to decoding !\n" );
        delete tf;
        delete[] encbuff;
        return -1;
    }
    
    printf( "Decoded : %s\n", decbuff );
    
    delete tf;
    delete[] encbuff;
    delete[] decbuff;
    
    return 0;
}
