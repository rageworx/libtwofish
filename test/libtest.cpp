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


int main( int argc, char** argv )
{
    uint8_t testkey[] = "this must be a key";
    uint8_t testiv[]  = "Oh dear, it must be a iv.";
    uint8_t testsrc[] = "This words will be encrypted, and cannot seen before decrypted.";
    uint8_t* encbuff  = NULL;
    size_t   encbuffsz = 0;
    uint8_t* decbuff  = NULL;
    size_t   decbuffsz = 0;
    
    printf( "Test word : %s\n", testsrc );
    
    printf( "Initializing ... " );
    bool retb = TwoFish::Initialize( testkey, testiv, sizeof( testkey ), sizeof( testiv ) );
    if ( retb == false )
    {
        printf( "Failure.\n" );
        return -1;
    }
    printf( "Ok.\n" );
    fflush( stdout );
    
    printf( "Encoding ... " );
    encbuffsz = TwoFish::Encode( testsrc, encbuff, sizeof( testsrc ) );
    printf( "%u bytes from %u bytes.\n", encbuffsz, sizeof( testsrc ) );
    if ( encbuffsz == 0 )
    {
        printf( "Failed to encoding !\n" );
        return -1;
    }
    printf( "Ok.\n" );
    fflush( stdout );

    prtHex( encbuff, encbuffsz );
    
    printf( "Decoding ... " );
    decbuffsz = TwoFish::Decode( encbuff, decbuff, encbuffsz );
    printf( "%u bytes from %u bytes.\n", decbuffsz, encbuffsz );
    if ( decbuffsz == 0 )
    {
        printf( "Failed to decoding !\n" );
        delete[] encbuff;
        return -1;
    }
    
    printf( "Decoded : %s\n", decbuff );
    
    delete[] encbuff;
    delete[] decbuff;
    
    return 0;
}
