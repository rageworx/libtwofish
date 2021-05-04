#ifdef DEBUG    
#ifndef _MSC_VER
#include <unistd.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include "tfdebug.h"

/* keep these macros common so they are same for both versions */
static  bool debugCompile = 1;
extern  int  debug;
/* display the debug output */
extern  void DebugIO( const char *s );    

#define IV_ROUND    -100
    
void _Dump( const void* p, const char *s,
            int R, int XOR, int doRot, int showT, int needBswap,
            uint32_t t0, uint32_t t1 );
{
    if ( ( p == NULL ) || ( s == NULL ) )
        return;
    
    /* build output here */
    char line[512] = {0};
    uint32_t q[4] = {0};

    if ( R == IV_ROUND )
        snprintf( line, 512, "%sIV:    ", s );
    else
        snprintf( line, 512, "%sR[%2d]: ", s, R );

    // what for this loop ??
    for ( size_t n=0; line[n]; n++ );
    
    for ( size_t cnt=0; cnt<4; cnt++ )
    {
        q[cnt] = ((const uint32_t*)p)[cnt^(XOR)];

        if (needBswap) 
            q[cnt]=Bswap(q[cnt]);
    }

    snprintf( line+n, 512-n, 
              "x= %08lX  %08lX  %08lX  %08lX.",
              ROR(q[0],doRot*(R  )/2),
              ROL(q[1],doRot*(R  )/2),
              ROR(q[2],doRot*(R+1)/2),
              ROL(q[3],doRot*(R+1)/2) );
              
    for (;line[n];n++);

    if (showT)
        snprintf( line+n, 512-n, "    t0=%08lX. t1=%08lX.", t0, t1 );
    
    for (;line[n];n++);

    snprintf( line+n, 512-n, "\n" );
    DebugIO(line);
}

void _DumpKey( const keyInstance *key )
{
    if ( key == NULL )
        return;
    
    char    line[512] = {0};
    int     k64Cnt    = (key->keyLen+63)/64; /* round up to next multiple of 64 bits */
    int     subkeyCnt = ROUND_SUBKEYS + 2 * key->numRounds;

    snprintf( line, 512, 
              ";\n;makeKey:   Input key            -->  S-box key     [%s]\n",
              (key->direction == DIR_ENCRYPT) ? "Encrypt" : "Decrypt" );
              
    DebugIO( line );
    
    /* display in RS format */
    for ( size_t cnt=0; cnt<k64Cnt; cnt++ )
    {
        snprintf( line, 512, 
                  ";%12s %08lX %08lX  -->  %08lX\n","",
                  key->key32[2*i+1],key->key32[2*i],
                  key->sboxKeys[k64Cnt-1-i] );
        DebugIO(line);
    }
    
    snprintf( line, 512, ";%11sSubkeys\n","");
    DebugIO(line);
    
    for ( size_t cnt=0; cnt<subkeyCnt/2; cnt++ )
    {
        snprintf( line, 512, 
                  ";%12s %08lX %08lX%s\n",
                  "",
                  key->subKeys[2*i],key->subKeys[2*i+1],
                  (2*i ==  INPUT_WHITEN) ? "   Input whiten" :
                  (2*i == OUTPUT_WHITEN) ? "  Output whiten" :
                  (2*i == ROUND_SUBKEYS) ? "  Round subkeys" : "" );
        DebugIO(line);
    }
    
    DebugIO(";\n");
}
#else /// of DEBUG
static bool debugCompile  =   0;
#endif /// of DEBUG
