/***************************************************************************
    twofish.cpp
    
  ------------------------------------------------------------------------
    
    Optimized C API calls for TWOFISH AES submission

    Modern C++ organized:
        Raphael Kim,    https://rageworx.info

    Submitters:
        Bruce Schneier, Counterpane Systems
        Doug Whiting,   Hi/fn
        John Kelsey,    Counterpane Systems
        Chris Hall,     Counterpane Systems
        David Wagner,   UC Berkeley
            
    Code Author:        Doug Whiting,   Hi/fn
        
    Version  1.00       April 1998
        
    Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.
        
    Notes:
        *   Optimized version
        *   Tab size is set to 4 characters in this file

***************************************************************************/
#include <unistd.h>

#include <cstdio>
#include <cassert>
#include <cstdint>
#include <cstring>

#include "tfish.h"
#include "tftables.h"

#if   defined(min_key)  && !defined(MIN_KEY)
    /* toupper() */
    #define MIN_KEY     1
#elif defined(part_key) && !defined(PART_KEY)
    #define PART_KEY    1
#elif defined(zero_key) && !defined(ZERO_KEY)
    #define ZERO_KEY    1
#endif

/*
+*****************************************************************************
*           Constants/Macros/Tables
-****************************************************************************/

static fullSbox MDStab;        /* not actually const.  Initialized ONE time */
static bool     needToBuildMDS = true;       /* is MDStab initialized yet? */

//#define     BIG_TAB     0
#define     BIG_TAB     1

#if BIG_TAB
uint8_t     bigTab[4][256][256];    /* pre-computed S-box */
#endif

/* number of rounds for various key sizes:  128, 192, 256 */
/* (ignored for now in optimized code!) */
const int   numRounds[4]= {0,ROUNDS_128,ROUNDS_192,ROUNDS_256};

#if REENTRANT
#define     _sBox_   key->sBox8x32
#else
static      fullSbox _sBox_;        /* permuted MDStab based on keys */
#endif
#define _sBox8_(N) (((uint8_t *) _sBox_) + (N)*256)

/*------- see what level of S-box precomputation we need to do -----*/
#if   defined(ZERO_KEY)
    #define MOD_STRING  "(Zero S-box keying)"
    #define Fe32_128(x,R)   \
        (   MDStab[0][p8(01)[p8(02)[_b(x,R  )]^b0(SKEY[1])]^b0(SKEY[0])] ^  \
            MDStab[1][p8(11)[p8(12)[_b(x,R+1)]^b1(SKEY[1])]^b1(SKEY[0])] ^  \
            MDStab[2][p8(21)[p8(22)[_b(x,R+2)]^b2(SKEY[1])]^b2(SKEY[0])] ^  \
            MDStab[3][p8(31)[p8(32)[_b(x,R+3)]^b3(SKEY[1])]^b3(SKEY[0])] )
    #define Fe32_192(x,R)   \
        (   MDStab[0][p8(01)[p8(02)[p8(03)[_b(x,R  )]^b0(SKEY[2])]^b0(SKEY[1])]^b0(SKEY[0])] ^ \
            MDStab[1][p8(11)[p8(12)[p8(13)[_b(x,R+1)]^b1(SKEY[2])]^b1(SKEY[1])]^b1(SKEY[0])] ^ \
            MDStab[2][p8(21)[p8(22)[p8(23)[_b(x,R+2)]^b2(SKEY[2])]^b2(SKEY[1])]^b2(SKEY[0])] ^ \
            MDStab[3][p8(31)[p8(32)[p8(33)[_b(x,R+3)]^b3(SKEY[2])]^b3(SKEY[1])]^b3(SKEY[0])] )
    #define Fe32_256(x,R)   \
        (   MDStab[0][p8(01)[p8(02)[p8(03)[p8(04)[_b(x,R  )]^b0(SKEY[3])]^b0(SKEY[2])]^b0(SKEY[1])]^b0(SKEY[0])] ^ \
            MDStab[1][p8(11)[p8(12)[p8(13)[p8(14)[_b(x,R+1)]^b1(SKEY[3])]^b1(SKEY[2])]^b1(SKEY[1])]^b1(SKEY[0])] ^ \
            MDStab[2][p8(21)[p8(22)[p8(23)[p8(24)[_b(x,R+2)]^b2(SKEY[3])]^b2(SKEY[2])]^b2(SKEY[1])]^b2(SKEY[0])] ^ \
            MDStab[3][p8(31)[p8(32)[p8(33)[p8(34)[_b(x,R+3)]^b3(SKEY[3])]^b3(SKEY[2])]^b3(SKEY[1])]^b3(SKEY[0])] )

    #define GetSboxKey  uint32_t SKEY[4];   /* local copy */ \
                        memcpy(SKEY,key->sboxKeys,sizeof(SKEY));
    /*----------------------------------------------------------------*/
    #elif defined(MIN_KEY)
    #define MOD_STRING  "(Minimal keying)"
    #define Fe32_(x,R)(MDStab[0][p8(01)[_sBox8_(0)[_b(x,R  )]] ^ b0(SKEY0)] ^ \
                       MDStab[1][p8(11)[_sBox8_(1)[_b(x,R+1)]] ^ b1(SKEY0)] ^ \
                       MDStab[2][p8(21)[_sBox8_(2)[_b(x,R+2)]] ^ b2(SKEY0)] ^ \
                       MDStab[3][p8(31)[_sBox8_(3)[_b(x,R+3)]] ^ b3(SKEY0)])
    #define sbSet(N,i,J,v) { _sBox8_(N)[i+J] = v; }
    #define GetSboxKey  uint32_t SKEY0  = key->sboxKeys[0]      /* local copy */
    /*----------------------------------------------------------------*/
    #elif defined(PART_KEY) 
    #define MOD_STRING  "(Partial keying)"
    #define Fe32_(x,R)(MDStab[0][_sBox8_(0)[_b(x,R  )]] ^ \
                       MDStab[1][_sBox8_(1)[_b(x,R+1)]] ^ \
                       MDStab[2][_sBox8_(2)[_b(x,R+2)]] ^ \
                       MDStab[3][_sBox8_(3)[_b(x,R+3)]])
    #define sbSet(N,i,J,v) { _sBox8_(N)[i+J] = v; }
    #define GetSboxKey  
/*----------------------------------------------------------------*/
#else   /* default is FULL_KEY */
    #ifndef FULL_KEY
        #define FULL_KEY    1
    #endif
    #if BIG_TAB
        #define TAB_STR     " (Big table)"
    #else
        #define TAB_STR
    #endif
    #ifdef COMPILE_KEY
        #define MOD_STRING  "(Compiled subkeys)" TAB_STR
    #else
        #define MOD_STRING  "(Full keying)" TAB_STR
    #endif
    /* Fe32_ does a full S-box + MDS lookup.  Need to #define _sBox_ before use.
       Note that we "interleave" 0,1, and 2,3 to avoid cache bank collisions
       in optimized assembly language.
    */
    #define Fe32_(x,R) (_sBox_[0][2*_b(x,R  )] ^ _sBox_[0][2*_b(x,R+1)+1] ^ \
                        _sBox_[2][2*_b(x,R+2)] ^ _sBox_[2][2*_b(x,R+3)+1])
            /* set a single S-box value, given the input byte */
    #define sbSet(N,i,J,v) { _sBox_[N&2][2*i+(N&1)+2*J]=MDStab[N][v]; }
    #define GetSboxKey  
#endif

const       char moduleDescription[] = "Optimized C ";
const       char modeString[]        = MOD_STRING;


/* macro(s) for debugging help */
/* nonzero --> compare against "slow" table */
#define     CHECK_TABLE     0
/* disable for full speed */
#define     VALIDATE_PARMS  1

#include    "tfdebug.h"               /* debug display macros */

/* end of debug macros */

#ifdef GetCodeSize
extern uint32_t Here(uint32_t x);           /* return caller's address! */
uint32_t TwofishCodeStart(void) { return Here(0); }
#endif

/*
+*****************************************************************************
*
* Function Name:    TableOp
*
* Function:         Handle table use checking
*
* Arguments:        op  =   what to do  (see TAB_* defns in AES.H)
*
* Return:           TF_SUCCESS --> done (for TAB_QUERY)       
*
* Notes: This routine is for use in generating the tables KAT file.
*        For this optimized version, we don't actually track table usage,
*        since it would make the macros incredibly ugly.  Instead we just
*        run for a fixed number of queries and then say we're done.
*
-****************************************************************************/
int TableOp(int op)
{
    static int queryCnt=0;

    switch (op)
    {
        case TAB_DISABLE:
            break;
        case TAB_ENABLE:
            break;
        case TAB_RESET:
            queryCnt=0;
            break;
        case TAB_QUERY:
            queryCnt++;
            if (queryCnt < TAB_MIN_QUERY)
                return TF_FAILURE;
    }
    
    return TF_SUCCESS;
}


/*
+*****************************************************************************
*
* Function Name:    ParseHexDword
*
* Function:         Parse ASCII hex nibbles and fill in key/iv dwords
*
* Arguments:        bit         =   # bits to read
*                   srcTxt      =   ASCII source
*                   d           =   ptr to dwords to fill in
*                   dstTxt      =   where to make a copy of ASCII source
*                                   (NULL ok)
*
* Return:           Zero if no error.  Nonzero --> invalid hex or length
*
* Notes:  Note that the parameter d is a uint32_t array, not a byte array.
*   This routine is coded to work both for little-endian and big-endian
*   architectures.  The character stream is interpreted as a LITTLE-ENDIAN
*   byte stream, since that is how the Pentium works, but the conversion
*   happens automatically below. 
*
-****************************************************************************/
int ParseHexDword( int bits, const char *srcTxt, uint32_t *d, char* dstTxt )
{
    char c;
    uint32_t b;

    union   /* make sure LittleEndian is defined correctly */
    {
        uint8_t  b[4];
        uint32_t d[1];
    } v;
        
    v.d[0]=1;
    if (v.b[0 ^ ADDR_XOR] != 1)
        return BAD_ENDIAN;      /* make sure compile-time switch is set ok */

    for ( size_t cnt=0; cnt*32<bits; cnt++ )
        d[cnt]=0;               /// first, zero the field

    /* parse one nibble at a time */
    for ( size_t cnt=0; cnt*4<bits; cnt++ )
    {
        /* case out the hexadecimal characters */
        c = srcTxt[cnt];
                
        if (dstTxt) 
            dstTxt[cnt]=c;
        
        if ((c >= '0') && (c <= '9'))
            b=c-'0';
        else if ((c >= 'a') && (c <= 'f'))
            b=c-'a'+10;
        else if ((c >= 'A') && (c <= 'F'))
            b=c-'A'+10;
        else
            return BAD_KEY_MAT; /* invalid hex character */
        
        /* works for big and little endian! */
        d[cnt/8] |= b << (4*((cnt^1)&7));       
    }

    return 0;                   /* no error */
}


#if CHECK_TABLE
/*
+*****************************************************************************
*
* Function Name:    f32
*
* Function:         Run four bytes through keyed S-boxes and apply MDS matrix
*
* Arguments:        x           =   input to f function
*                   k32         =   pointer to key dwords
*                   keyLen      =   total key length (k32 --> keyLey/2 bits)
*
* Return:           The output of the keyed permutation applied to x.
*
* Notes:
*   This function is a keyed 32-bit permutation.  It is the major building
*   block for the Twofish round function, including the four keyed 8x8 
*   permutations and the 4x4 MDS matrix multiply.  This function is used
*   both for generating round subkeys and within the round function on the
*   block being encrypted.  
*
*   This version is fairly slow and pedagogical, although a smartcard would
*   probably perform the operation exactly this way in firmware.   For
*   ultimate performance, the entire operation can be completed with four
*   lookups into four 256x32-bit tables, with three dword xors.
*
*   The MDS matrix is defined in TABLE.H.  To multiply by Mij, just use the
*   macro Mij(x).
*
-****************************************************************************/
uint32_t f32( uint32_t x, const uint32_t *k32, size_t keyLen )
{
    uint8_t  b[4];
    
    /* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
    /* Note that each byte goes through a different combination of S-boxes.*/

    *((uint32_t *)b) = Bswap(x);    /* make b[0] = LSB, b[3] = MSB */
    
    switch ( ((keyLen + 63)/64) & 3 )
    {
        case 0:     /* 256 bits of key */
            b[0] = p8(04)[b[0]] ^ b0(k32[3]);
            b[1] = p8(14)[b[1]] ^ b1(k32[3]);
            b[2] = p8(24)[b[2]] ^ b2(k32[3]);
            b[3] = p8(34)[b[3]] ^ b3(k32[3]);
            /* fall thru, having pre-processed b[0]..b[3] with k32[3] */
        case 3:     /* 192 bits of key */
            b[0] = p8(03)[b[0]] ^ b0(k32[2]);
            b[1] = p8(13)[b[1]] ^ b1(k32[2]);
            b[2] = p8(23)[b[2]] ^ b2(k32[2]);
            b[3] = p8(33)[b[3]] ^ b3(k32[2]);
            /* fall thru, having pre-processed b[0]..b[3] with k32[2] */
        case 2:     /* 128 bits of key */
            b[0] = p8(00)[p8(01)[p8(02)[b[0]] ^ b0(k32[1])] ^ b0(k32[0])];
            b[1] = p8(10)[p8(11)[p8(12)[b[1]] ^ b1(k32[1])] ^ b1(k32[0])];
            b[2] = p8(20)[p8(21)[p8(22)[b[2]] ^ b2(k32[1])] ^ b2(k32[0])];
            b[3] = p8(30)[p8(31)[p8(32)[b[3]] ^ b3(k32[1])] ^ b3(k32[0])];
    }

    /* Now perform the MDS matrix multiply inline. */
    return  ((M00(b[0]) ^ M01(b[1]) ^ M02(b[2]) ^ M03(b[3]))      ) ^
            ((M10(b[0]) ^ M11(b[1]) ^ M12(b[2]) ^ M13(b[3])) <<  8) ^
            ((M20(b[0]) ^ M21(b[1]) ^ M22(b[2]) ^ M23(b[3])) << 16) ^
            ((M30(b[0]) ^ M31(b[1]) ^ M32(b[2]) ^ M33(b[3])) << 24);
    }
#endif  /* CHECK_TABLE */


/*
+*****************************************************************************
*
* Function Name:    RS_MDS_encode
*
* Function:         Use (12,8) Reed-Solomon code over GF(256) to produce
*                   a key S-box dword from two key material dwords.
*
* Arguments:        k0  =   1st dword
*                   k1  =   2nd dword
*
* Return:           Remainder polynomial generated using RS code
*
* Notes:
*   Since this computation is done only once per reKey per 64 bits of key,
*   the performance impact of this routine is imperceptible. The RS code
*   chosen has "simple" coefficients to allow smartcard/hardware implementation
*   without lookup tables.
*
-****************************************************************************/
uint32_t RS_MDS_Encode( uint32_t k0,uint32_t k1 )
{
    uint32_t ret = 0;

    for ( size_t cnt=0; cnt<2; cnt++ )
    {
        /* merge in 32 more key bits */
        ret ^= (cnt) ? k0 : k1;
        /* shift one byte at a time */
        for ( size_t shft=0; shft<4; shft++ )
            RS_rem(ret);
    }
    return ret;
}


/*
+*****************************************************************************
*
* Function Name:    BuildMDS
*
* Function:         Initialize the MDStab array
*
* Arguments:        None.
*
* Return:           None.
*
* Notes:
*   Here we precompute all the fixed MDS table.  This only needs to be done
*   one time at initialization, after which the table is "const".
*
-****************************************************************************/
void BuildMDS(void)
{
    /* Prevent to double rebuild */
    if ( needToBuildMDS == false )
        return;
    
    for ( size_t cnt=0; cnt<256; cnt++ )
    {
        uint8_t m1[2] = {0};
        uint8_t mX[2] = {0};
        uint8_t mY[4] = {0};
        
        /* compute all the matrix elements */
        m1[0]=P8x8[0][cnt];
        mX[0]=(uint8_t) Mul_X(m1[0]);
        mY[0]=(uint8_t) Mul_Y(m1[0]);

        m1[1]=P8x8[1][cnt];
        mX[1]=(uint8_t) Mul_X(m1[1]);
        mY[1]=(uint8_t) Mul_Y(m1[1]);

#undef  Mul_1                   /* change what the pre-processor does with Mij */
#undef  Mul_X
#undef  Mul_Y
#define Mul_1   m1              /* It will now access m01[], m5B[], and mEF[] */
#define Mul_X   mX              
#define Mul_Y   mY

        size_t  d = 0;

#define SetMDS(N)                   \
        b0(d) = M0##N[P_##N##0];    \
        b1(d) = M1##N[P_##N##0];    \
        b2(d) = M2##N[P_##N##0];    \
        b3(d) = M3##N[P_##N##0];    \
        MDStab[N][cnt] = d;

        SetMDS(0);              /* fill in the matrix with elements computed above */
        SetMDS(1);
        SetMDS(2);
        SetMDS(3);
    }
#undef  Mul_1
#undef  Mul_X
#undef  Mul_Y
#define Mul_1   Mx_1            /* re-enable true multiply */
#define Mul_X   Mx_X
#define Mul_Y   Mx_Y
    
#if BIG_TAB
    for ( size_t cnt=0; cnt<4; cnt++ )
    {
        const uint8_t* q0 = NULL;
        const uint8_t* q1 = NULL;

        switch (cnt)
        {
            case 0: q0 = p8(01); q1 = p8(02);   break;
            case 1: q0 = p8(11); q1 = p8(12);   break;
            case 2: q0 = p8(21); q1 = p8(22);   break;
            case 3: q0 = p8(31); q1 = p8(32);   break;
        }
        
        for ( size_t cntj=0; cntj<256; cntj++ )
            for ( size_t cntk=0; cntk<256; cntk++)
                bigTab[cnt][cntj][cntk]=q0[q1[cntk]^cntj];
    }
#endif

    /* NEVER modify the table again! */
    needToBuildMDS = false;
}

/*
+*****************************************************************************
*
* Function Name:    ReverseRoundSubkeys
*
* Function:         Reverse order of round subkeys to switch between encrypt/decrypt
*
* Arguments:        key     =   ptr to keyInstance to be reversed
*                   newDir  =   new direction value
*
* Return:           None.
*
* Notes:
*   This optimization allows both blockEncrypt and blockDecrypt to use the same
*   "fallthru" switch statement based on the number of rounds.
*   Note that key->numRounds must be even and >= 2 here.
*
-****************************************************************************/
void ReverseRoundSubkeys( keyInstance* key, uint8_t newDir )
{
    if ( key == NULL )
        return;
    
    /*register*/ uint32_t* r0 = key->subKeys+ROUND_SUBKEYS;
    /*register*/ uint32_t* r1 = r0 + 2*key->numRounds - 2;

    for (;r0 < r1; r0+=2,r1-=2 )
    {
        /* swap the order */
        uint32_t t0 = r0[0];      
        uint32_t t1 = r0[1];
        /* but keep relative order within pairs */
        r0[0] = r1[0];
        r0[1] = r1[1];
        r1[0] = t0;
        r1[1] = t1;
    }

    key->direction = newDir;
}

/*
+*****************************************************************************
*
* Function Name:    Xor256
*
* Function:         Copy an 8-bit permutation (256 bytes), xoring with a byte
*
* Arguments:        dst     =   where to put result
*                   src     =   where to get data (can be same asa dst)
*                   b       =   byte to xor
*
* Return:           None
*
* Notes:
*   BorlandC's optimization is terrible!  When we put the code inline,
*   it generates fairly good code in the *following* segment (not in the Xor256
*   code itself).  If the call is made, the code following the call is awful!
*   The penalty is nearly 50%!  So we take the code size hit for inlining for
*   Borland, while Microsoft happily works with a call.
*
-****************************************************************************/
#define Xor32(dst,src,i) { ((uint32_t *)dst)[i] = ((uint32_t *)src)[i] ^ tmpX; } 
#define Xor256(dst,src,b)               \
    {                                   \
    register uint32_t tmpX=0x01010101u * b;\
    for (i=0;i<64;i+=4)                 \
        { Xor32(dst,src,i  ); Xor32(dst,src,i+1); Xor32(dst,src,i+2); Xor32(dst,src,i+3); } \
    }

/*
+*****************************************************************************
*
* Function Name:    reKey
*
* Function:         Initialize the Twofish key schedule from key32
*
* Arguments:        key         =   ptr to keyInstance to be initialized
*
* Return:           TF_SUCCESS on success
*
* Notes:
*   Here we precompute all the round subkeys, although that is not actually
*   required.  For example, on a smartcard, the round subkeys can 
*   be generated on-the-fly using f32()
*
-****************************************************************************/
int reKey( keyInstance* key )
{
    if ( key == NULL )
        return TF_FAILURE;
    
    size_t  i,j;
    size_t  k64Cnt = 0;
    size_t  keyLen = 0;
    size_t  subkeyCnt;
    uint32_t A=0;
    uint32_t B=0;
    uint32_t q;
    uint32_t sKey[MAX_KEY_BITS/64] = {0};
    uint32_t k32e[MAX_KEY_BITS/64] = {0};
    uint32_t k32o[MAX_KEY_BITS/64] = {0};
    /* small local 8-bit permutations */
    uint8_t L0[256] = {0};
    uint8_t L1[256] = {0};

#if VALIDATE_PARMS
    #if ALIGN32
    if ((key->keyLen % 64) || (key->keyLen < MIN_KEY_BITS))
    {
        printf( "(Bad Key Inst, len = %u bits)", key->keyLen );
        return BAD_KEY_INSTANCE;
    }
    #endif
#endif

    if ( needToBuildMDS == true )         /* do this one time only */
    {
        BuildMDS();
    }

#define F32(res,x,k32)  \
    {                                                           \
    uint32_t t=x;                                                   \
    switch (k64Cnt & 3)                                         \
        {                                                       \
        case 0:  /* same as 4 */                                \
                    b0(t)   = p8(04)[b0(t)] ^ b0(k32[3]);       \
                    b1(t)   = p8(14)[b1(t)] ^ b1(k32[3]);       \
                    b2(t)   = p8(24)[b2(t)] ^ b2(k32[3]);       \
                    b3(t)   = p8(34)[b3(t)] ^ b3(k32[3]);       \
                 /* fall thru, having pre-processed t */        \
        case 3:     b0(t)   = p8(03)[b0(t)] ^ b0(k32[2]);       \
                    b1(t)   = p8(13)[b1(t)] ^ b1(k32[2]);       \
                    b2(t)   = p8(23)[b2(t)] ^ b2(k32[2]);       \
                    b3(t)   = p8(33)[b3(t)] ^ b3(k32[2]);       \
                 /* fall thru, having pre-processed t */        \
        case 2:  /* 128-bit keys (optimize for this case) */    \
            res=    MDStab[0][p8(01)[p8(02)[b0(t)] ^ b0(k32[1])] ^ b0(k32[0])] ^    \
                    MDStab[1][p8(11)[p8(12)[b1(t)] ^ b1(k32[1])] ^ b1(k32[0])] ^    \
                    MDStab[2][p8(21)[p8(22)[b2(t)] ^ b2(k32[1])] ^ b2(k32[0])] ^    \
                    MDStab[3][p8(31)[p8(32)[b3(t)] ^ b3(k32[1])] ^ b3(k32[0])] ;    \
        }                                                       \
    }

    subkeyCnt = ROUND_SUBKEYS + 2*key->numRounds;
    keyLen=key->keyLen;
    k64Cnt=(keyLen+63)/64;          /* number of 64-bit key words */
    
    for (i=0,j=k64Cnt-1;i<k64Cnt;i++,j--)
    {                           /* split into even/odd key dwords */
        k32e[i]=key->key32[2*i  ];
        k32o[i]=key->key32[2*i+1];
        /* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
        sKey[j]=key->sboxKeys[j]=RS_MDS_Encode(k32e[i],k32o[i]);    /* reverse order */
    }

    for (i=q=0;i<subkeyCnt/2;i++,q+=SK_STEP)    
    {                           /* compute round subkeys for PHT */
        F32(A,q        ,k32e);      /* A uses even key dwords */
        F32(B,q+SK_BUMP,k32o);      /* B uses odd  key dwords */
        B = ROL(B,8);
        key->subKeys[2*i  ] = A+B;  /* combine with a PHT */
        B = A + 2*B;
        key->subKeys[2*i+1] = ROL(B,SK_ROTL);
    }
    
#if !defined(ZERO_KEY)
    switch (keyLen) /* case out key length for speed in generating S-boxes */
    {
        case 128:
        #if defined(FULL_KEY) || defined(PART_KEY)
#if BIG_TAB
            #define one128(N,J) sbSet(N,i,J,L0[i+J])
            #define sb128(N) {                      \
                uint8_t *qq=bigTab[N][b##N(sKey[1])];   \
                Xor256(L0,qq,b##N(sKey[0]));        \
                for (i=0;i<256;i+=2) { one128(N,0); one128(N,1); } }
#else
            #define one128(N,J) sbSet(N,i,J,p8(N##1)[L0[i+J]]^k0)
            #define sb128(N) {                  \
                Xor256(L0,p8(N##2),b##N(sKey[1]));  \
                { register uint32_t k0=b##N(sKey[0]);   \
                for (i=0;i<256;i+=2) { one128(N,0); one128(N,1); } } }
#endif
        #elif defined(MIN_KEY)
            #define sb128(N) Xor256(_sBox8_(N),p8(N##2),b##N(sKey[1]))
        #endif
            sb128(0); sb128(1); sb128(2); sb128(3);
            break;
            
        case 192:
        #if defined(FULL_KEY) || defined(PART_KEY)
            #define one192(N,J) sbSet(N,i,J,p8(N##1)[p8(N##2)[L0[i+J]]^k1]^k0)
            #define sb192(N) {                      \
                Xor256(L0,p8(N##3),b##N(sKey[2]));  \
                { register uint32_t k0=b##N(sKey[0]);   \
                  register uint32_t k1=b##N(sKey[1]);   \
                  for (i=0;i<256;i+=2) { one192(N,0); one192(N,1); } } }
        #elif defined(MIN_KEY)
            #define one192(N,J) sbSet(N,i,J,p8(N##2)[L0[i+J]]^k1)
            #define sb192(N) {                      \
                Xor256(L0,p8(N##3),b##N(sKey[2]));  \
                { register uint32_t k1=b##N(sKey[1]);   \
                  for (i=0;i<256;i+=2) { one192(N,0); one192(N,1); } } }
        #endif
            sb192(0); sb192(1); sb192(2); sb192(3);
            break;
            
        case 256:
        #if defined(FULL_KEY) || defined(PART_KEY)
            #define one256(N,J) sbSet(N,i,J,p8(N##1)[p8(N##2)[L0[i+J]]^k1]^k0)
            #define sb256(N) {                                      \
                Xor256(L1,p8(N##4),b##N(sKey[3]));                  \
                for (i=0;i<256;i+=2) {L0[i  ]=p8(N##3)[L1[i]];      \
                                      L0[i+1]=p8(N##3)[L1[i+1]]; }  \
                Xor256(L0,L0,b##N(sKey[2]));                        \
                { register uint32_t k0=b##N(sKey[0]);                   \
                  register uint32_t k1=b##N(sKey[1]);                   \
                  for (i=0;i<256;i+=2) { one256(N,0); one256(N,1); } } }
        #elif defined(MIN_KEY)
            #define one256(N,J) sbSet(N,i,J,p8(N##2)[L0[i+J]]^k1)
            #define sb256(N) {                                      \
                Xor256(L1,p8(N##4),b##N(sKey[3]));                  \
                for (i=0;i<256;i+=2) {L0[i  ]=p8(N##3)[L1[i]];      \
                                      L0[i+1]=p8(N##3)[L1[i+1]]; }  \
                Xor256(L0,L0,b##N(sKey[2]));                        \
                { register uint32_t k1=b##N(sKey[1]);                   \
                  for (i=0;i<256;i+=2) { one256(N,0); one256(N,1); } } }
        #endif
            sb256(0); sb256(1); sb256(2); sb256(3);
            break;
#endif /// of  !defined(ZERO_KEY)    
    } /// of switch (keyLen)

#if CHECK_TABLE                     /* sanity check  vs. pedagogical code*/
    GetSboxKey;
    
    for ( size_t cnt=0; cnt<subkeyCnt/2; cnt++ )
    {
        A = f32(cnt*SK_STEP        ,k32e,keyLen); /* A uses even key dwords */
        B = f32(cnt*SK_STEP+SK_BUMP,k32o,keyLen); /* B uses odd  key dwords */
        B = ROL(B,8);
        assert(key->subKeys[2*cnt  ] == A+  B);
        assert(key->subKeys[2*cnt+1] == ROL(A+2*B,SK_ROTL));
    }
  #if !defined(ZERO_KEY)            /* any S-boxes to check? */
    for ( size_t cnt=q=0; cnt<256; cnt++, q+=0x01010101 )
        assert(f32(q,key->sboxKeys,keyLen) == Fe32_(q,0));
  #endif
#endif /* CHECK_TABLE */

    DebugDumpKey(key);

    if (key->direction == DIR_ENCRYPT)  
        ReverseRoundSubkeys(key,DIR_ENCRYPT);   /* reverse the round subkey order */

    return TF_SUCCESS;
}

/*
+*****************************************************************************
*
* Function Name:    makeKey
*
* Function:         Initialize the Twofish key schedule
*
* Arguments:        key         =   ptr to keyInstance to be initialized
*                   direction   =   DIR_ENCRYPT or DIR_DECRYPT
*                   keyLen      =   # bits of key text at *keyMaterial
*                   keyMaterial =   ptr to hex ASCII chars representing key bits
*
* Return:           TF_SUCCESS on success
*                   else error code (e.g., BAD_KEY_DIR)
*
* Notes:    This parses the key bits from keyMaterial.  Zeroes out unused key bits
*
-****************************************************************************/
int makeKey( keyInstance* key, uint8_t direction, size_t keyLen, const char* keyMaterial )
{
    /* first, sanity check on parameters */
#if VALIDATE_PARMS
    /* must have a keyInstance to initialize */
    if (key == NULL)            
        return BAD_KEY_INSTANCE;
    
    /* must have valid direction */
    if ((direction != DIR_ENCRYPT) && (direction != DIR_DECRYPT))
        return BAD_KEY_DIR;

    /* length must be valid */
    if ((keyLen > MAX_KEY_BITS) || (keyLen < 8) || (keyLen & 0x3F))
        return BAD_KEY_MAT;
    
    /* show that we are initialized */
    key->keySig = VALID_SIG;
#endif /// of VALIDATE_PARMS

    /* set our cipher direction */
    key->direction  = direction;
    /* round up to multiple of 64 */
    key->keyLen     = (keyLen+63) & ~63;
    key->numRounds  = numRounds[(keyLen-1)/64];
    /* zero unused bits */
    memset(key->key32,0,sizeof(key->key32));
    /* terminate ASCII string */
    key->keyMaterial[MAX_KEY_SIZE]=0;

    if ( (keyMaterial == NULL) || (keyMaterial[0]==0) )
        return TF_SUCCESS;

    if ( ParseHexDword(keyLen,keyMaterial,key->key32,key->keyMaterial) )
        return BAD_KEY_MAT;
    
    return reKey(key);          /* generate round subkeys */
}

/*
+*****************************************************************************
*
* Function Name:    cipherInit
*
* Function:         Initialize the Twofish cipher in a given mode
*
* Arguments:        cipher      =   ptr to cipherInstance to be initialized
*                   mode        =   MODE_ECB, MODE_CBC, or MODE_CFB1
*                   IV          =   ptr to hex ASCII test representing IV bytes
*
* Return:           TF_SUCCESS on success
*                   else error code (e.g., BAD_CIPHER_MODE)
*
-****************************************************************************/
int cipherInit( cipherInstance* cipher, uint8_t mode, const char* IV )
{
    /* first, sanity check on parameters */
#if VALIDATE_PARMS              
    /* must have a cipherInstance to initialize */
    if (cipher == NULL)         
        return BAD_PARAMS;
    
    /* must have valid cipher mode */
    if ((mode != MODE_ECB) && (mode != MODE_CBC) && (mode != MODE_CFB1))
        return BAD_CIPHER_MODE;
    
    cipher->cipherSig   =   VALID_SIG;
#endif

    if ((mode != MODE_ECB) && (IV)) /* parse the IV */
    {
        if (ParseHexDword(BLOCK_SIZE,IV,cipher->iv32,NULL))
            return BAD_IV_MAT;
        
        /* make byte-oriented copy for CFB1 */
        for ( size_t cnt=0; cnt<BLOCK_SIZE/32; cnt++ )
            ((uint32_t *)cipher->IV)[cnt] = Bswap(cipher->iv32[cnt]);
    }

    cipher->mode = mode;

    return TF_SUCCESS;
}

/*
+*****************************************************************************
*
* Function Name:    blockEncrypt
*
* Function:         Encrypt block(s) of data using Twofish
*
* Arguments:        cipher      =   ptr to already initialized cipherInstance
*                   key         =   ptr to already initialized keyInstance
*                   input       =   ptr to data blocks to be encrypted
*                   inputLen    =   # bits to encrypt (multiple of blockSize)
*                   outBuffer   =   ptr to where to put encrypted blocks
*
* Return:           # bits ciphered (>= 0)
*                   else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*        If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*        an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
*        sizes can be supported.
*
-****************************************************************************/
#define LoadBlockE(N)  x[N]=Bswap(((uint32_t *)input)[N]) ^ sk[INPUT_WHITEN+N] ^ IV[N]
#define EncryptRound(K,R,id)    \
            t0     = Fe32##id(x[K  ],0);                    \
            t1     = Fe32##id(x[K^1],3);                    \
            x[K^3] = ROL(x[K^3],1);                         \
            x[K^2]^= t0 +   t1 + sk[ROUND_SUBKEYS+2*(R)  ]; \
            x[K^3]^= t0 + 2*t1 + sk[ROUND_SUBKEYS+2*(R)+1]; \
            x[K^2] = ROR(x[K^2],1);                         \
            DebugDump(x,"",rounds-(R),0,0,1,0);
#define     Encrypt2(R,id)  { EncryptRound(0,R+1,id); EncryptRound(2,R,id); }
int blockEncrypt( cipherInstance* cipher, keyInstance* key, 
                  const uint8_t* input, size_t inputLen, uint8_t* outBuffer )
{
    /* block being encrypted */
    uint32_t x[BLOCK_SIZE/32] = {0};
    /* number of rounds */
    size_t   rounds = key->numRounds;
    /* temps for CFB */
    uint8_t  bit,bit0,ctBit,carry;

    /* make local copies of things for faster access */
    uint8_t  mode = cipher->mode;
    uint32_t sk[TOTAL_SUBKEYS] = {0};
    uint32_t IV[BLOCK_SIZE/32] = {0};

    GetSboxKey;

#if VALIDATE_PARMS
    if ((cipher == NULL) || (cipher->cipherSig != VALID_SIG))
        return BAD_CIPHER_STATE;
    
    if ((key == NULL) || (key->keySig != VALID_SIG))
        return BAD_KEY_INSTANCE;
    
    if ((rounds < 2) || (rounds > MAX_ROUNDS) || (rounds&1))
        return BAD_KEY_INSTANCE;
    
    if ((mode != MODE_CFB1) && (inputLen % BLOCK_SIZE))
        return BAD_INPUT_LEN;

#endif /// of VALIDATE_PARMS

    if ( mode == MODE_CFB1 )
    {   /* use recursion here to handle CFB, one block at a time */
        cipher->mode = MODE_ECB;    /* do encryption in ECB */
        
        for ( size_t n=0; n<inputLen; n++ )
        {
            blockEncrypt(cipher,key,cipher->IV,BLOCK_SIZE,(uint8_t*)x);
            bit0  = 0x80 >> (n & 7);/* which bit position in byte */
            ctBit = (input[n/8] & bit0) ^ ((((uint8_t *) x)[0] & 0x80) >> (n&7));
            outBuffer[n/8] = (outBuffer[n/8] & ~ bit0) | ctBit;
            carry = ctBit >> (7 - (n&7));
            
            //for ( size_t cnt=BLOCK_SIZE/8-1; cnt>=0; cnt-- )
            for ( size_t cnt=BLOCK_SIZE/8; cnt-->0; )
            {
                bit = cipher->IV[cnt] >> 7;   /* save next "carry" from shift */
                cipher->IV[cnt] = (cipher->IV[cnt] << 1) ^ carry;
                carry = bit;
            }
        }
        
        cipher->mode = MODE_CFB1;   /* restore mode for next time */
        return inputLen;
    }

    /* here for ECB, CBC modes */
    if (key->direction != DIR_ENCRYPT)
        ReverseRoundSubkeys(key,DIR_ENCRYPT);   /* reverse the round subkey order */

    /* make local copy of subkeys for speed */
    memcpy(sk,key->subKeys,sizeof(uint32_t)*(ROUND_SUBKEYS+2*rounds));

    if (mode == MODE_CBC)
        BlockCopy(IV,cipher->iv32)
    else
        IV[0]=IV[1]=IV[2]=IV[3]=0;

    for ( size_t n=0; n<inputLen; 
          n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8 )
    {
#ifdef DEBUG
        DebugDump(input,"\n",-1,0,0,0,1);
        if (cipher->mode == MODE_CBC)
            DebugDump(cipher->iv32,"",IV_ROUND,0,0,0,0);
#endif
        LoadBlockE(0);  LoadBlockE(1);  LoadBlockE(2);  LoadBlockE(3);
#ifdef DEBUG
        DebugDump(x,"",0,0,0,0,0);
#endif

        uint32_t t0 = 0;
        uint32_t t1 = 0;

#if defined(ZERO_KEY)
        switch (key->keyLen)
        {
            case 128:
                for ( size_t cnt=rounds-2; cnt>=0; cnt-=2 )
                    Encrypt2( cnt, _128 );
                break;
                
            case 192:
                for ( size_t cnt=rounds-2; cnt>=0; cnt-=2 )
                    Encrypt2( cnt, _192 );
                break;
                
            case 256:
                for ( size_t cnt=rounds-2; cnt>=0; cnt-=2 )
                    Encrypt2( cnt, _256 );
                break;
        }
#else
        Encrypt2(14,_);
        Encrypt2(12,_);
        Encrypt2(10,_);
        Encrypt2( 8,_);
        Encrypt2( 6,_);
        Encrypt2( 4,_);
        Encrypt2( 2,_);
        Encrypt2( 0,_);
#endif

        /* need to do (or undo, depending on your point of view) final swap */
#if LittleEndian
    #define StoreBlockE(N)  ((uint32_t *)outBuffer)[N]=x[N^2] ^ sk[OUTPUT_WHITEN+N]
#else
    #define StoreBlockE(N)  { t0=x[N^2] ^ sk[OUTPUT_WHITEN+N]; ((uint32_t *)outBuffer)[N]=Bswap(t0); }
#endif
        StoreBlockE(0); StoreBlockE(1); StoreBlockE(2); StoreBlockE(3);
        
        if ( mode == MODE_CBC )
        {
            IV[0] = Bswap(((uint32_t*)outBuffer)[0]);
            IV[1] = Bswap(((uint32_t*)outBuffer)[1]);
            IV[2] = Bswap(((uint32_t*)outBuffer)[2]);
            IV[3] = Bswap(((uint32_t*)outBuffer)[3]);
        }
        
#ifdef DEBUG
        DebugDump(outBuffer,"",rounds+1,0,0,0,1);
        
        if (cipher->mode == MODE_CBC)
            DebugDump(cipher->iv32,"",IV_ROUND,0,0,0,0);
#endif
    }

    if ( mode == MODE_CBC )
        BlockCopy( cipher->iv32, IV );

    return (int)inputLen;
}

/*
+*****************************************************************************
*
* Function Name:    blockDecrypt
*
* Function:         Decrypt block(s) of data using Twofish
*
* Arguments:        cipher      =   ptr to already initialized cipherInstance
*                   key         =   ptr to already initialized keyInstance
*                   input       =   ptr to data blocks to be decrypted
*                   inputLen    =   # bits to encrypt (multiple of blockSize)
*                   outBuffer   =   ptr to where to put decrypted blocks
*
* Return:           # bits ciphered (>= 0)
*                   else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*        If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*        an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
*        sizes can be supported.
*
-****************************************************************************/
#define LoadBlockD(N) x[N^2]=Bswap(((uint32_t *)input)[N]) ^ sk[OUTPUT_WHITEN+N]
#define DecryptRound(K,R,id)                                \
            t0     = Fe32##id(x[K  ],0);                    \
            t1     = Fe32##id(x[K^1],3);                    \
            x[K^2] = ROL (x[K^2],1);                        \
            x[K^2]^= t0 +   t1 + sk[ROUND_SUBKEYS+2*(R)  ]; \
            x[K^3]^= t0 + 2*t1 + sk[ROUND_SUBKEYS+2*(R)+1]; \
            x[K^3] = ROR (x[K^3],1);                        \

#define     Decrypt2(R,id)  { DecryptRound(2,R+1,id); DecryptRound(0,R,id); }
int blockDecrypt( cipherInstance* cipher, keyInstance* key, 
                  const uint8_t* input, size_t inputLen, uint8_t* outBuffer )
{
    /* block being encrypted */
    uint32_t x[BLOCK_SIZE/32] = {0};         
    /* number of rounds */
    size_t   rounds=key->numRounds;
    /* temps for CFB */
    uint8_t  bit,bit0,ctBit,carry;

    /* make local copies of things for faster access */
    uint8_t  mode = cipher->mode;
    uint32_t sk[TOTAL_SUBKEYS] = {0};
    uint32_t IV[BLOCK_SIZE/32] = {0};

    GetSboxKey;

#if VALIDATE_PARMS
    if ((cipher == NULL) || (cipher->cipherSig != VALID_SIG))
        return BAD_CIPHER_STATE;
    
    if ((key == NULL) || (key->keySig != VALID_SIG))
        return BAD_KEY_INSTANCE;
    
    if ((rounds < 2) || (rounds > MAX_ROUNDS) || (rounds&1))
        return BAD_KEY_INSTANCE;
    
    if ((cipher->mode != MODE_CFB1) && (inputLen % BLOCK_SIZE))
        return BAD_INPUT_LEN;
#endif

    if (cipher->mode == MODE_CFB1)
    {   /* use blockEncrypt here to handle CFB, one block at a time */
        cipher->mode = MODE_ECB;    /* do encryption in ECB */
        
        for ( size_t n=0; n<inputLen; n++ )
        {
            blockEncrypt(cipher,key,cipher->IV,BLOCK_SIZE,(uint8_t *)x);
            bit0  = 0x80 >> (n & 7);
            ctBit = input[n/8] & bit0;
            outBuffer[n/8] = (outBuffer[n/8] & ~ bit0) |
                             (ctBit ^ ((((uint8_t *) x)[0] & 0x80) >> (n&7)));
            carry = ctBit >> (7 - (n&7));
            
            //for ( size_t cnt=BLOCK_SIZE/8-1;i>=0;i--)
            for ( size_t cnt=BLOCK_SIZE/8; cnt-->0; )
            {
                /* save next "carry" from shift */
                bit = cipher->IV[cnt] >> 7;
                cipher->IV[cnt] = (cipher->IV[cnt] << 1) ^ carry;
                carry = bit;
            }
        }
        
        /* restore mode for next time */
        cipher->mode = MODE_CFB1;
        
        return inputLen;
    }

    /* here for ECB, CBC modes */
    if (key->direction != DIR_DECRYPT)
        ReverseRoundSubkeys(key,DIR_DECRYPT);   /// reverse the round subkey order

    /* make local copy of subkeys for speed */
    memcpy(sk,key->subKeys,sizeof(uint32_t)*(ROUND_SUBKEYS+2*rounds));
    
    if ( mode == MODE_CBC )
        BlockCopy(IV,cipher->iv32)
    else
        IV[0]=IV[1]=IV[2]=IV[3]=0;

    for ( size_t n=0; n<inputLen;
          n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8 )
    {
#ifdef DEBUG
        DebugDump(input,"\n",rounds+1,0,0,0,1);
#endif /// if DEBUG
        LoadBlockD(0);  LoadBlockD(1);  LoadBlockD(2);  LoadBlockD(3);

        uint32_t t0 = 0;
        uint32_t t1 = 0;

#if defined(ZERO_KEY)
        switch (key->keyLen)
        {
            case 128:
                for ( size_t cnt=rounds-2; cnt>=0; cnt-=2 )
                    Decrypt2( cnt, _128 );
                break;
                
            case 192:
                for ( size_t cnt=rounds-2; cnt>=0; cnt-=2 )
                    Decrypt2( cnt, _192 );
                break;
                
            case 256:
                for ( size_t cnt=rounds-2; cnt>=0; cnt-=2 )
                    Decrypt2( cnt, _256 );
                break;
        }
#else
        Decrypt2(14,_);
        Decrypt2(12,_);
        Decrypt2(10,_);
        Decrypt2( 8,_);
        Decrypt2( 6,_);
        Decrypt2( 4,_);
        Decrypt2( 2,_);
        Decrypt2( 0,_);
#endif
        DebugDump(x,"",0,0,0,0,0);
        
        if (cipher->mode == MODE_ECB)
        {
#if LittleEndian
    #define StoreBlockD(N)  ((uint32_t *)outBuffer)[N] = x[N] ^ sk[INPUT_WHITEN+N]
#else
    #define StoreBlockD(N)  { t0=x[N]^sk[INPUT_WHITEN+N]; ((uint32_t *)outBuffer)[N] = Bswap(t0); }
#endif
            StoreBlockD(0); StoreBlockD(1); StoreBlockD(2); StoreBlockD(3);
#undef  StoreBlockD
            DebugDump(outBuffer,"",-1,0,0,0,1);
            continue;
        }
        else
        {
#define StoreBlockD(N)  x[N]   ^= sk[INPUT_WHITEN+N] ^ IV[N];   \
                        IV[N]   = Bswap(((uint32_t *)input)[N]);    \
                        ((uint32_t *)outBuffer)[N] = Bswap(x[N]);
            StoreBlockD(0); StoreBlockD(1); StoreBlockD(2); StoreBlockD(3);
#undef  StoreBlockD
            DebugDump(outBuffer,"",-1,0,0,0,1);
        }
    }
    
    /* restore iv32 to cipher */
    if (mode == MODE_CBC)
        BlockCopy(cipher->iv32,IV)

    return inputLen;
}

#ifdef GetCodeSize
uint32_t TwofishCodeSize(void)
{
    uint32_t x= Here(0);
#ifdef USE_ASM
    if (useAsm & 3)
        return TwofishAsmCodeSize();
#endif
    return x - TwofishCodeStart();
};
#endif
