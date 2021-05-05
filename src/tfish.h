#ifndef __TFISH_H__
#define __TFISH_H__

/* ---------- See examples at end of this file for typical usage -------- */

/* AES Cipher header file for ANSI C Submissions
    Lawrence E. Bassham III
    Computer Security Division
    National Institute of Standards and Technology

    This sample is to assist implementers developing to the
Cryptographic API Profile for AES Candidate Algorithm Submissions.
Please consult this document as a cross-reference.
    
    ANY CHANGES, WHERE APPROPRIATE, TO INFORMATION PROVIDED IN THIS FILE
MUST BE DOCUMENTED. CHANGES ARE ONLY APPROPRIATE WHERE SPECIFIED WITH
THE STRING "CHANGE POSSIBLE". FUNCTION CALLS AND THEIR PARAMETERS
CANNOT BE CHANGED. STRUCTURES CAN BE ALTERED TO ALLOW IMPLEMENTERS TO
INCLUDE IMPLEMENTATION SPECIFIC INFORMATION.
*/

/* platform-specific defines */
#include "tfplatform.h"

/*  Defines:
        Add any additional defines you need
*/

#define     DIR_ENCRYPT         0  /* Are we encrpyting? */
#define     DIR_DECRYPT         1  /* Are we decrpyting? */
#define     MODE_ECB            1  /* Are we ciphering in ECB mode? */
#define     MODE_CBC            2  /* Are we ciphering in CBC mode? */
#define     MODE_CFB1           3  /* Are we ciphering in 1-bit CFB mode? */

#define     TF_SUCCESS           1
#define     TF_FAILURE           0
#define     BAD_KEY_DIR         -1  /* Key direction is invalid (unknown value) */
#define     BAD_KEY_MAT         -2  /* Key material not of correct length */
#define     BAD_KEY_INSTANCE    -3  /* Key passed is not valid */
#define     BAD_CIPHER_MODE     -4  /* Params struct passed to cipherInit invalid */
#define     BAD_CIPHER_STATE    -5  /* Cipher in wrong state (e.g., not initialized) */

/* CHANGE POSSIBLE: inclusion of algorithm specific defines */
/* TWOFISH specific definitions */
#define     MAX_KEY_SIZE        64  /* # of ASCII chars needed to represent a key */
#define     MAX_IV_SIZE         16  /* # of bytes needed to represent an IV */
#define     BAD_INPUT_LEN       -6  /* inputLen not a multiple of block size */
#define     BAD_PARAMS          -7  /* invalid parameters */
#define     BAD_IV_MAT          -8  /* invalid IV text */
#define     BAD_ENDIAN          -9  /* incorrect endianness define */
#define     BAD_ALIGN32         -10 /* incorrect 32-bit alignment */

#define     BLOCK_SIZE          128 /* number of bits per block */
#define     MAX_ROUNDS           16 /* max # rounds (for allocating subkey array) */
#define     ROUNDS_128           16 /* default number of rounds for 128-bit keys*/
#define     ROUNDS_192           16 /* default number of rounds for 192-bit keys*/
#define     ROUNDS_256           16 /* default number of rounds for 256-bit keys*/
#define     MAX_KEY_BITS        256 /* max number of bits of key */
#define     MIN_KEY_BITS        128 /* min number of bits of key (zero pad) */
#define     VALID_SIG    0x48534946 /* initialization signature ('FISH') */
#define     MCT_OUTER           400 /* MCT outer loop */
#define     MCT_INNER         10000 /* MCT inner loop */
#define     REENTRANT             1 /* nonzero forces reentrant code (slightly slower) */

#define     INPUT_WHITEN        0   /* subkey array indices */
#define     OUTPUT_WHITEN       ( INPUT_WHITEN + BLOCK_SIZE/32)
#define     ROUND_SUBKEYS       (OUTPUT_WHITEN + BLOCK_SIZE/32) /* use 2 * (# rounds) */
#define     TOTAL_SUBKEYS       (ROUND_SUBKEYS + 2*MAX_ROUNDS)

typedef uint32_t fullSbox[4][256];

/* The structure for key information */
typedef struct
{
    /* Key used for encrypting or decrypting? */
    uint8_t  direction;                 
#if ALIGN32
    /* keep 32-bit alignment with direction */
    uint8_t  dummyAlign[3];
#endif
    /* Length of the key */
    uint32_t keyLen;
    /* Raw key data in ASCII */
    char     keyMaterial[MAX_KEY_SIZE+4];

    /* Twofish-specific parameters: */
    /* set to VALID_SIG by makeKey() */
    uint32_t keySig;
    /* number of rounds in cipher */
    uint32_t numRounds;
    /* actual key bits, in dwords */
    uint32_t key32[MAX_KEY_BITS/32];
    /* key bits used for S-boxes */
    uint32_t sboxKeys[MAX_KEY_BITS/64];
    /* round subkeys, input/output whitening bits */
    uint32_t subKeys[TOTAL_SUBKEYS];
#if REENTRANT
/* fully expanded S-box */
    fullSbox sBox8x32;
#endif /// of REENTRANT
} keyInstance;

/* The structure for cipher information */
typedef struct
{
    /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
    uint8_t  mode;
#if ALIGN32
    /* keep 32-bit alignment */
    uint8_t  dummyAlign[3];
#endif
    /* CFB1 iv bytes  (CBC uses iv32) */
    uint8_t  IV[MAX_IV_SIZE];

    /* Twofish-specific parameters: */
    /* set to VALID_SIG by cipherInit() */
    uint32_t cipherSig;
    /* CBC IV bytes arranged as dwords */
    uint32_t iv32[BLOCK_SIZE/32];
} cipherInstance;

/* Function protoypes */
void   BuildMDS();
int    makeKey( keyInstance* key, uint8_t direction, size_t keyLen = 0, const char* keyMaterial = NULL );
int    reKey( keyInstance *key );    /// do key schedule using modified key.keyDwords
int    cipherInit( cipherInstance* cipher, uint8_t mode, const char* IV );
int    blockEncrypt( cipherInstance* cipher, keyInstance* key, const uint8_t* input, size_t inputLen, uint8_t* outBuffer );
int    blockDecrypt( cipherInstance* cipher, keyInstance* key, const uint8_t* input, size_t inputLen, uint8_t* outBuffer );

/* API to check table usage, for use in ECB_TBL KAT */
#define     TAB_DISABLE         0
#define     TAB_ENABLE          1
#define     TAB_RESET           2
#define     TAB_QUERY           3
#define     TAB_MIN_QUERY       50

int TableOp(int op);

/* optimize block copies */
#if (BLOCK_SIZE == 128)
    #define     Copy1(d,s,N)    ((uint32_t*)(d))[N] = ((uint32_t*)(s))[N]
    #define     BlockCopy(d,s)  { Copy1(d,s,0);Copy1(d,s,1);Copy1(d,s,2);Copy1(d,s,3); }
#else
    #define     BlockCopy(d,s)  { memcpy(d,s,BLOCK_SIZE/8); }
#endif

#endif /// of __TFISH_H__
