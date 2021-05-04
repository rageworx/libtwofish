#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cstdint>

#include "tfish.h"

/* max # blocks per call in TestTwofish */
#define MAX_BLK_CNT     4       

/* keySize must be 128, 192, or 256 */
int TestTwofish( uint8_t mode, size_t keySize ) 
{   /* return 0 iff test passes */

    /* key information, including tables */
    keyInstance    ki = {0};
    /* keeps mode (ECB, CBC) and IV */    
    cipherInstance ci = {0};
    
    uint8_t plainText[MAX_BLK_CNT*(BLOCK_SIZE/8)] = {0};
    uint8_t cipherText[MAX_BLK_CNT*(BLOCK_SIZE/8)] = {0};
    uint8_t decryptOut[MAX_BLK_CNT*(BLOCK_SIZE/8)] = {0};
    
    uint8_t iv[BLOCK_SIZE/8] = {0};
    size_t  i,byteCnt;

    if ( makeKey( &ki, DIR_ENCRYPT, keySize  ) != TF_SUCCESS )
        return 1;               /* 'dummy' setup for a 128-bit key */
       
    if ( cipherInit( &ci, mode, NULL ) != TF_SUCCESS )
        return 1;               /* 'dummy' setup for cipher */
    
    for (i=0;i<keySize/32;i++)  /* select key bits */
        ki.key32[i]=0x10003 * rand();
        
    reKey(&ki);                 /* run the key schedule */

    /* set up random iv (if needed)*/    
    if ( mode != MODE_ECB )
    {
        for (i=0;i<sizeof(iv);i++)
            iv[i]=(uint8_t) rand();
        
        memcpy(ci.iv32,iv,sizeof(ci.iv32)); /* copy the IV to ci */
    }

    /* select number of bytes to encrypt (multiple of block) */
    /* e.g., byteCnt = 16, 32, 48, 64 */
    byteCnt = (BLOCK_SIZE/8) * (1 + (rand() % MAX_BLK_CNT));

    for (i=0;i<byteCnt;i++)     /* generate test data */
        plainText[i]=(uint8_t) rand()%0xFF;
    
    /* encrypt the bytes */
    if ( blockEncrypt( &ci, &ki, plainText,byteCnt*8,cipherText) != byteCnt*8 )
        return 1;

    /* decrypt the bytes */
    if ( mode != MODE_ECB )       /* first re-init the IV (if needed) */
        memcpy(ci.iv32,iv,sizeof(ci.iv32));

    if ( blockDecrypt( &ci, &ki, cipherText,byteCnt*8,decryptOut) != byteCnt*8 )
        return 1;               
    
    /* make sure the decrypt output matches original plaintext */
    if ( memcmp(plainText,decryptOut,byteCnt) )
        return 1;       

    return 0;                   /* tests passed! */
}

int main( int argc, char** argv )
{
    printf( "TwoFish testing example.\n" );
    fflush( stdout );
    
    srand((unsigned) time(NULL));   /* randomize */

    for ( size_t keySize=128; keySize<=256; keySize+=64 )
    {
        for ( size_t testCnt=0; testCnt<10; testCnt++ )
        {
            if ( TestTwofish( MODE_ECB, keySize ) != 0 )
            { 
                printf("ECB Failure at keySize=%d",keySize); 
                return -1;
            }
            
            if ( TestTwofish( MODE_CBC, keySize ) != 0 )
            { 
                printf("CBC Failure at keySize=%d",keySize); 
                return -1;
            }
        }
    }
    
    printf("Tests passed\n");
    
    return 0;
}