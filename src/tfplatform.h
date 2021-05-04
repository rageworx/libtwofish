#ifndef __TFPLATFORM_H__
#define __TFPLATFORM_H__
/***************************************************************************
    
    tfplatform.h
  ------------------------------------------------------------------------  
    Platform-specific defines for TWOFISH code

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
        *   Tab size is set to 4 characters in this file

***************************************************************************/

/* use intrinsic rotate if possible */
#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#if (0) && defined(__BORLANDC__) && (__BORLANDC__ >= 0x462)
    #error "!!!This does not work for some reason!!!"
    /* get prototype for _lrotl() , _lrotr() */
    #include    <stdlib.h>
    #pragma inline __lrotl__
    #pragma inline __lrotr__
    /* get rid of inefficient definitions */
    #undef  ROL
    #undef  ROR
    /* use compiler intrinsic rotations */
    #define ROL(x,n)    __lrotl__(x,n)
    #define ROR(x,n)    __lrotr__(x,n)
#endif

#ifdef _MSC_VER /// Oh, MSVC ?
    /* get prototypes for rotation functions */
    #include    <stdlib.h>                  
    #undef  ROL
    #undef  ROR
    /* use intrinsic compiler rotations */
    #pragma intrinsic(_lrotl,_lrotr)
    #define ROL(x,n)    _lrotl(x,n)         
    #define ROR(x,n)    _lrotr(x,n)
#endif

#if defined(_WIN32)
    // windows machines are every little-endian
    #define LittleEndian        1
#elif defined(__linux__)
    #define LittleEndian        1
#elif defined(__APPLE__)
    #if defined(__BIG_ENDIAN__)
        #define LittleEndian    0
    #else
        // nodern Apple machines are little-endian
        #define LittleEndian    1
    #endif 
#else
    // Other platforms determine to little-endian.
    #define LittleEndian        1
#endif 

#ifndef _M_IX86
    #ifdef  __BORLANDC__
        /* make sure this is defined for Intel CPUs */
        #define _M_IX86                 300
    #endif
#endif

/* Do alignment for 4bytes, modern C++ compilers may 4 bytes alignment */
#define     ALIGN32             1

#if LittleEndian
    /* NOP for little-endian machines */
    #define     Bswap(x)        (x)
    /* NOP for little-endian machines */
    #define     ADDR_XOR        0
#else
    #define     Bswap(x)        ((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
    /* convert byte address in dword */
    #define     ADDR_XOR        3
#endif

/*  Macros for extracting bytes from dwords (correct for endianness) */
/* pick bytes out of a dword */
#define _b(x,N) (((uint8_t *)&x)[((N) & 3) ^ ADDR_XOR]) 

/* extract LSB of DWORD */
#define     b0(x)           _b(x,0)
#define     b1(x)           _b(x,1)
#define     b2(x)           _b(x,2)
#define     b3(x)           _b(x,3)
/* extract MSB of DWORD */

#endif /// of __TFPLATFORM_H__