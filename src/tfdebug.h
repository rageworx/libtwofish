#ifndef __TFDEBUG_H__
#define __TFDEBUG_H__

#ifdef DEBUG

    #define DebugDump(x,s,R,XOR,doRot,showT,needBswap)  \
        { if (debug) _Dump(x,s,R,XOR,doRot,showT,needBswap,t0,t1); }
    #define DebugDumpKey(key) \
        { if (debug) _DumpKey(key); }

void _Dump( const void*, const char *, int, int, int, int, int, uint32_t, uint32_t );
void _DumpKey( const keyInstance );

#else /// of DEBUG
    
    #define DebugDump(x,s,R,XOR,doRot,showT,needBswap)
    #define DebugDumpKey(key)    

#endif /// of DEBUG
#endif /// of __TFDEBUG_H__