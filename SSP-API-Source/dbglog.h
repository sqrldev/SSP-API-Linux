
// dbglog.h

#ifndef DBGLOG_H
#define DBGLOG_H

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sqtypes.h"

// For debugging
extern FILE *pLogFile;
extern SQ_BOOL bCounterReset;

SQ_RCODE ReadDebugFilter();
SQ_RCODE CheckDebugFilter(char *pFunctionName);
void Lprintf(const char *pFormat, ...);
void Beg(char *pFunctionName, char *pFile, int Line);
void End(char *pFile, int Line);
void Log(const char *pFormat, ...);

// These functions are set up as macros so they can be
// completely eliminated from the code when not debugging.

#ifndef DBG_LOG
#define BEG(S)
#define END(S)
#define LOG(A, ...)
#endif

#ifndef BEG
 #define BEG(S) Beg(S, __FILE__, __LINE__)
#endif
#ifndef END
 #define END() End(__FILE__, __LINE__)
#endif
#ifndef LOG
 #define LOG(A, ...) Log(A, ##__VA_ARGS__)
#endif

#endif
