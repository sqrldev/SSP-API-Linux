
#ifndef SQTYPES_H
#define SQTYPES_H

#include <stdint.h>

typedef void		SQ_VOID;
typedef char		SQ_CHAR;
typedef uint8_t		SQ_BYTE;
typedef uint16_t	SQ_WORD;
typedef uint32_t	SQ_DWORD;
typedef uint64_t	SQ_QWORD;

typedef void(*SQ_PROCPTR)(void *);

typedef enum SQ_BOOL_T{
	SQ_TRUE		=	(1==1),
	SQ_FALSE	=	!SQ_TRUE
} SQ_BOOL;

typedef enum SQ_RCODE_T{
	SQ_PASS 	=	0,
	SQ_FAIL 	=	~SQ_PASS
} SQ_RCODE;

typedef struct SQRL_RESPONSE_T {
	SQ_CHAR *pszHeaders;
	SQ_BYTE *pData;
	SQ_DWORD DataLen;
} SQRL_RESPONSE;

typedef struct SQRL_CONTROL_BLOCK_T {
	SQ_CHAR *lpszMethod;
	SQ_CHAR *lpszPathInfo;
	SQ_CHAR *lpszQueryString;
	SQ_DWORD DataLen;
	SQ_CHAR *lpData;
	SQ_CHAR *lpszHttpHost;
	SQ_CHAR *lpszHttpReferrer;
	SQ_CHAR *lpszRemoteAddr;
	const char *lpszHttpOrigin;
	SQ_CHAR szServerPort[5+1]; // max "65535"

	SQ_VOID *lpHandlerStruct;
	SQRL_RESPONSE *pResponse;
} SQRL_CONTROL_BLOCK;

#endif
