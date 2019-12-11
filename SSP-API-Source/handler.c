
// handler.c

#include "global.h"

SQ_RCODE InitSqrlHandler() {
	switch(nHandlerName) {
		case SQ_OPENSSL:
		return InitSqrlHandlerOpenSSL();
		
		case SQ_MBEDTLS:
		return InitSqrlHandlerMBedTLS();

		default:
		// no handler
		return SQ_PASS;
	}
}

SQ_RCODE WriteResponseHeaders(SQRL_CONTROL_BLOCK *pSCB, HTTP_STATUS Status, SQ_CHAR *pszHeaders, SQ_DWORD DataLen) {
	BEG("WriteResponseHeaders()");
	LOG("Status: %s", HttpStatusLookup[Status].pStatus);
	LOG("Headers:");
	LOG("Beg...");
//[
	char *pTmp=strcpy(malloc(strlen(pszHeaders)+1), pszHeaders);
	char *token=strtok(pTmp, "\r\n");
	while(token!=NULL) {
		LOG("%s", token);
		token=strtok(NULL, "\r\n");
	}
	free(pTmp);
//]
	LOG("...End");

	enum {BufSiz=64};
	char szPreBuffer[BufSiz];
	char szPostBuffer[BufSiz];
	
	int len=0;
	
	len+=sprintf(szPreBuffer, "HTTP/1.0 %s\r\n", HttpStatusLookup[Status].pStatus);
	len+=strlen(pszHeaders);
	len+=sprintf(szPostBuffer, "content-length: %d\r\n\r\n", DataLen);
	
	if(pSCB->pResponse!=NULL) {
		// Return the headers
		pSCB->pResponse->pszHeaders=GlobalAlloc(len+1);
		sprintf(pSCB->pResponse->pszHeaders, "%s%s%s", szPreBuffer, pszHeaders, szPostBuffer);
	}
	else {
#if defined NO_HANDLER
		LOG("NO_HANDLER is #defined");
#else
		// Save the headers for WriteClient()
		char aDummyBuffer[1024];
		char *pszHandlerHeaders;
		switch(nHandlerName) {
			case SQ_OPENSSL:
			pszHandlerHeaders=GetHeadersBufferOpenSSL(pSCB);
			break;
			
			case SQ_MBEDTLS:
			pszHandlerHeaders=GetHeadersBufferMBedTLS(pSCB);
			break;
			
			default:
			pszHandlerHeaders=aDummyBuffer;
			break;
		}
		sprintf(pszHandlerHeaders, "%s%s%s", szPreBuffer, pszHeaders, szPostBuffer);
#endif
	}
	END();
	return SQ_PASS;	
}

SQ_RCODE WriteClient(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pData, SQ_DWORD *pDataLen) {
	switch(nHandlerName) {
		case SQ_OPENSSL:
		return WriteClientOpenSSL(pSCB, pData, pDataLen);
			
		case SQ_MBEDTLS:
		return WriteClientMBedTLS(pSCB, pData, pDataLen);
			
		default:
		return SQ_PASS;
		}
}

SQ_RCODE ProcessHeaders(SQRL_CONTROL_BLOCK *pSCB, char *pHeaders) {
	BEG("ProcessHeaders()");
	// Each header ends in \r\n.
	// strtok() null-terminates each token at the delimiter
	char *pToken=strtok(pHeaders, "\r\n");
	while(pToken !=NULL ) {
		printf(" %s\r\n", pToken);
		
		// Extract the Headers we are interested in
		char *pName;
		int len;
		pName="Host: "; len=strlen(pName);
		if(memcmp(pToken, pName, len)==0) {
			pSCB->lpszHttpHost=pToken+len;
		}
		pName="Referer: "; len=strlen(pName);
		if(memcmp(pToken, pName, len)==0) {
			pSCB->lpszHttpReferrer=pToken+len;
		}
		pName="Origin: "; len=strlen(pName);
		if(memcmp(pToken, pName, len)==0) {
			pSCB->lpszHttpOrigin=pToken+len;
		}
		pToken=strtok(NULL, "\r\n");
	}
	END();
	return SQ_PASS;
}
