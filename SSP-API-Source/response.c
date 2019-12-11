
// response.c

#include "global.h"

/*
===============================================================================
	SEND SQRL REPLY				     
-------------------------------------------------------------------------------
	This formats and sends a Sqrl Query reply to the requesting SQRL Client   
-------------------------------------------------------------------------------
*/
SQ_RCODE SendSqrlReply(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pReplyData, SQ_DWORD ReplyLength, SQ_RCODE Success) {
	BEG("SendSqrlReply()");
	SQ_RCODE rc=SQ_PASS;
	SQ_CHAR szSqrlHeaders[2048];

	sprintf(szSqrlHeaders, pszHttpReplyHeaderFormat, szPublicAuthDomain);
	
	if(pReplyData==NULL || ReplyLength==0) {
		pReplyData=(SQ_BYTE *)"";
		ReplyLength=0;
	}
	HTTP_STATUS Status=(Success==SQ_PASS? HTTP_OK: HTTP_BAD_REQUEST);
	WriteResponseHeaders(pSCB, Status, szSqrlHeaders, ReplyLength);
	rc=WriteToClient(pSCB, pReplyData, ReplyLength);

	END();
	return rc;
}

/*
===============================================================================
	RETURN STRING TO CALLER
===============================================================================
*/
SQ_RCODE ReturnStringToCaller(SQ_CHAR *pszResponseString, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ReturnStringToCaller()");
	SQ_RCODE rc=SQ_PASS;

	LOG("pszResponseString: %s", pszResponseString);
	
	// Send the http response back
	SQ_DWORD ResponseLength;
	ResponseLength=strlen(pszResponseString);

	SQ_CHAR szHeaders[1024];
	sprintf(szHeaders, pszHttpResponseHeaderFormat, szPublicAuthDomain);
	LOG("[]", szHeaders, strlen(szHeaders));

	WriteResponseHeaders(pSCB, HTTP_OK, szHeaders, ResponseLength);
	rc=WriteClient(pSCB, (SQ_BYTE *)pszResponseString, &ResponseLength);
	
	END();
	return rc;
}

/*
============================================================================
	RETURN IMAGE TO CLIENT (SEND CHART IMAGE)
----------------------------------------------------------------------------
*/
SQ_RCODE ReturnImageToClient (SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pImageData, SQ_DWORD ImageLength) {
	BEG("ReturnImageToClient()");
	SQ_RCODE rc=SQ_PASS;

	SQ_CHAR szImageHeaders[1024];

	sprintf(szImageHeaders, pszHttpImageHeaderFormat, szPublicAuthDomain);
	LOG("[c]", szImageHeaders, strlen(szImageHeaders));
	
	WriteResponseHeaders(pSCB, HTTP_OK, szImageHeaders, ImageLength);
	rc=WriteToClient(pSCB, pImageData, ImageLength);

	END();
	return rc;
}

/*
============================================================================
	WRITE TO CLIENT
	Note: WriteResponseHeaders() is issued by the caller
----------------------------------------------------------------------------
*/
SQ_RCODE WriteToClient(SQRL_CONTROL_BLOCK* pSCB, SQ_BYTE *pBuffer, SQ_DWORD OptionalLength) {
	BEG("WriteToClient()");
	SQ_RCODE rc=SQ_PASS;

	SQ_DWORD BytesToWrite;
	
	if(OptionalLength>0) {
		BytesToWrite=OptionalLength;
	}
	else {
		BytesToWrite=strlen((char *)pBuffer);
	}
	rc=WriteClient(pSCB, pBuffer, &BytesToWrite);

	END();
	return rc;
}

/*
===============================================================================
	RETURN 404 NOT FOUND
===============================================================================
*/
SQ_RCODE Return404NotFound(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("Return404Notfound()");
	SQ_RCODE rc=SQ_PASS;
	SQ_CHAR szHeaders[2048];

	// now we send out our response headers including a cookie...
//. what cookie?
	sprintf(szHeaders, pszHttpResponseHeaderFormat, szPublicAuthDomain);
	SQ_CHAR *pBuffer=HttpStatusLookup[HTTP_NOT_FOUND].pStatus;
	SQ_DWORD Length=strlen(pBuffer);

	WriteResponseHeaders(pSCB, HTTP_NOT_FOUND, szHeaders, Length);
	rc=WriteClient(pSCB, (SQ_BYTE *)pBuffer, &Length);

	END();
	return rc;
}
/*
===============================================================================
	RETURN 410 GONE
===============================================================================
*/
SQ_RCODE Return410Gone(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("Return410Gone()");
	SQ_RCODE rc=SQ_PASS;
	SQ_CHAR szHeaders[2048];

	// now we send out our response headers including a cookie...
//. what cookie?
	sprintf(szHeaders, pszHttpResponseHeaderFormat, szPublicAuthDomain);
	SQ_CHAR *pBuffer=HttpStatusLookup[HTTP_GONE].pStatus;
	SQ_DWORD Length=strlen(pBuffer);

	WriteResponseHeaders(pSCB, HTTP_GONE, szHeaders, Length);
	rc=WriteClient(pSCB, (SQ_BYTE *)pBuffer, &Length);

	END();
	return rc;
}
