
// browser.c - API for Web Browser to SSP Server

/*
via HTTPS GET

/nut.sqrl
/png.sqrl?{ 12-char nut }
/pag.sqrl?{ 12-char nut }
*/ 

#include "global.h"

/*
===============================================================================
	GET STRING IN GLOBAL ALLOC
	in:  pString
	ret: 
===============================================================================
*/
SQ_CHAR *GetStringInGlobalAlloc(SQ_CHAR *pString) {
	// get the string's length
	// allocate a buffer for it
	// copy the string into the alloc
	// return the buffer pointer (our alloc)
	return strcpy((SQ_CHAR *)GlobalAlloc(strlen(pString)+1), pString);
}
/*
===============================================================================
	GetQueryParamNut
	in: pSCB->lpszQueryString
	out: pszNutBuffer
-------------------------------------------------------------------------------
The QueryString looks like "nut=<12 character base64url encoded nut>..."
We extract and return "<12 character base64url encoded nut>"
szNutEquals is "nut="
SQRL_NUT_LEN is 12
*/
void GetQueryParamNut(SQ_CHAR *pszNutBuffer, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("GetQueryParamNut()");

	pszNutBuffer[0]='\0';

	if(pSCB->lpszQueryString==NULL) {
		END();
		return;
	}

	int nPrefixLen=strlen(pszNutEquals); // 4
	
	if(strlen(pSCB->lpszQueryString)<SQRL_NUT_LEN+nPrefixLen) {
		END();
		return;
	}

	SQ_CHAR *ptr=strstr(pSCB->lpszQueryString, pszNutEquals);
	if(ptr==NULL) {
		END();
		return;
	}

	SQ_CHAR *pNut=&ptr[nPrefixLen];
	if(strlen(pNut)>=SQRL_NUT_LEN){
		memcpy(pszNutBuffer, pNut, SQRL_NUT_LEN);
		pszNutBuffer[SQRL_NUT_LEN]='\0';
	}
//[
LOG("pszNutBuffer: %s", pszNutBuffer);
//]
	END();
}

/*
===============================================================================
	SET LOGIN PAGE URL
	in: pSCB
	out: pPendingAuth->pszLoginPageURL
===============================================================================
*/
void SetLoginPageUrl(PENDING_AUTHS *pPendingAuth, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("SetLoginPageUrl()");
	SQ_CHAR szEncodedReferrer[2048];

	// Encode the referrer to base 64 url
	GetUrlEncodedReferrer(szEncodedReferrer, sizeof(szEncodedReferrer), pSCB);
	
	// Has the login page not been registered or has it changed?
	if(pPendingAuth->pszLoginPageURL==NULL || 
		strcmp(szEncodedReferrer, pPendingAuth->pszLoginPageURL)!=0) {

		// release any previous alloc
		GlobalFree((void **)&pPendingAuth->pszLoginPageURL);
		
		// assign the new alloc
		pPendingAuth->pszLoginPageURL=GetStringInGlobalAlloc(szEncodedReferrer);
	}

	LOG("pPendingAuth->pszLoginPageURL: %s", pPendingAuth->pszLoginPageURL);
	END();
}

//===============================================================================
//	SET PATH EXTENSION STRING
//===============================================================================
SQ_VOID SetPathExtensionString(SQ_CHAR *pszPathExtension, SQRL_CONTROL_BLOCK *pSCB) {
	// if we had a query, let's check to see whether it begins with a digit
	char *pszQuery=pSCB->lpszQueryString;
	if(pszQuery!=NULL && pszQuery[0]>='1' && pszQuery[0]<='9') {
		// we setup "x=n&" and transpose that digit
		sprintf(pszPathExtension, "%s%c&", pszPathPrefix, pszQuery[0]); 
	}
}

//===============================================================================
//	PREP PENDING AUTH OBJECT
//===============================================================================
PENDING_AUTHS *PrepPendingAuthObject(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("PrepPendingAuthObject()");

	PENDING_AUTHS *pPendingAuth=(PENDING_AUTHS *)GlobalAlloc(sizeof(PENDING_AUTHS));
	pPendingAuth->QueueObject.TimeStamp=GetSystemOneSecondTime();
	
	// get /nut.sqrl?n parameter (if present)
	SetPathExtensionString(pPendingAuth->szPathExtension, pSCB);
	GetUnique12charNut(pPendingAuth->aBrowserNut, SQ_FALSE);
	memcpy(pPendingAuth->aProtocolNut, pPendingAuth->aBrowserNut, SQRL_NUT_LEN);
	
	// Concatenate two 12-char "nuts" to make the CPS nonce
	SQ_CHAR *pHi=&pPendingAuth->aCPSNonce[0];
	GetUnique12charNut(pHi, SQ_FALSE);
	SQ_CHAR *pLo=&pPendingAuth->aCPSNonce[12];
	GetUnique12charNut(pLo, SQ_FALSE);

	ObtainClientConnectionIP(pPendingAuth->aRequestIP, pSCB);
	SetInitialAuthMacs( pPendingAuth, pSCB);
	SetLoginPageUrl(pPendingAuth, pSCB);

	// return our object to our caller
	END();
	return pPendingAuth;
}

/*
===============================================================================
	SUBMIT CPS AUTH
-------------------------------------------------------------------------------
 This query is invoked by a browser redirect to this SQRL service provider in
 response to a successful CPS-style authentication. It carries the secret CPS
 key which the client received from this service to confirm the browser's ID.

		/cps.sqrl?{-SQRL-server-provided-CPS-nonce-}

 This code looks up the pending auth item in the "PendingAuthsQueue" in-memory
 list using the caller's session cookie as its key. It captures ;the browser's
 session cookie and the authenticated SQRL public key from the pending queue,
 then checks to see whether the caller's CPS matches what we expect for this
 authentication. And, in either event, the pending auth is deleted from the
 system. In the event of successful CPS match, we call out to the web server,g
 providing it the browser's now-authenticated session cookie, the SQRL identity
 of the authenticator (which it regards as an opaque token) and the web server
 account identity previously associated with this SQRL identity, if any. The
 web server returns the URL of the page the waiting browser should be referred
 to now that its session is authenticated and its identities are known.
-------------------------------------------------------------------------------
*/
SQ_VOID SubmitCpsAuth(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("SubmitCpsAuth()");
	PENDING_AUTHS AuthedAuth;
	SQ_CHAR *pszLoginPageURL=(char *)pszNull;
	SQRL_ASSOCIATIONS SqrlDB;
	SQ_CHAR szOptionsValue[32];
	SQ_CHAR szResponseString[1024];
	ASSOC_REC_DATA *pAssocRecData=&SqrlDB.AssocRecData;
		
	if(pSCB->lpszQueryString==NULL || strlen(pSCB->lpszQueryString)!=CPS_TOKEN_LEN) {
		// if we failed, return a 404
		Return404NotFound(pSCB);
		END();
		return;
	}
	
	// scan the PendingAuthsQueue looking for our target CPS nonce

LOG("owner: %u", PendingAuthsQueue.CriticalSection.Lock.__data.__owner);
LOG("&Lock: %p", &PendingAuthsQueue.CriticalSection.Lock);

	EnterCriticalSection(&PendingAuthsQueue.CriticalSection);

LOG("owner: %u", PendingAuthsQueue.CriticalSection.Lock.__data.__owner);
LOG("&Lock: %p", &PendingAuthsQueue.CriticalSection.Lock);

	PENDING_AUTHS *pPendingAuth;
	//	AuthedAuth is our authenticated pending auth
	pPendingAuth=LookupByCPS(&AuthedAuth, pSCB->lpszQueryString, /*Update*/SQ_FALSE);
	if(pPendingAuth != NULL) {
		// We found the CPS nonce. Since this CPS query from the hosting
		// server always represents the conclusion of a SQRL authentication,
		// we delete the Pending Auths object from our in-memory queue after
		// getting a local copy.
		if(pPendingAuth->pszLoginPageURL!=NULL) {
			pszLoginPageURL=pPendingAuth->pszLoginPageURL;
		}
		pPendingAuth->pszLoginPageURL=NULL;
		
		DeletePendingAuthObject(pPendingAuth);
		LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);
	}
	else {
		LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);
		Return404NotFound(pSCB); // if we failed, return a 404
		GlobalFree((void **)&pszLoginPageURL);
		END();
		return;
	}
	
	// the hosting web server submitted a query for the auth info using a
	// valid one-time CPS token. So we use the authenticated SqrlUser to
	// lookup any Sqrl association record

	if(GetRecordBySqrlID(&SqrlDB, AuthedAuth.szSqrlPublicKey)!=SQ_PASS) {
		Return404NotFound(pSCB); // if we failed, return a 404
		GlobalFree((void **)&pszLoginPageURL);
		END();
		return;
	}
	// convert the "OptionsValue" param into an szString for (stat=)

	SQ_DWORD OptVal;
	SQ_DWORD *pOptVal;
	szOptionsValue[0]='\0';
	
	OptVal=AuthedAuth.OptionsValue;
	if((OptVal&OPT_SQRLONLY)==OPT_SQRLONLY) {
		strcat(szOptionsValue, pszSqrlOnly);
	}
	if((OptVal&OPT_HARDLOCK)==OPT_HARDLOCK) {
		if(szOptionsValue[0]!='\0') strcat(szOptionsValue, pszComma);
		strcat(szOptionsValue, pszHardLock);
	}
	
	pOptVal=&SqrlDB.AssocRecData.SqrlOptionFlags;
	OptVal=*pOptVal;
	if((OptVal&AUTH_DISABLED)==AUTH_DISABLED) {
		if(szOptionsValue[0]!='\0') strcat(szOptionsValue, pszComma);
		strcat(szOptionsValue, pszDisabled);
	}
	if((OptVal&REMOVE_REQUESTED)==REMOVE_REQUESTED) {
		if(szOptionsValue[0]!='\0') strcat(szOptionsValue, pszComma);
		strcat(szOptionsValue, pszRemove);
		// we only report the deletion command once. so we turn
		// the bit off and save the update after reporting it once
		*pOptVal&=(!REMOVE_REQUESTED);
		StoreSqrlRecord(&SqrlDB);	
	}
	if((OptVal&USER_REKEYED)==USER_REKEYED) {
		if(szOptionsValue[0]!='\0') strcat(szOptionsValue, pszComma);
		strcat(szOptionsValue, pszRekeyed);
		// we only report the rekeying once. so we turn
		// the bit off and save the update after reporting it once
		*pOptVal&=(!USER_REKEYED);
		StoreSqrlRecord(&SqrlDB);	
	}
	
	// now we form the value of the "SQRL-Auth:" query header
	if(strlen(pAssocRecData->szAccount)>0) {
		sprintf(szResponseString, pszUserIdWithAccount, &SqrlDB.szSqrlUser, &szOptionsValue, pszLoginPageURL, &pAssocRecData->szAccount);
	}
	else {
		// the SQRL ID has not yet been associated with an account,
		// so we return the session and the SQRL ID...
		sprintf(szResponseString, pszUserIdWithNoAccount, &SqrlDB.szSqrlUser, &szOptionsValue, pszLoginPageURL);
	}

	LogTheQueryAndReply(szResponseString, pSCB);
	ReturnStringToCaller(szResponseString, pSCB);

	GlobalFree((void **)&pszLoginPageURL);
	LOG("szResponseString: %s", szResponseString);
	END();
}

/*
===============================================================================
	TRIGGER NON CPS AUTH
-------------------------------------------------------------------------------
 We come here when we have successfully authenticated without CPS. So we need
 to place a URL into the "NextPageURL" which the periodic query for /pag.sqrl
 will pickup and jump the user's browser to. That NextPageURL should be a CPS
 style query which INCLUDES the CPS nonce which only we know. When the browser
 jumps there, will be identical to the browser being redirected from the local
 client for a full CPS auth... so we'll then redirect to the Webserver.
===============================================================================
*/
void TriggerNonCpsAuth(PENDING_AUTHS *pPendingAuth, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("TriggerNonCpsAuth()");
	SQ_CHAR szUrlBuffer[2048];
	
	PlaceCpsUrlIntoBuffer(szUrlBuffer, pPendingAuth);

	// now we place the string into an alloc for use and later release
	GlobalFree((void**)&pPendingAuth->pszNextPageURL);
	pPendingAuth->pszNextPageURL=GetStringInGlobalAlloc(szUrlBuffer);
	
	// the next time the browser JavaScript probes for a next page it will
	// be directed to our /cps.sqrl handler with the proper CPS nonce for
	// the auth... so it will succeed.

	END();
}

/*
===============================================================================
	GET SESSION NUT
-------------------------------------------------------------------------------
	/nut.sqrl
-------------------------------------------------------------------------------
 This query may be invoked by JavaScript running on a site's login/registration
 pages offering SQRL login ==OR== by the hosting server if it wishes to provide
 the NUT directly bound into the provided pages. If page-based JavaScript uses
 an XHR request, the data is then appended to the page's sqrl:// invocation HREF.

 The handler below creates or references an item in the "PendingAuthsQueue"
 in-memory list using the caller's session cookie as its key. If a new item is
 created, a guaranteed unique 12-character nut is also created and associated
 with the caller's session cookie. And in any event, we receive that 12-char
 nut and base64url-encoded cancellation URL... which we return to our caller.
-------------------------------------------------------------------------------
	{12-char-nut}&can={-base64url-}
-------------------------------------------------------------------------------
*/
SQ_VOID GetSessionNut(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("GetSessionNut()");
	SQ_BYTE	szNutBuffer[16];
	SQ_CHAR szEncodedReferrer[2048];
	SQ_CHAR	szQueryReply[2048];
	SQ_CHAR *pszPathExt;
	
	// create a new Pending Auth object with a new Browser Nut for queries

	PENDING_AUTHS *pPendingAuth=PrepPendingAuthObject(pSCB);

	Enqueue(&PendingAuthsQueue, (QUEUE_OBJECT *)pPendingAuth);

	// create a null-terminated version of the 12-char nut for output
	memcpy(szNutBuffer, pPendingAuth->aBrowserNut, SQRL_NUT_LEN);
	szNutBuffer[SQRL_NUT_LEN]='\0';
//[
LOG("szNutBuffer: %s", szNutBuffer);
//]
	pszPathExt=pPendingAuth->szPathExtension;

	// Set our 'can={--}' value to the page referrer
	GetUrlEncodedReferrer(szEncodedReferrer, sizeof(szEncodedReferrer), pSCB);
//[
LOG("szEncodedReferrer: %s", szEncodedReferrer);
//]
	sprintf(szQueryReply, pszNutAndCanLinkFormat, pszPathExt, szNutBuffer, szEncodedReferrer);

	ReturnStringToCaller(szQueryReply, pSCB);
	LogTheQueryAndReply(szQueryReply, pSCB);
	
//[
LOG("PA.QueueObject.TimeStamp: %u", pPendingAuth->QueueObject.TimeStamp);
LOG("szQueryReply: %s", szQueryReply);
//]

	END();
}

/*
===============================================================================
	GET QR CODE
-------------------------------------------------------------------------------
 This query is invoked by a site's login/registration pages which display a
 SQRL QR code:
	/png.sqrl?nut={12-char Nut}&can={encoded cancel}

 This code references or creates an item in the "PendingAuthsQueue" in-memory
 list using the caller's session cookie as its key. If a new item is created,
 a guaranteed unique 12-character nut is also created and associated with the
 caller's session cookie. And in any event, we receive that 12-character nut
 in response to the call to "InitPendingAuthAndReturnNut" which we combine
 into a SQRL query of the form:

	sqrl://{hostname}/sqrl?nut=abcdefghijkl

 ...which is encoded into a standard QR code image and returned to our caller.
-------------------------------------------------------------------------------
*/

SQ_VOID GetQRcode(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("GetQRcode()");
	SQ_CHAR szNutBuffer[16];
	SQ_CHAR szQRdata[512];
	SQ_CHAR *pszPathExt;
	
	GetQueryParamNut(szNutBuffer, pSCB);

	// now we lock the queue and find our pending auth object by its nut
	EnterCriticalSection(&PendingAuthsQueue.CriticalSection);
	PENDING_AUTHS *pPendingAuth=LookupByNut(NULL, szNutBuffer, /*UpdateObject=*/SQ_FALSE, /*ProtocolNut=*/SQ_FALSE, pSCB);
	
	// we want to grab this pending auth's path extension value
	pszPathExt=(char *)pszNull;
	if(pPendingAuth!=NULL) {
		pszPathExt=pPendingAuth->szPathExtension;
	}

	// and quickly unlock the pending auths queue
	LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);

	// now we obtain the Hostname our caller used for this query
	// so we can embed it into the QR code we're going to display
	// now we form our QR code string using: 'sqrl://%s/sqrl?%snut=%s'

//[
// To Do !
//. check if lpszHttpHost is NULL and return HSE_STATUS_ERROR if it is (can it be?)
//]
	sprintf(szQRdata, pszQRcodeFormat, pSCB->lpszHttpHost, pszPathExt, szNutBuffer);

	// and this final string is bound into a QR code image and returned
	SendStringAsQRcodeImage(pSCB, szQRdata);

	// log our return of a PNG image
	LogTheQueryAndReply(szQRdata, pSCB);
	END();
}

/*
===============================================================================
	GET NEXT PAGE
-------------------------------------------------------------------------------
 This query is invoked by JavaScript running on a site's login/registration
 pages offering SQRL login. The JavaScript uses an AJAX-style XMLHttpRequest
 to request the URL of the page, if any, that it should change to:

	/pag.sqrl?nut={12-char Nut}&can={encoded cancel}

 This code looks up an item in the "PendingAuthsQueue" in-memory list using the
 caller's session cookie as its key. If a matching item is found which also
 contains a non-null 'pszNextPageURL' this signifies that the authentication
 succeeded and is providing the caller with its next page. So the pending auth
 object is deleted from the system and the URL is returned to the caller.
-------------------------------------------------------------------------------
*/

SQ_VOID GetNextPage(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("GetNextPage()");
	SQ_CHAR szNutBuffer[16];

	GetQueryParamNut(szNutBuffer, pSCB);
	
	// now we lock the queue and find our pending auth object by its nut
	EnterCriticalSection(&PendingAuthsQueue.CriticalSection);
	
	PENDING_AUTHS *pPendingAuth=LookupByNut(NULL, szNutBuffer, /*UpdateObject=*/SQ_FALSE, /*ProtocolNut=*/SQ_FALSE, pSCB);

	if(pPendingAuth==NULL) {
		// if this is a query for a non-existant nut, it's NEVER going
		// to be found. So we release the lock and return a "410 GONE"
		// HTTP status. The querying page can then refresh itself to
		// obtain a new nut
		LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);
		Return410Gone(pSCB);
		
		END();
		return;
	}

	// we found the matching nut. so let's check to see whether a next page
	// for us to jump to has been registered?  since we will ALWAYS release
	// this alloc if it's NOT zero (see below) we need to show that it is
	// no longer allocated, so we get it and ZERO it at the same time

	SQ_CHAR *pNextPageURL=pPendingAuth->pszNextPageURL;
	pPendingAuth->pszNextPageURL=NULL;
		
	// we also take this occasion to update the szLoginPageURL
	// so that when we DO jump, we'll be jumping to the latest.
	SetLoginPageUrl(pPendingAuth, pSCB);

	// and now we can unlock the pending auths queue
	LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);

	// now we either direct the caller to the registered page, or return a
	// 404 Not Found if we either have NO pending auth or NO registered page.
//[
LOG("pNextPageURL: %p %s", pNextPageURL, pNextPageURL);
//]
	if(pNextPageURL!=NULL) {
		LogTheQueryAndReply(pNextPageURL, pSCB);
		ReturnStringToCaller(pNextPageURL, pSCB);
		GlobalFree((void **)&pNextPageURL);
	}
	else {
		Return404NotFound(pSCB);
	}

	END();
}

SQ_RCODE ListSupersededIDs(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ListSupersededIDs");
	char *pszList=GetSupersededIDs();
	ReturnStringToCaller(pszList, pSCB);
	GlobalFree((void **)&pszList);

	END();
	return SQ_PASS;
}

SQ_RCODE ListPendingAuths(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ListPendingAuths");
	char *pszList=GetPendingAuths();
	ReturnStringToCaller(pszList, pSCB);
	GlobalFree((void **)&pszList);

	END();
	return SQ_PASS;
}

SQ_RCODE ListDatabase(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ListDatabase");

	char *pszList=GetBerkeleyMainDatabase();
	ReturnStringToCaller(pszList, pSCB);
	GlobalFree((void **)&pszList);

	END();
	return SQ_PASS;
}

