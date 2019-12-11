
// sspapi.c api shared library interface

#include "global.h"

SQ_CHAR *SSP_Ping() {
	BEG("SSP_Ping()");
	END();
	return "Ping!\r\n";
}
	
SQ_RCODE SSP_ResetCounter() {
	BEG("SSP_ResetCounter()");
	SQ_RCODE rc=SetCfgItem(CFG_MONOTONIC_COUNTER, "0000000000000000");
	bCounterReset=SQ_TRUE;
	END();
	return rc;
}	
SQ_RCODE SSP_InitSqrlCfgData() {
	BEG("SSP_InitSqrlCfgData()");
	SQ_RCODE rc=InitSqrlCfgData();
	END();
	return rc;
}
SQ_RCODE SSP_InitSqrlSystem() {
	BEG("SSP_InitSqrlSystem()");
	SQ_RCODE rc=InitSqrlSystem();
	END();
	return rc;
}
SQ_RCODE SSP_InitSqrlHandler() {
	BEG("SSP_InitSqrlHandler()");
	SQ_RCODE rc=InitSqrlHandler();
	END();
	return rc;
}
SQ_RCODE SSP_ShutDownSqrlSystem() {
	BEG("SSP_ShutDownSqrlSystem()");
	SQ_RCODE rc=ShutDownSqrlSystem();
	END();
	return rc;
}

void SSP_InitResponse(SQRL_RESPONSE *pResponse) {
	BEG("InitResponse()");
	pResponse->pszHeaders=NULL;
	pResponse->pData=NULL;
	pResponse->DataLen=0;
	END();
}
void SSP_FreeResponse(SQRL_RESPONSE *pResponse) {
	BEG("FreeResponse()");
	GlobalFree((void **)&pResponse->pszHeaders);
	GlobalFree((void **)&pResponse->pData);
	SSP_InitResponse(pResponse);
	END();
}
void SSP_SendRequest(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("SSP_SendRequest()");
	LOG("     Method: %s", pSCB->lpszMethod);
	LOG("  Path Info: %s", pSCB->lpszPathInfo);
	LOG("QueryString: %s", pSCB->lpszQueryString);
	HttpExtensionProc(pSCB);
	END();
}

//[
void SQ_RevertToSelf() {
	BEG("RevertToSelf()");
	LOG("Stub");
	// Implement as required
	END();
}
//]

/*	
===============================================================================
	HTTP EXTENSION PROC
------------------------------------------------------------------------------
	This receives, sanity checks, and appropriately routes to the appropriate
	sub-handler all invocations of this handler of the form "/xxx.sqrl?..."
-------------------------------------------------------------------------------
*/
void HttpExtensionProc (SQRL_CONTROL_BLOCK *pSCB) {
//[
LOG("");
LOG("****************************************************************");
LOG("****************************************************************");
LOG("");
//]]
	BEG("HttpExtensionProc()");
do {
	SQ_RevertToSelf();
	
	if(SqrlApiRunning==SQ_FALSE) {
		break;
	}

	char *pMethod=pSCB->lpszMethod;
	if(pMethod==NULL) {
		Return404NotFound(pSCB);
		break;
	}
	// Convert to lower case and return if not GET or POST 
	// (note this converts the null after GET to a space)
	SQ_DWORD Method=*(SQ_DWORD *)pMethod | 0x20202020;
	if((Method!=*(SQ_DWORD *)"get ") && (Method!=*(SQ_DWORD *)"post")) {
		Return404NotFound(pSCB);
		break;
	}

	// Parse the Path Info
	// format: "/xxx.sqrl" (9 characters)
	
	char *pPathInfo=pSCB->lpszPathInfo;
	if(strlen(pPathInfo)!=PATH_INFO_LEN){
		Return404NotFound(pSCB);
		break;
	}

	// Make a copy so we can convert to lowercase
	char aPathInfo[PATH_INFO_LEN];
	for(int i=0; i<PATH_INFO_LEN; i++) aPathInfo[i]=tolower(pPathInfo[i]);
	
	// Make sure, after five chars, it ends in "sqrl"
	if(*(SQ_DWORD *)&aPathInfo[5]!=*(SQ_DWORD *)"sqrl") {
		Return404NotFound(pSCB);
		break;
	}

	SQ_DWORD ObjectName=*(SQ_DWORD *)&aPathInfo[1];
	
	//======================< BROWSER QUERIES >======================
	
	if(ObjectName==*(SQ_DWORD *)"nut.") GetSessionNut(pSCB); else
	if(ObjectName==*(SQ_DWORD *)"png.") GetQRcode(pSCB); else
	if(ObjectName==*(SQ_DWORD *)"pag.") GetNextPage(pSCB); 	else

//[
//. For development
	if(ObjectName==*(SQ_DWORD *)"sup.") ListSupersededIDs(pSCB); else
	if(ObjectName==*(SQ_DWORD *)"pnd.") ListPendingAuths(pSCB); else
	if(ObjectName==*(SQ_DWORD *)"bdb.") ListDatabase(pSCB); else
//]	
	//=====================< SQRL CLIENT QUERY >=====================

	if(ObjectName==*(SQ_DWORD *)"cli." &&  Method==*(SQ_DWORD *)"post") {
		HandleClientQuery(pSCB);
	}

	//=====================< WEBSERVER QUERIES >=====================

	else {
		if(VerifyPrivateQuery(pSCB)==SQ_FAIL){
			Return404NotFound(pSCB);
			break;
		}

		if(ObjectName==*(SQ_DWORD *)"cps.") SubmitCpsAuth(pSCB); else
		if(ObjectName==*(SQ_DWORD *)"add.") AddAssociation(pSCB); else
		if(ObjectName==*(SQ_DWORD *)"rem.") RemoveAssociation(pSCB); else
		if(ObjectName==*(SQ_DWORD *)"lst.") ListAssociations(pSCB); else
		if(ObjectName==*(SQ_DWORD *)"inv.") InviteAssociation(pSCB); else
//[
//. For development (or perhaps added to the api)
		if(ObjectName==*(SQ_DWORD *)"acc.") AcceptInvitation(pSCB); else
//]
		Return404NotFound(pSCB);
		break;
	}
}
while(0); // once

//[
LOG("");
LOG("****************************************************************");
LOG("****************************************************************");
LOG("");
//]]
	END();
}

/*
===============================================================================
	GET URL ENCODED REFERRER
-------------------------------------------------------------------------------
	The browser's SQRL CPS HREF link needs to have a 'can=' cancel term which will
	be the page which initiates the SQRL authentication. We capture the "REFERER"
	header value when the browser requests /nut.sqrl and we (a) return it in the
	query response and (b) use to generate the HMAC to verify the client's query.
===============================================================================
*/
void GetUrlEncodedReferrer(SQ_CHAR *pszEncodedPageURL, SQ_DWORD EncBufLen, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("GetUrlEncodedReferrer()");
	
	int siz=0;
	if(pSCB->lpszHttpReferrer !=NULL) {
		siz=SqrlCvrtToBase64(pszEncodedPageURL, EncBufLen, (SQ_BYTE *)pSCB->lpszHttpReferrer, strlen(pSCB->lpszHttpReferrer));
	}
	pszEncodedPageURL[siz]='\0';
	
	LOG("PageReferrer: %s", pSCB->lpszHttpReferrer);
	LOG("EncodedPageURL: %s", pszEncodedPageURL);
	END();
}

/*				
===============================================================================
	INIT SQRL SYSTEM API
-------------------------------------------------------------------------------
	This is called once on startup.
===============================================================================
*/

SQ_RCODE InitSqrlSystem() {
	BEG("InitSqrlSystem()");
	SQ_RCODE rc=SQ_PASS;
	remove("SSPAPI.log");
	SqrlApiRunning=SQ_TRUE;

//[ for development
// We need this because the BEG, END and LOG macros use global variables
rc|=InitializeCriticalSection(&DebugCriticalSection);
//]
	rc|=InitializeCriticalSection(&IncDataCriticalSection);
	rc|=CreateQueue(&PendingAuthsQueue);
	rc|=OpenSqrlDatabaseFiles();
	
	// If any initialization failed rc will be SQ_FAIL
	END();
	return rc;
}

/*
===============================================================================
	SHUTDOWN SQRL SYSTEM API
	This performs any graceful shutdown work required.
===============================================================================
*/
SQ_RCODE ShutDownSqrlSystem() {
	BEG("ShutdownSqrlSystem()");
	SQ_RCODE rc=SQ_PASS;
	
	//	Clear our 'running' flag to terminate async's
	SqrlApiRunning=SQ_FALSE;

	rc|=DeleteCriticalSection(&IncDataCriticalSection);
	rc|=DeleteQueue(&PendingAuthsQueue, (SQ_PROCPTR)DeletePendingAuthAllocs);
	rc|=CloseBerkeleyDBs();
	
	END();
	#ifdef LOGFILE
	if(pLogFile!=NULL) fclose(pLogFile);
	#endif
	return rc;
}
