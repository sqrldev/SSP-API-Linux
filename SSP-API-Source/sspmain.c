
// sspmain.c - main() for TEST, HTTP or FUNC interface to SSP-API library

#include <stdio.h>

#include "dbglog.h"
#include "sspapi.h"

#ifdef TEST_INTERFACE
// A minimal libsspapi.so for developing a PHP Extension
int main(int argc, char *argv[]) {
	Log("main() TEST_INTERFACE");
	
	// Just call Ping() to see if we are working
	printf("%s", SSP_Ping());
	printf("\r\n");
}
#endif

#ifdef HTTP_INTERFACE
int main(int argc, char *argv[]) {
	LOG("main() HTTP_INTERFACE");

	int err=0;

//[ For TESTING
	printf("%s", SSP_Ping());
	printf("\r\n");
//	SSP_ResetCounter(); // reset the monotonic counter so we get repeatable nut values
//]
	do {
		// Initializations
		if(SSP_InitSqrlCfgData()!=SQ_PASS) {
			printf("Error: Unable to configure the Sqrl System\r\n");
			err=1;
			break;
		}
		if(SSP_InitSqrlSystem()!=SQ_PASS) {
			printf("Error: Unable to initialize the Sqrl System\r\n");
			err=2;
			break;
		}
		
		// The handler runs until stopped
		if(SSP_InitSqrlHandler()!=SQ_PASS) {
			printf("Error: Unable to initialize the Http Handler Server\r\n");
			err=3;
			break;
		}
		
		// Graceful exit
		if(SSP_ShutDownSqrlSystem()!=SQ_PASS) {
			printf("Error: Unable to shutdown the Sqrl System\r\n");
			err=4;
			break;
		}
	} while(0); // once
	
	return err;
}
#endif

#ifdef FUNC_INTERFACE
void PrintResponse(SQRL_RESPONSE *pR) {
	printf("Resp Headers (%d):\r\n<BEG>%s<END>\r\n", (int)strlen(pR->pszHeaders), pR->pszHeaders); 
	if(pR->DataLen==0) {
		printf("(no data)\r\n");
	}
	else {
		printf("Resp Data (%d):\r\n", pR->DataLen);
		printf("<BEG>");
		
		// Print characters or bytes depending on content
		SQ_BYTE *a=pR->pData;
		int n=pR->DataLen;
		int i;
		for(i=0; i<n; i++) {
			SQ_BYTE z=a[i];
			if(z=='\r' || z=='\n') continue;
			if(z<0x20 || z>0x7f) break;
			}
		if(i<n) {
			// Print bytes
			for(i=0; i<n; i++) {
				printf(" %02x", pR->pData[i]);
			}
		}
		else {
			// Print characters
			for(i=0; i<n; i++) {
				printf("%c", pR->pData[i]);
			}
		}
		printf("<END>\r\n");
	}
}

extern void *GlobalAlloc(SQ_DWORD);
extern void GlobalFree(void **);
extern void DecodeBase64szAndStore(SQ_CHAR **, SQ_CHAR *);
extern void HttpExtensionProc(SQRL_CONTROL_BLOCK *pSCB);

void DecodeResponse(SQRL_RESPONSE *pR) {
	SQ_CHAR *pszServer=GlobalAlloc(pR->DataLen+1);
	memcpy(pszServer, pR->pData, pR->DataLen);
	SQ_CHAR *pszServerDecode;
	DecodeBase64szAndStore(&pszServerDecode, pszServer);
	printf("Server Decode:\r\n%s", pszServerDecode);
	GlobalFree((void **)&pszServer);
	GlobalFree((void **)&pszServerDecode);
}

char *pClientNutQuery="nut=3yUP9OMU0gMA";
char *pClientCmdQuery=
"client=dmVyPTENCmNtZD1xdWVyeQ0KaWRrPXA5MHpQOEhFalFMU056bFI5bDRfUVdPeU1pVTdyMVM2aUdXWGNPblBMUEENCm9wdD1jcHN-c3VrDQo&server=c3FybDovL3Nxcmwuc2VydmVyLmZwZjo4NDQzL2NsaS5zcXJsP251dD0zeVVQOU9NVTBnTUEmY2FuPWFIUjBjSE02THk5M1pXSXVjMlZ5ZG1WeUxtWndaaTl6YVdkdWFXNA&ids=t6EFv8QS_fk3CD_ywTLKaoZuYYh8hLPgBCmpeqhyFQrvEfiCQPq9C1G3eTKKvuiQ0TAdhBf8v--OF5efL_IFBw";

char *pClientNutIdent="nut=e695TAlW96QA";
char *pClientCmdIdent=
"client=dmVyPTENCmNtZD1pZGVudA0KaWRrPXA5MHpQOEhFalFMU056bFI5bDRfUVdPeU1pVTdyMVM2aUdXWGNPblBMUEENCm9wdD1jcHN-c3VrDQo&server=dmVyPTENCm51dD1lNjk1VEFsVzk2UUENCnRpZj01DQpxcnk9L2NsaS5zcXJsP251dD1lNjk1VEFsVzk2UUENCnN1az1BeTZkdkVaUGRITDNEUjhGYngwcWtkM0FwRmVtd29kSFVsQlBmZ1J5Q2hJDQo&ids=CQ040jXDHnvAvAxi9ehl_Z4_TaF036amCoVAXCfwJQcueW0rTVag4o9WZPRmTKjD-V_oMBtQshaEqB_9JPZDBg";

void SetUpSqrlControlBlock(
	SQRL_CONTROL_BLOCK *pSCB,
	char *pszMethod,
	char *pszPathInfo,
	char *pszQueryString,
	int DataLen,
	void *pData,
	char *pszHttpHost,
	char *pszHttpReferrer,
	char *pszRemoteAddr,
	char *pszHttpOrigin,
	char *pszServerPort,
	SQRL_RESPONSE *pResponse
	) {

	pSCB->lpszMethod=pszMethod;
	pSCB->lpszPathInfo=pszPathInfo;
	pSCB->lpszQueryString=pszQueryString;
	pSCB->DataLen=DataLen;
	pSCB->lpData=pData;
	
	pSCB->lpszHttpHost=pszHttpHost; // sqrl.server:8443
	pSCB->lpszHttpReferrer=pszHttpReferrer;
	pSCB->lpszRemoteAddr=pszRemoteAddr;
	pSCB->lpszHttpOrigin=pszHttpOrigin;
	strcpy(pSCB->szServerPort, pszServerPort); //"8443");
	pSCB->lpHandlerStruct=NULL;
	pSCB->pResponse=pResponse;

printf("\r\n");
printf("*** Method: %s\r\n", pSCB->lpszMethod);
printf("*** PthInf: %s\r\n", pSCB->lpszPathInfo);

}

int main(int argc, char *argv[]) {
	LOG("main() FUNC_INTERFACE");

//[ For TESTING
	printf("%s", SSP_Ping());
	printf("\r\n");
//	SSP_ResetCounter(); // reset the monotonic counter so we get repeatable nut values
//]
	// Initializations
	if(SSP_InitSqrlCfgData()!=SQ_PASS) {
		printf("Error: Unable to configure the Sqrl System\r\n");
		return 1;
	}
	if(SSP_InitSqrlSystem()!=SQ_PASS) {
		printf("Error: Unable to initialize the Sqrl System\r\n");
		return 2;
	}

	// Simulate HTTP Queries
	enum {NutEqLen=strlen("nut=")+strlen("nutnutnutnut")};
	char szNutEq[NutEqLen+1];
//	char aPostData[1024];
	SQRL_CONTROL_BLOCK scb;
	SQRL_RESPONSE rsp;
	
	// Get Nut
	SetUpSqrlControlBlock(
		&scb,
		"GET",
		"/nut.sqrl",
		"",
		0,
		NULL,
		"sqrl.server:8443",
		"https://web.server/signin",
		"192.168.1.100",
		"https://web.server",
		"8443",
		&rsp
		);
	SSP_InitResponse(&rsp);
	SSP_SendRequest(&scb);
	PrintResponse(&rsp);

	memcpy(szNutEq, rsp.pData, NutEqLen);
	szNutEq[NutEqLen]='\0';
	
	SSP_FreeResponse(&rsp);

	// Get QRcode
	SetUpSqrlControlBlock(
		&scb,
		"GET",
		"/png.sqrl",
		szNutEq,
		0,
		NULL,
		"sqrl.server:8443",
		"https://web.server/signin",
		"192.168.1.100",
		NULL,
		"8443",
		&rsp
		);
	SSP_InitResponse(&rsp);
	SSP_SendRequest(&scb);
	PrintResponse(&rsp);

	SSP_FreeResponse(&rsp);

/*
	// Get Next Page
	SetUpSqrlControlBlock(
		&scb,
		"GET",
		"/pag.sqrl",
		szNutEq,
		0,
		NULL,
		"sqrl.server:8443",
		"https://web.server/signin",
		"192.168.1.100",
		"https://web.server",
		"8443",
		&rsp
		);
	SSP_InitResponse(&rsp);
	SSP_SendRequest(&scb);
	PrintResponse(&rsp);

	SSP_FreeResponse(&rsp);
*/	

	// Sign In
	SetUpSqrlControlBlock(
		&scb,
		"POST",
		"/cli.sqrl",
		pClientNutQuery,
		strlen(pClientCmdQuery),
		pClientCmdQuery,
		"sqrl.server:8443",
		"https://web.server/signin",
		"192.168.1.100",
		"https://web.server",
		"8443",
		&rsp
		);
	SSP_InitResponse(&rsp);
	SSP_SendRequest(&scb);
	PrintResponse(&rsp);
	DecodeResponse(&rsp);
	SSP_FreeResponse(&rsp);

	SetUpSqrlControlBlock(
		&scb,
		"POST",
		"/cli.sqrl",
		pClientNutIdent,
		strlen(pClientCmdIdent),
		pClientCmdIdent,
		"sqrl.server:8443",
		"https://web.server/signin",
		"192.168.1.100",
		"https://web.server",
		"8443",
		&rsp
		);
	SSP_InitResponse(&rsp);
	SSP_SendRequest(&scb);
	PrintResponse(&rsp);
	DecodeResponse(&rsp);
	SSP_FreeResponse(&rsp);


	// Submit CPS Authentication
	SetUpSqrlControlBlock(
		&scb,
		"GET",
		"/cps.sqrl",
		"000000000000000000000000",
		0,
		NULL,
		"",//"sqrl.server:8443",//host
		"",//"https://web.server/signin",//referrer
		"192.168.1.100",//remoteaddr
		"", //"https://web.server",//origin
		"8443",//port
		&rsp
		);
	SSP_InitResponse(&rsp);
	SSP_SendRequest(&scb);
	PrintResponse(&rsp);
	DecodeResponse(&rsp);
	SSP_FreeResponse(&rsp);


/*
	// List DataBase
	SetUpSqrlControlBlock(
		&scb,
		"GET",
		"/bdb.sqrl",
		"",
		0,
		NULL,
		"sqrl.server:8443",
		"https://web.server/signin",
		"192.168.1.100",
		"https://web.server",
		"8443",
		&rsp
		);
	SSP_InitResponse(&rsp);
	PrintResponse(&rsp);

	SSP_FreeResponse(&rsp);
*/
	SSP_ShutDownSqrlSystem();
	
	return 0;
}
#endif
