
// configdata.c

#include "global.h"

static const char *pTheOpenFilename=NULL;

int HexToNybble(int h) {
	// quick conversion for valid hex characters 0-9, A-F, a-f
	// also 'converts' non-hex characters (which shouldn't be there anyway)
	if(h>0x3f) h+=9;
	return h&0x0f;
}
int NybbleToHex(int n) {
	// quick conversion for numbers 0-15 to '0'-'9', 'A'-'F'
	// also 'converts' larger numbers  (which shouldn't be there anyway)
	n&=0x0f; // must be 0-15
	return n<=9? '0'+n: 'A'+n-10;
}

SQ_RCODE CreateFile(FILE **ppFile, const char *pFilename, char *pMode) {
	// this is only called by OpenFile()
	*ppFile=fopen(pFilename, "w");
	if(*ppFile==NULL) {
		LOG("Unable to create file %s", pFilename);
		return SQ_FAIL;
	}
	fclose(*ppFile);

	// re-open the file as requested
	*ppFile=fopen(pFilename, pMode);
	if(*ppFile==NULL) {
		LOG("Unable to create file %s", pFilename);
		return SQ_FAIL;
	}
	// pFile is valid
	return SQ_PASS;
}

SQ_RCODE OpenFile(FILE **ppFile, const char *pFilename, char *pMode) {
	// open the file for reading and writing (binary if applicable)
	pTheOpenFilename=(char *)pFilename;
	*ppFile=fopen(pFilename, pMode);
	if(*ppFile==NULL) {
		// if the file doesn't exit create it
		if(CreateFile(ppFile, pFilename, pMode)==SQ_FAIL){
			*ppFile=NULL;
			return SQ_FAIL;
		}		
	}
	// pFile is valid
	return SQ_PASS;
}
	
SQ_RCODE CloseFile(FILE **ppFile) {
	SQ_RCODE rc=SQ_PASS;
	
	if(*ppFile!=NULL) {
		rc|=fflush(*ppFile);
		rc|=fclose(*ppFile);
		*ppFile=NULL;
	}
	if(rc!=SQ_PASS) {
		LOG("Error closing file %s", pTheOpenFilename); 
		rc=SQ_FAIL;
	}
	pTheOpenFilename=NULL;
	return rc;
}

/***************
READ CONFIG FILE
***************/

SQ_RCODE ReadCfgFile(CFG_ITEM **ppCfgItems, char **ppData) {
	BEG("ReadCfgFile()");
	// Note: The caller supplies pointer for pCfgItems and pData
	// This function allocates memory of them
	// The caller must free that memory.
	
	SQ_RCODE rc=SQ_PASS;
	FILE *pFile;
		
	if(OpenFile(&pFile, pszCfgFile, "rb")==SQ_FAIL) {
		END();
		return SQ_FAIL;
	}
	
	// Set up the name=value table
	*ppCfgItems=(CFG_ITEM *)GlobalAlloc(CFG_NUM_ITEMS*sizeof(CFG_ITEM));
	CFG_ITEM *pCfgItems=*ppCfgItems;
	
	int i;
	for(i=0; i<CFG_NUM_ITEMS; i++) {
		pCfgItems[i].pszValue=(char *)pszNull;
		pCfgItems[i].pComments=NULL;
		pCfgItems[i].NumComments=0;
	}

	// Get the file size
	struct stat buf;
	stat(pszCfgFile, &buf);
	int Size=buf.st_size;
	
	// Allocate memory and read the file into it
	*ppData=(char *)GlobalAlloc(Size+1);
	char *pData=*ppData;
	fread(pData, sizeof(char), Size, pFile);
	pData[Size]='\0';
	
	// Parse the Name=Value data
	char *pszLF="\n";
	char *pszLine;
	
	pszLine=strtok(pData, pszLF);
	char *pComments=NULL;
	int NumComments=0;
	int LineNo=0;
	while(pszLine!=NULL) {
		LineNo++;
		
		// Remove possible CR
		char *ptr=strchr(pszLine, '\r');
		if(ptr!=NULL) *ptr='\0';
		
		if(pszLine[0]=='#') {
			// This is a comment line
			NumComments++;
			// Save the address of the first comment
			if(pComments==NULL) pComments=pszLine;
		}
		else {
			int i;
			for(i=0; i<CFG_NUM_ITEMS; i++) {
				// Find the name and its value
				if(strstr(pszLine, aCfgInfo[i].pszName)==pszLine) {
					pCfgItems[i].pszValue=pszLine+strlen(aCfgInfo[i].pszName);
					pCfgItems[i].pComments=pComments;
					pCfgItems[i].NumComments=NumComments;
					pComments=NULL;
					NumComments=0;
					break;
				}
			}
			
			if(i==CFG_NUM_ITEMS) {
				// We didn't find the value
				printf("Unknown name=value in %s has been removed:\r\n", pszCfgFile);
				printf("Line %d: %s\r\n", LineNo, pszLine);
			}
		}
		pszLine=strtok(NULL, pszLF);
	}
	CloseFile(&pFile);
	
	END();
	return rc;
}

/****************
WRITE CONFIG FILE
****************/

SQ_RCODE WriteCfgFile(CFG_ITEM *pCfgItems, char *pData) {
	BEG("WriteCfgFile()");
	SQ_RCODE rc=SQ_PASS;
	FILE *pFile;
		
	if(OpenFile(&pFile, pszCfgFile, "wb")==SQ_FAIL) {
		END();
		return SQ_FAIL;
	}
	int i;
	for(i=0; i<CFG_NUM_ITEMS; i++) {
		if(pCfgItems[i].pComments!=NULL && pData!=NULL) {
			char *ptr=pCfgItems[i].pComments;
			int j;
			for(j=0; j<pCfgItems[i].NumComments; j++)
				{
				fprintf(pFile, "%s\r\n", ptr);
				ptr+=strlen(ptr);
				while(*ptr!='#') ptr++;
				}			
			}
		fprintf(pFile, "%s%s\r\n", aCfgInfo[i].pszName, pCfgItems[i].pszValue);
	}
	CloseFile(&pFile);
	
	END();
	return rc;
}

/***********************
GET32 HIGH ENTROPY BYTES
***********************/

SQ_RCODE Get32HighEntropyBytes(char *pszBuffer) {
	// pBuffer must accept a 64-hex-char null-terminated string
	char *pRandomDevName="/dev/random";
	FILE *pRandomDev=fopen(pRandomDevName, "rb");
	if(pRandomDev==NULL) {
		// The random number will have to be obtained elsewhere
		// (e.g. https://www.grc.com/passwords.htm )
		LOG("Unable to obtain random number from dev/random");
		return SQ_FAIL;
		}
	
	// Verify the device id
	struct stat StatBuffer;
	stat(pRandomDevName, &StatBuffer);
	dev_t Device=StatBuffer.st_rdev;
	int maj=major(Device);
	int min=minor(Device);
	if(maj!=1 || min!=8) {
		LOG("Wrong dev/random device id %d.%d. Expecting 1.8", maj, min);
		return SQ_FAIL;
	}

	int i, j;
	for(i=0; i<BYTES_FOR_256_BITS; i++) {
		// Get a random byte
		SQ_BYTE n;
		fread(&n, 1, 1, pRandomDev);
		
		// Convert to a hex char array
		j=i*2;
		pszBuffer[j+0]=(char)NybbleToHex(n>>4);
		pszBuffer[j+1]=(char)NybbleToHex(n&0x0f);
	}
	fclose(pRandomDev);

	// Null-terminate it
	pszBuffer[i*2]='\0';
	return SQ_PASS;
}

SQ_CHAR szMonotonicCounter[BYTES_FOR_64_BITS*2+1];

const SQ_CHAR szHandlerName[HANDLER_NAME_SIZ];
const SQ_CHAR szCertFilename[SQ_MAX_PATH];
const SQ_CHAR szKeyFilename[SQ_MAX_PATH];
const SQ_CHAR szListenIp[SQ_IP_LEN+1];
const SQ_CHAR szListenPort[SQ_PORT_LEN+1];
const SQ_CHAR szPrivateAccessIp[SQ_IP_LEN+1];
const SQ_CHAR szSystemKey[BYTES_FOR_256_BITS*2+1];
const SQ_CHAR szDatabaseKey[DATABASE_KEY_LEN+1];
const SQ_CHAR szTransactionLogging[sizeof(char)+1];
const SQ_CHAR szPublicAuthDomain[SQ_MAX_URL];
const SQ_CHAR szWebServerAuthUrlArray[10][SQ_MAX_URL];

const SQ_HANDLER nHandlerName;
const SQ_CHAR szListenUrl[8+SQ_IP_LEN+1+SQ_PORT_LEN+1]; // https://<ip>:<port>
const SQ_BOOL bEnableTransactionLogging;

int ReadLine(char *pszBuffer, int BufLen) {
	// BufLen is the maximum string length
	// The buffer size is BufLen+1
	int n=0;
	while(1) {
		// Input characters until CR
		char c=getchar();
		if(c=='\r' || c=='\n') break;
		if(n<BufLen){
			// Only accept BufLen number of characters
			pszBuffer[n]=c;
			n++;
		}
	}
	// Null-terminate the string
	pszBuffer[n]='\0';
	
	// return number of characters read	
	return n;
}

/**********************
INIT CONFIGURATION DATA
**********************/
SQ_RCODE InitSqrlCfgData() {
	BEG("InitCfgData()");
	SQ_RCODE rc =SQ_PASS;
	
	CFG_ITEM *pCfgItems=NULL;
	char *pData=NULL;
	ReadCfgFile(&pCfgItems, &pData);
	
	// Check if values have been entered

	enum {BufLen=255};
	char szInputBuffer[CFG_NUM_ITEMS][BufLen+1];
	int len;
	
	len=strlen(pCfgItems[CFG_MONOTONIC_COUNTER].pszValue);
	if(len!=BYTES_FOR_64_BITS*2) {
		pCfgItems[CFG_MONOTONIC_COUNTER].pszValue=(char *)&"0000000000000000";
	}

	len=strlen(pCfgItems[CFG_HANDLER_NAME].pszValue);
	if(len==0) {
		// No handler specified
		pCfgItems[CFG_HANDLER_NAME].pszValue="(none)";
	}

	len=strlen(pCfgItems[CFG_CERT_FILENAME].pszValue);
	if(len==0) {
		// No filename for the signed certificate
		do {
			printf("\r\n! Enter Certificate Filename:\r\n");
		}
		while(ReadLine(szInputBuffer[CFG_CERT_FILENAME], BufLen)<1);
		pCfgItems[CFG_CERT_FILENAME].pszValue=szInputBuffer[CFG_CERT_FILENAME];
	}

	len=strlen(pCfgItems[CFG_KEY_FILENAME].pszValue);
	if(len==0) {
		// No filename for the private key
		do {
			printf("\r\n! Enter Certificate Key Filename:\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_KEY_FILENAME])<1);
		pCfgItems[CFG_KEY_FILENAME].pszValue=szInputBuffer[CFG_KEY_FILENAME];
	}

	len=strlen(pCfgItems[CFG_LISTEN_IP].pszValue);
	if(len==0) {
		// No Listen IP
		do {
			printf("\r\n! Enter Listening IP nnn.nnn.nnn.nnn\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_LISTEN_IP])<1);
		pCfgItems[CFG_LISTEN_IP].pszValue=szInputBuffer[CFG_LISTEN_IP];
	}

	len=strlen(pCfgItems[CFG_LISTEN_PORT].pszValue);
	if(len==0) {
		// No Listen Port
		do {
			printf("\r\n! Enter Listening Port nnnnn\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_LISTEN_PORT])<1);
		pCfgItems[CFG_LISTEN_PORT].pszValue=szInputBuffer[CFG_LISTEN_PORT];
	}

	len=strlen(pCfgItems[CFG_PRIVATE_ACCESS_IP].pszValue);
	if(len==0) {
		// No Private Access IP
		do {
			printf("\r\n! Enter Private Access IP nnn.nnn.nnn.nnn, or *, or ?\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_PRIVATE_ACCESS_IP])<1);
		pCfgItems[CFG_PRIVATE_ACCESS_IP].pszValue=szInputBuffer[CFG_PRIVATE_ACCESS_IP];
	}

	SQ_CHAR szSystemKey[BYTES_FOR_256_BITS*2+1];
	len=strlen(pCfgItems[CFG_SYSTEM_KEY].pszValue);
	if(len!=BYTES_FOR_256_BITS*2) {
		// Value has not been initialized.  Set it to a high entropy random
		// number using the Linux "file" /dev/random (device id 1.8)
		if(Get32HighEntropyBytes(szSystemKey)==SQ_PASS) {
			pCfgItems[CFG_SYSTEM_KEY].pszValue=szSystemKey;
		}
		else {
			do {
				printf("\r\n! Enter High Entropy System Secret Key (64 Hex Characters)\r\n");
			}
			while(scanf("%s", szInputBuffer[CFG_SYSTEM_KEY])<64);
			pCfgItems[CFG_SYSTEM_KEY].pszValue=szInputBuffer[CFG_SYSTEM_KEY];
		}
	}
	
	// Set Sqrl Static Secret
	SQ_CHAR *pszHex=(char *)pCfgItems[CFG_SYSTEM_KEY].pszValue;
	SQ_BYTE *pNybble=(SQ_BYTE *)aSystemKey;

	// Convert to a byte array
	int j;
	for(j=0; j<BYTES_FOR_256_BITS; j++){
		// assume valid hex digit, if not just convert what's there
		int k=j*2;
		SQ_BYTE a=HexToNybble(pszHex[k+0]);
		SQ_BYTE b=HexToNybble(pszHex[k+1]);
		pNybble[j]=(a<<4)+(b);
	}

	SQ_CHAR szDataBaseKey[DATABASE_KEY_LEN+1];
	len=strlen(pCfgItems[CFG_DATABASE_KEY].pszValue);
	if(len!=DATABASE_KEY_LEN) {
		// Value has not been initialized
		// Convert the first 24 bytes to Base64URL to get a 32 char database password key
		CvrtToBase64String(szDataBaseKey, 32, aSystemKey, 24);
		pCfgItems[CFG_DATABASE_KEY].pszValue=szDataBaseKey;
	}

	len=strlen(pCfgItems[CFG_TRANSACTION_LOGGING].pszValue);
	if(len!=sizeof(char)) {
		do {
			printf("\r\n! Enter TransactionLogging (0=Disabled 1=Enabled)\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_TRANSACTION_LOGGING])!=1);
		pCfgItems[CFG_TRANSACTION_LOGGING].pszValue=szInputBuffer[CFG_TRANSACTION_LOGGING];
	}

	len=strlen(pCfgItems[CFG_PUBLIC_AUTH_DOMAIN].pszValue);
	if(len==0) {
		// Value has not been initialized
		do {
			printf("\r\n! Enter PublicAuthDomain URL e.g. https://web.server\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_PUBLIC_AUTH_DOMAIN])<1);
		pCfgItems[CFG_PUBLIC_AUTH_DOMAIN].pszValue=szInputBuffer[CFG_PUBLIC_AUTH_DOMAIN];
	}
	
	len=strlen(pCfgItems[CFG_WEB_SERVER_AUTH_URL0].pszValue);
	if(len==0) {
		// No Web Server Auth URL (the first is required, 1-9 are optional)
		do {
			printf("\r\n! Enter Web Server Authentication URL e.g. https://web.server/auth\r\n");
		}
		while(scanf("%s", szInputBuffer[CFG_WEB_SERVER_AUTH_URL0])<1);
		pCfgItems[CFG_WEB_SERVER_AUTH_URL0].pszValue=szInputBuffer[CFG_WEB_SERVER_AUTH_URL0];
	}

	printf("Configuration Data in %s:\r\n", pszCfgFile);
	int i;
	for(i=0; i<CFG_NUM_ITEMS; i++) {
		printf(" [%s%s]\r\n", aCfgInfo[i].pszName, pCfgItems[i].pszValue);
	
		// Save all the values (except for the monotonic counter these are all constant after initialization)
		strncpy((char *)aCfgInfo[i].pszVariable, pCfgItems[i].pszValue, aCfgInfo[i].Length);
	}

	// Derive nHandlerName from szHandlerName
	if(strcmp(szHandlerName, "MBedTLS")==0) *(SQ_HANDLER *)&nHandlerName=SQ_MBEDTLS;
	else if(strcmp(szHandlerName, "OpenSSL")==0) *(SQ_HANDLER *)&nHandlerName=SQ_OPENSSL;
	else *(SQ_HANDLER *)&nHandlerName=NO_HANDLER;
	
	*(SQ_BOOL*)&bEnableTransactionLogging=(szTransactionLogging[0]=='0'? SQ_FALSE: SQ_TRUE);
		
	// Derive szListenURL from szListenIP and szListenPort
	sprintf((char *)szListenUrl, "https://%s:%s", szListenIp, szListenPort);
	printf("\r\n");
	printf("Listen URL: %s", szListenUrl);
	printf("\r\n");
	
	// Derive bEnableTransactionLogging from szTransactionLogging
	*(SQ_BOOL*)&bEnableTransactionLogging=(szTransactionLogging[0]=='0'? SQ_FALSE: SQ_TRUE);
		
	WriteCfgFile(pCfgItems, pData);
	GlobalFree((void **)&pCfgItems);
	GlobalFree((void **)&pData);
	
	END();
	return rc;
}

/*
===============================================================================
	GET 64-BIT COUNTER
===============================================================================
*/

SQ_RCODE Get64BitCounter(SQ_BYTE *pCounterByteArray) {
	// This is an 8-byte little-endian array stored in the sspapi.cfg as big-endian 16 hex characters
	SQ_RCODE rc=SQ_PASS;
	
	SQ_BYTE *pHex=(SQ_BYTE *)szMonotonicCounter;
	int i, j, k;
	for(i=0, j=BYTES_FOR_64_BITS; i<BYTES_FOR_64_BITS; i++){
		// assume valid hex digit, if not just convert what's there
		k=i*2;
		j--;
		SQ_BYTE a=HexToNybble(pHex[k]);
		SQ_BYTE b=HexToNybble(pHex[k+1]);
		pCounterByteArray[j]=(a<<4)+(b);
	}
	return rc;
}

/*
===============================================================================
	SET 64-BIT COUNTER
===============================================================================
*/
SQ_RCODE Set64BitCounter(SQ_BYTE *pCounterByteArray) {
	// This is an 8-byte little-endian array stored in a text file as big-endian 16 hex characters
	SQ_RCODE rc=SQ_PASS;

	SQ_CHAR aHex[BYTES_FOR_64_BITS*2+1];
	int i, j, k;
	for(i=0, j=BYTES_FOR_64_BITS; i<BYTES_FOR_64_BITS; i++){
		// assume valid hex digit, if not just convert what's there
		k=i*2;
		j--;
		aHex[k+0]=(char)NybbleToHex(pCounterByteArray[j]>>4);
		aHex[k+1]=(char)NybbleToHex(pCounterByteArray[j]&0x0f);
	}
	// Null-terminate and save
	aHex[BYTES_FOR_64_BITS*2]='\0';
	rc=SetCfgItem(CFG_MONOTONIC_COUNTER, aHex);
	
	return rc;
}
SQ_RCODE SetCfgItem(int ItemIndex, char *pszItemValue) {
	BEG("SetCfgItem()");
	SQ_RCODE rc=SQ_PASS;
	int i=ItemIndex;
	
	CFG_ITEM *pCfgItems;
	char *pData;
	ReadCfgFile(&pCfgItems, &pData);
	pCfgItems[ItemIndex].pszValue=pszItemValue;
	strncpy((char *)aCfgInfo[i].pszVariable, pCfgItems[i].pszValue, aCfgInfo[i].Length);
	rc=WriteCfgFile(pCfgItems, pData);
	GlobalFree((void **)&pCfgItems);
	GlobalFree((void **)&pData);
		
	END();
	return rc;
}
