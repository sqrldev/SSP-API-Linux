
// utils.c

#include "global.h"
#include "blowfish.h"

/*
===============================================================================
	LOG THE QUERY AND REPLY
	Conditionally log the incoming query and our reply
===============================================================================
*/
void LogTheQueryAndReply(SQ_CHAR *pszMessage, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("LogTheQueryAndReply()");
	SQ_CHAR szQuery[2048];

	if(bEnableTransactionLogging==SQ_TRUE){
		strcpy(szQuery, pSCB->lpszMethod);
		strcat(szQuery, " ");
		strcat(szQuery, pSCB->lpszPathInfo);
		if(pSCB->lpszQueryString!=NULL){
			strcat(szQuery, "?");
			strcat(szQuery, pSCB->lpszQueryString);
		}
		strcat(szQuery, "\r\n                          : ");
		strcat(szQuery, pszMessage);

		//[
		//? should we open the file in exclusive share mode
		//? or protect it with a critical section?
		//]
		
		FILE *pFile=fopen("SSPAPI.log", "a");
		int MsgLen=strlen(szQuery);
		fwrite(szQuery, 1, MsgLen, pFile);
		fwrite("\r\n", 1, 2, pFile);
		fflush(pFile);
		fclose(pFile);
		}
	END();
}
	
/*
===============================================================================
	GLOBAL ALLOC / GLOBAL FREE / SAFE GLOBAL FREE				     
-------------------------------------------------------------------------------
*/
//[ For development to check for allocations not subsequently freed]
static int AllocCount=0;
//]
void *GlobalAlloc(SQ_DWORD NumBytes) {
	BEG("GlobalAlloc()");
	void *ptr;
	if((ptr=calloc(NumBytes, 1))==NULL) {
		perror("sspapi: Out of Memory\r\n");
		exit(1);
	}
//[
	LOG("%p", ptr);
	AllocCount++;
	LOG("[%d]", AllocCount);
//]
	END();
	return ptr;
}
void GlobalFree(void **ppGlobalAllocation) {
	if(ppGlobalAllocation==NULL || *ppGlobalAllocation==pszNull) {
		// The pointer is NULL or to "", not to allocated memory
		return;
	}
	BEG("GlobalFree()");
//[
	LOG("%p", *ppGlobalAllocation);
//]
	if(*ppGlobalAllocation!=NULL) {
		free(*ppGlobalAllocation);
		*ppGlobalAllocation=NULL;
//[
		AllocCount--;
//]
	}
//[
	LOG("[%d]", AllocCount);
//]
	END();
}

/*
===============================================================================
	CHECK LOCALHOST CALLER
	This checks for the IPv6 localhost IP: 2002:7F00:0001:0000:0000:0000:0000:0000
	The status flags are set when we return. We return ZERO (equal) if it's LOCAL
===============================================================================
*/
SQ_RCODE CheckLocalhostCaller(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("CheckLocalhostCaller()");

	SQ_BYTE aIPbuffer[IPV6_BYTE_LEN]; // [16]
	SQ_BYTE aLocalhost[]={
		0x20, 0x02, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	ObtainClientConnectionIP(aIPbuffer, pSCB);
	END();
	return (memcmp(aIPbuffer, aLocalhost, IPV6_BYTE_LEN)==0? SQ_PASS: SQ_FAIL);
}

//------------------------------------------------------------------------------
void SQ_GetSystemTimeAsFileTime(SQ_QWORD *pFileTime) {
	BEG("SQ_GetSystemTimeAsFileTime()");
	// This offset was obtained from the Windows function
	//  SystemTimeToFileTime(1970-01-01 00:00:00);
	// It is the number of 100ns units from 
	//  1601-01-01 00:00:00 to 1970-01-01 00:00:00

	SQ_QWORD Offset1601To1970=(SQ_DWORD)0x019db1ded53e8000;
	SQ_QWORD TenMillion=(SQ_QWORD)10000000;
	SQ_QWORD RawTime=(SQ_QWORD)time(NULL);

	*pFileTime=Offset1601To1970+TenMillion*RawTime;
	END();
}

//------------------------------------------------------------------------------
SQ_DWORD SQ_GetFileTimeAgeInMinutes(SQ_QWORD *pSqrlLastActivityDate, SQ_QWORD *pCurrentTime) {
	BEG("SQ_GetFiletimeAgeInMinutes()");
	SQ_QWORD SixHundredMillion=(SQ_QWORD)600000000;
	SQ_QWORD AgeInMinutes=(*pCurrentTime-*pSqrlLastActivityDate)/SixHundredMillion;
	END();
	return (SQ_DWORD)AgeInMinutes;
}
/*
===============================================================================
	GET SYSTEM ONE SECOND TIME
	This returns a low-resolution (1 second) time in a single DWORD value.    
===============================================================================
*/
SQ_DWORD GetSystemOneSecondTime(){
	BEG("GetSystemOneSecondCount()");

//? A latent Y2038 bug ???

	time_t now;
	time(&now);

	END();
	return (SQ_DWORD)now;
}

/*
============================================================================
	GET NEXT MONOTONIC COUNTER VALUE
	We give this a pointer to a 8-byte (64-bit) buffer, which it fills
============================================================================
*/
SQ_RCODE GetNextMonotonicCounterValue(SQ_BYTE *pNextValue) {
	BEG("GetNextMonotonicCounterValue()");

	// bytes are little-endian
	
	EnterCriticalSection(&IncDataCriticalSection);

	// Get the current value 
	SQ_BYTE aValue[BYTES_FOR_64_BITS]; // 8 bytes=64bits
	if(Get64BitCounter(aValue)==SQ_FAIL){
		// ERROR
		memset(aValue, 0, BYTES_FOR_64_BITS);
	}

LOG("Current monotonic counter value:");
LOG("[x]", aValue, BYTES_FOR_64_BITS);

	// Increment the counter value
	SQ_WORD tmp;
	SQ_WORD carry=1;
	for(int i=0; i<BYTES_FOR_64_BITS; i++) {
		tmp=(SQ_WORD)(aValue[i])+carry;
		aValue[i]=(SQ_BYTE)(tmp&0xff);
		carry=(SQ_WORD)(tmp>>8);
		if(carry==0) break;
	}
	if(Set64BitCounter(aValue)==SQ_FAIL){
		// ERROR
	}

	memcpy(pNextValue, aValue, BYTES_FOR_64_BITS);

	LeaveCriticalSection(&IncDataCriticalSection);
	END();
	return SQ_PASS;
}

/*
===============================================================================
	GET UNPREDICTABLE 64 BITS
===============================================================================
*/
void GetUnpredictable64bits(SQ_BYTE *p64bitBuffer) {
	BEG("GetUnpredictable64bits()");

	// this byte array is little-endian
	// retrieve a 64-bit monotonic counter value...
	if(GetNextMonotonicCounterValue(p64bitBuffer)==SQ_FAIL) {
		// ERROR: Cannot get next counter value
//[
LOG("Error:%s %d", __FILE__, __LINE__);
//]
	}
	// which we then encrypt (in place)
	blowfish_context_t *ctx = (blowfish_context_t *)GlobalAlloc(sizeof(blowfish_context_t));
	blowfish_initiate(ctx, aSystemKey, BLOWFISH_KEY_LEN);

	// separate the high 4 and low 4 bytes
	blowfish_encryptblock(ctx, (BF_ULONG *)(&p64bitBuffer[4]), (BF_ULONG *)(&p64bitBuffer[0]));

	blowfish_clean(ctx);
	GlobalFree((void **)&ctx);

	END();
}
/*
===============================================================================
	GET UNIQUE 12 CHAR NUT
 ------------------------------------------------------------------------------
	Given a pointer to a 12 or 13-character buffer, this fills it with
	a unique 72-bit pseudo-random value encoded into Base64url.
-------------------------------------------------------------------------------
*/
void GetUnique12charNut(SQ_CHAR *pszBase64Buffer, SQ_BOOL NullTerm) {
	BEG("GetUnique12charNut()");

	const int CtrLen=BYTES_FOR_64_BITS+1; // 9 bytes, 72 bits
	const int BufLen=SQRL_NUT_LEN; // 12 encoded characters
	
	SQ_BYTE aEncryptedCounter[CtrLen];

	// retrieve a 64-bit monotonic counter value which we then encrypt
	GetUnpredictable64bits(aEncryptedCounter);
	// add a byte of high entropy clock ticks
	aEncryptedCounter[CtrLen-1]=(SQ_BYTE)(clock()&0xff);
//[
// If counter was reset for testing don't let this byte change
if(bCounterReset==SQ_TRUE) aEncryptedCounter[CtrLen-1]=0x00;
//]	

//[
LOG("aEncryptedCounter:");
LOG("[x]", aEncryptedCounter, CtrLen);
//]
	// encode our pseudo-random number
	SqrlCvrtToBase64(pszBase64Buffer, BufLen, aEncryptedCounter, CtrLen);
	
	// null-terminate if requested (pszBase64Buffer size must be BufLen+1)
	if(NullTerm) pszBase64Buffer[BufLen]='\0';
//[
LOG("pszBase64Buffer:");
LOG("[c]", pszBase64Buffer, BufLen);
//]
	END();
}
/*
===============================================================================
	GET UNIQUE 20 DIGIT TOKEN
 ------------------------------------------------------------------------------
	Given a pointer to a 20-character buffer, this fills the buffer with a 
	unique 20-digit decimal number. It performs 20 rounds of long division of
	a 128-bit guaranteed unique binary number
-------------------------------------------------------------------------------
*/
void GetUnique20digitToken(SQ_CHAR *p20CharBuffer, SQ_BOOL NullTerm) {
	BEG("GetUnique20digitToken()");
	
	// retrieve a unique 64-bit pseudo-random value which we decimalize
	SQ_BYTE Entropy[16]; // 128 bits (treated as little-endian)
	GetUnpredictable64bits(&Entropy[0]);
	GetUnpredictable64bits(&Entropy[8]);
	
	SQ_DWORD ByteNdx;
	SQ_DWORD CharNdx=20;
	SQ_QWORD Q[1]; // The 64-bit accumulator
	SQ_QWORD *pQ=&Q[0];
	SQ_DWORD *pLo=&((SQ_DWORD *)Q)[0];
	SQ_DWORD *pHi=&((SQ_DWORD *)Q)[1];
	
	do {
		CharNdx--;
		*pHi=0;
		ByteNdx=4;
		do {
			ByteNdx--;
			*pLo=((SQ_DWORD *)Entropy)[ByteNdx];
			SQ_DWORD lo=*pQ/10;
			SQ_DWORD hi=*pQ%10;
			*pLo=lo;
			*pHi=hi;
			((SQ_DWORD *)Entropy)[ByteNdx]=*pLo;
		} while(ByteNdx>0);
		p20CharBuffer[CharNdx]=*pHi+'0';
	} while(CharNdx>0);
	
	if(NullTerm==SQ_TRUE) {
		p20CharBuffer[20]='\0';
	}
	LOG("[]", p20CharBuffer, 20);
	END();
}
//------------------------------------------------------------------------------
void IPv4StringToAddress(char *pIPaddress, void *pBuffer, unsigned int *pBufferLength) {
	BEG("IPv4StringToAddress()");
	
	// The address bytes are stored in big-endian format
	// We expect the string to be a valid ip so we just use sscanf()
	//  and return all zeros if there is an error
	
	// The IP4 conversion produces 4 bytes
	const int NumBytes=4;
	if(*pBufferLength>=NumBytes) {
		// We need a temporary array of ints for sscanf()
		int tmp[NumBytes];
		if(sscanf(pIPaddress, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3])==NumBytes) {
			// Copy bytes (value 0x00-0xff) into the buffer
			SQ_BYTE *p=(SQ_BYTE *)pBuffer;
			for(int i=0; i<NumBytes; i++) {
				p[i]=(SQ_BYTE)tmp[i];
			}
			*pBufferLength=NumBytes;
			
			END();
			return;
		}
	}		
	// Otherwise there is an error, return zeros
	memset(pBuffer, 0, *pBufferLength);
	*pBufferLength=0;
	
	END();
}

//------------------------------------------------------------------------------
void IPv6StringToAddress(char *pIPaddress, void *pBuffer, unsigned int *pBufferLength) {
	BEG("IPv6StringToAddress()");
	// The address bytes are stored in big-endian format
	// We expect the string to be a valid ip so we just use sscanf() and return all zeros if there is an error
	
	// The IP6 conversion produces 8 words (16 bytes)
	const int NumWords=8;
	const int NumBytes=NumWords*2;
	if(*pBufferLength>=NumBytes) {
		// We need a temporary array of ints for sscanf()
		int tmp[NumWords];
		if(sscanf(pIPaddress, "%x:%x:%x:%x:%x:%x:%x:%x", 
			&tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7])==NumWords) {
			// Copy words (value 0x0000-0xffff) into the buffer
			SQ_BYTE *p=(SQ_BYTE *)pBuffer;
			for(int i=0; i<NumWords; i++) {
				p[i*2+0]=(SQ_BYTE)(tmp[i]>>8);
				p[i*2+1]=(SQ_BYTE)(tmp[i]&0xff);
			}
			*pBufferLength=NumBytes;
			END();
			return;
		}
	}
	// Otherwise there is an error
	memset(pBuffer, 0, *pBufferLength);
	*pBufferLength=0;
	END();
}

/*
===============================================================================
	OBTAIN CLIENT CONNECTION IP
-------------------------------------------------------------------------------
	This obtains the client's connection IP with IPv4 & IPv6 compatibility. If the
	server returns an IP string containing a ':' we treat it as an IPv6 address.
	If ':' is not present, we treat it as an IPv4 address. In that case we create
	a 128-bit IPv6 style address "2002:xxxx:xxxx:0000:0000:0000:0000:0000.
===============================================================================
*/
void ObtainClientConnectionIP(void *pIPbuffer, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ObtainClientConnectionIP()");

	// IP address bytes are stored in big-endian order
//*	SQ_CHAR szIPaddress[64];
	SQ_DWORD BufferLength;
	SQ_BYTE aIPv4SockAddr[4]; // xx.xx.xx.xx
	SQ_WORD aIPv6SockAddr[8]; // xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
	
	// we may have an IPv4 address (aa.bb.cc.dd), so we preload the 6to4 
	// "2002:" mapping in case we need to plug an IPv4 format address into
	// IPv6 address space: 2002:aabb:ccdd:0000:0000:0000:0000:0000

	memset(aIPv6SockAddr, 0, IPV6_BYTE_LEN);
	aIPv6SockAddr[0]=0x0220; // 2002:0000:0000:0000:0000:0000:0000:0000
	
	// we need to determine whether we received an IPv4 or IPv6 address
	if(strstr(pSCB->lpszRemoteAddr, ":")!=NULL) {
		// we DID find an ':' in the address string, so it's IPv6
		// but is it "::1" which is our localhost loopback IPv6 IP?
		if(strcmp(pSCB->lpszRemoteAddr, "::1")==0) {
			aIPv6SockAddr[1]|=0x007f; // 2002:7f00:0000:0000:0000:0000:0000:0000
			aIPv6SockAddr[2]|=0x0100; // 2002:7f00:0001:0000:0000:0000:0000:0000 
			memcpy(pIPbuffer, aIPv6SockAddr, IPV6_BYTE_LEN);

			END();
			return;
		}
	
		BufferLength=sizeof(aIPv6SockAddr);
		IPv6StringToAddress(pSCB->lpszRemoteAddr, aIPv6SockAddr, &BufferLength);
	}
	else {
		// we have an IPv4 address (aa.bb.cc.dd) so let's plug-in its 32-bits
		BufferLength=sizeof(aIPv4SockAddr);
		IPv4StringToAddress(pSCB->lpszRemoteAddr, aIPv4SockAddr, &BufferLength);
		aIPv6SockAddr[1]|=((SQ_WORD *)aIPv4SockAddr)[0]; // 2002:aabb:0000:0000:0000:0000:0000:0000
		aIPv6SockAddr[2]|=((SQ_WORD *)aIPv4SockAddr)[1]; // 2002:aabb:ccdd:0000:0000:0000:0000:0000
	}
	// return the final 128-bit (16-byte) IPv6 format address
	memcpy(pIPbuffer, aIPv6SockAddr, IPV6_BYTE_LEN);

	LOG("aIPv4SockAddr (dec):");
	LOG("[d]", aIPv4SockAddr, IPV4_BYTE_LEN);
	LOG("aIPv6SockAddr: (dec):");
	LOG("[d]", aIPv6SockAddr, IPV6_BYTE_LEN);

	END();
}

/*===============================================================================
	VERIFY PRIVATE QUERY
	This verifies that our client's requesting hostname and port are correct for
	access to the private SSP API functions. We return NOT ZERO if they are wrong.
===============================================================================
*/
SQ_RCODE VerifyPrivateQuery(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("VerifyPrivateQuery()");

	SQ_CHAR szLogError[512];
		
	if(szPrivateAccessIp[0]=='?') {
		// Private Access IP has not been specified in the sspapi.cfg file
		// Assume this first query is from our private access ip
		SetCfgItem(CFG_PRIVATE_ACCESS_IP, pSCB->lpszRemoteAddr);
	}
	
	// let's first check the port the user is calling since that's the most
	// likely to be incorrect for innocent mis-queries to the private APIs.
//	if(strcmp(pSCB->szServerPort, szPrivatePort)!=0) {
	if(strcmp(pSCB->szServerPort, szListenPort)!=0) {
		END();
		return SQ_FAIL;
	}
	//we DO have the proper port number, so do we have a wildcard query IP?
	if(szPrivateAccessIp[0]=='*') {
		END();
		return SQ_PASS;
	}
	// if the caller is local, then we know it's okay
	if(CheckLocalhostCaller(pSCB)==SQ_PASS) {
		END();
		return SQ_PASS;
	}
	// it's the correct port, and it's not a LocalHost query.
	//	so let's see whether it's a valid non-localhost IP?

//[
//. Why strstr() and not strcmp() ?
//]
	if(strstr(szPrivateAccessIp, pSCB->lpszRemoteAddr)==NULL) {
		// if an attempt was made to access the private query from
		// a non-registered IP, let's make a log entry...
		sprintf(szLogError, pszBlockedPrivateQuery, pSCB->lpszRemoteAddr);
		LogTheQueryAndReply(szLogError, pSCB);
		END();
		return SQ_FAIL;
	}

	END();
	return SQ_PASS;
}

/*
============================================================================
	URL ENCODE				     
----------------------------------------------------------------------------
*/
SQ_BYTE UrlEncodeTable[]={
//	0                               1
//	0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f 
	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,

//	2                               3
//	0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f
//	sp  " # $ % &         + ,     /                     : ; < = > ?
	1,0,1,1,1,1,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,
 
//	4                               5
//	0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f
//	@                                                     [ \ ] ^
	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,

//	6                               7
//	0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f
//	  ~ } | {                                                     `
	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0
//	`                                                     { | } ~
};

// Note: The size of the destination buffer must be at least
//  strlen(pSrcBuffer)*3+1 to avoid possible overruns

void UrlEncode(SQ_CHAR *pDstBuffer, SQ_CHAR *pSrcBuffer) {
	BEG("");

	// Source and destination indices
	int SrcNdx=0;
	int DstNdx=0;
	int c;
	do {
		// Check if the character needs to be encoded as %hex
		c=(int)((unsigned char)pSrcBuffer[SrcNdx++]);
		if(UrlEncodeTable[c]==0) {
			// no, copy directly
			pDstBuffer[DstNdx++]=c;
		}
		else {
			// yes, convert to %hex
			pDstBuffer[DstNdx++]='%';
			pDstBuffer[DstNdx++]=(char)NybbleToHex(c>>4);
			pDstBuffer[DstNdx++]=(char)NybbleToHex(c&0x0f);
		}
	} while(c!='\0');
	END();
}

/*
===============================================================================
	PLACE CPS URL INTO BUFFER
	in: pCPSNonce
	out pBuffer
===============================================================================
*/
void PlaceCpsUrlIntoBuffer(SQ_CHAR *pBuffer, PENDING_AUTHS *pPendingAuth) {
	BEG("PlaceCpsUrlIntoBuffer()");
	SQ_CHAR szCPSNonce[28];
	
	// we check for any path extension "x=n" (n is at offset 2)
	char PathExt=pPendingAuth->szPathExtension[2]; // null or '0' to '9'
	int ndx=0;
	if(PathExt>='1' && PathExt<='9') {
		ndx=PathExt-'0';
		
		// If there is no URL for that path extension, just use the primary URL
		if(strlen(szWebServerAuthUrlArray[ndx])==0) {
			ndx=0;
//[
char sPathExt[]="x=?";
memcpy(sPathExt, pPendingAuth->szPathExtension, 3);
LOG("Warning: No Auth URL for Path Extension %s", sPathExt);
//]
		}
	}
	memcpy(szCPSNonce, pPendingAuth->aCPSNonce, CPS_TOKEN_LEN);
	szCPSNonce[CPS_TOKEN_LEN]='\0';
	sprintf(pBuffer, "%s?%s", szWebServerAuthUrlArray[ndx], szCPSNonce);
//[
if(PathExt<'0' || PathExt>'9') {PathExt='-';}
LOG("PathExt: %c, Auth URL[%d]: %s, CPSNonce: %s", 
PathExt, ndx, szWebServerAuthUrlArray[ndx], szCPSNonce);
//]
	END();
}
