
// handler using Open SSL

#include "global.h"

// compile with libraries libssl and libcrypto

#include <unistd.h> // for close()
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct OPENSSL_STRUCT_T {
	long int thread_id;
	SSL *ssl;
	char szClientIp[1024];
	char szHeaders[1024];
} OPENSSL_STRUCT;


static SQ_BOOL bFinished;

// Once initialized, these are constant
//[not used] const char szListenProtocol[]="https://";
//[in configdata.c] const char szListenIp[SQ_IP_LEN+1]; // "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
//[in configdata.c] const char szListenPort[SQ_PORT_LEN+1]; // "65565"

//[
// needs modifying to accept AF_INET6 ip address too
//]
int create_socket() {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(strtol(szListenPort, NULL, 10));
    inet_pton(AF_INET, szListenIp, &addr.sin_addr.s_addr);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
    }
///[
// https://stackoverflow.com/questions/4163268/how-to-reuse-a-bound-port-with-openssl-api
//setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
///]
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
    }
    if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl() { 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, szCertFilename, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, szKeyFilename, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
    }
}

void ParseAndProcessRequest(SSL *ssl, char *pRequest, int Len) {
	BEG("ParseAndProcessRequest");
//[
//. can we even implement multi-threading in OpenSSL?
long int thread_id=(long int)pthread_self();
//]
	SQRL_CONTROL_BLOCK scb;
	OPENSSL_STRUCT openssl;
	
	memset(&scb, 0, sizeof(SQRL_CONTROL_BLOCK));
	memset(&openssl, 0, sizeof(OPENSSL_STRUCT));
	openssl.thread_id=thread_id;
	openssl.ssl=ssl;
	
	printf("Bytes received: %d\n", Len);
	printf("Data: ");
	for (int i=0; i<Len; i++) printf("%0x ", pRequest[i]);
	printf("\n");
	pRequest[Len]='\0';
	printf("%s\n", pRequest);
	printf("\n");

	int sock_fd;
	sock_fd=SSL_get_fd(ssl);
	printf("sock_fd: %d\n", sock_fd);

	struct sockaddr peeraddr;
	unsigned int peeraddrlen=sizeof(struct sockaddr)*2;
	int rc=getpeername(sock_fd, &peeraddr, &peeraddrlen);
rc=rc;

	printf("sa_family: %08x\n", peeraddr.sa_family);
	printf("sa_data[]hex: ");
	for (int i=0; i<peeraddrlen; i++) printf("%x ", (unsigned char)peeraddr.sa_data[i]);
	printf("\n");
	printf("sa_data[]dec: ");
	for (int i=0; i<peeraddrlen; i++) printf("%u ", (unsigned char)peeraddr.sa_data[i]);
	printf("\n");
	printf("\n");

	if (peeraddr.sa_family == AF_INET) {
		struct sockaddr_in *peeraddr_in=(struct sockaddr_in *)&peeraddr; 
		inet_ntop(AF_INET, &(peeraddr_in->sin_addr.s_addr), openssl.szClientIp, 1024 );
		printf("iv4: %s\n", openssl.szClientIp);
	} else if (peeraddr.sa_family == AF_INET6) {
		struct sockaddr_in6 *peeraddr_in=(struct sockaddr_in6 *)&peeraddr; 
		inet_ntop(AF_INET6, &(peeraddr_in->sin6_addr.s6_addr), openssl.szClientIp, 1024 );
		printf("iv6: %s\n", openssl.szClientIp);
	} else {
		printf("Unknown socket type passed to worker(): %i\n", peeraddr.sa_family);
	}

	// Request-Line = Method <SP> Request-URI <SP> HTTP-Version <CRLF>
	char *pBuf=pRequest;
	char *pEnd=pBuf+Len;
		
	// Get the Method
	while(*pBuf==' ' || *pBuf=='\r' || *pBuf=='\n') pBuf++;
	if(pBuf<pEnd) scb.lpszMethod=pBuf;
	while(*pBuf!=' ' && *pBuf!='\r' && *pBuf!='\n') pBuf++;
	if(pBuf<pEnd) *pBuf='\0';
//[
printf("SCB.lpszMethod: %s\r\n", scb.lpszMethod);
//]
	// Get the Request PathInfo
	pBuf++;
	while(*pBuf==' ' || *pBuf=='\r' || *pBuf=='\n') pBuf++;
	if(pBuf<pEnd) scb.lpszPathInfo=pBuf;
	while(*pBuf!=' ' && *pBuf!='?' && *pBuf!='\r' && *pBuf!='\n') pBuf++;
	char q=*pBuf;
	if(pBuf<pEnd) *pBuf='\0';
//[
printf("SCB.lpszPathInfo: %s\r\n", scb.lpszPathInfo);
//]		
	// Get the Query
	if(q=='?') {
		pBuf++;
		if(pBuf<pEnd) scb.lpszQueryString=pBuf;
		while(*pBuf!=' ' && *pBuf!='\r' && *pBuf!='\n') pBuf++;
		if(pBuf<pEnd) *pBuf='\0';
	}
//[
printf("SCB.lpszQueryString: %s\r\n", scb.lpszQueryString);
//]		
	// Get The HTTP-Version (we don't use it)
	pBuf++;
	while(*pBuf==' ' || *pBuf=='\r' || *pBuf=='\n') pBuf++;
	char *lpszHTTPVersion='\0';
	if(pBuf<pEnd) lpszHTTPVersion=pBuf;
	while(*pBuf!=' ' && *pBuf!='\r' && *pBuf!='\n') pBuf++;
	if(pBuf<pEnd) *pBuf='\0';
//[
printf("HTTP Version: %s\r\n", lpszHTTPVersion);
//]		
	// Advance to the Headers
	pBuf++;
	while(*pBuf==' ' || *pBuf=='\r' || *pBuf=='\n') pBuf++;
	char *pHeadersBeg; // start of headers
	if(pBuf<pEnd) pHeadersBeg=pBuf;
		
	// Parse the buffer into headers and data
		
	// Find the end of the headers ( <CRLF><CRLF> )
	while(memcmp(pBuf, "\r\n\r\n", 4)!=0) pBuf++;
	pBuf+=2; // skip past the first <CRLF>
	if(pBuf<pEnd) *pBuf='\0';
//[
printf("HTTP HeaderLen: %d\r\n", (int)(pBuf-pHeadersBeg));
printf("HTTP Headers: \r\n");
//]
	ProcessHeaders(&scb, pHeadersBeg);
		
	// Advance to the Data
	pBuf++;
	while(*pBuf==' ' || *pBuf=='\r' || *pBuf=='\n') pBuf++;
	char *pDataBeg; // end of headers, start of data
	if(pBuf>=pEnd) {
		// There is no data
		pDataBeg=pEnd;
	} else {
		pDataBeg=pBuf;
	}
	char *pDataEnd=pEnd;
/// can we make this '\0' ?	
printf("HTTP DataLen: %d\r\n", (int)(pDataEnd-pDataBeg));
		
	// Get the data length
	scb.DataLen=pDataEnd-pDataBeg;
printf("SCB.DataLen %d\r\n", scb.DataLen);

	// Get the data
	scb.lpData=pDataBeg;
printf("HTTP Data: %s\r\n", scb.lpData);
		
	strcpy(scb.szServerPort, szListenPort);
printf("SCB.lpszServerPort: %s\r\n", scb.szServerPort);

printf("SCB.lpszHttpHost: %s\r\n", scb.lpszHttpHost);

printf("SCB.lpszHttpReferrer: %s\r\n", scb.lpszHttpReferrer);

	scb.lpszRemoteAddr=openssl.szClientIp;
printf("SCB.lpszRemoteAddr: %s\r\n", scb.lpszRemoteAddr);

printf("SCB.lpszHttpOrigin: %s\r\n", scb.lpszHttpOrigin);

	scb.lpHandlerStruct=&openssl;
	scb.pResponse=NULL;
printf("\r\n//]\r\n");

	EnterCriticalSection(&DebugCriticalSection);

	LOG("  Method: %s", scb.lpszMethod);
	LOG("PathInfo: %s", scb.lpszPathInfo);
	LOG("   Query: %s", scb.lpszQueryString);

//[ FOR TESTING
	if(strcmp(scb.lpszPathInfo, "/end.sqrl")==0) {
		bFinished=SQ_TRUE;
	}
	else if(strcmp(scb.lpszPathInfo, "/del.sqrl")==0) {
		CloseBerkeleyDBs();
		DeleteSqrlDatabaseFiles();
		bFinished=SQ_TRUE;
	}
	else 
//]
	HttpExtensionProc(&scb);

	LOG("");
	LeaveCriticalSection(&DebugCriticalSection);
//]
	END();
}

SQ_RCODE InitSqrlHandlerOpenSSL() {
	BEG("InitSqrlHandlerOpenSSL()");
	SQ_RCODE rc=SQ_PASS;
	
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket();

    /* Handle connections */
	
    while (bFinished==SQ_FALSE) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
LOG("OpenSSL: accept() client=%d", client);
        if (client < 0) {
			END();
            return SQ_FAIL;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
			char buf[1024];
			int r = SSL_read(ssl, buf, 1024);
			
			if(r<=0) {
				// Handle the error
				switch (r) {
					default:
					printf("SSL_read returned error code %d", r);
					break;
				}
			}
			else {
				// Parse and process the request
				ParseAndProcessRequest(ssl, buf, r);
			}
		}
        SSL_free(ssl);
        close(client);
LOG("openSSL: client closed");
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
	
	END();
	return rc;
}

char *GetHeadersBufferOpenSSL(SQRL_CONTROL_BLOCK *pSCB) {
	return ((OPENSSL_STRUCT *)pSCB->lpHandlerStruct)->szHeaders;
	}
	
SQ_RCODE WriteClientOpenSSL(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pData, SQ_DWORD *pDataLen) {
	BEG("WriteClient()");
	LOG("Data:");
	LOG("Beg...");
	LOG("[]", pData, *pDataLen);
	LOG("...End");

	SQ_RCODE rc=SQ_PASS;

	if(pSCB->pResponse!=NULL) {
		pSCB->pResponse->pData=GlobalAlloc(*pDataLen);
		memcpy(pSCB->pResponse->pData, pData, *pDataLen);
		pSCB->pResponse->DataLen=*pDataLen;
	}
	else {
//		long int thread_id=((OPENSSL_STRUCT *)(pSCB->lpHandlerStruct))->thread_id;
		SSL *pSSL=((OPENSSL_STRUCT *)(pSCB->lpHandlerStruct))->ssl;
		char *pszHeaders=((OPENSSL_STRUCT *)(pSCB->lpHandlerStruct))->szHeaders;
		
		int HeadersLen=strlen(pszHeaders);
		int len=HeadersLen+*pDataLen;
		int ret;
		
		unsigned char *pBuffer=(unsigned char *)GlobalAlloc(len);

		memcpy(pBuffer, pszHeaders, HeadersLen);
		memcpy(pBuffer+HeadersLen, pData, *pDataLen);

		ret=SSL_write(pSSL, pBuffer, len);
/// check ret value

		GlobalFree((void **)&pBuffer);
		rc=(ret=0? SQ_PASS: SQ_FAIL);
	}
	
	END();
	return rc;
}

