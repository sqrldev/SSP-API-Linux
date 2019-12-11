
// handler_mb MBedTLS server (derived from MBedTLS ssl_pthread_server.c)

#include "global.h"

#if defined NO_MBEDTLS

// None of the following code is used

#else

// Options required for this SSP_API
#define MBEDTLS_PEM_PARSE
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD

// This is NOT defined
#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

// This IS defined
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf
#define mbedtls_exit exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#include <stdlib.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

// This IS defined
#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

// This is NOT defined
#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
void mbedtls_param_failed(const char *failure_condition, const char *file, int line) {
	mbedtls_printf("%s:%i: Input param failed - %s\n", file, line, failure_condition);
	mbedtls_exit( MBEDTLS_EXIT_FAILURE );
}
#endif

//[fpf
// MBedTLS specific data we need to carry in the SQRL_CONTROL_BLOCK scb
typedef struct MBEDTLS_STRUCT_T {
	long int thread_id;
	mbedtls_ssl_context ssl;
	char szHeaders[1024];
} MBEDTLS_STRUCT;

static SQ_BOOL bFinished;

#define DEBUG_LEVEL 0
#define MAX_NUM_THREADS 1024
mbedtls_threading_mutex_t debug_mutex;

static void my_mutexed_debug(void *ctx, int level, const char *file, int line, const char *str ) {
    long int thread_id=(long int)pthread_self();
    mbedtls_mutex_lock(&debug_mutex);
//?	((void)level);
	mbedtls_fprintf((FILE *)ctx, "%s:%04d: [ #%ld ] %s", file, line, thread_id, str );
	fflush((FILE *)ctx);
    mbedtls_mutex_unlock( &debug_mutex );
}

typedef struct {
    mbedtls_net_context client_fd;
    int thread_complete;
    const mbedtls_ssl_config *config;
	char szClientIp[SQ_IP_LEN+1];
} thread_info_t;

typedef struct {
    int active;
    thread_info_t   data;
    pthread_t       thread;
} pthread_info_t;

static thread_info_t    base_info;
static pthread_info_t   threads[MAX_NUM_THREADS];

static void *handle_ssl_connection( void *data ) {
	BEG("handle_ssl_connection()");
	int ret, len;
	thread_info_t *thread_info=(thread_info_t *)data;
	mbedtls_net_context *client_fd=&thread_info->client_fd;
	long int thread_id=(long int)pthread_self();
	char buf[1024];
	mbedtls_ssl_context ssl;

	// Make sure memory references are valid
	mbedtls_ssl_init(&ssl);
	mbedtls_printf("[# %08lx ]  Setting up SSL/TLS data\n", thread_id );

    // * 4. Get the SSL context ready

    if((ret=mbedtls_ssl_setup(&ssl, thread_info->config))!=0) {
		mbedtls_printf("[# %08lx ]  failed: mbedtls_ssl_setup returned -0x%04x\n", thread_id, -ret);
        goto thread_exit;
    }
    mbedtls_ssl_set_bio(&ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // * 5. Handshake
	
	mbedtls_printf("[# %08lx ]  Performing the SSL/TLS handshake\n", thread_id);
	while((ret=mbedtls_ssl_handshake(&ssl))!=0) {
		if(ret!=MBEDTLS_ERR_SSL_WANT_READ && ret!=MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_printf("[# %08lx ]  failed: mbedtls_ssl_handshake returned -0x%04x\n", thread_id, -ret);
			goto thread_exit;
        }
    }
    mbedtls_printf("[# %08lx ]  ok\n", thread_id);

	// * 6. Read the HTTP Request

	mbedtls_printf("[# %08lx ]  < Read from client\n", thread_id);

//[fpf
//. is this right for multi-threading?
	SQRL_CONTROL_BLOCK scb;
	MBEDTLS_STRUCT mbedtls;
	
	memset(&scb, 0, sizeof(SQRL_CONTROL_BLOCK));
	memset(&mbedtls, 0, sizeof(MBEDTLS_STRUCT));
	mbedtls.thread_id=thread_id;
	mbedtls.ssl=ssl;
//]
	do {
		len=sizeof(buf)-1;
		memset(buf, 0, sizeof(buf));
		ret=mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

		if(ret==MBEDTLS_ERR_SSL_WANT_READ || ret==MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
		}
		if(ret<=0) {
			switch(ret) {
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
				mbedtls_printf("[# %08lx ]  connection was closed gracefully\n", thread_id);
				goto thread_exit;

				case MBEDTLS_ERR_NET_CONN_RESET:
				mbedtls_printf("[# %08lx ]  connection was reset by peer\n", thread_id);
				goto thread_exit;

				default:
				mbedtls_printf("[# %08lx ]  mbedtls_ssl_read returned -0x%04x\n", thread_id, -ret);
				goto thread_exit;
            }
        }
        len=ret;
        mbedtls_printf("[# %08lx ]  %d bytes read\n=====\n%s\n=====\n", thread_id, len, (char *) buf);

		if(ret>0) {
//[
printf("\r\n//[\r\n");
//]
		// Request-Line = Method <SP> Request-URI <SP> HTTP-Version <CRLF>
		char *pBuf=buf;
		char *pEnd=pBuf+len;
		
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

		scb.lpszRemoteAddr=thread_info->szClientIp;
printf("SCB.lpszRemoteAddr: %s\r\n", scb.lpszRemoteAddr);

printf("SCB.lpszHttpOrigin: %s\r\n", scb.lpszHttpOrigin);

		scb.lpHandlerStruct=&mbedtls;
		scb.pResponse=NULL;
printf("\r\n//]\r\n");
//]
            break;
		}
    }
    while( 1 );
//[fpf
	// Parse and process the query
	EnterCriticalSection(&DebugCriticalSection);
	
	LOG("Parse and Process the Query");

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
    ret = 0;

thread_exit:

// This IS defined
#if defined(MBEDTLS_ERROR_C)
	if(ret!=0 ) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100 );
		mbedtls_printf("[# %08lx ]  Last error was: -0x%04x - %s\n\n", thread_id, -ret, error_buf );
	}
#endif
	mbedtls_net_free(client_fd);
	mbedtls_ssl_free(&ssl);

	thread_info->thread_complete=1;

	END();
	return NULL;
}

static int thread_create( mbedtls_net_context *client_fd, char *pszClientIp ) {
	BEG("thread_create()");
    int ret, i;

    // * Find in-active or finished thread slot
	for(i=0; i<MAX_NUM_THREADS; i++) {
		if(threads[i].active==0) {
			break;
		}
        if(threads[i].data.thread_complete==1) {
			mbedtls_printf("[ MBedTLS ]  Cleaning up thread %d\n", i);
			pthread_join(threads[i].thread, NULL);
			memset(&threads[i], 0, sizeof(pthread_info_t));
			break;
		}
	}
	if(i==MAX_NUM_THREADS)
		return -1;

	// * Fill thread-info for thread

	memcpy(&threads[i].data, &base_info, sizeof(base_info));
	threads[i].active=1;
	memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));
//[fpf
	strcpy(threads[i].data.szClientIp, pszClientIp);
//]
    ret=pthread_create(&threads[i].thread, NULL, handle_ssl_connection, &threads[i].data);

	END();
    return ret;
}
#endif

SQ_RCODE InitSqrlHandlerMBedTLS() {
	BEG("InitSqrlHandlerMBedTLS()");
	SQ_RCODE rc=SQ_PASS;
	
#if defined NO_MBEDTLS
	LOG("NO_MBEDTLS is #defined");
#else
	const char *pCertFilename=szCertFilename;
	const char *pKeyFilename=szKeyFilename;
		
	int ret;
	mbedtls_net_context listen_fd, client_fd;
	const char pers[]="ssl_pthread_server";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt srvcert;
	mbedtls_x509_crt cachain;
	mbedtls_pk_context pkey;

// This IS defined
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
	mbedtls_ssl_cache_init(&cache);
#endif

	mbedtls_x509_crt_init(&srvcert);
	mbedtls_x509_crt_init(&cachain);

	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	memset(threads, 0, sizeof(threads));
	mbedtls_net_init(&listen_fd);
	mbedtls_net_init(&client_fd);

	mbedtls_mutex_init(&debug_mutex);

	base_info.config=&conf;

	// * We use only a single entropy source that is used in all the threads.
	mbedtls_entropy_init(&entropy);

	// * 1. Load the certificates and private RSA key
	
	mbedtls_printf("\n  . Loading the server cert. and key...");
	fflush(stdout);

    // * This demonstration program uses embedded test certificates.
    // * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
    // * server and CA certificates, as well as mbedtls_pk_parse_keyfile().

	ret=mbedtls_x509_crt_parse_file(&srvcert, pCertFilename);
	if(ret!=0) {
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_pk_init(&pkey);
	ret=mbedtls_pk_parse_keyfile(&pkey, pKeyFilename, "");

	if(ret!=0) {
		mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
		goto exit;
	}
	mbedtls_printf(" ok\n");

    // * 1b. Seed the random number generator

	mbedtls_printf("  . Seeding the random number generator...");

	if((ret=mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)))!=0) {
		mbedtls_printf(" failed: mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
		goto exit;
	}
    mbedtls_printf(" ok\n");

    // * 1c. Prepare SSL configuration

	mbedtls_printf("  . Setting up the SSL data....");

	if((ret=mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT))!= 0) {
		mbedtls_printf( " failed: mbedtls_ssl_config_defaults returned -0x%04x\n", -ret );
		goto exit;
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_mutexed_debug, stdout);

    // * mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if MBEDTLS_THREADING_C is set.

// This IS defined
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );
#endif

//[fpf
//    mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
    mbedtls_ssl_conf_ca_chain(&conf, &srvcert, NULL);
//]
    if((ret=mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey))!=0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
		goto exit;
	}
    mbedtls_printf(" ok\n");

    // * 2. Setup the listening TCP socket

	mbedtls_printf("  . Bind on %s ...", szListenUrl);
	fflush(stdout);

	if((ret=mbedtls_net_bind(&listen_fd, szListenIp, szListenPort, MBEDTLS_NET_PROTO_TCP))!=0) {
		mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
		goto exit;
	}
	mbedtls_printf(" ok\n");

reset:

// This IS defined
#if defined MBEDTLS_ERROR_C
	if(ret!=0) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		mbedtls_printf("[ MBedTLS ]  Last error was: -0x%04x - %s\n", -ret, error_buf);
	}
#endif

    // * 3. Wait until a client connects

	mbedtls_printf("[ MBedTLS ]  Waiting for a remote connection\n");

	unsigned char aClientIp[16]={0};
	size_t nClientIpLen=0;

//[ TEST 
	ret = mbedtls_net_set_nonblock( &listen_fd );
	bFinished=SQ_FALSE;

	while(1) {
		if((ret=mbedtls_net_accept(&listen_fd, &client_fd, aClientIp, sizeof(aClientIp), &nClientIpLen))!=0) {
			if(ret==MBEDTLS_ERR_SSL_WANT_READ) {
				continue;
			}	
			mbedtls_printf("[ MBedTLS ] failed: mbedtls_net_accept returned -0x%04x\n", ret);
			goto exit;
		}
	if (bFinished==SQ_TRUE) goto exit;
	break;
	} // while
// ]

	mbedtls_printf("[ MBedTLS ]  ok\n");
	mbedtls_printf("[ MBedTLS ]  ip:");

	for(int i=0; i<nClientIpLen; i++) mbedtls_printf(" %d", aClientIp[i]);
    mbedtls_printf("\n");
	
	// Convert ip to string "big-endian"
	// ipv4: 255.255.255.255
	// ipv6: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

///. Don't know if this is correct for ipv6 or not

	SQ_BYTE *pByte=(SQ_BYTE *)aClientIp;
	char szRemoteIp[SQ_IP_LEN+1];
	switch(nClientIpLen) {
		case 4: // bytes
		// ipv4
		sprintf(szRemoteIp, "%d.%d.%d.%d", 
			pByte[0], pByte[1], pByte[2], pByte[3]);
		break;
		
		case 16: // bytes
		// ipv6
		sprintf(szRemoteIp, "%x%x:%x%x:%x%x:%x%x%x%x:%x%x:%x%x:%x%x", 
			pByte[0], pByte[1], pByte[2], pByte[3],
			pByte[4], pByte[5], pByte[6], pByte[7],
			pByte[8], pByte[9], pByte[10], pByte[11],
			pByte[12], pByte[13], pByte[14], pByte[15]);
		break;
		
		default:
		sprintf(szRemoteIp, "?.?.?.?");
		break;
	}
	mbedtls_printf("[ MBedTLS ]  Creating a new thread\n");

	if((ret=thread_create(&client_fd, szRemoteIp))!=0) {
		mbedtls_printf("[ MBedTLS ]  failed: thread_create returned %d\n", ret);
		mbedtls_net_free(&client_fd);
		goto reset;
	}
	ret=0;
	goto reset;

exit:
	mbedtls_x509_crt_free(&srvcert);
	mbedtls_pk_free(&pkey);

// This IS defined
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free(&cache);
#endif
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ssl_config_free(&conf);

	mbedtls_net_free(&listen_fd);
	mbedtls_mutex_free(&debug_mutex);

	rc=(ret==0? SQ_PASS: SQ_FAIL);
#endif
	END();
	return rc;
}

char *GetHeadersBufferMBedTLS(SQRL_CONTROL_BLOCK *pSCB) {
	return ((MBEDTLS_STRUCT *)pSCB->lpHandlerStruct)->szHeaders;
	}
	
SQ_RCODE WriteClientMBedTLS(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pData, SQ_DWORD *pDataLen) {
	BEG("WriteClientMBedTLS()");
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
#if defined NO_MBEDTLS
		LOG("NO_MBEDTLS is #defined");
#else
		long int thread_id=((MBEDTLS_STRUCT*)(pSCB->lpHandlerStruct))->thread_id;
		mbedtls_ssl_context ssl=((MBEDTLS_STRUCT*)(pSCB->lpHandlerStruct))->ssl;
		char *pszHeaders=((MBEDTLS_STRUCT*)(pSCB->lpHandlerStruct))->szHeaders;

		mbedtls_printf("[# %08lx ]  > Write to client:\n", thread_id);

		int HeadersLen=strlen(pszHeaders);
		int len=HeadersLen+*pDataLen;
		int ret;
		
		unsigned char *pBuffer=(unsigned char *)GlobalAlloc(len);

		memcpy(pBuffer, pszHeaders, HeadersLen);
		memcpy(pBuffer+HeadersLen, pData, *pDataLen);
		
		while((ret=mbedtls_ssl_write(&ssl, pBuffer, len ))<=0) {
			if(ret==MBEDTLS_ERR_NET_CONN_RESET) {
				mbedtls_printf("[# %08lx ]  failed: peer closed the connection\n", thread_id);
				goto thread_exit;
			}

			if(ret!=MBEDTLS_ERR_SSL_WANT_READ && ret!=MBEDTLS_ERR_SSL_WANT_WRITE) {
				mbedtls_printf("[# %08lx ]  failed: mbedtls_ssl_write returned -0x%04x\n", thread_id, ret);
				goto thread_exit;
			}
		}

		len=ret;
		mbedtls_printf("[# %08lx ]  %d bytes written\n=====\n%s\n=====\n", thread_id, len, (char *)pBuffer);

	/// do we close the connection if we have a "keep-alive" header?

		mbedtls_printf("[# %08lx ]  . Closing the connection...", thread_id);

		while((ret=mbedtls_ssl_close_notify(&ssl))<0) {
			if(ret!=MBEDTLS_ERR_SSL_WANT_READ && ret!=MBEDTLS_ERR_SSL_WANT_WRITE) {
				mbedtls_printf("[# %08lx ]  failed: mbedtls_ssl_close_notify returned -0x%04x\n", thread_id, ret);
				goto thread_exit;
			}
		}
		mbedtls_printf(" ok\n");

thread_exit:
		GlobalFree((void **)&pBuffer);
		rc=(ret==0? SQ_PASS: SQ_FAIL);
#endif
	}

	END();
	return rc;
}
