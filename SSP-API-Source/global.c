
// global.c

#include "global.h"

SQ_BOOL SqrlApiRunning;
QUEUE PendingAuthsQueue;
const SQ_BYTE aSystemKey[BYTES_FOR_256_BITS];

const char *pszNull="";
const char *pszCRLF="\r\n";
const char *pszNutEquals="nut=";
const char *pszUserIdWithAccount="user=%s&stat=%s&name=%s&acct=%s";
const char *pszUserIdWithNoAccount="user=%s&stat=%s&name=%s";
const char *pszUrlPrefix="url=";
const char *pszPathPrefix="x=";
const char *pszSqrlOnly="SqrlOnly";
const char *pszHardLock="HardLock";
const char *pszDisabled="Disabled";
const char *pszRemove="Remove";
const char *pszRekeyed="Rekeyed";
const char *pszComma=",";

const char *pszBlockedPrivateQuery=
	"Private query to non-registered IP blocked: %s";
const char *pszQueryTokenList[]=
	{"user=", "acct=", "name=", "stat=", "invt="};
	
const char *pszNutAndCanLinkFormat=
	"%snut=%s&can=%s"
	;
const char *pszQRcodeFormat=
	"sqrl://%s/cli.sqrl?%snut=%s"
	;
const char *pszSQlinkFormat=
	"sqrl://%s/cli.sqrl?%snut=%s&can=%s"
	;
const char *pszEnumerationFormat=
	"user=%s&acct=%s&name=%s&stat=%s&invt=%s\r\n"
	;
const char *pszSqrlReplyFormat=
	"ver=1\r\n"
	"nut=%s\r\n"
	"tif=%X\r\n"
	"qry=/cli.sqrl?%snut=%s\r\n"
	;
const char *pszHttpResponseHeaderFormat=
	"Expires: Mon, 01 Jan 1990 00:00:00 GMT\r\n"
	"Content-Type: text/plain\r\n"
	"Cache-control: no-cache\r\n"
	"P3P: CP=\"NOI DSP COR NID NOR\"\r\n"
	"Pragma: no-cache\r\n"
	"Vary: Origin\r\n"
	"Access-Control-Allow-Origin: %s\r\n"
	"Connection: close\r\n"
//.	"Content-Length: %d\r\n"					// WriteResponseHeaders() does this
//.	"\r\n"										// WriteResponseHeaders()does this
	;
const char *pszHttpImageHeaderFormat=
	"Expires: Mon, 01 Jan 1990 00:00:00 GMT\r\n"
	"Content-Type: image/png\r\n"
	"Cache-control: no-cache\r\n"	
	"P3P: CP=\"NOI DSP COR NID NOR\"\r\n"	
	"Pragma: no-cache\r\n"
	"Vary: Origin\r\n"	
	"Access-Control-Allow-Origin: %s\r\n"
	"Connection: close\r\n"
//.	"Content-Length: %d\r\n"					// WriteResponseHeaders() does this
//.	"\r\n"										// WriteResponseHeaders() does this
	;
const char *pszHttpReplyHeaderFormat=
	"Content-Type: application/x-www-form-urlencoded\r\n"
	"Expires: Mon, 01 Jan 1990 00:00:00 GMT\r\n"
	"Cache-control: no-cache\r\n"
	"Pragma: no-cache\r\n"
	"Vary: Origin\r\n"
	"Access-Control-Allow-Origin: %s\r\n"
//.	"Content-Length: %d\r\n"					// WriteResponseHeaders() does this
//.	"\r\n"										// WriteResponseHeaders() does this
	;

const char *pszCfgFile=".sspapi.cfg";	

// The CfgNames must be in the same order as the CFG enums in global.h
// Lengths are 1 less than the allocated null-terminated string size 
CFG_INFO aCfgInfo[] ={
	{"MonotonicCounter=", (const char *)szMonotonicCounter, BYTES_FOR_64_BITS*2},
	{"HandlerName=", (const char *)szHandlerName, HANDLER_NAME_SIZ-1},
	{"CertFilename=", (const char *)szCertFilename, SQ_MAX_PATH-1},
	{"KeyFilename=", (const char *)szKeyFilename, SQ_MAX_PATH-1},
	{"ListenIP=", (const char *)szListenIp, SQ_IP_LEN},
	{"ListenPort=", (const char *)szListenPort, SQ_PORT_LEN},
	{"PrivateAccessIP=", (const char *)szPrivateAccessIp, SQ_IP_LEN},
	{"SystemKey=", (const char *)szSystemKey, BYTES_FOR_256_BITS*2},
	{"DatabaseKey=", (const char *)szDatabaseKey, DATABASE_KEY_LEN},
	{"TransactionLogging=", (const char *)szTransactionLogging, sizeof(char)},
	{"PublicAuthDomain=", (const char *)szPublicAuthDomain, SQ_MAX_URL-1},
	{"WebServerAuthURL0=", (const char *)szWebServerAuthUrlArray[0], SQ_MAX_URL-1},
	{"WebServerAuthURL1=", (const char *)szWebServerAuthUrlArray[1], SQ_MAX_URL-1},
	{"WebServerAuthURL2=", (const char *)szWebServerAuthUrlArray[2], SQ_MAX_URL-1},
	{"WebServerAuthURL3=", (const char *)szWebServerAuthUrlArray[3], SQ_MAX_URL-1},
	{"WebServerAuthURL4=", (const char *)szWebServerAuthUrlArray[4], SQ_MAX_URL-1},
	{"WebServerAuthURL5=", (const char *)szWebServerAuthUrlArray[5], SQ_MAX_URL-1},
	{"WebServerAuthURL6=", (const char *)szWebServerAuthUrlArray[6], SQ_MAX_URL-1},
	{"WebServerAuthURL7=", (const char *)szWebServerAuthUrlArray[7], SQ_MAX_URL-1},
	{"WebServerAuthURL8=", (const char *)szWebServerAuthUrlArray[8], SQ_MAX_URL-1},
	{"WebServerAuthURL9=", (const char *)szWebServerAuthUrlArray[9], SQ_MAX_URL-1},
};

const HTTP_STATUS_LOOKUP HttpStatusLookup[]={
	{200, "200 OK"},
//	{302, "302 Found"},
	{400, "400 Bad Request"},
	{404, "404 Not Found"},
	{410, "410 Gone"}
};

const CLIENT_TOKEN ClientTokens[]={
	{"ver=", QUERY_VER},
	{"cmd=", QUERY_CMD},
	{"opt=", QUERY_OPT},
	{"idk=", QUERY_IDK},
	{"pidk=", QUERY_PIDK},
	{"suk=", QUERY_SUK},
	{"vuk=", QUERY_VUK}
};
const int NumClientTokens=sizeof(ClientTokens)/sizeof(ClientTokens[0]);

const QUERY_TOKEN QueryTokens[]={
	{"client=", QUERY_CLIENT},
	{"server=", QUERY_SERVER},
	{"ids=", QUERY_IDS},
	{"pids=", QUERY_PIDS},
	{"urs=", QUERY_URS}
};
const int NumQueryTokens=sizeof(QueryTokens)/sizeof(QueryTokens[0]);

const CMD_OPT_TABLE CommandTable[]={
	{"query", CMD_QUERY},
	{"ident", CMD_IDENT},
	{"enable", CMD_ENABLE},
	{"disable", CMD_DISABLE},
	{"remove", CMD_REMOVE}
};
const int NumCommandItems=sizeof(CommandTable)/sizeof(CommandTable[0]);

const CMD_OPT_TABLE OptionTable[]={
	{"sqrlonly", OPT_SQRLONLY},
	{"hardlock", OPT_HARDLOCK},
	{"cps", OPT_CPS_MODE},
	{"suk", OPT_SUK_REQ},
	{"noiptest", OPT_NOIPTEST}
};
const int NumOptionItems=sizeof(OptionTable)/sizeof(OptionTable[0]);

// Count number of characters in a UTF-8 string
int Utf8Len(char *pszUtf8) {
	char *ptr=pszUtf8;
	int n=0;
	char c;
	
	while((c=*ptr)!='\0') {
		if((c&0x80)==0x00) { // 0bbbbbbb
			// 1 byte code
			n++;
			ptr++;
		}
		else if((c&0xe0)==0xc0) { // 110bbbbb
			// 2 byte code (extra bytes are 10bbbbbb)
			n++;
			ptr++;
			if((*ptr&0xc0)!=0x80) return 0; // UTF-8 encoding error
			ptr++;
		}
		else if((c&0xf0)==0xe0) { // 1110bbbb)
			// 3 byte code (extra bytes are 10bbbbbb)
			n++;
			ptr++;
			if((*ptr&0xc0)!=0x80) return 0; // UTF-8 encoding error
			ptr++;
			if((*ptr&0xc0)!=0x80) return 0; // UTF-8 encoding error
			ptr++;
		}
		else if((c&0xf8)==0xf0) { // 11110bbb)
			// 4 byte code (extra bytes are 10bbbbbb)
			n++;
			ptr++;
			if((*ptr&0xc0)!=0x80) return 0; // UTF-8 encoding error
			ptr++;
			if((*ptr&0xc0)!=0x80) return 0; // UTF-8 encoding error
			ptr++;
			if((*ptr&0xc0)!=0x80) return 0; // UTF-8 encoding error
			ptr++;
		}
	}
	return n;
}
