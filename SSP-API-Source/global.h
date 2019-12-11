
// global.h

#ifndef GLOBAL_H
#define GLOBAL_H

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <linux/random.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "dbglog.h"
#include "sqtypes.h"
#include "sspapi.h"

// The CfgNames must be in the same order as in CFG_INFO aCfgInfo[] in global.c
enum {
	CFG_MONOTONIC_COUNTER,
	CFG_HANDLER_NAME,
	CFG_CERT_FILENAME,
	CFG_KEY_FILENAME,
	CFG_LISTEN_IP,
	CFG_LISTEN_PORT,
	CFG_PRIVATE_ACCESS_IP,
	CFG_SYSTEM_KEY,
	CFG_DATABASE_KEY,
	CFG_TRANSACTION_LOGGING,
	CFG_PUBLIC_AUTH_DOMAIN,
	CFG_WEB_SERVER_AUTH_URL0,
	CFG_WEB_SERVER_AUTH_URL1,
	CFG_WEB_SERVER_AUTH_URL2,
	CFG_WEB_SERVER_AUTH_URL3,
	CFG_WEB_SERVER_AUTH_URL4,
	CFG_WEB_SERVER_AUTH_URL5,
	CFG_WEB_SERVER_AUTH_URL6,
	CFG_WEB_SERVER_AUTH_URL7,
	CFG_WEB_SERVER_AUTH_URL8,
	CFG_WEB_SERVER_AUTH_URL9,
	
	CFG_NUM_ITEMS
};
enum {
	USER_ID_FIELD_SIZ	=16,		// 15+1 Sqrl User ID field size 
	USER_ID_LEN			=12,		// 12 chars base64url (72 bits)
	SQRL_NUT_LEN		=12,		// 12 chars base64url (72 bits)
	BINARY_KEY_LEN		=32,		// bytes needed for 256 bits
	ASCII_KEY_LEN		=43,		// 32 bytes expands to 43 chars 
	ASCII_BUF_LEN		=44,		// 43 chars + Terminating null
	ASCII_SIG_LEN		=86,		// 64 bytes expands to 86 chars

	DATABASE_KEY_LEN	=32,		// 32 character password key

	INVITATION_TOKEN_LEN=20,		// 20 chars ASCII token string
	CPS_TOKEN_LEN		=24,		// 24 chars base64url (144 bits)
	SIGNATURE_LEN		=64			// ids, pids, urs
};
enum {
	QUERY_STRING_LEN	=16,
	MINIMUM_CLIENT_QUERY=200,	// client query must be at least
	MAXIMUM_CLIENT_QUERY=4000	// make sure it's not too long
};
enum {
	QUERY_NUT	=0x0001,
	QUERY_CLIENT=0x0002,
	QUERY_SERVER=0x0004,
	QUERY_IDS	=0x0008,
	QUERY_PIDS	=0x0010,
	QUERY_URS	=0x0020,
	QUERY_VER	=0x0040,
	QUERY_CMD	=0x0080,
	QUERY_OPT	=0x0100,
	QUERY_IDK	=0x0200,
	QUERY_PIDK	=0x0400,
	QUERY_SUK	=0x0800,
	QUERY_VUK	=0x1000
};
enum {
	VALID_IDS	=0x0001,
	VALID_PIDS	=0x0002,
	VALID_URS	=0x0004
};
enum{
	QUERY_MAC_INVALID	=0x80000000, // bad ServerMAC from client
	QUERY_NUT_INVALID	=0x40000000,
	PENDING_AUTH_VALID	=0x20000000
};
enum {
	CURRENT_ID_MATCH	=0x0001,
	PREVIOUS_ID_MATCH	=0x0002,
	IP_ADDRESS_MATCH	=0x0004,
	SQRL_DISABLED		=0x0008,
	CMD_NOT_SUPPORTED	=0x0010,
	TRANSIENT_ERROR		=0x0020,
	COMMAND_FAILED		=0x0040,
	CLIENT_FAILED		=0x0080,
	WRONG_SQRL_ID		=0x0100,
	SUPERSEDED_ID		=0x0200
};
enum {
	PATH_INFO_LEN		=9,			// /xxx.sqrl is 9 chars
	BYTES_FOR_64_BITS	=8,
	BYTES_FOR_256_BITS	=32,
	SHA256_BYTE_LEN		=32,
	BLOWFISH_KEY_LEN	=32,
	IPV4_BYTE_LEN		=4,
	IPV6_BYTE_LEN		=16,
	PENDING_AUTH_EXP	=60*60		//  one hour association expiration
};
enum {
	CMD_QUERY		=0x01,
	CMD_IDENT		=0x02,
	CMD_DISABLE		=0x04,
	CMD_ENABLE		=0x08,
	CMD_REMOVE		=0x10
};
enum {
	OPT_SQRLONLY	=0x01,
	OPT_HARDLOCK	=0x02,
	OPT_NOIPTEST	=0x04,		
	OPT_CPS_MODE	=0x08,		
	OPT_SUK_REQ		=0x10
};
enum {
	AUTH_DISABLED	=0x01,	// static account status bit flags
	REMOVE_REQUESTED=0x02,	//user is requesting disassociation
	USER_REKEYED	=0x04	// set until we've reported this to the server
};

// SqrlHandler
typedef enum {
	NO_HANDLER,
	SQ_OPENSSL,
	SQ_MBEDTLS
} SQ_HANDLER;

enum {
	HANDLER_NAME_SIZ=16,	// 15+1 for "MBedTLS", "OpenSSL" or other handlers in .sspapi.cfg
	SQ_IP_LEN		=sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"), // 45,
	SQ_PORT_LEN		=sizeof("65535"), // 5,

	// For the SSP API only, x=n is restricted to 1 digit (0-9)
	SQ_EXT_LEN		=sizeof("9"),

	SQ_MAX_URL		=256,
	SQ_MAX_PATH		=260,
};
	
typedef struct CRITICAL_SECTION_T {
	pthread_mutex_t	Lock;
	int count;
} CRITICAL_SECTION;

typedef struct HTTP_STATUS_LOOKUP_T {
	int Status;
	char *pStatus;
} HTTP_STATUS_LOOKUP; 

typedef enum HTTP_STATUS_T {
	HTTP_OK,
	HTTP_FOUND,
	HTTP_BAD_REQUEST,
	HTTP_NOT_FOUND,
	HTTP_GONE
} HTTP_STATUS;
	
typedef struct QUEUE_OBJECT_T {
	struct QUEUE_OBJECT_T *pPriorObject;	// non-null pointer to prior object
	struct QUEUE_OBJECT_T *pNextObject;	// non-null pointer to next object
	union {
		SQ_DWORD TimeStamp;		// system time of last activity (sec.)
		SQ_DWORD DataPtr;
		SQ_DWORD ObjectData1;
	};
	union {
		SQ_DWORD ObjectTag;		// a 32-bit object association
		SQ_DWORD DataLen;   
		SQ_DWORD ObjectData2;
	}; 
} QUEUE_OBJECT;

typedef struct QUEUE_T {
	QUEUE_OBJECT *pFirstInQueue;	// pointer to next object to be removed
	QUEUE_OBJECT *pLastInQueue;		// pointer to last object added
	SQ_DWORD ObjectCount;			// count of objects in queue
	CRITICAL_SECTION CriticalSection;
} QUEUE;

typedef struct PENDING_AUTHS_T {
	QUEUE_OBJECT QueueObject;		// GRC's standard QUEUE management obj
	SQ_CHAR aBrowserNut[12];		// the initial 12-character nut nonce
	SQ_CHAR	aProtocolNut[12];		// successive 12-character nut nonces
	SQ_CHAR	szSqrlPublicKey[44];	// the user's valid SQRL ID
	SQ_CHAR	szInvitation[24];		// an invitation pending on this session
	SQ_CHAR	aRequestIP[16];			// the requestor's IPv6 IP
	SQ_CHAR	aCPSNonce[24];			// the 24-character CPS nonce
	SQ_BYTE	aTransactionMAC1[32];	// HMAC256 hash with "&can=..." appended
	SQ_BYTE	aTransactionMAC2[32];	// HMAC256 hash without "&can=..."
	SQ_DWORD OptionsValue;			// the SQRL client's 'opt' value
	SQ_CHAR szPathExtension[7+1];	// null string or x=n& from /nut.sqrl? param
	SQ_CHAR *pszNextPageURL;		// a global alloc containing the URL
	SQ_CHAR *pszLoginPageURL	;	// a global alloc with the requesting URL
} PENDING_AUTHS;

typedef struct HEADER_ITEM_T {
	char *pKey;
	char *pVal;
} HEADER_ITEM;

enum {
	MAX_HEADERS=16
};

// SSP-API Configuration File 
extern const char *pszCfgFile;

typedef struct CFG_INFO_T {
	const char *pszName;
	const char *pszVariable;
	const int Length; // string length for char sz<Variable>[Length+1]
} CFG_INFO;

extern CFG_INFO aCfgInfo[];

typedef struct CFG_ITEM_T{
	char *pszValue;
	char *pComments;
	int NumComments;
} CFG_ITEM;

extern int NumCfgItems;

/*
===============================================================================
	CLIENT TO SERVER
	A pointer to an instance of this structure is passed to "ParseClientQuery" by
	"HandleClientQuery".  "ParseClientQuery" parses and examines every aspect of
	the client's SQRL protocol query. It sets flags & verifies client signatures.
-------------------------------------------------------------------------------
	This structure holds the received and parsed query parameters.	     
----------------------------------------------------------------------------
*/
typedef struct CLIENT_TO_SERVER_T {
	SQ_DWORD DataPresent;			// flags for data that's valid
	SQ_DWORD SignaturesValid;		// flags for valid signatures
	SQ_CHAR *pszVer;					// pointer to the returned ver= string
	SQ_DWORD cmd;					// request command bit flags
	SQ_DWORD opt;					// request options bit flags
	SQ_CHAR nut[12];				// the 12-charater nut nonce
	SQ_BYTE idk[32];
	SQ_BYTE pidk[32];
	SQ_BYTE suk[32];
	SQ_BYTE vuk[32];
	SQ_BYTE ids[SIGNATURE_LEN];
	SQ_BYTE	pids[SIGNATURE_LEN];
	SQ_BYTE	urs[SIGNATURE_LEN];
	SQ_VOID *pSigningBuf;			// pointer to aloocated signature buffer
	SQ_DWORD SigningBufLen;			// length of the signature buffer
} CLIENT_TO_SERVER;

/*
===============================================================================
	SQRL ASSOCIATIONS
-------------------------------------------------------------------------------
	This is the database template for managing our SQRL ID -to- Account mapping.
	It is keyed by its first and second records: the 44-character szSqrlPublicKey
	and the web server's account as an ASCII string up to 64 characters. It maps
	the user's SQRL ID to the web server's internal account and holds SQRL keys
	and other management data. To support Managed Shared Access, it also provides
	a szUserHandle to allow managers to know whose SQRL ID this is and a szStatus
	string for general purpose management needs.
-------------------------------------------------------------------------------
*/
typedef struct ASSOC_REC_DATA_T {
	SQ_CHAR szAccount					[68];		// the webserver's user account
	SQ_CHAR szUserHandle				[68];		// a friendly username for mgmt
	SQ_CHAR szStatus					[68];		// undefined server data

	SQ_BYTE aSqrlPublicIdentity			[32];		// 32-byte SQRL public key
	SQ_BYTE aSqrlServerUnlockKey		[32];		// the DH IDLock data
	SQ_BYTE aSqrlVerifyUnlockKey		[32];		//	"	"
	SQ_QWORD SqrlLastActivityDate;					// used to purge unlinked entries
	SQ_DWORD SqrlOptionFlags;						// auth disabled, maybe others
} ASSOC_REC_DATA;

typedef struct SQRL_ASSOCIATIONS_T {
	SQ_CHAR szSqrlUser[USER_ID_FIELD_SIZ];			// for 12-character static SQRL user
	ASSOC_REC_DATA AssocRecData;
} SQRL_ASSOCIATIONS;

/*
===============================================================================
	SUPERSEDED IDENTITIES
-------------------------------------------------------------------------------
	This is the database template used for logging all retired SQRL identities
	the SSPAPI has ever encountered. EVERY "Previous" ID it encounters is added
	to this database which is indexed on the 32-byte PreviousID. If any attempt
	is ever made to present one of these retired identities as a CurrentID, the
	operation is immediately failed with a TIF error return having its 0x200 bit.
-------------------------------------------------------------------------------
*/
typedef struct SUPERSEDED_IDENTITIES_T {
	SQ_BYTE aSupersededIdentity			[32];		// 32-byte SQRL public key
} SUPERSEDED_IDENTITIES;

/*
===============================================================================
	QUERY PARAMS
-------------------------------------------------------------------------------
	The Add and Remove queries may provide all or some of the parameters pointed
	to by this structure. This structure is populated by "ParseQueryParams".
-------------------------------------------------------------------------------
*/
typedef struct QUERY_PARAMS_T {
	SQ_CHAR *pszSqrlUser;
	SQ_CHAR *pszAccount;
	SQ_CHAR *pszUserHandle;
	SQ_CHAR *pszStatus;
	SQ_CHAR *pszInvite;
} QUERY_PARAMS;

// An element of ClientTokens[]
typedef struct CLIENT_TOKEN_T {
	char *pName;
	SQ_DWORD BitMask;
} CLIENT_TOKEN;

// An element of QueryTokens[]
typedef struct QUERY_TOKEN_T {
	char *pName;
	SQ_DWORD BitMask;
} QUERY_TOKEN;

// An element of CommandTable[] or OptionsTable[]
typedef struct CMD_OPT_TABLE_T {
	SQ_CHAR *pszName;
	SQ_DWORD FlagBit;
} CMD_OPT_TABLE;

//[
extern CRITICAL_SECTION DebugCriticalSection;
extern char *pStack[];
extern int StackNdx;
//]
extern CRITICAL_SECTION IncDataCriticalSection;

extern QUEUE PendingAuthsQueue;
extern SQ_BOOL SqrlApiRunning;

extern const HTTP_STATUS_LOOKUP HttpStatusLookup[];

extern const char *pszNull;
extern const char *pszNutEquals;
extern const char *pszUrlPrefix;
extern const char *pszPathPrefix;
extern const char *pszNutAndCanLinkFormat;
extern const char *pszQRcodeFormat;
extern const char *pszSQlinkFormat;
extern const char *pszHttpResponseHeaderFormat;
extern const char *pszHttpReplyHeaderFormat;
extern const char *pszHttpImageHeaderFormat;
extern const char *pszUserIdWithAccount;
extern const char *pszUserIdWithNoAccount;
extern const char *pszBlockedPrivateQuery;
extern const char *pszEnumerationFormat;
extern const char *pszQueryTokenList[];

extern const char *pszPathPrefix;
extern const char *pszSqrlOnly;
extern const char *pszHardLock;
extern const char *pszDisabled;
extern const char *pszRemove;
extern const char *pszRekeyed;
extern const char *pszComma;

extern SQ_CHAR szMonotonicCounter[];

extern const SQ_CHAR szHandlerName[];
extern const SQ_CHAR szCertFilename[];
extern const SQ_CHAR szKeyFilename[];
extern const SQ_CHAR szListenIp[];
extern const SQ_CHAR szListenPort[];
extern const SQ_CHAR szPrivateAccessIp[];
extern const SQ_CHAR szSystemKey[];
extern const SQ_CHAR szDatabaseKey[]; 
extern const SQ_CHAR szTransactionLogging[];
extern const SQ_CHAR szPublicAuthDomain[];
extern const SQ_CHAR szWebServerAuthUrlArray[][SQ_MAX_URL];

extern const SQ_HANDLER nHandlerName;
extern const SQ_CHAR szListenUrl[];
extern const SQ_BYTE aSystemKey[];
extern const SQ_BOOL bEnableTransactionLogging;

extern const CLIENT_TOKEN ClientTokens[];
extern const int NumClientTokens;
extern const QUERY_TOKEN QueryTokens[];
extern const int NumQueryTokens;
extern const CMD_OPT_TABLE CommandTable[];
extern const int NumCommandItems;
extern const CMD_OPT_TABLE OptionTable[];
extern const int NumOptionItems;

extern const SQ_CHAR *pszSqrlReplyFormat;

// Functions

// base64url.c
int GetBase64urlEncodedSize(int len);
int GetBase64urlDecodedSize(int len);
int Base64urlEncode(const unsigned char *in, int len, char *out, int siz);
int Base64urlDecode(const char *in, int len, unsigned char *out, int siz);
SQ_DWORD SqrlCvrtToBase64(SQ_CHAR *pOut, SQ_DWORD SizOut, const SQ_BYTE *pIn, SQ_DWORD LenIn);
SQ_DWORD SqrlCvrtFromBase64(SQ_BYTE *pOut, SQ_DWORD SizeOut, const SQ_CHAR *pIn, SQ_DWORD LengthIn);
SQ_DWORD CvrtToBase64String(SQ_CHAR *pOut, SQ_DWORD SizOut, const SQ_BYTE *pIn, SQ_DWORD LenIn);
void DecodeBase64szAndStore(SQ_BYTE **ppszDecoded, const SQ_CHAR *pBase64sz);

// browser.c
SQ_CHAR *GetStringInGlobalAlloc(SQ_CHAR *pString);
void GetQueryParamNut(SQ_CHAR *pszNutBuffer, SQRL_CONTROL_BLOCK *pSCB);
void SetLoginPageUrl(PENDING_AUTHS *pPendingAuth, SQRL_CONTROL_BLOCK *pSCB);
SQ_VOID SubmitCpsAuth(SQRL_CONTROL_BLOCK *pSCB);
void TriggerNonCpsAuth(PENDING_AUTHS *pPendingAuth, SQRL_CONTROL_BLOCK *pSCB);
SQ_VOID GetSessionNut(SQRL_CONTROL_BLOCK *pSCB);
SQ_VOID GetQRcode(SQRL_CONTROL_BLOCK *pSCB);
SQ_VOID GetNextPage(SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE ListSupersededIDs(SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE ListPendingAuths(SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE ListDatabase(SQRL_CONTROL_BLOCK *pSCB);
SQ_VOID SetPathExtensionString(SQ_CHAR *pszPathExtension, SQRL_CONTROL_BLOCK *pSCB);
PENDING_AUTHS *PrepPendingAuthObject(SQRL_CONTROL_BLOCK *pSCB);

// client.c
void CommandOptionParser(SQ_DWORD *pResultFlags, const CMD_OPT_TABLE ArgsTable[], int NumItems, SQ_CHAR *pszArgList);
SQ_RCODE ParseClientQuery (CLIENT_TO_SERVER *pParams, PENDING_AUTHS **ppPendingAuth, SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE SanityCheckAsciiKey(SQ_CHAR *pKey);
SQ_CHAR *NullTerminateString(SQ_CHAR *ptr);
SQ_RCODE HandleClientQuery(SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE SendResponse(SQRL_CONTROL_BLOCK *pSCB, CLIENT_TO_SERVER *pQueryParams, SQ_DWORD TransInfo, SQRL_ASSOCIATIONS *pSqrlAssoc, PENDING_AUTHS *pPendingAuth);
void UpdateSqrlAssociationRecord(SQRL_ASSOCIATIONS *pSqrlAssoc, CLIENT_TO_SERVER *pQueryParams);

// configdata.c
SQ_RCODE ReadCfgFile(CFG_ITEM **ppCfgItems, char **ppData);
SQ_RCODE WriteCfgFile(CFG_ITEM *pCfgItems, char *pData);
int HexToNybble(int h);
int NybbleToHex(int n);
SQ_RCODE CreateFile(FILE **ppFile, const char *pFilename, char *pMode);
SQ_RCODE OpenFile(FILE **ppFile, const char *pFilename, char *pMode);
SQ_RCODE CloseFile(FILE **ppFile);
SQ_RCODE InitSqrlCfgData();
SQ_RCODE Get64BitCounter(SQ_BYTE *pCounterByteArray);
SQ_RCODE Set64BitCounter(SQ_BYTE *pCounterByteArray);
SQ_RCODE SetCfgItem(int ItemIndex, char *pszItemValue);

// criticalsection.c
int InitializeCriticalSection(CRITICAL_SECTION *pLock);
int DeleteCriticalSection(CRITICAL_SECTION *pLock);
SQ_BOOL EnterCriticalSection(CRITICAL_SECTION *pLock);
SQ_BOOL LeaveCriticalSection(CRITICAL_SECTION *pLock);

// crypto.c
SQ_RCODE HMAC256(SQ_BYTE *pHashOut, SQ_BYTE *pSourceToHMAC, SQ_DWORD Len, const SQ_BYTE *pHashKey);
SQ_RCODE SqrlVerifySig(SQ_BYTE *pMsg, SQ_DWORD uMsgLen, SQ_BYTE *pSig, SQ_BYTE *pPubKey);

// database.c
void SweepNightlyAbandonedInvitations();
void SweepNightlyAbandonedAuthentications();
void *DatabaseSweepThread(SQ_VOID *Dummy);
void TerminateDatabaseSweeper();
void GetDatabasePathname(SQ_CHAR *pszDatabasePath);
void SyncAllBDB();
void DeleteSqrlDatabaseFiles();
SQ_RCODE OpenSqrlDatabaseFiles();
SQ_RCODE CloseBerkeleyDBs();
SQ_RCODE StoreSqrlRecord(SQRL_ASSOCIATIONS *pSqrlDataRecord);
SQ_RCODE GetRecordByUserID(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_CHAR *pszUserId);
SQ_RCODE GetRecordBySqrlID(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_CHAR *pszSqrlId);
SQ_RCODE GetRecordBySqrlKey(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_BYTE *p_idk);
SQ_RCODE GetRecordByInvitation(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_CHAR *pszInvitation);
SQ_RCODE DeleteSqrlRecord(SQRL_ASSOCIATIONS *pSqrlAssocRec);
SQ_RCODE LogSupersededID(SUPERSEDED_IDENTITIES *pSupersededIdentity);
SQ_RCODE CheckForSupersededID(SUPERSEDED_IDENTITIES *pSupersededIdentity);
SQ_CHAR *GetListOfAssociations(SQ_CHAR *pszAccount);
void UpdateByAccount(QUERY_PARAMS *pQueryParams, SQ_BOOL Remove);
char *GetBerkeleyMainDatabase();
char *GetSupersededIDs();

// global.c
int Utf8Len(char *pszUtf8);

// handler.c
SQ_RCODE InitSqrlHandler();
SQ_RCODE WriteResponseHeaders(SQRL_CONTROL_BLOCK *pSCB, HTTP_STATUS Status, SQ_CHAR *pszHeaders, SQ_DWORD DataLen);
SQ_RCODE WriteClient(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pData, SQ_DWORD *pDataLen);
SQ_RCODE ProcessHeaders(SQRL_CONTROL_BLOCK *pSCB, char *pHeaders);

// handler-openssl.c
SQ_RCODE InitSqrlHandlerOpenSSL();
char *GetHeadersBufferOpenSSL();
SQ_RCODE WriteClientOpenSSL(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pData, SQ_DWORD *pDataLen);

// handler-mbedtls.c
SQ_RCODE InitSqrlHandlerMBedTLS();
char *GetHeadersBufferMBedTLS();
SQ_RCODE WriteClientMBedTLS(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pData, SQ_DWORD *pDataLen);

// pendingauths.c
void DeletePendingAuthAllocs(void *pObject);
void DeletePendingAuthObject(void *pObject);
PENDING_AUTHS *LookupByNut(PENDING_AUTHS *pPendingAuth, SQ_CHAR *pNut, SQ_BOOL bUpdateObject, SQ_BOOL bProtocolNut, SQRL_CONTROL_BLOCK *pSCB);
PENDING_AUTHS *LookupByCPS(PENDING_AUTHS *pPendingAuth, SQ_VOID *pCPSnonce, SQ_BOOL bUpdateObject);
void SetInitialAuthMacs(PENDING_AUTHS *pPendingAuth, SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE CreateQueue(QUEUE *pQueue);
SQ_RCODE DeleteQueue(QUEUE *pQueue, SQ_PROCPTR pDestructor);
SQ_RCODE Enqueue(QUEUE *pQueue, QUEUE_OBJECT *pNewObject);
QUEUE_OBJECT *Dequeue(QUEUE *pQueue);
SQ_RCODE DequeueObject(QUEUE *pQueue, QUEUE_OBJECT *pQueueObject);
char *GetPendingAuths();

// qrcode.c
void SendStringAsQRcodeImage(SQRL_CONTROL_BLOCK *pSCB, SQ_CHAR *pszStringToConvert);

// response.c
SQ_RCODE SendSqrlReply(SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pReplyData, SQ_DWORD ReplyLength, SQ_RCODE Success);
SQ_RCODE ReturnStringToCaller(SQ_CHAR *pszResponseString, SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE ReturnImageToClient (SQRL_CONTROL_BLOCK *pSCB, SQ_BYTE *pImageData, SQ_DWORD ImageLength);
SQ_RCODE WriteToClient(SQRL_CONTROL_BLOCK* pSCB, SQ_BYTE *pBuffer, SQ_DWORD OptionalLength);
SQ_RCODE Return404NotFound(SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE Return410Gone(SQRL_CONTROL_BLOCK *pSCB);

// server.c
void DeEscapeFormData(SQ_CHAR *pszBufferToDeEscape);
void ParseQueryParams(QUERY_PARAMS *pQueryParams, SQ_CHAR *pszQueryString);
void VerifyValidInvitation(SQ_BYTE * pSqrlPublicIdentity);
SQ_RCODE ReturnListOfAssociations(SQ_CHAR *pszAccount, SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE UpdateBySqrlUser(QUERY_PARAMS *pQueryParams);
SQ_RCODE AddAssociation(SQRL_CONTROL_BLOCK *pSCB);
void RemoveAssociation(SQRL_CONTROL_BLOCK *pSCB);
void ListAssociations(SQRL_CONTROL_BLOCK *pSCB);
void InviteAssociation(SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE AcceptInvitation(SQRL_CONTROL_BLOCK *pSCB);

// sspapi.c
void InitResponse(SQRL_RESPONSE *pResponse);
void FreeResponse(SQRL_RESPONSE *pResponse);
void HttpExtensionProc (SQRL_CONTROL_BLOCK *pSCB);
void GetUrlEncodedReferrer(SQ_CHAR *pszEncodedPageURL, SQ_DWORD EncBufLen, SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE InitSqrlSystem();
SQ_RCODE ShutDownSqrlSystem();

// utils.c
void LogTheQueryAndReply(SQ_CHAR *pszMessage, SQRL_CONTROL_BLOCK *pSCB);
void *GlobalAlloc(SQ_DWORD NumBytes);
void GlobalFree(void **ppGlobalAllocation);
SQ_RCODE CheckLocalhostCaller(SQRL_CONTROL_BLOCK *pSCB);
void SQ_GetSystemTimeAsFileTime(SQ_QWORD *pFileTime);
SQ_DWORD SQ_GetFileTimeAgeInMinutes(SQ_QWORD *pSqrlLastActivityDate, SQ_QWORD *pCurrentTime);
SQ_DWORD GetSystemOneSecondTime();
SQ_RCODE GetNextMonotonicCounterValue(SQ_BYTE *pNextValue);
void GetUnpredictable64bits(SQ_BYTE *p64bitBuffer);
void GetUnique12charNut(SQ_CHAR *pszBase64Buffer, SQ_BOOL NullTerm);
void GetUnique20digitToken(SQ_CHAR *p20CharBuffer, SQ_BOOL NullTerm);
void IPv4StringToAddress(char *pIPaddress, void *pBuffer, unsigned int *pBufferLength);
void IPv6StringToAddress(char *pIPaddress, void *pBuffer, unsigned int *pBufferLength);
void ObtainClientConnectionIP(void *pIPbuffer, SQRL_CONTROL_BLOCK *pSCB);
SQ_RCODE VerifyPrivateQuery(SQRL_CONTROL_BLOCK *pSCB);
void UrlEncode(SQ_CHAR *pDstBuffer, SQ_CHAR *pSrcBuffer);
void PlaceCpsUrlIntoBuffer(SQ_CHAR *pBuffer, PENDING_AUTHS *pPendingAuth);

#endif
