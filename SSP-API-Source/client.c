
// client.c

/*
via HTTPS POST
/cli.sqrl
*/

/*
===============================================================================
	SQRL CLIENT PROTOCOL IMPLEMENTATION
===============================================================================
*/

#include "global.h"

/*
============================================================================
	COMMAND AND OPTION PARSER				     
----------------------------------------------------------------------------
*/
void CommandOptionParser(SQ_DWORD *pResultFlags, const CMD_OPT_TABLE ArgsTable[], int NumItems, SQ_CHAR *pszArgList) {
	BEG("CommandOptionParser()");
	
	// Find the command in CommandTable or the options in OptionsTable
	*pResultFlags=0;

	// we assume pszArgs is null-terminated and args end with '~' or '\r'
	// for commands there should be just one ending in CR LF e.g. query\r\n
	// for options they will be separated by "~" and end with CR LF e.g. suk~cps\r\n
	
	// Scan pszArgLst for args, pBeg, pEnd will designate an arg
	//       query\r\n    suk~cps\r\n
	// pBeg: ^      ^     ^   ^    ^ 
	// pEnd:      ^          ^   ^
	char *pBeg;
	char *pEnd;
	char c;
	
	pEnd=pszArgList;
	while(1) {
		// pBeg points to the first char of a possible command or option
		// we increment pEnd to point to the last char
		pBeg=pEnd;
		while(1) {
			c=*pEnd;
			if(c=='\n' || c=='\0') {
				END();
				return; // we're done
			}
			if(c=='~' || c=='\r' ) {
				break; // we found another option
			}
			pEnd++;
		}
			
		// We have an arg
		// Temporarily replace c with '\0' to null-terminate it
		// See if it's in the table and set a flag bit if it is
		*pEnd='\0';
		for(int i=0; i<NumItems; i++) {
			if(strcmp(pBeg, ArgsTable[i].pszName)==0) {
				*pResultFlags|=ArgsTable[i].FlagBit;
				break;
			}
		}
		// Restore c in case we need the ArgList elsewhere
		*pEnd=c;
		
		// Look for the next arg
		pEnd++;
	}
	END();
}

/*
===============================================================================
	PARSE CLIENT QUERY

-------------------------------------------------------------------------------
 This parses the client's query data filling in the CLIENT_TO_SERVER structure
 with all of the client's various keys, checks signatures, sets status flags,
 and also looks up and returns any PendingAuth structure with a matching NUT.
===============================================================================
*/
SQ_RCODE ParseClientQuery (CLIENT_TO_SERVER *pParams, PENDING_AUTHS **ppPendingAuth, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ParseClientQuery()");
	SQ_BYTE aServerMAC[BINARY_KEY_LEN];
	SQ_CHAR *pszClient;
	SQ_CHAR *pszClientDecode;
	SQ_CHAR *pszServer;
	SQ_DWORD TestBits;
	SQ_CHAR *pBeg;
	SQ_CHAR *pEnd;
	SQ_CHAR *pData;

	PENDING_AUTHS *pPendingAuth;

	// Set our dynamic allocation pointers to NULL so we can
	// abort if needed and have any allocations safely released
	pszClient=NULL;
	pszClientDecode=NULL;
	pszServer=NULL;
	
	// Zero the output structure
	memset(pParams, 0, sizeof(CLIENT_TO_SERVER));
	
	// We set up one large "do {} once" so we can break out of it
	// on any error instead of using "goto Exit"
//[
// this could also be made into a separate function (approx 400 lines of code)
//]
	SQ_BOOL bAbort=SQ_FALSE;
	do {
		// Sanity check the length of the POST data
		int DataLen=pSCB->DataLen;
		if(DataLen<MINIMUM_CLIENT_QUERY || DataLen>MAXIMUM_CLIENT_QUERY) {
			// Too short or too long, abort
LOG("Abort: Post data length (%d) is too short (less than %d) or too long (more than %d)", 
DataLen, MINIMUM_CLIENT_QUERY, MAXIMUM_CLIENT_QUERY);
			bAbort=SQ_TRUE;
			break;
		}
		// All POST queries have "nut={12-char nut}" as their query string
		if(pSCB->lpszQueryString==NULL) {
			// We have a NULL query, abort
LOG("Abort: Query is NULL");
			bAbort=SQ_TRUE;
			break;
		}
		int QueryLen=strlen(pSCB->lpszQueryString);
		if(QueryLen < QUERY_STRING_LEN) {
			// It's less than 16 characters, abort
LOG("Abort: Query (%s) is less than %d characters", pSCB->lpszQueryString, QUERY_STRING_LEN);
			bAbort=SQ_TRUE;
			break;
		}
		SQ_CHAR *pNut=strstr(pSCB->lpszQueryString, pszNutEquals);
		if(pNut==NULL) {
			// It doesn't contain "nut=", abort
LOG("Abort: Query (%s) doesn't contain 'nut='", pSCB->lpszQueryString);
			bAbort=SQ_TRUE;
			break;
		}
		if(strlen(pNut)-strlen(pszNutEquals) < SQRL_NUT_LEN ) {
LOG("Abort: Query (%s) nut length is less than %d", pSCB->lpszQueryString, SQRL_NUT_LEN);
			bAbort=SQ_TRUE;
			break;
		}
		pNut+=strlen(pszNutEquals);
		
		// show that the client's query DOES contain a valid-looking NUT
		pParams->DataPresent|=QUERY_NUT;
		
		// now let's lookup the query's pending authentication by the query NUT
		// if it exists we retrieve the object pointer and remove it from the 
		// queue while we're working on it.  If it does not exist we allocate a
		// structure to hold our work.  Once we're finished we'll re-queue it.

		EnterCriticalSection(&PendingAuthsQueue.CriticalSection);
		pPendingAuth=LookupByNut(NULL, pNut, /*UpdateObject*/SQ_FALSE, /*ProtocolNut*/SQ_TRUE, NULL);
		
		// Set the pointer for our caller's use
		*ppPendingAuth=pPendingAuth;
		if(pPendingAuth==NULL) {
			pParams->DataPresent|=QUERY_NUT_INVALID|QUERY_MAC_INVALID;
		} else {
			DequeueObject(&PendingAuthsQueue, (QUEUE_OBJECT *)pPendingAuth);
			pParams->DataPresent|=PENDING_AUTH_VALID;
		}
		
		LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);
		/*
		===============================================================================
		We have a query that appears sane, and we found a valid matching query NUT.
		Now we parse the the POST's top level arguments of "client=", "server=",
		"pids=", 'ids=', 'urs='
		===============================================================================
		*/
		// Scan Top Args ("client=", "server=", "ids=", "pids=", "urs=")
		//--------------------------------------------------------------
	
		// Set pointers to the beginning and end of the POST data
		pBeg=pSCB->lpData;
//[
//. Why does the MASM version skip the first two bytes?
//]
		pEnd=pBeg+DataLen;
		
		// Set a pointer for scanning
		pData=pBeg;
		
		//        "client=...&server=..."
		// pData:  ^         ^          ^
		while(1) {
			SQ_CHAR *ptr;
			
			// Look for the next "="
			if((ptr=memchr(pData, '=', pEnd-pData))==NULL) {
				// We have reached the end normally
				break; // out of while()
			}
			// Skip past any "&"
			if(*pData=='&') pData++;
			
			// See which query parameter we have, "client=, "server=" etc.
			int i;			
			for(i=0; i<NumQueryTokens; i++) {
				int ArgLen=strlen(QueryTokens[i].pName);
				if(pData+ArgLen<=pEnd && memcmp(pData, QueryTokens[i].pName, ArgLen)==0) {
					// We found a parameter
					break; // out of the for()
				}
			}
			
			// We may or may not have found a parameter name we recognize
			// Regardless, we look for the end of its value
			
			// Set pData to the character after the "=" (could be pEnd)
			pData=ptr+1;
			
			// pEnd is one after the last byte in the POST data
			// look for an '&' '\0' or reaching the end of the POST data
			// Length is the number of bytes found after the '='
			while(ptr<pEnd && *ptr!='\0' && *ptr !='&') ptr++;
			int ValueLen=ptr-pData;

			if(ValueLen==0) {
				// Abort
LOG("Abort: No data for %s=", QueryTokens[i].pName);
				bAbort=SQ_TRUE;
				break; // out of while()
			}

			if(i==NumQueryTokens) {
				// We didn't find a match, per protocol we ignore this parameter and its value
				pData+=ValueLen;
				continue; // next while()
			}

			// See if we have this parameter's value already
			if((pParams->DataPresent&QueryTokens[i].BitMask)==QueryTokens[i].BitMask) {
				// Abort
LOG("Abort: Multiple entries for %s=", QueryTokens[i].pName);
				bAbort=SQ_TRUE;
				break; // out of for()
			}
			// Indicate we now have this parameter's value
			pParams->DataPresent|=QueryTokens[i].BitMask;

			// Process that query parameter
			switch(QueryTokens[i].BitMask) {
			case QUERY_CLIENT:
//[
LOG("client:");
if((pParams->DataPresent&QUERY_CLIENT)==0) {LOG("NULL");}
else {LOG("[]", pData, ValueLen);}
//]
				// Allocate memory for the data
				pszClient=GlobalAlloc(ValueLen+1);
				memcpy(pszClient, pData, ValueLen);

				// Decode it
				// The function allocates memory so we need to pass the address of our pointer
				DecodeBase64szAndStore((SQ_BYTE **)&pszClientDecode, pszClient);
//[
LOG("clientDecode:");
if((pParams->DataPresent&QUERY_CLIENT)==0) {LOG("NULL");}
else {LOG("[]", pszClientDecode, strlen(pszClientDecode));}
//]
				break;
			
			case QUERY_SERVER:
//[
LOG("server:");
if((pParams->DataPresent&QUERY_SERVER)==0) LOG("NULL");
else LOG("[]", pData, ValueLen);
// Allocate memory for the data
pszServer=GlobalAlloc(ValueLen+1);
memcpy(pszServer, pData, ValueLen);
SQ_CHAR *pszServerDecode;
DecodeBase64szAndStore((SQ_BYTE **)&pszServerDecode, pszServer);
LOG("serverDecode:");
if((pParams->DataPresent&QUERY_SERVER)==0) LOG("NULL");
else LOG("[]", pszServerDecode, strlen(pszServerDecode));
GlobalFree((void **)&pszServer);
GlobalFree((void **)&pszServerDecode);
//]
				pszServer=GlobalAlloc(ValueLen+1);
				memcpy(pszServer, pData, ValueLen);
				
				// we need to verify that the HMAC of the server's returned value
				// equals (one of the) HMACs that we saved when we sent the reply

				HMAC256(aServerMAC, (SQ_BYTE *)pszServer, strlen(pszServer), aSystemKey);
				PENDING_AUTHS *pPendingAuth=*ppPendingAuth;
				if(pPendingAuth!=NULL) {
//[
LOG("Check aServerMAC:");
LOG("[]", aServerMAC, SHA256_BYTE_LEN);
LOG("aTransactionMAC1:");
LOG("[]", pPendingAuth->aTransactionMAC1, SHA256_BYTE_LEN);
LOG("aTransactionMAC2:");
LOG("[]", pPendingAuth->aTransactionMAC2, SHA256_BYTE_LEN);
//]
					if(memcmp(aServerMAC, pPendingAuth->aTransactionMAC1, BINARY_KEY_LEN)!=0 &&
						memcmp(aServerMAC, pPendingAuth->aTransactionMAC2, BINARY_KEY_LEN)!=0) {
						pParams->DataPresent|=QUERY_MAC_INVALID;
					}
				}
				break;
				
			case QUERY_IDS:
//[
LOG(" ids:");
if((pParams->DataPresent&QUERY_IDS)==0) {LOG("NULL");}
else {LOG("[]", pData, ValueLen);}
//]
				if(ValueLen==ASCII_SIG_LEN) {
					// Decode it
					SqrlCvrtFromBase64(pParams->ids, SIGNATURE_LEN, pData, ValueLen);
				}
				break;
									
			case QUERY_PIDS:
//[
LOG("pids:");
if((pParams->DataPresent&QUERY_PIDS)==0) {LOG("NULL");}
else {LOG("[]", pData, ValueLen);}
//]
				if(ValueLen==ASCII_SIG_LEN) {
					// Decode it
					SqrlCvrtFromBase64(pParams->pids, SIGNATURE_LEN, pData, ValueLen);
				}
				break;

			case QUERY_URS:
//[
LOG(" urs:");
if((pParams->DataPresent&QUERY_URS)==0) {LOG("NULL");}
else {LOG("[]", pData, ValueLen);}
//]
				if(ValueLen==ASCII_SIG_LEN) {
					// Decode it
					SqrlCvrtFromBase64(pParams->urs, SIGNATURE_LEN, pData, ValueLen);
				}
				break;

			default:
				break;
			}
			// We found and processed one of "client=", "server=", "ids=" etc.
			// Advance the data pointer to the byte after the value we just processed
			pData+=ValueLen;
		
			if(bAbort==SQ_TRUE) {
				break; // out of while()
			}
		// Look for the next top parameter name
		}

		if(bAbort==SQ_TRUE) {
			break; // out of do()
		}

		/*
		===============================================================================
		We have parsed the top level client, server, and signature parameters and
		converted the various signatures to binary.  So now we need to unpack and
		parse the client's parameters to obtain the version, commands, and public
		keys the client has provided to authenticate its various requests.
		===============================================================================
		*/
		// ClientParams
		//-------------

		// Set pointers to the beginning and end of the client data
		if(pszClientDecode==NULL) {
LOG("Abort: No client data");
			bAbort=SQ_TRUE;
			break;
		}
		pBeg=pszClientDecode;
//[
// Why does the MASM version skip the first two bytes?
//]
		DataLen=strlen(pBeg);
		pEnd=pBeg+DataLen;
		
		// Set a pointer for scanning
		pData=pBeg;

		//     "ver=..\r\ncmd=...\r\n...\r\n\r\n"
		//pData: ^         ^                 ^
		while(1) {
			SQ_CHAR *ptr;
	
			// Look for the next "="
			if((ptr=memchr(pData, '=', pEnd-pData))==NULL) {
				// We have reached the end normally
				break; // out of while()
			}
			// Skip past '\0', CR, LF 
			if(*pData=='\0') pData++;
			if(*pData=='\r') pData++;
			if(*pData=='\n') pData++;
		
			// See which client arg we have, "ver=", "cmd=" etc.
			int i;
			for(i=0; i<NumClientTokens; i++) {
				int ArgLen=strlen(ClientTokens[i].pName);
				if(pData+ArgLen<=pEnd && memcmp(pData, ClientTokens[i].pName, ArgLen)==0) {
					// We found a parameter
					break; // out of the for()
				}
			}
			// We may or may not have found a parameter name we recognize
			// Regardless, we look for the end of its value
			
			// Set pData to the character after the "=" (could be pEnd)
			pData=ptr+1;
			
			// pEnd is one after the last byte in the client data
			// look for a CR, LF, '\0' or reaching the end of the client data
			// Length is the number of bytes found after the '='
			while(ptr<pEnd && *ptr!='\0' && *ptr!='\r' && *ptr!='\n') ptr++;
			int ValueLen=ptr-pData;
			
			if(ValueLen==0) {
				// Abort
LOG("Abort: No data for %s=", ClientTokens[i].pName);
				bAbort=SQ_TRUE;
				break; // out of while()
			}

			if(i==NumClientTokens) {
				// We didn't find a match, per protocol we ignore this parameter and its value
				pData+=ValueLen;
				continue; // next while()
			}
		
			// See if we have this parameter's value already
			if((pParams->DataPresent&ClientTokens[i].BitMask)==ClientTokens[i].BitMask) {
				// Abort
LOG("Abort: Multiple entries for %s=", ClientTokens[i].pName);
				bAbort=SQ_TRUE;
				break; // out of for()
			}
			// Indicate we now have this parameter's value
			pParams->DataPresent|=ClientTokens[i].BitMask;
		
			// Process that client parameter
			switch(ClientTokens[i].BitMask) {
			case QUERY_VER:
				pParams->pszVer=pData;
				NullTerminateString(pParams->pszVer);
				break;
				
			case QUERY_CMD:
				CommandOptionParser(&pParams->cmd, CommandTable, NumCommandItems, pData);
				break;
				
			case QUERY_OPT:
				CommandOptionParser(&pParams->opt, OptionTable, NumOptionItems, pData);
				break;
				
			case QUERY_IDK:
				if(SanityCheckAsciiKey(pData)==SQ_FAIL) {
					continue; // the while()
				}
				SqrlCvrtFromBase64(pParams->idk, BINARY_KEY_LEN, pData, ASCII_KEY_LEN);
				break;
				
			case QUERY_PIDK:
				if(SanityCheckAsciiKey(pData)==SQ_FAIL) {
					continue; // the while()
				}
				SqrlCvrtFromBase64(pParams->pidk, BINARY_KEY_LEN, pData, ASCII_KEY_LEN);
				break;
				
			case QUERY_SUK:
				if(SanityCheckAsciiKey(pData)==SQ_FAIL) {
					continue; // the while()
				}
				SqrlCvrtFromBase64(pParams->suk, BINARY_KEY_LEN, pData, ASCII_KEY_LEN);
				break;

			case QUERY_VUK:
				if(SanityCheckAsciiKey(pData)==SQ_FAIL) {
					continue; // the while()
				}
				SqrlCvrtFromBase64(pParams->vuk, BINARY_KEY_LEN, pData, ASCII_KEY_LEN);
				break;
				
			default:
				break;
			}
			// We found and processed one of "ver=", "cmd=" ect.
			// Advance the data pointer to the byte after the value just processed
			pData+=ValueLen;
			
			if(bAbort==SQ_TRUE) {
				break; // out of while()
			}
		}
		
		if(bAbort==SQ_TRUE) {
			break; // out of do()
		}

		/*
		----------------------------------------------------------------------------
		We have parsed the top level client, server, and signature parameters and 
		converted the various signatures to binary. So now let's verify the sigs. 
		----------------------------------------------------------------------------
		*/
		TestBits=QUERY_CLIENT|QUERY_SERVER|QUERY_IDS|QUERY_IDK;
		if((pParams->DataPresent&TestBits)!=TestBits) {
LOG("Abort: Not all of client=, server=, idk=, ids= are present");
			bAbort=SQ_TRUE;
			break; // out of do()
		}
		
		// we have everything we needed to check the ID Signature...
		SQ_DWORD ClientLen=strlen(pszClient);
		SQ_DWORD ServerLen=strlen(pszServer);
		pParams->SigningBufLen=ClientLen+ServerLen;
		pParams->pSigningBuf=(SQ_BYTE *)GlobalAlloc(pParams->SigningBufLen);
	
		memcpy(pParams->pSigningBuf+0, pszClient, ClientLen);
		memcpy(pParams->pSigningBuf+ClientLen, pszServer, ServerLen);
	
		// we found 'client=', 'server=', 'ids=' & 'idk=' tokens,
		// so we can and must verify the provided signature
	
//[
LOG("SigningBuf"); LOG("[]", pParams->pSigningBuf, pParams->SigningBufLen);
LOG("ids"); LOG("[]", pParams->ids, 64);
LOG("idk"); LOG("[]", pParams->idk, 32);
//]

		if(SqrlVerifySig(pParams->pSigningBuf, pParams->SigningBufLen, pParams->ids, pParams->idk)==SQ_PASS) {
			// the signature was correct, so let's flag its success
			pParams->SignaturesValid|=VALID_IDS;
		}

		// if we had a Previous Identity Key and Previous Identity Signature
		TestBits=QUERY_PIDK|QUERY_PIDS;
		if((pParams->DataPresent&TestBits)==TestBits) {
//[
LOG("SigningBuf"); LOG("[]", pParams->pSigningBuf, pParams->SigningBufLen);
LOG("pids"); LOG("[]", pParams->pids, 64);
LOG("pidk"); LOG("[]", pParams->pidk, 32);
//]
			if(SqrlVerifySig(pParams->pSigningBuf, pParams->SigningBufLen, pParams->pids, pParams->pidk)==SQ_PASS) {
				// the signature was correct, so let's flag its success
				pParams->SignaturesValid|=VALID_PIDS;

				// we have a previous identity and it was validly signed,
				// so we log this identity into our superseded database
				SUPERSEDED_IDENTITIES SupersededIdentity;
				memcpy(SupersededIdentity.aSupersededIdentity, pParams->pidk, BINARY_KEY_LEN);
				LogSupersededID(&SupersededIdentity);
			}
		}
	} while(0); // end of do()

	GlobalFree((void **)&pszClient);
	GlobalFree((void **)&pszClientDecode);
	GlobalFree((void **)&pszServer);

LOG("Client to Server Parameters:");

LOG(" DataPreset: 0x%08x", pParams->DataPresent);
if((pParams->DataPresent&QUERY_NUT)!=0) LOG("  nut"); 
if((pParams->DataPresent&QUERY_CLIENT)!=0) LOG("  client"); 
if((pParams->DataPresent&QUERY_SERVER)!=0) LOG("  server");
if((pParams->DataPresent&QUERY_IDS)!=0) LOG("  ids");
if((pParams->DataPresent&QUERY_PIDS)!=0) LOG("  pids"); 
if((pParams->DataPresent&QUERY_URS)!=0) LOG("  urs");

if((pParams->DataPresent&QUERY_NUT_INVALID)==0) LOG("  (nut not invalid)"); else LOG("  nut invalid"); 
if((pParams->DataPresent&QUERY_MAC_INVALID)==0) LOG("  (MAC not invalid)"); else LOG("  MAC invalid");
if((pParams->DataPresent&PENDING_AUTH_VALID)==0) LOG("  (no pending auth)"); else LOG("  pending auth valid");

LOG(" Valid Signatures: 0x%08x", pParams->SignaturesValid);
if((pParams->SignaturesValid&VALID_IDS)!=0) LOG("  ids"); 
if((pParams->SignaturesValid&VALID_PIDS)!=0) LOG("  pids"); 
if((pParams->SignaturesValid&VALID_URS)!=0) LOG("  urs");

LOG(" Command(s): 0x%08x", pParams->cmd);
if((pParams->cmd&CMD_QUERY)!=0) LOG("  query"); 
if((pParams->cmd&CMD_IDENT)!=0) LOG("  ident"); 
if((pParams->cmd&CMD_DISABLE)!=0) LOG("  disable"); 
if((pParams->cmd&CMD_ENABLE)!=0) LOG("  enable"); 
if((pParams->cmd&CMD_REMOVE)!=0) LOG("  remove");

LOG(" Options: 0x%08x", pParams->opt);
if((pParams->opt&OPT_SQRLONLY)!=0) LOG("  sqrlonly"); 
if((pParams->opt&OPT_HARDLOCK)!=0) LOG("  hardlock"); 
if((pParams->opt&OPT_CPS_MODE)!=0) LOG("  cps");
if((pParams->opt&OPT_SUK_REQ)!=0) LOG("  suk"); 
if((pParams->opt&OPT_NOIPTEST)!=0) LOG("  noiptest");
	
	END();
	return (bAbort==SQ_FALSE? SQ_PASS: SQ_FAIL);
}

/*
--------------------------------------------------------------------------
	SanityCheckAsciiKey
	this scans a CR/LF/null-terminated string,
	null terminates it, and checks its length.
--------------------------------------------------------------------------
*/
SQ_RCODE SanityCheckAsciiKey(SQ_CHAR *pKey) {
	SQ_CHAR *pEnd=NullTerminateString(pKey);
	return (pEnd-pKey==ASCII_KEY_LEN? SQ_PASS: SQ_FAIL);	
}
/*
--------------------------------------------------------------------------
	NullTerminateString
	we're standing at the start of a run of characters
	so we scan forward to the first CR, LF, '&' or NULL
	and convert THAT character to a null for term,
--------------------------------------------------------------------------
*/
SQ_CHAR *NullTerminateString(SQ_CHAR *ptr) {
	while(*ptr!='\0') {
		if(*ptr=='\r' || *ptr=='\n') {
			*ptr='\0';
			break;
		}
		ptr++;
	}
	return ptr;
}

/*
===============================================================================
	HANDLE CLIENT QUERY			     
-------------------------------------------------------------------------------
*/
SQ_RCODE HandleClientQuery(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("HandleClientQuery()");
	SQ_RCODE rc=SQ_FAIL;
	SQ_DWORD TransInfo;
	CLIENT_TO_SERVER QueryParams;
	PENDING_AUTHS *pPendingAuth;
	SQ_BYTE aIPaddress[16];
	SQRL_ASSOCIATIONS SqrlAssoc;
	SQRL_ASSOCIATIONS *pSqrlAssoc=&SqrlAssoc;
	ASSOC_REC_DATA *pAssocRecData=&SqrlAssoc.AssocRecData;
	SQ_DWORD TestBits;
	
	TransInfo=0;

	// the subsequent call to "ParseClientQuery" looks up and populates the
	// PendingAuth structure from our previous browser queries which created
	// and setup the various structure components. We use the szInvitation,
	// szSqrlPublicKey and TransactionMAC fields during this work below...
	
	if(ParseClientQuery(&QueryParams, &pPendingAuth, pSCB)==SQ_FAIL) {
		rc=SendSqrlReply(pSCB, NULL, 0, SQ_FAIL);
		END();
		return rc;
	}
	// Bit set indicates an error
	if((QueryParams.DataPresent&QUERY_NUT_INVALID)==QUERY_NUT_INVALID) {
		TransInfo|=(COMMAND_FAILED|TRANSIENT_ERROR);
//[
LOG("Query Nut Invalid -> TIF=0x%x", TransInfo);
//]
	}

	// Bit set indicates an error
	if((QueryParams.DataPresent&QUERY_MAC_INVALID)==QUERY_MAC_INVALID) {
		TransInfo|=(COMMAND_FAILED|CLIENT_FAILED);
//[
LOG("Query MAC Invalid -> TIF=0x%x", TransInfo);
//]
	}

	// Bits not set indicate an error (all TestBits must be set)
	TestBits=QUERY_NUT|QUERY_CLIENT|QUERY_SERVER|QUERY_IDS|QUERY_IDK|QUERY_VER|QUERY_CMD;
	if((QueryParams.DataPresent&TestBits) != TestBits) {
		TransInfo|=(COMMAND_FAILED|CLIENT_FAILED);
//[
LOG("Query Nut    %s", (TestBits&QUERY_NUT)==0? "Missing": "OK");
LOG("Query Client %s", (TestBits&QUERY_CLIENT)==0? "Missing": "OK");
LOG("Query Server %s", (TestBits&QUERY_SERVER)==0? "Missing": "OK");
LOG("Query IDS    %s", (TestBits&QUERY_IDS)==0? "Missing": "OK");
LOG("Query IDK    %s", (TestBits&QUERY_IDK)==0? "Missing": "OK");
LOG("Query Ver    %s", (TestBits&QUERY_VER)==0? "Missing": "OK");
LOG("Query Cmd    %s", (TestBits&QUERY_CMD)==0? "Missing": "OK");
LOG("             -> TIF=0x%x", TransInfo);
//]
	}
	
	// if we did locate the pending auth object NUT, we check the IP
	if((QueryParams.DataPresent&PENDING_AUTH_VALID)==PENDING_AUTH_VALID) {
		// check to see whether we have an IP match
		ObtainClientConnectionIP(aIPaddress, pSCB);
	
		if(memcmp(aIPaddress, pPendingAuth->aRequestIP, sizeof(aIPaddress))!=0) {
			if((QueryParams.opt&OPT_NOIPTEST)==0) {
				TransInfo|=(COMMAND_FAILED);
//[
LOG("IP Address Mismatch and opt=noiptest -> TIF=0x%x", TransInfo);
//]
//[
LOG("aIPaddress: (dec):");
LOG("[d]", aIPaddress, IPV6_BYTE_LEN);
LOG("pPendingAuth->aRequestIP: (dec):");
LOG("[d]", pPendingAuth->aRequestIP, IPV6_BYTE_LEN);
//]
			}
		}
		else {
			TransInfo|=IP_ADDRESS_MATCH;
//[
LOG("IP Address Match -> TIF=0x%x", TransInfo);
//]
		}
	}
	// if we have already determined that things are not right, we fail fast
	if((TransInfo&COMMAND_FAILED)==COMMAND_FAILED) {
		rc=SendResponse(pSCB, &QueryParams, TransInfo, pSqrlAssoc, pPendingAuth);
		END();
		return rc;
	}

	/*
	-------------------------------------------------------------------------------
	We have parsed the client's query and have set the collection of bit flags
	based upon the presence of client keys and signatures. Now we use what we
	know to load up the associated SQRL record, if any. If we cannot locate a
	record by SQRL ID, we'll check to see whether we have a pending invitation
	and can locate a record by this invitation.
	-------------------------------------------------------------------------------
	*/
	memset(pSqrlAssoc, 0, sizeof(SQRL_ASSOCIATIONS));

	// if we have a valid =CURRENT= ID signature... see if we know them
	if((QueryParams.SignaturesValid&VALID_IDS)==VALID_IDS) {
		// before we check for them using their cursor key,
		// we check to see whether they are presenting a key
		// that's known to have been previously superseded
		SUPERSEDED_IDENTITIES SupersededIdentity;
		memcpy(SupersededIdentity.aSupersededIdentity, QueryParams.idk, BINARY_KEY_LEN);
///[
//Alternate implementation to allow non-query commands to proceed
/*

		if(CheckForSupersededID(&SupersededIdentity)==SQ_PASS) {
			TransInfo|=SUPERSEDED_ID;
			if(QueryParams.cmd!=CMD_QUERY) {
				TransInfo|=COMMAND_FAILED;
			}
			rc=SendResponse(pSCB, &QueryParams, TransInfo, pSqrlAssoc, pPendingAuth);
			END();
			return rc;
		}
*/
		if(CheckForSupersededID(&SupersededIdentity)==SQ_PASS) {
			TransInfo|=SUPERSEDED_ID;
		}
///]
		if(GetRecordBySqrlKey(pSqrlAssoc, QueryParams.idk)==SQ_PASS) {
			// a record WAS found for this user under their CURRENT
			// Identity Key, so let's note that success
			TransInfo|=CURRENT_ID_MATCH;
			
			// and we have retrieved the record so we can get the
			// identity's SUK value in case we need to offer it
		}
	}
	
	// if we have a valid =PREVIOUS= ID signature... see if we know them
	if((QueryParams.SignaturesValid&VALID_PIDS)==VALID_PIDS) {
		if(GetRecordBySqrlKey(pSqrlAssoc, QueryParams.pidk)==SQ_PASS) {
			// a record WAS found for this user under their PREVIOUS
			// Identity Key, so let's note that success
			TransInfo|=PREVIOUS_ID_MATCH;
			
			// set the USER_REKEYED flag to notify the web server
			// in case it wants to do something with the information
			pAssocRecData->SqrlOptionFlags|=USER_REKEYED;
			StoreSqrlRecord(pSqrlAssoc);
			
			// and we have retrieved the record so we can get the
			// identity's SUK value in case we need to offer it
		}
	}

	// if SQRL login is flagged as disabled in the user's record
	// we need to set the TIF flag now so that the QUERY op reports
	if((pAssocRecData->SqrlOptionFlags&AUTH_DISABLED)==AUTH_DISABLED) {
		TransInfo|=SQRL_DISABLED;
	}

	// is this an initial 'query' query
	if(QueryParams.cmd==CMD_QUERY) {
//[
// We already exited above if there was a command failure and have not set 
// the bit since, so the follow code from the original MASM is not needed.
//]
/*
		// if so, we won't label this as a command failure
		// UNLESS we also had a client failure
		if((TransInfo&CLIENT_FAILED)==0) {
			TransInfo&=~COMMAND_FAILED;
		}
*/
		rc=SendResponse(pSCB, &QueryParams, TransInfo, pSqrlAssoc, pPendingAuth);
		END();
		return rc;
	}

	if((TransInfo&COMMAND_FAILED)==COMMAND_FAILED) {
		rc=SendResponse(pSCB, &QueryParams, TransInfo, pSqrlAssoc, pPendingAuth);
		END();
		return rc;
	}

	/*
	========================[ END OF CMD_QUERY PROCESSING ]========================
	*/
	// if we did find the user, we will have loaded their Sqrl data from the
	// SQRL association database.  So now we can verify their URS signature
	// if they provided one...

	TestBits=(CURRENT_ID_MATCH|PREVIOUS_ID_MATCH);
	if((TransInfo&TestBits)!=0 && (QueryParams.DataPresent&QUERY_URS)==QUERY_URS && QueryParams.SigningBufLen!=0) {
		if(SqrlVerifySig(QueryParams.pSigningBuf, QueryParams.SigningBufLen, QueryParams.urs, pAssocRecData->aSqrlVerifyUnlockKey)==SQ_PASS) {
			// the signature was correct, so let's flag its success
			QueryParams.SignaturesValid|=VALID_URS;
		}
//[
else {
	LOG("URS Verification failed");
}
//]
	}

	/*
	-------------------------------------------------------------------------------
	==========================[ BEGIN ACTIVE PROCESSING ]==========================
	-------------------------------------------------------------------------------
	*/
	// If this query contains everything we need to update the user's account
	// from their previous identity, we do so now...
	if((TransInfo&PREVIOUS_ID_MATCH)==PREVIOUS_ID_MATCH && (QueryParams.SignaturesValid&VALID_URS)==VALID_URS) {
		// we're updating our identity key so we always re-enable access
		pAssocRecData->SqrlOptionFlags&=~AUTH_DISABLED;
		
		// re-store the record under the newly updated SQRL identity...
		UpdateSqrlAssociationRecord(&SqrlAssoc, &QueryParams);
		
		// now we turn OFF "previous match" and turn on "current match"
		TransInfo&=~PREVIOUS_ID_MATCH;
		TransInfo|=CURRENT_ID_MATCH;
//[
LOG("Previous IDK Rekeyed to Current IDK -> TIF=0x%x", TransInfo);
//]
	}

	// if the user was not identified by current or previous ID,
	// we cannot perform any database updates or commands, so we
	// need to check to see whether we're being asked to do an
	// ENABLE, DISABLE or REMOVE, which requires recognition:

	TestBits=CMD_DISABLE|CMD_ENABLE|CMD_REMOVE;
	if((TransInfo&(CURRENT_ID_MATCH|PREVIOUS_ID_MATCH))==0 && (QueryParams.cmd&TestBits)!=0) {
		TransInfo|=COMMAND_FAILED;
//[
LOG("No ID match with Disable, Enable, or Remove command -> TIF=0x%x", TransInfo);
//]
		rc=SendResponse(pSCB, &QueryParams, TransInfo, pSqrlAssoc, pPendingAuth);
		END();
		return rc;
	}

	// we have the possibly-updated SQRL identity (IDK) from the authenticated
	// SQRL transaction, so let's move the client's IDK into our Pending Auths
	CvrtToBase64String(pPendingAuth->szSqrlPublicKey, ASCII_KEY_LEN, QueryParams.idk, BINARY_KEY_LEN);

	// we'll also capture the non-Query transaction's "opt" value so that it
	// can later be sent to the webserver as the 'status' so that SqrlOnly
	// and HardLock can be maintained for the account's owner
	pPendingAuth->OptionsValue=QueryParams.opt;

	/*
	======================[ HANDLE SPECIFIC CLIENT COMMANDS ]======================
	*/
	switch(QueryParams.cmd) {
		case CMD_IDENT:
		// if the account is disabled, we fail the IDENT command
		if((TransInfo&SQRL_DISABLED)==SQRL_DISABLED) {
			TransInfo|=COMMAND_FAILED;
//[
LOG("cmd=ident SQRL Disabled -> TIF=0x%x", TransInfo);
//]
			break;
		}
		if((TransInfo&(CURRENT_ID_MATCH|PREVIOUS_ID_MATCH))==0) {
			// if we're being asked to associate a possibly new ID,
			// has the client provided all of the material we'll need?
			SQ_DWORD TestBits;
			TestBits=QUERY_IDK|QUERY_SUK|QUERY_VUK;
			if((QueryParams.DataPresent&TestBits)!=TestBits) {
				TransInfo|=COMMAND_FAILED;
//[
LOG("cmd=ident, new id, IDK/SUK/VUK missing -> TIF=0x%x", TransInfo);
//]
				break;
			}
	
			// we have not found a record by our current or previous
			// SQRL identity. So let's see whether we have a pending
			// invitation for this new and successful authentication
			if((QueryParams.DataPresent&PENDING_AUTH_VALID)==PENDING_AUTH_VALID &&(strlen(pPendingAuth->szInvitation)!=0)) {
				// look for a pending invitation
				GetRecordByInvitation(pSqrlAssoc, pPendingAuth->szInvitation);
			}
			
			// we did not already have a SQRL association record. so
			// we create one, either to accept an invitation, in which
			// case the Account will already be filled-in and we'll
			// have a completed association, or with the Account not
			// yet filled so we'll have a pending association.
			UpdateSqrlAssociationRecord(&SqrlAssoc, &QueryParams);
		}
		
		// if we are NOT using CPS mode, we won't be authenticating when
		// the client issues the /cps.sqrl? query. So we notify the web
		// server NOW since we have a successful IDENT authentication...
		if((QueryParams.opt&OPT_CPS_MODE)==0 && (TransInfo & COMMAND_FAILED)==0) {
			TriggerNonCpsAuth(pPendingAuth, pSCB);
		}
		break;
		
		case CMD_DISABLE:
		// set the account disabled bit
		pAssocRecData->SqrlOptionFlags|=AUTH_DISABLED;
		StoreSqrlRecord(pSqrlAssoc);
		TransInfo|=SQRL_DISABLED;
//[
LOG("cmd=disable -> TIF=0x%x", TransInfo);
//]
		break;

		case CMD_ENABLE:
		if((QueryParams.SignaturesValid&VALID_URS)==VALID_URS) {
			// we're enabling a disabled account, so we turn off
			// the SQRL-disabled bit and save the result
			pAssocRecData->SqrlOptionFlags&=~AUTH_DISABLED;
			StoreSqrlRecord(pSqrlAssoc);
			TransInfo&=~SQRL_DISABLED;
//[
LOG("cmd=enable, Valid URS -> TIF=0x%x", TransInfo);
//]
		}
		else {
			TransInfo|=COMMAND_FAILED;
//[
LOG("cmd=enable, Invalid URS -> TIF=0x%x", TransInfo);
//]
		}
		break;
		
		case CMD_REMOVE:
		if((QueryParams.SignaturesValid&VALID_URS)==VALID_URS) {
			// we're removing a SQRL identity and account association
			pAssocRecData->SqrlOptionFlags|=REMOVE_REQUESTED;
			StoreSqrlRecord(pSqrlAssoc);			
//[
LOG("cmd=remove, Valid URS -> TIF=0x%x", TransInfo);
//]
		}
		else {
			TransInfo|=COMMAND_FAILED;
//[
LOG("cmd=remove, Invalid URS -> TIF=0x%x", TransInfo);
//]
		}
		break;

		default:
//[
// I added this
//]
			// Indicate failure and clear other status bits)
			TransInfo=(COMMAND_FAILED|CLIENT_FAILED|CMD_NOT_SUPPORTED);
//[
LOG("cmd=??? -> TIF=0x%x", TransInfo);
//]
		break;
	}

	rc=SendResponse(pSCB, &QueryParams, TransInfo, pSqrlAssoc, pPendingAuth);
	END();
	return rc;
}

SQ_BOOL IsNonZero(SQ_BYTE *pBuffer, SQ_DWORD BufLen) {
	int i;
	for(i=0; i<BufLen; i++) if(pBuffer[i]!=0) return SQ_TRUE;
	return SQ_FALSE;
}

/*				
============================================================================
	SEND RESPONSE BACK TO THE CLIENT			     
============================================================================
*/
SQ_RCODE SendResponse(SQRL_CONTROL_BLOCK *pSCB, CLIENT_TO_SERVER *pQueryParams, SQ_DWORD TransInfo, SQRL_ASSOCIATIONS *pSqrlAssoc, PENDING_AUTHS *pPendingAuth){
	BEG("SendResponse()");
	SQ_RCODE rc=SQ_PASS;
	ASSOC_REC_DATA *pAssocRecData=&pSqrlAssoc->AssocRecData;
	SQ_CHAR szTheNextNut[16];

	// release any existing allocated signing buffer
	GlobalFree((void **)&pQueryParams->pSigningBuf);
	
	// first we'll create a 2K ReplyBuffer for our normal needs.
	SQ_CHAR *pszReplyBuffer=(SQ_CHAR *)GlobalAlloc(2048);

	// place a 12-character zero-terminated string into "szNextNut"
	GetUnique12charNut(szTheNextNut, /*Null-Terminate=*/SQ_TRUE);
	
	// we grab this pending auth's path extension string, if any
	char *pPathExt=(char *)pszNull;
	if(pPendingAuth!=NULL) {
		pPathExt=pPendingAuth->szPathExtension;
	}
	
	// place out the beginning of the reply with 'nut', 'TIF', 'nut'
	sprintf(pszReplyBuffer, pszSqrlReplyFormat, szTheNextNut, TransInfo, pPathExt, szTheNextNut);
	
	// if the original query nut was invalid, it's not going to get any better
	// so we only add to the response if the nut is not invalid

	if((pQueryParams->DataPresent&QUERY_NUT_INVALID)==0) {
		// Now we conditionally append the SUK data ONLY IF we have it, and if
		// the client either might need it OR has explicitly asked for it. The
		// client might need it if our previous ID matched, or our current ID
		// matched *and* the account is disabled

		SQ_BOOL bHaveSUK       = IsNonZero(pAssocRecData->aSqrlServerUnlockKey, BYTES_FOR_256_BITS);
		SQ_BOOL bClientAsks    = (pQueryParams->opt&OPT_SUK_REQ)==OPT_SUK_REQ;
		SQ_BOOL bPreviousMatch = (TransInfo&PREVIOUS_ID_MATCH)==PREVIOUS_ID_MATCH;
		SQ_BOOL bCurrentMatch  = (TransInfo&CURRENT_ID_MATCH)==CURRENT_ID_MATCH;
		SQ_BOOL bAcctDisabled  = (TransInfo&SQRL_DISABLED)==SQRL_DISABLED;
		
		if(bHaveSUK && (bClientAsks || bPreviousMatch || (bCurrentMatch && bAcctDisabled))) {
			strcat(pszReplyBuffer, "suk=");
			
			// convert the identity's SUK to Base64url ASCII
			SqrlCvrtToBase64(pszReplyBuffer+strlen(pszReplyBuffer), ASCII_KEY_LEN,
				pAssocRecData->aSqrlServerUnlockKey, BINARY_KEY_LEN);

			strcat(pszReplyBuffer, "\r\n");
		}
		// if we are using Client Provided Session (CPS) and we have the CPS URL
		if(pQueryParams->cmd!=CMD_QUERY && (pQueryParams->opt&OPT_CPS_MODE)==OPT_CPS_MODE) {
			// append 'url=https://{hostname}/cps.sqrl?{CPS token}
			strcat(pszReplyBuffer, pszUrlPrefix);
			PlaceCpsUrlIntoBuffer(pszReplyBuffer+strlen(pszReplyBuffer), pPendingAuth);
			strcat(pszReplyBuffer, "\r\n");
		}
	}
//[
	LOG("pszReplyBuffer:");
	LOG("[]", pszReplyBuffer, strlen(pszReplyBuffer));
//]
	
	// now we base64url convert the assembled reply data...Send:
	SQ_DWORD BufLen=strlen((SQ_CHAR *)pszReplyBuffer);
	SQ_DWORD BufSiz=GetBase64urlEncodedSize(BufLen)+1;
	SQ_BYTE *pEncReplyBuffer=(SQ_BYTE *)GlobalAlloc(BufSiz);
	
	BufLen=SqrlCvrtToBase64((SQ_CHAR *)pEncReplyBuffer, BufSiz, (SQ_BYTE *)pszReplyBuffer, BufLen);
	
	if(pPendingAuth!=NULL) {
		// now calculate our reply's HMAC256 and update the PendingAuth list
		// the length of pEncReplyBuffer (BufLen) was returned by SqrlCvrtToBase64

		HMAC256(pPendingAuth->aTransactionMAC1, pEncReplyBuffer, BufLen, aSystemKey);
		memset(pPendingAuth->aTransactionMAC2, 0, SHA256_BYTE_LEN);

LOG("Calculation of HMAC1 in SendResponse():");
LOG("Encoded Reply:");
LOG("[c]", pEncReplyBuffer, BufLen);
LOG("TransactionMAC1:");
LOG("[]", pPendingAuth->aTransactionMAC1, SHA256_BYTE_LEN);
		
		// now we copy the new nut into our pending auths structure
		memcpy(pPendingAuth->aProtocolNut, szTheNextNut, SQRL_NUT_LEN);
		
		// and we return this object to the pending auths queue for subsequent use
		Enqueue(&PendingAuthsQueue, (QUEUE_OBJECT *)pPendingAuth);
	}
	rc=SendSqrlReply(pSCB, pEncReplyBuffer, BufLen, SQ_PASS);
	
	GlobalFree((void **)&pszReplyBuffer);
	GlobalFree((void **)&pEncReplyBuffer);
	END();
	return rc;
}

/*
===============================================================================
	UpdateSqrlAssociationRecord:
-------------------------------------------------------------------------------
*/
void UpdateSqrlAssociationRecord(SQRL_ASSOCIATIONS *pSqrlAssoc, CLIENT_TO_SERVER *pQueryParams) {
	ASSOC_REC_DATA *pAssocRecData=&pSqrlAssoc->AssocRecData;
	
	//	update the SQRL identity keys from the client's provided data
	memcpy(pAssocRecData->aSqrlServerUnlockKey, pQueryParams->suk, BINARY_KEY_LEN);
	memcpy(pAssocRecData->aSqrlVerifyUnlockKey, pQueryParams->vuk, BINARY_KEY_LEN);
	memcpy(pAssocRecData->aSqrlPublicIdentity, pQueryParams->idk, BINARY_KEY_LEN);

	//	save the new record under its new key...
	StoreSqrlRecord(pSqrlAssoc);
}

