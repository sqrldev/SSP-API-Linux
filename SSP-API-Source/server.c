
// server.c

/*
via HTTPS GET

/add.sqrl?user={user ID}&acct={account ID}&name={UserHandle}&stat={status}
/add.sqrl?acct={account ID}&name={UserHandle}&stat={status}

/rem.sqrl?user={user ID}
/rem.sqrl?acct={account ID}
/rem.sqrl?acct={account ID}&name={UserHandle}

/lst.sqrl?acct={account ID}
/lst.sqrl?invt={invitation}
/lst.sqrl?user={user ID}

/inv.sqrl?acct={account ID}&name={UserHandle}&stat={status}
*/ 

/*
===============================================================================
 	SERVER INTERFACE
-------------------------------------------------------------------------------
	This provides the implementation of the API functions used by the web server
	to manage SQRL-to-Account associations. It is called when the server wishes to
	add, remove, enumerate or invite a SQRL user to or from a web server account.
===============================================================================
*/

#include "global.h"

/*
===============================================================================
	DE-ESCAPE FORM DATA
	This removes URL-encoding from a form's POST data. Since the resulting buffer
	will always be smaller than the source, we perform an in-place conversion.
===============================================================================
*/
void DeEscapeFormData(SQ_CHAR *pszBufferToDeEscape) {
	BEG("DeEscapeFormData()");

	// Set up our source and destination string pointers
	char *src=pszBufferToDeEscape;
	char *dst=pszBufferToDeEscape;

	while(1) {
		// Get the next character
		char c=*src;
		src++;

		// if it's a "+"
		if(c=='+') {
			// convert it back into a space
			c=' ';
		}
		// if it's a URL escape character
		else if(c=='%') {
			// Convert the next two hex characters to binary
			c=HexToNybble(*src)<<4;
			src++;
			c|=HexToNybble(*src);
			src++;
		}
		// put the converted character back out
		*dst=c;
		dst++;
		
		// Exit if we are at the end of the string
		if(c=='\0') break;
	}
	END();
}

/*
===============================================================================
	PARSE QUERY PARAMS
-------------------------------------------------------------------------------
	Given a pointer to an ampersand-delimited (&) null-terminated string, this
	converts all '&' into nulls to zero-terminate the arguments and, for each
	parameter found, adds a pointer to the argument structure. If the parameter
	is NOT present the value placed into the structure will be the address of
	szNull as distinct from a pointer to the parameter's null. This distinction
	is important since it allows the caller to distinguish between a parameter
	which is present but whose value is null from a parameter that's not present.

===============================================================================
*/
void ParseQueryParams(QUERY_PARAMS *pQueryParams, SQ_CHAR *pszQueryString) {
	BEG("ParseQueryParams()");

	// look for instances of each of the tokens and set the pointer
	// to the token's parameter which follows the separating '='

	// we scan through this buffer of parameters
	// remove '+' and '%xx' URL escapements
	DeEscapeFormData(pszQueryString);

	const char *pszQueryTokenList[]={
		"user=",
		"acct=",
		"name=",
		"stat=",
		"invt="
		};

	// Set up an array to access the QUERY_PARAMS elements
	SQ_CHAR **ppQueryParams[]={
		&pQueryParams->pszSqrlUser,
		&pQueryParams->pszAccount,
		&pQueryParams->pszUserHandle,
		&pQueryParams->pszStatus,
		&pQueryParams->pszInvite
	};

	 int i;
	 int n=sizeof(pszQueryTokenList)/sizeof(pszQueryTokenList[0]);
	 char *ptr;
	 
	 // for each token
	 for(i=0; i<n; i++) {
		 // is it in the query?
		ptr=strstr(pszQueryString, pszQueryTokenList[i]);
		if(ptr!=NULL) {
			// advance to the parameter value
			ptr+=strlen(pszQueryTokenList[i]);
		}
		else {
			ptr=(char *)pszNull;
		}
		*ppQueryParams[i]=ptr;
	 }

	 // now let's convert all '&' separators into parameter null-terminators
	 n=strlen(pszQueryString);
	 ptr=pszQueryString;
	 for(i=0; i<n; i++, ptr++){
		 if(*ptr=='&') *ptr='\0';
	 }
	 
	END();
}

/*
===============================================================================
	VERIFY VALID INVITATION
===============================================================================
*/
void VerifyValidInvitation(SQ_BYTE * pSqrlPublicIdentity) {
	BEG("VerifyValidInvitation()");
	
	if(pSqrlPublicIdentity[0]!='.') {
		pSqrlPublicIdentity[0]='\0';
	}
	else {
		// we DO have a '.' as the first character, but since the field is binary
		// this could be a one-in-256 coincidence. So let's make sure the rest
		// are decimal digits
		int i;
		SQ_BYTE *ptr=&pSqrlPublicIdentity[1];
		for(i=0; i<INVITATION_TOKEN_LEN; i++, ptr++) {
			if(*ptr<'0' || *ptr>'9') {
				pSqrlPublicIdentity[0]='\0';
				break;
			}
		}
	}
	END();
}

/*
===============================================================================
	RETURN LIST OF ASSOCIATIONS
-------------------------------------------------------------------------------
	The Add/Remove/List queries each return a list of SQRL IDs, User Handles and
	the Status currently associated with the account after the query processing.
	This common function handles the return of that list from any of functions.
===============================================================================
*/
SQ_RCODE ReturnListOfAssociations(SQ_CHAR *pszAccount, SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ReturnListOfAssociations()");
	SQ_RCODE rc=SQ_FAIL;
	SQ_CHAR *pszList;
	
	// The caller must ensure pszAccount is not NULL

	// given the account ID string, lookup every record we have with that
	// account ID, format a possibly-multiline string and return a global
	// allocation which we will then return to our caller

	pszList=GetListOfAssociations(pszAccount);
	LogTheQueryAndReply(pszList, pSCB);
	
	rc=ReturnStringToCaller(pszList, pSCB);
	
	GlobalFree((void **)&pszList);
	END();
	return rc;
}

/*
===============================================================================
	UPDATE BY SQRL USER
-------------------------------------------------------------------------------
	We look up a unique SQRL record by the user's SQRL identity, then add any
	of the other information that the caller has provided to that record.
===============================================================================
*/
SQ_RCODE UpdateBySqrlUser(QUERY_PARAMS *pQueryParams) {
	BEG("UpdateBySqrlUser()");
	SQ_RCODE rc=SQ_FAIL;
	SQRL_ASSOCIATIONS SqrlAssoc;
	ASSOC_REC_DATA *pAssocRecData=&SqrlAssoc.AssocRecData;
	
	// lookup the database record by the user's SQRL identity
	if(GetRecordByUserID(&SqrlAssoc, pQueryParams->pszSqrlUser)==SQ_FAIL) {
		return rc;
	}

	// we found the record by the user's SQRL identity so now we update the
	// record with any additional info the caller provided in their query
	if(pQueryParams->pszAccount!=pszNull) {
		strncpy(pAssocRecData->szAccount, pQueryParams->pszAccount, 64);
	}
	if(pQueryParams->pszUserHandle!=pszNull) {
		strncpy(pAssocRecData->szUserHandle, pQueryParams->pszUserHandle, 64);
	}
	if(pQueryParams->pszStatus!=pszNull) {
		strncpy(pAssocRecData->szStatus, pQueryParams->pszStatus, 64);
	}
	// and now we update the record with the newly updated data
	rc=StoreSqrlRecord(&SqrlAssoc);

	END();
	return rc;
}

/*
===============================================================================
	ADD ASSOCIATION
-------------------------------------------------------------------------------
	/add.sqrl?user={user ID}&acct={account ID}&name={UserHandle}&stat={status}
	/add.sqrl?acct={account ID}&name={UserHandle}&stat={status}
-------------------------------------------------------------------------------
	This function allows the webserver to associate a newly authenticating
	SQRL ID with an existing webserver account and/or to provide or update
	an associated user handle and status with the association.
===============================================================================
*/
SQ_RCODE AddAssociation(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("AddAssociation()");
	SQ_RCODE rc=SQ_FAIL;
	QUERY_PARAMS QueryParams;

	ParseQueryParams(&QueryParams, pSCB->lpszQueryString);
	
	// if we have an Account, find it, otherwise return fail
	if(QueryParams.pszAccount!=NULL) {
		// do we have a User identity?
		if(QueryParams.pszSqrlUser!=NULL) {
			UpdateBySqrlUser(&QueryParams);
		}
		else {
			UpdateByAccount(&QueryParams, /*Remove=*/SQ_FALSE);
		}
		rc=ReturnListOfAssociations(QueryParams.pszAccount, pSCB);
	}
	END();
	return rc;
}

/*
===============================================================================
	REMOVE ASSOCIATION
-------------------------------------------------------------------------------
	/rem.sqrl?user={user ID}
	/rem.sqrl?acct={account ID}
	/rem.sqrl?acct={account ID}&name={UserHandle}
-------------------------------------------------------------------------------
	This deletes a SQRL/Account association. If a SQRL ID is present, since they
	are guaranteed to be unique, that record is removed. Otherwise, if an Account
	is supplied, one or more of those will be removed. If no UserHandle is supplied
	ALL matching accounts will be removed. Otherwise, if a UserHandle is given the
	record matching both Account and UserHandle will be removed.
===============================================================================
*/
void RemoveAssociation(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("RemoveAssociation()");
	QUERY_PARAMS QueryParams;
	SQRL_ASSOCIATIONS SqrlAssoc;

	ParseQueryParams(&QueryParams, pSCB->lpszQueryString);

	// if the caller provided us with a SQRL identity, we simply delete it
	if(QueryParams.pszSqrlUser!=NULL) {
		if(GetRecordByUserID(&SqrlAssoc, QueryParams.pszSqrlUser)==SQ_PASS) {
			QueryParams.pszAccount=SqrlAssoc.AssocRecData.szAccount;
			DeleteSqrlRecord(&SqrlAssoc);
		}
	}
	// if we have an account ID, find it and delete
	else if(QueryParams.pszAccount!=NULL) {
		UpdateByAccount(&QueryParams, /*Remove=*/SQ_TRUE);
	}
	if(QueryParams.pszAccount!=NULL) {
		ReturnListOfAssociations(QueryParams.pszAccount, pSCB);
	}
	END();
}

/*
===============================================================================
	LIST ASSOCIATIONS
-------------------------------------------------------------------------------
	/lst.sqrl?acct={account ID}
	/lst.sqrl?invt={invitation}
	/lst.sqrl?user={user ID}
-------------------------------------------------------------------------------
	When given an Account ID, this returns a list of all SQRL user associations
	currently associated with the provided web server account. When given an
	invitation or a SqrlUser, it returns the item matching that specification.
===============================================================================
*/
void ListAssociations(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("ListAssociations()");
	QUERY_PARAMS QueryParams;
	SQ_CHAR szUrlEncodedName[256];
	SQRL_ASSOCIATIONS SqrlAssoc;
	ASSOC_REC_DATA *pAssocRecData=&SqrlAssoc.AssocRecData;
	SQ_CHAR szLineItem[512];

	ParseQueryParams(&QueryParams, pSCB->lpszQueryString);

	do {
		// if the caller provided an ACCT= parameter we're being asked to list
		// all associations with that account.
		if(QueryParams.pszAccount!=NULL) {
			ReturnListOfAssociations(QueryParams.pszAccount, pSCB);
			END();
			return;
		}

		// it's not an enumeration of multiple associations so we'll be
		// retrieving a single record based upon our selection specification

		// let's check to see whether we were given an invitation to find...
		if(QueryParams.pszInvite!=NULL) {
			if(GetRecordByInvitation(&SqrlAssoc, QueryParams.pszInvite)==SQ_FAIL) {
				// if our lookup failed, we're finished
				ReturnStringToCaller((char *)pszNull, pSCB);
				break;
			}
		}
		else if(QueryParams.pszSqrlUser!=NULL) {
			if(GetRecordByUserID(&SqrlAssoc, QueryParams.pszSqrlUser)==SQ_FAIL) {
				// if our lookup failed, we're finished
				ReturnStringToCaller((char *)pszNull, pSCB);
				break;
			}
		}
		else {
			ReturnStringToCaller((char *)pszNull, pSCB);
			break;
		}

		// make sure the user's provided name is URL safe
		UrlEncode(szUrlEncodedName, pAssocRecData->szUserHandle);
	
		// check to see whether we have a valid invitation. If not, blank it
		VerifyValidInvitation(pAssocRecData->aSqrlPublicIdentity);

		// we've retrieved the item to return based upon the provided criteria
		// so now we format the standard data items into a string and return them
		sprintf(szLineItem, pszEnumerationFormat, SqrlAssoc.szSqrlUser, 
			pAssocRecData->szAccount, szUrlEncodedName,
			pAssocRecData->szStatus, &pAssocRecData->aSqrlPublicIdentity[1]);
			
		ReturnStringToCaller(szLineItem, pSCB);
	} while (0); // once
	END();
}

/*
===============================================================================
	INVITE ASSOCIATION
-------------------------------------------------------------------------------
	/inv.sqrl?acct={account ID}&name={UserHandle}&stat={status}
-------------------------------------------------------------------------------
	This creates a new pending invitation record for the provided web server
	acct identity. It assigns this a pseudo SQRL ID flagged by a period '.'
	character followed by 20 decimal digits. This is placed into the SQRL ID
	field and is also returned to the user as the response to this query.
===============================================================================
*/
void InviteAssociation(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("InviteAssociation");
	QUERY_PARAMS QueryParams;
	SQRL_ASSOCIATIONS SqrlAssoc;
	ASSOC_REC_DATA *pAssocRecData=&SqrlAssoc.AssocRecData;

	ParseQueryParams(&QueryParams, pSCB->lpszQueryString);

	memset(&SqrlAssoc, 0, sizeof(SQRL_ASSOCIATIONS));
	
	// place a new unique .{20-char} token into the SQRL public key field
	pAssocRecData->aSqrlPublicIdentity[0]='.';

	GetUnique20digitToken((char *)&pAssocRecData->aSqrlPublicIdentity[1], SQ_FALSE);

	// place the account identifier into the SQRL association record

	strncpy(pAssocRecData->szAccount, QueryParams.pszAccount, 65);
	strncpy(pAssocRecData->szUserHandle, QueryParams.pszUserHandle, 65);
	strncpy(pAssocRecData->szStatus, QueryParams.pszStatus, 65);
	StoreSqrlRecord(&SqrlAssoc);

	ReturnStringToCaller((SQ_CHAR *)&pAssocRecData->aSqrlPublicIdentity[1], pSCB);
	
	END();
}

//.[ For Testing
/*
===============================================================================
	ACCEPT INVITATION
-------------------------------------------------------------------------------
   	/acc.sqrl?user={user ID}&invt={invitation}
-------------------------------------------------------------------------------
	We are brought here when an authenticated SQRL user  has filled-in and 
	accepted an invitation to join an existing website account.
	At this point TWO SQRL associations will exist: The association of the SQRL
	user which will only contain the three SQRL identity keys and SQRL options.
	There will also be an association created by the website's invitation request.
	That request will contain the AccountID, UserHandle and Status. So our task
	here is to MERGE these two pending associations into a single permanent static
	association.
	
	We lookup the invitation to confirm its validity. If it's found we retain its
	Account, Username & Status data then delete the invitation. We then use
	/add.sqrl?sqrl={SQRL ID}&acct={account ID}&user={UserHandle}&stat={status}
	to merge the newly obtained AccountID, Userhandle and Status to the new SQRL.
===============================================================================
*/
SQ_RCODE AcceptInvitation(SQRL_CONTROL_BLOCK *pSCB) {
	BEG("AcceptInvitation");
	SQ_RCODE rc;
//	SQ_CHAR szOriginalCode[32];
//	SQ_CHAR szCompressedCode[32];
//	SQ_CHAR szListInvitedUserQuery[512];
//	SQ_CHAR szSqrlUser[16];
	QUERY_PARAMS QueryParams;
	SQRL_ASSOCIATIONS SqrlAssocRecord;
	ASSOC_REC_DATA *pAssocRecData=&SqrlAssocRecord.AssocRecData;
	
	// Get the UserID and 20-digit invitation
	ParseQueryParams(&QueryParams, pSCB->lpszQueryString);

//[
LOG("QueryParams");
LOG("  SqrlUser: %s", QueryParams.pszSqrlUser);
LOG("   Account: %s", QueryParams.pszAccount);
LOG("UserHandle: %s", QueryParams.pszUserHandle);
LOG("    Status: %s", QueryParams.pszStatus);
LOG("    Invite: %s", QueryParams.pszInvite);
//]

	// Lookup the invitation in the database
	if(GetRecordByInvitation(&SqrlAssocRecord, QueryParams.pszInvite)==SQ_FAIL 
		|| strlen(pAssocRecData->szAccount)==0) {
		ReturnStringToCaller((char *)pszNull, pSCB);
		END();
		return SQ_FAIL;
	}
	
	// Copy the invitation's account, handle and status into QueryParms
	QueryParams.pszAccount=pAssocRecData->szAccount;
	QueryParams.pszUserHandle=pAssocRecData->szUserHandle;
	QueryParams.pszStatus=pAssocRecData->szStatus;

//[
LOG("QueryParams");
LOG("  SqrlUser: %s", QueryParams.pszSqrlUser);
LOG("   Account: %s", QueryParams.pszAccount);
LOG("UserHandle: %s", QueryParams.pszUserHandle);
LOG("    Status: %s", QueryParams.pszStatus);
LOG("    Invite: %s", QueryParams.pszInvite);
//]

	// Update the invited SqrlUser
	UpdateBySqrlUser(&QueryParams);

	// Remove the invitation record from the database
	rc=DeleteSqrlRecord(&SqrlAssocRecord);

	ReturnListOfAssociations(QueryParams.pszAccount, pSCB);
	
	END();
	return rc;
}

//.]
