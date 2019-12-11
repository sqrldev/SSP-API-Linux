
// database.c - Interface ot the Berkeley Database

#include "global.h"
#include "db.h"

pthread_t DBSweepThreadId;

const SQ_CHAR *pszMainDBname="sqrl-assoc.db"; // Primary account database file
const SQ_CHAR *pszAcctDBname="sqrl-index.db"; // Secondary Accounts index
const SQ_CHAR *pszSqrlDBname="sqrl-ident.db"; // Secondary SQRL identity index
const SQ_CHAR *pszDeadDBname="sqrl-super.db"; // Superseded identities log file

DB *pMainDB;
DB *pAcctDB;
DB *pSqrlDB;
DB *pDeadDB;
/*
===============================================================================			
	OPEN BDB				     
-------------------------------------------------------------------------------
	Create an instance of a DB structure (called BDB here since 'db' is a     
	MASM reserved name), set a 4K page size, 32K caching size, specify and    
	enable AES encryption, and open the indicated file, returning the status. 
-------------------------------------------------------------------------------
*/
DB *OpenBDB(const SQ_CHAR *pszDBname, SQ_BOOL AllowDups) {
	BEG("OpenBDB()");
	SQ_CHAR szDatabaseFile[SQ_MAX_PATH];
	DB *ptrBDB;
	
	GetDatabasePathname(szDatabaseFile);
	strcat(szDatabaseFile, pszDBname);
	
	db_create((DB **)&ptrBDB, NULL, 0);

	// set the database's page size to 4K (NTFS's cluster size)
	ptrBDB->set_pagesize(ptrBDB, 4096);
	
	// set the database's cache size to 32K (system enforced min is 20K)
	ptrBDB->set_cachesize(ptrBDB, 0, 32768, 1);
	
	// set the database's encryption mode (AES) and password key
	ptrBDB->set_encrypt(ptrBDB, szDatabaseKey, DB_ENCRYPT_AES);
		
	// specify that we will be using checksum and encryption
	SQ_DWORD flags=DB_CHKSUM|DB_ENCRYPT;
	if(AllowDups==SQ_TRUE) {
		flags|=DB_DUP|DB_DUPSORT;
	}
	ptrBDB->set_flags(ptrBDB, flags);	
	
	// and now open the database
	if(ptrBDB->open(ptrBDB, NULL, szDatabaseFile, NULL, DB_BTREE, DB_CREATE|DB_THREAD, 0)!=0) {
		ptrBDB=NULL;
	}
	
	END();
	return ptrBDB;
}

/*
===============================================================================
	SAFE DATABASE CLOSE
===============================================================================
*/
SQ_RCODE SafeDatabaseClose(DB *pDatabaseObject) {
	BEG("SafeDatabaseClose()");
	
	if(pDatabaseObject!=NULL) {
		pDatabaseObject->close(pDatabaseObject, 0);
	}
	
	END();
	return SQ_PASS;
}

/*
-------------------------------------------------------------------------------
	This initializes the DBTs for a series of DB_SET / DB_NEXT calls
-------------------------------------------------------------------------------
*/
void SetDBTs(SQ_CHAR *pszAccount, SQRL_ASSOCIATIONS *pSqrlAssoc, DBT *pKey, DBT *pIndex, DBT *pData) {
	BEG("SetDBTs()");
	
	memset(pKey, 0, sizeof(DBT));
	memset(pIndex, 0, sizeof(DBT));
	memset(pData, 0, sizeof(DBT));

	pKey->data=pszAccount;
	pKey->size=strlen(pszAccount);

	pIndex->data=pSqrlAssoc->szSqrlUser;
	pIndex->ulen=USER_ID_FIELD_SIZ;
	pIndex->flags=DB_DBT_USERMEM;

	pData->data=&pSqrlAssoc->AssocRecData;
	pData->ulen=sizeof(ASSOC_REC_DATA);
	pData->flags=DB_DBT_USERMEM;
	
	END();
}

/*
===============================================================================
	ACCT KEY CREATOR (callback)			     
-------------------------------------------------------------------------------
	This is the Account index key synthesizing callback. It provides the   
	key for the Secondary Account index file via the file association.     
-------------------------------------------------------------------------------
*/
int AcctKeyCreator(DB *p2ndDB, const DBT *p1stKey, const DBT *p1stData, DBT *p2ndKey) {
	BEG("AcctKeyCreator()");
	LOG("IN: p1stKey->data: %s", p1stKey->data);
	LOG("IN: p1stData->data->szAccount: %s", ((ASSOC_REC_DATA *)(p1stData->data))->szAccount);
	
	// (Only uses 1stData and 2ndKey)
	
	// zero the result DBT
	memset(p2ndKey, 0, sizeof(DBT));
	
	// set the ACCOUNTS record of the primary DBT as our Secondary Key
	p2ndKey->data=p1stData->data;

	int len=strlen(p1stData->data);
	if(len==0) {
		// if the key is null we create an szNull key ("")
		len++;
	}
	// set the username's length
	p2ndKey->size=len;

	LOG("OUT: p2ndKey->data->pAccount: %s", ((ASSOC_REC_DATA *)(p2ndKey->data))->szAccount);
	LOG("OUT: p2ndKey->size: %d", p2ndKey->size);
	END();

	// return that we should index this key
	return 0;
}

/*
===============================================================================
	SQRL KEY CREATOR (callback)			     
-------------------------------------------------------------------------------
	This is the PublicKey index key synthesizing callback. It provides the   
	key for the Secondary PublicKey index file via the file association.     
-------------------------------------------------------------------------------
*/
int SqrlKeyCreator(DB *p2ndDB, const DBT *p1stKey, const DBT *p1stData, DBT *p2ndKey) {
	BEG("SqrlKeyCreator()");
	LOG("IN: p1stKey->data: %s", p1stKey->data);
	LOG("IN: p1stData->data->szAccount: %s", ((ASSOC_REC_DATA *)(p1stData->data))->szAccount);

	// (Only uses 1stData and 2ndKey)

//	mov	edi, p2ndKey		; get our result DBT pointer
//	invoke	FillMemory, edi, SIZEOF DBT, NULL ; zero the result DBT
	memset(p2ndKey, 0, sizeof(DBT));

	SQ_BYTE *pSqrlID=((ASSOC_REC_DATA *)(p1stData->data))->aSqrlPublicIdentity;
	
//[
	LOG("pSqrlID:");
	LOG("[]", pSqrlID, BINARY_KEY_LEN);
//]	
	// if we have a SQRL ID, we index it

	// If the SqrlPublicIdentity (IDK) is all zeros, assume we don't have one
	// there's only a 1 in 2^256 chance the IDK is all zeros
	for(int i=0; i<BINARY_KEY_LEN; i++) {
		if(pSqrlID[i]!=0) {
			// set as our Secondary Key
			p2ndKey->data=pSqrlID;
			p2ndKey->size=BINARY_KEY_LEN;
//[
			LOG("OUT: p2ndKey->data");
			LOG("[]", p2ndKey->data, p2ndKey->size);
//]
			END();
			// indicate we should index this key
			return 0;
		}
	}
	LOG("OUT: No SqrlID, DB_DONOTINDEX");
	END();

	//	remove NULL indexes
	return DB_DONOTINDEX;
}

/*
===============================================================================
	NIGHTLY ABANDONED INVITATION SWEEP
-------------------------------------------------------------------------------
	This enumerates though the main database in primary key sequence, checking
	for any records whose szSqrlPublicKey begins with '.' which would flag it
	as a record created as an invitation which has not yet been associated with
	a SQRL ID, which would accept the invitation, replacing the '.' char prefix
	with a base64url SQRL public key. For any '.' records we find, we check the
	record's age. If the invitation has been outstanding for more than two
	weeks (14 days) we delete the invitation.
===============================================================================
*/
void SweepNightlyAbandonedInvitations() {
	BEG("SweepNightlyAbandonedInvitations()");
	SQ_QWORD CurrentTime;
	DBC *pCursor;
	DBT KeyDBT;
	DBT DataDBT;
	DBT SecondaryDBT;
	SQRL_ASSOCIATIONS SqrlRecord;
	ASSOC_REC_DATA *pAssocRecData=&SqrlRecord.AssocRecData;
	
	int DBmode;
		
	// get 'now' for the last-accessed age of any abandoned SQRL DB records
	SQ_GetSystemTimeAsFileTime(&CurrentTime);

	// create a cursor to enumerate over the secondary Sqrl ID index
	if(pSqrlDB->cursor(pSqrlDB, NULL, &pCursor, 0)!=0) {
		END();
		return;
	}

	memset(&SecondaryDBT, 0, sizeof(DBT));
	SecondaryDBT.data=&".";
	SecondaryDBT.size=1;
	
	// setup our user buffers to receive the enumerated data
	memset(&KeyDBT, 0, sizeof(DBT));
	KeyDBT.data=&SqrlRecord;
	KeyDBT.ulen=USER_ID_FIELD_SIZ;
	KeyDBT.flags=DB_DBT_USERMEM;

	memset(&DataDBT, 0, sizeof(DBT));
	DataDBT.data=pAssocRecData;
	DataDBT.ulen=sizeof(ASSOC_REC_DATA);
	DataDBT.flags=DB_DBT_USERMEM;

	DBmode=DB_SET_RANGE;
	while(1) {
		// access the first or next record of the DB in SQRL ID sequence
		if(pCursor->pget(pCursor, (DBT*)&SecondaryDBT, (DBT*)&KeyDBT, (DBT*)&DataDBT, DBmode)!=0) {
			// no more records
			break;
		}
		DBmode=DB_NEXT;

		// the 'get' returned zero, so we DID retrieve a new database record
		// does the SQRL public key of this record begin with '.'
		if(pAssocRecData->aSqrlPublicIdentity[0]!='.') {
			//	if not, we're done here (all the '.' records come first)
			break;
		}
	
		// we have an invitation record, so let's check its age...
		if(SQ_GetFileTimeAgeInMinutes(&pAssocRecData->SqrlLastActivityDate, &CurrentTime)<60*24*14) {
			//	keep it
			continue;
		}
	
		// after 14 days, rescind the invitation
		// we found an old invitation beginning with '.' so let's delete it
		if(pCursor->del(pCursor, 0)!=0) {
			// it failed
			break;
		}
	} // back to while()
	
	// close our enumeration cursor
	pCursor->close(pCursor);

	// to protect from crashing write the updates now
	SyncAllBDB();

	END();
}

/*
===============================================================================
	NIGHTLY ABANDONED AUTHENTICATIONS SWEEP
-------------------------------------------------------------------------------
	When a user authenticates with an unknown SQRL identity, a SQRL record is
	created and this authentication is reported to the webserver so that it can
	associate this new authentication record with a webserver account. Since it
	is possible for a webserver to drop the ball on this, we perform a nightly
	sweep of the SQRL database looking for any "abandoned" unassociated records.
	Since we sweep only once every 24 hours, we delete any records older than 24
	hours at the time of the sweep. NOTE: We enumerate records by secondary key
	(szAccount) where we allow duplicate keys, since we might have multiple SQRL
	identities associated with a single webserver account. So we'll have multiple
	records with the same szAccount key. THIS sweep for abandoned records will be
	efficient since our secondary key is sorted and our target abandoned records
	will have NULL szAccount fields so they will be the first records enumerated.
===============================================================================
*/
void SweepNightlyAbandonedAuthentications() {
	BEG("SweepNightlyAbandonedAuthentications()");
	SQ_QWORD CurrentTime;
	DBC *pCursor;
	DBT KeyDBT;
	DBT DataDBT;
	DBT SecondaryDBT;
	SQRL_ASSOCIATIONS SqrlRecord;
	ASSOC_REC_DATA *pAssocRecData=&SqrlRecord.AssocRecData;

	// get 'now' for the last-accessed age of any abandoned SQRL DB records
	SQ_GetSystemTimeAsFileTime(&CurrentTime);

	// create a cursor to enumerate over the secondary Sqrl ID index
	if(pAcctDB->cursor(pAcctDB, NULL, &pCursor, 0)!=0) {
		END();
		return;
	}

	memset(&SecondaryDBT, 0, sizeof(DBT));
	SecondaryDBT.data=(char *)pszNull;
	SecondaryDBT.size=1;

	// setup our user buffers to receive the enumerated data
	memset(&KeyDBT, 0, sizeof(DBT));
	KeyDBT.data=&SqrlRecord;
	KeyDBT.ulen=USER_ID_FIELD_SIZ;
	KeyDBT.flags=DB_DBT_USERMEM;

	memset(&DataDBT, 0, sizeof(DBT));
	DataDBT.data=&SqrlRecord.AssocRecData;
	DataDBT.ulen=sizeof(ASSOC_REC_DATA);
	DataDBT.flags=DB_DBT_USERMEM;

	int mode=DB_SET_RANGE;
	
	while(1) {
		// access the first or next record of the DB in SQRL ID sequence
		if(pCursor->pget(pCursor, &SecondaryDBT, &KeyDBT, &DataDBT, mode)!=0) {
			break;
		}

		// the 'get' returned zero, so we DID retrieve a new database record
		// does the retrieved record have a zero-length szAccount (key)?
		if(strlen(pAssocRecData->szAccount)>0) {
			// as soon as we hit a non-null key, we're done
			break;
		}
	
		// prep for retrieving a series of values
		mode=DB_NEXT;

		// we have an abandoned record (no associated webserver account)
		// so let's check its age...
		// if it's been at least 4 hours, remove the record
		if(SQ_GetFileTimeAgeInMinutes(&pAssocRecData->SqrlLastActivityDate, &CurrentTime)<60*4) {
			// otherwise keep it
			continue;
		}

		// we found a record older than four hours with no webserver association
		// so let's delete it
		if(pCursor->del(pCursor, 0)!=0) {
			//	if this fails we're done
			break;
		}
	}

	// close our enumeration cursor
	pCursor->close(pCursor);

	// to protect from crashing write the updates now
	SyncAllBDB();
}

/*
===============================================================================
	DATABASE SWEEP THREAD
===============================================================================
*/
void *DatabaseSweepThread(SQ_VOID *Dummy) {
	time_t EpochTime=time(NULL);
	struct tm LocalTime=*localtime(&EpochTime);
	int LastSweepDay=LocalTime.tm_wday;
	
	// Check at the 30-sec mark (the first check is not less than 30 sec from now)
	sleep(90-LocalTime.tm_sec);
	
	while(SqrlApiRunning==SQ_TRUE) {
		EpochTime=time(NULL);
		LocalTime=*localtime(&EpochTime);
//.		LOG("DatabaseSweepThread: Checking for day change "
//.			"%d:%02d:%02d", LocalTime.tm_hour, LocalTime.tm_min, LocalTime.tm_sec);

		if(LocalTime.tm_wday!=LastSweepDay) {
			SweepNightlyAbandonedInvitations();
			SweepNightlyAbandonedAuthentications();
			
			// Wait again for the next day
			LastSweepDay=LocalTime.tm_wday;
		}
		sleep(60); // seconds
	}
	return NULL;
}	

/*
==============================================================================
	TERMINATE DATA SWEEPER
-------------------------------------------------------------------------------
	We awaken the sleeping thread by kicking it out of the SleepEx call at which
	point the fact that "SqrlApiRunning" has been reset will terminate the thread.
===============================================================================
*/
void TerminateDatabaseSweeper() {
	BEG("TerminateDatabaseSweeper()");

	if(DBSweepThreadId!=0) {
		if(pthread_cancel(DBSweepThreadId)!=0) {
			LOG("Error: Unable to cancel thread");
		}

	   /* Join with thread to see what its exit status was */
	   void *result;
	   if(pthread_join(DBSweepThreadId, &result)!=0) {
			LOG("Error: Unable to join thread");
	   }
	   if(result==PTHREAD_CANCELED) {
		   LOG("DBSweepThread cancelled, result=%d", result);
		   DBSweepThreadId=0;
	   }
	   else {
	       LOG("DBSweepThread not cancelled, result=%d", result);
	   }
	}
	END();
}

/*
===============================================================================
	GET DATABASE PATHNAME
===============================================================================
*/
void GetDatabasePathname(SQ_CHAR *pszDatabasePath) {
	BEG("GetDatabasePathname()");
	// get our module's full pathname for locating the database files

//. Don't know what to do here... just use the current directory

	strcpy(pszDatabasePath, "");

	END();
}

/*
============================================================================
	SYNC ALL BDB				     
 -------------------------------------------------------------------------- 
    Berkeley DB =NEVER= flushes RAM buffers to disk. So this leaves us	     
    vulnerable to crashing. So we flush the caches after any modification.  
----------------------------------------------------------------------------
*/
void SyncAllBDB() {
	BEG("SyncAllBDB()");

	pMainDB->sync(pMainDB, 0);
	pMainDB->sync(pAcctDB, 0);
	pMainDB->sync(pSqrlDB, 0);
	pMainDB->sync(pDeadDB, 0);

	END();
}

/*
===============================================================================
	DELETE SQRL DATABASE FILES
===============================================================================
*/
void DeleteSqrlDatabaseFiles() {
	BEG("DeleteSqrlDatabaseFiles()");
	SQ_CHAR szDatabaseFile[SQ_MAX_PATH];

	GetDatabasePathname(szDatabaseFile);
	strcat(szDatabaseFile, pszMainDBname);
	remove(szDatabaseFile);

	GetDatabasePathname(szDatabaseFile);
	strcat(szDatabaseFile, pszAcctDBname);
	remove(szDatabaseFile);

	GetDatabasePathname(szDatabaseFile);
	strcat(szDatabaseFile, pszSqrlDBname);
	remove(szDatabaseFile);

	GetDatabasePathname(szDatabaseFile);
	strcat(szDatabaseFile, pszDeadDBname);
	remove(szDatabaseFile);

	END();
}

/*
===============================================================================
	OPEN SQRL DATABASE FILES			     
 ------------------------------------------------------------------------------
	This opens the three SQRL account database files, the primary and     
	both secondary indexes, and associates the two secondary indexes	     
	to the primary through the two key creator callback functions.	     
-------------------------------------------------------------------------------
*/
SQ_RCODE OpenSqrlDatabaseFiles() {
	BEG("OpenSqrlDatabaseFiles()");

	// Create the PRIMARY DB
	pMainDB=OpenBDB(pszMainDBname, /*AllowDups=*/SQ_FALSE);
	if(pMainDB==NULL) {
		LOG("Unable to create %s", pszMainDBname);
		END();
		return SQ_FAIL;
	}

	// Create the Account DB
	// associate our secondary index to track primary changes

	pAcctDB=OpenBDB(pszAcctDBname, /*AllowDups=*/SQ_TRUE);
	if(pAcctDB==NULL) {
		LOG("Unable to create %s", pszAcctDBname);
		END();
		return SQ_FAIL;
	}
//[check return value?]	
	pMainDB->associate(pMainDB, NULL, pAcctDB, AcctKeyCreator, 0);

	// Create the Sqrl DB
	// associate our secondary index to track primary changes
	
	pSqrlDB=OpenBDB(pszSqrlDBname, /*AllowDups=*/SQ_FALSE);
	if(pSqrlDB==NULL) {
		LOG("Unable to create %s", pszSqrlDBname);
		END();
		return SQ_FAIL;
	}
//[check return value?]	
	pMainDB->associate(pMainDB, NULL, pSqrlDB, SqrlKeyCreator, 0);

	// Create the Dead DB 
	pDeadDB=OpenBDB(pszDeadDBname, /*AllowDups=*/SQ_FALSE);
	if(pDeadDB==NULL) {
		LOG("Unable to create %s", pszDeadDBname);
		END();
		return SQ_FAIL;
	}

	// create our background database sweeper thread	

	int err=pthread_create(&DBSweepThreadId, NULL, &DatabaseSweepThread, NULL);
	if(err!=0) {
		LOG("Error: Unable to create thread: %s", strerror(err));
	}
	else {
		LOG("DatabaseSweepThread created successfully");
	}

	END();
	return SQ_PASS;
}
/*
============================================================================
	CLOSE BERKELEY DBs				     
 -------------------------------------------------------------------------- 
	This closes the SQRL database files after flushing any dirty caches.    
----------------------------------------------------------------------------
*/
SQ_RCODE CloseBerkeleyDBs() {
	BEG("CloseBerkeleyDBs()");

	// we must first terminate our background cleanup sweeper thread
	TerminateDatabaseSweeper();
	
	// now we're able to close our databases
	SafeDatabaseClose(pAcctDB);
	pAcctDB=NULL;
	
	SafeDatabaseClose(pSqrlDB);
	pSqrlDB=NULL;
	
	SafeDatabaseClose(pMainDB);
	pMainDB=NULL;
	
	SafeDatabaseClose(pDeadDB);
	pDeadDB=NULL;
	
	END();
	return SQ_PASS;
}

/*
============================================================================
	STORE SQRL RECORD				     
 -------------------------------------------------------------------------- 
	Given a pointer a SqrlDemoRecord, this stores it into the SQRL database.  
	If the record exists, its RecordNumber index will be non-NULL, so we'll   
	overwrite any existing record with the same index. If the index is NULL,   
	this is a new record, so bump the index count, fill it in, and save it.   
----------------------------------------------------------------------------
*/
SQ_RCODE StoreSqrlRecord(SQRL_ASSOCIATIONS *pSqrlDataRecord) {
	BEG("StoreSqrlRecord()");
	SQ_RCODE rc=SQ_FAIL;
	ASSOC_REC_DATA *pAssocRecData=&pSqrlDataRecord->AssocRecData;
	DBT KeyDBT;
	DBT DataDBT;
	
	LOG("Storing Association for SQRL: %s and Acct: %s",
		pSqrlDataRecord->szSqrlUser, pAssocRecData->szAccount);

	if(strlen(pSqrlDataRecord->szSqrlUser)>0) {
		// This record already exists, just update it
	}
	else {
		// Assign a new primary index for this record
		GetUnique12charNut(pSqrlDataRecord->szSqrlUser, /*Null-Terminate=*/SQ_TRUE);
	}

	// set the timestamp for this write
	SQ_GetSystemTimeAsFileTime(&pAssocRecData->SqrlLastActivityDate);
	
	memset(&KeyDBT, 0, sizeof(KeyDBT));
	KeyDBT.data=&pSqrlDataRecord->szSqrlUser;
	KeyDBT.size=sizeof(pSqrlDataRecord->szSqrlUser);

	memset(&DataDBT, 0, sizeof(DataDBT));
	DataDBT.data=&pSqrlDataRecord->AssocRecData;
	DataDBT.size=sizeof(ASSOC_REC_DATA);

	if(pMainDB->put(pMainDB, NULL, &KeyDBT, &DataDBT, 0)==0) {
		rc=SQ_PASS;
	}
	
	// to protect from crashing write the updates now
	SyncAllBDB();
	
	END();
	return rc;
}

/*
===============================================================================
	GET RECORD BY USER ID
-------------------------------------------------------------------------------
	Given a user-supplied buffer and 12-character User ID index: Retrieve    
	a SQRL association record to the user's buffer. Return ZERO on success.     
-------------------------------------------------------------------------------
*/
SQ_RCODE GetRecordByUserID(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_CHAR *pszUserId) {
	BEG("GetRecordByUserID()");
	SQ_RCODE rc=SQ_FAIL;
	SQ_CHAR SqrlUser[USER_ID_FIELD_SIZ]; // 16
	DBT Index;
	DBT Data;

	memset(SqrlUser, 0, sizeof(SqrlUser));
	strncpy(SqrlUser, pszUserId, USER_ID_LEN); // 12 chars
	memcpy(pSqrlRecord->szSqrlUser, SqrlUser, USER_ID_FIELD_SIZ);

	memset(&Index, 0, sizeof(DBT));
	Index.data=SqrlUser;
	Index.size=USER_ID_FIELD_SIZ;

	memset(&Data, 0, sizeof(DBT));
	Data.data=&pSqrlRecord->AssocRecData;
	Data.ulen=sizeof(ASSOC_REC_DATA);
	Data.flags=DB_DBT_USERMEM;

	if(pMainDB->get(pMainDB, NULL, &Index, &Data, 0)==0) {
		rc=SQ_PASS;
	}
	END();
	return rc;
}

/*
===============================================================================
	GET RECORD BY SQRL ID
-------------------------------------------------------------------------------
    Given a user-supplied buffer and 44-character ASCII SQRL ID, retrieve
    a SQRL association into the user's buffer & return ZERO on success.     
-------------------------------------------------------------------------------
*/
SQ_RCODE GetRecordBySqrlID(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_CHAR *pszSqrlID) {
	BEG("GetRecordBySqrlID()");
	SQ_RCODE rc=SQ_FAIL;
	SQ_BYTE LookupKey[32];
	DBT SecondaryKey;
	DBT Index;
	DBT Data;

	memset(&SecondaryKey, 0, sizeof(DBT));
//. what if the conversion fails?
	SqrlCvrtFromBase64(LookupKey, BINARY_KEY_LEN, pszSqrlID, ASCII_KEY_LEN);
	
	SecondaryKey.data=LookupKey;
	SecondaryKey.size=BINARY_KEY_LEN;

	memset(&Index, 0, sizeof(DBT));
	Index.data=pSqrlRecord;
	Index.ulen=USER_ID_FIELD_SIZ;
	Index.flags=DB_DBT_USERMEM;

	memset(&Data, 0, sizeof(DBT));
	Data.data=&pSqrlRecord->AssocRecData;
	Data.ulen=sizeof(ASSOC_REC_DATA);
	Data.flags=DB_DBT_USERMEM;

	if(pSqrlDB->pget(pSqrlDB, NULL, &SecondaryKey, &Index, &Data, 0)==0) {
		rc=SQ_PASS;
	}
	END();
	return rc;
}

/*
===============================================================================
	GET RECORD BY SQRL KEY
------------------------------------------------------------------------------
	Given a user-supplied buffer and 32-byte SQRL Identity binary key, retrieve    
	a SQRL demo association into the user's buffer and return ZERO on success.     
-------------------------------------------------------------------------------
*/
SQ_RCODE GetRecordBySqrlKey(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_BYTE *p_idk) {
	BEG("GetRecordBySqrlKey()");
	SQ_RCODE rc=SQ_FAIL;
	DBT SecondaryKey;
	DBT Index;
	DBT Data;

	memset(&SecondaryKey, 0, sizeof(DBT));
	SecondaryKey.data=p_idk;
	SecondaryKey.size=BINARY_KEY_LEN;

	memset(&Index, 0, sizeof(DBT));
	Index.data=pSqrlRecord;
	Index.ulen=USER_ID_FIELD_SIZ;
	Index.flags=DB_DBT_USERMEM;

	memset(&Data, 0, sizeof(DBT));
	Data.data=&pSqrlRecord->AssocRecData;
	Data.ulen=sizeof(ASSOC_REC_DATA);
	Data.flags=DB_DBT_USERMEM;

	if(pSqrlDB->pget(pSqrlDB, NULL, &SecondaryKey, &Index, &Data, 0)==0) {
		rc=SQ_PASS;
	}

	END();
	return rc;
}

/*
===============================================================================
	GET RECORD BY INVITATION
-------------------------------------------------------------------------------
	Given a user-supplied buffer and 20-char Invitation index: Retrieve    
	a SQRL demo record into the user's buffer andreturn ZERO on success.     
-------------------------------------------------------------------------------
*/
SQ_RCODE GetRecordByInvitation(SQRL_ASSOCIATIONS *pSqrlRecord, SQ_CHAR *pszInvitation) {
	BEG("GetRecordByInvitation()");
	
	// The invitation is stored in the same field as the Sqrl idk and treated as binary data
	// 32 byte idk: 0123456789abcdef0123456789abcdef 
	// 21 char inv: .01234567890123456789
	SQ_RCODE rc=SQ_FAIL;
//	SQ_CHAR szSqrlIdentity[ASCII_BUF_LEN];
	SQ_BYTE aSqrlIdentity[BINARY_KEY_LEN];
//	memset(szSqrlIdentity, 0, ASCII_BUF_LEN);
	memset(aSqrlIdentity, 0, BINARY_KEY_LEN);
	
	// invitations are flagged with a PERIOD prefix
//	szSqrlIdentity[0]='.';
	aSqrlIdentity[0]='.';

	// copy the provided SZ string into the assembly buffer + null
	strncpy((SQ_CHAR *)&aSqrlIdentity[1], pszInvitation, BINARY_KEY_LEN-1);
	
	// lookup the SQRL associations record by invitation
	if(GetRecordBySqrlKey(pSqrlRecord, aSqrlIdentity)==SQ_PASS) {
		rc=SQ_PASS;
	}
	
	END();
	return rc;
}

/*
============================================================================
	DELETE SQRL RECORD				     
----------------------------------------------------------------------------
*/
SQ_RCODE DeleteSqrlRecord(SQRL_ASSOCIATIONS *pSqrlAssocRec) {
	BEG("DeleteSqrlRecord()");
	SQ_RCODE rc=SQ_FAIL;
	DBT Index;

	memset(&Index, 0, sizeof(DBT));
	
	Index.data=pSqrlAssocRec;
	Index.size=USER_ID_FIELD_SIZ;

	if(pMainDB->del(pMainDB, NULL, &Index, 0)==0) {
		rc=SQ_PASS;
	}
	SyncAllBDB();
	
	END();
	return rc;
}

/*
============================================================================
	LOG SUPERSEDED ID
---------------------------------------------------------------------------- 
	Given a pointer to a 32-byte Superseded identity buffer, this stores it
	into the dead SQRL identities database. We do not need to check for the
	existing identity since this DDB do not allow DUPS and any existing rec
	will simply be overwritten. This is faster than first checking and not
	store if the record is found.
----------------------------------------------------------------------------
*/
SQ_RCODE LogSupersededID(SUPERSEDED_IDENTITIES *pIdentityToLog) {
	BEG("LogSupersededID()");
	SQ_RCODE rc=SQ_FAIL;
	DBT KeyDBT;
	DBT DataDBT;
//[
	LOG("Logging Superseded ID: ");
	LOG("[]", pIdentityToLog->aSupersededIdentity, BINARY_KEY_LEN);
//]
	memset(&KeyDBT, 0, sizeof(KeyDBT));
	
	KeyDBT.data=pIdentityToLog->aSupersededIdentity;
	KeyDBT.size=BINARY_KEY_LEN;

	// no associated data to be stored in the log
	memset(&DataDBT, 0, sizeof(DBT));

	if(pDeadDB->put(pDeadDB, NULL, &KeyDBT, &DataDBT, 0)==0) {
		rc=SQ_PASS;
	}

	// to protect from crashing write the updates now
	SyncAllBDB();
	
	END();
	return rc;
}

/*
===============================================================================
	CHECK FOR SUPERSEDED ID
-------------------------------------------------------------------------------
	Given a pointer to a 32-byte ID to check, this returns ZERO if the ID =WAS=
	found in the Superseded identities log.
-------------------------------------------------------------------------------
*/
SQ_RCODE CheckForSupersededID(SUPERSEDED_IDENTITIES *pIdentityToCheck) {
	BEG("CheckForSupersededID()");
	SQ_RCODE rc=SQ_FAIL;
	DBT Index;
	DBT Data;

	memset(&Index, 0, sizeof(DBT));
	Index.data=pIdentityToCheck->aSupersededIdentity;
	Index.size=BINARY_KEY_LEN;

	// no associated data to be stored in the log
	memset(&Data, 0, sizeof(DBT));
	Data.ulen=0; // no data
	Data.flags=DB_DBT_USERMEM;

	if(pDeadDB->get(pDeadDB, NULL, &Index, &Data, 0)==0) {
		rc=SQ_PASS;
	}

	END();
	return rc;
}

/*				
===============================================================================
	GET LIST OF ASSOCIATIONS
-------------------------------------------------------------------------------
	The Add/Remove/List queries each return a list of SQRL IDs, User Handles and
	the Status currently associated with the account after the query processing.
	This common function handles the return of that list from any of functions.
	It formats the SQRL Association data and returns a set of CR/LF terminated
	lines in a single global alloc containing a single szString.
===============================================================================
*/
SQ_CHAR *GetListOfAssociations(SQ_CHAR *pszAccount) {
	BEG("GetListOfAssociations()");
	LOG("Account: %s", pszAccount);
	DBC *pCursor;
	DBT Key;
	DBT Index;
	DBT Data;
	SQ_CHAR szLineItem[512];
	SQ_DWORD TotalLength;
	SQ_CHAR szUrlEncodedName[256];
	SQ_CHAR *pszBuffer;
	SQRL_ASSOCIATIONS SqrlAssoc;
	SQRL_ASSOCIATIONS *SAptr;
	int DBmode;
	
	pszBuffer=NULL;
	pCursor=NULL;

	// create a cursor to enumerate over the SECONDARY database
	if(pAcctDB->cursor(pAcctDB, NULL, &pCursor, 0)!=0) {
		END();
		return (SQ_CHAR *)GlobalAlloc(1);
	}

	TotalLength=0;
	SetDBTs(pszAccount, &SqrlAssoc, &Key, &Index, &Data);
	DBmode=DB_SET;
	while(1) {
		// access the first or next record of the DB in SQRL ID sequence
		if(pCursor->pget(pCursor, (DBT*)&Key, (DBT*)&Index, (DBT*)&Data, DBmode)!=0) {
			// if we hit the end, perhaps we succeeded?
			break;
		}

		LOG("Key.Data:");
		LOG("[]", Key.data, Key.size);
		LOG("Index.pData:");
		LOG("[]", Index.data, Index.size);
		LOG("Data.pData:");
		LOG("[]", Data.data, Data.size);

		DBmode=DB_NEXT;
		SAptr=&SqrlAssoc;

		if(strcmp(SAptr->AssocRecData.szAccount, pszAccount)!=0) {
			break;
		}

		// make sure the user's provided name is URL safe
		UrlEncode(szUrlEncodedName, SAptr->AssocRecData.szUserHandle);

		SQ_CHAR *pszInvite=(char *)pszNull;
		if(SAptr->AssocRecData.aSqrlPublicIdentity[0]=='.') {
			pszInvite=(SQ_CHAR *)&SAptr->AssocRecData.aSqrlPublicIdentity[1];
		}

		// get the total length of this formatted line item
		TotalLength+=sprintf(szLineItem, pszEnumerationFormat,
			SAptr->szSqrlUser,
			SAptr->AssocRecData.szAccount,
			szUrlEncodedName,
			SAptr->AssocRecData.szStatus,
			pszInvite);
//[
LOG("Association: %s", szLineItem);
//]
	} // back to while()
	
	if(TotalLength==0) {
		// we didn't have even ONE line to output
		pCursor->close(pCursor);
		END();
		return (SQ_CHAR *)GlobalAlloc(1);
	}
	
	pszBuffer=GlobalAlloc(TotalLength+1);
	
	// we did have at least one line to output... so let's do that now
	SetDBTs(pszAccount, &SqrlAssoc, &Key, &Index, &Data);
	DBmode=DB_SET;
	while(1) {
		// now let's get the first or next record... and check
		if(pCursor->pget(pCursor, (DBT*)&Key, (DBT*)&Index, (DBT*)&Data, DBmode)!=0) {
			break;
		}
		DBmode=DB_NEXT;
		SAptr=&SqrlAssoc;

		if(strcmp(SAptr->AssocRecData.szAccount, pszAccount)!=0) {
			pCursor->close(pCursor);
			END();
			return pszBuffer;
		}

		// make sure the user's provided name is URL safe
		UrlEncode(szUrlEncodedName, SAptr->AssocRecData.szUserHandle);

		// get length of the string we have built so far
		// hold it in ECX to sum for format insertion
		SQ_CHAR *pszInvite=(char *)pszNull;
	
		if(SAptr->AssocRecData.aSqrlPublicIdentity[0]=='.') {
			pszInvite=(SQ_CHAR *)&SAptr->AssocRecData.aSqrlPublicIdentity[1];
		}

		// add the formatted item to the end of the growing string
		sprintf(&pszBuffer[strlen(pszBuffer)], pszEnumerationFormat, 
			SAptr->szSqrlUser,
			SAptr->AssocRecData.szAccount,
			&szUrlEncodedName,
			SAptr->AssocRecData.szStatus,
			pszInvite);
	} // back to while()
	
	// close our enumeration cursor
	pCursor->close(pCursor);

	// return our global alloc containing the string
	END();
	return pszBuffer;
	}

/*
===============================================================================
	UPDATE BY ACCOUNT
-------------------------------------------------------------------------------
	This updates or deletes one or more SQRL-account associations. If a UserHandle
	is provided, only the association matching the UserHandle will be updated or
	deleted. If no UserHandle is provided, =EVERY= association with the matching
	account will be updated or deleted.
===============================================================================
*/
void UpdateByAccount(QUERY_PARAMS *pQueryParams, SQ_BOOL Remove) {
	BEG("UpdateByAccount()");
	DBC *pCursor;
	DBT Key;
	DBT Index;
	DBT Data;
	SQRL_ASSOCIATIONS SqrlAssoc;
	ASSOC_REC_DATA *pAssocRecData=&SqrlAssoc.AssocRecData;
	int DBmode;

	// create a cursor to enumerate over the SECONDARY database
	// get a pointer to our secondary Account database
	if(pAcctDB->cursor(pAcctDB, NULL, &pCursor, 0)!=0) {
		END();
		return;
	}

	memset(&Key, 0, sizeof(DBT));
	memset(&Index, 0, sizeof(DBT));
	memset(&Data, 0, sizeof(DBT));

	Key.data=pQueryParams->pszAccount;
	Key.size=strlen(Key.data);

	// point our get key data to the Sqrl Record pointer
	Index.data=&SqrlAssoc;
	Index.ulen=USER_ID_FIELD_SIZ;
	Index.flags=DB_DBT_USERMEM;

	// set the start of the record data
	Data.data=&SqrlAssoc.AssocRecData;
	Data.ulen=sizeof(ASSOC_REC_DATA);
	Data.flags=DB_DBT_USERMEM;

	DBmode=DB_SET;
	while(1) {
		// access the first or next record of the DB in SQRL ID sequence
		if(pCursor->pget(pCursor, (DBT*)&Key, (DBT*)&Index, (DBT*)&Data, DBmode)!=0) {
			// if we hit the end we're finished
			break;
		}
		DBmode=DB_NEXT;
		
		// make sure we found a record with a matching Account
		if(strcmp(pAssocRecData->szAccount, pQueryParams->pszAccount)!=0) {
			// if not, we're done
			break;
		}
		
		// we found a candidate. so if we were provided a UserHandle, we
		// check for a match. Otherwise we perform the requested operation.
		if(pQueryParams->pszUserHandle!=NULL) {
			// do the szUserHandles match?
			if(strcmp(pAssocRecData->szUserHandle, pQueryParams->pszUserHandle)!=0) {
				// if not a match, we'll keep looking
				continue;
			}
		}
		// we either have no UserHandle, or the UserHandle provided is a match.
		// so we perform the requested action on this record...
		if(Remove) {
			pCursor->del(pCursor, 0);
		}
		else {
			// and we conditionally update the UserHandle and the Status strings
			if(pQueryParams->pszUserHandle!=pszNull) {
				strcpy(pAssocRecData->szUserHandle, pQueryParams->pszUserHandle);
			}
			if(pQueryParams->pszStatus!=pszNull) {
				strcpy(pAssocRecData->szStatus, pQueryParams->pszStatus);
			}
			// now we put the updated data back right where we found it.
			pCursor->put(pCursor, (DBT*)&Index, (DBT*)&Data, DB_CURRENT);
		}
	} // back to while()

	// close our enumeration cursor
	pCursor->close(pCursor);
	// to protect from crashing write the updates now
	SyncAllBDB();
	END();
}

//.[ For development
char *GetBerkeleyMainDatabase() {
	DBC *pCursor;

	// start with a null-terminated empty string
	char *pszList=GlobalAlloc(1);
	
	char *pszFormat=
		"UserId(KEY): %s\r\n"
		"    Account: %s\r\n"
		" UserHandle: %s\r\n"
		"     Status: %s\r\n"
		"%s\r\n"
		"        SUK: %s\r\n"
		"        VUK: %s\r\n"
		"   Accessed: %s"
		"\r\n";
	char *pszInvite=" Invitation: ";
	char *pszSqrlId="SqrlId(IDK): %02x%02x%02x%02x%02x%02x%02x%02x...";
	char szSqrlIdInvite[64]; // the effective size of the above strings
	int TotalLen=1; // allow for null terminator
	
	// Don't check for errors, assume everything works
	pMainDB->cursor(pMainDB, NULL, &pCursor, 0);
	DBT key, data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	while ((pCursor->get(pCursor, (DBT*)&key, (DBT*)&data, DB_NEXT)) == 0) {
		ASSOC_REC_DATA*ptr=(ASSOC_REC_DATA*)(data.data);
		if(ptr->aSqrlPublicIdentity[0]=='.') {
			strcpy(szSqrlIdInvite, pszInvite); 
			memcpy(strchr(szSqrlIdInvite, '\0'), &ptr->aSqrlPublicIdentity[1], 20);
			szSqrlIdInvite[strlen(pszInvite)+20]='\0';
		}
		else {
			sprintf(szSqrlIdInvite, pszSqrlId, 
				ptr->aSqrlPublicIdentity[0],
				ptr->aSqrlPublicIdentity[1],
				ptr->aSqrlPublicIdentity[2],
				ptr->aSqrlPublicIdentity[3],
				ptr->aSqrlPublicIdentity[4],
				ptr->aSqrlPublicIdentity[5],
				ptr->aSqrlPublicIdentity[6],
				ptr->aSqrlPublicIdentity[7]);
		}
		char szSUK[16+3+1];
		sprintf(szSUK, "%02x%02x%02x%02x%02x%02x%02x%02x...",
			ptr->aSqrlServerUnlockKey[0],
			ptr->aSqrlServerUnlockKey[1],
			ptr->aSqrlServerUnlockKey[2],
			ptr->aSqrlServerUnlockKey[3],
			ptr->aSqrlServerUnlockKey[4],
			ptr->aSqrlServerUnlockKey[5],
			ptr->aSqrlServerUnlockKey[6],
			ptr->aSqrlServerUnlockKey[7]);

		char szVUK[16+3+1];
		sprintf(szVUK, "%02x%02x%02x%02x%02x%02x%02x%02x...",
			ptr->aSqrlVerifyUnlockKey[0],
			ptr->aSqrlVerifyUnlockKey[1],
			ptr->aSqrlVerifyUnlockKey[2],
			ptr->aSqrlVerifyUnlockKey[3],
			ptr->aSqrlVerifyUnlockKey[4],
			ptr->aSqrlVerifyUnlockKey[5],
			ptr->aSqrlVerifyUnlockKey[6],
			ptr->aSqrlVerifyUnlockKey[7]);
		
		SQ_QWORD Offset1601To1970=(SQ_DWORD)0x019db1ded53e8000;
		time_t LastActivity=(time_t)((ptr->SqrlLastActivityDate-Offset1601To1970)/10000000);

		TotalLen=TotalLen
			+strlen(pszFormat)-strlen("%s%s%s%s%s%s%s%s") // <- number of %s's in pszFormat
			+strlen(key.data)
			+strlen(ptr->szAccount)
			+strlen(ptr->szUserHandle)
			+strlen(ptr->szStatus)
			+strlen(szSqrlIdInvite)
			+strlen(szSUK)
			+strlen(szVUK)
			+strlen("DDD MMM dd hh:mm:ss yyyy\r\n");
		pszList=realloc(pszList, TotalLen);
		
		sprintf(strchr(pszList, '\0'), pszFormat, 
			key.data, 
			ptr->szAccount, 
			ptr->szUserHandle,
			ptr->szStatus,
			szSqrlIdInvite,
			szSUK,
			szVUK,
			ctime(&LastActivity));
	}
	return pszList;
}

char *GetSupersededIDs() {
	DBC *pCursor;
	
// start with a null-terminated empty string
	char *pszList=GlobalAlloc(1);
	
	char *pszFormat=
		" SuperIDK: %s\r\n";
	int TotalLen=1; // allow for null terminator
	
	// Don't check for errors, assume everything works
	pDeadDB->cursor(pDeadDB, NULL, &pCursor, 0);
	DBT key, data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	while ((pCursor->get(pCursor, (DBT*)&key, (DBT*)&data, DB_NEXT)) == 0) {
		SQ_BYTE *ptr=(SQ_BYTE *)(key.data);
		char szIUK[16+3+1];
		sprintf(szIUK, "%02x%02x%02x%02x%02x%02x%02x%02x...",
			ptr[0],
			ptr[1],
			ptr[2],
			ptr[3],
			ptr[4],
			ptr[5],
			ptr[6],
			ptr[7]);

		TotalLen=TotalLen
			+strlen(pszFormat)-strlen("%s") // <- number of %s's in pszFormat
			+strlen(szIUK);
		pszList=realloc(pszList, TotalLen);
		
		sprintf(strchr(pszList, '\0'), pszFormat, 
			szIUK);
	}
	return pszList;
}

//]
