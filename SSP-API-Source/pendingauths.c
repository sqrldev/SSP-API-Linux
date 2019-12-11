
// pendingauths.c

#include "global.h"

QUEUE PendingAuthsQueue;

/*
===============================================================================
	DELETE PENDING AUTH ALLOCS
	This is called when we're shutting down as a callback of "DeleteQueue".
===============================================================================
*/
void DeletePendingAuthAllocs(void *pObject) {
	BEG("DeletePendingAuthAllocs)");
	PENDING_AUTHS *pPendingAuth=(PENDING_AUTHS *)pObject;
	
	// Note: GlobalFree() tests for a null pointer
	
	// if we have a next page URL, we release it
	GlobalFree((void **)&pPendingAuth->pszNextPageURL);

	// if we have a login page URL, we release it
	GlobalFree((void **)&pPendingAuth->pszLoginPageURL);

	END();
}

/*
===============================================================================
	DELETE PENDING AUTH OBJECT
	This removes a pending authentication object from the pending auths queue. It
	optionally deletes any per-object allocations, then deletes the object itself.
===============================================================================
*/
void DeletePendingAuthObject(void *pObject) {
	BEG("DeletePendingAuthOject()");
	QUEUE_OBJECT *pQueueObject=(QUEUE_OBJECT *)pObject;
	PENDING_AUTHS *pPendingAuth=(PENDING_AUTHS *)pObject;
	
	DequeueObject(&PendingAuthsQueue, pQueueObject);

	// if we have a next page URL
	GlobalFree((void **)&pPendingAuth->pszNextPageURL);
	
	// if we have a login page URL
	GlobalFree((void **)&pPendingAuth->pszLoginPageURL);
	
	// and release the object itself
	GlobalFree((void **)&pPendingAuth);
	END();
}
	
/*
===============================================================================
	LOOKUP BY NUT
	This searches for the pending auth object by client query provided NUT.
	If, during the search, any expired pending objects are found, they are
	immediately deleted. If the target object is found its timestamp is updated.
	Then the object is either read or written depending upon the UpdateObject
	boolean. And a pointer to the object is also returned...
===============================================================================
*/
PENDING_AUTHS *LookupByNut(PENDING_AUTHS *pPendingAuth, SQ_CHAR *pNut, SQ_BOOL bUpdateObject, SQ_BOOL bProtocolNut, SQRL_CONTROL_BLOCK *pSCB){
	BEG("LookupByNut()");
//[
if(bProtocolNut) LOG("Looking for ProtocolNut:"); else LOG("Looking for Browser Nut:");
LOG("[]", pNut, SQRL_NUT_LEN);
//]
	SQ_CHAR aIpAddress[16];
	SQ_DWORD LowResTime=GetSystemOneSecondTime();
	
	if(pSCB!=NULL) {
		ObtainClientConnectionIP(aIpAddress, pSCB);
	}
	
	EnterCriticalSection(&PendingAuthsQueue.CriticalSection);

	void *pObject=NULL;
	void *pNextObject=PendingAuthsQueue.pFirstInQueue;

	while((pObject=pNextObject)!=NULL) {
		pNextObject=((QUEUE_OBJECT *)pObject)->pNextObject;
//[
//? what happens when the timer wraps around?
//]
		if(LowResTime-((QUEUE_OBJECT *)pObject)->TimeStamp > PENDING_AUTH_EXP) {
			DeletePendingAuthObject(pObject);
			continue; // (the while loop)
		}

		// choose which of our nuts we're looking up here...
		SQ_CHAR *pObjectNut;
		if(bProtocolNut==SQ_TRUE) {
			pObjectNut=((PENDING_AUTHS *)pObject)->aProtocolNut;
//[
LOG("pObject->ProtocolNut:");
LOG("[]", pObjectNut, SQRL_NUT_LEN);
//]
		}
		else {
			pObjectNut=((PENDING_AUTHS *)pObject)->aBrowserNut;
//[
LOG("pObject->BrowserNut:");
LOG("[]", pObjectNut, SQRL_NUT_LEN);
//]
		}
		
		// If the nuts don't match check the next queue entry
		if(strncmp(pNut, pObjectNut, SQRL_NUT_LEN)!=0){
			continue; //(the while loop)
		}

//[
LOG("We have found a matching Nut");
//]
		// we have found a matching NUT (#1 or #2) so now we
		// verify the caller's IP address if we have a pSCB
		if(pSCB!=NULL){
			// we FOUND the NUT we're searching for. Was the query
			// from the same IP as the original /nut/sqrl query?
//[
LOG("IpAddress:");
LOG("[]", aIpAddress, IPV6_BYTE_LEN);
LOG("RequestIP:");
LOG("[]", ((PENDING_AUTHS *)pObject)->aRequestIP, IPV6_BYTE_LEN);
//]
			if(strncmp(aIpAddress, ((PENDING_AUTHS *)pObject)->aRequestIP, IPV6_BYTE_LEN)!=0){
				// we had an IP mismatch with queries from the same
				// browser session, which should NEVER happen...
				DeletePendingAuthObject(pObject);

				// the object is gone, return NULL
				pObject=NULL;
				break; //(out of while)
			}
		}
//[
//? compare with Lookup by CPS, it doesn't test if pPendingAuth is NULL
//]
		if(pPendingAuth!=NULL) {
			if(bUpdateObject==SQ_TRUE) {
				// copy the object provided by our caller
				memcpy(pObject, pPendingAuth, sizeof(PENDING_AUTHS));
//[
LOG("Writing object");
//]
			}
			else{
				// or return a copy of this Pending Auth to our caller
				memcpy(pPendingAuth, pObject, sizeof(PENDING_AUTHS));
//[
LOG("Reading object");
//]
			}
		}
		break; // (out of while)
	} // (back to while)

	LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);
//[
if(pObject==NULL) LOG("We did not find a matching Nut");
if(pObject!=NULL) LOG("We did     find a matching Nut");
//]
	END();
	return pObject;
}

/*
===============================================================================
	LOOKUP BY CPS
	This searches for the pending auth object by Client Provided Session nonce.
	If, during the search, any expired pending objects are found, they are
	immediately deleted. If the target object is found its timestamp is updated.
	Then the object is either read or written depending upon the UpdateObject
	boolean. And a pointer to the object is also returned...
===============================================================================
*/
PENDING_AUTHS *LookupByCPS(PENDING_AUTHS *pPendingAuth, SQ_VOID *pCPSnonce, SQ_BOOL bUpdateObject) {
	BEG("LookupByCPS()");
	// we search for these 24 chars
	LOG("pCPSnonce=%s", (char *)pCPSnonce);

	SQ_DWORD LowResTime=GetSystemOneSecondTime();

LOG("owner: %u", PendingAuthsQueue.CriticalSection.Lock.__data.__owner);
LOG("&Lock: %p", &PendingAuthsQueue.CriticalSection.Lock);
	
	EnterCriticalSection(&PendingAuthsQueue.CriticalSection);

	void *pObject=NULL;
	void *pNextObject=PendingAuthsQueue.pFirstInQueue;

	while((pObject=pNextObject)!=NULL) {
		pNextObject=((QUEUE_OBJECT *)pObject)->pNextObject;
//[
//? what happens when the timer wraps around?
//]
		if(LowResTime-((QUEUE_OBJECT *)pObject)->TimeStamp > PENDING_AUTH_EXP){
			DeletePendingAuthObject(pObject);
			continue; // (the while loop)
		}

		SQ_CHAR *pObjectCPSnonce;
		pObjectCPSnonce=((PENDING_AUTHS *)pObject)->aCPSNonce;
		if(strncmp(pCPSnonce, pObjectCPSnonce, CPS_TOKEN_LEN)!=0){
			continue; //(the while loop)
		}
//[
//? compare with LookupByNut, it tests if pPendingAuth is NULL
//]			
		// we FOUND the NUT we're searching for, so we either...
		if(bUpdateObject==SQ_TRUE) {
			// copy the object provided by our caller
			memcpy(pObject, pPendingAuth, sizeof(PENDING_AUTHS));
		}
		else {
			// or return a copy of this Pending Auth to our caller
			memcpy(pPendingAuth, pObject, sizeof(PENDING_AUTHS));
		}
		break; // (out of while)
	} // (back to while)

	LeaveCriticalSection(&PendingAuthsQueue.CriticalSection);

	END();
	return pObject;
}

/*
===============================================================================
	SET INITIAL AUTH MACS
===============================================================================
*/
void SetInitialAuthMacs(PENDING_AUTHS *pPendingAuth, SQRL_CONTROL_BLOCK *pSCB){
	BEG("SetInitialAuthMacs()");
	SQ_CHAR szNutText[16];
	SQ_CHAR szSqrlURL[512];
	SQ_CHAR szStringToMAC[512];
	SQ_CHAR szEncodedReferrer[2048];

	GetUrlEncodedReferrer(szEncodedReferrer, sizeof(szEncodedReferrer), pSCB);

	// get our associated nut string and null-terminate it
	memcpy(szNutText, pPendingAuth->aBrowserNut, SQRL_NUT_LEN);
	szNutText[SQRL_NUT_LEN]='\0';

	int len;

	// obtain and store the HMAC for the string: sqrl://{hostname}/sqrl?nut={-nut-}
	len=sprintf(szSqrlURL, pszQRcodeFormat, pSCB->lpszHttpHost, pPendingAuth->szPathExtension, szNutText);

LOG("Calculation of HMAC1 in SetInitialAuthMacs():");
LOG("SqrlURL without can=:");

	len=SqrlCvrtToBase64(szStringToMAC, sizeof(szStringToMAC), (SQ_BYTE *)szSqrlURL, len);
	HMAC256(pPendingAuth->aTransactionMAC1, (SQ_BYTE *)szStringToMAC, len, aSystemKey);

	// and the HMAC for the string: sqrl://{hostname}/sqrl?nut={-nut-}&can={-referer-}
	len=sprintf(szSqrlURL, pszSQlinkFormat, pSCB->lpszHttpHost, pPendingAuth->szPathExtension, szNutText, szEncodedReferrer);

LOG("Calculation of HMAC2 in SetInitialAuthMacs():");
LOG("SqrlURL with can=:");

	len=SqrlCvrtToBase64(szStringToMAC, sizeof(szStringToMAC), (SQ_BYTE *)szSqrlURL, len);
	HMAC256(pPendingAuth->aTransactionMAC2, (SQ_BYTE *)szStringToMAC, len, aSystemKey);

	END();
}

/*
============================================================================
	CREATE QUEUE				     
 -------------------------------------------------------------------------- 
	Creates an empty queue object by initializing a QUEUE structure.
	in:  pQueue pointer to an existing QUEUE structure
	out: pQueue initialized to zeros
----------------------------------------------------------------------------
*/
SQ_RCODE CreateQueue(QUEUE *pQueue) {
	BEG("CreateQueue()");

	memset(pQueue, 0, sizeof(QUEUE));
	InitializeCriticalSection(&pQueue->CriticalSection);

	END();
	return SQ_PASS;
}

/*
============================================================================
	DELETE QUEUE				     
 -------------------------------------------------------------------------- 
	Deletes ALL queued objects, their allocs, and the queue's critical section.
	in:  pQueue
	in:  pDestructor - call back to delete object 
	out: pQueue
----------------------------------------------------------------------------
*/

SQ_RCODE DeleteQueue(QUEUE *pQueue, SQ_PROCPTR pDestructor) {
	BEG("DeleteQueue()");
	QUEUE_OBJECT *pQueueObject;
	
	while((pQueueObject=Dequeue(pQueue))!=NULL) {
		pDestructor(pQueueObject);
		GlobalFree((void **)&pQueueObject);
		}
	DeleteCriticalSection(&pQueue->CriticalSection);

	END();
	return SQ_PASS;
}

/*
============================================================================
	ENQUEUE				     
 -------------------------------------------------------------------------- 
	Adds the QueueObject to the end of the QueuePointer queue.
	in:  pQueue
	in:  pNewObject
	out: pQueue
----------------------------------------------------------------------------
*/
SQ_RCODE Enqueue(QUEUE *pQueue, QUEUE_OBJECT *pNewObject) {
	BEG("EnQueue()");

	EnterCriticalSection(&pQueue->CriticalSection);
	
	// Add the new object to the end of the queue
	pNewObject->pPriorObject=pQueue->pLastInQueue;
	pNewObject->pNextObject=0;

	if(pQueue->pLastInQueue!=0){
		// The queue is not empty, hook old last object to new one
		pQueue->pLastInQueue->pNextObject=pNewObject;
	}
	else {
		// The queue is empty, set this object as the first also
		pQueue->pFirstInQueue=pNewObject;
	}
	
	// Set this object as the last
	pQueue->pLastInQueue=pNewObject;

	// Increment the number of objects in the Queue
	pQueue->ObjectCount++;

	LeaveCriticalSection(&pQueue->CriticalSection);

	END();
	return SQ_PASS;
}

/*
============================================================================
	DEQUEUE				     
 -------------------------------------------------------------------------- 
	Takes (and removes) the next (first) object from the queue.		     
	Returns the pointer to the object, or NULL if the queue is empty.
	in : pQueue
	out: pQueue
	ret: first object or NULL
----------------------------------------------------------------------------
*/
QUEUE_OBJECT *Dequeue(QUEUE *pQueue) {
	BEG("DeQueue()");

	EnterCriticalSection(&pQueue->CriticalSection);

	// Get the current first queue object
	QUEUE_OBJECT *pFirstInQueue=pQueue->pFirstInQueue;
	
	// Only proceed if the queue is not empty
	if(pFirstInQueue!=NULL){
		// Make the next object the first
		QUEUE_OBJECT *pQueueObject=pFirstInQueue->pNextObject;
		pQueue->pFirstInQueue=pQueueObject;

		if(pQueueObject!=NULL){
			// The new first object is not NULL, set it's prior object to NULL
			pQueueObject->pPriorObject=NULL;
		}
		else {
			// The first object is NULL, so the queue is empty
			pQueue->pLastInQueue=pQueueObject;
		}
		pQueue->ObjectCount--;
	}
	LeaveCriticalSection(&pQueue->CriticalSection);

	// Return the first object, or NULL if the queue is empty
	END();
	return pFirstInQueue;
}

/*
============================================================================
	DEQUEUE OBJECT				     
 -------------------------------------------------------------------------- 
	Dequeues the specified object (not necessarily the first object) from     
	the queue.
	in : pQueue
	in : pQueueObject
	out: pQueue
----------------------------------------------------------------------------
*/
SQ_RCODE DequeueObject(QUEUE *pQueue, QUEUE_OBJECT *pQueueObject) {
	BEG("DeQueueObject()");
LOG("owner: %u", pQueue->CriticalSection.Lock.__data.__owner);
LOG("&Lock: %p", &pQueue->CriticalSection.Lock);

	EnterCriticalSection(&pQueue->CriticalSection);
	
	// Unhook the object from it's previous object or first in queue
	if(pQueueObject->pPriorObject!=NULL) {
		// If there is a prior object hook it to the next object
		pQueueObject->pPriorObject->pNextObject=pQueueObject->pNextObject;
	}
	else {
		// Other wise make the next object the first
		pQueue->pFirstInQueue=pQueueObject->pNextObject;
	}
	
	// Unhook the object from it's next object or last in queue
	if(pQueueObject->pNextObject!=NULL) {
		pQueueObject->pNextObject->pPriorObject=pQueueObject->pPriorObject;
	}
	else {
		pQueue->pLastInQueue=pQueueObject->pPriorObject;
	}
	
	// Decrement the object count
	pQueue->ObjectCount--;

	LeaveCriticalSection(&pQueue->CriticalSection);

	END();
	return SQ_PASS;
}

//[ For testing with /pnd.sqrl
char *GetPendingAuths() {
	// start with a null-terminated empty string
	char *pszList=GlobalAlloc(1);

	char *pszFormat=
		"    Browser Nut: %s\r\n"
		"   Protocol Nut: %s\r\n"
		"Sqrl Public Key: %s\r\n"
		"     Invitation: %s\r\n"
		"      CPS Nonce: %s\r\n"
		"\r\n";

	int TotalLen=1; // allow for null terminator

	PENDING_AUTHS *pPendingAuth=NULL;
	void *pNextObject=PendingAuthsQueue.pFirstInQueue;

	// Don't check for errors, assume everything works
	while(pNextObject!=NULL) {
		pPendingAuth=(PENDING_AUTHS *)pNextObject;
		pNextObject=((QUEUE_OBJECT *)pPendingAuth)->pNextObject;
		
		char szBrowserNut[SQRL_NUT_LEN+1];
		memcpy(szBrowserNut, pPendingAuth->aBrowserNut, SQRL_NUT_LEN);
		szBrowserNut[SQRL_NUT_LEN]='\0';

		char szProtocolNut[SQRL_NUT_LEN+1];
		memcpy(szProtocolNut, pPendingAuth->aProtocolNut, SQRL_NUT_LEN);
		szProtocolNut[SQRL_NUT_LEN]='\0';
		
		char szCPSNonce[CPS_TOKEN_LEN+1];
		memcpy(szCPSNonce, pPendingAuth->aCPSNonce, CPS_TOKEN_LEN);
		szCPSNonce[CPS_TOKEN_LEN]='\0';
//[
LOG(szBrowserNut);
LOG(szProtocolNut);
LOG(pPendingAuth->szSqrlPublicKey);
LOG(pPendingAuth->szInvitation);
LOG(szCPSNonce);
//]
		TotalLen=TotalLen
			+strlen(pszFormat)-strlen("%s%s%s%s%s")
			+strlen(szBrowserNut)
			+strlen(szProtocolNut)
			+strlen(pPendingAuth->szSqrlPublicKey)
			+strlen(pPendingAuth->szInvitation)
			+strlen(szCPSNonce)
			+strlen("\r\n");

		pszList=realloc(pszList, TotalLen);
		
		sprintf(strchr(pszList, '\0'), pszFormat, 
			szBrowserNut,
			szProtocolNut,
			pPendingAuth->szSqrlPublicKey,
			pPendingAuth->szInvitation,
			szCPSNonce);
	}
	return pszList;
}
//]

