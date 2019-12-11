
// criticalsection.c

#include "global.h"

CRITICAL_SECTION DebugCriticalSection;
CRITICAL_SECTION IncDataCriticalSection;

int InitializeCriticalSection(CRITICAL_SECTION *pLock) {
	BEG("InitializeCriticalSection()");
	LOG("pLock: %p", pLock);

	pLock->count=0;
	int rc=pthread_mutex_init(&pLock->Lock, NULL);
	if(rc!=0) {
		// ERROR: Cannot create mutex
		perror("Cannot create mutex\r\n");
	}
	END();
	return rc;
}

int DeleteCriticalSection(CRITICAL_SECTION *pLock){
	BEG("DeleteCriticalSection()");
	LOG("pLock: %p", pLock);

	pLock->count=0;
	int rc=pthread_mutex_destroy(&pLock->Lock);
	if(rc!=0) {
		perror("Cannot destroy mutex\r\n");
	}
	END();
	return rc;
}

SQ_BOOL EnterCriticalSection(CRITICAL_SECTION *pLock) {
	BEG("EnterCriticalSection()");
	LOG("pLock: %p", pLock);
	LOG("Count: %d", pLock->count);
	
	pLock->count++;
	if(pLock->count > 1) {
		END();
		return SQ_FALSE;
	}
	
	if(StackNdx>1) {
		// Log the locking function 
		LOG("%s (Ndx %d)", pStack[StackNdx-2], StackNdx);
	}

    /* Enter the critical section -- other threads are locked out */
	int rc=0;
	rc=pthread_mutex_lock(&pLock->Lock);
	if(rc!=0) {
		perror("Cannot lock mutex\r\n");
	}
	
	END();
	return SQ_TRUE;
}

SQ_BOOL LeaveCriticalSection(CRITICAL_SECTION *pLock) {
	BEG("LeaveCriticalSection()");
	LOG("pLock: %p", pLock);
	LOG("Count: %d", pLock->count);

	pLock->count--;
	if(pLock->count > 0) {
		END();
		return SQ_FALSE;
	}
	
	if(StackNdx>1) {
		// Log the unlocking function 
		LOG("%s (Ndx %d)", pStack[StackNdx-2], StackNdx);
	}

    /* Leave the critical section -- other threads can now pthread_mutex_lock()  */
    int rc=pthread_mutex_unlock(&pLock->Lock);
	if(rc!=0) {
		perror("Cannot unlock mutex\r\n");
	}

	END();
	return SQ_TRUE;
}