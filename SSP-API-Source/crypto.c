
// crypto.c

#include "global.h"
#include "sodium.h"

/*				
============================================================================
	HMAC256				     
 -------------------------------------------------------------------------- 
	BYTES_FOR_256_BITS (16 byte long key)	
	in:  pSourceToHMAC
	in:  Len
	in:  pHashKey
	out: pHastOut
----------------------------------------------------------------------------
*/
SQ_RCODE HMAC256(SQ_BYTE *pHashOut, SQ_BYTE *pSourceToHMAC, SQ_DWORD Len, const SQ_BYTE *pHashKey) {
	BEG("HMAC256()");
	LOG("in:");
	LOG("[]", pSourceToHMAC, Len);

	SQ_QWORD SourceLen;
	SourceLen=(SQ_QWORD)Len;
	
	int rc=crypto_auth_hmacsha256(pHashOut, pSourceToHMAC, SourceLen, pHashKey);
	
	LOG("out");
	LOG("[]", pHashOut, SHA256_BYTE_LEN);
	END();
	return (rc==0? SQ_PASS: SQ_FAIL);
}

/*
============================================================================
	SQRL VERIFY SIG				     
 -------------------------------------------------------------------------- 
  What: Given a message that was previously signed, the signature that was  
        previously obtained, and the public key matching the private key    
        that was originally used, this returns 0 for successful signature   
        verification or -1 in the event of anything amiss.		     
 									     
   How: The Sodium library wants to see a composite "sig | message" buffer, 
        but SQRL uses separate signatures.  So we need to rebuild a hybrid  
        buffer to pass to Sodium. Sodium also wants to return a result	     
        msg buffer which we don't want. But it also uses it as a working    
        scratch buffer. So we need to supply it a scratch buffer too.	     
 									     
  Args: (in) ptr to (unsigned) message to check			     
        (in) len of message to check					     
        (in) ptr to 64-byte signature					     
        (in) ptr to 32-byte public key					     
 									     
  Retr: 0 == Success							     
        0 != Failure / HeapAlloc or Signature Verify failure		     
----------------------------------------------------------------------------
*/
SQ_RCODE SqrlVerifySig(SQ_BYTE *pMsg, SQ_DWORD uMsgLen, SQ_BYTE *pSig, SQ_BYTE *pPubKey) {
	BEG("SqrlVerifySig");
	SQ_QWORD smlen;
	SQ_QWORD mlen;
	
	// the signed message length is 64 bytes longer than the caller's
	// provided message length. So we adjust the length up by 64 bytes...

	smlen=mlen=(SQ_QWORD)(uMsgLen+crypto_sign_BYTES);
	
	// create a temporary source buffer into which we will assemble
	// a composite signed message of the sort Sodium wants to see

	SQ_BYTE *pSrcBuf;
	pSrcBuf=(SQ_BYTE *)GlobalAlloc(smlen);
	
	// annoyingly, Sodium uses the "return" buffer (which we neither
	// need nor want) as scratch space while working. So we need to
	// give it a same-size working buffer to mess around with

	SQ_BYTE *pRetBuf;
	pRetBuf=(SQ_BYTE *)GlobalAlloc(mlen);

	// copy the signature into the first 64 bytes of the source buffer
	memcpy(pSrcBuf, pSig, crypto_sign_BYTES);

	// copy the caller's message to be sig-checked into the buffer balance
	memcpy(pSrcBuf+crypto_sign_BYTES, pMsg, uMsgLen);

	// we're now setup to invoke Sodium's signature verification
	// function it writes into and mucks around with the 'edi'
	// scratch buffer and the mlen length

	assert(sizeof(SQ_QWORD)==sizeof(long long unsigned int));
	long long unsigned int *pmlen=(long long unsigned int *)&mlen;
	int rc=crypto_sign_open(pRetBuf, pmlen, pSrcBuf, smlen, pPubKey);

	// one way or another we're all done now, so we free up our allocs
	GlobalFree((void **)&pSrcBuf);
	GlobalFree((void **)&pRetBuf);

//[
if(rc==SQ_PASS) LOG("Verification Passed"); else LOG("Verification Failed");
//]

	END();
	return (rc==0? SQ_PASS: SQ_FAIL);
}
