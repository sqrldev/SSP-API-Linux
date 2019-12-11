
// base64url.c

#include "global.h"

// Encoding:

const char b64urlchars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Decoding: "-..0123456789.......ABCDEFGHIJKLMNOPQRSTUVWXYZ...._.abcdefghijklmnopqrstuvwxyz"

int b64urlbytes[]={62, -1, -1, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -1, -1, -1, 63, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};
    
int GetBase64urlEncodedSize(int len) {
	// we do not pad with '=' or '==' or null-terminate
	// #bytes: 1 2 3 4 5 6  7  8  9
	// #chars: 2 3 4 6 7 8 10 11 12
	return 4*(len-1)/3+2;
}

int GetBase64urlDecodedSize(int len) {
	// we do not pad with =' or '==' or null-terminate
	// #chars: 2 3 4 6 7 8 10 11 12
	// #bytes: 1 2 3 4 5 6  7  8  9
 	return ((len-1)/4)*3 + (len-1)%4;
}

int b64_isvalidchar(char c) {
	if(c<'-' || c>'z' || b64urlbytes[c-45]==-1) {
		// Invalid Base64url character
		return 0;
	}
	else {
		// Valid Base64url character
		return 1;
	}
}    

/*
Three 8-bit bytes encode into four 6-bit base 64 characters

3n+0 bytes require 4n+0 characters
3n+1 bytes require 4n+2 characters
3n+2 bytes require 4n+3 characters

Note that 4n+1 characters is not a valid encoding
*/

int Base64urlEncode(const unsigned char *in, int len, char *out, int siz) {
	// in = pointer to input byte array
	// len = length of input byte array
	// out = pointer to output character array
	// siz = size of the output array
	// the output array is not null-terminated
	// we do not pad the output array with '=' or '=='
	
    int i;
    int j;
	int n;
    
    if(in==NULL || len==0 || out==NULL || siz==0){
		// ERROR: invalid function parameter(s)
		return 0;
	}
 
	n=GetBase64urlEncodedSize(len);
    if(siz < n) {
    	// ERROR: client-provided array is too small
    	return 0;
    }
 
	int len3=(len/3)*3;  // length rounded down to a multiple of 3
	int a, b, c, d;
	
    for (i=0, j=0; i<len3; i+=3, j+=4) {
		a=in[i+0]>>2;
		b=in[i+0]<<4 | in[i+1]>>4;
		c=in[i+1]<<2 | in[i+2]>>6;
		d=in[i+2];
		out[j+0]=b64urlchars[a&0x3f];
		out[j+1]=b64urlchars[b&0x3f];
		out[j+2]=b64urlchars[c&0x3f];
		out[j+3]=b64urlchars[d&0x3f];
	}
	if(len%3==1) {
		a=in[i+0]>>2;
		b=in[i+0]<<4;
		out[j+0]=b64urlchars[a&0x3f];
		out[j+1]=b64urlchars[b&0x3f];
	}
	if(len%3==2) {
		a=in[i+0]>>2;
		b=in[i+0]<<4 | in[i+1]>>4;
		c=in[i+1]<<2;
		out[j+0]=b64urlchars[a&0x3f];
		out[j+1]=b64urlchars[b&0x3f];
		out[j+2]=b64urlchars[c&0x3f];
	}
//[
LOG("in:");
LOG("[]", in, len);
LOG("out:");
LOG("[c]", out, n);
//]
	return n;
}
SQ_DWORD SqrlCvrtToBase64(SQ_CHAR *pOut, SQ_DWORD SizOut, const SQ_BYTE *pIn, SQ_DWORD LenIn) {
	BEG("SqrlCvrtToBase64()");
	SQ_DWORD LenOut=Base64urlEncode(pIn, LenIn, pOut, SizOut);
	END();
	return LenOut;
}

int Base64urlDecode(const char *in, int len, unsigned char *out, int siz) {
	// in = pointer to input char array
	// len = length of input char array
	// out = pointer to output byte array
	// siz = size of the output array
	// the input array is not null-terminated
	// we do not pad the input array with '=' or '=='
    int i, j;
	
    if(in==NULL || len==0) return 0;
    if(out==NULL || siz==0) return 0;
 
	if(len%4==1) return 0;
    for (i=0; i<len; i++) if (b64_isvalidchar(in[i])==0) return 0;
	
	int n=GetBase64urlDecodedSize(len);
    if (siz < n) return 0;
 
	int len4=(len/4)*4; // length rounded down to a multiple of 4
	int a, b, c, d;
	
	for(i=0, j=0; i<len4; i+=4, j+=3) {
		// get the four 6-bit values
		a=b64urlbytes[in[i+0]-45];
		b=b64urlbytes[in[i+1]-45];
		c=b64urlbytes[in[i+2]-45];
		d=b64urlbytes[in[i+3]-45];
		
		// decode them into three 8-bit bytes
		out[j+0]=a<<2 | b>>4;
		out[j+1]=b<<4 | c>>2;
		out[j+2]=c<<6 | d;
	}
	// Decode any partial block
	if(len%4>1) {
		a=b64urlbytes[in[i+0]-45];
		b=b64urlbytes[in[i+1]-45];
		out[j+0]=a<<2 | b>>4;
	}
	if(len%4>2) {
		c=b64urlbytes[in[i+2]-45];
		out[j+1]=b<<4 | c>>2;
	}
    return n;
}
SQ_DWORD SqrlCvrtFromBase64(SQ_BYTE *pOut, SQ_DWORD SizeOut, const SQ_CHAR *pIn, SQ_DWORD LengthIn) {
	BEG("SqrlCvrtFromBase64()");
	SQ_DWORD LenOut=Base64urlDecode(pIn, LengthIn, pOut, SizeOut);
	END();
	return LenOut;
}

SQ_DWORD CvrtToBase64String(SQ_CHAR *pOut, SQ_DWORD SizOut, const SQ_BYTE *pIn, SQ_DWORD LenIn) {
	BEG("CvrtToBase64String()");
	SQ_DWORD LenOut=Base64urlEncode(pIn, LenIn, pOut, SizOut);
	pOut[LenOut]='\0';
	END();
	return LenOut;
}
/*
============================================================================
	DECODE BASE64SZ AND STORE			     
 -------------------------------------------------------------------------- 
	Given a null-terminated Base64 string, this decodes it and places	     
	the resulting data into a Global Alloc, stored in the provided ptr.    
----------------------------------------------------------------------------
*/
void DecodeBase64szAndStore(SQ_BYTE **ppszDecoded, const SQ_CHAR *pBase64sz) {
	BEG("DecodeBase64szAndStore()");

	int len=strlen(pBase64sz);
	int siz=GetBase64urlDecodedSize(len);
	*ppszDecoded=(SQ_BYTE *)GlobalAlloc(siz+1);
	
	// Note: GlobalAlloc initializes with zeros 
	// so szDecoded will be null-terminated automatically 

	SqrlCvrtFromBase64(*ppszDecoded, siz, pBase64sz, len);
	
	END();
}
