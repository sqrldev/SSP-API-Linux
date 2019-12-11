
// dbglog.c

#include "dbglog.h"

SQ_BOOL bCounterReset=SQ_FALSE;

// Detailed Log For Debugging (not thread-safe)
enum {
	NumItems=128,
	ItemLen=32
};

static char aDebugFilter[NumItems][ItemLen];
static char *pDebugFilter=NULL;

SQ_RCODE ReadDebugFilter() {
	// Initialize
	memset(aDebugFilter, 0, NumItems*ItemLen);
	pDebugFilter=&aDebugFilter[0][0];

	FILE *pFile;
	if((pFile=fopen("DebugFilter.txt", "rb"))==NULL) {
		LOG("Unable to open %s", "DebugFilter.txt");
		return SQ_FAIL;
	}
	int i=0;
	while (fgets(aDebugFilter[i], ItemLen, pFile)!=NULL) {
		char *ptr=strpbrk(aDebugFilter[i], "\r\n");
		if(ptr!=NULL) *ptr='\0';
		i++;
	}
	fclose(pFile);
	return SQ_PASS;
}

SQ_RCODE CheckDebugFilter(char *pFunctionName) {
	// Check if we have read in the file
	if(pDebugFilter==NULL) {
		ReadDebugFilter();
	}
	int i;
	for(i=0; i<NumItems; i++) {
		if(strlen(aDebugFilter[i])==0) break;
		if(strcmp(aDebugFilter[i], pFunctionName)==0) return SQ_PASS;
	}
	return SQ_FAIL;
}

FILE *pLogFile=NULL;
int StackNdx=0;
char *pStack[32];
int aStack[32];

//#define CONSOLE
#define LOGFILE

char szLogTime[]="???????????????";
char *LogTime() {
	time_t curtime;
	time(&curtime);
	// WWW MMM DD HH:MM:SS YYYY
	char *pctime=ctime(&curtime);
	// MMM DD HH:MM:SS
	if(memcmp(pctime+4, szLogTime, 15)==0) {
		return NULL;
	} else {
		memcpy(szLogTime, pctime+4, 15);
		return szLogTime;
	}
}

void Lprintf(const char *pFormat, ...){
	char *pLogTime=NULL;
	if(strncmp(pFormat, "[BEG]", 5)==0 ||
		strncmp(pFormat, "[END]", 5)==0 ||
		strncmp(pFormat, "[LOG]", 5)==0) {
		pLogTime=LogTime();
	}
	
	va_list args;
	va_start(args, pFormat);
#ifdef CONSOLE
	if(pLogTime!=NULL) {
		printf("\r\n%s\r\n\r\n", pLogTime);
		for(int i=0; i<StackNdx; i++) printf("  ");
	}
	vprintf(pFormat, args);
#endif
#ifdef LOGFILE	
	if(pLogFile==NULL) {
		pLogFile=fopen("LogFile.txt", "wb");
	}
	if(pLogFile!=NULL) {
		if(pLogTime!=NULL) {
			fprintf(pLogFile, "\r\n%s\r\n\r\n", pLogTime);
			for(int i=0; i<StackNdx; i++) fprintf(pLogFile, "  ");
		}
		vfprintf(pLogFile, pFormat, args);
		fflush(pLogFile);
	}
#endif	
	va_end(args);
}

void Beg(char *pFunctionName, char *pFile, int Line) {
	pStack[StackNdx]=pFunctionName;
	if(CheckDebugFilter(pFunctionName)==SQ_PASS) {
		aStack[StackNdx]=1;
	}
	SQ_BOOL bFilter=SQ_FALSE;
	for(int i=0; i<=StackNdx; i++) if(aStack[i]==1) bFilter=SQ_TRUE;
	if(bFilter==SQ_FALSE) {
		for(int i=0; i<StackNdx; i++) Lprintf("  ");
		Lprintf("[BEG] %s %s %d\r\n", pFunctionName, pFile, Line);
	}
	StackNdx++;
}

void End(char *pFile, int Line) {
	StackNdx--;
	SQ_BOOL bFilter=SQ_FALSE;
	for(int i=0; i<=StackNdx; i++) if(aStack[i]==1) bFilter=SQ_TRUE;
	if(bFilter==SQ_FALSE) {
		for(int i=0; i<StackNdx; i++) Lprintf("  ");
		Lprintf("[END] %s %s %d\r\n", pStack[StackNdx], pFile, Line);
	}
	aStack[StackNdx]=0;
}

void Log(const char *pFormat, ...){
	// (StackNdx is 1 more than its value in BEG or END)
	for(int ndx=1; ndx<StackNdx; ndx++) if(aStack[ndx]==1) return;
	for(int i=0; i<StackNdx; i++) Lprintf("  ");
	Lprintf("[LOG] ");
	va_list args;
	va_start(args, pFormat);
	
	if(strcmp(pFormat, "[]")==0) {
		// Print characters or bytes depending on content
		SQ_BYTE *a=va_arg(args, SQ_BYTE *);
		int n=va_arg(args, int);
		char f='c';
		for(int i=0; i<n; i++) {
			SQ_BYTE z=a[i];
			if(z=='\r' || z=='\n') continue;
			if(z<0x20 || z>0x7f) {
				f='x';
				break;
			}			
		}
		if(f=='c') {
			// log an ASCII character array
			Lprintf("\"");
			for(int i=0; i<n; i++) {
				Lprintf("%c", a[i]);
				if(a[i]=='\n')	for(int j=0; j<StackNdx+3; j++) Lprintf("  ");
			}	
			Lprintf("\"");
		}
		else if(f=='x') {
			// log a byte array in hex
			for(int i=0; i<n; i++) {
				Lprintf("%02x ", a[i]);
			}
		}
	}
	else if(strcmp(pFormat,"[c]")==0) {
		// log an ASCII character array
		SQ_BYTE *a=va_arg(args, SQ_BYTE *);
		int n=va_arg(args, int);
		Lprintf("\"");
		for(int i=0; i<n; i++) {
			Lprintf("%c", a[i]);
			if(a[i]=='\n')	for(int j=0; j<StackNdx+3; j++) Lprintf("  ");
		}
		Lprintf("\"");
	}
	else if(strcmp(pFormat,"[d]")==0) {
		// log a byte array in dec
		SQ_BYTE *a=va_arg(args, SQ_BYTE *);
		int n=va_arg(args, int);
		for(int i=0; i<n; i++) {
			Lprintf("%d ", a[i]);
		}
	}
	else if(strcmp(pFormat,"[x]")==0) {
		// log a byte array in hex
		SQ_BYTE *a=va_arg(args, SQ_BYTE *);
		int n=va_arg(args, int);
		for(int i=0; i<n; i++) {
			Lprintf("%02x ", a[i]);
		}
	}
	else {
#ifdef CONSOLE
		vprintf(pFormat, args);
#endif
#ifdef LOGFILE	
	if(pLogFile==NULL) {
		pLogFile=fopen("LogFile.txt", "wb");
	}
	if(pLogFile!=NULL) {
		vfprintf(pLogFile, pFormat, args);
		fflush(pLogFile);
	}
#endif	
	}
	va_end(args);
	Lprintf("\r\n");
}
