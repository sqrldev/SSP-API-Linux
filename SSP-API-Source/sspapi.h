
// sspapi.h "public" library functions

#ifndef SSPAPI_H
#define SSPAPI_H

#include "sqtypes.h"

SQ_CHAR *SSP_Ping();
//[ For Testing
SQ_RCODE SSP_ResetCounter();
//]
SQ_RCODE SSP_InitSqrlCfgData();
SQ_RCODE SSP_InitSqrlSystem();
SQ_RCODE SSP_InitSqrlHandler();
SQ_RCODE SSP_ShutDownSqrlSystem();

void SSP_InitResponse(SQRL_RESPONSE *pResponse);
void SSP_SendRequest(SQRL_CONTROL_BLOCK *pSCB);
void SSP_FreeResponse(SQRL_RESPONSE *pResponse);

#endif
