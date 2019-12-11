#include "sspphp.h"
#include "../SSP-API-Source/sspapi.h"

#include <dlfcn.h>

static void *sspapi_handle;
static SQ_CHAR *(*phpPing)();
static SQ_RCODE (*phpResetCounter)();
static SQ_RCODE (*phpInitSqrlCfgData)();
static SQ_RCODE (*phpInitSqrlSystem)();
static SQ_RCODE (*phpShutDownSqrlSystem)();
static void (*phpInitResponse)(SQRL_RESPONSE *pResponse);
static void (*phpSendRequest)(SQRL_CONTROL_BLOCK *pSCB);
static void (*phpFreeResponse)(SQRL_RESPONSE *pResponse);

PHP_FUNCTION(sspapiOpenLibrary) {
	php_printf("open_sspapi_library()<br>");

	sspapi_handle=dlopen("libsspapi.so", RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
	if(sspapi_handle==NULL) {
		php_printf("dlerror (libsspapi): %s<br>", dlerror());
		RETURN_NULL();
	}
	else {
		php_printf("libsspapi.so opened successfully %p<br>", sspapi_handle);
	}

	int n=0;
	do {
		char *error;
		dlerror(); // clear any error

	n++;
		*(void **) (&phpPing)=dlsym(sspapi_handle, "SSP_Ping");
		if((error=dlerror())!=NULL) break;
	n++;
		*(void **) (&phpResetCounter)=dlsym(sspapi_handle, "SSP_ResetCounter");
		if((error=dlerror())!=NULL) break;
	n++;

		*(void **) (&phpInitSqrlCfgData)=dlsym(sspapi_handle, "SSP_InitSqrlCfgData");
		if((error=dlerror())!=NULL) break;
	n++;
		*(void **) (&phpInitSqrlSystem)=dlsym(sspapi_handle, "SSP_InitSqrlSystem");
		if((error=dlerror())!=NULL) break;
	n++;
		*(void **) (&phpShutDownSqrlSystem)=dlsym(sspapi_handle, "SSP_ShutDownSqrlSystem");
		if((error=dlerror())!=NULL) break;
	n++;
		*(void **) (&phpInitResponse)=dlsym(sspapi_handle, "SSP_InitResponse");
		if((error=dlerror())!=NULL) break;
	n++;
		*(void **) (&phpSendRequest)=dlsym(sspapi_handle, "SSP_SendRequest");
		if((error=dlerror())!=NULL) break;
	n++;
		*(void **) (&phpFreeResponse)=dlsym(sspapi_handle, "SSP_FreeResponse");
		if((error=dlerror())!=NULL) break;

		php_printf("dlsym(sspapi_handle): OK<br>");
		RETURN_TRUE;
	} while (0);
	php_printf("dlerror in dlsym(sspapi_handle): %d %s<br>", n, dlerror());
	RETURN_NULL();
}

PHP_FUNCTION(sspapiCloseLibrary) {
	php_printf("close_sspapi_library()<br>");
	
	int rc=dlclose(sspapi_handle);
	if(rc!=0) {
		php_printf("dlclose(%p): %d<br>", sspapi_handle, rc);
		RETURN_NULL();
	}
	else {
		php_printf("libsspapi.so closed successfully<br>");
	}
	RETURN_TRUE;
}

PHP_FUNCTION(sspapiPing) {
	php_printf("sspapiPing()<br>");
	php_printf("%s", phpPing());
	RETURN_TRUE;
}

PHP_FUNCTION(sspapiResetCounter) {
	php_printf("sspapiResetCounter()<br>");
	php_printf("rc: %d<br>", phpResetCounter());
	phpResetCounter();
	RETURN_TRUE;
}

PHP_FUNCTION(sspapiInitSqrlCfgData) {
	php_printf("sspapiInitSqrlCfgData()<br>");
	php_printf("rc: %d<br>", phpInitSqrlCfgData());
phpInitSqrlCfgData();
	RETURN_TRUE;
}

PHP_FUNCTION(sspapiInitSqrlSystem) {
	php_printf("sspapiInitSqrlSystem()<br>");
	php_printf("rc: %d<br>", phpInitSqrlSystem());
phpInitSqrlSystem();
	RETURN_TRUE;
}

PHP_FUNCTION(sspapiShutDownSqrlSystem) {
	php_printf("sspapiShutdownSqrlSystem()<br>");
	php_printf("rc: %d<br>", phpShutDownSqrlSystem());
phpShutDownSqrlSystem();
	RETURN_TRUE;
}

PHP_FUNCTION(sspapiSendRequest) {
 	php_printf("sspapiSendRequest()<br>");
	zval *arr, *data;
	HashTable *arr_hash;
	HashPosition pointer;
	int array_count;
	
	enum{NUM_ELEMENTS=10};
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &arr) == FAILURE) {
		RETURN_NULL();
	}
	arr_hash = Z_ARRVAL_P(arr);
	array_count = zend_hash_num_elements(arr_hash);
	
	php_printf("The array passed contains %d elements<br>", array_count);
	if(array_count!=NUM_ELEMENTS) {
		php_printf("Error: The array must contain %d elements<br>", NUM_ELEMENTS);
		RETURN_NULL();
	}

	SQRL_CONTROL_BLOCK scb;
	
	zend_hash_internal_pointer_reset_ex(arr_hash, &pointer);
	for(int i=0; i<array_count; i++) {
		data=zend_hash_get_current_data_ex(arr_hash, &pointer);
		if(Z_TYPE_P(data) == IS_STRING){
			php_printf("%d: ", i);
			PHPWRITE(Z_STRVAL_P(data), Z_STRLEN_P(data));
			php_printf("<br>");
		}
		if(Z_TYPE_P(data) == IS_LONG){
			php_printf("%d: ", i);
			php_printf("%ld", (long)Z_LVAL_P(data));
			php_printf("<br>");
		}
		switch(i) {
			case 0: scb.lpszMethod=Z_STRVAL_P(data); break;
			case 1: scb.lpszPathInfo=Z_STRVAL_P(data); break;
			case 2: scb.lpszQueryString=Z_STRVAL_P(data); break;
			case 3: scb.DataLen=Z_LVAL_P(data); break;
			case 4: scb.lpData=Z_STRVAL_P(data); break;
			case 5: scb.lpszHttpHost=Z_STRVAL_P(data); break;
			case 6: scb.lpszHttpReferrer=Z_STRVAL_P(data); break;
			case 7: scb.lpszRemoteAddr=Z_STRVAL_P(data); break;
			case 8: scb.lpszHttpOrigin=Z_STRVAL_P(data); break;
			case 9: strcpy(scb.szServerPort, Z_STRVAL_P(data)) ; break;
		}
		zend_hash_move_forward_ex(arr_hash, &pointer);
	}

	SQRL_RESPONSE rsp;
	phpInitResponse(&rsp);

php_printf("&rsp %p<br>", &rsp);
php_printf(" rsp.pszHeaders %p<br>", rsp.pszHeaders);
php_printf(" rsp.pData %p<br>", rsp.pData);
php_printf(" rsp.DataLen %d<br>", rsp.DataLen);
	
	scb.pResponse=&rsp;
	
	php_printf("*** %s<br>", scb.lpszMethod);
	php_printf("*** %s<br>", scb.lpszPathInfo);
	php_printf("*** %s<br>", scb.lpszQueryString);
	php_printf("*** %d<br>", (int)scb.DataLen);
	php_printf("*** %s<br>", scb.lpData);
	php_printf("*** %s<br>", scb.lpszHttpHost);
	php_printf("*** %s<br>", scb.lpszHttpReferrer);
	php_printf("*** %s<br>", scb.lpszRemoteAddr);
	php_printf("*** %s<br>", scb.lpszHttpOrigin);
	php_printf("*** %s<br>", scb.szServerPort);
	php_printf("*** %p<br>", scb.pResponse);
	
	phpSendRequest(&scb);
	
php_printf("&rsp %p<br>", &rsp);
php_printf(" rsp.pszHeaders %p<br>", rsp.pszHeaders);
php_printf(" rsp.pData %p<br>", rsp.pData);
php_printf(" rsp.DataLen %d<br>", rsp.DataLen);

for(int i=0; i<rsp.DataLen; i++) {
	php_printf("%02x ", rsp.pData[i]);
}
php_printf("<br>");

	array_init(return_value);
	add_next_index_string(return_value, rsp.pszHeaders);
	add_next_index_stringl(return_value, rsp.pData, rsp.DataLen);
	add_next_index_long(return_value, rsp.DataLen);

	phpFreeResponse(&rsp);

	php_printf("&rsp %p<br>", &rsp);
	php_printf(" rsp.pszHeaders %p<br>", rsp.pszHeaders);
	php_printf(" rsp.pData %p<br>", rsp.pData);
	php_printf(" rsp.DataLen %d<br>", rsp.DataLen);
	
	return;
}

static zend_function_entry php_sspphp_functions[] = {
	PHP_FE(sspapiOpenLibrary, NULL)
	PHP_FE(sspapiCloseLibrary, NULL)
	PHP_FE(sspapiPing, NULL)
	PHP_FE(sspapiResetCounter, NULL)
	PHP_FE(sspapiInitSqrlCfgData, NULL)
	PHP_FE(sspapiInitSqrlSystem, NULL)
	PHP_FE(sspapiShutDownSqrlSystem, NULL)
	PHP_FE(sspapiSendRequest, NULL)
    PHP_FE_END
};
zend_module_entry sspphp_module_entry = {
  #if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,        // Roughly means if PHP Version > 4.2.0
  #endif
    SSPPHP_EXTNAME,        // Define PHP extension name
    php_sspphp_functions,		/* Functions */
    NULL,        /* MINIT */
    NULL,        /* MSHUTDOWN */
    NULL,        /* RINIT */
    NULL,        /* RSHUTDOWN */
    NULL,        /* MINFO */
  #if ZEND_MODULE_API_NO >= 20010901
    SSPPHP_EXTVER,        // Roughly means if PHP Version > 4.2.0
  #endif
    STANDARD_MODULE_PROPERTIES
};
#ifdef COMPILE_DL_SSPPHP
  ZEND_GET_MODULE(sspphp)      // Common for all PHP extensions which are build as shared modules
#endif

