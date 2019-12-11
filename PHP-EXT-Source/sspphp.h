#ifndef SSPPHP_H
#define SSPPHP_H

#define SSPPHP_EXTNAME "sspphp"
#define SSPPHP_EXTVER "1.0"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

extern zend_module_entry sspphp_module_entry;

#define phpext_sspphp_ptr &sspphp_module_entry

#endif
