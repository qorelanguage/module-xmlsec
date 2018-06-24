
//#include <config.h>

#include <qore/Qore.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif // XMLSEC_NO_XSLT

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>

#define NEED_XMLSEC_BIG_LOCK 1

#define XMLSEC_KEYDATA_AESID 1
#define XMLSEC_KEYDATA_DESID 2
#define XMLSEC_KEYDATA_DSAID 3
#define XMLSEC_KEYDATA_HMACID 4
#define XMLSEC_KEYDATA_RSAID 5
#define XMLSEC_KEYDATA_X509ID 6
#define XMLSEC_KEYDATA_RAWX509CERTID 7

extern xmlSecKeyDataId xmlsec_get_keydata_id(int i);
