
#include <config.h>

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

#include "QoreXmlSecKeyDataIdNode.h"
#include "QoreXmlSecKeyDataFormatNode.h"
