/*
  xmlsec Qore module

  Copyright (C) 2008 David Nichols, all rights reserved
*/

#include "qore-xmlsec.h"

#include <qore/QoreSSLCertificate.h>

#include "QC_XmlSecKey.h"
#include "QC_XmlSecKeyManager.h"

QoreStringNode* xmlsec_module_init();
void xmlsec_module_ns_init(QoreNamespace *rns, QoreNamespace *qns);
void xmlsec_module_delete();

// qore module symbols
DLLEXPORT char qore_module_name[] = "xmlsec";
DLLEXPORT char qore_module_version[] = PACKAGE_VERSION;
DLLEXPORT char qore_module_description[] = "xmlsec module";
DLLEXPORT char qore_module_author[] = "David Nichols";
DLLEXPORT char qore_module_url[] = "http://qoretechnologies.com/qore";
DLLEXPORT int qore_module_api_major = QORE_MODULE_API_MAJOR;
DLLEXPORT int qore_module_api_minor = QORE_MODULE_API_MINOR;
DLLEXPORT qore_module_init_t qore_module_init = xmlsec_module_init;
DLLEXPORT qore_module_ns_init_t qore_module_ns_init = xmlsec_module_ns_init;
DLLEXPORT qore_module_delete_t qore_module_delete = xmlsec_module_delete;
DLLEXPORT qore_license_t qore_module_license = QL_LGPL;

QoreNamespace XmlSec_NS("XmlSec");
qore_type_t NT_XMLSECKEYDATAID = -1;
qore_type_t NT_XMLSECKEYDATAFORMAT = -1;

// we have to put a lock around the following calls (the same lock)
// xmlSecDSigCtxSign(), xmlSecEncCtxBinaryEncrypt(), xmlSecEncCtxXmlEncrypt(),
// and xmlSecEncCtxDecrypt() or we get decrypting errors
#ifdef NEED_XMLSEC_BIG_LOCK
DLLLOCAL QoreThreadLock big_lock;
#endif

// xmlsec library error callback function
static void qore_xmlSecErrorsCallback(const char *file, int line, const char *func, const char *errorObject, const char *errorSubject, int reason, const char *msg)
{
   //printd(5, "xmlsec error: %s: %s: %s\n", errorObject, errorSubject, msg);
}

QoreStringNode *xmlsec_module_init() {
   xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
   xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
   xmlIndentTreeOutput = 0;
#endif // XMLSEC_NO_XSLT

   // Init xmlsec library
   if (xmlSecInit() < 0)
      return new QoreStringNode("xmlsec initialization failed");

   // Check loaded library version
   if (xmlSecCheckVersion() != 1)
      return new QoreStringNode("xmlsec library version is not compatible");

   /* Load default crypto engine if we are supporting dynamic
    * loading for xmlsec-crypto libraries. Use the crypto library
    * name ("openssl", "nss", etc.) to load corresponding
    * xmlsec-crypto library.
    */

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
   if (xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
      QoreStringNode *str = new QoreStringNode();
      str->sprintf("unable to load default xmlsec-crypto library. Make sure you have it installed and check your shared library path (%s) environment variable",
#if defined(DARWIN)
                   "DYLD_LIBRARY_PATH"
#elif defined(HPUX_PARISC)
                   "SHLIB_PATH"
#else
                   "LD_LIBRARY_PATH"
#endif
         );
      return str;
   }
#endif // XMLSEC_CRYPTO_DYNAMIC_LOADING

   // Init crypto library
   if (xmlSecCryptoAppInit(NULL) < 0)
      return new QoreStringNode("crypto initialization failed");

   // Init xmlsec-crypto library
   if (xmlSecCryptoInit() < 0)
      return new QoreStringNode("xmlsec-crypto initialization failed");

   // set error callback function
   xmlSecErrorsSetCallback(qore_xmlSecErrorsCallback);

   // setup XmlSec namespace
   // add classes
   XmlSec_NS.addSystemClass(initXmlSecClass());
   XmlSec_NS.addSystemClass(initXmlSecKeyClass());
   XmlSec_NS.addSystemClass(initXmlSecKeyManagerClass());

   // setup types and constants
   NT_XMLSECKEYDATAID = get_next_type_id();

   // add constants
   XmlSec_NS.addConstant("ModuleVersion",               new QoreStringNode(PACKAGE_VERSION));

   XmlSec_NS.addConstant("xmlSecKeyDataAesId",          new QoreXmlSecKeyDataIdNode(xmlSecKeyDataAesId));
   XmlSec_NS.addConstant("xmlSecKeyDataDesId",          new QoreXmlSecKeyDataIdNode(xmlSecKeyDataDesId));
   XmlSec_NS.addConstant("xmlSecKeyDataDsaId",          new QoreXmlSecKeyDataIdNode(xmlSecKeyDataDsaId));
   XmlSec_NS.addConstant("xmlSecKeyDataHmacId",         new QoreXmlSecKeyDataIdNode(xmlSecKeyDataHmacId));
   XmlSec_NS.addConstant("xmlSecKeyDataRsaId",          new QoreXmlSecKeyDataIdNode(xmlSecKeyDataRsaId));
   XmlSec_NS.addConstant("xmlSecKeyDataX509Id",         new QoreXmlSecKeyDataIdNode(xmlSecKeyDataX509Id));
   XmlSec_NS.addConstant("xmlSecKeyDataRawX509CertId",  new QoreXmlSecKeyDataIdNode(xmlSecKeyDataRawX509CertId));

   NT_XMLSECKEYDATAFORMAT = get_next_type_id();

   XmlSec_NS.addConstant("xmlSecKeyDataFormatUnknown",  new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatUnknown));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatBinary",   new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatBinary));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatPem",      new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatPem));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatDer",      new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatDer));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatPkcs8Pem", new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatPkcs8Pem));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatPkcs8Der", new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatPkcs8Der));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatPkcs12",   new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatPkcs12));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatCertPem",  new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatCertPem));
   XmlSec_NS.addConstant("xmlSecKeyDataFormatCertDer",  new QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormatCertDer));

   XmlSec_NS.addConstant("xmlSecKeyDataTypeUnknown",    xmlSecKeyDataTypeUnknown);
   XmlSec_NS.addConstant("xmlSecKeyDataTypeNone",       xmlSecKeyDataTypeNone);
   XmlSec_NS.addConstant("xmlSecKeyDataTypePublic",     xmlSecKeyDataTypePublic);
   XmlSec_NS.addConstant("xmlSecKeyDataTypePrivate",    xmlSecKeyDataTypePrivate);
   XmlSec_NS.addConstant("xmlSecKeyDataTypeSymmetric",  xmlSecKeyDataTypeSymmetric);
   XmlSec_NS.addConstant("xmlSecKeyDataTypeSession",    xmlSecKeyDataTypeSession);
   XmlSec_NS.addConstant("xmlSecKeyDataTypePermanent",  xmlSecKeyDataTypePermanent);
   XmlSec_NS.addConstant("xmlSecKeyDataTypeTrusted",    xmlSecKeyDataTypeTrusted);
   XmlSec_NS.addConstant("xmlSecKeyDataTypeAny",        xmlSecKeyDataTypeAny);

   return 0;
}

void xmlsec_module_ns_init(QoreNamespace *rns, QoreNamespace *qns) {
   qns->addNamespace(XmlSec_NS.copy());
}

void xmlsec_module_delete() {
   // Shutdown xmlsec-crypto library
   xmlSecCryptoShutdown();

   // Shutdown crypto library
   xmlSecCryptoAppShutdown();

   // Shutdown xmlsec library
   xmlSecShutdown();

   // Shutdown libxslt/libxml
#ifndef XMLSEC_NO_XSLT
   xsltCleanupGlobals();
#endif // XMLSEC_NO_XSLT
}

