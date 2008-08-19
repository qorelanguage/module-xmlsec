/*
  xmlsec Qore module

  Copyright (C) 2008 David Nichols, all rights reserved
*/

#include <qore/Qore.h>
#include <qore/QoreSSLCertificate.h>

#include "qore-xmlsec.h"

#include "QC_XmlSecKey.h"
#include "QC_XmlSecKeyManager.h"

QoreStringNode *xmlsec_module_init();
void xmlsec_module_ns_init(QoreNamespace *rns, QoreNamespace *qns);
void xmlsec_module_delete();

#define QORE_XMLSEC_VERSION "0.1"

// qore module symbols
DLLEXPORT char qore_module_name[] = "xmlsec";
DLLEXPORT char qore_module_version[] = QORE_XMLSEC_VERSION;
DLLEXPORT char qore_module_description[] = "xmlsec module";
DLLEXPORT char qore_module_author[] = "David Nichols";
DLLEXPORT char qore_module_url[] = "http://qoretechnologies.com/qore";
DLLEXPORT int qore_module_api_major = QORE_MODULE_API_MAJOR;
DLLEXPORT int qore_module_api_minor = QORE_MODULE_API_MINOR;
DLLEXPORT qore_module_init_t qore_module_init = xmlsec_module_init;
DLLEXPORT qore_module_ns_init_t qore_module_ns_init = xmlsec_module_ns_init;
DLLEXPORT qore_module_delete_t qore_module_delete = xmlsec_module_delete;
DLLEXPORT qore_license_t qore_module_license = QL_GPL;

QoreNamespace XmlSec_NS("XmlSec");
qore_type_t NT_XMLSECKEYDATAID = -1;
qore_type_t NT_XMLSECKEYDATAFORMAT = -1;

// we have to put a lock around the following calls (the same lock!)
// xmlSecDSigCtxSign(), xmlSecEncCtxBinaryEncrypt(), xmlSecEncCtxXmlEncrypt(), 
// and xmlSecEncCtxDecrypt() or we get decrypting errors!
#define NEED_XMLSEC_BIG_LOCK
#ifdef NEED_XMLSEC_BIG_LOCK
static QoreThreadLock big_lock;
#endif

// xmlsec library error callback function
static void qore_xmlSecErrorsCallback(const char *file, int line, const char *func, const char *errorObject, const char *errorSubject, int reason, const char *msg)
{
   //printd(5, "xmlsec error: %s: %s: %s\n", errorObject, errorSubject, msg);
}

class DSigCtx {
   private:

   public:
      xmlSecDSigCtxPtr dsigCtx;

      DLLLOCAL DSigCtx() : dsigCtx(xmlSecDSigCtxCreate(0))
      {
      }

      DLLLOCAL ~DSigCtx()
      {
	 if (dsigCtx)
	    xmlSecDSigCtxDestroy(dsigCtx);
      }

      // takes over ownership of key
      DLLLOCAL void setKey(xmlSecKeyPtr key)
      {
	 dsigCtx->signKey = key;
      }

      DLLLOCAL int sign(xmlNodePtr node, ExceptionSink *xsink)
      {
#ifdef NEED_XMLSEC_BIG_LOCK
	 AutoLocker al(big_lock);
#endif
	 // sign the template
	 if (xmlSecDSigCtxSign(dsigCtx, node) < 0) {
	    xsink->raiseException("XMLSEC-DSIGCTX-ERROR", "signature failed");
	    return -1;
	 }
	 return 0;
      }

      DLLLOCAL int verify(xmlNodePtr node, ExceptionSink *xsink)
      {
	 if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
	    xsink->raiseException("XMLSEC-DSIGCTX-ERROR", "signature could not be verified");
	    return -1;
	 }
	 return 0;
      }

      DLLLOCAL operator bool() const
      {
	 return (bool)dsigCtx;
      }

      DLLLOCAL bool getStatus() { return dsigCtx->status; }

      DLLLOCAL bool getTransformStatus() 
      {
	 assert(dsigCtx->signMethod);
	 return dsigCtx->signMethod->status;
      }
};

class QoreXmlDoc {
   private:
      xmlDocPtr doc;

   public:
      // we cast to xmlChar* to work with older versions of libxml2
      // (newer versions are OK and require "const xmlChar*")
      DLLLOCAL QoreXmlDoc(const char *str) : doc(xmlParseDoc((xmlChar *)str))
      {
      }

      DLLLOCAL ~QoreXmlDoc()
      {
	 if (doc)
	    xmlFreeDoc(doc);
      }

      DLLLOCAL operator bool() const
      {
	 return (bool)doc;
      }

      DLLLOCAL xmlNodePtr getRootElement()
      {
	 return xmlDocGetRootElement(doc);
      }

      DLLLOCAL void dump()
      {
	 // print document to stdout
	 xmlDocDump(stdout, doc);
      }

      DLLLOCAL QoreStringNode *getString()
      {
	 xmlChar *p;
	 int size;

	 xmlDocDumpMemory(doc, &p, &size);

	 return new QoreStringNode((char *)p, (qore_size_t)size, (qore_size_t)size + 1, QCS_UTF8);
      }
};

class QoreXmlSecEncCtx {
   private:
      xmlSecEncCtxPtr encCtx;

   public:
      DLLLOCAL QoreXmlSecEncCtx(ExceptionSink *xsink, xmlSecKeysMngrPtr mgr = 0) : encCtx(xmlSecEncCtxCreate(mgr))
      {
      }

      DLLLOCAL ~QoreXmlSecEncCtx()
      {
	 if (encCtx)
	    xmlSecEncCtxDestroy(encCtx);
      }

      DLLLOCAL operator bool() const
      {
	 return (bool)encCtx;
      }

      // takes over ownership of key
      DLLLOCAL void setKey(xmlSecKeyPtr key)
      {
	 encCtx->encKey = key;
      }

      DLLLOCAL int encryptBinary(xmlNodePtr tmpl, const BinaryNode *b)
      {
#ifdef NEED_XMLSEC_BIG_LOCK
	 AutoLocker al(big_lock);
#endif
	 return (xmlSecEncCtxBinaryEncrypt(encCtx, tmpl, (const unsigned char *)b->getPtr(), b->size()) < 0) ? -1 : 0;
      }

      DLLLOCAL int encryptNode(xmlNodePtr tmpl, xmlNodePtr node)
      {
#ifdef NEED_XMLSEC_BIG_LOCK
	 AutoLocker al(big_lock);
#endif
	 return (xmlSecEncCtxXmlEncrypt(encCtx, tmpl, node) < 0) ? -1 : 0;
      }

      DLLLOCAL int decrypt(xmlNodePtr node, BinaryNode *&out, ExceptionSink *xsink)
      {
#ifdef NEED_XMLSEC_BIG_LOCK
	 AutoLocker al(big_lock);
#endif
	 if (xmlSecEncCtxDecrypt(encCtx, node) < 0 || !encCtx->result) {
	    xsink->raiseException("XMLSEC-DECRYPT-ERROR", "decryption failed");
	    return -1;
	 }

	 if (!encCtx->resultReplaced) {
	    // place output in "out"
	    out = new BinaryNode();
	    out->append(xmlSecBufferGetData(encCtx->result), xmlSecBufferGetSize(encCtx->result));
	 }
	 else
	    out = 0;

	 return 0;
      }

};

// xmlsec_encrypt(data_to_encrypt, template_string, XmlSecKey, [XmlSecKeyManager])
static AbstractQoreNode *f_xmlsec_encrypt(const QoreListNode *args, ExceptionSink *xsink)
{
   const BinaryNode *bin_data = 0;
   const QoreStringNode *str_data = 0;

   const AbstractQoreNode *data = get_param(args, 0);
   if (data) {
      qore_type_t t = data->getType();
      if (t == NT_BINARY)
	 bin_data = reinterpret_cast<const BinaryNode *>(data);
      else if (t == NT_STRING)
	 str_data = reinterpret_cast<const QoreStringNode *>(data);
   }
   if (!str_data && !bin_data) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "missing string or binary data to encrypt as first argument to xmlsec_encrypt()");
      return 0;
   }

   const QoreStringNode *tmpl = test_string_param(args, 1);
   if (!tmpl) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "missing XML template string as second argument to xmlsec_encrypt()");
      return 0;
   }

   const QoreObject *obj = test_object_param(args, 2);
   QoreXmlSecKey *key = obj ? (QoreXmlSecKey *)obj->getReferencedPrivateData(CID_XMLSECKEY, xsink) : 0;
   if (!key) {
      if (!*xsink)
	 xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "missing XmlSecKey object as third argument to xmlsec_encrypt()");
      return 0;
   }
   SimpleRefHolder<QoreXmlSecKey> holder(key);

   // get optional XmlSecKeyManager argument
   obj = test_object_param(args, 3);
   QoreXmlSecKeyManager *mgr = obj ? (QoreXmlSecKeyManager *)obj->getReferencedPrivateData(CID_XMLSECKEYMANAGER, xsink) : 0;
   if (*xsink)
      return 0;
   SimpleRefHolder<QoreXmlSecKeyManager> mgr_holder(mgr);
   
   TempEncodingHelper template_utf8(tmpl, QCS_UTF8, xsink);
   if (!template_utf8)
      return 0;

   QoreXmlDoc doc(template_utf8->getBuffer());
   if (!doc || !doc.getRootElement()) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "unable to parse XML template string");
      return 0;
   }

   // find start node
   xmlNodePtr node = xmlSecFindNode(doc.getRootElement(), xmlSecNodeEncryptedData, xmlSecEncNs);
   if (!node) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "start node not found in template");
      return 0;
   }
   
   //printd(5, "mgr=%08p\n", mgr ? mgr->getKeyManager() : 0);
   QoreXmlSecEncCtx encCtx(xsink, mgr ? mgr->getKeyManager() : 0);
   if (!encCtx) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "failed to create encryption context");
      return 0;
   }

   xmlSecKeyPtr new_key = key->clone(xsink);
   if (!new_key)
      return 0;

   encCtx.setKey(new_key);

   if (bin_data) {
      if (encCtx.encryptBinary(node, bin_data)) {
	 xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "encryption failed");
	 return 0;
      }
      return doc.getString();
   }

   // do XML encryption

   TempEncodingHelper edoc_utf8(str_data, QCS_UTF8, xsink);
   if (!edoc_utf8)
      return 0;
   
   QoreXmlDoc edoc(edoc_utf8->getBuffer());
   if (!edoc || !edoc.getRootElement()) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "failed to parse XML data to encrypt passed as first argument to xmlsec_encrypt()");
      return 0;
   }
   
   if (encCtx.encryptNode(node, edoc.getRootElement())) {
      xsink->raiseException("XMLSEC-ENCRYPT-ERROR", "encryption failed");
      return 0;
   }

   return edoc.getString();
}

// xmlsec_decrypt(xml, XmlSecKey | XmlSecKeyManager)
static AbstractQoreNode *f_xmlsec_decrypt(const QoreListNode *args, ExceptionSink *xsink)
{
   const QoreStringNode *xml = test_string_param(args, 0);
   if (!xml) {
      xsink->raiseException("XMLSEC-DECRYPT-ERROR", "missing XML string to decrypt as first argument to xmlsec_decrypt()");
      return 0;
   }

   const QoreObject *obj = test_object_param(args, 1);
   SimpleRefHolder<QoreXmlSecKey> key(obj ? (QoreXmlSecKey *)obj->getReferencedPrivateData(CID_XMLSECKEY, xsink) : 0);
   SimpleRefHolder<QoreXmlSecKeyManager> mgr;
   if (!key) {
      if (*xsink)
	 return 0;

      mgr = obj ? (QoreXmlSecKeyManager *)obj->getReferencedPrivateData(CID_XMLSECKEYMANAGER, xsink) : 0;
      if (!mgr) {
	 if (!*xsink)
	    xsink->raiseException("XMLSEC-DECRYPT-ERROR", "missing XmlSecKey or XmlSecKeyManager object as second argument to xmlsec_decrypt()");
	 return 0;
      }
   }

   TempEncodingHelper xml_utf8(xml, QCS_UTF8, xsink);
   if (!xml_utf8)
      return 0;

   QoreXmlDoc doc(xml_utf8->getBuffer());
   if (!doc || !doc.getRootElement()) {
      xsink->raiseException("XMLSEC-DECRYPT-ERROR", "unable to parse XML string");
      return 0;
   }

   // find start node
   xmlNodePtr node = xmlSecFindNode(doc.getRootElement(), xmlSecNodeEncryptedData, xmlSecEncNs);
   if (!node) {
      xsink->raiseException("XMLSEC-DECRYPT-ERROR", "start node not found in template");
      return 0;
   }
   
   //printd(5, "mgr=%08p\n", mgr ? mgr->getKeyManager() : 0);
   QoreXmlSecEncCtx encCtx(xsink, mgr ? mgr->getKeyManager() : 0);
   if (!encCtx) {
      xsink->raiseException("XMLSEC-DECRYPT-ERROR", "failed to create decryption context");
      return 0;
   }

   if (key) {
      xmlSecKeyPtr new_key = key->clone(xsink);
      if (!new_key)
	 return 0;

      encCtx.setKey(new_key);
   }

   BinaryNode *b;
   if (encCtx.decrypt(node, b, xsink))
      return 0;

   return b ? (AbstractQoreNode *)b : (AbstractQoreNode *)doc.getString();
}

// xmlsec_sign(template_string, XmlSecKey)
static AbstractQoreNode *f_xmlsec_sign(const QoreListNode *args, ExceptionSink *xsink)
{
   const QoreStringNode *templ = test_string_param(args, 0);
   if (!templ) {
      xsink->raiseException("XMLSEC-SIGN-ERROR", "missing XML template string as first argument to xmlsec_sign()");
      return 0;
   }

   const QoreObject *obj = test_object_param(args, 1);
   QoreXmlSecKey *key = obj ? (QoreXmlSecKey *)obj->getReferencedPrivateData(CID_XMLSECKEY, xsink) : 0;
   if (!key) {
      if (!*xsink)
	 xsink->raiseException("XMLSEC-SIGN-ERROR", "missing XmlSecKey object as second argument to xmlsec_sign()");
      return 0;
   }
   SimpleRefHolder<QoreXmlSecKey> holder(key);

   TempEncodingHelper template_utf8(templ, QCS_UTF8, xsink);
   if (!template_utf8)
      return 0;

   QoreXmlDoc doc(template_utf8->getBuffer());
   if (!doc || !doc.getRootElement()) {
      xsink->raiseException("XMLSEC-SIGN-ERROR", "unable to parse XML template string");
      return 0;
   }

   // find start node
   xmlNodePtr node = xmlSecFindNode(doc.getRootElement(), xmlSecNodeSignature, xmlSecDSigNs);
   if (!node) {
      xsink->raiseException("XMLSEC-SIGN-ERROR", "start node not found in template");
      return 0;
   }

   DSigCtx dsigCtx;
   if (!dsigCtx) {
      xsink->raiseException("XMLSEC-SIGN-ERROR", "failed to create signature context");
      return 0;
   }

   xmlSecKeyPtr new_key = key->clone(xsink);
   if (!new_key)
      return 0;

   // set key data
   dsigCtx.setKey(new_key);

   if (dsigCtx.sign(node, xsink))
      return 0;

   return doc.getString();
}

// xmlsec_verify(signed_xml_string, XmlSecKey)
static AbstractQoreNode *f_xmlsec_verify(const QoreListNode *args, ExceptionSink *xsink)
{
   const QoreStringNode *signed_string = test_string_param(args, 0);
   if (!signed_string) {
      xsink->raiseException("XMLSEC-VERIFY-ERROR", "missing signed XML string as first argument to xmlsec_verify()");
      return 0;
   }

   const QoreObject *obj = test_object_param(args, 1);
   QoreXmlSecKey *key = obj ? (QoreXmlSecKey *)obj->getReferencedPrivateData(CID_XMLSECKEY, xsink) : 0;
   if (!key) {
      if (!*xsink)
	 xsink->raiseException("XMLSEC-VERIFY-ERROR", "missing XmlSecKey object as second argument to xmlsec_verify()");
      return 0;
   }
   SimpleRefHolder<QoreXmlSecKey> holder(key);

   TempEncodingHelper str_utf8(signed_string, QCS_UTF8, xsink);
   if (!str_utf8)
      return 0;

   QoreXmlDoc doc(str_utf8->getBuffer());
   if (!doc || !doc.getRootElement()) {
      xsink->raiseException("XMLSEC-VERIFY-ERROR", "unable to parse signed XML string");
      return 0;
   }

   // find start node
   xmlNodePtr node = xmlSecFindNode(doc.getRootElement(), xmlSecNodeSignature, xmlSecDSigNs);
   if (!node) {
      xsink->raiseException("XMLSEC-VERIFY-ERROR", "start node not found in string");
      return 0;
   }

   DSigCtx dsigCtx;
   if (!dsigCtx) {
      xsink->raiseException("XMLSEC-VERIFY-ERROR", "failed to create signature context");
      return 0;
   }

   xmlSecKeyPtr new_key = key->clone(xsink);
   if (!new_key)
      return 0;

   // set key data
   dsigCtx.setKey(new_key);

   if (dsigCtx.verify(node, xsink))
      return 0;
   
   //printd(5, "stat=%d success=%d (signMethod->status=%d/%d, fail=%d, ok=%d)\n", dsigCtx.getStatus(), xmlSecDSigStatusSucceeded, dsigCtx.dsigCtx->signMethod->status, dsigCtx.getTransformStatus(), xmlSecTransformStatusFail, xmlSecTransformStatusOk);

   // check if signatures do not match
   if (dsigCtx.getTransformStatus() == xmlSecTransformStatusFail)
      xsink->raiseException("XMLSEC-VERIFY-ERROR", "signature verification failed; signatures do not match");
   else if (dsigCtx.getStatus() != xmlSecDSigStatusSucceeded)
      xsink->raiseException("XMLSEC-VERIFY-ERROR", "signature verification failed; crypto error");

   return 0;
}

QoreStringNode *xmlsec_module_init()
{
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

   // add builtin functions
   BuiltinFunctionList::add("xmlsec_sign",    f_xmlsec_sign);
   BuiltinFunctionList::add("xmlsec_verify",  f_xmlsec_verify);
   BuiltinFunctionList::add("xmlsec_encrypt", f_xmlsec_encrypt);
   BuiltinFunctionList::add("xmlsec_decrypt", f_xmlsec_decrypt);

   // setup XmlSec namespace

   // add classes
   XmlSec_NS.addSystemClass(initXmlSecKeyClass());
   XmlSec_NS.addSystemClass(initXmlSecKeyManagerClass());

   // setup types and constants
   NT_XMLSECKEYDATAID = get_next_type_id();

   // add constants
   XmlSec_NS.addConstant("ModuleVersion",               new QoreStringNode(QORE_XMLSEC_VERSION));

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

   XmlSec_NS.addConstant("xmlSecKeyDataTypeUnknown",    new QoreBigIntNode(xmlSecKeyDataTypeUnknown));
   XmlSec_NS.addConstant("xmlSecKeyDataTypeNone",       new QoreBigIntNode(xmlSecKeyDataTypeNone));
   XmlSec_NS.addConstant("xmlSecKeyDataTypePublic",     new QoreBigIntNode(xmlSecKeyDataTypePublic));
   XmlSec_NS.addConstant("xmlSecKeyDataTypePrivate",    new QoreBigIntNode(xmlSecKeyDataTypePrivate));
   XmlSec_NS.addConstant("xmlSecKeyDataTypeSymmetric",  new QoreBigIntNode(xmlSecKeyDataTypeSymmetric));
   XmlSec_NS.addConstant("xmlSecKeyDataTypeSession",    new QoreBigIntNode(xmlSecKeyDataTypeSession));
   XmlSec_NS.addConstant("xmlSecKeyDataTypePermanent",  new QoreBigIntNode(xmlSecKeyDataTypePermanent));
   XmlSec_NS.addConstant("xmlSecKeyDataTypeTrusted",    new QoreBigIntNode(xmlSecKeyDataTypeTrusted));
   XmlSec_NS.addConstant("xmlSecKeyDataTypeAny",        new QoreBigIntNode(xmlSecKeyDataTypeAny));   

   return 0;
}

void xmlsec_module_ns_init(QoreNamespace *rns, QoreNamespace *qns)
{
   qns->addNamespace(XmlSec_NS.copy());
}

void xmlsec_module_delete()
{
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

