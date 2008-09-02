/*
  QC_XmlSecKey.cc

  Qore Programming Language

  Copyright 2003 - 2008 David Nichols

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "qore-xmlsec.h"

#include <qore/QoreSSLCertificate.h>

#include "QC_XmlSecKey.h"

qore_classid_t CID_XMLSECKEY = -1;
QoreClass *QC_XMLSECKEY = 0;

// new XmlSecKey(binary, format, [password])
// new XmlSecKey(string, format, [password])
// new XmlSecKey(string, num_bits, type)
// new XmlSecKey(id, num_bits, type)
static void XMLSECKEY_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink)
{
   const AbstractQoreNode *p = get_param(params, 0);

   qore_type_t t = p->getType();
   if (t == NT_STRING) {
      const QoreStringNode *str = reinterpret_cast<const QoreStringNode *>(p);

      const QoreXmlSecKeyDataFormatNode *format = test_xmlseckeydataformat_param(params, 1);
      if (!format) {
	 p = get_param(params, 1);
	 int num_bits = p ? p->getAsInt() : 0;

	 p = get_param(params, 2);
	 xmlSecKeyDataType type = p ? p->getAsInt() : xmlSecKeyDataTypeUnknown;

	 SimpleRefHolder<QoreXmlSecKey> key(new QoreXmlSecKey((const xmlChar *)str->getBuffer(), num_bits, type, xsink));
	 if (*xsink)
	    return;
	 
	 self->setPrivate(CID_XMLSECKEY, key.release());
	 return;
      }

      const QoreStringNode *pass = test_string_param(params, 2);

      SimpleRefHolder<QoreXmlSecKey> key(new QoreXmlSecKey(xsink, (xmlSecByte *)str->getBuffer(), str->strlen(), format->getFormat(), pass ? pass->getBuffer() : 0));
      if (*xsink)
	 return;

      self->setPrivate(CID_XMLSECKEY, key.release());
      return;
   }

   if (t == NT_BINARY) {
      const BinaryNode *b = reinterpret_cast<const BinaryNode *>(p);

      const QoreXmlSecKeyDataFormatNode *format = test_xmlseckeydataformat_param(params, 1);
      if (!format) {
	 xsink->raiseException("XMLSECKEY-CONSTRUCTOR-ERROR", "missing xmlSecKeyDataFormat value as second argument after binary argument in XmlSecKey::constructor()");
	 return;
      }

      const QoreStringNode *pass = test_string_param(params, 2);

      SimpleRefHolder<QoreXmlSecKey> key(new QoreXmlSecKey(xsink, (xmlSecByte *)b->getPtr(), b->size(), format->getFormat(), pass ? pass->getBuffer() : 0));
      if (*xsink)
	 return;

      self->setPrivate(CID_XMLSECKEY, key.release());
      return;
   }

   if (t == NT_XMLSECKEYDATAID) {
      const QoreXmlSecKeyDataIdNode *id = reinterpret_cast<const QoreXmlSecKeyDataIdNode *>(p);

      p = get_param(params, 1);
      int num_bits = p ? p->getAsInt() : 0;

      p = get_param(params, 2);
      xmlSecKeyDataType type = p ? p->getAsInt() : xmlSecKeyDataTypeUnknown;

      SimpleRefHolder<QoreXmlSecKey> key(new QoreXmlSecKey(id->getID(), num_bits, type, xsink));
      if (*xsink)
	 return;

      self->setPrivate(CID_XMLSECKEY, key.release());
      return;
   }

   xsink->raiseException("XMLSECKEY-CONSTRUCTOR-ERROR", "expecting string, binary, or xmlSecKeyDataId type as first argument to XmlSecKey::constructor(), got type '%s'", p ? p->getTypeName() : "NOTHING");
}

static void XMLSECKEY_copy(QoreObject *self, QoreObject *old, QoreXmlSecKey *key, ExceptionSink *xsink)
{
   QoreXmlSecKey *nk = key->copy(xsink);
   if (!nk)
      return;

   self->setPrivate(CID_XMLSECKEY, nk);
}

// XmlSecKey::setCertificate(string|binary, format)
// XmlSecKey::setCertificate(SSLCertificate)
static AbstractQoreNode *XMLSECKEY_setCertificate(QoreObject *self, QoreXmlSecKey *key, const QoreListNode *params, ExceptionSink *xsink)
{
   const AbstractQoreNode *p = get_param(params, 0);

   qore_type_t t = p ? p->getType() : NT_NOTHING;
   if (t) {
      if (t == NT_STRING) {
	 const QoreStringNode *str = reinterpret_cast<const QoreStringNode *>(p);

	 const QoreXmlSecKeyDataFormatNode *fmt = test_xmlseckeydataformat_param(params, 1);
	 if (!fmt) {
	    xsink->raiseException("XMLSECKEY-SETCERTIFICATE-ERROR", "missing xmlSecKeyDataFormat value as second argument to XmlSecKey::setCertificate(), required when first argument is a string");
	    return 0;
	 }
	 
	 xmlSecKeyDataFormat format = fmt->getFormat();

	 key->setCertificate((xmlSecByte *)str->getBuffer(), str->strlen(), format, xsink);
	 return 0;
      }
      else if (t == NT_BINARY) {
	 const BinaryNode *b = reinterpret_cast<const BinaryNode *>(p);

	 const QoreXmlSecKeyDataFormatNode *fmt = test_xmlseckeydataformat_param(params, 1);
	 if (!fmt) {
	    xsink->raiseException("XMLSECKEY-SETCERTIFICATE-ERROR", "missing xmlSecKeyDataFormat value as second argument to XmlSecKey::setCertificate(), required when first argument is a binary object");
	    return 0;
	 }
	 
	 xmlSecKeyDataFormat format = fmt->getFormat();

	 key->setCertificate((xmlSecByte *)b->getPtr(), b->size(), format, xsink);
	 return 0;
      }
      else if (t == NT_OBJECT) {
	 const QoreObject *obj = reinterpret_cast<const QoreObject *>(p);
	 QoreSSLCertificate *c = (QoreSSLCertificate *)obj->getReferencedPrivateData(CID_SSLCERTIFICATE, xsink);
	 if (*xsink)
	    return 0;
	 if (c) {
	    ReferenceHolder<QoreSSLCertificate> holder(c, xsink);
	    SimpleRefHolder<QoreStringNode> cert_pem(c->getPEM(xsink));
	    if (*xsink)
	       return 0;

	    key->setCertificate((xmlSecByte *)cert_pem->getBuffer(), cert_pem->strlen(), xmlSecKeyDataFormatCertPem, xsink);
	    return 0;
	 }
      }      
   }

   xsink->raiseException("XMLSECKEY-SETCERTIFICATE-ERROR", "expecting a string, binary, or SSLCertificate as first argument of XmlSecKey::setCertificate(), got type: '%s'", p ? p->getTypeName() : "NOTHING");

   return 0;
}

static AbstractQoreNode *XMLSECKEY_setName(QoreObject *self, QoreXmlSecKey *key, const QoreListNode *params, ExceptionSink *xsink)
{
   const QoreStringNode *str = test_string_param(params, 0);
   if (!str) {
      xsink->raiseException("XMLSECKEY-SETNAME-ERROR", "missing string argument to XmlSecKey::setName()");
      return 0;
   }

   key->setName(str->getBuffer(), xsink);
   return 0;
}

static AbstractQoreNode *XMLSECKEY_getName(QoreObject *self, QoreXmlSecKey *key, const QoreListNode *params, ExceptionSink *xsink)
{
   return key->getName(xsink);
}

static AbstractQoreNode *XMLSECKEY_getType(QoreObject *self, QoreXmlSecKey *key, const QoreListNode *params, ExceptionSink *xsink)
{
   xmlSecKeyDataType type = key->getType(xsink);
   if (*xsink)
      return 0;

   return new QoreBigIntNode(type);
}

/*
static AbstractQoreNode *XMLSECKEY_getSize(QoreObject *self, QoreXmlSecKey *key, const QoreListNode *params, ExceptionSink *xsink)
{
   int size = key->getSize(xsink);
   if (*xsink)
      return;

   return new QoreBigIntNode(size);
}
*/

QoreClass *initXmlSecKeyClass()
{
   QORE_TRACE("initXmlSecKeyClass()");

   QoreClass *QC_XMLSECKEY = new QoreClass("XmlSecKey");
   CID_XMLSECKEY = QC_XMLSECKEY->getID();

   QC_XMLSECKEY->setConstructor(XMLSECKEY_constructor);
   QC_XMLSECKEY->setCopy((q_copy_t)XMLSECKEY_copy);

   QC_XMLSECKEY->addMethod("setCertificate",   (q_method_t)XMLSECKEY_setCertificate);
   QC_XMLSECKEY->addMethod("setName",          (q_method_t)XMLSECKEY_setName);
   QC_XMLSECKEY->addMethod("getName",          (q_method_t)XMLSECKEY_getName);
   QC_XMLSECKEY->addMethod("getType",          (q_method_t)XMLSECKEY_getType);
   //QC_XMLSECKEY->addMethod("getSize",          (q_method_t)XMLSECKEY_getSize);
   //QC_XMLSECKEY->addMethod("",        (q_method_t)XMLSECKEY_);

   return QC_XMLSECKEY;
}
