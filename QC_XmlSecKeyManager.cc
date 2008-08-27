/*
  QC_XmlSecKeyManager.cc

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

#include <qore/Qore.h>
#include <qore/QoreSSLCertificate.h>

#include "qore-xmlsec.h"

#include "QC_XmlSecKeyManager.h"
#include "QC_XmlSecKey.h"

qore_classid_t CID_XMLSECKEYMANAGER = -1;
QoreClass *QC_XMLSECKEYMANAGER = 0;

static void XMLSECKEYMANAGER_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink)
{
   SimpleRefHolder<QoreXmlSecKeyManager> mgr(new QoreXmlSecKeyManager(xsink));
   if (*xsink)
      return;
   
   self->setPrivate(CID_XMLSECKEYMANAGER, mgr.release());
}

static void XMLSECKEYMANAGER_copy(QoreObject *self, QoreObject *old, QoreXmlSecKeyManager *key, ExceptionSink *xsink)
{
   xsink->raiseException("XMLSECKEYMANAGER-COPY-ERROR", "The XmlSecKeyManager class cannot be copied");
}

static AbstractQoreNode *XMLSECKEYMANAGER_addKey(QoreObject *self, QoreXmlSecKeyManager *mgr, const QoreListNode *params, ExceptionSink *xsink)
{
   const QoreObject *obj = test_object_param(params, 0);
   QoreXmlSecKey *key = obj ? (QoreXmlSecKey *)obj->getReferencedPrivateData(CID_XMLSECKEY, xsink) : 0;
   if (!key) {
      if (!*xsink)
	 xsink->raiseException("XMLSECKEYMANAGER-ADDKEY-ERROR", "missing XmlSecKey object as sole argument to XmlSecKeyManager::addKey()");
      return 0;
   }
    SimpleRefHolder<QoreXmlSecKey> holder(key);

   xmlSecKeyPtr new_key = key->clone(xsink);
   if (!new_key)
      return 0;

   if (mgr->adoptKey(new_key, xsink))
      return 0;

   return 0;
}

QoreClass *initXmlSecKeyManagerClass()
{
   QORE_TRACE("initXmlSecKeyManagerClass()");

   QoreClass *QC_XMLSECKEYMANAGER = new QoreClass("XmlSecKeyManager");
   CID_XMLSECKEYMANAGER = QC_XMLSECKEYMANAGER->getID();

   QC_XMLSECKEYMANAGER->setConstructor(XMLSECKEYMANAGER_constructor);
   QC_XMLSECKEYMANAGER->setCopy((q_copy_t)XMLSECKEYMANAGER_copy);

   QC_XMLSECKEYMANAGER->addMethod("addKey",        (q_method_t)XMLSECKEYMANAGER_addKey);
   //QC_XMLSECKEYMANAGER->addMethod("",        (q_method_t)XMLSECKEYMANAGER_);

   return QC_XMLSECKEYMANAGER;
}
