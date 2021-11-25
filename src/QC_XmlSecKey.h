/*
    QC_XmlSecKey.h

    Qore Programming Language

    Copyright 2003 - 2021 Qore Technologies, s.r.o.

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

#ifndef _QORE_XMLSECKEY_H

#define _QORE_XMLSECKEY_H

DLLLOCAL extern qore_classid_t CID_XMLSECKEY;
DLLLOCAL extern QoreClass* QC_XMLSECKEY;

DLLLOCAL QoreClass* initXmlSecKeyClass(QoreNamespace& ns);

class QoreXmlSecKey : public AbstractPrivateData, public QoreThreadLock {
public:
    DLLLOCAL QoreXmlSecKey(ExceptionSink* xsink, xmlSecByte* ptr, int len, xmlSecKeyDataFormat format,
            const char* password = nullptr) {
        key = xmlSecCryptoAppKeyLoadMemory(ptr, len, format, password, 0, 0);
        if (!key) {
            xsink->raiseException("XMLSECKEY-ERROR", "key creation from memory buffer failed");
            return;
        }
    }

    DLLLOCAL QoreXmlSecKey(const xmlChar* name, xmlSecSize sizeBits, xmlSecKeyDataType type,
            ExceptionSink* xsink) {
        key = xmlSecKeyGenerateByName(name, sizeBits, type);
        if (!key) {
            xsink->raiseException("XMLSECKEY-ERROR", "key generation failed");
            return;
        }
    }

    DLLLOCAL QoreXmlSecKey(xmlSecKeyDataId dataId, xmlSecSize sizeBits, xmlSecKeyDataType type,
            ExceptionSink* xsink) {
        key = xmlSecKeyGenerate(dataId, sizeBits, type);
        if (!key) {
            xsink->raiseException("XMLSECKEY-ERROR", "key generation failed");
            return;
        }
    }

    DLLLOCAL ~QoreXmlSecKey() {
        if (key) {
            xmlSecKeyDestroy(key);
        }
    }

    DLLLOCAL xmlSecKeyPtr clone(ExceptionSink* xsink) {
        xmlSecKeyPtr k = xmlSecKeyDuplicate(key);
        if (!k) {
            xsink->raiseException("XMLSECKEY-ERROR", "failed to copy key");
            return nullptr;
        }
        return k;
    }

    DLLLOCAL QoreXmlSecKey* copy(ExceptionSink* xsink) {
        xmlSecKeyPtr k = xmlSecKeyDuplicate(key);
        if (!k) {
            xsink->raiseException("XMLSECKEY-ERROR", "failed to copy key");
            return nullptr;
        }
        return new QoreXmlSecKey(k);
    }

    DLLLOCAL operator bool() const {
        return (bool)key;
    }

    DLLLOCAL int setCertificate(xmlSecByte *ptr, int len, xmlSecKeyDataFormat format, ExceptionSink* xsink) {
        AutoLocker al(this);
        if (checkValidIntern(xsink))
            return -1;

        if (xmlSecCryptoAppKeyCertLoadMemory(key, ptr, len, format)) {
            xsink->raiseException("XMLSECKEY-ERROR", "failed to add certificate");
            return -1;
        }
        return 0;
    }

    DLLLOCAL int setName(const char *name, ExceptionSink* xsink) {
        AutoLocker al(this);
        if (checkValidIntern(xsink))
            return -1;

        // set key name
        if (xmlSecKeySetName(key, (xmlChar *)name) < 0) {
            xsink->raiseException("XMLSECKEY-ERROR","failed to set key name '%s'", name);
            return -1;
        }
        return 0;
    }

    DLLLOCAL QoreStringNode* getName(ExceptionSink* xsink) {
        AutoLocker al(this);
        if (checkValidIntern(xsink)) {
            return nullptr;
        }

        const xmlChar* name = xmlSecKeyGetName(key);
        return name ? new QoreStringNode(name) : nullptr;
    }

    DLLLOCAL xmlSecKeyDataType getType(ExceptionSink* xsink) {
        AutoLocker al(this);
        if (checkValidIntern(xsink)) {
            return xmlSecKeyDataTypeUnknown;
        }

        return xmlSecKeyGetType(key);
    }

    DLLLOCAL int64 getSize(ExceptionSink* xsink) {
        AutoLocker al(this);
        if (checkValidIntern(xsink))
            return -1;

        return xmlSecKeyDataGetSize(xmlSecKeyGetValue(key));
    }

    DLLLOCAL bool isValid() {
        AutoLocker al(this);
        return isValidIntern();
    }

private:
    xmlSecKeyPtr key;

    // not implemented
    QoreXmlSecKey(const QoreXmlSecKey& k) = delete;

    DLLLOCAL QoreXmlSecKey(xmlSecKeyPtr k) : key(k) {}

    DLLLOCAL bool isValidIntern() { return xmlSecKeyIsValid(key); }

    DLLLOCAL int checkValidIntern(ExceptionSink* xsink) {
        if (!isValidIntern()) {
            xsink->raiseException("XMLSECKEY-ERROR", "key is not valid");
            return -1;
        }
        return 0;
    }
};

#endif
