/*
    QC_XmlSecKeyManager.h

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

#ifndef _QORE_XMLSECKEYMANAGER_H

#define _QORE_XMLSECKEYMANAGER_H

DLLLOCAL extern qore_classid_t CID_XMLSECKEYMANAGER;
DLLLOCAL extern QoreClass* QC_XMLSECKEYMANAGER;

DLLLOCAL QoreClass* initXmlSecKeyManagerClass(QoreNamespace& ns);

class QoreXmlSecKeyManager : public AbstractPrivateData, public QoreThreadLock {
private:
    xmlSecKeysMngrPtr keyMgr;

public:
    DLLLOCAL QoreXmlSecKeyManager(ExceptionSink* xsink) : keyMgr(xmlSecKeysMngrCreate()) {
        if (!keyMgr) {
            xsink->raiseException("XMLSECKEYMANAGER-ERROR", "failed to create key manager");
            return;
        }

        if (xmlSecCryptoAppDefaultKeysMngrInit(keyMgr) < 0) {
            xmlSecKeysMngrDestroy(keyMgr);
            keyMgr = nullptr;
            xsink->raiseException("XMLSECKEYMANAGER-ERROR", "failed to initialize key manager");
        }
    }

    DLLLOCAL ~QoreXmlSecKeyManager() {
        if (keyMgr) {
            xmlSecKeysMngrDestroy(keyMgr);
        }
    }

    // takes ownership of key - deletes key if operation fails
    DLLLOCAL int adoptKey(xmlSecKeyPtr key, ExceptionSink* xsink) {
        AutoLocker al(this);

        if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(keyMgr, key)) {
            xmlSecKeyDestroy(key);
            xsink->raiseException("XMLSECKEYMANAGER-ERROR", "failed to adopt key");
            return -1;
        }

        return 0;
    }

    //! loads a certificate from a file and marks it according to the arguments
    DLLLOCAL int loadCertFromPath(ExceptionSink* xsink, const char* filename, xmlSecKeyDataFormat format,
            xmlSecKeyDataType type) {
        AutoLocker al(this);

        if (xmlSecCryptoAppKeysMngrCertLoad(keyMgr, filename, format, type)) {
            xsink->raiseException("XMLSECKEYMANAGER-ERROR", "failed to import certificate from path '%s'", filename);
            return -1;
        }

        return 0;
    }

    //! loads a certificate from memory and marks it according to the arguments
    DLLLOCAL int loadCertFromMemory(ExceptionSink* xsink, const xmlSecByte* data, xmlSecSize dataSize,
            xmlSecKeyDataFormat format, xmlSecKeyDataType type) {
        AutoLocker al(this);

        if (xmlSecCryptoAppKeysMngrCertLoadMemory(keyMgr, data, dataSize, format, type)) {
            xsink->raiseException("XMLSECKEYMANAGER-ERROR", "failed to import certificate from data of size %d",
                (int)dataSize);
            return -1;
        }

        return 0;
    }

    DLLLOCAL operator bool() const {
        return (bool)keyMgr;
    }

    DLLLOCAL xmlSecKeysMngrPtr getKeyManager() {
        return keyMgr;
    }
};

#endif
