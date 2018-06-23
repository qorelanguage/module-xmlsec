/*
    Qore Programming Language

    Copyright 2003 - 2018 Qore Technologies, s.r.o.

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

#ifndef _QORE_XMLSEC_QOREXMLSECENCCTX_H

#define _QORE_XMLSEC_QOREXMLSECENCCTX_H

#ifdef NEED_XMLSEC_BIG_LOCK
extern DLLLOCAL QoreThreadLock big_lock;
#endif

class QoreXmlSecEncCtx {
private:
    xmlSecEncCtxPtr encCtx;

public:
    DLLLOCAL QoreXmlSecEncCtx(ExceptionSink* xsink, xmlSecKeysMngrPtr mgr = nullptr) : encCtx(xmlSecEncCtxCreate(mgr)) {
    }

    DLLLOCAL ~QoreXmlSecEncCtx() {
        if (encCtx) {
            xmlSecEncCtxDestroy(encCtx);
        }
    }

    DLLLOCAL operator bool() const {
        return (bool)encCtx;
    }

    // takes over ownership of key
    DLLLOCAL void setKey(xmlSecKeyPtr key) {
        encCtx->encKey = key;
    }

    DLLLOCAL int encryptBinary(xmlNodePtr tmpl, const BinaryNode *b) {
#ifdef NEED_XMLSEC_BIG_LOCK
        AutoLocker al(big_lock);
#endif
        return (xmlSecEncCtxBinaryEncrypt(encCtx, tmpl, (const unsigned char *)b->getPtr(), b->size()) < 0) ? -1 : 0;
    }

    DLLLOCAL int encryptNode(xmlNodePtr tmpl, xmlNodePtr node) {
#ifdef NEED_XMLSEC_BIG_LOCK
        AutoLocker al(big_lock);
#endif
        return (xmlSecEncCtxXmlEncrypt(encCtx, tmpl, node) < 0) ? -1 : 0;
    }

    DLLLOCAL int decrypt(xmlNodePtr node, BinaryNode *&out, ExceptionSink *xsink) {
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

#endif