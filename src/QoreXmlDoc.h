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

#ifndef _QORE_XMLSEC_QOREXMLDOC_H

#define _QORE_XMLSEC_QOREXMLDOC_H

class QoreXmlDoc {
private:
    xmlDocPtr doc;

public:
    // we cast to xmlChar* to work with older versions of libxml2
    // (newer versions are OK and require "const xmlChar*")
    DLLLOCAL QoreXmlDoc(const char *str) : doc(xmlParseDoc((xmlChar*)str)) {
    }

    DLLLOCAL ~QoreXmlDoc() {
        if (doc)
            xmlFreeDoc(doc);
    }

    DLLLOCAL operator bool() const {
        return (bool)doc;
    }

    DLLLOCAL xmlNodePtr getRootElement() {
        return xmlDocGetRootElement(doc);
    }

    DLLLOCAL void dump() {
        // print document to stdout
        xmlDocDump(stdout, doc);
    }

    DLLLOCAL QoreStringNode* getString() {
        xmlChar* p;
        int size;

        xmlDocDumpMemory(doc, &p, &size);
        return new QoreStringNode((char *)p, (qore_size_t)size, (qore_size_t)size + 1, QCS_UTF8);
    }
};

#endif