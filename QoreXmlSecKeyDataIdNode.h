/*
  QoreXmlSecKeyDataIdNode.h

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

#ifndef _QORE_QOREXMLSECKEYDATAIDNODE_H

#define _QORE_QOREXMLSECKEYDATAIDNODE_H

DLLEXPORT extern qore_type_t NT_XMLSECKEYDATAID;

class QoreXmlSecKeyDataIdNode : public SimpleValueQoreNode
{
   private:
      xmlSecKeyDataId id;

      DLLLOCAL virtual bool getAsBoolImpl() const { return false; }
      DLLLOCAL virtual int getAsIntImpl() const { return 0; }
      DLLLOCAL virtual int64 getAsBigIntImpl() const { return 0; }
      DLLLOCAL virtual double getAsFloatImpl() const { return 0.0; }

   public:
      DLLLOCAL QoreXmlSecKeyDataIdNode(xmlSecKeyDataId v) : SimpleValueQoreNode(NT_XMLSECKEYDATAID), id(v)
      {
      }

      DLLLOCAL ~QoreXmlSecKeyDataIdNode()
      {
      }

      DLLLOCAL virtual QoreString *getStringRepresentation(bool &del) const
      {
	 del = true;
	 QoreString *str = new QoreString();
	 getStringRepresentation(*str);
	 return str;
      }

      DLLLOCAL virtual void getStringRepresentation(QoreString &str) const
      {
	 str.sprintf("xmlSecKeyDataId %08p", id);
      }

      DLLLOCAL virtual QoreString *getAsString(bool &del, int foff, class ExceptionSink *xsink) const
      {
	 return getStringRepresentation(del);
      }

      DLLLOCAL virtual int getAsString(QoreString &str, int foff, class ExceptionSink *xsink) const
      {
	 getStringRepresentation(str);
	 return 0;
      }

      DLLLOCAL virtual AbstractQoreNode *realCopy() const
      {
	 return new QoreXmlSecKeyDataIdNode(id);
      }

      // the type passed must always be equal to the current type
      DLLLOCAL virtual bool is_equal_soft(const AbstractQoreNode *v, ExceptionSink *xsink) const
      {
	 return QoreXmlSecKeyDataIdNode::is_equal_hard(v, xsink);
      }

      DLLLOCAL virtual bool is_equal_hard(const AbstractQoreNode *v, ExceptionSink *xsink) const
      {
	 const QoreXmlSecKeyDataIdNode *n = dynamic_cast<const QoreXmlSecKeyDataIdNode *>(v);
	 if (!n)
	    return false;

	 return n->id == id;
      }

      // returns the type name as a c string
      DLLLOCAL virtual const char *getTypeName() const
      {
	 return "xmlSecKeyDataId";
      }

      DLLLOCAL xmlSecKeyDataId getID() const
      {
         return id;
      }
};

static inline const QoreXmlSecKeyDataIdNode *test_xmlseckeydataid_param(const QoreListNode *n, int i)
{
   if (!n) return 0;
   return dynamic_cast<const QoreXmlSecKeyDataIdNode *>(n->retrieve_entry(i));
}

#endif
