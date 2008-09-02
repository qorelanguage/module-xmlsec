/*
  QoreXmlSecKeyDataFormatNode.h

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

#ifndef _QORE_QOREXMLSECKEYDATAFORMATNODE_H

#define _QORE_QOREXMLSECKEYDATAFORMATNODE_H

DLLEXPORT extern qore_type_t NT_XMLSECKEYDATAFORMAT;

class QoreXmlSecKeyDataFormatNode : public SimpleValueQoreNode
{
   private:
      xmlSecKeyDataFormat format;

      DLLLOCAL virtual bool getAsBoolImpl() const { return (bool)format; }
      DLLLOCAL virtual int getAsIntImpl() const { return (int)format; }
      DLLLOCAL virtual int64 getAsBigIntImpl() const { return (int64)format; }
      DLLLOCAL virtual double getAsFloatImpl() const { return (double)format; }

   public:
      DLLLOCAL QoreXmlSecKeyDataFormatNode(xmlSecKeyDataFormat v) : SimpleValueQoreNode(NT_XMLSECKEYDATAFORMAT), format(v)
      {
      }

      DLLLOCAL ~QoreXmlSecKeyDataFormatNode()
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
	 str.sprintf("xmlSecKeyDataFormat %d", format);
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
	 return new QoreXmlSecKeyDataFormatNode(format);
      }

      // the type passed must always be equal to the current type
      DLLLOCAL virtual bool is_equal_soft(const AbstractQoreNode *v, ExceptionSink *xsink) const
      {
	 return QoreXmlSecKeyDataFormatNode::is_equal_hard(v, xsink);
      }

      DLLLOCAL virtual bool is_equal_hard(const AbstractQoreNode *v, ExceptionSink *xsink) const
      {
	 const QoreXmlSecKeyDataFormatNode *n = dynamic_cast<const QoreXmlSecKeyDataFormatNode *>(v);
	 if (!n)
	    return false;

	 return n->format == format;
      }

      // returns the type name as a c string
      DLLLOCAL virtual const char *getTypeName() const
      {
	 return "xmlSecKeyDataFormat";
      }

      DLLLOCAL xmlSecKeyDataFormat getFormat() const
      {
         return format;
      }
};

static inline const QoreXmlSecKeyDataFormatNode *test_xmlseckeydataformat_param(const QoreListNode *n, int i)
{
   if (!n) return 0;
   return dynamic_cast<const QoreXmlSecKeyDataFormatNode *>(n->retrieve_entry(i));
}

#endif
