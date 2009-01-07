AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

noinst_HEADERS = src/qore-xmlsec.h \
	src/QC_XmlSecKey.h \
	src/QC_XmlSecKeyManager.h \
	src/QoreXmlSecKeyDataFormatNode.h \
	src/QoreXmlSecKeyDataIdNode.h

EXTRA_DIST = COPYING ChangeLog AUTHORS README \
	RELEASE-NOTES \
	qore-xmlsec-module.spec docs/xmlsec-module-doc.html

ACLOCAL_AMFLAGS=-I m4

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
