

XMLSEC_SOURCES = xmlsec.cc QC_XmlSecKey.cc QC_XmlSecKeyManager.cc

lib_LTLIBRARIES = xmlsec.la
xmlsec_la_SOURCES = $(XMLSEC_SOURCES)
xmlsec_la_LDFLAGS = -module -avoid-version $(XMLSEC_LDFLAGS) $(LIBXML2_LDFLAGS)

AM_CPPFLAGS = $(XMLSEC_CPPFLAGS) $(QORE_CPPFLAGS) $(LIBXML2_CPPFLAGS)

if COND_PROFILE
AM_CXXFLAGS = -g -pg
else
if COND_DEBUG
AM_CXXFLAGS = -g
endif
endif

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

install-exec-hook:
	mv $(DESTDIR)$(libdir)/xmlsec.$(MODULE_SUFFIX) $(DESTDIR)$(libdir)/xmlsec-api-$(MODULE_API).qmod
	rm -f $(DESTDIR)$(libdir)/xmlsec.la $(DESTDIR)$(libdir)/xmlsec.a
