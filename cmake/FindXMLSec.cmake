#  Find the LibXMLSec digital siginature library
#
#  XMLSEC1_FOUND - System has LibXMLSec
#  XMLSEC1_INCLUDE_DIR - The LibXMLSec include directory
#  XMLSEC1_LIBRARIES - The libraries needed to use LibXMLSec
#  XMLSEC1_DEFINITIONS - Compiler switches required for using LibXMLSec
#=============================================================================

# use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
FIND_PACKAGE(PkgConfig)
PKG_CHECK_MODULES(PC_XMLSEC1 xmlsec1 QUIET)
PKG_CHECK_MODULES(PC_XMLSEC1_OPENSSL xmlsec1-openssl QUIET)
SET(XMLSEC1_DEFINITIONS ${PC_XMLSEC1_CFLAGS_OTHER})
SET(XMLSEC1_OPENSSL_DEFINITIONS ${PC_XMLSEC1_OPENSSL_CFLAGS_OTHER})
STRING(REPLACE ";" " " XMLSEC1_CFLAGS "${XMLSEC1_DEFINITIONS}")
STRING(REPLACE ";" " " XMLSEC1_OPENSSL_CFLAGS "${XMLSEC1_OPENSSL_DEFINITIONS}")

FIND_PATH(XMLSEC1_INCLUDE_DIR NAMES xmlsec/xmlsec.h
   HINTS
   ${PC_XMLSEC1_INCLUDEDIR}
   ${PC_XMLSEC1_INCLUDE_DIRS}
   PATH_SUFFIXES xmlsec1
)

FIND_PATH(XMLSEC1_OPENSSL_INCLUDE_DIR NAMES xmlsec/openssl/crypto.h
   HINTS
   ${PC_XMLSEC1_OPENSSL_INCLUDEDIR}
   ${PC_XMLSEC1_OPENSSL_INCLUDE_DIRS}
   PATH_SUFFIXES xmlsec1
)

FIND_LIBRARY(XMLSEC1_LIBRARIES NAMES xmlsec1
   HINTS
   ${PC_XMLSEC1_LIBDIR}
   ${PC_XMLSEC1_LIBRARY_DIRS}
)

FIND_LIBRARY(XMLSEC1_OPENSSL_LIBRARIES NAMES xmlsec1-openssl
   HINTS
   ${PC_XMLSEC1_LIBDIR}
   ${PC_XMLSEC1_LIBRARY_DIRS}
)

# handle the QUIETLY and REQUIRED arguments and set XMLSEC1_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XMLSec DEFAULT_MSG XMLSEC1_LIBRARIES XMLSEC1_OPENSSL_LIBRARIES XMLSEC1_INCLUDE_DIR XMLSEC1_OPENSSL_INCLUDE_DIR)
MARK_AS_ADVANCED(XMLSEC1_INCLUDE_DIR XMLSEC1_OPENSSL_INCLUDE_DIR XMLSEC1_LIBRARIES XMLSEC1_OPENSSL_LIBRARIES )