include(CheckFunctionExists)

find_path(XMLSEC_INCLUDE_DIR xmlsec/xmlsec.h
    HINTS $ENV{XMLSEC_DIR}/include
    PATH_SUFFIXES xmlsec1
)

#message(STATUS "XMLSEC_INCLUDE_DIR: ${XMLSEC_INCLUDE_DIR} hint: $ENV{XMLSEC_DIR}/include")

check_function_exists(xmlSecFindNode HAVE_XMLSEC)
if (NOT HAVE_XMLSEC)
    message(STATUS "-- Looking for xmlsec")
    find_library(XMLSEC_LIBRARY NAMES xmlsec1 xmlsec
      HINTS $ENV{XMLSEC_DIR}/lib64
    )
    if (XMLSEC_INCLUDE_DIR AND XMLSEC_LIBRARY)
        message(STATUS "-- Found xmlsec: ${XMLSEC_LIBRARY}")
        set(HAVE_XMLSEC true)
    else (XMLSEC_INCLUDE_DIR AND XMLSEC_LIBRARY)
        message(FATAL_ERROR "no xmlsec found")
    endif (XMLSEC_INCLUDE_DIR AND XMLSEC_LIBRARY)
endif (NOT HAVE_XMLSEC)
