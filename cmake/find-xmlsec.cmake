# - Try to find CZMQ
# Once done this will define
# CZMQ_FOUND - System has CZMQ
# CZMQ_INCLUDE_DIRS - The CZMQ include directories
# CZMQ_LIBRARIES - The libraries needed to use CZMQ
# CZMQ_DEFINITIONS - Compiler switches required for using CZMQ

include(CheckFunctionExists)

find_path(XMLSEC_INCLUDE_DIR xmlsec.h
    HINTS $ENV{XMLSEC_DIR}/include
    PATH_SUFFIXES xmlsec1/xmlsec
)

#message(STATUS "XMLSEC_INCLUDE_DIR: ${XMLSEC_INCLUDE_DIR} hint: $ENV{XMLSEC_DIR}/include")

check_function_exists(xmlSecFindNode HAVE_XMLSEC)
if (NOT HAVE_XMLSEC)
    message(STATUS "-- Looking for xmlsec")
    find_library(XMLSEC_LIBRARY NAMES xmlsec1 xmlsec)
    if (XMLSEC_INCLUDE_DIR AND XMLSEC_LIBRARY)
        message(STATUS "-- Found xmlsec: ${XMLSEC_LIBRARY}")
        set(HAVE_XMLSEC true)
    else (XMLSEC_INCLUDE_DIR AND XMLSEC_LIBRARY)
        message(FATAL_ERROR "no xmlsec found")
    endif (XMLSEC_INCLUDE_DIR AND XMLSEC_LIBRARY)
endif (NOT HAVE_XMLSEC)
