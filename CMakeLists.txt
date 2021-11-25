cmake_minimum_required(VERSION 2.8.3)

project(qore-xmlsec-module)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)
set (VERSION_PATCH 0)

set(PROJECT_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(Qore 1.0 REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(XMLSec REQUIRED)

list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBXML2_LIBRARIES})

list(APPEND CMAKE_REQUIRED_LIBRARIES ${XMLSEC1_LIBRARIES})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${XMLSEC1_OPENSSL_LIBRARIES})

list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBXML2_INCLUDE_DIR})

list(APPEND CMAKE_REQUIRED_INCLUDES ${XMLSEC1_INCLUDE_DIR})
list(APPEND CMAKE_REQUIRED_INCLUDES ${XMLSEC1_OPENSSL_INCLUDE_DIR})

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${XMLSEC1_INCLUDE_DIR})
include_directories(${LIBXML2_INCLUDE_DIR})
include_directories(${QORE_INCLUDE_DIR})

# Check for C++11.
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${XMLSEC_CFLAGS} ${XMLSEC1_OPENSSL_CFLAGS}")

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

include_directories(${XMLSEC_INCLUDE_DIR})

set(QPP_SRC
    src/QC_XmlSec.qpp
    src/QC_XmlSecKey.qpp
    src/QC_XmlSecKeyManager.qpp
)

set(CPP_SRC
    src/xmlsec.cpp
)

set(QMOD
)

qore_wrap_qpp_value(QPP_SOURCES ${QPP_SRC})

SET (module_name "xmlsec")

set(QORE_DOX_TMPL_SRC
  docs/mainpage.dox.tmpl
)

add_library(${module_name} MODULE ${QPP_SOURCES} ${CPP_SRC})

qore_binary_module(${module_name} ${PROJECT_VERSION} "${XMLSEC1_LIBRARIES}" "${XMLSEC1_OPENSSL_LIBRARIES}")
#qore_user_modules("${QMOD}")
install(PROGRAMS ${SCRIPTS} DESTINATION bin)

qore_dist(${PROJECT_VERSION})

qore_config_info()

FIND_PACKAGE(Doxygen)
if (DOXYGEN_FOUND)
    qore_wrap_dox(QORE_DOX_SRC ${QORE_DOX_TMPL_SRC})
    add_custom_target(QORE_MOD_DOX_FILES DEPENDS ${QORE_DOX_SRC})
    add_dependencies(docs QORE_MOD_DOX_FILES)
endif()
