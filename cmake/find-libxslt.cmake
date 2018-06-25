include(CheckFunctionExists)

find_path(LIBXSLT_INCLUDE_DIR xslt.h
    HINTS $ENV{LIBXSLT_DIR}/include
    PATH_SUFFIXES libxslt
)

#message(STATUS "LIBXSLT_INCLUDE_DIR: ${LIBXSLT_INCLUDE_DIR} hint: $ENV{LIBXSLT_DIR}/include")

check_function_exists(xsltCleanupGlobals HAVE_LIBXSLT)
if (NOT HAVE_LIBXSLT)
    message(STATUS "-- Looking for libxslt")
    find_library(LIBXSLT_LIBRARY NAMES xslt HINTS $ENV{LIBXSLT_DIR}/lib)
    if (LIBXSLT_INCLUDE_DIR AND LIBXSLT_LIBRARY)
        message(STATUS "-- Found libxslt: ${LIBXSLT_LIBRARY}")
        set(HAVE_LIBXSLT true)
    else (LIBXSLT_INCLUDE_DIR AND LIBXSLT_LIBRARY)
        message(FATAL_ERROR "no libxslt found")
    endif (LIBXSLT_INCLUDE_DIR AND LIBXSLT_LIBRARY)
endif (NOT HAVE_LIBXSLT)
