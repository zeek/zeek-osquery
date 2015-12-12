# - Try to find osquery headers and libraries for building an extension
#
# Usage of this module as follows:
#
#     find_package(Osquery)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  OSQUERY_ROOT_DIR   Set this variable to the root installation of
#                     osquery if the module has problems finding
#                     the proper installation path.
#
# Variables defined by this module:
#
#  OSQUERY_FOUND             System has osquery libs/headers
#  OSQUERY_LIBRARY           The osquery library/libraries
#  OSQUERY_INCLUDE_DIR       The location of osquery headers

find_path(OSQUERY_ROOT_DIR
    NAMES include/osquery/sdk.h
)

find_library(OSQUERY_LIBRARY
    NAMES osquery
    HINTS ${OSQUERY_ROOT_DIR}/lib
)

find_path(OSQUERY_INCLUDE_DIR
    NAMES osquery/sdk.h
    HINTS ${OSQUERY_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(osquery DEFAULT_MSG
    OSQUERY_LIBRARY
    OSQUERY_INCLUDE_DIR
)

mark_as_advanced(
    OSQUERY_ROOT_DIR
    OSQUERY_LIBRARY
    OSQUERY_INCLUDE_DIR
)
