# - Try to find glog headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(Glog)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  GLOG_ROOT_DIR   Set this variable to the root installation of
#                  glog if the module has problems finding
#                  the proper installation path.
#
# Variables defined by this module:
#
#  GLOG_FOUND             System has glog libs/headers
#  GLOG_LIBRARY           The glog library/libraries
#  GLOG_INCLUDE_DIR       The location of glog headers

find_path(GLOG_ROOT
    NAMES glog/logging.h
)

find_library(GLOG_LIBRARY
    NAMES glog
    HINTS ${GLOG_ROOT}/lib
)

find_path(GLOG_INCLUDE_DIR
    NAMES glog/logging.h
    HINTS ${GLOG_ROOT}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(glog DEFAULT_MSG
    GLOG_LIBRARY
    GLOG_INCLUDE_DIR
)

mark_as_advanced(
    GLOG_ROOT
    GLOG_LIBRARY
    GLOG_INCLUDE_DIR
)
