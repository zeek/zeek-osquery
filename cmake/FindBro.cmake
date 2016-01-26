# - Try to find Bro installation.
#
# Usage of this module as follows:
#
#     find_package(Bro)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  BRO_ROOT_DIR   Set this variable to the root installation of
#                 Bro if the module has problems finding
#                 the proper installation path.
#
# Variables defined by this module:
#
#  BRO_FOUND             System has Bro installed.
#  BRO_SITE_DIR          The directory for Bro site scripts.

find_path(BRO_ROOT_DIR
    NAMES bin/bro
)

find_path(BRO_SITE_DIR
    NAMES local.bro
    HINTS ${BRO_ROOT_DIR}/share/bro/site
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Bro DEFAULT_MSG
    BRO_SITE_DIR
)

mark_as_advanced(
    BRO_ROOT
    BRO_SITE_DIR
)
