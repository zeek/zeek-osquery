# Show warning when installing user is different from the one that configured,
# except when the install is root.
if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    install(CODE "
    if (NOT \"$ENV{USER}\" STREQUAL \"\$ENV{USER}\" AND
        NOT \"\$ENV{USER}\" STREQUAL root)
        message(STATUS \"WARNING: Install is being performed by user \"
                \"'\$ENV{USER}', but the build directory was configured by \"
                \"user '$ENV{USER}'. This may result in a permissions error \"
                \"when writing the install manifest, but you can ignore it \"
                \"and consider the installation as successful if you don't \"
                \"care about the install manifest.\")
    endif ()
    ")
endif ()
