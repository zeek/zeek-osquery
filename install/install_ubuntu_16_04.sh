#!/bin/bash
##
## For ubuntu 16.04
##
## Clean installed stuff (in /usr/local/) with: 
##  sudo rm -rf /usr/local/lib/libcaf_* /usr/local/include/caf/ /usr/local/lib/libbroker.so* /usr/local/include/broker/ /usr/local/lib/libosquery.a /usr/local/include/osquery/
##  sudo rm -rf /usr/local/osquery
##  sudo rm /usr/local/bin/osqueryi /usr/local/bin/osqueryd
##
## Clean downloaded stuff by this script:
##  rm -rf ./actor-framework ./broker ./osquery
##
## Clean bro-osquery stuff:
## rm -rf ./osquery/osquery/external/extension_bro_osquery
##

CORES=4

function downloadCAF() {
 tmp_dir=$(pwd)
 cd $WORKING_DIR
 if [ -d "actor-framework" ]; then
  echo "Actor Framework already installed"
 else
  echo "Downloading CAF"
  git clone https://github.com/actor-framework/actor-framework
  cd actor-framework

  echo "Patching CAF"
  git checkout tags/0.14.5
  # Patch
  echo "---" > patchfile
  echo " CMakeLists.txt | 51 ++++++++++++++++++++++++++++++++++++++++++++++-----" >> patchfile
  echo " 1 file changed, 46 insertions(+), 5 deletions(-)" >> patchfile
  echo "" >> patchfile
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile
  echo "index 9a20c5e..d506b9d 100644" >> patchfile
  echo "--- a/CMakeLists.txt" >> patchfile
  echo "+++ b/CMakeLists.txt" >> patchfile
  echo "@@ -152,7 +152,7 @@ endif()" >> patchfile
  echo " # add -stdlib=libc++ when using Clang if possible" >> patchfile
  echo " if(NOT CAF_NO_AUTO_LIBCPP AND \"\${CMAKE_CXX_COMPILER_ID}\" MATCHES \"Clang\")" >> patchfile
  echo "   set(CXXFLAGS_BACKUP \"\${CMAKE_CXX_FLAGS}\")" >> patchfile
  echo "-  set(CMAKE_CXX_FLAGS \"-std=c++11 -stdlib=libc++\")" >> patchfile
  echo "+    set(CMAKE_CXX_FLAGS \"-std=c++11 -stdlib=libc++\")" >> patchfile
  echo "   try_run(ProgramResult" >> patchfile
  echo "           CompilationSucceeded" >> patchfile
  echo "           \"\${CMAKE_CURRENT_BINARY_DIR}\"" >> patchfile
  echo "@@ -161,9 +161,9 @@ if(NOT CAF_NO_AUTO_LIBCPP AND \"\${CMAKE_CXX_COMPILER_ID}\" MATCHES \"Clang\")" >> patchfile
  echo "   if(NOT CompilationSucceeded OR NOT ProgramResult EQUAL 0)" >> patchfile
  echo "     message(STATUS \"Use clang with GCC' libstdc++\")" >> patchfile
  echo "   else()" >> patchfile
  echo "-    message(STATUS \"Automatically added '-stdlib=libc++' flag \"" >> patchfile
  echo "-                   \"(CAF_NO_AUTO_LIBCPP not defined)\")" >> patchfile
  echo "-    set(EXTRA_FLAGS \"\${EXTRA_FLAGS} -stdlib=libc++\")" >> patchfile
  echo "+	  message(STATUS \"Automatically added '-stdlib=libc++' flag \"" >> patchfile
  echo "+	          \"(CAF_NO_AUTO_LIBCPP not defined)\")" >> patchfile
  echo "+	  set(EXTRA_FLAGS \"\${EXTRA_FLAGS} -stdlib=libc++\")" >> patchfile
  echo "   endif()" >> patchfile
  echo "   # restore CXX flags" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS \"\${CXXFLAGS_BACKUP}\")" >> patchfile
  echo "@@ -222,11 +222,52 @@ if(CMAKE_CXX_FLAGS)" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELEASE        \"\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELWITHDEBINFO \"\")" >> patchfile
  echo " else()" >> patchfile
  echo "-  set(CMAKE_CXX_FLAGS \"-std=c++11 -Wextra -Wall -pedantic \${EXTRA_FLAGS}\")" >> patchfile
  echo "+  set(BUILD_DEPS \"/usr/local/osquery\")" >> patchfile
  echo "+  set(CPP11_FLAGS \"-std=c++11 -stdlib=libstdc++\")" >> patchfile
  echo "+  set(STATIC_FLAGS \"-static-libstdc++\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(default_prefix \"\${BUILD_DEPS}\")" >> patchfile
  echo "+  set(legacy_prefix \"\${BUILD_DEPS}/legacy\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CFLAGS \"-isystem\${default_prefix}/include \${CFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CFLAGS \"-L\${default_prefix}/lib \${CFLAGS}\")" >> patchfile
  echo "+  set(CFLAGS \"-L\${default_prefix}/lib \${CFLAGS}\")" >> patchfile
  echo "+  set(CXXFLAGS \"-L\${default_prefix}/lib \${CXXFLAGS}\")" >> patchfile
  echo "+  set(CXXFLAGS \"-L\${legacy_prefix}/lib \${CXXFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CXXFLAGS \"-I\${default_prefix}/include \${CXXFLAGS}\")" >> patchfile
  echo "+  set(CXXFLAGS \"-I\${legacy_prefix}/include \${CXXFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CFLAGS  \"-isystem\${legacy_prefix}/include \${CFLAGS}\")" >> patchfile
  echo "+  set(CXXFLAGS \"-isystem\${legacy_prefix}/include \${CXXFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(LDFLAGS \"\${LDFLAGS} -Wl,--dynamic-linker=\${legacy_prefix}/lib/ld-linux-x86-64.so.2\")" >> patchfile
  echo "+  #set(LDFLAGS \"\${LDFLAGS} -Wl,-rpath,\${legacy_prefix}/lib\")" >> patchfile
  echo "+" >> patchfile
  echo "+  #set(LDFLAGS \"\${LDFLAGS} -Wl,-rpath,\${default_prefix}/lib\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(LDFLAGS \"\${LDFLAGS} -L\${default_prefix}/lib\")" >> patchfile
  echo "+  set(LDFLAGS \"-L\${default_prefix}/lib \${LDFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(LDFLAGS \"\${LDFLAGS} -lrt -pthread -ldl\")" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CFLAGS \"\${CFLAGS} -fPIC -DNDEBUG -Os -march=core2\")" >> patchfile
  echo "+  set(CXXFLAGS \"\${CXXFLAGS} -fPIC -DNDEBUG -Os -march=core2\")" >> patchfile
  echo "+" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CMAKE_MODULE_LINKER_FLAGS \${LDFLAGS})" >> patchfile
  echo "+  set(CMAKE_SHARED_LINKER_FLAGS \${LDFLAGS})" >> patchfile
  echo "+  #set(CMAKE_STATIC_LINKER_FLAGS \${LDFLAGS})" >> patchfile
  echo "+" >> patchfile
  echo "+  set(CMAKE_CXX_FLAGS \"\${CPP11_FLAGS} \${STATIC_FLAGS} -Wextra -Wall -pedantic \${EXTRA_FLAGS}\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_DEBUG          \"-O0 -g\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_MINSIZEREL     \"-Os\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELEASE        \"-O3 -DNDEBUG\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELWITHDEBINFO \"-O2 -g\")" >> patchfile
  echo "+  " >> patchfile
  echo "+  set(CMAKE_C_FLAGS \"\${CFLAGS} \${CMAKE_C_FLAGS}\")" >> patchfile
  echo "+  set(CMAKE_CXX_FLAGS \"\${CXXFLAGS} \${CMAKE_CXX_FLAGS}\")" >> patchfile
  echo " endif()" >> patchfile
  echo " # set build default build type to RelWithDebInfo if not set" >> patchfile
  echo " if(NOT CMAKE_BUILD_TYPE)" >> patchfile
  echo "-- " >> patchfile
  echo "2.7.4" >> patchfile
  patch -p1 < patchfile
 fi

 cd $tmp_dir
 echo
 echo
}

function downloadBroker() {
 tmp_dir=$(pwd)
 cd $WORKING_DIR
 if [ -d "broker" ]; then
  echo "Broker already installed"
 else
  echo "Downloading Broker"
  git clone --recursive https://github.com/bro/broker
  cd broker

  echo "Patching Broker"
  # Patch tool chain
  echo "---" > patchfile
  echo " CMakeLists.txt | 50 +++++++++++++++++++++++++++++++++++++++++++++++++-" >> patchfile
  echo " 1 file changed, 49 insertions(+), 1 deletion(-)" >> patchfile
  echo "" >> patchfile
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile
  echo "index e439cde..a0d0855 100644" >> patchfile
  echo "--- a/CMakeLists.txt" >> patchfile
  echo "+++ b/CMakeLists.txt" >> patchfile
  echo "@@ -158,12 +158,60 @@ if ( ENABLE_STATIC )" >> patchfile
  echo "     install(TARGETS brokerStatic DESTINATION \${INSTALL_LIB_DIR})" >> patchfile
  echo " endif ()" >> patchfile
  echo " " >> patchfile
  echo "+string(TOUPPER \${CMAKE_BUILD_TYPE} BuildType)" >> patchfile
  echo "+" >> patchfile
  echo "+set(BUILD_DEPS \"/usr/local/osquery\")" >> patchfile
  echo "+set(CPP11_FLAGS \"-std=c++11 -stdlib=libstdc++\")" >> patchfile
  echo "+set(STATIC_FLAGS \"-static-libstdc++\")" >> patchfile
  echo "+set(default_prefix \"\${BUILD_DEPS}\")" >> patchfile
  echo "+set(legacy_prefix \"\${BUILD_DEPS}/legacy\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(CFLAGS \"-isystem\${default_prefix}/include \${CFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(CFLAGS \"-L\${default_prefix}/lib \${CFLAGS}\")" >> patchfile
  echo "+set(CFLAGS \"-L\${default_prefix}/lib \${CFLAGS}\")" >> patchfile
  echo "+set(CXXFLAGS \"-L\${default_prefix}/lib \${CXXFLAGS}\")" >> patchfile
  echo "+set(CXXFLAGS \"-L\${legacy_prefix}/lib \${CXXFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(CXXFLAGS \"-I\${default_prefix}/include \${CXXFLAGS}\")" >> patchfile
  echo "+set(CXXFLAGS \"-I\${legacy_prefix}/include \${CXXFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(CFLAGS  \"-isystem\${legacy_prefix}/include \${CFLAGS}\")" >> patchfile
  echo "+set(CXXFLAGS \"-isystem\${legacy_prefix}/include \${CXXFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(LDFLAGS \"\${LDFLAGS} -Wl,--dynamic-linker=\${legacy_prefix}/lib/ld-linux-x86-64.so.2\")" >> patchfile
  echo "+#set(LDFLAGS \"\${LDFLAGS} -Wl,-rpath,\${legacy_prefix}/lib\")" >> patchfile
  echo "+" >> patchfile
  echo "+#set(LDFLAGS \"\${LDFLAGS} -Wl,-rpath,\${default_prefix}/lib\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(LDFLAGS \"\${LDFLAGS} -L\${default_prefix}/lib\")" >> patchfile
  echo "+set(LDFLAGS \"-L\${default_prefix}/lib \${LDFLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(LDFLAGS \"\${LDFLAGS} -lrt -pthread -ldl\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(CFLAGS \"\${CFLAGS} -fPIC -DNDEBUG -Os -march=core2\")" >> patchfile
  echo "+set(CXXFLAGS \"\${CXXFLAGS} -fPIC -DNDEBUG -Os -march=core2\")" >> patchfile
  echo "+" >> patchfile
  echo "+" >> patchfile
  echo "+set(CMAKE_MODULE_LINKER_FLAGS \${LDFLAGS})" >> patchfile
  echo "+set(CMAKE_SHARED_LINKER_FLAGS \${LDFLAGS})" >> patchfile
  echo "+#set(CMAKE_STATIC_LINKER_FLAGS \${LDFLAGS})" >> patchfile
  echo "+" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS \"\${CPP11_FLAGS} \${STATIC_FLAGS} -Wextra -Wall -pedantic -ftemplate-depth=512 \${EXTRA_FLAGS}\")" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS_DEBUG          \"-O0 -g\")" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS_MINSIZEREL     \"-Os\")" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS_RELEASE        \"-O3 -DNDEBUG\")" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS_RELWITHDEBINFO \"-O2 -g\")" >> patchfile
  echo "+" >> patchfile
  echo "+set(CMAKE_C_FLAGS \"\${CFLAGS} \${CMAKE_C_FLAGS}\")" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS \"\${CXXFLAGS} \${CMAKE_CXX_FLAGS}\")" >> patchfile
  echo "+" >> patchfile
  echo " add_subdirectory(bindings)" >> patchfile
  echo " " >> patchfile
  echo " enable_testing()" >> patchfile
  echo " add_subdirectory(tests)" >> patchfile
  echo " " >> patchfile
  echo "-string(TOUPPER \${CMAKE_BUILD_TYPE} BuildType)" >> patchfile
  echo "+" >> patchfile
  echo " " >> patchfile
  echo " #------------------------------------------------------------------------------" >> patchfile
  echo " #                                Build Summary" >> patchfile
  echo "-- " >> patchfile
  echo "2.7.4" >> patchfile
  patch -p1 < patchfile
  
  # Patch disable tests
  echo "---" > patchfile2
  echo " CMakeLists.txt | 2 +-" >> patchfile2
  echo " 1 file changed, 1 insertion(+), 1 deletion(-)" >> patchfile2
  echo "" >> patchfile2
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile2
  echo "index a0d0855..3786df1 100644" >> patchfile2
  echo "--- a/CMakeLists.txt" >> patchfile2
  echo "+++ b/CMakeLists.txt" >> patchfile2
  echo "@@ -209,7 +209,7 @@ set(CMAKE_CXX_FLAGS \"\${CXXFLAGS} \${CMAKE_CXX_FLAGS}\")" >> patchfile2
  echo " add_subdirectory(bindings)" >> patchfile2
  echo " " >> patchfile2
  echo " enable_testing()" >> patchfile2
  echo "-add_subdirectory(tests)" >> patchfile2
  echo "+#add_subdirectory(tests)" >> patchfile2
  echo " " >> patchfile2
  echo " " >> patchfile2
  echo " " >> patchfile2
  echo "-- " >> patchfile2
  echo "2.7.4" >> patchfile2
  patch -p1 < patchfile2
 fi

  cd $tmp_dir
  echo
  echo
}


function downloadOsquery() {
 tmp_dir=$(pwd)
 cd $WORKING_DIR
 if [ -d "osquery" ]; then
  echo "Osquery already installed"
 else
  echo "Downloading Osquery"
  git clone https://github.com/facebook/osquery
  cd osquery
  
#  echo "Patching Osquery"
#  # Patch: stdlib=libstdc++
#  # applied with commit ae19b7797dfc6e66e5880d20eedfa795b2552094
 fi

  cd $tmp_dir
  echo
  echo  
}

function downloadBroOsquery() {
 tmp_dir=$(pwd)
 cd ${WORKING_DIR}/osquery/external
 if [ -d "extension_bro_osquery" ]; then
  echo "Bro-Osquery already installed"
 else
  echo "Downloading Bro-Osquery"
  git clone https://github.com/bro/bro-osquery extension_bro_osquery
  cd extension_bro_osquery
 fi

  cd $tmp_dir
}

function patchOsqueryForExtensions() {
 tmp_dir=$(pwd)
 cd ${WORKING_DIR}/osquery
 # Patch external call
 echo "---" > patchfile6
 echo " osquery/CMakeLists.txt | 6 +++---" >> patchfile6
 echo " 1 file changed, 3 insertions(+), 3 deletions(-)" >> patchfile6
 echo "" >> patchfile6
 echo "diff --git a/osquery/CMakeLists.txt b/osquery/CMakeLists.txt" >> patchfile6
 echo "index e7cad39..9a4f1d3 100644" >> patchfile6
 echo "--- a/osquery/CMakeLists.txt" >> patchfile6
 echo "+++ b/osquery/CMakeLists.txt" >> patchfile6
 echo "@@ -149,9 +149,6 @@ add_subdirectory(registry)" >> patchfile6
 echo " add_subdirectory(sql)" >> patchfile6
 echo " add_subdirectory(remote)" >> patchfile6
 echo " " >> patchfile6
 echo "-# Add externals directory from parent" >> patchfile6
 echo "-add_subdirectory(\"\${CMAKE_SOURCE_DIR}/external\" \"\${CMAKE_BINARY_DIR}/external\")" >> patchfile6
 echo "-" >> patchfile6
 echo " if(NOT DEFINED ENV{SKIP_TABLES})" >> patchfile6
 echo "   add_subdirectory(tables)" >> patchfile6
 echo " " >> patchfile6
 echo "@@ -312,6 +309,9 @@ if(NOT \${OSQUERY_BUILD_SDK_ONLY})" >> patchfile6
 echo "   endif()" >> patchfile6
 echo " endif()" >> patchfile6
 echo " " >> patchfile6
 echo "+# Add externals directory from parent" >> patchfile6
 echo "+add_subdirectory(\"\${CMAKE_SOURCE_DIR}/external\" \"\${CMAKE_BINARY_DIR}/external\")" >> patchfile6
 echo "+" >> patchfile6
 echo " if(NOT DEFINED ENV{SKIP_TESTS})" >> patchfile6
 echo "   # osquery testing library (testing helper methods/libs)." >> patchfile6
 echo "   add_library(libosquery_testing STATIC tests/test_util.cpp)" >> patchfile6
 echo "-- " >> patchfile6
 echo "2.7.4" >> patchfile6
 patch -p1 < patchfile6

 if [ -d "external" ]; then
  echo "Osquery already prepared for extensions"
 else
  cd ${WORKING_DIR}/osquery
  echo "Patching Osquery for extensions"
  # Patch: Remove external folder from CMakeLists.txt
  echo "-- " > patchfile3
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile3
  echo "index 40a0687..0dcd6b6 100644" >> patchfile3
  echo "--- a/CMakeLists.txt" >> patchfile3
  echo "+++ b/CMakeLists.txt" >> patchfile3
  echo "@@ -485,7 +485,7 @@ add_subdirectory(\"\${CMAKE_SOURCE_DIR}/third-party/gmock-1.7.0\")" >> patchfile3
  echo " " >> patchfile3
  echo " add_subdirectory(osquery)" >> patchfile3
  echo " add_subdirectory(tools/tests)" >> patchfile3
  echo "-add_subdirectory(external)" >> patchfile3
  echo "+#add_subdirectory(external)" >> patchfile3
  echo " " >> patchfile3
  echo " # Include the kernel building targets/macros" >> patchfile3
  echo " if(NOT \${OSQUERY_BUILD_SDK_ONLY})" >> patchfile3
  echo "-- " >> patchfile3
  echo "2.7.4" >> patchfile3
  patch -p1 < patchfile3
  
  # Patch: Add external folder to osquery/CMakeLists.txt
  echo "---" > patchfile4 
  echo " osquery/CMakeLists.txt | 2 ++" >> patchfile4 
  echo " 1 file changed, 2 insertions(+)" >> patchfile4 
  echo "" >> patchfile4 
  echo "diff --git a/osquery/CMakeLists.txt b/osquery/CMakeLists.txt" >> patchfile4 
  echo "index a2e5608..19116b5 100644" >> patchfile4 
  echo "--- a/osquery/CMakeLists.txt" >> patchfile4 
  echo "+++ b/osquery/CMakeLists.txt" >> patchfile4 
  echo "@@ -375,4 +375,6 @@ if(NOT DEFINED ENV{SKIP_TESTS})" >> patchfile4 
  echo " " >> patchfile4 
  echo "   # Build the example extension module with the SDK." >> patchfile4 
  echo "   ADD_OSQUERY_MODULE(modexample examples/example_module.cpp)" >> patchfile4 
  echo "+" >> patchfile4 
  echo "+  add_subdirectory(external)" >> patchfile4 
  echo " endif()" >> patchfile4 
  echo "-- " >> patchfile4 
  echo "2.7.4" >> patchfile4
  patch -p1 < patchfile4

  # Patch: Change path in osquery/external/CMakeLists.txt
  echo "---" > patchfile5
  echo " external/CMakeLists.txt | 2 +-" >> patchfile5
  echo " 1 file changed, 1 insertion(+), 1 deletion(-)" >> patchfile5
  echo "" >> patchfile5
  echo "diff --git a/external/CMakeLists.txt b/external/CMakeLists.txt" >> patchfile5
  echo "index c1dfadc..d5761cd 100644" >> patchfile5
  echo "--- a/external/CMakeLists.txt" >> patchfile5
  echo "+++ b/external/CMakeLists.txt" >> patchfile5
  echo "@@ -23,7 +23,7 @@ endmacro()" >> patchfile5
  echo " " >> patchfile5
  echo " # Discover each directory, which contains the implementation for an extension" >> patchfile5
  echo " # or module, usually symlinked." >> patchfile5
  echo "-SUBDIRLIST(EXTERNAL_PROJECTS \"\${CMAKE_SOURCE_DIR}/external\")" >> patchfile5
  echo "+SUBDIRLIST(EXTERNAL_PROJECTS \"\${CMAKE_SOURCE_DIR}/osquery/external\")" >> patchfile5
  echo " " >> patchfile5
  echo " # Each project may:" >> patchfile5
  echo " #   1. Be named \"external_PROJECT_NAME\", all .cpp, .c, .mm files will be compiled." >> patchfile5
  echo "-- " >> patchfile5
  echo "2.7.4" >> patchfile5
  patch -p1 < patchfile5

  cd ${WORKING_DIR}
  echo "Creating \"osquery/osquery/external\""
  mkdir osquery/osquery/external
  cp osquery/external/CMakeLists.txt osquery/osquery/external/
 fi

  cd $tmp_dir
  echo
  echo
}

echo "Welcome to bro-osquery install script"

echo ""
echo "#### Component Setup ####"
echo ""
WORKING_DIR=$(pwd)
cd ${WORKING_DIR}
echo

# Download and patch individual projects
echo "--- Prepare ACTOR FRAMEWORK ---"
downloadCAF
echo "--- Prepare BROKER ---"
downloadBroker
echo "--- Prepare OSQUERY ---"
downloadOsquery


# Compile and install dependencies
echo ""
echo "#### BUILD Dependencies ####"
echo ""
sudo ls > /dev/null
unset CC
unset CXX
unset CXXFLAGS
unset CMAKE_CXX_FLAGS
cd $WORKING_DIR

echo
echo "--- Build OSQUERY ---"
echo
cd ${WORKING_DIR}/osquery
make deps 
make -j${CORES} && sudo make install
cd ${WORKING_DIR}

# Provide build invironment
export CC=/usr/local/osquery/bin/clang
export CXX=/usr/local/osquery/bin/clang++

echo
echo "--- Build ACTOR FRAMEWORK ---"
echo
cd ${WORKING_DIR}/actor-framework
#./configure --no-auto-libc++ --no-examples --no-unit-tests --build-static-only
./configure --no-auto-libc++ --no-examples --no-unit-tests
make -j${CORES} && sudo make install
cd ${WORKING_DIR}

echo
echo "--- Build BROKER---"
echo
cd ${WORKING_DIR}/broker
#./configure --disable-pybroker --enable-static-only
./configure --disable-pybroker
make -j${CORES} && sudo make install
cd ${WORKING_DIR}

# Prepare and build bro-osquery
echo
echo
echo "#### BRO-OSQUERY ###"
echo "Done so far:"
echo "   1) Build OSQUERY (dependencies, binaries and library)"
echo "   2) Build CAF (library)"
echo "   3) Build BROKER (library)"
echo ""
echo "--- Prepare BRO-OSQUERY ---"
patchOsqueryForExtensions
downloadBroOsquery

cd ${WORKING_DIR}/osquery
make bro-osquery -j${CORES} # Will build the third party extension
# Runtime Configuration
echo
echo
echo "#### CONFIGURATION ###"
echo "--- Bro-OSquery ---"
cd ${WORKING_DIR}
cd osquery/external/extension_bro_osquery
echo "Run: sudo ./osquery/build/linux/external/extension_bro_osquery/bro-osquery.ext"
echo "Configuration: /etc/osquery/osquery.config"
echo ""
echo "--- OSquery ---"
cd ${WORKING_DIR}
if [ ! -d "/etc/osquery" ]; then
  sudo mkdir -p /etc/osquery
fi
if [ ! -f "/etc/osquery/osquery.conf" ]; then
cd osquery/external/extension_bro_osquery
  sudo cp install/osquery.example.conf /etc/osquery/osquery.conf
fi
if [ ! -d "/var/osquery/" ]; then
  sudo mkdir -p /var/osquery/
fi
echo "Run: sudo osqueryi / sudo osqueryd"
echo "Configuration: /etc/osquery/osquery.conf"
echo ""
echo "#### Bye Bye ###"
