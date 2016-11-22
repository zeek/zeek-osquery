#!/bin/bash
##
## For ubuntu 16.04
##
## Clean installed stuff (in /usr/local/) with: 
##  sudo rm -rf /usr/local/lib/libcaf_* /usr/local/include/caf/ /usr/local/lib/libbroker.so* /usr/local/include/broker/ /usr/local/lib/libosquery.a /usr/local/include/osquery/
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
  echo " CMakeLists.txt | 10 +++++++++-" >> patchfile
  echo " 1 file changed, 9 insertions(+), 1 deletion(-)" >> patchfile
  echo "" >> patchfile
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile
  echo "index 9a20c5e..11d4b21 100644" >> patchfile
  echo "--- a/CMakeLists.txt" >> patchfile
  echo "+++ b/CMakeLists.txt" >> patchfile
  echo "@@ -222,11 +222,19 @@ if(CMAKE_CXX_FLAGS)" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELEASE        \"\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELWITHDEBINFO \"\")" >> patchfile
  echo " else()" >> patchfile
  echo "-  set(CMAKE_CXX_FLAGS \"-std=c++11 -Wextra -Wall -pedantic \${EXTRA_FLAGS}\")" >> patchfile
  echo "+  set(BUILD_DEPS \"/usr/local/osquery\")" >> patchfile
  echo "+  set(CPP11_FLAGS \"-std=c++11 -stdlib=libstdc++\")" >> patchfile
  echo "+  set(STATIC_FLAGS \"-static-libstdc++\")" >> patchfile
  echo "+  set(STATIC_SYSTEM_LIBS \"-l:\${BUILD_DEPS}/legacy/lib/libpthread.so\" \"-l:\${BUILD_DEPS}/lib/libz.so\" \"-l:\${BUILD_DEPS}/legacy/lib/libdl.so\" \"-l:\${BUILD_DEPS}/legacy/lib/librt.so\" \"-l:\${BUILD_DEPS}/legacy/lib/libc.so\" \"-rdynamic\" \"-l:\${BUILD_DEPS}/lib/libgcc_s.so\")" >> patchfile
  echo "+  set(CMAKE_CXX_FLAGS \"\${CPP11_FLAGS} -Wextra -Wall -pedantic \${EXTRA_FLAGS}\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_DEBUG          \"-O0 -g\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_MINSIZEREL     \"-Os\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELEASE        \"-O3 -DNDEBUG\")" >> patchfile
  echo "   set(CMAKE_CXX_FLAGS_RELWITHDEBINFO \"-O2 -g\")" >> patchfile
  echo "+  include_directories(SYSTEM \"\${BUILD_DEPS}/legacy/include\")" >> patchfile
  echo "+  include_directories(SYSTEM \"\${BUILD_DEPS}/include\")" >> patchfile
  echo "+ set(CMAKE_CXX_STANDARD_LIBRARIES \${STATIC_SYSTEM_LIBS})" >> patchfile
  echo "+ set(CMAKE_CXX_STANDARD_LIBRARIES \${STATIC_FLAGS})" >> patchfile
  echo " endif()" >> patchfile
  echo " # set build default build type to RelWithDebInfo if not set" >> patchfile
  echo " if(NOT CMAKE_BUILD_TYPE)" >> patchfile
  echo "-- " >> patchfile
  echo "1.9.1" >> patchfile
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
  # Patch
  echo "---" > patchfile
  echo " CMakeLists.txt | 12 ++++++++++++" >> patchfile
  echo " 1 file changed, 12 insertions(+)" >> patchfile
  echo "" >> patchfile
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile
  echo "index e439cde..f1e0be3 100644" >> patchfile
  echo "--- a/CMakeLists.txt" >> patchfile
  echo "+++ b/CMakeLists.txt" >> patchfile
  echo "@@ -165,6 +165,18 @@ add_subdirectory(tests)" >> patchfile
  echo " " >> patchfile
  echo " string(TOUPPER \${CMAKE_BUILD_TYPE} BuildType)" >> patchfile
  echo " " >> patchfile
  echo "+  set(BUILD_DEPS \"/usr/local/osquery\")" >> patchfile
  echo "+  set(CPP11_FLAGS \"-std=c++11 -stdlib=libstdc++\")" >> patchfile
  echo "+  set(STATIC_FLAGS \"-static-libstdc++\")" >> patchfile
  echo "+  set(STATIC_SYSTEM_LIBS \"-l:\${BUILD_DEPS}/legacy/lib/libpthread.so\" \"-l:\${BUILD_DEPS}/lib/libz.so\" \"-l:\${BUILD_DEPS}/legacy/lib/libdl.so\" \"-l:\${BUILD_DEPS}/legacy/lib/librt.so\" \"-l:\${BUILD_DEPS}/legacy/lib/libc.so\" \"-rdynamic\" \"-l:\${BUILD_DEPS}/lib/libgcc_s.so\")" >> patchfile
  echo "+set(CMAKE_CXX_FLAGS \"\${CPP11_FLAGS} -ftemplate-depth=512 \${CMAKE_CXX_FLAGS}\")" >> patchfile
  echo "+include_directories(SYSTEM \"\${BUILD_DEPS}/legacy/include\")" >> patchfile
  echo "+include_directories(SYSTEM \"\${BUILD_DEPS}/include\")" >> patchfile
  echo "+link_directories(\"/usr/local/osquery/lib\")" >> patchfile
  echo "+set(CMAKE_CXX_STANDARD_LIBRARIES \${STATIC_SYSTEM_LIBS})" >> patchfile
  echo "+set(CMAKE_CXX_STANDARD_LIBRARIES \${STATIC_FLAGS})" >> patchfile
  echo "+" >> patchfile
  echo "+" >> patchfile
  echo " #------------------------------------------------------------------------------" >> patchfile
  echo " #                                Build Summary" >> patchfile
  echo " #------------------------------------------------------------------------------" >> patchfile
  echo "-- " >> patchfile
  echo "1.9.1" >> patchfile
  patch -p1 < patchfile
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
  
  echo "Patching Osquery"
  # Patch: stdlib=libstdc++
  echo "---" > patchfile
  echo " CMakeLists.txt | 2 +-" >> patchfile
  echo " 1 file changed, 1 insertion(+), 1 deletion(-)" >> patchfile
  echo "" >> patchfile
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile
  echo "index 40a0687..7506ae7 100644" >> patchfile
  echo "--- a/CMakeLists.txt" >> patchfile
  echo "+++ b/CMakeLists.txt" >> patchfile
  echo "@@ -130,7 +130,7 @@ elseif(WIN32)" >> patchfile
  echo "   set(OS_WHOLELINK_POST \"\")" >> patchfile
  echo "   set(WINDOWS TRUE)" >> patchfile
  echo " else()" >> patchfile
  echo "-  set(CXX_COMPILE_FLAGS \"\${CXX_COMPILE_FLAGS} -std=c++11\")" >> patchfile
  echo "+  set(CXX_COMPILE_FLAGS \"\${CXX_COMPILE_FLAGS} -std=c++11 -stdlib=libstdc++\")" >> patchfile
  echo "   set(OS_WHOLELINK_PRE \"-Wl,-whole-archive\")" >> patchfile
  echo "   set(OS_WHOLELINK_POST \"-Wl,-no-whole-archive\")" >> patchfile
  echo "   # Set CMAKE variables depending on platform, to know which tables and what" >> patchfile
  echo "-- " >> patchfile
  echo "2.7.4" >> patchfile
  patch -p1 < patchfile
  # Patch: Make PYTHON_EXECUTABLE point to /usr/local/osquery/bin/python
  echo "---" > patchfile2
  echo " CMakeLists.txt | 5 +++--" >> patchfile2
  echo " 1 file changed, 3 insertions(+), 2 deletions(-)" >> patchfile2
  echo "" >> patchfile2
  echo "diff --git a/CMakeLists.txt b/CMakeLists.txt" >> patchfile2
  echo "index 40a0687..38a61a2 100644" >> patchfile2
  echo "--- a/CMakeLists.txt" >> patchfile2
  echo "+++ b/CMakeLists.txt" >> patchfile2
  echo "@@ -78,8 +78,8 @@ endif()" >> patchfile2
  echo " set(C_COMPILE_FLAGS \"\")" >> patchfile2
  echo " set(CXX_COMPILE_FLAGS \"\")" >> patchfile2
  echo " " >> patchfile2
  echo "-find_program(PYTHON_EXECUTABLE \"python\" ENV PATH)" >> patchfile2
  echo "-find_program(THRIFT_COMPILER \"thrift\" ENV PATH)" >> patchfile2
  echo "+find_program(PYTHON_EXECUTABLE \"python\" \${BUILD_DEPS} ENV PATH)" >> patchfile2
  echo "+find_program(THRIFT_COMPILER \"thrift\" \${BUILD_DEPS} ENV PATH)" >> patchfile2
  echo " " >> patchfile2
  echo " # Use osquery language to set platform/os" >> patchfile2
  echo " if(DEFINED ENV{OSQUERY_PLATFORM})" >> patchfile2
  echo "-- " >> patchfile2
  echo "1.9.1" >> patchfile2
  patch -p1 < patchfile2
 fi

  cd $tmp_dir
  echo
  echo  
}

function downloadBroOsquery() {
 tmp_dir=$(pwd)
 cd ${WORKING_DIR}/osquery/osquery/external
 if [ -d "extension_bro_osquery" ]; then
  echo "Bro-Osquery already installed"
 else
  echo "Downloading Bro-Osquery"
  git clone https://github.com/bro/bro-osquery extension_bro_osquery
  cd extension_bro_osquery
  git checkout dev/haas
 fi

  cd $tmp_dir
}

function patchOsqueryForExtensions() {
 tmp_dir=$(pwd)
 cd ${WORKING_DIR}/osquery/osquery
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
  echo "@@ -477,7 +477,7 @@ add_subdirectory(\"\${CMAKE_SOURCE_DIR}/third-party/gmock-1.7.0\")" >> patchfile3
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
  echo "@@ -374,4 +374,6 @@ if(NOT DEFINED ENV{SKIP_TESTS})" >> patchfile4 
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
make deps && make -j${CORES} && sudo make install
cd ${WORKING_DIR}

# Provide build invironment
export CC=/usr/local/osquery/bin/clang
export CXX=/usr/local/osquery/bin/clang++

echo
echo "--- Build ACTOR FRAMEWORK ---"
echo
cd ${WORKING_DIR}/actor-framework
./configure --no-auto-libc++
make -j${CORES} && sudo make install
cd ${WORKING_DIR}

echo
echo "--- Build BROKER---"
echo
cd ${WORKING_DIR}/broker
./configure
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
cd ${WORKING_DIR}
echo "--- Bro-OSquery ---"
cd osquery/osquery/external/extension_bro_osquery
sudo mkdir /var/osquery
sudo cp etc/broker.ini.in /var/osquery/broker.ini
echo "Run: sudo ./osquery/build/linux/osquery/external/extension_bro_osquery/bro-osquery.ext"
echo "Configuration: /var/osquery/broker.ini"
cd ${WORKING_DIR}
echo ""
echo "--- OSquery ---"
cd osquery
sudo mkdir /etc/osquery
sudo mkdir -p /var/log/osquery
sudo cp tools/deployment/osquery.example.conf /etc/osquery/osquery.conf
echo "Run: sudo osqueryi / sudo osqueryd"
echo "Configuration: /etc/osquery/osquery.conf"
echo ""
echo "#### Bye Bye ###"
