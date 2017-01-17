cmake_minimum_required(VERSION 2.8)
string(ASCII 27 ESC)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

#project(bro-osquery)
set(PROJECT_NAME bro-osquery)

find_package(Libcaf COMPONENTS core io REQUIRED)
find_package(Broker REQUIRED)

include_directories(BEFORE ${BROKER_INCLUDE_DIRS})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include)
#include_directories(BEFORE ${CMAKE_BINARY_DIR}/src)
set(LINK_LIBS ${LINK_LIBS} ${BROKER_LIBRARY} ${LIBCAF_LIBRARIES})

set(PROJECT_SOURCES
#  src/logger.cpp
  src/extension.cpp
  src/utils.cpp
  src/BrokerManager.cpp
  src/plugins.cpp
#  src/Parser.cpp
)

SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

ADD_OSQUERY_EXTENSION(${PROJECT_NAME} ${PROJECT_SOURCES})
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})
set(CPP11_FLAGS "-std=c++11 -stdlib=libstdc++")
set(CMAKE_CXX_FLAGS "${CPP11_FLAGS} ${CMAKE_CXX_FLAGS} /usr/local/osquery/Cellar/glibc/2.19/lib/libc.so -Wl,-rpath,/usr/local/lib")
include_directories(SYSTEM "${BUILD_DEPS}/legacy/include")
include_directories(SYSTEM "${BUILD_DEPS}/include")

# Bro-OSquery Configuration File
#set(BROSERY_INI_PATH "${CMAKE_INSTALL_PREFIX}/etc/brosquery/config.ini")
#configure_file(${CMAKE_SOURCE_DIR}/etc/broker.ini.in ${CMAKE_BINARY_DIR}/etc/broker.ini)
#InstallClobberImmune(${CMAKE_BINARY_DIR}/etc/broker.ini ${BROSERY_INI_PATH})


message(
    "\n==================|  Bro-Osquery Config Summary  |===================="
    "\nInstall prefix:   ${CMAKE_INSTALL_PREFIX}"
    "\nBroker prefix:    ${BROKER_ROOT_DIR}"
    "\nCAF prefix:       ${LIBCAF_ROOT_DIR}"
    "\n"
    "\nLink libraries:   ${LINK_LIBS}"
    "\nCC:               ${CMAKE_C_COMPILER}"
    "\nCFLAGS:           ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:              ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:         ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\n=================================================================")
