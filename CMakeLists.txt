cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

project(bro-osquery)

# Name of extension.
set(TARGET bro-osquery)

# If no explicit compiler override and clang++ exists, prefer clang.
#find_file(CLANGXX_EXISTS "clang++")
#if(DEFINED ENV{CC})
	#set(CMAKE_C_COMPILER "$ENV{CC}")
	#LOG("Overriding C compiler from clang to $ENV{CC}")
#elseif(CLANGXX_EXISTS)
	#set(CMAKE_C_COMPILER "clang")
#endif()
#if(DEFINED ENV{CXX})
	#set(CMAKE_CXX_COMPILER "$ENV{CXX}")
	#LOG("Overriding CXX compiler from clang++ to $ENV{CXX}")
#elseif(CLANGXX_EXISTS)
	#set(CMAKE_CXX_COMPILER "clang++")
#endif()

find_package(Libcaf COMPONENTS core io REQUIRED)
find_package(Broker REQUIRED)
find_package(Osquery REQUIRED)
find_package(Glog REQUIRED)

include_directories(BEFORE ${BROKER_INCLUDE_DIRS})
include_directories(BEFORE ${OSQUERY_INCLUDE_DIRS})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(BEFORE ${CMAKE_BINARY_DIR}/src)

set(LINK_LIBS ${LINK_LIBS} ${BROKER_LIBRARY} ${LIBCAF_LIBRARIES} ${OSQUERY_LIBRARY} ${GLOG_LIBRARY})

set(CMAKE_CXX_FLAGS "-I ${BROKER_INCLUDE_DIR} -I ${OSQUERY_INCLUDE_DIR} -I ${GLOG_INCLUDE_DIR} ${CMAKE_CXX_FLAGS}")

include(RequireCXX11)
include(InstallClobberImmune)

# Platform specifics.
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set(LINK_LIBS ${LINK_LIBS} "-L /usr/local/lib")
	set(LINK_LIBS ${LINK_LIBS} "-lbroker -lcrypto -lssl -lreadline -lncurses -lpthread -lbz2 -lz -lsnappy -ldl -lrt -lthrift -lgflags -lglog -lboost_system -lboost_filesystem -lboost_regex -lyara")

elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    message(FATAL_ERROR "FreeBSD not yet tried.")

elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    message(FATAL_ERROR "Darwin not yet tried.")

else ()
    message(FATAL_ERROR "Platform ${CMAKE_SYSTEM_NAME} not supported.")
endif ()

set(SRCS
    src/BrokerConnectionManager.cpp
    src/BrokerQueryManager.cpp
    src/BrokerQueryPlugin.cpp
    src/main.cpp
    src/StateMachine.cpp
    src/utility.cpp
		aux/sql_parser/sqlselect.cpp
		aux/sql_parser/lexer.cpp
)

set(BROKER_INI_PATH "${CMAKE_INSTALL_PREFIX}/etc/broker.ini")

configure_file(${CMAKE_SOURCE_DIR}/src/config.h.in ${CMAKE_BINARY_DIR}/src/config.h)
configure_file(${CMAKE_SOURCE_DIR}/etc/broker.ini.in ${CMAKE_BINARY_DIR}/etc/broker.ini)
configure_file(${CMAKE_SOURCE_DIR}/etc/bro-osquery.service.in ${CMAKE_BINARY_DIR}/etc/bro-osquery.service)

SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

add_executable(${TARGET} ${SRCS})
target_link_libraries(${TARGET} ${LINK_LIBS})

install(FILES ${CMAKE_BINARY_DIR}/etc/broker.ini DESTINATION etc RENAME broker.ini.sample)
install(TARGETS ${TARGET} RUNTIME DESTINATION bin)

InstallClobberImmune(${CMAKE_BINARY_DIR}/etc/broker.ini ${BROKER_INI_PATH})

message(
    "\n==================|  Bro-Osquery Config Summary  |===================="
    "\nInstall prefix:   ${CMAKE_INSTALL_PREFIX}"
    "\nBro prefix:       ${BRO_ROOT_DIR}"
    "\nBro site scripts: ${BRO_SITE_DIR}"
    "\nBroker prefix:    ${BROKER_ROOT_DIR}"
    "\nCAF prefix:       ${LIBCAF_ROOT_DIR}"
    "\nOsquery prefix:   ${OSQUERY_ROOT_DIR}"
    "\n"
    "\nLink libraries:   ${LINK_LIBS}"
    "\nCC:               ${CMAKE_C_COMPILER}"
    "\nCFLAGS:           ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:              ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:         ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\n=================================================================")

include(UserChangedWarning)
