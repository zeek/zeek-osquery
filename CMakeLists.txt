
cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

project(bro-osquery)

# Name of extension (exluding '.ext').
set(TARGET BrokerQueryManagerPlugin)

find_package(Libcaf COMPONENTS core io REQUIRED)
find_package(Broker REQUIRED)
find_package(Osquery REQUIRED)
find_package(Glog REQUIRED)

include_directories(BEFORE ${BROKER_INCLUDE_DIRS})
include_directories(BEFORE ${OSQUERY_INCLUDE_DIRS})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(LINK_LIBS ${LINK_LIBS} ${LIBCAF_LIBRARIES} ${BROKER_LIBRARY} ${OSQUERY_LIBRARY} ${GLOG_LIBRARY})

set(CMAKE_CXX_FLAGS "-I ${BROKER_INCLUDE_DIR} -I ${OSQUERY_INCLUDE_DIR} -I ${GLOG_INCLUDE_DIR} ${CMAKE_CXX_FLAGS}")

include(RequireCXX11)

# Platform specifics.
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINK_LIBS ${LINK_LIBS} "-lpthread")

    # TODO: Better ways to handle these?
    set(LINK_LIBS ${LINK_LIBS} "-lboost_thread -lboost_system -lboost_filesystem -lthrift -lcrypto -ldl -lglog -lthriftz -lgflags -lrocksdb_lite -lz -lbz2 -lsnappy")

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
)

add_executable(${TARGET} ${SRCS})
target_link_libraries(${TARGET} ${LINK_LIBS})
set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${TARGET}.ext")

message(
    "\n==================|  broker Config Summary  |===================="
    "\nInstall prefix:  ${CMAKE_INSTALL_PREFIX}"
    "\nBroker prefix:   ${BROKER_ROOT}"
    "\nOsquery prefix:  ${OSQUERY_ROOT}"
    "\n"
    "\nLink libraries:  ${LINK_LIBS}"
    "\nCC:              ${CMAKE_C_COMPILER}"
    "\nCFLAGS:          ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:             ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:        ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\n=================================================================")

include(UserChangedWarning)
