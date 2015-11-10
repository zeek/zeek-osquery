# 
 #  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 #  Institute of Space Technology
 #  All rights reserved.
 #
 #  This source code is licensed under the BSD-style license found in the
 #  LICENSE file in the root directory of this source tree. An additional grant
 #  of patent rights can be found in the PATENTS file in the same directory.
 #
 #



# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build


# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/BrokerConnectionManager.o \
	${OBJECTDIR}/BrokerQueryManager.o \
	${OBJECTDIR}/BrokerQueryPlugin.o \
	${OBJECTDIR}/StateMachine.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/utility.o



# C Compiler Flags
CFLAGS += -std=c++11 

# CC Compiler Flags
CCFLAGS=-lbroker -std=c++11
CXXFLAGS=-lbroker -std=c++11

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-L /home/robin/bro/osquery/bro/build/aux/broker -L /home/robin/bro/osquery/osquery/build/21/third-party/glog/lib -lbroker -lboost_thread -lthrift -lboost_system -lcrypto -ldl -lglog -lboost_filesystem -lthriftz -losquery -lgflags -lpthread -lrocksdb_lite -lz -lbz2 -lsnappy

# Build Targets

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/BrokerQueryManagerPlugin: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/BrokerQueryManagerPlugin.ext ${OBJECTFILES} ${LDLIBSOPTIONS} -s

${OBJECTDIR}/BrokerConnectionManager.o: BrokerConnectionManager.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -std=c++11 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/BrokerConnectionManager.o BrokerConnectionManager.cpp

${OBJECTDIR}/BrokerQueryManager.o: BrokerQueryManager.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -std=c++11 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/BrokerQueryManager.o BrokerQueryManager.cpp

${OBJECTDIR}/BrokerQueryPlugin.o: BrokerQueryPlugin.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -std=c++11 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/BrokerQueryPlugin.o BrokerQueryPlugin.cpp

${OBJECTDIR}/StateMachine.o: StateMachine.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/StateMachine.o StateMachine.cpp

${OBJECTDIR}/utility.o: utility.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -std=c++11 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/utility.o utility.cpp

${OBJECTDIR}/main.o: main.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -std=c++11 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.cpp


#install Target
install: ${OBJECTFILES}
	${MKDIR} -p /usr/lib/osquery
	${MKDIR} -p /usr/lib/osquery/extensions
	sudo cp -rf ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/BrokerQueryManagerPlugin.ext /usr/lib/osquery/extensions
	${MKDIR} -p /var/osquery
	sudo cp -rf broker.ini /var/osquery/
	${MKDIR} -p /etc/osquery
	sudo echo "/usr/lib/osquery/extensions/BrokerQueryManagerPlugin.ext" > /etc/osquery/extensions.load

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/BrokerQueryManagerPlugin.ext

# Subprojects
.clean-subprojects:

