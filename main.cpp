/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */



#include <string>
#include <iostream>
#include <osquery/events.h>
#include <osquery/sql.h>
#include <osquery/sdk.h>
#include <osquery/registry.h>
#include <sstream>
#include <csignal>
#include "BrokerConnectionManager.h"
#include "BrokerQueryManager.h"
#include "BrokerQueryPlugin.h"
#include "utility.h"
#include "StateMachine.h"



// :osquery::REGISTER_EXTERNAL to define BrokerQueryManagerPlugin 
REGISTER_EXTERNAL(BrokerQueryManagerPlugin, "config", "brokerQueryManager")



// main runner
int main(int argc, char* argv[]) {
    
  //osquery::runner start logging, threads, etc. for our extension
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);
  LOG(WARNING) <<"Initialized OSquery." ;
  //wait 1sec for osqueryd to load
  usleep(1000000);
  
    //SignalHandler object to trace kill signal
  SignalHandler *signalHandler = new SignalHandler;
  //To start the program form INIT state.
  currentState = INIT;
  try
    {
      // try setting up signal handler for kill signal
      signalHandler->setupSignalHandler();
      //StateMachine object
      StateMachine smObj(signalHandler);
      //run the state machine
      int statusCode = smObj.Run();
      
      if(statusCode == SUCCESS)
      {
        // delete SignalHandler object 
        delete signalHandler;
      }
     }
  // catches exception thrown at kill signal setup time
    catch(SignalException& e)
    {
        // delete SignalHandler object 
        delete signalHandler;
        LOG(ERROR) << "SignalException: " <<e.what();
    }
 
    
LOG(WARNING) <<"Shutting down extension";
// Finally shutdown.
runner.shutdown();
              
return 0;
}
