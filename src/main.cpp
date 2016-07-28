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

#include "StateMachine.h"


offlineSqliteDB* ptDb;
std::string cBData;
// :osquery::REGISTER_EXTERNAL to define BrokerQueryManagerPlugin 
//REGISTER_EXTERNAL(BrokerQueryManagerPlugin, "config", "brokerQueryManager")


// main runner
int main(int argc, char* argv[]) {
    
  //create offlineSqliteDB object
  ptDb = new offlineSqliteDB;
   
  //wait 5sec for osqueryd to load
  usleep(5000000);
  //osquery::runner start logging, threads, etc. for our extension
  //osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);
  LOG(WARNING) <<"Initialized OSquery." ;
  
 
    //SignalHandler object to trace kill signal
  SignalHandler *signalHandler = new SignalHandler;
  
  try
    {
      // try setting up signal handler for kill signal
      signalHandler->setupSignalHandler();
      //StateMachine object
      StateMachine stateMachineObj(signalHandler);
      
      //run the state machine
      int statusCode = stateMachineObj.Run();

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
//runner.shutdown();*/
              
return 0;
}
