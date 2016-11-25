#include <osquery/sdk.h>
#include <osquery/system.h>

#include "logger/logger.h"
#include "BrokerManager.h"
#include <utils.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <iostream>
#include <unistd.h>

using namespace osquery;

REGISTER_EXTERNAL(BroLoggerPlugin, "logger", "bro");

int main(int argc, char* argv[]) {
  
  // Setup Extension
  Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status_ext = startExtension("bro-osquery", "0.0.1");
  if (!status_ext.ok()) {
    LOG(ERROR) << status_ext.getMessage();
    runner.requestShutdown(status_ext.getCode());
  }

  // Setup Broker Endpoint
  broker::init();
  BrokerManager* bm = BrokerManager::getInstance();
  std::string uid = bm->getNodeID();
  bm->createEndpoint("Bro-osquery Extension");
  broker::message_queue* mq_all = bm->createAndGetMessageQueue("/osquery/all");
  broker::message_queue* mq_uid = bm->createAndGetMessageQueue(std::string("/osquery/uid/") + uid);
  auto status_broker = bm->peerEndpoint("172.17.0.2", 9999);
  if (!status_broker.ok()) {
    LOG(ERROR) << status_broker.getMessage();
    runner.requestShutdown(status_broker.getCode());
  }
  // Annouce this endpoint to be a bro-osquery extension
  broker::message announceMsg;
  announceMsg.push_back("new_osquery_host");
  announceMsg.push_back(uid);
  bm->getEndpoint()->send("/osquery/announces", announceMsg);

  // Wait for schedule requests
  // TODO wait on "/osquery/all" in parallel
  while (true) {
    for ( auto& msg: mq_uid->need_pop() ) {
      // Check Event Type
      std::string eventName = broker::to_string(msg[0]);
      LOG(INFO) << "Received Event With Name: " << eventName;
      
      if ( eventName == "add_osquery_query" ) 
      {
        // Retrieve query
        std::string response_eventName = broker::to_string(msg[1]);
        std::string query = broker::to_string(msg[2]);
        printColumnsInfo(query);
        bm->addBrokerQueryEntry(query, response_eventName);
      }
      else if ( eventName == "remove_osquery_query" ) 
      {
        LOG(ERROR) << "NOT IMPLEMENTED";
      } else 
      {
        LOG(ERROR) << "Unknown Event Name: '" << eventName << "'";
	continue;
      }

      // Apply to new config/schedule
      std::map<std::string, std::string> config;
      config["data"] = bm->getQueryConfigString();
      LOG(INFO) << "Applying new config: " << config["data"];
      Config::getInstance().update(config);
    }
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
