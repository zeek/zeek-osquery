/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

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
  BrokerManager bm = BrokerManager::getInstance();
  broker::endpoint extensionEP("Bro-osquery Extension");
  broker::message_queue mq_schedule("/osquery/schedule/query", extensionEP);
  auto status_broker = bm.peerEndpoint(extensionEP);
  if (!status_broker.ok()) {
    LOG(ERROR) << status_broker.getMessage();
    runner.requestShutdown(status_broker.getCode());
  }
  BroLoggerPlugin::loggerEP = &extensionEP;

  // Wait for schedule requests
  while (true) {
    for ( auto& msg: mq_schedule.need_pop() ) {
      // Retrieve query
      std::string query = broker::to_string(msg);
      std::size_t pos = query.find("]") -  1;
      query = query.substr(1,pos);

      // Is add
      // Assuming query subscription only
      bm.addBrokerQueryEntry(query);

      // is remove
      // TODO: removeBrokerQueryEntry(msg)
      
      // Apply to new config/schedule
      std::map<std::string, std::string> config;
      config["data"] = bm.getQueryConfigString();
      LOG(INFO) << "Applying new config: " << config["data"];
      Config::getInstance().update(config);
    }
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
