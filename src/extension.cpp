#include <osquery/sdk.h>
#include <osquery/flags.h>
#include <osquery/system.h>
//#include <osquery/database.h>

#include "logger/logger.h"
#include "BrokerManager.h"
//#include "Parser.h"
#include <utils.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <iostream>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

//#include <libconfig.h++>

using namespace osquery;

// Define config flags
namespace osquery {
    EXTENSION_FLAG(string,
            bro_endpoint,
            "172.17.0.2",
            "IP Address for ERROR/WARN/INFO and results logging (Bro Endpoint)");
}

REGISTER_EXTERNAL(BroLoggerPlugin, "logger", "bro");

void signalHandler( int signum ) {
  LOG(INFO) << "Interrupt signal (" << signum << ") received";

  // TODO Announce this node goes offline  

  exit(signum);
}


int main(int argc, char* argv[]) {

  signal(SIGINT, signalHandler);

    /*
    // Init Config
    Parser* parser = Parser::getInstance();
    parser->parseConfig("/usr/local/etc/brosquery/config.ini");
    std::string welt = parser->getConfig()->lookup("hallo");
    LOG(ERROR) << "welt = " << welt;
    */
  
  // Setup OSquery Extension
  Initializer runner(argc, argv, ToolType::EXTENSION);
  auto status_ext = startExtension("bro-osquery", "0.0.1");
  if (!status_ext.ok()) {
    LOG(ERROR) << status_ext.getMessage();
    runner.requestShutdown(status_ext.getCode());
  }

  // Setup Broker Endpoint
  broker::init();
  BrokerManager* bm = BrokerManager::getInstance();
  bm->createEndpoint("Bro-osquery Extension");
  // Retrieve uid and groups
  std::string uid = bm->getNodeID();
  auto groups = bm->getGroups();
  // Listen on default topics (global, groups and node)
  bm->createMessageQueue("/bro/osquery/all");
  bm->createMessageQueue("/bro/osquery/uid/" + uid);
  for (std::string g: groups) {
    bm->createMessageQueue("/bro/osquery/group/" + g);
  }
  // Connect to Bro
  LOG(INFO) << "Connecting to " << FLAGS_bro_endpoint;
  auto status_broker = bm->peerEndpoint(FLAGS_bro_endpoint, 9999);
  if (!status_broker.ok()) {
    LOG(ERROR) << status_broker.getMessage();
    runner.requestShutdown(status_broker.getCode());
  }

  // Announce this endpoint to be a bro-osquery extension
  broker::vector group_list;
  for (std::string g: groups) {
    group_list.push_back( g );
  }
  QueryData addr_results;
  auto status_if = osquery::queryExternal("SELECT address from interface_addresses", addr_results);
  if (!status_if.ok()) {
    LOG(ERROR) << status_if.getMessage();
    runner.requestShutdown(status_if.getCode());
  }
  broker::vector addr_list;
  for (auto row: addr_results) {
    std::string ip = row.at("address");
    addr_list.push_back( broker::address::from_string(ip).get() );
  }
  broker::message announceMsg = broker::message{"host_new", uid, group_list, addr_list};
  bm->getEndpoint()->send("/bro/osquery/announces", announceMsg);

  // Wait for schedule requests
  fd_set fds;
  std::vector<std::string> topics;
  int sock;
  broker::message_queue* queue = nullptr;
  int sMax;
  while (true) {
    // Retrieve info about each message queue
    FD_ZERO(&fds);
    bm->getTopics(topics); // List of subscribed topics
    sMax = 0;
    for (auto topic: topics) {
      sock = bm->getMessageQueue(topic)->fd();
      if (sock > sMax) {sMax = sock;}
      FD_SET(sock, &fds); // each topic -> message_queue -> fd
    }
    // Wait for incoming message
    if ( select(sMax + 1, &fds, NULL, NULL, NULL) < 0) {
      LOG(ERROR) << "Select returned an error code";
      continue;
    }
    
    // Check for the socket where a message arrived on
    for (auto topic: topics) {
      queue = bm->getMessageQueue(topic);
      sock = queue->fd();
      if ( FD_ISSET(sock, &fds) ) {
    
        // Process each message on this socket
        for ( auto& msg: queue->want_pop() ) {
          // Check Event Type
          std::string eventName = broker::to_string(msg[0]);
          LOG(INFO) << "Received event '" << eventName << "' on topic '" << topic << "'";

          if ( eventName == "osquery::host_query" ) {
          // One-Time Query Execution
              // TODO: How should responses to a query look like that has no results?
              //    a) Only sending results as they are available (we might can do this asynchronously via logger)
              //    b) Sending empty results if no result available (we have to actively check/wait for request exec)
              //a)
              SubscriptionRequest sr;
              createSubscriptionRequest(msg, topic, sr);
              std::string newQID = bm->addBrokerOneTimeQueryEntry(sr);
              if (newQID=="-1") {
                  LOG(ERROR) << "Unable to add Broker Query Entry";
                  runner.requestShutdown(1);
              }

              // Execute the query
              LOG(INFO) << "Executing one-time query: " << sr.response_event << ": " << sr.query;
              QueryData results;
              auto status_query = osquery::queryExternal(sr.query, results);
              if (!status_query.ok()) {
                  LOG(ERROR) << status_query.getMessage();
                  runner.requestShutdown(status_query.getCode());
              }

              if (results.empty()) {
                  LOG(INFO) << "One-time query: " << sr.response_event << " has no results";
                  bm->removeBrokerQueryEntry(sr.query);
                  continue;
              }
              /*
              std::string response_event = broker::to_string(msg[1]);
              std::string query = broker::to_string(msg[2]);


              // Execute the query
              LOG(INFO) << "Executing one-time query: " << response_event << ": " << query;
              QueryData results;
              auto status_query = osquery::queryExternal(query, results);
              if (!status_query.ok()) {
                  LOG(ERROR) << status_query.getMessage();
                  runner.requestShutdown(status_query.getCode());
              }
               */

              // Assemble a response item (as snapshot)
              QueryLogItem item;
              item.name = newQID;
              item.identifier = osquery::getHostIdentifier();
              item.time = osquery::getUnixTime();
              item.calendar_time = osquery::getAsciiTime();
              item.snapshot_results = results;

              //printQueryLogItem(item);

              // Send snapshot to the logger
              std::string registry_name = "logger";
              std::string item_name = "bro";
              std::string json;
              serializeQueryLogItemJSON(item, json);
              printQueryLogItemJSON(json);
              PluginRequest request = {{"snapshot", json}, {"category", "event"}};
              auto status_call = osquery::Registry::call(registry_name, item_name, request);
              if (!status_call.ok()) {
                  std::string error = "Error logging the results of one-time query: " + sr.query + ": " +
                          status_call.toString();
                  LOG(ERROR) << error;
                  Initializer::requestShutdown(EXIT_CATASTROPHIC, error);
              }

              continue;

          } else if ( eventName == "osquery::host_subscribe" ) {
          // New SQL Query Request
            SubscriptionRequest sr;
            createSubscriptionRequest(msg, topic, sr);

            bm->addBrokerScheduleQueryEntry(sr);

          } else if ( eventName == "osquery::host_unsubscribe" ) {
          // SQL Query Cancel
            SubscriptionRequest sr;
            createSubscriptionRequest(msg, topic, sr);
            //TODO: find an UNIQUE identifier (currently the exact sql string)
            std::string query = sr.query;

            bm->removeBrokerQueryEntry(query);

          } else {
          // Unkown Message
            //LOG(ERROR) << "Unknown Event Name: '" << eventName << "'";
            //LOG(ERROR) << "\t" << broker::to_string(msg);
            continue;
          }

          // Apply to new config/schedule
          std::map<std::string, std::string> config;
          config["data"] = bm->getQueryConfigString();
          LOG(INFO) << "Applying new config: " << config["data"];
          osquery::Config::getInstance().update(config);
        }
      }
    }
  }

  LOG(ERROR) << "What happened here?";
  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
