#include <osquery/sdk.h>
#include <osquery/system.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <BrokerManager.h>
#include <iostream>
#include <list>

namespace osquery {

BrokerManager::BrokerManager() {

}

/////////////////////////////////////////////////////////
//////////// Endpoint ///////////////////////////////////
/////////////////////////////////////////////////////////

Status BrokerManager::peerEndpoint(broker::endpoint& ep) {
  LOG(INFO) << "Connecting...";
  ep.peer("172.17.0.2", 9999);
  auto cs = ep.outgoing_connection_status().need_pop().front();
  if ( cs.status != broker::outgoing_connection_status::tag::established )
  {
      LOG(ERROR) << "Failed to connect to broker endpoint";
      return Status(1, "Failed to connect");
  }
  return Status(0, "OK");
}


/////////////////////////////////////////////////////////
//////////////// Schedule/Query Handling ////////////////
/////////////////////////////////////////////////////////

Status BrokerManager::addBrokerQueryEntry(const std::string query, int interval,
                           bool added, bool removed, bool snapshot) {
  // TODO make random
  const std::string queryID = "foo";
  return addBrokerQueryEntry(queryID, query, interval, added, removed, snapshot);
}

Status BrokerManager::addBrokerQueryEntry(const std::string& queryID, const std::string query, 
                           int interval, bool added, bool removed, bool snapshot) {
  brokerQueries.emplace_back(queryID, query, interval, added, removed, snapshot);
  return Status(0, "OK");
}

std::string BrokerManager::getQueryConfigString() {
  std::string pre = "{\"schedule\": {\"bro\": {\"query\": \"";
  std::string post = ";\", \"interval\": 10} } } ";

  // Format each query
  std::vector<std::string> scheduleQ;
  for (const auto& i: brokerQueries) {
    // "<queryID>": {"query": "<query>;", "interval": <interval>, "added": <added>, ...}
//    std::string q = std::str( format("\"%1\": {\"query\": \"%2;\", \"interval\": %3, \"added\": %4, \"removed\": %5, \"snapshot\": %6}") %
//                              std::get<0>(i) % std::get<1>(i) % std::get<2>(i)
//                              std::get<3>(i) % std::get<4>(i) % std::get<5>(i) );
    std::stringstream ss;
    ss << "\"" << std::get<0>(i) <<"\": {\"query\": \"" << std::get<1>(i) << ";\", \"interval\": " << std::get<2>(i) << ", \"added\": " << std::get<3>(i) << ", \"removed\": " << std::get<4>(i) << ", \"snapshot\": " << std::get<5>(i) << "}";
    std::string q = ss.str();
//    LOG(INFO) << "BrokerQueryEntry: " << q;
    scheduleQ.push_back(q);
  }
  
  // Assemble queries
  std::stringstream ss;
  for(size_t i = 0; i < scheduleQ.size(); ++i) {
    if(i != 0)
      ss << ",";
    ss << scheduleQ[i];
  }
  std::string queries = ss.str();
  std::string config = std::string( "{\"schedule\": {" ) + queries + std::string( "} }" );
//  LOG(INFO) << "Assembled config:\n\t" << config;
  
  return config;
}

/////////////////////////////////////////////////////////
//////////////// Broker Send Methods/////////////////////
/////////////////////////////////////////////////////////


Status BrokerManager::logQueryLogItemToBro(const QueryLogItem& qli, const std::string& topic, broker::endpoint* ep) {

  // Attributes from QueryLogItem
  std::string name = qli.name; // The QueryID
  std::string identifier = qli.identifier; // The HostID
  size_t time = qli.time;
  std::string calendar_time = qli.calendar_time;
  std::map<std::string, std::string> decorations = qli.decorations;

  // Attributes derived from query
  // - Could be qli.name or the table_name
  std::string event_name = "my_event";

  // Send added
  for (const auto& row: qli.results.added) {
    this->logQueryLogItemRowToBro(event_name, row, "added", topic, ep);
  }  

  // Send removed
  // Not Implemented

  // Send snapshot
  // Not Implemented

  return Status(0, "OK");
}
  
Status BrokerManager::logQueryLogItemRowToBro(const std::string& event_name, const osquery::Row& row, const std::string& trigger, const std::string& topic, broker::endpoint* ep) {
  // Create Event Message
  broker::message msg;
  // Set Event_Name
  msg.push_back(event_name);
  // Set Params
  msg.push_back("Hallo ");
  msg.push_back("Welt!");

  // Create and Send Broker Event Message
  if ( ep == nullptr )
  {
    LOG(ERROR) << "Endpoint not set yet!";
    return Status(1, "Endpoint not set");
  } else {
    LOG(INFO) << "Sending Message: " << broker::to_string(msg);
    ep->send(topic, msg);
  }

  return Status(0, "OK");
}

}
