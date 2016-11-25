#include <osquery/sdk.h>
#include <osquery/system.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <BrokerManager.h>
#include <iostream>
#include <list>
#include <stdlib.h>     /* srand, rand */
#include <time.h>

namespace osquery {

BrokerManager* BrokerManager::_instance = nullptr;

BrokerManager::BrokerManager() {

}

void BrokerManager::printThis(std::string s) {
  LOG(ERROR) << "Hello from bm (this=" << &(*this) << "; PID=" << ::getpid() << "; this->ep=" << this->ep << "): " << s;

}

std::string BrokerManager::getNodeID() {
  if ( this->nodeID == "" ) {
    const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::stringstream ss;
    for (int i = 0; i < 64; ++i) 
      ss << alphanum[rand() % (sizeof(alphanum) - 1)];
    this->nodeID = ss.str();
  }
  return this->nodeID;
}

/////////////////////////////////////////////////////////
//////////// Endpoint ///////////////////////////////////
/////////////////////////////////////////////////////////

Status BrokerManager::createEndpoint(std::string ep_name) {
  if ( this->ep != nullptr ) 
  {
    LOG(ERROR) << "Broker Endpoint already exists";
    return Status(1, "Broker Endpoint already exists");
  }
  this->ep = new broker::endpoint(ep_name);
  return Status(0, "OK");
}

broker::endpoint* BrokerManager::getEndpoint() {
  return this->ep;
}

broker::message_queue* BrokerManager::createAndGetMessageQueue(std::string topic) {
  auto it = this->messageQueues.find(topic);
  if ( it == this->messageQueues.end() )
  {
    LOG(INFO) << "Creating message queue: " << topic;
    broker::message_queue* mq = new broker::message_queue(topic, *(this->ep));
    this->messageQueues[topic] = mq;
  }
  return this->messageQueues.at(topic);
}

Status BrokerManager::peerEndpoint(std::string ip, int port) {
  LOG(INFO) << "Connecting...";
  if ( this->ep == nullptr ) 
  {
    LOG(ERROR) << "Broker Endpoint to set";
    return Status(1, "Broker Endpoint not set");
  }

  this->ep->peer(ip, port);
  auto cs = this->ep->outgoing_connection_status().need_pop().front();
  if ( cs.status != broker::outgoing_connection_status::tag::established )
  {
    LOG(ERROR) << "Failed to connect to bro endpoint";
    return Status(1, "Failed to connect");
  }
  return Status(0, "OK");
}


/////////////////////////////////////////////////////////
//////////////// Schedule/Query Handling ////////////////
/////////////////////////////////////////////////////////

Status BrokerManager::addBrokerQueryEntry(const std::string query, const std::string eventName, 
                           int interval, bool added, bool removed, bool snapshot) {
  const std::string queryID = std::to_string(this->_nextUID++);
  return addBrokerQueryEntry(queryID, query, eventName, interval, added, removed, snapshot);
}

Status BrokerManager::addBrokerQueryEntry(const std::string& queryID, const std::string query, const std::string eventName,
                           int interval, bool added, bool removed, bool snapshot) {
  if ( this->brokerQueries.find(queryID) != this->brokerQueries.end() ) 
  {
    LOG(ERROR) << "QueryID '" << queryID << "' already exists";
    return Status(1, "Duplicate queryID");
  }

  this->eventNames[queryID] = eventName;
  this->brokerQueries[queryID] = BrokerQueryEntry{queryID, query, interval, added, removed, snapshot};
  return Status(0, "OK");
}

std::string BrokerManager::getQueryConfigString() {
  std::string pre = "{\"schedule\": {\"bro\": {\"query\": \"";
  std::string post = ";\", \"interval\": 10} } } ";

  // Format each query
  std::vector<std::string> scheduleQ;
//  for (const auto& i: brokerQueries) {
  for(auto it = this->brokerQueries.begin(); it != this->brokerQueries.end(); it++) {
    auto i = it->second;
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


Status BrokerManager::logQueryLogItemToBro(const QueryLogItem& qli) {

  std::string topic = "/osquery/uid/"+this->getNodeID();

  // Attributes from QueryLogItem
  std::string queryID = qli.name; // The QueryID
  std::string identifier = qli.identifier; // The HostID
  size_t time = qli.time;
  std::string calendar_time = qli.calendar_time;
  std::map<std::string, std::string> decorations = qli.decorations;

  // Send added
  for (const auto& row: qli.results.added) {
    this->logQueryLogItemRowToBro(queryID, row, "added", topic);
  }  

  // Send removed
  // Not Implemented

  // Send snapshot
  // Not Implemented

  return Status(0, "OK");
}
  
Status BrokerManager::logQueryLogItemRowToBro(const std::string queryID, const osquery::Row& row, const std::string& trigger, const std::string& topic) {
  // Create Event Message
  broker::message msg;
  // Set Event_Name
  std::string event_name = this->eventNames.at(queryID);
  LOG(INFO) << "Creating message for event with name :'" << event_name << "'";
  msg.push_back(event_name);

  // Get Info about SQL Query and Types
  BrokerQueryEntry bqe = this->brokerQueries.at(queryID);
  TableColumns columns;
  std::string query = std::get<1>(bqe);
  Status status = getQueryColumnsExternal(query, columns);
  std::map<std::string, ColumnType> columnTypes;
  for (std::tuple<std::string, ColumnType, ColumnOptions> t: columns) {
    columnTypes[std::get<0>(t)] = std::get<1>(t);
  }

  // Set Params
  for (const auto& col: row) {
    std::string colName = col.first;
    std::string value = col.second;
    LOG(INFO) << "Column named '" << colName << "' is of type '" << kColumnTypeNames.at(columnTypes.at(colName)) << "'";
    switch ( columnTypes.at(colName) ) {
      case ColumnType::UNKNOWN_TYPE : {
        LOG(ERROR) << "Sending unknown column type as string";
        msg.push_back( value );
        break;
      }
      case ColumnType::TEXT_TYPE : {
        msg.push_back( AS_LITERAL(TEXT_LITERAL, value) );
        break;
      }
      case ColumnType::INTEGER_TYPE : {
        msg.push_back( AS_LITERAL(INTEGER_LITERAL, value) );
        break;
      }
      case ColumnType::BIGINT_TYPE : {
        msg.push_back( AS_LITERAL(BIGINT_LITERAL, value) );
        break;
      }
      case ColumnType::UNSIGNED_BIGINT_TYPE : {
        msg.push_back( AS_LITERAL(UNSIGNED_BIGINT_LITERAL, value) );
        break;
      }
      case ColumnType::DOUBLE_TYPE : {
        msg.push_back( AS_LITERAL(DOUBLE_LITERAL, value) );
        break;
      }
      case ColumnType::BLOB_TYPE : {
        LOG(ERROR) << "Sending blob column type as string";
        msg.push_back( value );
        break;
      }
      default : {
        LOG(ERROR) << "Unkown ColumnType!";
        continue;
      }
    }
  }

  // Create and Send Broker Event Message
  if ( this->ep == nullptr )
  {
    LOG(ERROR) << "Endpoint not set yet!";
    return Status(1, "Endpoint not set");
  } else {
    LOG(INFO) << "Sending Message: " << broker::to_string(msg);
    this->ep->send(topic, msg);
  }

  return Status(0, "OK");
}

}
