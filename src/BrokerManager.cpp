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
  //TODO: read from config or default

  // Generate Random ID
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

std::vector<std::string> BrokerManager::getGroups() {
  //TODO: read dynamic list
  return std::vector<std::string>{"eu/de/HH/UHH"};
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

Status BrokerManager::createMessageQueue(std::string topic) {
  if ( this->messageQueues.find(topic) == this->messageQueues.end() )
  {
    LOG(INFO) << "Creating message queue: " << topic;
    broker::message_queue* mq = new broker::message_queue(topic, *(this->ep));
    this->messageQueues[topic] = mq;
    return Status(0,"OK");
  }
  return Status(1,"Message queue exists for topic");
}

broker::message_queue* BrokerManager::getMessageQueue(std::string topic) {
  return this->messageQueues.at(topic);
}

Status BrokerManager::getTopics(std::vector<std::string>& topics) {
  topics.clear();
  //for (auto it = this->messageQueues.begin(); it != this->messageQueues.end(); it++) {
  for (const auto& mq: this->messageQueues) {
    topics.push_back(mq.first); // append topic
  }
  return Status(0, "OK");
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

Status BrokerManager::addBrokerQueryEntry(const QueryRequest& qr) {
  const std::string queryID = std::to_string(this->_nextUID++);
  return addBrokerQueryEntry(queryID, qr);
}

Status BrokerManager::addBrokerQueryEntry(const std::string& queryID, const QueryRequest& qr) {
  std::string query = qr.query;
  std::string response_event = qr.response_event;
  std::string response_topic = qr.response_topic;
  int interval = qr.interval;
  bool added = qr.added;
  bool removed = qr.removed;
  bool snapshot = qr.snapshot;
  if ( this->brokerQueries.find(queryID) != this->brokerQueries.end() ) 
  {
    LOG(ERROR) << "QueryID '" << queryID << "' already exists";
    return Status(1, "Duplicate queryID");
  }

  this->brokerQueries[queryID] = BrokerQueryEntry{queryID, query, interval, added, removed, snapshot};
  this->eventNames[queryID] = response_event;
  this->eventTopics[queryID] = response_topic;
  return Status(0, "OK");
}

std::string BrokerManager::findIDForQuery(const std::string& query) {
  // Search the queryID for this specific query
  for (const auto& e: this->brokerQueries) {
    std::string queryID = e.first;
    BrokerQueryEntry bqe = e.second;
    if ( std::get<1>(bqe) == query ) {
      return queryID;
    }
  }
  return "";
}

Status BrokerManager::removeBrokerQueryEntry(const std::string& query) {
  std::string queryID = this->findIDForQuery(query);
  if (queryID == "") {
    LOG(ERROR) << "Unable to find ID for query: '" << query << "'";
    return Status(1, "Unable to find ID for query");
  }

  // Delete query info
  LOG(INFO) << "Deleting query '" << query << "' with queryID '" << queryID << "'";
  this->eventTopics.erase(queryID);
  this->eventNames.erase(queryID);
  this->brokerQueries.erase(queryID);

  return Status(0,"OK");
}

std::string BrokerManager::getQueryConfigString() {
  std::string pre = "{\"schedule\": {\"bro\": {\"query\": \"";
  std::string post = ";\", \"interval\": 10} } } ";

  // Format each query
  std::vector<std::string> scheduleQ;
  for(const auto& bq: brokerQueries) {
    auto i = bq.second;
    std::stringstream ss;
    ss << "\"" << std::get<0>(i) <<"\": {\"query\": \"" << std::get<1>(i) << ";\", \"interval\": " << std::get<2>(i) << ", \"added\": " << std::get<3>(i) << ", \"removed\": " << std::get<4>(i) << ", \"snapshot\": " << std::get<5>(i) << "}";
    std::string q = ss.str();
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
  
  return config;
}

/////////////////////////////////////////////////////////
//////////////// Broker Send Methods/////////////////////
/////////////////////////////////////////////////////////


Status BrokerManager::logQueryLogItemToBro(const QueryLogItem& qli) {


  // Attributes from QueryLogItem
  std::string queryID = qli.name; // The QueryID
  std::string identifier = qli.identifier; // The HostID
  size_t time = qli.time;
  std::string calendar_time = qli.calendar_time;
  std::map<std::string, std::string> decorations = qli.decorations;

  // Send added
  for (const auto& row: qli.results.added) {
    this->logQueryLogItemRowToBro(queryID, identifier, row, "added");
  }  

  // Send removed
  // TODO: Not Implemented

  // Send snapshot
    for (const auto& row: qli.snapshot_results) {
        this->logQueryLogItemRowToBro(queryID, identifier, row, "snapshot");
    }
    // TODO: Not Implemented

  return Status(0, "OK");
}
  
Status BrokerManager::logQueryLogItemRowToBro(const std::string queryID, const std::string identifier, const osquery::Row& row, const std::string& trigger) {
  // Create Event Message
  broker::message msg;

  // Set Event_Name
  std::string event_name;
  if (trigger == "snapshot")
    event_name = identifier;
  else if (trigger == "added")
    event_name = this->eventNames.at(queryID);

  LOG(INFO) << "Creating message for event with name :'" << event_name << "'";
  msg.push_back(event_name);

  std::string query;
  // Get Info about SQL Query and Types
  if (trigger == "snapshot")
    query = queryID;
  else if (trigger == "added") {
    BrokerQueryEntry bqe = this->brokerQueries.at(queryID);
    query = std::get<1>(bqe);
  }
  TableColumns columns;
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
  std::string topic;
  if (trigger == "snapshot") {
      // TODO: Make dynamic (set when receiving the request)
    std::string uid = this->getNodeID();
    topic = "/osquery/uid/" + uid;
  } else if (trigger == "added")
    topic = this->eventTopics.at(queryID);

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
