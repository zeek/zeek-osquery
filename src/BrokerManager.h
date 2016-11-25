#include <osquery/sdk.h>
#include <osquery/system.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <iostream>
#include <list>

namespace osquery {

class BrokerManager {
  
  //ID, query, interval, added, removed, snapshot
  typedef std::tuple<std::string, std::string, int, bool, bool, bool> BrokerQueryEntry;

  private:
    BrokerManager();

  public: 

    // Get a singleton instance
    static BrokerManager* getInstance() {
      if (!_instance)
        _instance = new BrokerManager ();
      return _instance;
    }
 
    void printThis(std::string s);
    
    std::string getNodeID();


    osquery::Status createEndpoint(std::string ep_name);

    broker::endpoint* getEndpoint();

    broker::message_queue* createAndGetMessageQueue(std::string topic);

    osquery::Status peerEndpoint(std::string ip, int port);


    osquery::Status addBrokerQueryEntry(const std::string query, const std::string eventName,
                               int interval=10, bool added=true, bool removed=true, bool snapshot=false);

    osquery::Status addBrokerQueryEntry(const std::string& queryID, const std::string query, const std::string eventName,
                               int interval, bool added, bool removed, bool snapshot);

    std::string getQueryConfigString();


    Status logQueryLogItemToBro(const QueryLogItem& qli);

    Status logQueryLogItemRowToBro(const std::string queryID, const osquery::Row& row, const std::string& trigger, const std::string& topic);

  private:
    // The singleton object
    static BrokerManager* _instance;
    // The ID identifying the node (private channel)
    std::string nodeID = "";
    // The Broker Endpoint
    broker::endpoint* ep = nullptr; // delete afterwards

    // Next unique QueryID
    int _nextUID = 1;
    // Collection of SQL Subscription queries, Key: QueryID
    std::map<std::string, BrokerQueryEntry> brokerQueries;
    

    // Some mapping to maintain the SQL subscriptions
    //  Key: topic_Name, Value: message_queue
    std::map<std::string, broker::message_queue*> messageQueues;
    //  Key: QueryID, Value: Event Name to use for the response
    std::map<std::string, std::string> eventNames;
    //  Key: QueryID, Value: Topic to use for the response
    std::map<std::string, std::string> eventTopics;

};

}
