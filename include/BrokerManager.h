#pragma once

#include <osquery/sdk.h>
#include <osquery/system.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <iostream>
#include <list>

namespace osquery {

  //ID, query, interval, added, removed, snapshot
  typedef std::tuple<std::string, std::string, int, bool, bool, bool> BrokerScheduleQueryEntry;
  typedef std::tuple<std::string, std::string> BrokerOneTimeQueryEntry;

    struct SubscriptionRequest {
        std::string query; // The requested SQL query
        std::string response_event; // The event name for the response event
        std::string response_topic; // The topic name for the response event
        uint64_t interval = 10;
        bool added = true;
        bool removed = false;
        bool snapshot = false;
    };

class BrokerManager {
  
  private:
    BrokerManager();

  public: 

    // Get a singleton instance
    static BrokerManager* getInstance() {
      if (!_instance)
        _instance = new BrokerManager ();
      return _instance;
    }

    // Topic Prefix
    const std::string TOPIC_PREFIX = "/bro/osquery/";
    const std::string TOPIC_ALL = this->TOPIC_PREFIX + "all";
    const std::string TOPIC_ANNOUNCE = this->TOPIC_PREFIX + "announce";
    const std::string TOPIC_PRE_INDIVIDUALS = this->TOPIC_PREFIX + "uid/";
    const std::string TOPIC_PRE_GROUPS = this->TOPIC_PREFIX + "group/";
    const std::string TOPIC_PRE_CUSTOMS = this->TOPIC_PREFIX + "custom/";

    // Event messages
    const std::string EVENT_HOST_NEW = "osquery::host_new";
    const std::string EVENT_HOST_QUERY =  "osquery::host_query";
    const std::string EVENT_HOST_SUBSCRIBE =  "osquery::host_subscribe";
    const std::string EVENT_HOST_UNSUBSCRIBE =  "osquery::host_unsubscribe";

    osquery::Status setNodeID(const std::string& uid);
    
    std::string getNodeID();

    osquery::Status addGroup(const std::string& group);
    
    std::vector<std::string> getGroups();


    osquery::Status createEndpoint(std::string ep_name);

    broker::endpoint* getEndpoint();

    osquery::Status createMessageQueue(std::string topic);

    broker::message_queue* getMessageQueue(std::string topic);
 
    osquery::Status getTopics(std::vector<std::string>& topics);

    osquery::Status peerEndpoint(std::string ip, int port);

    std::string addBrokerOneTimeQueryEntry(const SubscriptionRequest& qr);

    osquery::Status addBrokerScheduleQueryEntry(const SubscriptionRequest& qr);

    osquery::Status addBrokerQueryEntry(const std::string& queryID, const SubscriptionRequest& qr, std::string qtype);

    std::string findIDForQuery(const std::string& query);

    osquery::Status removeBrokerQueryEntry(const std::string& query);

    std::string getQueryConfigString();


    Status logQueryLogItemToBro(const QueryLogItem& qli);

    Status sendEvent(const std::string& topic, const broker::message& msg);

  private:
    // The singleton object
    static BrokerManager* _instance;

    // The ID identifying the node (private channel)
    std::string nodeID = "";
    // The groups of the node
    std::vector<std::string> groups;
    // The Broker Endpoint
    broker::endpoint* ep = nullptr; // delete afterwards

    // Next unique QueryID
    int _nextUID = 1;
    // Collection of SQL Subscription queries, Key: QueryID
    std::map<std::string, BrokerScheduleQueryEntry> brokerScheduleQueries;
    // Collection of SQL One-Time Subscription queries, Key: QueryID
    std::map<std::string, BrokerOneTimeQueryEntry> brokerOneTimeQueries;
    

    // Some mapping to maintain the SQL subscriptions
    //  Key: topic_Name, Value: message_queue
    std::map<std::string, broker::message_queue*> messageQueues;
    //  Key: QueryID, Value: Event Name to use for the response
    std::map<std::string, std::string> eventNames;
    //  Key: QueryID, Value: Topic to use for the response
    std::map<std::string, std::string> eventTopics;

};

}
