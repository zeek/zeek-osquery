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
    
    /// Get a singleton instance
    static BrokerManager& getInstance() {
      static BrokerManager bm;
      return bm;
    };

    osquery::Status peerEndpoint(broker::endpoint& ep);


    osquery::Status addBrokerQueryEntry(const std::string query, int interval=10,
                               bool added=true, bool removed=true, bool snapshot=false);

    osquery::Status addBrokerQueryEntry(const std::string& queryID, const std::string query,
                               int interval, bool added, bool removed, bool snapshot);

    std::string getQueryConfigString();


    Status logQueryLogItemToBro(const QueryLogItem& qli, const std::string& topic, broker::endpoint* ep);

    Status logQueryLogItemRowToBro(const std::string& event_name, const osquery::Row& row, const std::string& trigger, const std::string& topic, broker::endpoint* ep);

  private:
    std::list<BrokerQueryEntry> brokerQueries;
};

}
