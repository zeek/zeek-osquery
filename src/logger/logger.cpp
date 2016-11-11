#include <exception>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include "logger.h"
#include "../utils.h"
#include "../BrokerManager.h"

namespace osquery {

// Register external? - Currently results only, no error log
FLAG(string,
     bro_endpoint,
     "127.0.0.1",
     "IP Address for ERROR/WARN/INFO and results logging (Bro Endpoint)");

broker::endpoint* BroLoggerPlugin::loggerEP = nullptr;

Status BroLoggerPlugin::setUp() {

  // TODO
  // Ensure FLAGS_bro_endpoint is a valid IP/hostname

  return Status(0, "OK");
}

Status BroLoggerPlugin::logString(const std::string& s) { 
  // Log Methods for QueryLogItems only?
  QueryLogItem item;
  Status status = deserializeQueryLogItemJSON(s, item);
  if ( status.getCode() == 0 ) {
    printQueryLogItemJSON(s);
    //return  logQueryLogItemToBro(item);
  } else {
    LOG(ERROR) << "Parsing query result FAILED";
    return Status(1, "Failed to deserialize QueryLogItem");
  }
  BrokerManager bm = BrokerManager::getInstance();
  return bm.logQueryLogItemToBro(item, "/osquery/schedule/result", BroLoggerPlugin::loggerEP);
}

Status BroLoggerPlugin::logSnapshot(const std::string& s) {
  // Send the snapshot data to a separate filename.
  //return logPrintToBro(s,"/schedule/snapshot");
  return Status(1, "Not Implemented");
}

Status BroLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  // NOT IMPLEMENTED
  return Status(1, "Not implemented");
}


void BroLoggerPlugin::init(const std::string& name,
                                  const std::vector<StatusLogLine>& log) {

}
}
