#include <exception>

#include <osquery/filesystem.h>
//#include <osquery/flags.h>
#include <osquery/logger.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include "logger.h"
#include "../utils.h"
#include "../BrokerManager.h"

namespace osquery {

Status BroLoggerPlugin::setUp() {

  // TODO: Ensure FLAGS_bro_endpoint is a valid IP/hostname
  return Status(0, "OK");
}

Status BroLoggerPlugin::logString(const std::string& s) {
    //LOG(ERROR) << "logString = " << s;
  // Log Methods for QueryLogItems only?
  QueryLogItem item;
  Status status = deserializeQueryLogItemJSON(s, item);
  if ( status.getCode() == 0 ) {
    //printQueryLogItemJSON(s);
  } else {
    LOG(ERROR) << "Parsing query result FAILED";
    return Status(1, "Failed to deserialize QueryLogItem");
  }
  return BrokerManager::getInstance()->logQueryLogItemToBro(item);
}

Status BroLoggerPlugin::logSnapshot(const std::string& s) {
    //LOG(ERROR) << "logSnapshot = " << s;
  return this->logString(s);
}

Status BroLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
    LOG(ERROR) << "logStatus = ";
  // NOT IMPLEMENTED
  return Status(1, "Not implemented");
}


void BroLoggerPlugin::init(const std::string& name,
                                  const std::vector<StatusLogLine>& log) {

}
}
