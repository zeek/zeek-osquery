#include <osquery/sdk.h>
#include <osquery/system.h>
//#include <osquery/flags.h>

#include <utils.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <iostream>

namespace osquery {

    Status createSubscriptionRequest(const std::string& rType, const broker::message& msg,
                                     const std::string& incoming_topic, SubscriptionRequest& sr) {

        //Check number of fields
        unsigned long numFields;
        if ( rType == "EXECUTE" )
            numFields = 6;
        else if ( rType == "SUBSCRIBE" )
            numFields = 7;
        else if ( rType == "UNSUBSCRIBE" )
            numFields = 7;
        else {
            LOG(WARNING) << "Unknown Request Type: '" << rType << "'";
            return Status(1, "Failed to create Subscription Request");
        }

        if ( msg.size()!= numFields) {
            LOG(WARNING) << "Invalid number of fields for " << rType << " "
                    "message '" << broker::to_string(msg[0]) << ""
                    "': " << msg.size() << " (expected " << numFields << ")";
            return Status(1, "Failed to create Subscription Request");
        }

        // Query String
        if ( broker::is<std::string>(msg[1]) )
            sr.query = *broker::get<std::string>(msg[2]);
        else {
            LOG(WARNING) << "Unexpected data type";
            return Status(1, "Failed to create Subscription Request");
        }

        // Response Event Name
        if ( broker::is<std::string>(msg[1]) )
            sr.response_event = *broker::get<std::string>(msg[1]);
        else {
            LOG(WARNING) << "Unexpected data type";
            return Status(1, "Failed to create Subscription Request");
        }

        // Cookie
        std::string cookie = broker::to_string(msg[3]);
        sr.cookie = cookie;

        // Response Topic
        if( broker::to_string(msg[4]).empty() ) {
            sr.response_topic = incoming_topic;
            LOG(WARNING) << "No response topic given for event '" << sr.response_event << "'. Reporting back to "
                    "incoming topic '" << incoming_topic << "'";
        } else {
            if ( broker::is<std::string>(msg[4]) )
                sr.response_topic = *broker::get<std::string>(msg[4]);
            else {
                LOG(WARNING) << "Unexpected data type";
                return Status(1, "Failed to create Subscription Request");
            }
        }

        // Update Type
        std::string update_type = broker::to_string(msg[5]);
        if (update_type == "ADDED") {
            sr.added = true; sr.removed = false; sr.snapshot = false;
        } else if (update_type == "REMOVED") {
            sr.added = false; sr.removed = true; sr.snapshot = false;
        } else if (update_type == "BOTH") {
            sr.added = true; sr.removed = true; sr.snapshot = false;
        } else if (update_type == "SNAPSHOT") {
            sr.added = false; sr.removed = false; sr.snapshot = true;
        } else {
            LOG(ERROR) << "Unknown update type: " << update_type;
            return Status(1, "Failed to create Subscription Request");
        }

        // If one-time query
        if ( rType == "EXECUTE" ) {
            if (sr.added or sr.removed or !sr.snapshot) {
                LOG(WARNING) << "Only possible to query SNAPSHOT for one-time queries";
            }
            return Status(0, "OK");
        }
        // SUBSCRIBE or UNSUBSCRIBE
        if ( sr.snapshot ) {
            LOG(WARNING) << "Only possible to query ADD and/or REMOVE for schedule queries";
        }

        // Interval
        if ( broker::is<uint64_t>(msg[6]) )
            sr.interval = *broker::get<uint64_t>(msg[6]);
        else {
            LOG(WARNING) << "Unexpected data type";
            return Status(1, "Failed to create Subscription Request");
        }

        return Status(0,"OK");
    }

/////////////////////////////////////////////////////////
//////////////// Print Debug Methods/////////////////////
/////////////////////////////////////////////////////////

void printColumnsInfo(const std::string& q) {
// Query Information
// Query Columns (ordered list of column name and corresponding SQL type)
//   for Column Type see: enum osquery::ColumnType
//   for Column Option see: enum class osquery::ColumnOptions
  TableColumns columns;
  Status status = getQueryColumnsExternal(q, columns);
  for (std::tuple<std::string, ColumnType, ColumnOptions> t: columns) {
    LOG(INFO) << std::get<0>(t) << std::endl;
  }
}

    Status printQueryLogItemJSON(const std::string& json_string) {
      LOG(INFO) << "QueryLogItemJSON to parse: " << json_string;
      QueryLogItem item;
      Status status = deserializeQueryLogItemJSON(json_string, item);
      if ( status.getCode() == 0 ) {
        return printQueryLogItem(item);
      } else {
        LOG(ERROR) << "Failed to parse Json Query Log Item" << std::endl;
        return Status(1, "Failed to parse");
      }
    }

Status printQueryLogItem(const QueryLogItem& item) {
    LOG(INFO) << "Parsed query result" << std::endl;
    LOG(INFO) << "\tDiffResults: " << std::endl;
      printDiffResults(item.results);
    LOG(INFO) << "\tQueryData: " << std::endl;
      printQueryData(item.snapshot_results);
    LOG(INFO) << "\tname: " << item.name;
    LOG(INFO) << "\tidentifier: " << item.identifier;
    LOG(INFO) << "\ttime: " << std::to_string(item.time);
    LOG(INFO) << "\tcalendar_time: " << item.calendar_time;
    LOG(INFO) << "\tdecorations: " << std::endl;
      printDecorations(item.decorations);
  return Status(0, "OK");
}

void printDiffResults(const DiffResults& results) {
  LOG(INFO) << "\t\tadded: ";
    printQueryData(results.added);
  LOG(INFO) << "\t\tremoved: ";
    printQueryData(results.removed);
}

void printQueryData(const QueryData& data) {
  /** using QueryData = std::vector<Row>; **/
  /** using Row = std::map<std::string, RowData>; **/
  /** using RowData = std::string; **/
//  LOG(INFO) << "Vector size: " << data.size();
  for (const Row& r: data) {
//    LOG(INFO) << "\t\t\t (Size: " << r.size() << ")";
    for (const auto& pair: r) {
      LOG(INFO) << "\t\t\t<" << pair.first << ", " << pair.second << "> ";
    }
    LOG(INFO) << std::endl;
  }
}

void printDecorations(const std::map<std::string, std::string>& deco) {
  /** std::map<std::string, std::string> decorations **/
  for (const auto& pair: deco) {
      LOG(INFO) << "\t\t\t<" << pair.first << ", " << pair.second << "> ";
  }
}

}

