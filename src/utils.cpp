#include <osquery/sdk.h>
#include <osquery/system.h>

#include <utils.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <iostream>

namespace osquery {

    Status createSubscriptionRequest(const broker::message& msg, std::string incoming_topic, SubscriptionRequest& sr) {

        sr.query = broker::to_string(msg[2]);
        sr.response_event = broker::to_string(msg[1]);
        // The topic where the request was received
        sr.response_topic = incoming_topic; // TODO: or use custom as optionally specified in msg
        std::string update_type = broker::to_string(msg[3]);
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

        if (sr.added or sr.removed)
            sr.init_dump = broker::get<bool>(msg[4]);

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

