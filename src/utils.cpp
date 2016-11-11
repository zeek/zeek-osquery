#include <osquery/sdk.h>
#include <osquery/system.h>

#include <utils.h>

#include <iostream>

namespace osquery {

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
  } else {
    LOG(ERROR) << "Failed to parse Json Query Log Item" << std::endl;
    return Status(1, "Failed to parse");
  }
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

