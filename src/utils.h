#include <osquery/sdk.h>
#include <osquery/system.h>

#include <iostream>

namespace osquery {

/**
 * @brief prints information about the columns requested by the given query
 * 
 * Asks the SQL Database about the table schema and retrieves column names/types
 *
 * @param q the input query
**/
void printColumnsInfo(const std::string& q);

Status printQueryLogItemJSON(const std::string& json_string);

Status printQueryLogItem(const QueryLogItem& item);

void printDiffResults(const DiffResults& results);

void printQueryData(const QueryData& data);

void printDecorations(const std::map<std::string, std::string>& deco);
}
