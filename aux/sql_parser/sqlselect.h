/*
* Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
* Institute of Space Technology
* All rights reserved.
*
* This source code is licensed under the BSD-style license found in the
* LICENSE file in the root directory of this source tree. An additional grant
* of patent rights can be found in the PATENTS file in the same directory.
*/

#pragma once

#include "sql.h"
#include <vector>

using namespace std;

/**
 * This class is used to represent all elements of SQL statement starting with
 * select keyword
 */
class sqlselect{
  //whether the SQL statement contains * => all character 
  bool select_all;
  //vector of sqlcolumns
  std::vector<sqlcolumn> columns;
  //vector of where clause 
  std::vector<sqlwhere> wheres;
  //vector of join clause
  std::vector<sqljoin> joins;
  //sting to hold table name
  std::vector<std::string> tables;
  //is order keyword is present
  bool order;
  
  bool to_limit;
  //holds the column name for order by keyword
  std::string order_by;

public:
  //constructor
  sqlselect();
  //function to add new column 
  void addColumn( sqlcolumn target);
  //function to add where clause information
  void addWhere(sqlcolumn column, std::string value, std::vector<char> arth);
  //function to add inner join information
  void addJoin(sqlcolumn col1, sqlcolumn col2);
  //function to set the table name
  void setTable(std::string t);
  //function to set the column name used by order_by keyword
  void set_order_by(std::string o);
  //return the table name
  std::string getTable();
  //get columns of SQL statement
  std::vector<sqlcolumn> getColumns();
  //get where clause information
  std::vector<sqlwhere> getWheres();
  //get the join clause information
  std::vector<sqljoin> getJoins();
  //prints all columns in the table
  void printColumns();
  //print table name
  void printTable();
  //print where information
  void printWheres();
  //prints order_by information
  void printOrderBy();
  //print inner join condition
  void printJoin();

};
