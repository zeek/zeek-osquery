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
 * @brief This class is used to represent all elements of SQL statement starting
 * with SELECT keyword
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
  /**
   * @brief constructor of the class
   */
  sqlselect();
  
  /**
   * @brief function to add new column
   * @param target input structure with column information
   */
  void addColumn( sqlcolumn target);
  
  /**
   * @brief function to add where clause information
   * @param column input structure with column information
   * @param value input value to be compared in the where clause
   * @param arth arithmatic condition in the where clause
   */
  void addWhere(sqlcolumn column, std::string value, std::vector<char> arth);
  
  /**
   * @brief function to add inner join information
   * @param col1 first input structure with column information
   * @param col2 second input structure with column information
   */
  void addJoin(sqlcolumn col1, sqlcolumn col2);
  
  /**
   * @brief function to set the table name
   * @param t input table name in the SQL statement
   */
  void setTable(std::string t);
  
  /**
   * @brief function to set the column name used by order_by keyword
   */
  void set_order_by(std::string o);
  
  /**
   * @brief get the table name
   * @return returns the table name provided in the sql statement
   */
  std::string getTable();
  
  /**
   * @brief get vector of columns provided in the SQL statement
   * @return vector of columns
   */
  std::vector<sqlcolumn> getColumns();
  
  /**
   * @brief get where clause information
   * @return vector of where clause info
   */
  std::vector<sqlwhere> getWheres();
  
  /**
   * @brief get the join clause information
   * @return vector of join statements info
   */
  std::vector<sqljoin> getJoins();
  
  /**
   * @brief prints all columns in the table
   */
  void printColumns();
  
  /**
   * @brief print table name
   */
  void printTable();
  
  /**
   * @brief print where information
   */
  void printWheres();
  
  /**
   * @brief prints order_by information
   */
  void printOrderBy();
  
  /**
   * @brief print inner join condition
   */
  void printJoin();

};
