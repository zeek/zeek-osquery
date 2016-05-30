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

#include <cstring>
#include <vector>
#include "keyword.h"

using namespace std;

/**
 * Structure that saves a chunk of SQL statement for further processing
 * offset: offset form the start of string
 * length: length of chunk/word
 */
struct sqlidentifier{
  int offset;
  int length;
  sqlidentifier(int o, int l):offset(o), length(l){};
};

/**
 * SQL statement current position.
 */
struct sqlstate{
  char *buffer;
  int offset;
  sqlidentifier identifier;
  sqlstate(char *c, int o, sqlidentifier i):buffer(c), offset(o), identifier(i){};
};

/**
 * Structure to hold the SQL statement.
 */
struct sqlstring {
  std::string s;
};

/**
 * SQL statement column information structure
 * tbname: table name 
 * name: name of column
 * sql_type: corresponding type of column
 */
struct sqlcolumn{
  std::string tbname;
  std::string name;
  sql_type type;
  sqlcolumn( std::string newname): name(newname){}; 
  sqlcolumn(std::string table, std::string newname): tbname(table), 
        name(newname){}; 
};

/**
 * SQL statement where clause structure
 * tbname: table name
 * column: column name used in the where clause
 * value: condition that is used in the where clause
 */
struct sqlwhere{
  sqlcolumn column;
  std::string value;
  std::vector<char> condition;
  sqlwhere(sqlcolumn newcolumn, std::string newvalue, std::vector<char> cond): 
        column(newcolumn), value(newvalue), condition(cond){};
};

/**
 * Structure to hold INNER JOIN table information
 * col1 => Column structure for 1st table and its corresponding column
 * col2 => Column structure for 2nd table and its corresponding column
 */
struct sqljoin{
    sqlcolumn col1;
    sqlcolumn col2;
    sqljoin(sqlcolumn newcol1, sqlcolumn newcol2): col1(newcol1), col2(newcol2)
    {};
};
/**
 * Structure to hold the whole table in one place
 * name: name of table
 * columns: vector of columns
 * primary_key: primary key of table.
 */
struct sqltable{
  sqlstring name;
  std::vector<sqlcolumn> columns;
  sqlstring primary_key;
};


