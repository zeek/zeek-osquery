/*
* Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
* Institute of Space Technology
* All rights reserved.
*
* This source code is licensed under the BSD-style license found in the
* LICENSE file in the root directory of this source tree. An additional grant
* of patent rights can be found in the PATENTS file in the same directory.
*/

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include "sqlselect.h"

using namespace std;

sqlselect::sqlselect(){}

void sqlselect::addColumn(sqlcolumn target)
{
  columns.push_back(target);
}

void sqlselect::addWhere(sqlcolumn column, std::string value, 
        std::vector<char> arth)
{
  sqlwhere where(column, value, arth);
  wheres.push_back(where);
}

void sqlselect::addJoin(sqlcolumn col1, sqlcolumn col2)
{
    sqljoin join(col1,col2);
    joins.push_back(join);
}

void sqlselect::setTable(std::string tbl)
{
  if (std::find(tables.begin(), tables.end(), tbl) == tables.end()) 
  {
  // tble not in tables, add it
  tables.push_back(tbl);
  }
}
void sqlselect::set_order_by(std::string o)
{
  order_by = o;
  order = true;
}
std::string sqlselect::getTable()
{
  return tables.at(0);
}

std::vector<sqlcolumn> sqlselect::getColumns()
{
    return columns;
}

std::vector<sqlwhere> sqlselect::getWheres()
{
    return wheres;
}

std::vector<sqljoin> sqlselect::getJoins()
{
    return joins;
}

void sqlselect::printColumns()
{
  std::cout<<"columns: ";
  for (int i=0; i<columns.size(); i++)
  {
    std::cout<<columns[i].tbname << " => " << columns[i].name<<", ";
  }
  std::cout<<std::endl;
}

void sqlselect::printTable()
{
    for(int i=0; i< tables.size(); i++)
    {
        std::cout<<"table: "<<tables[i]<<std::endl;
    }
}

void sqlselect::printWheres()
{
  std::cout<<"Where: " << endl;
  for (int i=0; i<wheres.size();i++)
  {
    std::cout<<i+1<<"- "<<wheres[i].column.tbname <<"." <<wheres[i].column.name;
    for(int j=0;j<wheres[i].condition.size();j++)
    {
        std::cout << wheres[i].condition[j];
    }
     std::cout<<wheres[i].value<<std::endl;
  }
}

void sqlselect::printJoin()
{
  std::cout<<"join: ";
  for (int i=0; i<joins.size();i++)
  {
    std::cout<<joins[i].col1.tbname <<"." <<joins[i].col1.name;
    std::cout << "  ===>  ";
    std::cout<<joins[i].col2.tbname <<"." <<joins[i].col2.name<<std::endl;
  }
}

void sqlselect::printOrderBy()
{
  std::cout<<"Order by: "<<order_by<<std::endl;
}
