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

#include <iostream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cassert>
#include "keyword.h"
#include "sqlselect.h"

class SqlLexer
{

public:
    /**
     * Constructor of class
     */
    SqlLexer(){}
    
   /**
    * Cuts/copy a word from SQL statement
    * @param buffer char* pointer to sql statement
    * @param offset current position of pointer during read process
    * @param length length of word to cut/copy
    * @return returns corresponding SQL keyword after enum mapping of word
    */
    sql_token slice_buffer(char *buffer, int offset, int length);

   /**
    * Just hovers over the first word in the SQL statement and 
    * processes it
    * @param sql_state pointer to current state of sql statement during read 
    * process
    */
    void lexer_alpha(sqlstate *sql_state);
    
   /**
    * lexer a word in SQL statement and return corresponding token
    * @param sql_state current state of SQL statement
    * @param sql pointer to sqlstatement object;responsible for collecting
    * useful information
    * @return returns corresponding SQL keyword after enum mapping of word 
    */
    sql_token lexer_alpha(sqlstate *sql_state, sqlselect *sql);
    
    /** Just to check the state of string and next word existence check
     * @param sql_state pointer to current state of sql statement during read 
     * process
     */
    void lexer_next(sqlstate *sql_state);
    
   /**
    * lexers alphabetically and returns a guess about the next word/character
    * Next word can be a terminator.
    * @param sql_state current state of SQL statement
    * @param sql pointer to SQLstatement object;responsible for collecting
    * useful information  
    * @return corresponding token after mapping.
    */
    sql_token lexer_select_next(sqlstate *sql_state, sqlselect *sql);

   /**
    * Function to extract columns information from the SQL statement. It builds
    * a vector of columns and each column is mapped with its table name.
    * @param sql_state current state of SQL statement
    * @param sql pointer to SQLstatement object;responsible for collecting
    * useful information 
    * @return returns TOK_ERROR | TOK_TERMINATOR | TOK_FROM based on condition 
    */
    sql_token lexer_select_columns(sqlstate *sql_state, sqlselect *sql);

   /**
    * lexers the SQL where clauses and there corresponding conditions. It builds 
    *  a vector of columns, arithmetic operation and comparing value.
    * @param sql_state current state of SQL statement
    * @param sql pointer to SQLstatement object;responsible for collecting
    * useful information 
    * @return returns TOK_ERROR | TOK_TERMINATOR | TOK_ORDER based on condition 
    */
    sql_token lexer_select_where(sqlstate *sql_state, sqlselect *sql);

   /**
    * The main function to lexer SQL statement and extracting useful
    * information out of statement.
    * @param buffer reference to string containing SQL statement
    * @param sql sqlselect class object to store extracted information 
    * @return returns TOK_ERROR | TOK_TERMINATOR during execution or termination 
    */
    sql_token lexer_select(char *buffer, sqlselect *sql);

   /**
    * Lexers the inner join clauses
    * @param sql_state current state of SQL statement
    * @param sql pointer to SQLstatement object;responsible for collecting
    * useful information 
    * @return returns TOK_ERROR | TOK_TERMINATOR based on condition 
    */
    sql_token lexer_inner_join(sqlstate *sql_state, sqlselect *sql);
    
};
 

