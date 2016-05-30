/*
* Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
* Institute of Space Technology
* All rights reserved.
*
* This source code is licensed under the BSD-style license found in the
* LICENSE file in the root directory of this source tree. An additional grant
* of patent rights can be found in the PATENTS file in the same directory.
*/


#include "lexer.h"
#include "utils.h"


#define PEEK (sql_state->buffer[sql_state->offset])
#define SKIP (sql_state->offset++)


sql_token SqlLexer::slice_buffer(char *buffer, int offset, int length){
  char sliced[length];
  int i=0;
  while (i<length){
    sliced[i] = buffer[i + offset];
    i++;
  }
  sliced[i] = '\0';
  return sql_keyword(sliced, length);
}


void SqlLexer::lexer_alpha(sqlstate *sql_state){
  int offset = sql_state->offset;
  while (is_identifier(PEEK)){
    sql_state->offset++;
  }
  int length = sql_state->offset - offset;
}

// lexer alphabetical string for select statement
sql_token SqlLexer::lexer_alpha(sqlstate *sql_state, sqlselect *sql){
  int offset = sql_state->offset;
  while (is_identifier(PEEK)){
    sql_state->offset++;
  }
  int length = sql_state->offset - offset;
  sql_token t = slice_buffer(sql_state->buffer, offset, length);

  if (t != TOK_IDENTIFIER) return t;
  sql_state->identifier.offset = offset;
  sql_state->identifier.length = length;
  return TOK_IDENTIFIER;
}


void SqlLexer::lexer_next(sqlstate *sql_state){
  char c = PEEK;
  //cout<<"peek: "<<c<<endl;
  if (is_alpha(c)) {
    lexer_alpha(sql_state);
  }
  c = PEEK;
  //cout<<"peek: "<<c<<endl;
  if (is_space(c)) SKIP; cout<<"skip once\n";
  c = PEEK;
  //cout<<"peek: "<<c<<endl;
  if (is_all(c)) SKIP; cout<<"skip once\n";
}

// lexer analysis for select statement
sql_token SqlLexer::lexer_select_next(sqlstate *sql_state, sqlselect *sql){
loop:
  char c = PEEK;
  if (is_space(c)){
    SKIP;
    goto loop;
   }
   /* to be changed */
  if (is_identifier(c)){
    return lexer_alpha(sql_state, sql);
  }
  /* checking if is digit */
  if (is_digit(c)){

  }
  if (is_all(c)){SKIP; goto loop;}
  if (is_quote(c)){SKIP; goto loop;}
  if (is_terminator(c)){return TOK_TERMINATOR;}

  return TOK_ERROR;
}

// lexer the selected target columns
//   "user.name, user.email"
// or  "name, email"
/* lexer of aggregate function needed */
sql_token SqlLexer::lexer_select_columns(sqlstate *sql_state, sqlselect *sql){
  loop:
    char c =PEEK;
    if (is_space(c)){
      SKIP;
      c = PEEK;
      // when there is no table name coming befor the dot '.'
      if (is_dot(c)) return TOK_ERROR;
      goto loop;
    }
    if (is_identifier(c)){
      sql_token t = lexer_alpha(sql_state, sql);
      /* put the target column name into sql */
      if (t == TOK_FROM) return t;
      c = PEEK;
      if (is_dot(c)){
        SKIP;
        char tname[10];
        char cname[10];
        extract(sql_state, tname);
        string table_name(tname);
        sql->setTable(table_name);
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, cname);
        string column_name(cname);
        sqlcolumn colw(table_name,column_name);
        sql->addColumn(colw);
        goto loop;
      }
      else {
        char name[10];
        extract(sql_state, name);
        string n(name);
        sqlcolumn col(n);
        //add column name
        sql->addColumn(col);
        goto loop;
      }
    }
    if (is_puntuation(c)){
      SKIP;
      goto loop;
    }
    return TOK_ERROR;
}

// lexer the SQL where clauses
sql_token SqlLexer::lexer_select_where(sqlstate *sql_state, sqlselect *sql){
  loop:
    char c = PEEK;
    if (is_space(c)){
      SKIP;
      c = PEEK;
      // when there is no table name coming before the dot '.'
      // ie where .username = ''
      if (is_dot(c)) return TOK_ERROR;
      goto loop;
    }
    if (is_alpha(c)){
      sql_token t = lexer_alpha(sql_state, sql);
      if (t == TOK_AND) {goto loop;}
      if (t == TOK_ORDER) {return t;}
      c = PEEK;
      if (is_dot(c)){
        SKIP;
        char tname[10];
        char cname[10];
        char tvalue[10];
        std::vector<char> arth;
        extract(sql_state, tname);
        string table_name(tname);
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, cname);
        string column_name(cname);
        sqlcolumn colw(table_name,column_name);
        // skip till there are arithmetic operators
        while (true)
        {
            if(!is_arithmatic(PEEK))
            {
                SKIP;
            }
            else
            {
               arth.push_back(PEEK);
               SKIP;
               if(is_arithmatic(PEEK))
               {
                arth.push_back(PEEK);   
               }
                break;
            }
        } 
        //step ahead to ignore arithmetic symbol
        SKIP;
        sql_token t = lexer_select_next(sql_state, sql);
        extract(sql_state, tvalue);
        string value(tvalue);
        sql->addWhere(colw, value, arth);       
        if (table_name != sql->getTable()) return TOK_ERROR;
        goto loop;
      }
      else{
        char name[10];
        std::vector<char> arth;
        extract(sql_state, name);
        string column_name(name);
        sqlcolumn col(column_name);
        // where username = ''
        while (true)
        {
            if(!is_arithmatic(PEEK))
            {
                SKIP;
            }
            else
            {
               arth.push_back(PEEK);
               SKIP;
               if(is_arithmatic(PEEK))
               {
                arth.push_back(PEEK);   
               }
                break;
            }
        } 
        SKIP;
        sql_token t = lexer_select_next(sql_state, sql);
        extract(sql_state, name);
        string value(name);
        sql->addWhere(col, value,arth);
        goto loop;
      }
    }
    if (is_puntuation(c)) SKIP;
    if (is_terminator(c)) return TOK_TERMINATOR;
    if (is_quote(c)){SKIP; goto loop;}

    return TOK_ERROR;
}

sql_token SqlLexer::lexer_select(char *buffer, sqlselect *sql)
{
    struct sqlidentifier i(0, 0);
    struct sqlstate sql_state(buffer, 0, i);
    sql_token t;
    do
    {
	t = lexer_select_next(&sql_state, sql);
	BYPASS:
	switch(t)
	{
		case TOK_SELECT:
		{
			// lexer the targeted columns
		  t = lexer_select_columns(&sql_state, sql);
		  if (t != TOK_FROM || t == TOK_ERROR)
                  {
                    cout<<"Syntax error around the column names"<<endl;
                    return TOK_ERROR;
                  }
		  goto BYPASS;
 		}
		case TOK_FROM:
		{
			// lexer the table name
  		t = lexer_select_next(&sql_state, sql);
  		char name[10];
  		extract(&sql_state, name);
  		string table_name(name);
  		break;
		}
		case TOK_INNER:
		{
			/* lexer the inner join clauses */
  		 t = lexer_inner_join(&sql_state, sql);
  		 if (t == TOK_TERMINATOR) return t;
		 break;
		}
		case TOK_WHERE:
		{
		 /* lexer the where clauses */
  		 t = lexer_select_where(&sql_state, sql);
  		 if (t == TOK_TERMINATOR) return t;
		 break;
		}
		case TOK_ERROR:
		{
			return t;
                        break;
		}
		case TOK_TERMINATOR:
		{
			return t;
                        break;
		}
		default:
		{
			return t;
		}

        };
    }while (t != TOK_TERMINATOR);
  return t;
}

sql_token SqlLexer::lexer_inner_join(sqlstate *sql_state, sqlselect *sql)
{
    loop:
    char c = PEEK;
    if (is_space(c))
    {
      SKIP;
      c = PEEK;
      // when there is no table name coming before the dot '.'
      // ie where .username = ''
      if (is_dot(c)) return TOK_ERROR;
      goto loop;
    }
    if (is_alpha(c))
    {
      sql_token t = lexer_alpha(sql_state, sql);
      if(t == TOK_AND) {goto loop;}
      if(t == TOK_JOIN){goto loop;}
      c = PEEK;
      if(is_dot(c))
      {
        SKIP;
        char t1name[10];
        char c1name[10];
        char t2name[10];
        char c2name[10];
        extract(sql_state, t1name);
        string table1_name(t1name);
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, c1name);
        string column1_name(c1name);
        sqlcolumn col1(table1_name,column1_name);
        // where username = ''
        while (PEEK != '=')
        {
            SKIP;
        } 
        SKIP;
        if (is_space(c))
        {
            SKIP;
        }
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, t2name);
        string table2_name(t2name);
        if(is_dot(c))
        {
            SKIP;
        }
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, c2name);
        string column2_name(c2name);
        sqlcolumn col2(table2_name,column2_name);
        sql->addJoin(col1,col2);

        //if (table1_name != sql->getTable()) return TOK_ERROR;
        //goto loop;
      }
      else{
        char name[10];
        extract(sql_state, name);
        c = PEEK;
        if(is_space(c))
        {SKIP;}
        t = lexer_alpha(sql_state, sql);
        if(t == TOK_ON) {SKIP;}
        else {return TOK_ERROR;}
        char t1name[10];
        char c1name[10];
        char t2name[10];
        char c2name[10];
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, t1name);
        string table1_name(t1name);
        //std::cout <<"Table1: " << table1_name <<endl;
        if(is_dot(PEEK))
        {SKIP;}
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, c1name);
        string column1_name(c1name);
        //std::cout <<"col1: " << column1_name <<endl;
        sqlcolumn col1(table1_name,column1_name);
        // where username = ''
        while (PEEK != '=')
        {
            SKIP;
        } 
        SKIP;
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, t2name);
        string table2_name(t2name);
        //std::cout <<"Table2: " << table2_name <<endl;
        if(is_dot(PEEK))
        {SKIP;}
        t = lexer_alpha(sql_state, sql);
        c = PEEK;
        extract(sql_state, c2name);
        string column2_name(c2name);
        sqlcolumn col2(table2_name,column2_name);
        sql->addJoin(col1,col2);
      }
    }
    if (is_puntuation(c)) SKIP;
    if (is_terminator(c)) return TOK_TERMINATOR;
    if (is_quote(c)){SKIP; goto loop;}

    return TOK_ERROR;
}
