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
/**
 * enum type for SQL keywords
 */
typedef enum{
  /* 0 */TOK_NULL,
  /* 1 */TOK_DELETE,
  /* 2 */TOK_ORDER,
  /* 3 */TOK_BY,
  /* 4 */TOK_AND,
  /* 4 */TOK_FROM,
  /* 5 */TOK_SELECT,
  /* 6 */TOK_HAVING,
  /* 7 */TOK_TRUNCATE,
  /* 8 */TOK_INSERT,
  /* 9 */TOK_UNION,
  /* 10 */TOK_UPDATE,
  /* 11 */TOK_INNER,               
  /* 12 */TOK_JOIN,
  /* 13 */TOK_ON,               
  /* 14 */TOK_WHERE,
  /* 15 */ TOK_MERGE,
  /* 16 */TOK_IDENTIFIER,
  /* 17 */TOK_ERROR,
  /* 18 */TOK_PASS,
  /* 19 */TOK_TERMINATOR
} sql_token;

/*
 *Enum containing all possible data types for SQL
 */
typedef enum{
  /* 1 */ TYPE_INT,
  /* 2 */ TYPE_CHAR,
  /* 3 */ TYPE_MONEY,
  /* 4 */ TYPE_BINARY,
  /* 5 */ TYPE_NUMERIC,
  /* 6 */ TYPE_BOOLEAN,
  /* 7 */ TYPE_VARCHAR,
  /* 7 */ TYPE_NONE,
} sql_type;

/**
 * It will map data type of a character with the enum
 * @param s word for the data type
 * @param l length of word
 * @return returns the corresponding enum type
 */
inline sql_type sql_checktype(char *s, int l){
  switch(l){
    case 3:
      if (strcasecmp(s, "int"))
        return TYPE_INT;
      break;
    case 4:
      if (strcasecmp(s, "char"))
        return TYPE_CHAR;
      break;
    case 5:
      if (strcasecmp(s, "money"))
        return TYPE_MONEY;
      break;
    case 6:
      if (strcasecmp(s, "binary"))
        return TYPE_BINARY;
      break;
    case 7:
      if (strcasecmp(s, "boolean"))
        return TYPE_BOOLEAN;
      if (strcasecmp(s, "numeric"))
        return TYPE_NUMERIC;
      if (strcasecmp(s, "varchar"))
        return TYPE_VARCHAR;
      break;
  }
  return TYPE_NONE;
}

/**
 * Maps the given word with the SQL key words
 * @param str word that is to be compared/checked
 * @param length length of that word
 * @return returns the corresponding enum type 
 */
inline sql_token sql_keyword(char *str, int length){
  switch (length) {
    case 2:
      if (!strcasecmp(str, "on"))
        return TOK_ON;
      if (!strcasecmp(str, "by"))
        return TOK_BY;
      break;
    case 3:
      if (!strcasecmp(str, "and"))
        return TOK_AND;
      break;
    case 4:
      if (!strcasecmp(str, "null"))
        return TOK_NULL;
      if (!strcasecmp(str, "from"))
        return TOK_FROM;
      if (!strcasecmp(str, "join"))
        return TOK_JOIN;
      break;
    case 5:
      if (!strcasecmp(str, "inner"))
        return TOK_INNER;
      if (!strcasecmp(str, "order"))
        return TOK_ORDER;
      if (!strcasecmp(str, "union"))
        return TOK_UNION;
      if (!strcasecmp(str, "where"))
        return TOK_WHERE;
      if (!strcasecmp(str, "merge"))
        return TOK_MERGE;
      break;
    case 6:
      if (!strcasecmp(str, "select"))
        return TOK_SELECT;
      if (!strcasecmp(str, "delete"))
        return TOK_DELETE;
      if (!strcasecmp(str, "insert"))
        return TOK_INSERT;
      if (!strcasecmp(str, "update"))
        return TOK_UPDATE;
      if (!strcasecmp(str, "having"))
        return TOK_HAVING;
      break;
  }
  return TOK_IDENTIFIER;
}

