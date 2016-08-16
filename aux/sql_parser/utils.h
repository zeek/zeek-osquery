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

/** @brief This file contains function that do string manipulation, string 
 * matching and character matching 
 */

 /**
 * @brief extract slice of string given the buffer, offset position and length
 */
void extract(sqlstate *state, char *copy){
  int i;
  int offset = state->identifier.offset;
  int length = state->identifier.length;

  for (i=0; i<length; i++){
    *(copy+i) = *(state->buffer+offset+i);
  }
  *(copy+i) = '\0';
}

/**
 * @brief returns ture if character is digit
 * @param c input character
 */
bool is_digit(char c){
  return isdigit(c);
}

/**
 * @brief returns true if character is some character of digit or underscore
 * @param c input character
 */
bool is_identifier(char c){
  return isalpha(c) || isdigit(c) || c == '_';
}

/**
 * @brief returns true if character is digit
 * @param c input character
 */
bool is_alpha(char c){
  return isalpha(c);
}

/**
 * @brief returns true if character is space
 * @param c input character
 */
bool is_space(char c){
  return c == ' ' || c == '\t' || c == '\v' || c == '\f';
}

/**
 * @brief returns true if character is '*' representing all in SQL
 * @param c input character
 */
bool is_all(char c){
  return c == '*';
}

/**
 * @brief returns true if character is period/dot
 * @param c input character
 */
bool is_dot(char c){
  return c == '.';
}

/**
 * @brief returns true if character is semi-colon -> terminator in SQL statement
 * @param c input character
 */
bool is_terminator(char c){
  return c == ';';
}

/**
 * @brief returns true if character is one of the punctuation marks ( ) ,
 * @param c input character
 */
bool is_puntuation(char c){
  return c == ',' || c == '(' || c == ')';
}

/**
 * @brief returns true if the character is equal operator
 * @param c input character
 */
bool is_equal(char c){
  return c == '=';
}

/**
 * @brief returns true if character is quotation mark. 
 * @param c input character
 */
bool is_quote(char c){
  return c == '\'';
}

/**
 * @brief returns true if character is any of arithmatic operation. 
 * @param c input character
 */
bool is_arithmatic(char c)
{
    return c == '=' || c == '>' || c == '<' || c == '!';
}
