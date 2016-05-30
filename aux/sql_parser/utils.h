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

/* This file contains function that do string manipulation, string matching, 
 * character matching 
 */

// extract slice of string given the buffer, offset position and length
void extract(sqlstate *state, char *copy){
  int i;
  int offset = state->identifier.offset;
  int length = state->identifier.length;

  for (i=0; i<length; i++){
    *(copy+i) = *(state->buffer+offset+i);
  }
  *(copy+i) = '\0';
}
//returns ture if character is digit
bool is_digit(char c){
  return isdigit(c);
}

//returns true if character is some character of digit or underscore
bool is_identifier(char c){
  return isalpha(c) || isdigit(c) || c == '_';
}

//returns true if character is digit
bool is_alpha(char c){
  return isalpha(c);
}

//returns true if character is space
bool is_space(char c){
  return c == ' ' || c == '\t' || c == '\v' || c == '\f';
}

//returns true if character is '*' representing all in SQL
bool is_all(char c){
  return c == '*';
}

//returns true if character is period/dot
bool is_dot(char c){
  return c == '.';
}

//returns true if character is semi-colon -> terminator in SQL statement
bool is_terminator(char c){
  return c == ';';
}

//returns true if character is one of the punctuation marks ( ) ,
bool is_puntuation(char c){
  return c == ',' || c == '(' || c == ')';
}

//returns true if the character is equal operator
bool is_equal(char c){
  return c == '=';
}

//returns true if character is quotation mark. 
bool is_quote(char c){
  return c == '\'';
}

bool is_arithmatic(char c)
{
    return c == '=' || c == '>' || c == '<' || c == '!';
}
