/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once


#include <broker/address.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <osquery/sdk.h>
#include <poll.h>
#include <iostream>
#include <unistd.h>
#include <vector>
#include "utility.h"




using namespace osquery;

/**
 * @brief Incoming broker-events information Structure.
 * It will hold Bro's query subscription function information 
 */
struct input_query
{
    //event name mapped at Bro-side
    std::string event_name;
    //SQL query in which Bro is interested 
    std::string query;
    // flag to send initial dump, default is false
    bool flag;
    //event type rather it is "ADD" or "REMOVED"
    std::string ev_type;
    //subscribed or un-subscribed
    bool sub_type;
};

/**
 *  @brief Update event's structure; to hold current and old query results that
 *   will be used to generate update event
 */
struct query_update
{
    //current query results
    QueryData current_results;
    //old query results
    QueryData old_results;
};


/**
 *  @brief Stores columns names extracted from query string
 *  
 */

//vector of query columns
typedef std::vector<std::string> query_columns;

// map of query columns; holds query columns for each query
typedef std::map<int,query_columns> query_columns_map;

//size of array
const int SIZE=1024;
//wait time for polling
const int PTIME = 2000;

/**
 *  @brief Query Manager is responsible for update tracking for given queries
 * 
 *  When broker connection is establish then control is handled to 
 *  BrokerQueryManager. Then it keeps tracking updates and sends update events
 *  to Bro-side
 */
class BrokerQueryManager
{
private:
    //broker topic string 
    std::string bTopic;
    //local machine user name
    char username[SIZE];
    bool firstTime;
    // To store the difference in query results
    DiffResults diff_result;
    //reference to local-host 
    broker::endpoint* ptlocalhost;
    //pointer to message queue object to read broker::messages
    broker::message_queue* ptmq;
    // vector of query_update
    std::vector<query_update> out_query_vector;
    //vector of input_query
    std::vector<input_query> in_query_vector;
    // Bro events name vector 
    std::vector<std::string> event;
    // query colum vector object
    query_columns qc;
    // query columns map object for storing each query columns
    query_columns_map qmap;
    // to track the CTRL +C kill signal
    SignalHandler *handle;
    
public:
    /**
     * @brief default constructor
     * 
     * @param lhost A pointer to local host passed form BrokerConnectionManager
     * @param mq A pointer to message queue used for reading broker messages
     * @param btp  broker topic read from file
     * 
     */ 
    BrokerQueryManager(broker::endpoint* lhost,
            broker::message_queue* mq,
            std::string btp);
    
    
    /**    
     *  @brief Extracts update type from bro events (broker::message) received.    
     *  It maps the interested event type whether "ADD", "REMOVED" or "BOTH" 
     *  with the subscribed SQL query.
     * 
     *  @return returns true if some data is written in local event vector 
     */
    bool getEventsFromBrokerMessage();
    
    /**    
     *  @brief Extracts query columns from SQL query.
     *  Builds column structure by extracting column name for each corresponding
     *  query string.
     *  
     *  @return returns true if extraction is successful 
     */
    bool queryColumnExtractor();
    
    /**    
     *  @brief Fills the out_query_vector with given queries initial results. 
     *  This function need to be called after each query subscription message 
     *  for initializing out_query_vectors.   
     * 
     *  @return True if out_query_vector is initialized properly
     */
    bool queryDataResultVectorInit();
    
    /**    
     *  @brief Tracks changes in query Tables
     *  
     *  This function manages and monitors the life cycle of queries, and
     *  tracks update in given queries tables: till the broker connection
     *  is up.
     */ 
    void queriesUpdateTrackingHandler();
    
    
    /**
     *  @brief A wrapper function to get daemon state against input SQL query. 
     * 
     *  @param queryString SQL formated string to get host-level information
     *
     *  @return Query results in the form of osquery::QueryData.
     */ 
    QueryData getQueryResult(const std::string& queryString);
    
    /**    
     *  @brief Calculates difference in query results; if there is any update
     *  (row added or removed) then it triggers sendUpdateEventToMaster() to 
     *  send updates to bro-side.
     * 
     *  @param iterator to indicate query for which we need to calculate
     *  difference.
     */
    void diffResultsAndEventTriger(int& i);
    
   /**    
    * @brief Sends update events to master in the form of broker::messages
    *
    * @param temp QueryData that holds update information whether added
    *  or removed
    * @param event_type Event type might be ADD, REMOVE, INIT_DUMP
    * @param iterator internal variable to map table with corresponding query
    */
    void sendUpdateEventToMaster(const QueryData& temp, std::string event_type,
        int& iterator);
    
    /**
    * @brief Extracts event name, type and SQL query form Broker Message.
    * Processes the input broker::message and builds an input_query structure
    * from broker message.
    * 
    * @param msg broker::message received in event form
    *
    * @return input_query structure containing event and SQL query
    *
    */
    input_query brokerMessageExtractor(const broker::message& msg);
    
    /**    
     * @brief Checks whether string contains all digits or not
     *
     * osquery::QueryData saves results in std::string formate.
     * To map query columns datatype with Bro's event arguments datatype,
     * we need to check data contained in query column's string.
     *
     * @param str std::string whose elements need to be checked 
     * @return returns true if elements in a string are all digits else false
     * 
     */
    bool isQueryColumnInteger(const std::string& str);
    
    
    /**    
     *  @brief Clears all vectors data 
     * 
     *  This function is called when Broker-Connection is broken.
     *  Then we need to free resources and go for listening new connection
     * 
     *  @return returns ture if resources are freed nicely.
     */
    bool ReInitializeVectors();
             
    
    /**
     *  @brief This function is used to set signal handler pointer 
     *  @param s_handle pointer to signal handler object created in main.cpp
     */
    void setSignalHandle(SignalHandler *s_handle);
    
    /**
     * @brief send warnings to bro-side
     * This function is responsible for sending warning events to bro side in 
     * the form of events.
     * 
     * @param str a string containing warning message 
     */
    void sendWarningtoBro(std::string str);
    
    /**
     * @brief send errors to bro-side
     * This function is responsible for sending error events to bro-side in 
     * the form of events.
     * 
     * @param str a string containing error message 
     */
    void sendErrortoBro(std::string str);
    
    /**
     * @brief send errors to bro-side
     * Sends ready event to bro-side as an ACK message so that bro-side start
     * sending SQL queries. This function is called after group topic is
     * registered.
     * 
     */
    void sendReadytoBro();
    
    /**
     * @brief SQL query formate checking. It simply checks whether SELECT and  
     * FROM keywords are in upper case. If not then it transforms them to upper
     * case. The rest of formating is checked by osquery itself. If osquery
     * could not process any query then it will generate an error message. Which 
     * can be sent to bro-side.
     * 
     * @param str SQL query string
     * @return returns formated SQL string
     */
    std::string formateSqlString(std::string str);
    
    /**
     * @brief If the SQL query is not registered before then it pushes the new
     * query to in_query_vector.
     * 
     * @param in input_query vector to broker
     * @return returns ture if operation is successful
     */
    bool addNewQueries(input_query in);
    
    /**
     * @brief If the SQL query is already registered before then it deleted the 
     * provided query from in_query_vector.
     * 
     * @param in input_query vector to broker
     * @return returns ture if operation is successful
     */
    bool deleteOldQueries(input_query in);
    
    /**
     * @brief To check the status of in_query_vector whether empty or not 
     * 
     * @return returns ture if the in_query_vector is not empty 
     */
    bool getInQueryVectorStatus();   
};


