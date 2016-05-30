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

#include <stdexcept>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <osquery/filesystem.h>
#include <osquery/sdk.h>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#include <string>
#include <vector>
#include "sqlite3.h"



using namespace osquery;
using std::runtime_error;


 
/**
 * enum for possible outputs of an operation
 */
enum OperationOutput {KILL_SIGNAL = -1, FAILURE = 0 , SUCCESS = 1};
//callback event data
extern std::string cBData;
/*
 * @brief Exception Class
 */
class SignalException : public runtime_error
{
    public:    
    SignalException(const std::string& message) : std::runtime_error(message)
    {}
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
///////////////////////Signal Handler class///////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
/*
 * @brief Kill or ctrl+C signal Handler Class
 */
class SignalHandler
{
protected:
    static bool mbGotExitSignal;
public:
    /**
     * @brief Setup the signal handlers for CTRL+C
     * 
     */ 
    void setupSignalHandler();
    
    /**
     * @brief Sets exit signal to true
     * 
     * @param _ignored Not used but required by function prototype to match
     * required handler
     * 
     */ 
    static void exitSignalHandler(int _ignored);
    
    /**
     * @brief Returns the bool flag indicating whether we received an
     *  exit signal
     * 
     * @return Flag indicating shutdown of program
     */
    static bool gotExitSignal();
    
    /**
     * @brief Sets the bool flag indicating whether we received an exit signal
     * 
     */ 
    static void setExitSignal(bool _bExitSignal); 
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
///////////////////////Text File Reader and writer class//////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

class FileReaderWriter
{
private: 
    // path to broker.ini file; used to initialize topic,hostname and port no
    std::string kPath;
    // local host Name
    std::string hostName;
    // broker topic necessary for receiving interested 
    std::string bTopic;
    // broker connection port
    std::string brPort;
    //Bro master IP
    std::string masterIP;
    //Retry Interval in millsec
    std::string retryInterval;
    //timer interval in millsec
    std::string timerInterval;
    //offline logging time
    std::string offlineLoggingInterval;
public:
    /**
     * @brief Default Constructor to initialize kPath with default path
     */
    FileReaderWriter();
    
    /**
     * @brief Reads hostName, broker_topic, broker_port from broker.ini at path
     * provided in constructor. 
     * 
     * @return Returns 0 if reading is successful else returns the error code
     */
    int read();
        
    /**
     * @brief Returns Local Host Name string
     * 
     * @return Returns local host name
     */
    std::string getHostName();
    
    /**
     * @brief Returns Broker Topic string
     * 
     * @return Returns broker_topic
     */
    std::string getBrokerTopic();
    
    /**
     * @brief Returns Broker Port string
     * 
     * @return Returns broker_port
     */
    std::string getBrokerConnectionPort();   
    
    /**
     * @brief Returns Bro Master ip string
     * 
     * @return Returns masterIP
     */
    std::string getMasterIp();
    
    /**
     * @brief Returns connection retry interval
     * This field is necessary in a sense that there will be number of client 
     * trying to connect with master. If in case, master is down then connection
     * attempt will generate a lot of traffic. So to minimize probing traffic 
     * this field  is used as control variable.
     * 
     * @return Returns retryInterval variable value.
     */
    std::string getRetryInterval();
    
    /**
     * @brief Returns the timer interval at which the query updates need to be
     * sent.
     * 
     * @return Returns timerInterval.
     */
    std::string getTimerInterval();
    
    /**
     * @brief Returns the offline logging time. -1 is for forever 
     * 
     * @return Returns offlineLoggingInterval variable.
     */
    std::string getOfflineLoggingInterval();
};
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
///////////////////////Database class/////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
/**
 * @brief This class encloses the functionality of offline logging and then 
 * sending formated data to Bro master.
 */
class offlineSqliteDB
{
private:
    //pointer to database file
    sqlite3 *db;
    //pointer to error message
    char *zErrMsg;
    //return code from function calls
    int rc;
public:
    offlineSqliteDB();
    
    /**
     * @brief Initialize database--create db file if it does not exists-- and 
     * create table structure for according to our requirement.
     * 
     * @return status code for the db operations success or failure. 
     */
    int init();
    
    /**
     * @brief Insert a new entry in database with the given data
     * @param count counter variable as an ID to track no of elements--required
     * at the time of fetching. 
     * @param msg string to save in database in broker::message formate.
     * 
     * @return status code for the db operations success or failure. 
     */
    int insertAnEvent(int count, std::string msg);
    
    /**
     * @brief parse an event from database 
     * @param count counter variable as an ID to track no of elements--required
     * at the time of fetching. 
     * 
     * @return A broker event in the form of a std::string 
     */
    std::string parseAnEvent(int count);
    
    /**
     * @brief deletes entire db contents-- it should be called after successful
     * sending of all events to server. 
     * @return status code about database deletion.
     */
    int deleteDB();
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
///////////////////////Global Functions///////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
   /**    
     *  @brief Returns local host IP 
     * 
     * Extracts local interface IPv4 using osquery::query interface
     * 
     *  @return the local host IP in std::string form
     */
    std::string getLocalHostIp();

  /**
	* @brief Split a given string based on an optional delimiter.
 	*
	* If no delimiter is supplied, the string will be lsplit based on whitespace.
	*
	* @param s the string that you'd like to lsplit
	* @param delim the delimiter which you'd like to lsplit the string by
	*
	* @return a vector of strings lsplit by delim.
	*/
	std::vector<std::string> lsplit(const std::string& s,
                               const std::string& delim = "\t ");

  /**
	* @brief Split a given string based on an delimiter.
	*
	* @param s the string that you'd like to lsplit.
	* @param delim the delimiter which you'd like to lsplit the string by.
	* @param occurrences the number of times to lsplit by delim.
	*
	* @return a vector of strings lsplit by delim for occurrences.
	*/
	std::vector<std::string> lsplit(const std::string& s,
                               const std::string& delim,
                               size_t occurences);
        
    /**
     * @brief call back functions to handle database operations
     */
    static int callback(void *NotUsed, int argc, char **argv, char **azColName);
    
    //pointer to database class
    extern offlineSqliteDB* ptDb;
