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
#include <osquery/filesystem.h>
#include <osquery/sdk.h>


using namespace osquery;
using std::runtime_error;


 
/**
 * enum for possible outputs of an operation
 */
enum OperationOutput {KILL_SIGNAL = -1, FAILURE = 0 , SUCCESS = 1};

/*
 * @brief Exception Class
 */
class SignalException : public runtime_error
{
    public:    
    SignalException(const std::string& message) : std::runtime_error(message)
    {}
};

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
     * @returns Flag indicating shutdown of program
     */
    static bool gotExitSignal();
    
    /**
     * @brief Sets the bool flag indicating whether we received an exit signal
     * 
     */ 
    static void setExitSignal(bool _bExitSignal); 
};

class FileReader
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
public:
    /**
     * @brief Default Constructor to initialize kPath with default path
     */
    FileReader();
    
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
     * attempt will generate a lot of trafic. So to minimize probing trafic 
     * this field  is used as control variable.
     * 
     * @return Returns retryInterval.
     */
    std::string getRetryInterval();
    
    /**
     * @brief Returns the timer interval at which the query updates need to be
     * sent.
     * 
     * @return Returns timerInterval.
     */
    std::string getTimerInterval();
};

/**    
     *  @brief Returns local host IP 
     * 
     * Extracts local interface IPv4 using osquery::query interface
     * 
     *  @return the local host IP in std::string form
     */
    std::string getLocalHostIp();
