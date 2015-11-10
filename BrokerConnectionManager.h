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
#include "BrokerQueryManager.h"
#include "utility.h"


/**
 * This class is responsible for broker connection management and as an higher 
 * level implementation for broker query manager operations. 
 */

class BrokerConnectionManager
{
private:
    //broker port for listening connection
    int bPort;
    // connection state tracking variable
    bool connected;
    // BrokerQueryManager pointer for processing query and generating
    // its response
    BrokerQueryManager* qm;
   //pointer broker endpoint as local host
    broker::endpoint* ptlocalhost;
    //pointer to message queue object to read broker::messages
    broker::message_queue* ptmq;
    //pointer to pooling for message queue
    pollfd* ptpfd;
    //peer name 
    broker::peering peer;
public:
    /**
     *  @brief Class constructor
     *  
     *  @param hostName local host name
     *  @param btp Broker topic used to send messages to interested peers
     *  @param bport Broker connection port used while listening
     * 
     */ 
     BrokerConnectionManager(std::string hostName,std::string btp,
             int bport=9999);
     
    //Class Destructor to delete pointed objects
    ~BrokerConnectionManager();
    
    
    /**
     * @brief connect to master
     * 
     * This function is responsible for connection establishment.
     * Uses broker::connect() to connect to master, retires after each
     * retry time given in broker.ini file
     * 
     * @param master_ip bro master ip address
     * @param retry_interval time in millisec to retry connection if not
     * established
     * 
     * @return true if connection is successful.
     */
    bool connectToMaster(std::string master_ip, std::chrono::duration<double>
                        retry_interval, SignalHandler* handler);
    
    /**
     *  @brief receives the broker topic extracted from broker message after
     *  topic event and then sets the broker::message_queue to start listening
     *  at new topic.
     *  
     *  @param gTopic group topic string
     * 
     */
    int getAndSetTopic(std::string gTopic);
    
    /**
     *  @brief Reads broker messages from queue and then Extracts messages 
     *  event name and  query string. Processes each query to corresponding
     *  query columns that will be used to map query columns with event
     *  arguments at the update event generation time.
     *  
     *  @return Returns ture if there is successful get and extraction.
     */ 
    bool processQueriesVectors();
    
    /**
     *  @brief When connection is established and queries are processed then
     *  this function is called to process query updates. 
     * 
     *  @param handle SignalHandler to track CTRL+C signal for lower level
     *  executing statements
     * @return return operation state
     */ 
    int trackResponseChangesAndSendResponseToMaster(SignalHandler *handle);
    
    /**    
     *  @brief Returns true if broker Connection is Alive
     * 
     *  keeps track of disconnect signal if received then it raises disconnect
     *  flag 
     * 
     * @return True if connection is up
     */ 
    bool isConnectionAlive();
    
    /**    
     *  @brief Returns QueryManager pointer 
     *  
     *  QueryManger pointer is required to call ReinitializeVectors from main
     *  so that we may reInitialize vectors when connection is broken.
     * 
     *  @returns qm pointer 
     */ 
    BrokerQueryManager* getQueryManagerPointer();
    
    /**    
     *  @brief Returns pollfd pointer 
     *  pollfd pointer is required to poll broker::message queue
     * 
     *  @returns local ptpfd pointer 
     */  
    pollfd* getPollfdPointer();
    
    /**    
     *  @brief Returns broker::message_queue pointer 
     *  broker::message_queue pointer is required to get broker::message
     * 
     *  @returns local ptmq pointer 
     */  
    broker::message_queue* getMessageQueuePointer();
    
    /**
     * @brief Closes the broker connection 
     * Simply un-peer the already established connection
     * 
     */
    void closeBrokerConnection();
    
};


