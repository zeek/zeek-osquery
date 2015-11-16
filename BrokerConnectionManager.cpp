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

#include "BrokerConnectionManager.h"




BrokerConnectionManager::BrokerConnectionManager(std::string hostName,
        std::string btp,int bport)
{
    if ( ! btp.size() || btp[btp.size() - 1] != '/' )
	btp += "/";

    btp += "host/" + hostName;

    //initialize broker API
    broker::init();
    this->bPort = bport;
    connected = false;
    //local host object
    ptlocalhost = new broker::endpoint(hostName);
    // broker messages queue
    ptmq = new broker::message_queue(btp,*ptlocalhost);
    // pooling for message queue
    ptpfd = new pollfd{ptmq->fd(), POLLIN, 0};
    // Query Manager Object
    qm = new BrokerQueryManager(ptlocalhost,ptmq,btp);
}

BrokerConnectionManager::~BrokerConnectionManager()
{
    // query manager object deletion
    delete qm;
    //local host object deletion
    delete ptlocalhost;
    // pooling object linked with message queue deletion
    delete ptpfd;
    // message queue deletion
    delete ptmq;
}

bool BrokerConnectionManager::connectToMaster(std::string master_ip,
        std::chrono::duration<double> retry_interval, SignalHandler* handler)
{
    LOG(WARNING) <<"Connecting to Master at "<<master_ip ;
    connected = false;
    peer = ptlocalhost->peer(master_ip,bPort);
    
    while(!connected && !(handler->gotExitSignal()))
    {
        auto conn_status = 
        ptlocalhost->outgoing_connection_status().want_pop();

        for(auto cs: conn_status)
        {
            if(cs.status == broker::outgoing_connection_status::tag::established)
            {
                LOG(WARNING) <<"Connection Established";
                connected = true;
                break;
            }
        }
    }
    return (!handler->gotExitSignal())? true: false;
}

int BrokerConnectionManager::getAndSetTopic(std::string gTopic)
{ 
   
    delete ptpfd;
    // pooling for message queue
    ptpfd = new pollfd{ptmq->fd(), POLLIN, 0};
    delete qm;
    qm = NULL;
    qm = new BrokerQueryManager(ptlocalhost,ptmq,gTopic);
    
    //send ready event to bro-side
    qm->sendReadytoBro();
    
    return (isConnectionAlive())?1:0;
}

bool BrokerConnectionManager::processQueriesVectors()
{
    //get the state of in_query_vector whether empty or not.
    bool temp = qm->getInQueryVectorStatus();
    //if not of empty
    if(temp)
    {
        //then extract columns form query strings
        temp = qm->queryColumnExtractor();
    }
    else
    {
        //send warning to bro.
        qm->sendWarningtoBro("No SQL query Registered... or"
                " query was unformated");
        ptlocalhost->unpeer(peer);
        connected = false;
        return false;
    }
    // extract event add/removed/both form event part if success
    if(qm->getEventsFromBrokerMessage())
    {
        // then fill the out_query_vector with query data
        temp = qm->queryDataResultVectorInit();
    }
    else
    {
        qm->sendErrortoBro("* is unexpected write columns instead");
    }
    return temp;
}

int BrokerConnectionManager::trackResponseChangesAndSendResponseToMaster(
                    SignalHandler *handle)
{
    //send a pointer to signal handler object created in main.cpp
    qm->setSignalHandle(handle);
    // start tracking updates
    qm->queriesUpdateTrackingHandler();
    
    return SUCCESS;
}



bool BrokerConnectionManager::isConnectionAlive()
{  
    //check connection queue if there is update
    auto conn_status =
    ptlocalhost->outgoing_connection_status().want_pop();
    for(auto cs: conn_status)
    {
        // if connection object found the check if there is disconnect flag
        if(cs.status == broker::outgoing_connection_status::tag::disconnected)
        {
            //if disconnected then break the connection.
            LOG(WARNING) <<"Connection Broken";
            closeBrokerConnection();
            connected = false;
        }
    }
    return connected;
}

 
BrokerQueryManager* BrokerConnectionManager::getQueryManagerPointer()
{
    return qm;
}

pollfd* BrokerConnectionManager::getPollfdPointer()
{
    return ptpfd;
}

broker::message_queue* BrokerConnectionManager::getMessageQueuePointer()
{
    return ptmq;   
}

void BrokerConnectionManager::closeBrokerConnection()
{
    ptlocalhost->unpeer(peer);
    connected = false;
}
