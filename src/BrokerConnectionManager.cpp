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

bool BrokerConnectionManager::isOffLoggingTimerEvent = false;
bool BrokerConnectionManager::connected = false;

BrokerConnectionManager::BrokerConnectionManager(std::string hostName,
        std::string btp,int bport, float loggingTime)
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
    //initialize offline logging interval
    setupTimerInterval(loggingTime);
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
    connected = false;
    
        auto conn_status = 
        ptlocalhost->outgoing_connection_status().want_pop();
        
        for(auto cs: conn_status)
        {
            if(cs.status == broker::outgoing_connection_status::tag::established)
            {
                BrokerConnectionManager::isOffLoggingTimerEvent = false;
                LOG(WARNING) <<"Connection Established";
                connected = true;
                break;
            }
        }
    return connected;
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
    qm->queriesUpdateTrackingHandler(isConnectionAlive(), 
            getLoggingPermission());
    
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
            //set the connected flag to false
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

void BrokerConnectionManager::setBrokerPeering(std::string master_ip)
{
    peer = ptlocalhost->peer(master_ip,bPort);
}

void BrokerConnectionManager::closeBrokerConnection()
{
    //initialize the timer
    //initializeTimer();
    ptlocalhost->unpeer(peer);
    connected = false;
}

void BrokerConnectionManager::setupTimerInterval(int interval)
{
    if(interval == -1)
    {
        loggingTimer.it_value.tv_usec = 0;
    }
    else
    {
    /* Configure the timer to expire after interval msec... */
    loggingTimer.it_value.tv_sec = 0;
    loggingTimer.it_value.tv_usec = (interval * 1000);
    loggingTimer.it_interval.tv_sec = 0;
    loggingTimer.it_interval.tv_usec = 0;    
    }
}

void BrokerConnectionManager::initializeTimer()
{
     struct sigaction sa;
     
     /* Install timer_handler as the signal handler for SIGVTALRM. */
     memset (&sa, 0, sizeof (sa));
     sa.sa_handler = &(BrokerConnectionManager::processTimerEvent);
     sigaction (SIGVTALRM, &sa, NULL);
    
     /* Start a virtual timer. It counts down whenever this process is
       executing. */
     if(loggingTimer.it_value.tv_usec != 0)
     {
         LOG(WARNING) << "Offline Logging started for " << 
                 (loggingTimer.it_value.tv_usec/1000) << " Minutes";
        setitimer (ITIMER_VIRTUAL, &loggingTimer, NULL);    
     }
}

void BrokerConnectionManager::processTimerEvent(int signum)
{
    if(!connected)
    {
        BrokerConnectionManager::isOffLoggingTimerEvent = true; 
    }
}
bool BrokerConnectionManager::getLoggingPermission()
{
    return isOffLoggingTimerEvent;
}