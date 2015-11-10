/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 */

#include "StateMachine.h"

bool StateMachine::isTimerEvent = false;

StateMachine::StateMachine(SignalHandler* handler)
{
    timerInterval = 0;
 
    //set the signal handler
    signalHandler = handler;
    //set connectionResponse to false
    connectionResponse = false;
    // set fileResponse to false
    fileResponse = false;
    // set processResponse to false
    processResponse = false;
    // set topicResponse to false;
    topicResponse = false;
    //set pointer of BrokerConnectionMnager to NULL
    ptBCM = NULL;
}


int StateMachine::initializeStateMachine()
{
    //set currentState to INIT at start
    currentState = INIT;
    //Reads hostName, broker_topic and broker_port form broker.ini file
     fileResponse = fileReader.read();
     // if reading is not successful
     if (fileResponse != 0)
     {
         return  KILL_SIGNAL;
     }
     
     //initialize the timer with timer_interval after reading broker.ini
     timerInterval = std::atoi(fileReader.getTimerInterval().c_str());
     setupTimerInterval(timerInterval);
     
     // if reading is successful
     // then make a broker connection manager object
    ptBCM = new BrokerConnectionManager(getLocalHostIp(),
        fileReader.getBrokerTopic(),
        std::atoi(fileReader.getBrokerConnectionPort().c_str()));

    connectionResponse = false;
    // Try to establish connection with master at IP given in
    // "broker.ini"
    connectionResponse = ptBCM->connectToMaster(fileReader.getMasterIp()
            ,std::chrono::duration<double>
    (std::atoi(fileReader.getRetryInterval().c_str())), signalHandler);
    //if the connection is not established then there must be CTRL +C
    if(!connectionResponse)
    {
        return  KILL_SIGNAL;
    }
    else
    {
        return SUCCESS; 
    }
}

PollData StateMachine::waitForEvents()
{
    //broker dequeue object
    PollData msgQueue;
    // poll message queue with polling time=0
    int rv = poll(ptBCM->getPollfdPointer() ,1, 0);
    // if pooling response is not of time out or queue is empty
    if(!(rv== -1) && !(rv==0))
    {
        //loop for all messages in queue
       msgQueue = ptBCM->getMessageQueuePointer()->want_pop();
       return msgQueue;
    }
    else
    {
        msgQueue.clear();
        return msgQueue;
    }
    
}

int StateMachine::extractAndProcessEvents(int event,broker::message msg)
{
    int statusCode = 0;
    
    switch(currentState)
    {
        case WAIT_FOR_TOPIC:
            {
                statusCode = processEventsInWaitForTopicState(event,msg);
                break;
            }
        case GET_AND_PROCESS_QUERIES:
            {
                statusCode = processEventsInGetAndProcessQueriesState(event,msg);
                break;  
            }
        case TERMINATE:
        {
            statusCode = processEventsInTerminateState();
            return statusCode;
        }
        default:
        {
            LOG(WARNING) << "ILLEGAL state" ;
        }
    };
    return statusCode;
}

int StateMachine::processEventsInWaitForTopicState(int ev,
        broker::message msg)
{
    int statusCode = 0;
    switch(ev)
    {
        case TOPIC_RECEIVED_EVENT:
        {
            statusCode = doActionsForGroupTopicEvent(msg);
            setNextState(statusCode);
            break;
        }
        case SIG_KILL_EVENT:
        {
            statusCode = doActionsForKillSignalEvent();
            return statusCode;
        }
        case TIMER_EVENT:
        {
            //stop the timer.In this state timer is not allowed.
            StateMachine::isTimerEvent = false;
            break;
        }
        case CONNECTION_BROKEN_EVENT:
        {
            doActionsForConnectionBrokenEvent();
            break;
        }
        default:
        {
            std::ostringstream stringStream;
            stringStream << eventToString(ev) << " is not allowed in " <<
                    "WAIT_FOR_TOPIC" << "expecting group topic events";
            LOG(WARNING) << stringStream;
            ptBCM->getQueryManagerPointer()->
                sendErrortoBro(stringStream.str());
        }
    };
}

int StateMachine::doActionsForGroupTopicEvent(broker::message msg)
{
    //read the group topic
    auto topic = broker::to_string(msg[1]);
    LOG(WARNING) << "Group Topic: " << topic;
    //set the new group topic
    int statusCode = ptBCM->getAndSetTopic(topic);
    
    if (statusCode == 0)
    {
        LOG(WARNING) << "Connection Broken" ;

        //delete  BrokerConnectionManager Object
        delete ptBCM;
        return FAILURE;
    }
    else if(topicResponse == -1)
    {
        return KILL_SIGNAL;
    }
    else
    {
        return SUCCESS;
    }
}

int StateMachine::processEventsInGetAndProcessQueriesState(int ev,
        broker::message msg)
{ 
    int statusCode = 0;
    switch(ev)
    {
        case SIG_KILL_EVENT:
        {
            statusCode = doActionsForKillSignalEvent();
            return statusCode;
        }
        case HOST_SUBSCRIBE_EVENT:
        {
            doActionsForHostSubscribeEvent(msg);
            break;
        }
        case HOST_SUBSCRIBE_END_EVENT:
        {
            statusCode = doActionsForHostSubscribeEndEvent();
            break;
        }
        case HOST_UNSUBSCRIBE_EVENT:
        {
            doActionsForHostUnSubscribeEvent(msg);
            break;
        }
        case HOST_UNSUBSCRIBE_END_EVENT:
        {
            doActionsForHostUnSubscribeEndEvent();
            break;
        }
        case CONNECTION_BROKEN_EVENT:
        {
            doActionsForConnectionBrokenEvent();
            break;
        }
        case TIMER_EVENT:
        {
            doActionsForTimerEvent();
            break;
        }
        default:
        {
            std::ostringstream stringStream;
            stringStream << eventToString(ev) << " is not allowed in " <<
                  "GET_AND_PROCESS_QUERIES " << "expecting subscription events";
            LOG(WARNING) << stringStream;
            ptBCM->getQueryManagerPointer()->
                sendErrortoBro(stringStream.str());
        }
    };
    
}

int StateMachine::doActionsForHostSubscribeEvent(broker::message msg)
{
    //temporary variable for input queries
    input_query inString;
    try
    {
        //try extracting broker::message
        inString = ptBCM->getQueryManagerPointer()->brokerMessageExtractor(msg);
        //if extraction is successful then add that query to local query vector
        ptBCM->getQueryManagerPointer()->addNewQueries(inString);
        
    }
    catch(std::string e)
    {
        LOG(WARNING) <<e ;
    } 
    return SUCCESS;
}

int StateMachine::doActionsForHostSubscribeEndEvent()
{
    int statusCode;
    statusCode = ptBCM->processQueriesVectors();
    if(!statusCode)
    {
        ptBCM->closeBrokerConnection();
        LOG(WARNING) << "Could not Process Queries";

        //reestablish connection and process queries.
        LOG(WARNING) << "Connection Broken" ;
        // if connection is down then reinitialize all query vectors
        ptBCM->getQueryManagerPointer()->ReInitializeVectors();
        //delete  BrokerConnectionManager Object
        delete ptBCM;
    }
    else
    {
        initializeTimer();
    } 
    return statusCode;
}

int StateMachine::doActionsForHostUnSubscribeEvent(broker::message msg)
{
    input_query inString;
    try
    {
        //try extracting broker::message
        inString = ptBCM->getQueryManagerPointer()->brokerMessageExtractor(msg);
        //if that query already exists then delete it.
        ptBCM->getQueryManagerPointer()->deleteOldQueries(inString);
        
    }
    catch(std::string e)
    {
        LOG(WARNING) <<e ;
    } 
    return SUCCESS;
}

int StateMachine::doActionsForHostUnSubscribeEndEvent()
{
    int statusCode = doActionsForHostSubscribeEndEvent();
    return statusCode;
}

int StateMachine::processEventsInTerminateState()
{
    ptBCM->getQueryManagerPointer()->sendWarningtoBro("CTRL+C" 
                        " Signal Received");
    //close broker connection
    ptBCM->closeBrokerConnection();
    // if connection is down then reinitialize all query vectors
    ptBCM->getQueryManagerPointer()->ReInitializeVectors();
    //delete  BrokerConnectionManager Object
    delete ptBCM;
    return SUCCESS;
}

int StateMachine::doActionsForKillSignalEvent()
{
    ptBCM->getQueryManagerPointer()->sendWarningtoBro("CTRL+C" 
                        " Signal Received");
    //close broker connection
    ptBCM->closeBrokerConnection();
    // if connection is down then reinitialize all query vectors
    ptBCM->getQueryManagerPointer()->ReInitializeVectors();
    //delete  BrokerConnectionManager Object
    delete ptBCM;
    
    return SIG_KILL_EVENT;
}

void StateMachine::setNextState(int statusCode)
{
    switch(currentState)
    {
        case INIT:
            {
                if(statusCode == KILL_SIGNAL)
                    currentState = TERMINATE;
                else if(statusCode == SUCCESS)
                    currentState = WAIT_FOR_TOPIC;
                break;
            }
        case WAIT_FOR_TOPIC:
            {
                if(statusCode == KILL_SIGNAL)
                    currentState = TERMINATE;
                else if(statusCode == SUCCESS)
                    currentState = GET_AND_PROCESS_QUERIES;
                else
                    currentState = INIT;
                break;
            }
        case GET_AND_PROCESS_QUERIES:
            {
                if(statusCode == KILL_SIGNAL)
                    currentState = TERMINATE;
                else if (statusCode == FAILURE)
                    currentState = INIT;
                else
                    currentState = currentState;
              break;  
            }
        LOG(WARNING) << currentState;
    };
}

int StateMachine::stringToEvent(std::string in)
{
    if(in == "SIG_KILL_EVENT")
    {
        return SIG_KILL_EVENT;
    }
    else if(in == "osquery::host_set_topic")
    {
        return TOPIC_RECEIVED_EVENT;
    }
    else if(in == "osquery::host_subscribe")
    {
        return HOST_SUBSCRIBE_EVENT;
    }
    else if(in == "osquery::host_subscribe_end")
    {
        return HOST_SUBSCRIBE_END_EVENT;
    }
    else if(in == "osquery::host_unsubscribe")
    {
        return HOST_UNSUBSCRIBE_EVENT;
    }
    else if(in == "osquery::host_unsubscribe_end")
    {
        return HOST_UNSUBSCRIBE_END_EVENT;
    }
    else if(in == "CONNECTION_BROKEN_EVENT")
    {
        return CONNECTION_BROKEN_EVENT;
    }
    else if(in == "CONNECTION_ESTABLISHED_EVENT")
    {
        return CONNECTION_ESTABLISHED_EVENT;
    }
    else
    {
        return ILLEGAL_EVENT;
    }
}

std::string StateMachine::eventToString(int ev)
{
    switch (ev)
    {
        case SIG_KILL_EVENT:
        {
            return "SIG_KILL_EVENT";
        }
        case TOPIC_RECEIVED_EVENT:
        {
            return "TOPIC_RECEIVED_EVENT";
        }
        case HOST_SUBSCRIBE_EVENT:
        {
            return "HOST_SUBSCRIBE_EVENT";
        }
        case HOST_SUBSCRIBE_END_EVENT:
        {
            return "HOST_SUBSCRIBE_END_EVENT";
        }
        case HOST_UNSUBSCRIBE_EVENT:
        {
            return "HOST_UNSUBSCRIBE_EVENT";
        }
        case HOST_UNSUBSCRIBE_END_EVENT:
        {
            return "HOST_UNSUBSCRIBE_END_EVENT";
        }
        default:
        {
            return "ILLEGAL_EVENT";
        }
    };
}

void StateMachine::setupTimerInterval(int interval)
{
    /* Configure the timer to expire after interval msec... */
     timer.it_value.tv_sec = 0;
     timer.it_value.tv_usec = interval;
     timer.it_interval.tv_sec = 0;
     timer.it_interval.tv_usec = 0;     
}

void StateMachine::initializeTimer()
{
     struct sigaction sa;

     /* Install timer_handler as the signal handler for SIGVTALRM. */
     memset (&sa, 0, sizeof (sa));
     sa.sa_handler = &(StateMachine::processTimerEvent);
     sigaction (SIGVTALRM, &sa, NULL);
    
     /* Start a virtual timer. It counts down whenever this process is
       executing. */
     setitimer (ITIMER_VIRTUAL, &timer, NULL);     
}

void StateMachine::processTimerEvent(int signum)
{
    StateMachine::isTimerEvent = true;
}


int StateMachine::doActionsForTimerEvent()
{
    ptBCM->trackResponseChangesAndSendResponseToMaster(
                signalHandler);
        StateMachine::isTimerEvent = false;
        /* Start a virtual timer. It counts down whenever this process is
       executing. */
       setitimer (ITIMER_VIRTUAL, &timer, NULL);
}


void StateMachine::doActionsForConnectionBrokenEvent()
{
    // if connection is down then reinitialize all query vectors
    ptBCM->getQueryManagerPointer()->ReInitializeVectors();
    //delete  BrokerConnectionManager Object
    delete ptBCM;
    
}

int StateMachine::Run()
{   
    int statusCode = 0;
    do
    {
        StateMachine::isTimerEvent = false;
        //initialize the state machine
        statusCode = initializeStateMachine();
        setNextState(statusCode);
        if(statusCode == SUCCESS)
        {
            do 
            {
                PollData tempQueue = waitForEvents();
                if(signalHandler->gotExitSignal())
                {
                    broker::message temp;
                    currentEvent = SIG_KILL_EVENT;
                    //pass kill signal to clean up the resources
                    extractAndProcessEvents(currentEvent,temp);
                   
                }
                else if(!ptBCM->isConnectionAlive())
                {
                    broker::message temp;
                    extractAndProcessEvents(CONNECTION_BROKEN_EVENT,temp);
                }
                else if(isTimerEvent)
                {
                    broker::message temp;
                    extractAndProcessEvents(TIMER_EVENT,temp);
                }
                else if(!tempQueue.empty())
                {
                    for(auto& msg : tempQueue)
                    {
                        if(signalHandler->gotExitSignal())
                        {
                            currentEvent = SIG_KILL_EVENT;
                            extractAndProcessEvents(currentEvent,msg);
                            break;
                        }
                        else
                        {
                            auto ev = broker::to_string(msg[0]);
                            statusCode = extractAndProcessEvents(
                                    stringToEvent(ev),msg);
                            if(statusCode == SIG_KILL_EVENT)
                            {
                                break;
                            }
                        }
                    }
                }
                else if(isTimerEvent)
                {
                    broker::message temp;
                    extractAndProcessEvents(TIMER_EVENT,temp);
                }
                
       
            }while(ptBCM->isConnectionAlive() &&
                    !signalHandler->gotExitSignal());
            if(signalHandler->gotExitSignal())
            {
                doActionsForKillSignalEvent();
            }
            
        }
        
    }while(!signalHandler->gotExitSignal());
    
    return SUCCESS;                
}
