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

/*State Machine Table:

       |PARAM_READ_   |CONNECTION  |TOPIC_RECEIVED |HOST        |HOST_SUBSCRIBE |HOST	      |HOST	    |SIG	 |CONNECTION   |TIMER       |
       |EVENT         |_ESTABLISHED|	           |_SUBSCRIBE  |_END	        |_UNSUBSCRIBE |_UNSUBSCRIBE |_KILL	 |_BROKEN      |_EVENT      |
       |	      |            |	           |            |	        |	      |_END	    |	         |	       |	    |
-------|--------------|------------|---------------|------------|---------------|-------------|-------------|------------|-------------|------------|
INIT   |pass control  |N-S--->WAIT_|illegitmate    |illegitimate|illegitmate    |illegitmate  |illegitmate  |free the    |free the     |stop-timer  |
       |to connection |_FOR_TOPIC  |event	   |event       |event	        |event	      |event	    |resources   |resources    |	    |
       |establishment |            |	           |            |		|	      |	            |and exit    |N-S----->INIT|	    |
       |	      |            |	           |            |		|	      |	            |gracefully  |	       |	    |
------ |--------------|------------|---------------|------------|---------------|-------------|-------------|------------|-------------|------------|
WAIT   |illegitimate  |illegitimate|extract and    |send warning|send_warning   |send_warning |send_warning |illegitimate|illegitimate |illegitimate|	
_FOR   |event         |event       |process topic  |to Broside  |to Broside	|to Broside   |to Broside   |event	 |event	       |event       |
_TOPIC |	      |            |N-S-->GET_AND_ |            |		|	      |	            |	         |	       |	    |
       |	      |            |PROCESS_QUERIES|            |		|	      |	            |	         |	       |	    |
-------|--------------|------------|---------------|------------|---------------|-------------|-------------|------------|-------------|------------|
GET    |illegitmate   |illegitmate |send warning   |add new     |process queries|delete given |process 	    |illegitimate|illegitmate  |track       |
_AND_  |event         |event       |to Bro-side    |query to    |and build 	|sql query    |queries and  |event	 |event	       |changes     |
PROCESS|	      |            |	           |local vector| vector	|from local   |build vector |	         |	       |and send    |
_QUER  |	      |            |	           |            |with updated   |vector	      |with updated |	         |	       |updates     |
IES    |	      |            |	           |            |values	        |	      |values	    |	         |	       |to Broside  |
-------|--------------|------------|---------------|------------|---------------|-------------|-------------|------------|-------------|------------|
TERMI- |illegitimate  |illegitimate|illegitmate    |illegitimate|illegitimate   |illegitimate |illegitimate |illegitimate|illegitimate |illegitimate|
NATE   |event         |event	   |event	   |event	|event	        | event	      |event	    |event	 |event	       |event       |

*/

#pragma once


#include <string>
#include <iostream>
#include <osquery/events.h>
#include <osquery/sql.h>
#include <osquery/sdk.h>
#include <osquery/registry.h>
#include <sstream>
#include <csignal>
#include <sys/time.h>
#include "BrokerConnectionManager.h"
#include "BrokerQueryManager.h"
#include "BrokerQueryPlugin.h"
#include "utility.h"


/**
 * This class implements the simple state machine operation. Its main function
 * is to track local as well as remote (bro-side) events and then do the 
 * allowed operations if the event is received in allowed operation state. 
 * If event is illegal then error/warning message will be delivered to bro-side.
 * 
 * This class has been written in an effort to eliminate or minimize the 
 * sequential/ordered execution.
 * 
 * It consists of four allowed states:
 * 1- INIT: 
 *          This is the initializing state in which we need to read broker.ini.
 *          If the reading process is successful then it also establishes the 
 *          connection with the Bro Master.
 * 2- WAIT_FOR_TOPIC: 
 *          In this state, "group topic event" is the only legitmite event. 
 *          When "group topic event" is received then it starts listening 
 *          for broker::messages on the newly received topic.
 * 3- GET_AND_PROCESS_QUERIES:
 *        This state is responsible for queries subscription and un-subscription
 *        and it also sends query updates when TIMER_EVENT is received.
 * 4- TERMINATE:
 *          In this state, occupied resources are freed and gracefully exits 
 *          from the module.
 *          . 
 */


enum State {INIT, WAIT_FOR_TOPIC,GET_AND_PROCESS_QUERIES,TERMINATE};

enum Event {TIMER_EVENT,CONNECTION_ESTABLISHED_EVENT,CONNECTION_BROKEN_EVENT, 
            SIG_KILL_EVENT, PARAM_READ_EVENT, TOPIC_RECEIVED_EVENT, 
            HOST_SUBSCRIBE_EVENT, HOST_SUBSCRIBE_END_EVENT,
            HOST_UNSUBSCRIBE_EVENT, HOST_UNSUBSCRIBE_END_EVENT, ILLEGAL_EVENT
            };
// To hold the current state
static State currentState;
 //To hold the event 
static Event currentEvent;

typedef std::deque<std::vector<broker::data>,
        std::allocator<std::vector<broker::data> > > PollData;



class StateMachine
{
private:
  // to store  the return values of BrokerQueryManager functions and
  // use it for comparison purpose
  bool processResponse;
  //connection response
  bool connectionResponse;
  // flag to check whether broker.ini is read or not
  int fileResponse;
  //to store getandSetTopic response 
  int topicResponse;
  //timer interval in millsec variable
  int timerInterval;
  // itimerval constructor to set initial value for timer.
  struct itimerval timer;
  //variable to check if timer has expired or has not
  static bool isTimerEvent;
  //SignalHandler object to trace kill signal
  SignalHandler *signalHandler;
  // BrokerConnectionManager class pointer
  BrokerConnectionManager* ptBCM;
  //FileReader Class Object
  FileReader fileReader;
  
  
private:
    /**
     * @brief To process the allowed actions in INIT state
     * This is the starting point of the state machine. File reading and 
     * connection establishment are done in this module.
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int initializeStateMachine();
    
    /**
     * @brief This function polls the broker messages form broker::queue
     * and returns the queue of messages if any; otherwise, it returns 
     * an empty queue.
     *  
     * @return returns a queue of messages
     */
    PollData waitForEvents();
    
    /**
     * @brief This function extracts event type from broker::message of
     * broker message queue and then passes that event for further processing
     * @param event represents the events received (local or remote) after 
     * polling process extracts the message form queue of broker::message.
     * @param msg broker::message received during polling process
     * 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int extractAndProcessEvents(int event,broker::message msg);
    
    /**
     * @brief To process the actions based on an event type in WAIT_FOR_TOPIC 
     * state. In this state kill signal and wait_for_topic are
     * allowed events all other are illegal events.
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int processEventsInWaitForTopicState(int event,broker::message msg);
    
    /**
     * @brief performs the required tasks when group topic is received
     * @param msg broker::message containing group topic 
     * 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForGroupTopicEvent(broker::message msg);
    
    /**
     * @brief To process the actions based on event type in
     * GET_AND_PROCESS_QUERIES state. In this state kill signal, subscribe,
     * un-subscribe, subscribe and un-subscribe end and timer events are allowed. 
     * All other events are illegal events.
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int processEventsInGetAndProcessQueriesState(int ev, broker::message msg);
    
    /**
     * @brief performs the required actions after "host subscribe event" is 
     * received.
     * @param msg broker::message containing subscription query 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForHostSubscribeEvent(broker::message msg);
    
    /**
     * @brief performs the required actions after "host subscribe end" event
     * The main actions are to process received queries and initialize vectors
     * with corresponding data.
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForHostSubscribeEndEvent();
    
    /**
     * @brief performs the required actions after "host subscribe end" event is 
     * received.
     * @param msg broker::message containing un-subscription query
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForHostUnSubscribeEvent(broker::message msg);
    
    /**
     * @brief performs the required actions after "host un-subscribe end" event
     * The main actions are to process received queries and initialize vectors
     * with corresponding data.
     * 
     * TODO: subscription and un-subscription end event might be same in future
     * 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForHostUnSubscribeEndEvent();
    
    /**
     * @brief To process the actions in TERMINATE state.
     * The main actions are to free the resources and graceful  shutdown.
     * 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int processEventsInTerminateState();
    
    /**
     * @brief performs the required actions after "kill signal event" is received
     * It will clean up the occupied resources.
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForKillSignalEvent();
    
    /**
     * @brief To find the next state of state machine based on the status 
     * code form the current state process functions.
     * 
     * @param statusCode Current state of state machine
     */
    void setNextState(int statusCode);
    
    /**
     * @breif A wrapper function to convert a string event to a corresponding 
     * Event ID.
     * @param in std::string input for mapping
     * 
     * @return returns the mapped event code 
     */
    int stringToEvent(std::string in);
    
     /**
     * @breif A wrapper function to convert an event ID to corresponding string
     * @param ev event input for mapping
     * 
     * @return returns the mapped event string 
     */
    std::string eventToString(int ev);
    
    /**
     * @brief initializes the timer structure with an initial value read from 
     * broker.ini file.
     * @param interval variable holding time in millsec 
     */
    void setupTimerInterval(int interval);
    
    /**
     * @brief This function will run the timer for one time only. For control
     * you need to call it manually where required. We are calling it when 
     * host subscription end event is received.
     */
    void initializeTimer();
    
    /**
     * @brief Timer signal handler function. We are setting the static variable
     * that will be checked later to process actions based on that event.
     * @signum signal value passed by signal generator
     */
    static void processTimerEvent(int signum);
    
    /**
     * @brief Actions performed after timer event
     * This will call the update function to process updates against registered 
     * SQL queries.
     * 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int doActionsForTimerEvent();
    
    /**
     * @brief When broker connection is broken then this function will free the
     * resources and set the pointer to entry point of machine. 
     */
    void doActionsForConnectionBrokenEvent();
    
public:
    
    /**
     * @brief Constructor 
     * To Initialize private member for safe usages
     * 
     * @param signalHandler pointer to signal handler object created in main()
     */
    StateMachine(SignalHandler *handler);
    
    
    /**
     * @brief The main function to operate the state machine. All state
     *  operations with state transitions will be managed in this function.
     * 
     * @return returns status code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int Run();
};
