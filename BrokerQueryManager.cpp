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

#include "BrokerQueryManager.h"
#include "utility.h"


BrokerQueryManager::BrokerQueryManager(broker::endpoint* lhost,
        broker::message_queue* mq,std::string btp)
{
    //point to broker topic object
    this->bTopic = btp;
    this->firstTime = true;
    //point to local host object
    this->ptlocalhost = lhost;
    //pointer to message queue object
    this->ptmq = mq;
    getlogin_r(this->username,SIZE);
}



bool BrokerQueryManager::getEventsFromBrokerMessage()
{
    if(!event.empty())
    {
        event.clear();
    }
    for(int i=0;i<in_query_vector.size();i++)
    {
        std::string s= in_query_vector[i].ev_type;
        event.emplace_back(s);
    }
    return (!event.empty())? true: false;
}

bool BrokerQueryManager::queryColumnExtractor()
{
    if(!qmap.empty())
    {
        qmap.clear();
    }
    //loop for all input queries
    for(int i=0;i<in_query_vector.size();i++)
    {
        input_query print = in_query_vector.at(i);
        LOG(WARNING) <<print.query;
        // Extracts the columns in query using osquery::split function
        for(auto& c1: osquery::split(print.query,"SELECT"))
        {
            for(auto& c2: osquery::split(c1,"FROM"))
            {
                for(auto& c3: osquery::split(c2,","))
                {
                    qc.push_back(c3);
                }
                break;
            }
            break;
        }
        // stores the corresponding query columns
        qmap.insert(query_columns_map::value_type(i,qc));
        qc.clear();
    }
    return (!qmap.empty()) ? true: false;

}

bool BrokerQueryManager::queryDataResultVectorInit()
{
    if(!out_query_vector.empty())
    {
        out_query_vector.clear();
    }
    for(int i=0;i<in_query_vector.size();i++)
    {
        query_update temp;
        temp.current_results = getQueryResult(in_query_vector[i].query);
        if(in_query_vector[i].flag)
        {
            std::string init = "INIT_DUMP";
           sendUpdateEventToMaster(temp.current_results,
                init,i);
        }
        temp.old_results = temp.current_results;
        temp.current_results.clear();
        // 0.5sec delay
        usleep(500000);
        temp.current_results = getQueryResult(in_query_vector[i].query);
        out_query_vector.emplace_back(temp);
        this->firstTime = false;
    }
    LOG(WARNING) <<"Sending Updates...";
    return (!out_query_vector.empty()) ? true: false;
}

void BrokerQueryManager::queriesUpdateTrackingHandler()
{

    for(int i=0;i<out_query_vector.size();i++)
    {
        BrokerQueryManager::diffResultsAndEventTriger(i);
    }

}

QueryData BrokerQueryManager::getQueryResult(const std::string& queryString)
{
    QueryData qd;
    Status status = osquery::queryExternal(queryString, qd);
    if(!status.ok())
    {
        sendErrortoBro(status.what());
    }
    return qd;
}

void BrokerQueryManager::diffResultsAndEventTriger(int& i)
{
    //After each 1sec daemon will query
    //usleep(1000000);
    out_query_vector[i].current_results =
            getQueryResult(in_query_vector[i].query);

    //osquery::diff function to calculate difference in two query results
    // for corresponding query.
    diff_result = osquery::diff(out_query_vector[i].old_results,
            out_query_vector[i].current_results);

    // check if new rows added and master is also interested in added events
    if((diff_result.added.size() > 0) && (event[i]=="ADD" || event[i]=="BOTH"))
    {
        //if success then send update to master
        sendUpdateEventToMaster(diff_result.added,
                "ADDED",i);
    }
    // check if any rows deleted and master is also interested in removed events
    if((diff_result.removed.size() > 0) && (event[i]=="REMOVED" || event[i]=="BOTH"))
    {
        //if success then send update to master
        sendUpdateEventToMaster(diff_result.removed,
                "REMOVED",i);
    }
    out_query_vector.at(i).old_results = out_query_vector.at(i).current_results;
}


void BrokerQueryManager::sendUpdateEventToMaster(const QueryData& temp,
        std::string event_type, int& iterator)
{
    typedef std::map<std::string, std::string>::const_reverse_iterator pt;
    broker::message msg;
    for (auto& r: temp )
    {
        if(!qmap.empty() && !handle->gotExitSignal())
        {
            msg.emplace_back(in_query_vector[iterator].event_name);
            msg.push_back(ptlocalhost->name());
           // msg.push_back(username);
            msg.push_back(event_type);
            //iterator for no of columns in corresponding query
            for(int i=0;i<qmap[iterator].size() && !handle->gotExitSignal();i++)
            {
                // iterator for each row column
                for(pt iter = r.rbegin(); iter != r.rend(); iter++)
                {
                    if(iter->first == qmap[iterator][i])
                    {
                        //check if column value is integer
                        if(isQueryColumnInteger(iter->second))
                        {
                            msg.emplace_back(std::stoi(iter->second.c_str()));
                        }
                        else
                        {
                            msg.emplace_back(iter->second);
                        }
                        break;
                    }
                }
            }
            //send broker message
        LOG(WARNING) << msg;
        this->ptlocalhost->send(bTopic, msg);
        msg.clear();
        }
        this->ptmq->want_pop().clear();
    }
}

input_query BrokerQueryManager::brokerMessageExtractor(
const broker::message& msg)
{
    input_query temp;
    
    auto ev = broker::to_string(msg[0]);

    if ((ev != "osquery::host_subscribe") == (ev != "osquery::host_unsubscribe"))
    {
        throw(std::string("unexpected event ") + ev);
    }
    
    if( msg.size() != 5 )
    {
        throw(std::string("No of arguments wrong" + msg.size()));
    }
    //At start there would be only subscription msgs.
    //temp.sub_type = (ev == "osquery::host_subscribe")?true:false;
    //event name
    temp.event_name = broker::to_string(msg[1]);
    //returns the query  string
    temp.query = broker::to_string(msg[2]);
    //correct the formating
    temp.query = formateSqlString(temp.query);
    //event type "ADD", "REMOVE" or "BOTH"
    temp.ev_type = broker::to_string(msg[3]);
    std::transform(temp.ev_type.begin(), temp.ev_type.end(),
            temp.ev_type.begin(), ::toupper);
    temp.flag = (broker::to_string(msg[4]) == "1")?true:false;

    //will throw an exception if query is not a proper SQL string
    if(temp.query.substr(0,6)!= "SELECT")
    {
        this->sendErrortoBro("Please send Proper query");
        throw(std::string("Please send Proper formated query"));
    }
    else
        return temp;
}

bool BrokerQueryManager::ReInitializeVectors()
{
    firstTime = true;
    if(!out_query_vector.empty())
    {
        out_query_vector.clear();
    }
    if(!event.empty())
    {
        event.clear();
    }
    if(!qc.empty())
    {
        qc.clear();
    }
    if(!qmap.empty())
    {
        qmap.clear();
    }
    if(!in_query_vector.empty())
    {
        in_query_vector.clear();
    }
  return (in_query_vector.empty()) ? true :false;
}


bool BrokerQueryManager::isQueryColumnInteger(const std::string& str)
{
    if (str.empty())
        return false;
    if ((str[0] == '-' || str[0] == '+'))
        return std::all_of(str.begin()+1,str.end(), ::isdigit);
    // Iterates over all elements of string to check whether all number?
    return std::all_of(str.begin(),str.end(), ::isdigit);
}


void BrokerQueryManager::setSignalHandle(SignalHandler *s_handle)
{
    this->handle = s_handle;
}

void BrokerQueryManager::sendWarningtoBro(std::string str)
{
    broker::message msg;
    //push event name, mapped at bro-side
    msg.emplace_back("osquery::host_warning");
    // host message
    msg.emplace_back(ptlocalhost->name());
    //warning message
    msg.emplace_back(str);
    //send event in the form of broker message
    ptlocalhost->send(bTopic,msg);
}

void BrokerQueryManager::sendErrortoBro(std::string str)
{
    broker::message msg;
    //push event name, mapped at bro-side
    msg.emplace_back("osquery::host_error");
    // host message
    msg.emplace_back(ptlocalhost->name());
    //error message
    msg.emplace_back(str);
    //send event in the form of broker message
    ptlocalhost->send(bTopic,msg);
}

void BrokerQueryManager::sendReadytoBro()
{
    broker::message msg;
    //push event name, mapped at bro-side
    msg.emplace_back("osquery::host_ready");
    // host message
    msg.emplace_back(ptlocalhost->name());
    //send event in the form of broker message
    ptlocalhost->send(bTopic,msg);
}

std::string BrokerQueryManager::formateSqlString(std::string str)
{
    //First convert to lower case
    std::transform(str.begin(), str.end(),str.begin(), ::tolower);
    //Transform "select" to upper case
    std::transform(str.begin(), str.begin()+6 ,str.begin(), ::toupper);
    //search the find location
    int loc = str.find("from");
    //change to upper case
    std::transform(str.begin()+loc, str.begin()+loc+4 ,str.begin()+loc,
            ::toupper);

    return str;
}


bool BrokerQueryManager::addNewQueries(input_query in)
{
    //to trace the query location
    int loc = 0;
    //iterator
    std::vector<input_query>::iterator itr;
    //iterate over all entries
    for(itr = in_query_vector.begin(); itr != in_query_vector.end(); itr++)
    {
        if(itr->query == in.query)
            break;
        else
            loc++;      
    }
    //if not found
   if (loc == in_query_vector.size())
    {
       in_query_vector.emplace_back(in);
       return true;
    } 
   else
   {
       this->sendErrortoBro(in.query + " is already registered");
       return false;
   }
    
}

bool BrokerQueryManager::deleteOldQueries(input_query in)
{ 
    //to trace the query location
    int loc = 0;
    //iterator
    std::vector<input_query>::iterator itr;
    //iterate over all entries
    for(itr = in_query_vector.begin(); itr != in_query_vector.end(); itr++)
    {
        if(itr->query == in.query)
            break;
        else
            loc++;      
    }
    //if not found
   if (loc == in_query_vector.size())
    {
       this->sendErrortoBro(in.query + " is unregistered");
       return false;
    } 
   else
    {
      in_query_vector.erase(in_query_vector.begin() + loc);
      return true;
    }
}

bool BrokerQueryManager::getInQueryVectorStatus()
{
    return (!in_query_vector.empty())? true: false;
}