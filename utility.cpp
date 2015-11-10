/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 */
#include <signal.h>
#include <errno.h>
#include "utility.h"


/*
 * Start of SignalHandler Class member functions
 */

bool SignalHandler::mbGotExitSignal = false;


void SignalHandler::setupSignalHandler()
{
    if (signal((int) SIGINT, SignalHandler::exitSignalHandler) == SIG_ERR)
    {
        // through exception if kill signal is not registered
        throw SignalException("Error while Registering SIGINT signal");
    }
}

void SignalHandler::exitSignalHandler(int _ignored)
{
    mbGotExitSignal = true;
}


bool SignalHandler::gotExitSignal()
{
    return mbGotExitSignal;
}

void SignalHandler::setExitSignal(bool _bExitSignal)
{
    mbGotExitSignal = _bExitSignal;
}




/*
 * End of SignalException class member functions
 */

/*
 * Start of FileReader class member functions
 */
FileReader::FileReader()
{
    //initialize kPath with the file directory 
    kPath = "/var/osquery/broker.ini";
}

int FileReader::read()
{
    //check if file exits?
    auto s = osquery::pathExists(kPath);
    //if file exists then
    if(s.ok())
    {
        std::string content;
        //read file content
        s = osquery::readFile(kPath,content);
        //if file not empty
        if(s.ok())
        {
            std::string temp[6];
            //split into lines
            auto strings = osquery::split(content,"\n");
            for(int i=0; i<strings.size();i++)
            {
                //extract the value of interest
                auto sp = osquery::split(strings[i],"=");
                temp[i] = sp[1].substr(1,sp[1].size()-2);  
            }
            //assign values to hostName, broker-topic and broker_port
            hostName = temp[0];
            bTopic = temp[1];
            brPort = temp[2];
            masterIP = temp[3];
            retryInterval = temp[4];
            timerInterval = temp[5];
        }
        else
        {
            LOG(ERROR) << "Error reading file";
            return s.getCode();
        }
    }
    else
    {
        LOG(ERROR) << "The Path does not exists";
        return 1;
    }
    return 0;
}

std::string FileReader::getHostName()
{
    //return local host name
    return hostName;
}

std::string FileReader::getBrokerTopic()
{
    //return broker_topic in string form
    return bTopic;
}

std::string FileReader::getBrokerConnectionPort()
{
    //return broker port in string form
    return brPort;
}

std::string FileReader::getMasterIp()
{
    return masterIP;
}

std::string FileReader::getRetryInterval()
{
    return retryInterval;
}

std::string FileReader::getTimerInterval()
{
    return timerInterval;
}

/*
 * End of FileReader Class member functions
 */

std::string getLocalHostIp()
{
    //map::iterator to iterator over osquery::Row columns
    typedef std::map<std::string, std::string>::const_reverse_iterator pt;
    
    //Using osquery; queries interface_addresses table
    QueryData ip_table; 
    osquery::queryExternal("SELECT address FROM interface_addresses",ip_table);
    // loop over each interface Row
    for(auto& r: ip_table)
    {
        for(pt iter = r.rbegin(); iter != r.rend(); iter++)
        {
            if((iter->second).size()>9 && (iter->second).size()<16)
            {
                return iter->second;
            }
        }
        std::cout<<std::endl;
    }
    return "";
}
