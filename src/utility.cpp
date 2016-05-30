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
#include <boost/algorithm/string.hpp>
#include "utility.h"

using std::fstream;
using std::ios;
/*
 * Start of SignalHandler Class member functions
 */
//to track SIGKILL signal event
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
    //set SIGKILL signal flag
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
 * Start of FileReaderWriter class member functions
 */
FileReaderWriter::FileReaderWriter()
{
    //initialize kPath with the file directory 
    kPath = "/var/osquery/broker.ini";
}

int FileReaderWriter::read()
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
            std::string temp[7];
            //split into lines
            auto strings = lsplit(content,"\n");
            if(strings.size() != 7)
            {
                LOG(ERROR) << "ini file arguments mismatch";
                return -1;
            }
            for(int i=0; i<strings.size();i++)
            {
                //extract the value of interest
                auto sp = lsplit(strings[i],"=");
                temp[i] = sp[1].substr(1,sp[1].size()-2);
                //assign values to hostName, broker-topic and broker_port
                if(sp[0]=="HostName")
                {
                    hostName = temp[i];
                }
                else if(sp[0]== "broker_topic")
                {
                    bTopic = temp[i];
                }
                else if(sp[0]== "broker_port")
                {
                    brPort = temp[i];
                }
                else if(sp[0]== "master_ip")
                {
                    masterIP = temp[i];
                }
                else if(sp[0]== "retry_interval")
                {
                    retryInterval = temp[i];
                }
                else if(sp[0]== "timer_interval")
                {
                    timerInterval = temp[i];
                }
                else if(sp[0] == "offline_logging_interval")
                {
                    offlineLoggingInterval = temp[i];
                }
                else
                    LOG(WARNING) << sp[0] << " is not allowed in broker.ini";
                
            }
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

///////////////////////////////////////////////////////////////////////////
////////////////////Helper Function///////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

std::string FileReaderWriter::getHostName()
{
    //return local host name
    return hostName;
}

std::string FileReaderWriter::getBrokerTopic()
{
    //return broker_topic in string form
    return bTopic;
}

std::string FileReaderWriter::getBrokerConnectionPort()
{
    //return broker port in string form
    return brPort;
}

std::string FileReaderWriter::getMasterIp()
{
    return masterIP;
}

std::string FileReaderWriter::getRetryInterval()
{
    return retryInterval;
}

std::string FileReaderWriter::getTimerInterval()
{
    return timerInterval;
}

std::string FileReaderWriter::getOfflineLoggingInterval()
{
    return offlineLoggingInterval;
}
/*
 * End of FileReaderWriter Class member functions
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
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
///////////////////////Database class functions///////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
offlineSqliteDB::offlineSqliteDB()
{
    zErrMsg = 0;
    rc = 0;
}

int offlineSqliteDB::init()
{
    //to hold sql command
    char *sql;
    //////////////////////////////////////////////
    //output file stream
    std::ofstream dbfile;
    //create a file if it does not exits
    dbfile.open("/tmp/offlineLogs.db");
    //close the file
    dbfile.close();
    //////////////////////////////////////////////////////////
    //test if db file is accessable
    rc = sqlite3_open("/tmp/offlineLogs.db", &db);
    if (rc)
    {
	LOG(ERROR) << "Can't open database: " <<sqlite3_errmsg(db);
        return -1;
    }
    
    //sql command to create table with two enteries
    std::string tmpQuery = std::string("CREATE TABLE OFFLINELOGGING(")
            + std::string("ID INT PRIMARY KEY NOT NULL,")
            + std::string("EVENT TEXT NOT NULL);");
    sql = (char *)(tmpQuery.c_str());
    //Execute SQL command
    rc = sqlite3_exec (db, sql, callback, 0 ,&zErrMsg);
    //if no success
    if (rc != SQLITE_OK)
    {
        LOG(ERROR) << "SQL error: " << zErrMsg ;
    }
    //close the database file
    sqlite3_close(db);
    //success code = 1
    return 1;
}

int offlineSqliteDB::insertAnEvent(int count, std::string msg)
{
    db = NULL; rc = 0;
    char *sql;
    std::string tmpQuery;
    //test if db file is accessable
    rc = sqlite3_open("/tmp/offlineLogs.db", &db);
    if (rc)
    {
	LOG(ERROR) << "Can't open database: " <<sqlite3_errmsg(db);
        return -1;
    }
    
    tmpQuery = std::string("INSERT INTO OFFLINELOGGING (ID,EVENT)")
            + std::string("VALUES (")
            + std::string(std::to_string(count))
            + std::string(",")
            + std::string("\"")
            + msg 
            + std::string("\"")
            + std::string(");");
    
    sql = (char *)(tmpQuery.c_str());
    //Execute SQL command
    rc = sqlite3_exec (db, sql, callback, 0 ,&zErrMsg);
    //if no success
    if (rc != SQLITE_OK)
    {
        LOG(ERROR) << "SQL error: " << zErrMsg ;
    }
    //close the database file
    sqlite3_close(db);
}

std::string offlineSqliteDB::parseAnEvent(int count)
{
    db = NULL; rc = 0;
    //check if file exits?
    auto s = osquery::pathExists("/tmp/offlineLogs.db");
    //if file exists then
    if(s.ok())
    {
    
    char *sql;
    std::string tmpQuery;
    //test if db file is accessable
    rc = sqlite3_open("/tmp/offlineLogs.db", &db);
    if (rc)
    {
	LOG(ERROR) << "Can't open database: " <<sqlite3_errmsg(db);
        //return -1;
    }
    
    tmpQuery = std::string("SELECT * FROM OFFLINELOGGING WHERE ID == ")
            + std::to_string(count)
            + std::string(";");
    sql = (char *)(tmpQuery.c_str());
    //clear data before callback function operation
    cBData = "";
    //Execute SQL command
    rc = sqlite3_exec (db, sql, callback, 0 ,&zErrMsg);
    //if no success
    if (rc != SQLITE_OK)
    {
        LOG(ERROR) << "SQL error: " << zErrMsg ;
    }
    //close the database file
    sqlite3_close(db);
    }
    else
    {
        LOG(WARNING) << "DB file does not exits";
    }
    return cBData;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
///////////////////////Global functions///////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

std::vector<std::string> lsplit(const std::string& s, const std::string& delim) {
  std::vector<std::string> elems;
  boost::split(elems, s, boost::is_any_of(delim));
  auto start =
      std::remove_if(elems.begin(), elems.end(), [](const std::string& s) {
        return s.size() == 0;
      });
  elems.erase(start, elems.end());
  for (auto& each : elems) {
    boost::algorithm::trim(each);
  }
  return elems;
}

std::vector<std::string> lsplit(const std::string& s,
                               const std::string& delim,
                               size_t occurences) {
  // Split the string normally with the required delimiter.
  auto content = lsplit(s, delim);
  // While the result lsplit exceeds the number of requested occurrences, join.
  std::vector<std::string> accumulator;
  std::vector<std::string> elems;
  for (size_t i = 0; i < content.size(); i++) {
    if (i < occurences) {
      elems.push_back(content.at(i));
    } else {
      accumulator.push_back(content.at(i));
    }
  }
  // Join the optional accumulator.
  if (accumulator.size() > 0) {
    elems.push_back(join(accumulator, delim));
  }
  return elems;
}

int callback(void *data, int argc, char **argv, char **azColName)
{
    cBData = argv[1];
    return 0;
}

