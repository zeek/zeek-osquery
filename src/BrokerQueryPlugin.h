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

#include <osquery/logger.h>
#include <osquery/sdk.h>

using namespace osquery;

class BrokerQueryManagerPlugin : public ConfigPlugin {
public:
    //Default Constructor
    BrokerQueryManagerPlugin() {}
    
    /**
     * @brief ConfigPlugin function; set to default
     * @param config Not used but required by function prototype
     * @return osquery::Status set it to "Not used"
     */
    Status genConfig(std::map<std::string,std::string>& config);
    
    //Default Destructor
    ~BrokerQueryManagerPlugin() {}
};



