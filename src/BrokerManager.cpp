#include <osquery/sdk.h>
#include <osquery/system.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include "BrokerManager.h"
#include "QueryManager.h"
#include <iostream>
#include <sstream>
#include <list>
#include <stdlib.h>     /* srand, rand */
#include <time.h>

namespace osquery {


    BrokerManager *BrokerManager::_instance = nullptr;

    BrokerManager::BrokerManager() {
        this->qm = QueryManager::getInstance();
    }

    osquery::Status BrokerManager::setNodeID(const std::string &uid) {
        if (this->nodeID.empty()) {
            // Save new node ID
            this->nodeID = uid;
            return Status(0, "OK");

        } else {
            LOG(WARNING) << "Node ID already set to '" << this->nodeID << "' (new: '" << uid << "')";
            return Status(1, "Unable to set Node ID");
        }
    }

    std::string BrokerManager::getNodeID() {
        if (!this->nodeID.empty()) {
            return this->nodeID;
        }

        // Try to derive from all MACs
        QueryData mac_results;
        auto status_if = osquery::queryExternal("SELECT mac from interface_details", mac_results);
        if (!status_if.ok()) {
            // Random ID is MAC info is not available
            LOG(ERROR) << status_if.getMessage();
            LOG(ERROR) << "Generating random temporary ID instead";
            // Generate Random ID
            if (this->nodeID == "") {
                const char alphanum[] =
                        "0123456789"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                std::stringstream ss;
                for (int i = 0; i < 64; ++i)
                    ss << alphanum[rand() % (sizeof(alphanum) - 1)];
                this->nodeID = ss.str();
            }
        } else {
            // Hash all MACs
            std::hash <std::string> hash_fn;
            std::stringstream macs;
            for (const auto &row: mac_results) {
                macs << row.at("mac");
            }
            size_t str_hash = hash_fn(macs.str());

            // Convert to Hex String
            std::stringstream hs;
            hs << std::hex << str_hash;
            this->nodeID = hs.str();
        }

        LOG(INFO) << "New Node ID: " << this->nodeID;
        return this->nodeID;
    }

    osquery::Status BrokerManager::addGroup(const std::string &group) {
        this->groups.push_back(group);
        return this->createMessageQueue(this->TOPIC_PRE_GROUPS + group);
    }

    std::vector <std::string> BrokerManager::getGroups() {
        return this->groups;
    }

/////////////////////////////////////////////////////////
//////////// Endpoint ///////////////////////////////////
/////////////////////////////////////////////////////////

    Status BrokerManager::createEndpoint(std::string ep_name) {
        if (this->ep != nullptr) {
            LOG(ERROR) << "Broker Endpoint already exists";
            return Status(1, "Broker Endpoint already exists");
        }
        this->ep = new broker::endpoint(ep_name);
        return Status(0, "OK");
    }

    broker::endpoint *BrokerManager::getEndpoint() {
        return this->ep;
    }

    Status BrokerManager::createMessageQueue(std::string topic) {
        if (this->messageQueues.find(topic) == this->messageQueues.end()) {
            LOG(INFO) << "Creating message queue: " << topic;
            broker::message_queue *mq = new broker::message_queue(topic, *(this->ep));
            this->messageQueues[topic] = mq;
            return Status(0, "OK");
        }
        return Status(1, "Message queue exists for topic");
    }

    broker::message_queue *BrokerManager::getMessageQueue(std::string topic) {
        return this->messageQueues.at(topic);
    }

    Status BrokerManager::getTopics(std::vector <std::string> &topics) {
        topics.clear();
        //for (auto it = this->messageQueues.begin(); it != this->messageQueues.end(); it++) {
        for (const auto &mq: this->messageQueues) {
            topics.push_back(mq.first); // append topic
        }
        return Status(0, "OK");
    }

    Status BrokerManager::peerEndpoint(std::string ip, int port) {
        LOG(INFO) << "Connecting...";
        if (this->ep == nullptr) {
            LOG(ERROR) << "Broker Endpoint nto set";
            return Status(1, "Broker Endpoint not set");
        }

        this->ep->peer(ip, port);
        auto cs = this->ep->outgoing_connection_status().need_pop().front();
        if (cs.status != broker::outgoing_connection_status::tag::established) {
            LOG(ERROR) << "Failed to connect to bro endpoint";
            return Status(1, "Failed to connect");
        }

        // Announce this endpoint to be a bro-osquery extension
        // Collect Groups
        broker::vector group_list;
        for (std::string g: this->getGroups()) {
            group_list.push_back(g);
        }
        // Collect IPs
        QueryData addr_results;
        auto status_if = osquery::queryExternal("SELECT address from interface_addresses", addr_results);
        if (!status_if.ok()) {
            LOG(ERROR) << status_if.getMessage();
            return Status(1, "Failed to retrieve interface addresses");
        }
        broker::vector addr_list;
        for (auto row: addr_results) {
            std::string if_mac = row.at("address");
            addr_list.push_back(broker::address::from_string(if_mac).get());
        }
        // Create Message
        broker::message announceMsg = broker::message{this->EVENT_HOST_NEW, this->getNodeID(), group_list, addr_list};
        this->sendEvent(TOPIC_ANNOUNCE, announceMsg);

        return Status(0, "OK");
    }


/////////////////////////////////////////////////////////
//////////////// Broker Send Methods/////////////////////
/////////////////////////////////////////////////////////


    Status BrokerManager::logQueryLogItemToBro(const QueryLogItem &qli) {
        // Attributes from QueryLogItem
        std::string queryID = qli.name; // The QueryID
//  std::string identifier = qli.identifier; // The HostID
//  size_t time = qli.time;
//  std::string calendar_time = qli.calendar_time;
//  std::map<std::string, std::string> decorations = qli.decorations;me;


        // Is this schedule or one-time? Get Query and Type
        std::string query;
        std::string qType;
        auto status_find = this->qm->findQueryAndType(queryID, qType, query);
        if ( !status_find.ok() ) {
            return status_find;
        }

        // Rows to be reported
        std::vector <std::tuple<osquery::Row, std::string>> rows;
        for (const auto &row: qli.results.added) {
            rows.emplace_back(row, "ADDED");
        }
        for (const auto &row: qli.results.removed) {
            rows.emplace_back(row, "REMOVED");
        }
        for (const auto &row: qli.snapshot_results) {
            rows.emplace_back(row, "SNAPSHOT");
        }

        // Get Info about SQL Query and Types
        TableColumns columns;
        Status status = getQueryColumnsExternal(query, columns);
        std::map <std::string, ColumnType> columnTypes;
        for (std::tuple <std::string, ColumnType, ColumnOptions> t: columns) {
            std::string columnName = std::get<0>(t);
            ColumnType columnType = std::get<1>(t);
//      ColumnOptions columnOptions = std::get<2>(t);
            columnTypes[columnName] = columnType;
//    LOG(INFO) << "Column named '" << columnName << "' is of type '" << kColumnTypeNames.at(columnType) << "'";
        }

        // Common message fields
        std::string uid = this->getNodeID();
        std::string topic = this->qm->getEventTopic(queryID);
        std::string event_name = this->qm->getEventName(queryID);
        LOG(INFO) << "Creating " << rows.size() << " messages for events with name :'" << event_name << "'";


        // Create message for each row
        for (const auto &element: rows) {
            // Get row and trigger
            osquery::Row row = std::get<0>(element);
            std::string trigger = std::get<1>(element);

            // Set event name, uid and trigger
            broker::message msg;
            msg.push_back(event_name);
            msg.push_back(uid);
            msg.push_back(trigger);

            // Format each column
            for (std::tuple <std::string, ColumnType, ColumnOptions> t: columns) {
                std::string colName = std::get<0>(t);
                if ( row.count(colName) != 1 ) {
                    LOG(ERROR) << "Column '" << colName << "' not present in results for '" << event_name << "'";
                    break;
                }
                std::string value = row.at(colName);
                switch (columnTypes.at(colName)) {
                    case ColumnType::UNKNOWN_TYPE : {
                        LOG(ERROR) << "Sending unknown column type as string";
                        msg.push_back(value);
                        break;
                    }
                    case ColumnType::TEXT_TYPE : {
                        msg.push_back(AS_LITERAL(TEXT_LITERAL, value));
                        break;
                    }
                    case ColumnType::INTEGER_TYPE : {
                        msg.push_back(AS_LITERAL(INTEGER_LITERAL, value));
                        break;
                    }
                    case ColumnType::BIGINT_TYPE : {
                        msg.push_back(AS_LITERAL(BIGINT_LITERAL, value));
                        break;
                    }
                    case ColumnType::UNSIGNED_BIGINT_TYPE : {
                        msg.push_back(AS_LITERAL(UNSIGNED_BIGINT_LITERAL, value));
                        break;
                    }
                    case ColumnType::DOUBLE_TYPE : {
                        msg.push_back(AS_LITERAL(DOUBLE_LITERAL, value));
                        break;
                    }
                    case ColumnType::BLOB_TYPE : {
                        LOG(ERROR) << "Sending blob column type as string";
                        msg.push_back(value);
                        break;
                    }
                    default : {
                        LOG(ERROR) << "Unkown ColumnType!";
                        continue;
                    }
                }
            }

            // Send event message
            this->sendEvent(topic, msg);
        }

        // Delete one-time query information
        if (qType == "ONETIME") {
            this->qm->removeQueryEntry(query);
        }

        return Status(0, "OK");
    }

    Status BrokerManager::sendEvent(const std::string &topic, const broker::message &msg) {
        if (this->ep == nullptr) {
            LOG(ERROR) << "Endpoint not set yet!";
            return Status(1, "Endpoint not set");
        } else {
            //LOG(INFO) << "Sending Message: " << broker::to_string(msg) << " to " << topic;
            this->ep->send(topic, msg);
        }

        return Status(0, "OK");
    }

}
