#include <osquery/sdk.h>
#include <osquery/system.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>

#include <BrokerManager.h>
#include <iostream>
#include <sstream>
#include <list>
#include <stdlib.h>     /* srand, rand */
#include <time.h>

namespace osquery {


    BrokerManager *BrokerManager::_instance = nullptr;

    BrokerManager::BrokerManager() {
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
        //TODO: read dynamic list
        return this->groups;//{"eu/de/HH/UHH"};
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
//////////////// Schedule/Query Handling ////////////////
/////////////////////////////////////////////////////////

    std::string BrokerManager::addBrokerOneTimeQueryEntry(const SubscriptionRequest &qr) {
        const std::string queryID = std::to_string(this->_nextUID++);
        if (addBrokerQueryEntry(queryID, qr, "ONETIME").ok())
            return queryID;
        else
            return "-1";
    }

    osquery::Status BrokerManager::addBrokerScheduleQueryEntry(const SubscriptionRequest &qr) {
        const std::string queryID = std::to_string(this->_nextUID++);
        return addBrokerQueryEntry(queryID, qr, "SCHEDULE");
    }

    Status
    BrokerManager::addBrokerQueryEntry(const std::string &queryID, const SubscriptionRequest &qr, std::string qtype) {
        std::string query = qr.query;
        std::string response_event = qr.response_event;
        std::string response_topic = qr.response_topic;
        int interval = qr.interval;
        bool added = qr.added;
        bool removed = qr.removed;
        bool snapshot = qr.snapshot;
        if (this->brokerScheduleQueries.find(queryID) != this->brokerScheduleQueries.end() or
            this->brokerOneTimeQueries.find(queryID) != this->brokerOneTimeQueries.end()) {
            LOG(ERROR) << "QueryID '" << queryID << "' already exists";
            return Status(1, "Duplicate queryID");
        }

        if (qtype == "SCHEDULE")
            this->brokerScheduleQueries[queryID] = BrokerScheduleQueryEntry{queryID, query, interval, added, removed,
                                                                            snapshot};
        else if (qtype == "ONETIME")
            this->brokerOneTimeQueries[queryID] = BrokerOneTimeQueryEntry{queryID, query};
        else
            LOG(ERROR) << "Unknown query type :" << qtype;
        this->eventNames[queryID] = response_event;
        this->eventTopics[queryID] = response_topic;
        return Status(0, "OK");
    }


    std::string BrokerManager::findIDForQuery(const std::string &query) {
        // Search the queryID for this specific query
        for (const auto &e: this->brokerScheduleQueries) {
            std::string queryID = e.first;
            BrokerScheduleQueryEntry bqe = e.second;
            if (std::get<1>(bqe) == query) {
                return queryID;
            }
        }

        for (const auto &e: this->brokerOneTimeQueries) {
            std::string queryID = e.first;
            BrokerOneTimeQueryEntry bqe = e.second;
            if (std::get<1>(bqe) == query) {
                return queryID;
            }
        }
        return "";
    }


    Status BrokerManager::removeBrokerQueryEntry(const std::string &query) {
        std::string queryID = this->findIDForQuery(query);
        if (queryID == "") {
            LOG(ERROR) << "Unable to find ID for query: '" << query << "'";
            return Status(1, "Unable to find ID for query");
        }

        // Delete query info
        this->eventTopics.erase(queryID);
        this->eventNames.erase(queryID);
        if (this->brokerScheduleQueries.find(queryID) != this->brokerScheduleQueries.end()) {
            LOG(INFO) << "Deleting schedule query '" << query << "' with queryID '" << queryID << "'";
            this->brokerScheduleQueries.erase(queryID);
        } else if (this->brokerOneTimeQueries.find(queryID) != this->brokerOneTimeQueries.end()) {
            LOG(INFO) << "Deleting onetime query '" << query << "' with queryID '" << queryID << "'";
            this->brokerOneTimeQueries.erase(queryID);
        }

        return Status(0, "OK");
    }

    std::string BrokerManager::getQueryConfigString() {
        // Format each query
        std::vector <std::string> scheduleQ;
        for (const auto &bq: brokerScheduleQueries) {
            auto i = bq.second;
            std::stringstream ss;
            ss << "\"" << std::get<0>(i) << "\": {\"query\": \"" << std::get<1>(i) << ";\", \"interval\": "
               << std::get<2>(i) << ", \"added\": " << std::get<3>(i) << ", \"removed\": " << std::get<4>(i)
               << ", \"snapshot\": " << std::get<5>(i) << "}";
            std::string q = ss.str();
            scheduleQ.push_back(q);
        }

        // Assemble queries
        std::stringstream ss;
        for (size_t i = 0; i < scheduleQ.size(); ++i) {
            if (i != 0)
                ss << ",";
            ss << scheduleQ[i];
        }
        std::string queries = ss.str();
        std::string config = std::string("{\"schedule\": {") + queries + std::string("} }");

        return config;
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


        // Is this schedule or one-time?
        std::string query;
        std::string qType;
        if (this->brokerScheduleQueries.find(queryID) != this->brokerScheduleQueries.end()) {
            qType = "SCHEDULE";
            query = std::get<1>(this->brokerScheduleQueries.at(queryID));
        } else if (this->brokerOneTimeQueries.find(queryID) != this->brokerOneTimeQueries.end()) {
            qType = "ONETIME";
            query = std::get<1>(this->brokerOneTimeQueries.at(queryID));
        } else {
            LOG(ERROR) << "QueryID not in brokerQueries";
            return Status(1, "Unknown QueryID");
        }

        // Rows to be reported
        std::vector <std::tuple<osquery::Row, std::string>> rows;
        for (const auto &row: qli.results.added) {
            rows.emplace_back(row, "ADDED");
        }
        for (const auto &row: qli.results.added) {
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
        std::string topic = this->eventTopics.at(queryID);
        std::string event_name = this->eventNames.at(queryID);
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
            this->removeBrokerQueryEntry(query);
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
