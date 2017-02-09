#include <osquery/sdk.h>
#include <osquery/flags.h>
#include <osquery/system.h>
//#include <osquery/database.h>

//#include "logger.h"
#include "BrokerManager.h"
#include "QueryManager.h"
//#include "Parser.h"
#include "utils.h"
#include "plugins.h"

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include <iostream>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

using namespace osquery;

REGISTER_EXTERNAL(BroLoggerPlugin, "logger", "bro");
REGISTER_EXTERNAL(BroConfigParserPlugin, "config_parser", "bro");

void signalHandler(int signum) {
    LOG(INFO) << "Interrupt signal (" << signum << ") received";

    // TODO Announce this node goes offline

    exit(signum);
}


int main(int argc, char *argv[]) {

    signal(SIGINT, signalHandler);

    // Setup OSquery Extension
    LOG(INFO) << "Starting osquery extention: bro-osquery";
    Initializer runner(argc, argv, ToolType::EXTENSION);
    auto status_ext = startExtension("bro-osquery", "1.0.0");
    if (!status_ext.ok()) {
        LOG(ERROR) << status_ext.getMessage();
        runner.requestShutdown(status_ext.getCode());
    }

    // Parse the config for Bro options
    LOG(INFO) << "Parsing Bro configuration";
    BroConfigParser bro_parser;
    auto status_options = bro_parser.parseBroOptions();
    if (!status_options.ok()) {
        LOG(ERROR) << status_options.getMessage();
        runner.requestShutdown(status_options.getCode());
    }
    // UID + Groups (parsed options)
    std::string bro_uid = bro_parser.getUID();
    std::vector<std::string> bro_groups;
    bro_parser.getGroups(bro_groups);

    // Setup Broker Endpoint
    LOG(INFO) << "Setup Broker Manager";
    broker::init();
    BrokerManager *bm = BrokerManager::getInstance();
    QueryManager *qm = QueryManager::getInstance();
    // UID
    if ( ! bro_uid.empty() )
        bm->setNodeID( bro_uid );
    std::string uid = bm->getNodeID();
    // Subscribe to all and individual topic
    bm->createEndpoint(uid);
    bm->createMessageQueue(bm->TOPIC_ALL);
    bm->createMessageQueue(bm->TOPIC_PRE_INDIVIDUALS + uid);
    // Subscribe to group topics
    for (std::string g: bro_groups) {
        bm->addGroup(g);
    }

    // Connect to Bro and send announce message
    LOG(INFO) << "Connecting to '" << bro_parser.getBro_IP() << ":" << bro_parser.getBro_Port() << "'";
    auto status_broker = bm->peerEndpoint(bro_parser.getBro_IP(), bro_parser.getBro_Port());
    if (!status_broker.ok()) {
        LOG(ERROR) << status_broker.getMessage();
        runner.requestShutdown(status_broker.getCode());
    }
    LOG(INFO) << "Broker connection established. " << "Ready to process, entering main loop.";

/*
 *
 * MAIN Loop
 *
 */

    // Wait for schedule requests
    fd_set fds;
    std::vector <std::string> topics;
    int sock;
    broker::message_queue *queue = nullptr;
    while (true) {
        // Retrieve info about each message queue
        FD_ZERO(&fds);
        bm->getTopics(topics); // List of subscribed topics
        int sMax = 0;
        for (auto topic: topics) {
            sock = bm->getMessageQueue(topic)->fd();
            if (sock > sMax) { sMax = sock; }
            FD_SET(sock, &fds); // each topic -> message_queue -> fd
        }
        // Wait for incoming message
        if (select(sMax + 1, &fds, NULL, NULL, NULL) < 0) {
            LOG(ERROR) << "Select returned an error code";
            continue;
        }

        // Check for the socket where a message arrived on
        for (auto topic: topics) {
            queue = bm->getMessageQueue(topic);
            sock = queue->fd();
            if (FD_ISSET(sock, &fds)) {

                // Process each message on this socket
                for (auto &msg: queue->want_pop()) {
                    // Check Event Type
                    if ( msg.size() < 1 or ! broker::is<std::string>(msg[0]) ) {
                        LOG(WARNING) << "No or invalid event name";
                        continue;
                    }
                    std::string eventName = *broker::get<std::string>(msg[0]);
                    LOG(INFO) << "Received event '" << eventName << "' on topic '" << topic << "'";

                    // osquery::host_execute
                    if (eventName == bm->EVENT_HOST_EXECUTE) {
                        // One-Time Query Execution
                        SubscriptionRequest sr;
                        createSubscriptionRequest("EXECUTE", msg, topic, sr);
                        std::string newQID = qm->addOneTimeQueryEntry(sr);
                        if (newQID == "-1") {
                            LOG(ERROR) << "Unable to add Broker Query Entry";
                            runner.requestShutdown(1);
                        }

                        // Execute the query
                        LOG(INFO) << "Executing one-time query: " << sr.response_event << ": " << sr.query;
                        QueryData results;
                        auto status_query = osquery::queryExternal(sr.query, results);
                        if (!status_query.ok()) {
                            LOG(ERROR) << status_query.getMessage();
                            runner.requestShutdown(status_query.getCode());
                        }

                        if (results.empty()) {
                            LOG(INFO) << "One-time query: " << sr.response_event << " has no results";
                            qm->removeQueryEntry(sr.query);
                            continue;
                        }

                        // Assemble a response item (as snapshot)
                        QueryLogItem item;
                        item.name = newQID;
                        item.identifier = osquery::getHostIdentifier();
                        item.time = osquery::getUnixTime();
                        item.calendar_time = osquery::getAsciiTime();
                        item.snapshot_results = results;

                        // Send snapshot to the logger
                        std::string registry_name = "logger";
                        std::string item_name = "bro";
                        std::string json;
                        serializeQueryLogItemJSON(item, json);
                        PluginRequest request = {{"snapshot", json},
                                                 {"category", "event"}};
                        auto status_call = osquery::Registry::call(registry_name, item_name, request);
                        if (!status_call.ok()) {
                            std::string error = "Error logging the results of one-time query: " + sr.query + ": " +
                                                status_call.toString();
                            LOG(ERROR) << error;
                            Initializer::requestShutdown(EXIT_CATASTROPHIC, error);
                        }

                        continue;

                    // osquery::host_join
                    } else if (eventName == bm->EVENT_HOST_JOIN) {
                        std::string newGroup = *broker::get<std::string>(msg[1]);
                        bm->addGroup(newGroup);
                        continue;

                    // osquery::host_leave
                    } else if (eventName == bm->EVENT_HOST_LEAVE) {
                        std::string newGroup = *broker::get<std::string>(msg[1]);
                        bm->removeGroup(newGroup);
                        continue;

                    // osquery::host_subscribe
                    } else if (eventName == bm->EVENT_HOST_SUBSCRIBE) {
                        // New SQL Query Request
                        SubscriptionRequest sr;
                        createSubscriptionRequest("SUBSCRIBE", msg, topic, sr);
                        qm->addScheduleQueryEntry(sr);

                    // osquery::host_unsubscribe
                    } else if (eventName == bm->EVENT_HOST_UNSUBSCRIBE) {
                        // SQL Query Cancel
                        SubscriptionRequest sr;
                        createSubscriptionRequest("UNSUBSCRIBE", msg, topic, sr);
                        //TODO: find an UNIQUE identifier (currently the exact sql string)
                        std::string query = sr.query;

                        qm->removeQueryEntry(query);

                    } else if (eventName == "osquery::host_test") {


                    } else {
                        // Unkown Message
                        LOG(ERROR) << "Unknown Event Name: '" << eventName << "'";
                        LOG(ERROR) << "\t" << broker::to_string(msg);
                        continue;
                    }

                    // Apply to new config/schedule
                    std::map <std::string, std::string> config_schedule;
                    config_schedule["bro"] = qm->getQueryConfigString();
                    LOG(INFO) << "Applying new schedule: " << config_schedule["bro"];
                    osquery::Config::getInstance().update(config_schedule);
                }
            }
        }
    }

    LOG(ERROR) << "What happened here?";
    // Finally wait for a signal / interrupt to shutdown.
    runner.waitForShutdown();
    return 0;
}
