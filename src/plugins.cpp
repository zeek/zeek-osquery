#include <osquery/logger.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>

#include "plugins.h"
#include "utils.h"
#include "BrokerManager.h"

namespace pt = boost::property_tree;

namespace osquery {

    Status BroLoggerPlugin::setUp() {

        // TODO: Ensure FLAGS_bro_endpoint is a valid IP/hostname
        return Status(0, "OK");
    }

    Status BroLoggerPlugin::logString(const std::string& s) {
        QueryLogItem item;
        Status status = deserializeQueryLogItemJSON(s, item);
        if ( status.getCode() == 0 ) {
            //printQueryLogItemJSON(s);
        } else {
            LOG(ERROR) << "Parsing query result FAILED";
            return Status(1, "Failed to deserialize QueryLogItem");
        }
        return BrokerManager::getInstance()->logQueryLogItemToBro(item);
    }

    Status BroLoggerPlugin::logSnapshot(const std::string& s) {
        //LOG(ERROR) << "logSnapshot = " << s;
        return this->logString(s);
    }

    Status BroLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
        LOG(ERROR) << "logStatus = ";
        // NOT IMPLEMENTED
        return Status(1, "Not implemented");
    }


    void BroLoggerPlugin::init(const std::string& name,
                               const std::vector<StatusLogLine>& log) {

    }



    Status BroConfigParserPlugin::setUp() {
        data_.put_child("bro", pt::ptree());
        return Status(0, "OK");
    }

    Status BroConfigParserPlugin::update(const std::string &source,
                                         const ParserConfig &config) {
        if (config.count("bro") > 0) {
            data_ = pt::ptree();
            data_.put_child("bro", config.at("bro"));
        }

        const auto &options = data_.get_child("bro");
        for (const auto &option : options) {
            std::string value = options.get<std::string>(option.first, "");
            if (value.empty()) {
                continue;
            }
        }

        return Status(0, "OK");
    }

}