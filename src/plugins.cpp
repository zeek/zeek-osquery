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



    Status BroConfigParser::parseBroOptions() {
        if ( this->parsed ) {
            LOG(ERROR) << "Bro Options already parsed";
            return Status(1, "Unable to parse Bro config");
        }

        // Dirty Hack: We have to retrieve and set the config ourselves before accessing options
        PluginResponse response;
        auto status = Registry::call("config", {{"action", "genConfig"}}, response);
        PluginRequest &config_filesystem = response.front();
        osquery::Config::getInstance().update(config_filesystem);

        // Retrieve Bro from Config:
        auto optionParser = osquery::Config::getInstance().getParser("bro").get();
        auto options = optionParser->getData().get_child("bro");

        for (const auto &option: options) {
            // BrokerEndpoint Address
            if (option.first == "bro_ip") {
                std::string bro_ip = options.get<std::string>(option.first);
                if ( ! bro_ip.empty() ) {
                    this->options_bro_ip = bro_ip;
                } else {
                    LOG(ERROR) << "bro_ip is empty";
                    return Status(1, "Unable to parse Bro config");
                }
            } else if (option.first == "bro_port") {
                int bro_port = options.get<int>(option.first);
                if ( bro_port > 0) {
                    this->options_bro_port = bro_port;
                } else {
                    LOG(ERROR) << "bro_port has invalid value: " << bro_port;
                    return Status(1, "Unable to parse Bro config");
                }
            }
            // UID
            else if (option.first == "uid") {
                std::string uid = options.get<std::string>(option.first);
                this->options_uid = uid;
            }
            // Groups
            else if (option.first == "groups") {
                auto groups_options = options.get_child(option.first);
                for ( const auto& group_option: groups_options ) {
                    std::string group = options.get<std::string>(option.first + "." + group_option.first);
                    this->options_groups.push_back(group);
                }
            }
            // Unknown
            else {
                LOG(WARNING) << "Unknown bro option: " << option.first;
            }
        }

        // Check parsed Bro Options
        // BrokerEndpoint Address
        if ( this->options_bro_ip.empty() ) {
            LOG(ERROR) << "Option bro.bro_ip was not given. Please specify in config.";
            return Status(1, "Invalid configuration");
        }
        if ( this->options_bro_port == -1 ) {
            int default_port = 9999;
            LOG(WARNING) << "Option bro.bro_port was not given. Assuming port " << default_port << ".";
            this->options_bro_port = default_port;
        }
        // UID
        if ( this->options_uid.empty() ) {
            LOG(INFO) << "Option bro.uid was not given. Generating one later.";
        }
        // Groups
        if ( this->options_groups.size() > 0 ) {
            LOG(INFO) << this->options_groups.size() << " initial groups found.";
        }

        this->parsed = true;
        return Status(0, "OK");
    }

    std::string BroConfigParser::getBro_IP() {
        if (parsed)
            return this->options_bro_ip;
        LOG(ERROR) << "Access to bro options before parsing config";
        return "";
    }

    int BroConfigParser::getBro_Port() {
        if (parsed)
            return this->options_bro_port;
        LOG(ERROR) << "Access to bro options before parsing config";
        return -1;
    }

    std::string BroConfigParser::getUID() {
        if (parsed)
            return this->options_uid;
        LOG(ERROR) << "Access to bro options before parsing config";
        return "";
    }

    void BroConfigParser::getGroups(std::vector<std::string>& groups) {
        if (parsed) {
            for (const auto &g: this->options_groups) {
                groups.push_back(g);
            }
            return;
        }

        LOG(ERROR) << "Access to bro options before parsing config";
    }

}