

#include <exception>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/config.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>


namespace osquery {

    class BroLoggerPlugin : public LoggerPlugin {
    public:

        Status setUp() override;

        /// Log results (differential) to a distinct path.
        Status logString(const std::string& s) override;

        /// Log snapshot data to a distinct path.
        Status logSnapshot(const std::string& s) override;

        /// Write a status to Bro.
        Status logStatus(const std::vector<StatusLogLine>& log) override;

        /**
         * @brief Initialize the logger plugin after osquery has begun.
         *
         */
        void init(const std::string& name,
                  const std::vector<StatusLogLine>& log) override;

    private:

    };


    class BroConfigParserPlugin : public ConfigParserPlugin {
    public:
        std::vector <std::string> keys() const override { return {"bro"}; }

        Status setUp() override;

        Status update(const std::string &source, const ParserConfig &config) override;
    };

    class BroConfigParser {
    public:

        Status parseBroOptions();

        std::string getBro_IP();

        int getBro_Port();

        std::string getUID();

        void getGroups(std::vector<std::string>& groups);

    private:
        bool parsed = false;
        // Parsed Bro Options
        std::string options_bro_ip = "";
        int options_bro_port = -1;
        std::string options_uid = "";
        std::vector<std::string> options_groups;

    };



}