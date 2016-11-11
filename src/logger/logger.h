#include <exception>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <broker/report.hh>


namespace osquery {

class BroLoggerPlugin : public LoggerPlugin {
 public:

  static broker::endpoint* loggerEP;

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

}
